"""Unit tests for Phase 7 failure handling, exception recovery, and device cleanup."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.provider import AIProviderError, MockLLMProvider
from sentinel.ai.report_generator import ReportGenerator
from sentinel.analyzers.apk.extractor import APKExtractor, APKMetadata
from sentinel.core.exceptions import APKValidationError, RuntimeDeviceError
from sentinel.core.models import RiskScoreSummary, ScanMetadata
from sentinel.orchestrator.pipeline import ScanExecutionResult, ScanPipeline


def _mock_apk_metadata() -> APKMetadata:
    return APKMetadata(
        file_path="app.apk",
        file_size_bytes=1048576,
        file_size_mb=1.0,
        sha256="abc",
        package_name="com.example.failtest",
        version_name="1.0.0",
        version_code=1,
        min_sdk=26,
        target_sdk=34,
        app_label="FailTestApp",
        launcher_activity="com.example.failtest.MainActivity",
    )


def test_invalid_apk_empty_file(tmp_path: Path):
    empty_apk = tmp_path / "empty.apk"
    empty_apk.touch()

    pipeline = ScanPipeline()
    with pytest.raises(APKValidationError, match="empty"):
        pipeline.execute_pipeline(empty_apk, output_dir=str(tmp_path / "out"))


def test_invalid_apk_corrupted_archive(tmp_path: Path):
    corrupt_apk = tmp_path / "corrupt.apk"
    corrupt_apk.write_bytes(b"NOT A REAL ZIP FILE CONTENT")

    pipeline = ScanPipeline()
    with pytest.raises(APKValidationError, match="ZIP"):
        pipeline.execute_pipeline(corrupt_apk, output_dir=str(tmp_path / "out"))


def test_missing_adb_raises_or_warns(tmp_path: Path):
    import zipfile
    valid_apk = tmp_path / "valid.apk"
    with zipfile.ZipFile(valid_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    pipeline = ScanPipeline()
    pipeline.adb.list_devices = MagicMock(return_value=[])

    # No device detected: pipeline skips device installation gracefully
    result = pipeline.execute_pipeline(
        valid_apk,
        output_dir=str(tmp_path / "out"),
        run_ui=False,
    )
    assert result.device_name is None
    assert result.runtime_summary["Installation"] == "SKIPPED"


def test_device_disconnection_during_run(tmp_path: Path):
    import zipfile
    valid_apk = tmp_path / "valid.apk"
    with zipfile.ZipFile(valid_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    pipeline = ScanPipeline()
    pipeline.adb.list_devices = MagicMock(return_value=["emulator-5554"])
    pipeline.adb.install_apk = MagicMock(return_value=(True, ""))
    pipeline.adb.is_package_installed = MagicMock(return_value=True)
    pipeline.adb.launch_package = MagicMock(return_value=(True, ""))
    pipeline.adb.is_running = MagicMock(return_value=True)
    # Simulate ADB dropping connection during logcat capture
    pipeline.adb.capture_logcat = MagicMock(side_effect=RuntimeDeviceError("device 'emulator-5554' not found"))
    pipeline.adb.force_stop = MagicMock()
    pipeline.adb.uninstall_package = MagicMock()
    pipeline.extractor.extract_metadata = MagicMock(return_value=_mock_apk_metadata())

    # Pipeline should handle runtime error without crashing whole execution
    with patch("sentinel.analyzers.android.manifest.ManifestAnalyzer.analyze", return_value=[]), \
         patch("sentinel.analyzers.secrets.scanner.SecretScanner.analyze", return_value=[]), \
         patch("sentinel.analyzers.flutter.detector.FlutterAnalyzer.analyze", return_value=[]), \
         patch("sentinel.analyzers.network.configuration.NetworkAnalyzer.analyze", return_value=[]):
        try:
            result = pipeline.execute_pipeline(valid_apk, output_dir=str(tmp_path / "out"), run_ui=False)
            assert result.scan_id != ""
        except RuntimeDeviceError:
            pass  # Even if raised, device cleanup in finally is guaranteed

    # Cleanup in finally was executed
    pipeline.adb.force_stop.assert_called()


def test_ai_provider_unavailable_fallback():
    mock_prov = MockLLMProvider()

    def err_call(p, s, j):
        raise AIProviderError("Provider 503 Service Unavailable")

    mock_prov.set_custom_handler(err_call)
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    gen = ReportGenerator(client)

    scan_res = ScanExecutionResult(
        scan_id="SCAN-FAIL-01",
        metadata=ScanMetadata(scan_id="SCAN-FAIL-01", app_path="app.apk", app_hash_sha256="abc"),
        apk_meta=None,
        device_name=None,
    )
    report = gen.generate_report(scan_res)
    assert report.is_ai_generated is False
    assert report.provider_used == "deterministic_fallback"


def test_invalid_ai_configuration():
    # Misconfigured provider name
    cfg = AIConfig(enabled=True, provider="non_existent_provider")
    client = AIClient(cfg)
    # AI client handles invalid provider by disabling itself gracefully
    assert client.is_enabled is False


def test_device_cleanup_guarantee_on_pipeline_exception(tmp_path: Path):
    import zipfile
    valid_apk = tmp_path / "valid.apk"
    with zipfile.ZipFile(valid_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    pipeline = ScanPipeline()
    pipeline.adb.list_devices = MagicMock(return_value=["emulator-5554"])
    pipeline.adb.install_apk = MagicMock(return_value=(True, ""))
    pipeline.adb.is_package_installed = MagicMock(return_value=True)
    pipeline.adb.force_stop = MagicMock()
    pipeline.adb.uninstall_package = MagicMock()
    pipeline.extractor.extract_metadata = MagicMock(return_value=_mock_apk_metadata())

    # Raise exception during static analysis
    with patch("sentinel.analyzers.android.manifest.ManifestAnalyzer.analyze", side_effect=Exception("Unexpected parse failure")):
        try:
            pipeline.execute_pipeline(valid_apk, output_dir=str(tmp_path / "out"), run_ui=False)
        except Exception:
            pass

    # Ensure device cleanup was executed in finally: block
    pipeline.adb.force_stop.assert_called_once()
    pipeline.adb.uninstall_package.assert_called_once()
