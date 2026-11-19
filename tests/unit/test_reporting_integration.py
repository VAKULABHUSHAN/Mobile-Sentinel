"""Unit tests for Reporting Pipeline Integration (Phase 6B).

Covers:
1. ReportGenerator invoked after scan completion.
2. AI summary attached to ScanExecutionResult.
3. JSON report contains AI summary.
4. Text report contains AI summary.
5. Deterministic findings remain unchanged.
6. Risk score invariance.
7. Severity invariance.
8. AI disabled fallback.
9. Provider failure fallback.
10. Missing AI summary handling.
11. Missing optional scan fields.
12. Existing CLI export compatibility.
13. JSON serialization and deserialization.
14. Report generation does not interfere with device cleanup.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.models import AIReportSummary
from sentinel.ai.provider import AIProviderNetworkError, MockLLMProvider
from sentinel.ai.report_generator import ReportGenerator
from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.cli.main import cli
from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import Finding, RiskScoreSummary, ScanMetadata, TestScenarioResult
from sentinel.orchestrator.pipeline import ScanExecutionResult, ScanPipeline
from sentinel.reporting.json_report import JsonReportGenerator
from sentinel.reporting.text_report import TextReportGenerator
from sentinel.ui_testing.models import ExplorationResult


def _create_mock_apk_metadata() -> APKMetadata:
    return APKMetadata(
        file_path="app.apk",
        file_size_bytes=2048576,
        file_size_mb=2.0,
        sha256="abc1234567890def",
        package_name="com.example.integ",
        version_name="1.0.0",
        version_code=1,
        min_sdk=26,
        target_sdk=34,
        app_label="IntegApp",
        launcher_activity="com.example.integ.MainActivity",
        is_flutter=False,
    )


def _create_mock_scan_result() -> ScanExecutionResult:
    apk = _create_mock_apk_metadata()
    meta = ScanMetadata(
        scan_id="SCAN-INTEG-001",
        app_path="app.apk",
        app_hash_sha256="abc1234567890def",
        app_name="IntegApp",
        package_name="com.example.integ",
        target_sdk=34,
    )
    findings = [
        Finding(
            id="F-EXP-01",
            title="Exported Service Unprotected",
            category=FindingCategory.ATTACK_SURFACE,
            severity=Severity.HIGH,
            confidence=0.9,
            description="Service com.example.integ.SyncService is exported without permissions",
            impact="Any application can bind to internal sync service",
            recommendation="Set android:exported=false",
            evidence={"service": "com.example.integ.SyncService"},
        ),
        Finding(
            id="F-NET-01",
            title="Cleartext Traffic Enabled",
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            confidence=0.85,
            description="Cleartext HTTP permitted in network security config",
            impact="Network sniffing vulnerability",
            recommendation="Enforce TLS",
        ),
    ]
    risk = RiskScoreSummary(
        overall_score=75.0,
        security_score=70.0,
        stability_score=90.0,
        performance_score=85.0,
        ux_score=80.0,
        accessibility_score=80.0,
        risk_level="MEDIUM",
        high_count=1,
        medium_count=1,
    )
    exploration = ExplorationResult(
        screens_discovered=4,
        screens_explored=4,
        actions_tested=8,
        screen_coverage_pct=100.0,
        action_coverage_pct=80.0,
    )
    ai_summary = AIReportSummary(
        executive_summary="Executive Summary: IntegApp underwent automated analysis.",
        quality_assessment="Solid runtime resilience with opportunities for security hardening.",
        security_summary="Identified 1 High and 1 Medium severity finding.",
        stability_summary="Execution was stable with no fatal crashes.",
        crash_summary="Zero crashes recorded.",
        screen_insights=["Discovered 4 screens."],
        test_recommendations=["Add integration tests for exported services."],
        critical_priorities=["Address Exported Service Unprotected."],
        remediation_recommendations=["Set android:exported=false."],
        is_ai_generated=True,
        provider_used="mock",
        model_used="mock-sentinel-ai",
    )

    return ScanExecutionResult(
        scan_id="SCAN-INTEG-001",
        metadata=meta,
        apk_meta=apk,
        device_name="emulator-5554",
        findings=findings,
        risk_summary=risk,
        runtime_summary={"Installation": "PASS", "Launch": "PASS", "Crash": "PASS"},
        exploration_result=exploration,
        security_explanations=[{
            "finding_id": "F-EXP-01",
            "plain_title": "Internal Service Exposed",
            "simplified_explanation": "Other apps can trigger this service",
            "urgency": "IMMEDIATE",
        }],
        failure_analyses=[],
        ai_report=ai_summary,
        duration_seconds=15.0,
    )


# 1. ReportGenerator invoked after scan completion in pipeline
def test_report_generator_invoked_after_scan_completion(tmp_path: Path):
    fake_apk = tmp_path / "test.apk"
    import zipfile
    with zipfile.ZipFile(fake_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    pipeline = ScanPipeline()
    pipeline.adb.list_devices = MagicMock(return_value=["emulator-5554"])
    pipeline.adb.install_apk = MagicMock(return_value=(True, "Success"))
    pipeline.adb.is_package_installed = MagicMock(return_value=True)
    pipeline.adb.launch_package = MagicMock(return_value=(True, ""))
    pipeline.adb.is_running = MagicMock(return_value=True)
    pipeline.adb.capture_logcat = MagicMock(return_value="")
    pipeline.adb.get_memory_info = MagicMock(return_value={})
    pipeline.adb.force_stop = MagicMock()
    pipeline.adb.uninstall_package = MagicMock()
    pipeline.extractor.extract_metadata = MagicMock(return_value=_create_mock_apk_metadata())

    # Mock ManifestAnalyzer and other static analyzers
    with patch("sentinel.analyzers.android.manifest.ManifestAnalyzer.analyze", return_value=[]), \
         patch("sentinel.analyzers.secrets.scanner.SecretScanner.analyze", return_value=[]), \
         patch("sentinel.analyzers.flutter.detector.FlutterAnalyzer.analyze", return_value=[]), \
         patch("sentinel.analyzers.network.configuration.NetworkAnalyzer.analyze", return_value=[]):
        result = pipeline.execute_pipeline(
            apk_path=fake_apk,
            output_dir=str(tmp_path / "reports"),
            run_ui=False,
            run_network=False,
            keep_installed=False,
        )

    # 1 & 2: Report generator was invoked and attached to ScanExecutionResult
    assert result.ai_report is not None
    assert isinstance(result.ai_report, AIReportSummary)
    assert result.ai_report.executive_summary != ""


# 2. AI summary attached to ScanExecutionResult
def test_ai_summary_attached_to_scan_execution_result():
    res = _create_mock_scan_result()
    assert res.ai_report is not None
    assert res.ai_report.is_ai_generated is True

    d = res.to_dict()
    assert "ai_report" in d
    assert d["ai_report"] is not None
    assert d["ai_report"]["executive_summary"] == res.ai_report.executive_summary
    assert d["ai_insights"]["report_summary"] is not None
    assert d["ai_insights"]["executive_summary"] == res.ai_report.executive_summary


# 3. JSON report contains AI summary
def test_json_report_contains_ai_summary(tmp_path: Path):
    res = _create_mock_scan_result()
    json_path = tmp_path / "report.json"

    gen = JsonReportGenerator()
    content = gen.generate(res, json_path)

    data = json.loads(content)
    assert "ai_report" in data
    assert data["ai_report"]["executive_summary"] == res.ai_report.executive_summary
    assert data["ai_report"]["quality_assessment"] == res.ai_report.quality_assessment
    assert "ai_insights" in data
    assert data["ai_insights"]["report_summary"]["executive_summary"] == res.ai_report.executive_summary
    assert data["ai_insights"]["is_ai_generated"] is True


# 4. Text report contains AI summary
def test_text_report_contains_ai_summary(tmp_path: Path):
    res = _create_mock_scan_result()
    txt_path = tmp_path / "report.txt"

    gen = TextReportGenerator()
    content = gen.generate(res, txt_path)

    assert "EXECUTIVE SUMMARY" in content
    assert "IntegApp underwent automated analysis" in content
    assert "OVERALL QUALITY ASSESSMENT" in content
    assert "Solid runtime resilience" in content
    assert "AI TEST RECOMMENDATIONS" in content
    assert "CRITICAL PRIORITIES" in content
    assert "RECOMMENDED REMEDIATION" in content


# 5. Deterministic findings remain unchanged
def test_deterministic_findings_remain_unchanged():
    res = _create_mock_scan_result()
    orig_findings_count = len(res.findings)
    orig_titles = [f.title for f in res.findings]

    gen = ReportGenerator(AIClient(AIConfig(enabled=False)))
    report = gen.generate_report(res)

    assert len(res.findings) == orig_findings_count
    assert [f.title for f in res.findings] == orig_titles


# 6. Risk score invariance
def test_risk_score_invariance():
    res = _create_mock_scan_result()
    orig_overall = res.risk_summary.overall_score
    orig_security = res.risk_summary.security_score
    orig_level = res.risk_summary.risk_level

    gen = ReportGenerator(AIClient(AIConfig(enabled=False)))
    gen.generate_report(res)

    assert res.risk_summary.overall_score == orig_overall
    assert res.risk_summary.security_score == orig_security
    assert res.risk_summary.risk_level == orig_level


# 7. Severity invariance
def test_severity_invariance():
    res = _create_mock_scan_result()
    orig_severities = [f.severity for f in res.findings]

    gen = ReportGenerator(AIClient(AIConfig(enabled=False)))
    gen.generate_report(res)

    assert [f.severity for f in res.findings] == orig_severities
    assert res.findings[0].severity == Severity.HIGH
    assert res.findings[1].severity == Severity.MEDIUM


# 8. AI disabled fallback
def test_ai_disabled_fallback(tmp_path: Path):
    res = _create_mock_scan_result()
    res.ai_report = None

    # When AI is disabled, ReportGenerator generates deterministic summary
    gen = ReportGenerator(AIClient(AIConfig(enabled=False)))
    fallback_report = gen.generate_report(res)

    assert fallback_report.is_ai_generated is False
    assert fallback_report.provider_used == "deterministic_fallback"
    assert "IntegApp" in fallback_report.executive_summary

    # Text report also handles fallback cleanly
    res.ai_report = fallback_report
    txt_path = tmp_path / "fallback_report.txt"
    txt_gen = TextReportGenerator()
    content = txt_gen.generate(res, txt_path)

    assert "[Deterministic Engine]" in content
    assert "IntegApp" in content


# 9. Provider failure fallback
def test_provider_failure_fallback():
    mock_prov = MockLLMProvider()

    def fail_call(prompt, system, json_mode):
        raise AIProviderNetworkError("Simulated LLM network timeout")

    mock_prov.set_custom_handler(fail_call)
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    gen = ReportGenerator(client)

    res = _create_mock_scan_result()
    report = gen.generate_report(res)

    assert report.is_ai_generated is False
    assert report.provider_used == "deterministic_fallback"
    assert report.executive_summary != ""


# 10. Missing AI summary handling
def test_missing_ai_summary_handling(tmp_path: Path):
    res = _create_mock_scan_result()
    res.ai_report = None  # Explicitly None

    json_path = tmp_path / "report.json"
    json_gen = JsonReportGenerator()
    json_content = json_gen.generate(res, json_path)
    data = json.loads(json_content)
    assert data["ai_report"] is None

    txt_path = tmp_path / "report.txt"
    txt_gen = TextReportGenerator()
    txt_content = txt_gen.generate(res, txt_path)
    assert "EXECUTIVE SUMMARY" in txt_content
    assert "IntegApp" in txt_content


# 11. Missing optional scan fields
def test_missing_optional_scan_fields(tmp_path: Path):
    minimal_res = ScanExecutionResult(
        scan_id="SCAN-MINIMAL",
        metadata=ScanMetadata(
            scan_id="SCAN-MINIMAL",
            app_path="app.apk",
            app_hash_sha256="abc",
        ),
        apk_meta=None,
        device_name=None,
        exploration_result=None,
        ai_report=None,
    )

    json_path = tmp_path / "minimal.json"
    json_gen = JsonReportGenerator()
    json_content = json_gen.generate(minimal_res, json_path)
    assert json_content != ""

    txt_path = tmp_path / "minimal.txt"
    txt_gen = TextReportGenerator()
    txt_content = txt_gen.generate(minimal_res, txt_path)
    assert "MOBILE SENTINEL SECURITY & QA AUDIT REPORT" in txt_content


# 12. Existing CLI export compatibility
def test_existing_cli_export_compatibility(tmp_path: Path):
    fake_apk = tmp_path / "app.apk"
    fake_apk.touch()

    mock_result = _create_mock_scan_result()

    runner = CliRunner()
    with patch("sentinel.runtime.adb.ADBController.list_devices", return_value=["emulator-5554"]), \
         patch("sentinel.orchestrator.pipeline.ScanPipeline.execute_pipeline", return_value=mock_result):
        out_dir = tmp_path / "cli_reports"
        res = runner.invoke(cli, ["test", str(fake_apk), "--output", str(out_dir)])
        assert res.exit_code == 0
        assert "Scan completed." in res.output

        # Verify exported files exist and contain AI summary
        report_folder = out_dir / mock_result.app_dir_name
        assert (report_folder / "report.txt").exists()
        assert (report_folder / "report.json").exists()

        data = json.loads((report_folder / "report.json").read_text(encoding="utf-8"))
        assert "ai_report" in data
        assert data["ai_report"] is not None


# 13. JSON serialization and deserialization
def test_json_serialization_and_deserialization():
    res = _create_mock_scan_result()
    d = res.to_dict()

    json_str = json.dumps(d)
    restored = json.loads(json_str)

    assert restored["scan_id"] == "SCAN-INTEG-001"
    assert restored["ai_report"]["executive_summary"] == res.ai_report.executive_summary
    assert len(restored["findings"]) == 2
    assert restored["risk_summary"]["overall_score"] == 75.0


# 14. Report generation does not interfere with device cleanup
def test_report_generation_does_not_interfere_with_device_cleanup(tmp_path: Path):
    fake_apk = tmp_path / "test.apk"
    import zipfile
    with zipfile.ZipFile(fake_apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    pipeline = ScanPipeline()
    pipeline.adb.list_devices = MagicMock(return_value=["emulator-5554"])
    pipeline.adb.install_apk = MagicMock(return_value=(True, "Success"))
    pipeline.adb.is_package_installed = MagicMock(return_value=True)
    pipeline.adb.launch_package = MagicMock(return_value=(True, ""))
    pipeline.adb.is_running = MagicMock(return_value=True)
    pipeline.adb.capture_logcat = MagicMock(return_value="")
    pipeline.adb.get_memory_info = MagicMock(return_value={})
    pipeline.adb.force_stop = MagicMock()
    pipeline.adb.uninstall_package = MagicMock()
    pipeline.extractor.extract_metadata = MagicMock(return_value=_create_mock_apk_metadata())

    # Simulate ReportGenerator throwing an exception
    with patch("sentinel.analyzers.android.manifest.ManifestAnalyzer.analyze", return_value=[]), \
         patch("sentinel.analyzers.secrets.scanner.SecretScanner.analyze", return_value=[]), \
         patch("sentinel.analyzers.flutter.detector.FlutterAnalyzer.analyze", return_value=[]), \
         patch("sentinel.analyzers.network.configuration.NetworkAnalyzer.analyze", return_value=[]), \
         patch("sentinel.ai.report_generator.ReportGenerator.generate_report", side_effect=RuntimeError("AI Crash")):
        result = pipeline.execute_pipeline(
            apk_path=fake_apk,
            output_dir=str(tmp_path / "reports"),
            run_ui=False,
            run_network=False,
            keep_installed=False,
        )

    # Device cleanup was properly called despite AI failure
    pipeline.adb.force_stop.assert_called_once()
    pipeline.adb.uninstall_package.assert_called_once()
    assert result.scan_id != ""
