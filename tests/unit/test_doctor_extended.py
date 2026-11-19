"""Unit tests for Phase 7 EnvironmentDoctor improvements."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinel.ai.config import AIConfig
from sentinel.core.enums import ToolStatus
from sentinel.environment.doctor import EnvironmentDoctor


def test_doctor_connected_device_none():
    doc = EnvironmentDoctor()
    fake_adb = MagicMock(found=True, path="adb")
    with patch.object(doc, "_run_command", return_value=(0, "List of devices attached\n\n", "")):
        res = doc.check_connected_device(fake_adb)
        assert res.found is False
        assert res.status == ToolStatus.DEGRADED
        assert "No connected Android devices" in res.details
        assert res.remediation is not None


def test_doctor_connected_device_present():
    doc = EnvironmentDoctor()
    fake_adb = MagicMock(found=True, path="adb")
    devices_output = "List of devices attached\nemulator-5554\tdevice\nphysical-serial\tdevice\n"
    with patch.object(doc, "_run_command", return_value=(0, devices_output, "")):
        res = doc.check_connected_device(fake_adb)
        assert res.found is True
        assert res.status == ToolStatus.AVAILABLE
        assert "2 device(s)" in res.version
        assert "emulator-5554" in res.details


def test_doctor_connected_device_unauthorized():
    doc = EnvironmentDoctor()
    fake_adb = MagicMock(found=True, path="adb")
    devices_output = "List of devices attached\nphone-123\tunauthorized\n"
    with patch.object(doc, "_run_command", return_value=(0, devices_output, "")):
        res = doc.check_connected_device(fake_adb)
        assert res.status == ToolStatus.DEGRADED
        assert "unauthorized" in res.details
        assert "USB debugging authorization" in res.remediation


def test_doctor_connected_device_missing_adb():
    doc = EnvironmentDoctor()
    fake_adb = MagicMock(found=False)
    res = doc.check_connected_device(fake_adb)
    assert res.status == ToolStatus.SKIPPED


def test_doctor_apk_processing():
    doc = EnvironmentDoctor()
    res = doc.check_apk_processing()
    assert res.found is True
    assert res.status == ToolStatus.AVAILABLE
    assert "zipfile" in res.version.lower() or "zipfile" in res.details.lower()


def test_doctor_ai_config_disabled():
    doc = EnvironmentDoctor()
    with patch("sentinel.ai.config.AIConfig.from_env", return_value=AIConfig(enabled=False)):
        res = doc.check_ai_config()
        assert res.status == ToolStatus.AVAILABLE
        assert res.version == "Disabled"
        assert "deterministic" in res.details.lower()


def test_doctor_ai_config_enabled():
    doc = EnvironmentDoctor()
    with patch("sentinel.ai.config.AIConfig.from_env", return_value=AIConfig(enabled=True, provider="gemini", model="gemini-1.5-flash")):
        res = doc.check_ai_config()
        assert res.status == ToolStatus.AVAILABLE
        assert "gemini" in res.details


def test_doctor_ai_provider_mock():
    doc = EnvironmentDoctor()
    cfg = AIConfig(enabled=True, provider="mock")
    res = doc.check_ai_provider(cfg)
    assert res.status == ToolStatus.AVAILABLE
    assert "Mock" in res.version


def test_doctor_ai_provider_gemini_missing_key():
    doc = EnvironmentDoctor()
    cfg = AIConfig(enabled=True, provider="gemini", api_key="")
    with patch.dict("os.environ", {}, clear=True):
        res = doc.check_ai_provider(cfg)
        assert res.status == ToolStatus.DEGRADED
        assert "Missing Key" in res.version
        assert "GEMINI_API_KEY" in res.remediation


def test_doctor_ai_provider_gemini_valid_key():
    doc = EnvironmentDoctor()
    cfg = AIConfig(enabled=True, provider="gemini", api_key="AIzaSyDummyKey1234567890abcdef")
    res = doc.check_ai_provider(cfg)
    assert res.status == ToolStatus.AVAILABLE
    assert res.found is True


def test_doctor_ai_provider_ollama():
    doc = EnvironmentDoctor()
    cfg = AIConfig(enabled=True, provider="ollama", base_url="http://localhost:11434")

    # When Ollama is unreachable
    with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")), \
         patch("shutil.which", return_value=None):
        res = doc.check_ai_provider(cfg)
        assert res.status == ToolStatus.DEGRADED
        assert "ollama serve" in res.remediation


def test_doctor_report_directory_permissions(tmp_path: Path):
    doc = EnvironmentDoctor()
    writable_dir = tmp_path / "valid_reports"
    res = doc.check_report_directory(str(writable_dir))
    assert res.status == ToolStatus.AVAILABLE
    assert res.found is True


def test_doctor_diagnose_includes_new_subsystems():
    doc = EnvironmentDoctor()
    report = doc.diagnose()

    expected_tools = [
        "python", "adb", "connected_device", "android_sdk",
        "java", "flutter", "apk_processing", "ai_config",
        "ai_provider", "report_directory",
    ]
    for tool in expected_tools:
        assert tool in report.tools

    assert report.ready_for_scan is True


def test_doctor_render_console_labels():
    doc = EnvironmentDoctor()
    report = doc.diagnose()
    rendered = doc.render_console_report(report)

    assert "MOBILE SENTINEL - ENVIRONMENT DOCTOR" in rendered
    assert "TOOL / SUBSYSTEM" in rendered
    assert "DETAILS" in rendered
    assert ("OK" in rendered or "AVAILABLE" in rendered)
