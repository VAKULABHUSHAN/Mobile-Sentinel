"""End-to-End integration test validating the complete Mobile Sentinel workflow:

APK Input -> Validation -> Extraction -> Static Analysis -> Runtime Analysis ->
UI Exploration -> Risk Scoring -> AI Intelligence -> Report Generation -> JSON/Text Export.
"""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.provider import MockLLMProvider
from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.orchestrator.pipeline import ScanPipeline
from sentinel.reporting.json_report import JsonReportGenerator
from sentinel.reporting.text_report import TextReportGenerator
from sentinel.ui_testing.models import UIElement

SAMPLE_DUMP_HIERARCHY = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.e2e" bounds="[0,0][1080,2400]">
    <node index="0" text="Login Screen" resource-id="com.example.e2e:id/title" class="android.widget.TextView" package="com.example.e2e" bounds="[100,200][980,300]" />
    <node index="1" text="" resource-id="com.example.e2e:id/username" class="android.widget.EditText" package="com.example.e2e" bounds="[100,400][980,500]" clickable="true" focusable="true" />
    <node index="2" text="" resource-id="com.example.e2e:id/password" class="android.widget.EditText" package="com.example.e2e" bounds="[100,550][980,650]" password="true" clickable="true" focusable="true" />
    <node index="3" text="Sign In" resource-id="com.example.e2e:id/btn_login" class="android.widget.Button" package="com.example.e2e" bounds="[100,750][980,850]" clickable="true" focusable="true" />
  </node>
</hierarchy>
"""


def _create_synthetic_test_apk(target_path: Path) -> Path:
    """Creates a controlled synthetic APK archive with manifest and secret assets."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest xmlns:android='http://schemas.android.com/apk/res/android' package='com.example.e2e'><application android:debuggable='true'></application></manifest>")
        zf.writestr("classes.dex", b"DEX\n035\x00fake_bytecode_bytes")
        zf.writestr("assets/config.json", b'{"aws_key": "AKIAIOSFODNN7EXAMPLE", "api_url": "http://insecure.test.com"}')
        zf.writestr("res/xml/network_security_config.xml", b'<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>')
    return target_path


def test_complete_e2e_mocked_pipeline(tmp_path: Path):
    """E2E workflow test validating extraction, static analysis, UI exploration, AI synthesis, and report output."""
    apk_file = tmp_path / "app-e2e.apk"
    _create_synthetic_test_apk(apk_file)

    reports_dir = tmp_path / "reports"

    # Set up canned AI responses covering screen analysis, test generation, security explanations, and report synthesis
    mock_llm = MockLLMProvider()

    def mock_handler(prompt, system_instruction, json_mode):
        if "executive and technical AI assessment report" in prompt:
            return json.dumps({
                "executive_summary": "E2E Automated Audit of E2ESentinelApp concluded with actionable recommendations.",
                "quality_assessment": "The application exhibits critical hardcoded credentials requiring immediate remediation.",
                "security_summary": "1 Critical AWS Key and 1 High Severity Insecure Network Configuration finding.",
                "stability_summary": "Application launched cleanly with zero runtime crashes or ANRs.",
                "crash_summary": "Zero fatal exceptions detected.",
                "screen_insights": ["Explored Login Screen with 3 interactive controls."],
                "test_recommendations": ["Automate boundary tests for input fields."],
                "critical_priorities": ["Revoke and rotate embedded AWS credentials immediately."],
                "remediation_recommendations": ["Enforce TLS in network_security_config.xml and migrate secrets to KMS."],
            })
        elif "test_cases" in prompt.lower() or "generate relevant, safe functional" in prompt.lower():
            return json.dumps({
                "test_cases": [{
                    "test_id": "TC-E2E-001",
                    "name": "Empty Credentials Submission",
                    "description": "Submit empty username and password fields to verify client-side validation.",
                    "target_screen": "LoginScreen",
                    "suggested_action": "tap",
                    "target_element": "btn_login",
                    "expected_outcome": "Validation error alert displayed.",
                    "risk_level": "SAFE",
                }]
            })
        elif "explain this technical android mobile application security finding" in prompt.lower():
            return json.dumps({
                "finding_id": "SECRETS_AWS_ACCESS_KEY",
                "plain_title": "Hardcoded Cloud Access Key Detected",
                "simplified_explanation": "An Amazon Web Services access key was embedded directly in the application assets.",
                "attack_scenario": "An attacker decompiles the APK and extracts the cloud access key.",
                "business_impact": "Unauthorized access to cloud infrastructure and storage buckets.",
                "remediation_guide": "Revoke the access key and store credentials securely on backend servers.",
                "urgency": "IMMEDIATE",
            })
        # Default screen understanding response
        return json.dumps({
            "screen_purpose": "User authentication gateway",
            "screen_type": "LOGIN",
            "summary": "Standard login screen with username and password fields.",
            "key_elements": ["username", "password", "btn_login"],
            "confidence": 0.95,
        })

    mock_llm.set_custom_handler(mock_handler)
    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_llm)

    pipeline = ScanPipeline()

    # Mock ADB runtime interactions
    pipeline.adb.list_devices = MagicMock(return_value=["emulator-5554"])
    pipeline.adb.get_device_properties = MagicMock(return_value={"android_version": "14", "model": "Pixel 8"})
    pipeline.adb.clear_logcat = MagicMock(return_value=True)
    pipeline.adb.get_foreground_package = MagicMock(return_value="com.example.e2e")
    pipeline.adb.get_current_activity = MagicMock(return_value="com.example.e2e.MainActivity")
    pipeline.adb.install_apk = MagicMock(return_value=(True, "Success"))
    pipeline.adb.is_package_installed = MagicMock(return_value=True)
    pipeline.adb.launch_package = MagicMock(return_value=(True, ""))
    pipeline.adb.is_running = MagicMock(return_value=True)
    pipeline.adb.dump_hierarchy = MagicMock(return_value=SAMPLE_DUMP_HIERARCHY)
    pipeline.adb.capture_logcat = MagicMock(return_value="04-12 10:00:00.000 1234 1234 I ActivityManager: Displayed com.example.e2e/.MainActivity: +450ms")
    pipeline.adb.get_memory_info = MagicMock(return_value={"total_pss": "34MB", "native_heap": "12MB"})
    pipeline.adb.set_network_state = MagicMock(return_value=True)
    pipeline.adb.set_rotation = MagicMock(return_value=True)
    pipeline.adb.force_stop = MagicMock(return_value=True)
    pipeline.adb.uninstall_package = MagicMock(return_value=True)

    def dummy_screenshot(dest: str, device: str = None) -> bool:
        Path(dest).write_bytes(b"\x89PNG\r\n\x1a\nfake_png")
        return True
    pipeline.adb.take_screenshot = MagicMock(side_effect=dummy_screenshot)

    # Mock extractor metadata
    mock_meta = APKMetadata(
        file_path=str(apk_file),
        file_size_bytes=apk_file.stat().st_size,
        file_size_mb=round(apk_file.stat().st_size / (1024 * 1024), 2),
        sha256="e2e1234567890abcdef",
        package_name="com.example.e2e",
        version_name="1.0.0",
        version_code=1,
        min_sdk=26,
        target_sdk=34,
        app_label="E2ESentinelApp",
        launcher_activity="com.example.e2e.MainActivity",
        activities=["com.example.e2e.MainActivity"],
        exported_components=[{"type": "activity", "name": "com.example.e2e.MainActivity", "exported": True}],
        permissions=["android.permission.INTERNET"],
        is_flutter=False,
    )
    pipeline.extractor.extract_metadata = MagicMock(return_value=mock_meta)

    # Inject mock AI client into AI analyzers
    with patch("sentinel.ai.report_generator.ReportGenerator.__init__", lambda self, *a, **k: setattr(self, "client", client)):
        result = pipeline.execute_pipeline(
            apk_path=apk_file,
            output_dir=str(reports_dir),
            run_ui=True,
            run_network=True,
            keep_installed=False,
        )

    # 1. Validation & Metadata assertions
    assert result.scan_id != ""
    assert result.apk_meta.package_name == "com.example.e2e"
    assert result.apk_meta.app_label == "E2ESentinelApp"

    # 2. Deterministic findings verification
    # SecretScanner must have extracted the AWS key from assets/config.json
    secret_findings = [f for f in result.findings if "AWS" in f.title or "KEY" in f.id]
    assert len(secret_findings) >= 1
    aws_finding = secret_findings[0]
    assert aws_finding.severity.value in ("CRITICAL", "HIGH")
    assert aws_finding.certainty.value == "CONFIRMED"

    # 3. Risk scoring evaluation
    assert result.risk_summary.overall_score < 100.0
    assert result.risk_summary.security_score < 100.0

    # 4. AI Report Summary verification
    assert result.ai_report is not None
    assert result.ai_report.is_ai_generated is True
    assert "E2E Automated Audit" in result.ai_report.executive_summary

    # 5. Device cleanup guarantee
    pipeline.adb.force_stop.assert_called_with("com.example.e2e", device="emulator-5554")
    pipeline.adb.uninstall_package.assert_called_with("com.example.e2e", device="emulator-5554")

    # 6. Report Export Verification
    target_report_dir = reports_dir / result.app_dir_name
    txt_path = target_report_dir / "report.txt"
    json_path = target_report_dir / "report.json"

    txt_gen = TextReportGenerator()
    txt_gen.generate(result, txt_path)

    json_gen = JsonReportGenerator()
    json_gen.generate(result, json_path)

    assert txt_path.exists()
    assert json_path.exists()

    # Verify JSON content
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["scan_id"] == result.scan_id
    assert data["apk_metadata"]["package_name"] == "com.example.e2e"
    assert data["ai_report"]["is_ai_generated"] is True
    assert len(data["findings"]) >= 1

    # Verify Text content
    text_content = txt_path.read_text(encoding="utf-8")
    assert "MOBILE SENTINEL SECURITY & QA AUDIT REPORT" in text_content
    assert "Application: E2ESentinelApp" in text_content
    assert "Package: com.example.e2e" in text_content
    assert "EXECUTIVE SUMMARY" in text_content
    assert "SECURITY FINDINGS (CONFIRMED DETERMINISTIC)" in text_content
    assert "FINAL VERDICT" in text_content


@pytest.mark.real_device
def test_optional_real_device_integration():
    """Optional real-device execution test. Skipped unless SENTINEL_REAL_DEVICE=1."""
    if not os.environ.get("SENTINEL_REAL_DEVICE"):
        pytest.skip("Physical device test requires SENTINEL_REAL_DEVICE=1 and connected Android hardware")

    from sentinel.runtime.adb import ADBController
    adb = ADBController()
    devices = adb.list_devices()
    assert len(devices) > 0, "SENTINEL_REAL_DEVICE=1 was specified but no devices are connected"
    props = adb.get_device_properties(devices[0])
    assert "model" in props
