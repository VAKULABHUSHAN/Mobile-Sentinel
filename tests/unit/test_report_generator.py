"""Unit tests for ReportGenerator (AI report synthesis, grounding, fallbacks, and redaction)."""

import json
from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.models import AIReportSummary
from sentinel.ai.provider import AIProviderNetworkError, MockLLMProvider
from sentinel.ai.report_generator import ReportGenerator
from sentinel.analyzers.apk.extractor import APKMetadata
from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import Finding, RiskScoreSummary, ScanMetadata
from sentinel.orchestrator.pipeline import ScanExecutionResult
from sentinel.ui_testing.models import ExplorationResult


def _create_sample_scan_result() -> ScanExecutionResult:
    apk = APKMetadata(
        file_path="demo.apk",
        file_size_bytes=1048576,
        file_size_mb=1.0,
        sha256="abc123sha256",
        package_name="com.example.demo",
        version_name="2.1.0",
        version_code=21,
        min_sdk=26,
        target_sdk=34,
        app_label="DemoApp",
        launcher_activity="com.example.demo.MainActivity",
        is_flutter=False,
    )
    meta = ScanMetadata(
        scan_id="SCAN-TEST-001",
        app_path="demo.apk",
        app_hash_sha256="abc123sha256",
        app_name="DemoApp",
        package_name="com.example.demo",
    )
    findings = [
        Finding(
            id="F-EXPORTED-ACT",
            title="Exported Activity Without Guard",
            category=FindingCategory.ATTACK_SURFACE,
            severity=Severity.HIGH,
            confidence=0.9,
            description="Exported activity with raw AWS key AKIAIOSFODNN7EXAMPLE",
            impact="Unauthorized activity invocation",
            recommendation="Set android:exported=false",
            evidence={"key": "AKIAIOSFODNN7EXAMPLE", "password": "password=SuperSecret123"},
        ),
        Finding(
            id="F-CLEARTEXT",
            title="Cleartext HTTP Traffic Permitted",
            category=FindingCategory.NETWORK,
            severity=Severity.MEDIUM,
            confidence=0.85,
            description="Cleartext HTTP is enabled in manifest",
            impact="Network traffic eavesdropping",
            recommendation="Enforce TLS in network_security_config.xml",
        ),
    ]
    risk = RiskScoreSummary(
        overall_score=72.0,
        security_score=65.0,
        stability_score=90.0,
        performance_score=85.0,
        ux_score=80.0,
        accessibility_score=75.0,
        risk_level="MEDIUM",
        high_count=1,
        medium_count=1,
    )
    exploration = ExplorationResult(
        screens_discovered=5,
        screens_explored=5,
        actions_tested=12,
        screen_coverage_pct=83.3,
        action_coverage_pct=75.0,
    )

    return ScanExecutionResult(
        scan_id="SCAN-TEST-001",
        metadata=meta,
        apk_meta=apk,
        device_name="emulator-5554",
        findings=findings,
        risk_summary=risk,
        runtime_summary={"Installation": "PASS", "Launch": "PASS", "Crash": "PASS"},
        exploration_result=exploration,
        failure_analyses=[{
            "failure_category": "crash",
            "title": "Main Thread NullPointer",
            "likely_root_cause": "Null view reference in onClick",
            "affected_component": "com.example.demo",
        }],
        security_explanations=[{
            "finding_id": "F-EXPORTED-ACT",
            "plain_title": "Unprotected Screen Exposed",
            "simplified_explanation": "Screen can be opened by other apps",
            "urgency": "IMMEDIATE",
        }],
    )


def test_successful_ai_report_generation():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "executive_summary": "Comprehensive AI Executive Summary for DemoApp.",
        "quality_assessment": "Application demonstrates solid runtime stability with areas for security hardening.",
        "security_summary": "Identified 2 security findings: 1 High severity exported activity.",
        "stability_summary": "Runtime execution completed without critical fatal crashes.",
        "crash_summary": "Observed 1 minor non-fatal exception during button click.",
        "screen_insights": ["Discovered 5 core application screens.", "Auth screen detected."],
        "test_recommendations": ["Add regression tests for exported activities."],
        "critical_priorities": ["Close exported activity in AndroidManifest.xml."],
        "remediation_recommendations": ["Set android:exported=false for internal screens."],
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    report = generator.generate_report(scan_res)

    assert report.is_ai_generated is True
    assert "Comprehensive AI Executive Summary" in report.executive_summary
    assert "solid runtime stability" in report.quality_assessment
    assert "2 security findings" in report.security_summary
    assert len(report.screen_insights) == 2
    assert len(report.critical_priorities) == 1
    assert "mock" in report.provider_used.lower()


def test_ai_disabled_mode():
    client = AIClient(AIConfig(enabled=False))
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    report = generator.generate_report(scan_res)

    assert report.is_ai_generated is False
    assert "DemoApp" in report.executive_summary
    assert "com.example.demo" in report.executive_summary
    assert report.provider_used == "deterministic_fallback"
    assert "65.0/100" in report.executive_summary


def test_provider_unavailable_fallback():
    mock_prov = MockLLMProvider()

    def fail_network(prompt, system, json_mode):
        raise AIProviderNetworkError("Failed to connect to AI provider API")

    mock_prov.set_custom_handler(fail_network)
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    report = generator.generate_report(scan_res)

    # Must fallback cleanly without raising exception
    assert report.is_ai_generated is False
    assert report.executive_summary != ""
    assert report.provider_used == "deterministic_fallback"


def test_malformed_json_response_fallback():
    mock_prov = MockLLMProvider(canned_responses=["NOT VALID JSON {{{ broken content"])
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    report = generator.generate_report(scan_res)

    assert report.is_ai_generated is False
    assert report.executive_summary != ""
    assert "DemoApp" in report.executive_summary


def test_empty_scan_results():
    client = AIClient(AIConfig(enabled=False))
    generator = ReportGenerator(client)

    # Completely empty invocation
    report = generator.generate_report(None)
    assert report.is_ai_generated is False
    assert report.executive_summary != ""
    assert "0 security and QA findings" in report.executive_summary


def test_security_severity_preservation():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "executive_summary": "Test Summary",
        "quality_assessment": "Test Quality",
        "security_summary": "Test Security",
        "stability_summary": "Test Stability",
        "crash_summary": "Test Crash",
        "screen_insights": ["Insight 1"],
        "test_recommendations": ["Test 1"],
        "critical_priorities": ["Priority 1"],
        "remediation_recommendations": ["Fix 1"],
    })
    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    orig_severities = [f.severity for f in scan_res.findings]

    generator.generate_report(scan_res)

    # Verify input findings severities were not altered
    current_severities = [f.severity for f in scan_res.findings]
    assert current_severities == orig_severities
    assert scan_res.findings[0].severity == Severity.HIGH
    assert scan_res.findings[1].severity == Severity.MEDIUM


def test_risk_score_preservation():
    mock_prov = MockLLMProvider()
    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    orig_score = scan_res.risk_summary.overall_score
    orig_sec = scan_res.risk_summary.security_score

    generator.generate_report(scan_res)

    # Risk scores must remain exact deterministic values
    assert scan_res.risk_summary.overall_score == orig_score
    assert scan_res.risk_summary.security_score == orig_sec
    assert scan_res.risk_summary.risk_level == "MEDIUM"


def test_no_fabricated_findings():
    mock_prov = MockLLMProvider()
    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    initial_findings_count = len(scan_res.findings)

    generator.generate_report(scan_res)

    # Generator must never append or delete confirmed findings
    assert len(scan_res.findings) == initial_findings_count


def test_sensitive_information_redaction():
    mock_prov = MockLLMProvider()
    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    generator.generate_report(scan_res)

    assert len(mock_prov.call_history) == 1
    sent_prompt = mock_prov.call_history[0]["prompt"]

    # Raw secrets must never appear in prompt
    assert "AKIAIOSFODNN7EXAMPLE" not in sent_prompt
    assert "[REDACTED_AWS_KEY]" in sent_prompt
    assert "SuperSecret123" not in sent_prompt
    assert "password=[REDACTED]" in sent_prompt


def test_deterministic_fallback():
    client = AIClient(AIConfig(enabled=False))
    generator = ReportGenerator(client)

    scan_res = _create_sample_scan_result()
    report = generator.generate_report(scan_res)

    assert report.is_ai_generated is False
    assert len(report.screen_insights) >= 2
    assert len(report.test_recommendations) >= 3
    assert len(report.critical_priorities) >= 1
    assert "Exported Activity Without Guard" in report.critical_priorities[0]
    assert len(report.remediation_recommendations) >= 1
    assert "android:exported=false" in report.remediation_recommendations[0]


def test_correct_serialization():
    report = AIReportSummary(
        executive_summary="Summary Text",
        quality_assessment="Quality Text",
        security_summary="Security Text",
        stability_summary="Stability Text",
        crash_summary="Crash Text",
        screen_insights=["Screen 1"],
        test_recommendations=["Test 1"],
        critical_priorities=["Priority 1"],
        remediation_recommendations=["Fix 1"],
        is_ai_generated=True,
    )

    data = report.to_dict()
    assert "executive_summary" in data
    assert "quality_assessment" in data
    assert "security_summary" in data
    assert "stability_summary" in data
    assert "crash_summary" in data
    assert "screen_insights" in data
    assert "test_recommendations" in data
    assert "critical_priorities" in data
    assert "remediation_recommendations" in data
    assert data["is_ai_generated"] is True

    # JSON serializability check
    json_str = json.dumps(data)
    assert "Summary Text" in json_str

    restored = AIReportSummary.from_dict(json.loads(json_str))
    assert restored.executive_summary == "Summary Text"
    assert restored.quality_assessment == "Quality Text"
    assert restored.security_summary == "Security Text"
    assert restored.screen_insights == ["Screen 1"]
    assert restored.is_ai_generated is True
