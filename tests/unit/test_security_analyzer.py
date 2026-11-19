"""Unit tests for SecurityAnalyzer (plain-English explanations, severity/evidence preservation, and secret redaction)."""

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.provider import AIProviderError, MockLLMProvider
from sentinel.ai.security_analyzer import SecurityAnalyzer
from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import Finding


def _create_sample_finding() -> Finding:
    return Finding(
        id="ANDROID_EXPORTED_ACTIVITY",
        title="Exported Activity Accessible to Third-Party Apps",
        category=FindingCategory.ATTACK_SURFACE,
        severity=Severity.HIGH,
        confidence=0.95,
        description="Activity com.example.app.SecretActivity is declared with android:exported=true.",
        impact="Any application installed on the device can launch this internal screen without permission.",
        recommendation="Set android:exported=false or attach a signature-level permission guard.",
        evidence={"activity_name": "com.example.app.SecretActivity", "intent_filters": 0},
    )


def _create_secret_finding() -> Finding:
    return Finding(
        id="SECRETS_AWS_ACCESS_KEY",
        title="Hardcoded AWS Access Key in Binary",
        category=FindingCategory.SECRETS,
        severity=Severity.CRITICAL,
        confidence=1.0,
        description="Embedded AWS key detected: AKIAIOSFODNN7EXAMPLE in assets/config.json",
        impact="Compromise of cloud storage buckets and AWS infrastructure.",
        recommendation="Revoke the AWS access key immediately and migrate to IAM roles.",
        evidence={"raw_key": "AKIAIOSFODNN7EXAMPLE", "file": "assets/config.json"},
    )


def test_security_finding_explanation():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "finding_id": "ANDROID_EXPORTED_ACTIVITY",
        "plain_title": "Unprotected Internal Screen Exposed",
        "simplified_explanation": "An internal screen in your app is visible to any other app on the phone.",
        "attack_scenario": "A malicious app sends an intent to launch SecretActivity and reads user data.",
        "business_impact": "Unauthorized access to private features and potential data leakage.",
        "remediation_guide": "Add android:exported='false' in your AndroidManifest.xml.",
        "urgency": "IMMEDIATE",
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    analyzer = SecurityAnalyzer(client)

    finding = _create_sample_finding()
    explanation = analyzer.explain_finding(finding)

    # Invariants verification
    assert explanation.finding_id == "ANDROID_EXPORTED_ACTIVITY"
    assert explanation.original_title == finding.title
    assert explanation.urgency == "IMMEDIATE"
    assert explanation.is_ai_generated is True
    assert "Unprotected Internal Screen" in explanation.plain_title
    assert explanation.evidence == finding.evidence


def test_original_severity_and_id_preservation():
    client = AIClient(AIConfig(enabled=False))
    analyzer = SecurityAnalyzer(client)

    f_high = _create_sample_finding()
    exp_high = analyzer.explain_finding(f_high)
    assert exp_high.finding_id == f_high.id
    assert exp_high.urgency == "IMMEDIATE"  # High severity maps to IMMEDIATE urgency

    f_crit = _create_secret_finding()
    exp_crit = analyzer.explain_finding(f_crit)
    assert exp_crit.finding_id == f_crit.id
    assert exp_crit.urgency == "IMMEDIATE"


def test_no_fabricated_findings():
    client = AIClient(AIConfig(enabled=False))
    analyzer = SecurityAnalyzer(client)

    input_findings = [_create_sample_finding(), _create_secret_finding()]
    explanations = analyzer.explain_all_findings(input_findings)

    # Exactly 2 explanations matching the exact 2 input findings
    assert len(explanations) == 2
    assert [e.finding_id for e in explanations] == [f.id for f in input_findings]


def test_secret_redaction_before_ai_prompt():
    mock_prov = MockLLMProvider()
    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    analyzer = SecurityAnalyzer(client)

    finding = _create_secret_finding()
    analyzer.explain_finding(finding)

    assert len(mock_prov.call_history) == 1
    sent_prompt = mock_prov.call_history[0]["prompt"]

    # Verify that the raw AWS key was redacted before being transmitted
    assert "AKIAIOSFODNN7EXAMPLE" not in sent_prompt
    assert "[REDACTED_AWS_KEY]" in sent_prompt


def test_invalid_ai_response_fallback():
    mock_prov = MockLLMProvider(canned_responses=["NOT VALID JSON"])
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    analyzer = SecurityAnalyzer(client)

    finding = _create_sample_finding()
    explanation = analyzer.explain_finding(finding)

    # Must fallback cleanly to deterministic explanation
    assert explanation.finding_id == finding.id
    assert explanation.is_ai_generated is False
    assert explanation.simplified_explanation == finding.description


def test_provider_failure_fallback():
    mock_prov = MockLLMProvider()

    def err_fn(p, s, j):
        raise AIProviderError("Provider failure")

    mock_prov.set_custom_handler(err_fn)
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    analyzer = SecurityAnalyzer(client)

    finding = _create_sample_finding()
    explanation = analyzer.explain_finding(finding)

    assert explanation.finding_id == finding.id
    assert explanation.is_ai_generated is False
