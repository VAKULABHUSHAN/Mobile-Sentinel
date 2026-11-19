"""Unit tests for AI data models, bounding, and serialization."""

from sentinel.ai.models import (
    AIReportSummary,
    AIResponse,
    ExplorationRecommendation,
    FailureAnalysis,
    GeneratedTestCase,
    ScreenUnderstanding,
    SecurityExplanation,
)


def test_screen_understanding_bounds_confidence():
    model = ScreenUnderstanding(
        screen_purpose="Login page",
        screen_type="LOGIN",
        confidence=1.5,  # Exceeds 1.0, should clamp
    )
    assert model.confidence == 1.0
    assert model.screen_type == "LOGIN"
    assert model.is_auth_screen is True

    data = model.to_dict()
    assert data["screen_type"] == "LOGIN"
    assert data["confidence"] == 1.0

    restored = ScreenUnderstanding.from_dict(data)
    assert restored.screen_purpose == "Login page"
    assert restored.screen_type == "LOGIN"
    assert restored.is_auth_screen is True


def test_generated_test_case_bounds_risk():
    tc = GeneratedTestCase(
        test_id="TC-001",
        name="Test Case",
        description="Description",
        target_screen="LoginScreen",
        risk_level="invalid_risk",  # Invalid, should default to SAFE
    )
    assert tc.risk_level == "SAFE"

    tc_destructive = GeneratedTestCase(
        test_id="TC-002",
        name="Delete Account",
        description="Delete user",
        target_screen="ProfileScreen",
        risk_level="DESTRUCTIVE",
    )
    assert tc_destructive.risk_level == "DESTRUCTIVE"

    d = tc_destructive.to_dict()
    restored = GeneratedTestCase.from_dict(d)
    assert restored.risk_level == "DESTRUCTIVE"


def test_exploration_recommendation_priority_clamping():
    rec = ExplorationRecommendation(
        target_description="Button",
        priority=20,  # Exceeds 10, should clamp
    )
    assert rec.priority == 10

    rec_low = ExplorationRecommendation(
        target_description="Button",
        priority=-5,  # Sub-zero, should clamp to 1
    )
    assert rec_low.priority == 1


def test_failure_analysis_confirmed_bug_invariant():
    fa = FailureAnalysis(
        title="App Freeze",
        severity="UNKNOWN_SEV",
        confidence=-0.2,
    )
    assert fa.severity == "LOW"
    assert fa.confidence == 0.0
    assert fa.is_confirmed_bug is False  # Must remain False for hypotheses


def test_security_explanation_urgency():
    se = SecurityExplanation(
        finding_id="ANDROID_EXPORTED_ACTIVITY",
        plain_title="Exported Activity Risk",
        simplified_explanation="Allows other apps to launch this screen",
        attack_scenario="Attacker sends explicit intent",
        business_impact="Unauthorized screen access",
        remediation_guide="Set android:exported=false",
        urgency="IMMEDIATE",
    )
    assert se.urgency == "IMMEDIATE"
    d = se.to_dict()
    restored = SecurityExplanation.from_dict(d)
    assert restored.finding_id == "ANDROID_EXPORTED_ACTIVITY"
    assert restored.urgency == "IMMEDIATE"


def test_ai_report_summary():
    report = AIReportSummary(
        executive_summary="Executive summary text",
        technical_analysis="Technical analysis text",
        critical_observations=["Observation 1"],
        prioritized_recommendations=["Recommendation 1"],
    )
    d = report.to_dict()
    assert d["executive_summary"] == "Executive summary text"
    assert "Observation 1" in d["critical_observations"]
