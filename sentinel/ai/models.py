"""Structured dataclass models and validation for Sentinel AI Intelligence Layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class AIResponse:
    """Standardized response from any LLM provider."""

    raw_text: str
    parsed_json: Optional[Dict[str, Any]] = None
    provider: str = ""
    model: str = ""
    duration_seconds: float = 0.0
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    is_mock: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScreenUnderstanding:
    """Structured comprehension of an Android application screen."""

    screen_purpose: str = "Unknown screen purpose"
    screen_type: str = "UNKNOWN"  # LOGIN, REGISTRATION, DASHBOARD, PROFILE, SETTINGS, FORM, LIST, DETAIL, PAYMENT, DIALOG, ONBOARDING, UNKNOWN
    summary: str = ""
    key_elements: List[str] = field(default_factory=list)
    interactive_controls: List[str] = field(default_factory=list)
    input_fields: List[str] = field(default_factory=list)
    navigation_possibilities: List[str] = field(default_factory=list)
    validation_opportunities: List[str] = field(default_factory=list)
    missing_states: List[str] = field(default_factory=list)
    usability_issues: List[str] = field(default_factory=list)
    accessibility_issues: List[str] = field(default_factory=list)
    is_auth_screen: bool = False
    has_form: bool = False
    matched_element_ids: List[str] = field(default_factory=list)
    confidence: float = 0.8
    is_ai_generated: bool = True

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        raw_type = (self.screen_type or "UNKNOWN").strip().upper()
        allowed = {
            "LOGIN", "REGISTRATION", "DASHBOARD", "PROFILE", "SETTINGS",
            "FORM", "LIST", "DETAIL", "PAYMENT", "DIALOG", "ONBOARDING", "UNKNOWN"
        }
        self.screen_type = raw_type if raw_type in allowed else "UNKNOWN"
        if self.screen_type in ("LOGIN", "REGISTRATION"):
            self.is_auth_screen = True
        if self.screen_type in ("FORM", "LOGIN", "REGISTRATION", "PROFILE"):
            self.has_form = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScreenUnderstanding:
        raw_type = str(data.get("screen_type", data.get("category", "UNKNOWN"))).strip().upper()
        return cls(
            screen_purpose=str(data.get("screen_purpose", "Unknown screen purpose")),
            screen_type=raw_type,
            summary=str(data.get("summary", "")),
            key_elements=list(data.get("key_elements", [])),
            interactive_controls=list(data.get("interactive_controls", [])),
            input_fields=list(data.get("input_fields", [])),
            navigation_possibilities=list(data.get("navigation_possibilities", [])),
            validation_opportunities=list(data.get("validation_opportunities", [])),
            missing_states=list(data.get("missing_states", [])),
            usability_issues=list(data.get("usability_issues", [])),
            accessibility_issues=list(data.get("accessibility_issues", [])),
            is_auth_screen=bool(data.get("is_auth_screen", raw_type in ("LOGIN", "REGISTRATION"))),
            has_form=bool(data.get("has_form", raw_type in ("FORM", "LOGIN", "REGISTRATION", "PROFILE"))),
            matched_element_ids=list(data.get("matched_element_ids", [])),
            confidence=float(data.get("confidence", 0.8)),
            is_ai_generated=bool(data.get("is_ai_generated", True)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GeneratedTestCase:
    """An AI-generated contextual test scenario for a specific screen."""

    test_id: str
    name: str
    description: str
    target_screen: str
    category: str = "Functional testing"  # Functional testing, Input validation, Boundary testing, Navigation testing, UI interaction testing, Authentication testing, Accessibility testing
    preconditions: str = "Application running and target screen in foreground"
    suggested_action: str = "tap"  # tap, type_text, scroll, back, wait
    target_element_id: Optional[str] = None
    target_element_description: str = ""
    target_element: Optional[str] = None  # Human-readable target element name/selector
    test_input: Optional[str] = None
    expected_outcome: str = ""
    risk_level: str = "SAFE"  # SAFE, CAUTION, DESTRUCTIVE
    reason: str = ""
    validation_type: str = "general"  # empty_field, invalid_format, boundary_value, valid_flow, button_behavior, navigation, general
    is_ai_generated: bool = True

    def __post_init__(self) -> None:
        self.risk_level = (self.risk_level or "SAFE").strip().upper()
        if self.risk_level not in ("SAFE", "CAUTION", "DESTRUCTIVE"):
            self.risk_level = "SAFE"

        self.suggested_action = (self.suggested_action or "tap").strip().lower()
        if not self.target_element:
            self.target_element = self.target_element_description or self.target_element_id or "Screen"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GeneratedTestCase:
        target_elem = data.get("target_element") or data.get("target_element_description") or data.get("target_element_id")
        return cls(
            test_id=str(data.get("test_id", "TC-AI-001")),
            name=str(data.get("name", "Unnamed Test Case")),
            description=str(data.get("description", "")),
            target_screen=str(data.get("target_screen", "CurrentScreen")),
            category=str(data.get("category", data.get("test_category", "Functional testing"))),
            preconditions=str(data.get("preconditions", "Screen is visible")),
            suggested_action=str(data.get("suggested_action", "tap")),
            target_element_id=data.get("target_element_id"),
            target_element_description=str(data.get("target_element_description", "")),
            target_element=str(target_elem) if target_elem else None,
            test_input=data.get("test_input"),
            expected_outcome=str(data.get("expected_outcome", "")),
            risk_level=str(data.get("risk_level", "SAFE")),
            reason=str(data.get("reason", "")),
            validation_type=str(data.get("validation_type", "general")),
            is_ai_generated=bool(data.get("is_ai_generated", True)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExplorationRecommendation:
    """An AI recommendation for the next safe UI action to explore."""

    recommendation_id: str = "REC-AI-001"
    target_screen: str = ""
    target_element_id: Optional[str] = None
    target_description: str = ""
    suggested_action: str = "tap"  # tap, type_text, scroll, back
    action_type: str = "tap"  # alias for suggested_action
    recommended_action_key: Optional[str] = None
    suggested_input: Optional[str] = None
    priority: int = 5  # 1 (lowest) to 10 (highest)
    expected_value: str = "Discover new screen or validate interactive flow"
    reason: str = ""
    workflow_goal: str = ""
    risk_level: str = "SAFE"  # SAFE, CAUTION, DESTRUCTIVE
    alternative_paths: List[str] = field(default_factory=list)
    is_ai_generated: bool = True

    def __post_init__(self) -> None:
        self.priority = max(1, min(10, int(self.priority)))
        self.suggested_action = (self.suggested_action or self.action_type or "tap").strip().lower()
        self.action_type = self.suggested_action
        self.risk_level = (self.risk_level or "SAFE").strip().upper()
        if self.risk_level not in ("SAFE", "CAUTION", "DESTRUCTIVE"):
            self.risk_level = "SAFE"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExplorationRecommendation:
        act = data.get("suggested_action") or data.get("action_type") or "tap"
        return cls(
            recommendation_id=str(data.get("recommendation_id", "REC-AI-001")),
            target_screen=str(data.get("target_screen", "")),
            target_element_id=data.get("target_element_id"),
            target_description=str(data.get("target_description", "")),
            suggested_action=str(act),
            action_type=str(act),
            recommended_action_key=data.get("recommended_action_key"),
            suggested_input=data.get("suggested_input"),
            priority=int(data.get("priority", 5)),
            expected_value=str(data.get("expected_value", "Discover new screen")),
            reason=str(data.get("reason", "")),
            workflow_goal=str(data.get("workflow_goal", "")),
            risk_level=str(data.get("risk_level", "SAFE")),
            alternative_paths=list(data.get("alternative_paths", [])),
            is_ai_generated=bool(data.get("is_ai_generated", True)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FailureAnalysis:
    """Analysis of a runtime anomaly, crash, or unexpected test outcome."""

    failure_id: str = "FAIL-AI-001"
    finding_id: str = "FAIL-AI-001"
    failure_category: str = "inconclusive"  # crash, anr, validation_success, unexpected_navigation, interaction_failure, permission_denied, network_error, environment_issue, inconclusive
    failure_type: str = "inconclusive"
    title: str = "Observed Execution Anomaly"
    description: str = ""
    likely_root_cause: str = ""
    possible_root_cause: str = ""
    supporting_evidence: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    affected_component: str = "Application"
    severity: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float = 0.5
    recommended_remediation: str = ""
    recommended_action: str = ""
    screen_name: str = ""
    test_case_id: Optional[str] = None
    reproduction_steps: List[str] = field(default_factory=list)
    is_confirmed_bug: bool = False  # False unless undeniable proof (e.g. fatal unhandled crash trace)
    is_ai_generated: bool = True

    def __post_init__(self) -> None:
        self.severity = (self.severity or "LOW").strip().upper()
        if self.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.severity = "LOW"
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

        if not self.finding_id:
            self.finding_id = self.failure_id
        if not self.failure_id:
            self.failure_id = self.finding_id

        if not self.failure_type:
            self.failure_type = self.failure_category
        if not self.failure_category:
            self.failure_category = self.failure_type

        if not self.possible_root_cause:
            self.possible_root_cause = self.likely_root_cause
        if not self.likely_root_cause:
            self.likely_root_cause = self.possible_root_cause

        if not self.evidence:
            self.evidence = self.supporting_evidence
        if not self.supporting_evidence:
            self.supporting_evidence = self.evidence

        if not self.recommended_action:
            self.recommended_action = self.recommended_remediation
        if not self.recommended_remediation:
            self.recommended_remediation = self.recommended_action

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FailureAnalysis:
        fid = str(data.get("failure_id") or data.get("finding_id") or "FAIL-AI-001")
        fcat = str(data.get("failure_category") or data.get("failure_type") or "inconclusive")
        root = str(data.get("likely_root_cause") or data.get("possible_root_cause") or "")
        ev = dict(data.get("supporting_evidence") or data.get("evidence") or {})
        remed = str(data.get("recommended_remediation") or data.get("recommended_action") or "")

        return cls(
            failure_id=fid,
            finding_id=fid,
            failure_category=fcat,
            failure_type=fcat,
            title=str(data.get("title", "Observed Execution Anomaly")),
            description=str(data.get("description", "")),
            likely_root_cause=root,
            possible_root_cause=root,
            supporting_evidence=ev,
            evidence=ev,
            affected_component=str(data.get("affected_component", "Application")),
            severity=str(data.get("severity", "LOW")),
            confidence=float(data.get("confidence", 0.5)),
            recommended_remediation=remed,
            recommended_action=remed,
            screen_name=str(data.get("screen_name", "")),
            test_case_id=data.get("test_case_id"),
            reproduction_steps=list(data.get("reproduction_steps", [])),
            is_confirmed_bug=bool(data.get("is_confirmed_bug", False)),
            is_ai_generated=bool(data.get("is_ai_generated", True)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityExplanation:
    """Human-readable interpretation and attack scenarios for static security findings."""

    finding_id: str
    original_title: str = ""
    plain_title: str = ""
    simplified_explanation: str = ""
    why_it_matters: str = ""
    business_impact: str = ""
    potential_impact: str = ""
    attack_scenario: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation_guide: str = ""
    recommended_remediation: str = ""
    confidence: float = 0.9
    urgency: str = "INFORMATIONAL"  # IMMEDIATE, NEAR_TERM, INFORMATIONAL
    is_ai_generated: bool = True

    def __post_init__(self) -> None:
        self.urgency = (self.urgency or "INFORMATIONAL").strip().upper()
        if self.urgency not in ("IMMEDIATE", "NEAR_TERM", "INFORMATIONAL"):
            self.urgency = "INFORMATIONAL"

        if not self.plain_title:
            self.plain_title = self.original_title
        if not self.original_title:
            self.original_title = self.plain_title

        if not self.business_impact:
            self.business_impact = self.why_it_matters
        if not self.why_it_matters:
            self.why_it_matters = self.business_impact

        if not self.attack_scenario:
            self.attack_scenario = self.potential_impact
        if not self.potential_impact:
            self.potential_impact = self.attack_scenario

        if not self.remediation_guide:
            self.remediation_guide = self.recommended_remediation
        if not self.recommended_remediation:
            self.recommended_remediation = self.remediation_guide

        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityExplanation:
        fid = str(data.get("finding_id", ""))
        title = str(data.get("plain_title") or data.get("original_title") or "")
        why = str(data.get("why_it_matters") or data.get("business_impact") or "")
        scenario = str(data.get("attack_scenario") or data.get("potential_impact") or "")
        remed = str(data.get("remediation_guide") or data.get("recommended_remediation") or "")

        return cls(
            finding_id=fid,
            original_title=title,
            plain_title=title,
            simplified_explanation=str(data.get("simplified_explanation", "")),
            why_it_matters=why,
            business_impact=why,
            potential_impact=scenario,
            attack_scenario=scenario,
            evidence=dict(data.get("evidence", {})),
            remediation_guide=remed,
            recommended_remediation=remed,
            confidence=float(data.get("confidence", 0.9)),
            urgency=str(data.get("urgency", "INFORMATIONAL")),
            is_ai_generated=bool(data.get("is_ai_generated", True)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AIReportSummary:
    """Consolidated AI-assisted summary generated for the audit report."""

    executive_summary: str = ""
    quality_assessment: str = ""
    security_summary: str = ""
    stability_summary: str = ""
    crash_summary: str = ""
    screen_insights: List[str] = field(default_factory=list)
    test_recommendations: List[str] = field(default_factory=list)
    critical_priorities: List[str] = field(default_factory=list)
    remediation_recommendations: List[str] = field(default_factory=list)

    # Aliases / backward compatibility with Phase 2 definitions:
    technical_analysis: str = ""
    functional_testing_summary: str = ""
    security_analysis_summary: str = ""
    coverage_analysis: str = ""
    critical_observations: List[str] = field(default_factory=list)
    prioritized_recommendations: List[str] = field(default_factory=list)
    provider_used: str = ""
    model_used: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_ai_generated: bool = True

    def __post_init__(self) -> None:
        if self.quality_assessment and not self.technical_analysis:
            self.technical_analysis = self.quality_assessment
        elif self.technical_analysis and not self.quality_assessment:
            self.quality_assessment = self.technical_analysis

        if self.security_summary and not self.security_analysis_summary:
            self.security_analysis_summary = self.security_summary
        elif self.security_analysis_summary and not self.security_summary:
            self.security_summary = self.security_analysis_summary

        if self.critical_priorities and not self.critical_observations:
            self.critical_observations = list(self.critical_priorities)
        elif self.critical_observations and not self.critical_priorities:
            self.critical_priorities = list(self.critical_observations)

        if self.remediation_recommendations and not self.prioritized_recommendations:
            self.prioritized_recommendations = list(self.remediation_recommendations)
        elif self.prioritized_recommendations and not self.remediation_recommendations:
            self.remediation_recommendations = list(self.prioritized_recommendations)

        if not self.crash_summary and self.stability_summary:
            self.crash_summary = self.stability_summary
        elif not self.stability_summary and self.crash_summary:
            self.stability_summary = self.crash_summary

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AIReportSummary:
        return cls(
            executive_summary=str(data.get("executive_summary", "")),
            quality_assessment=str(data.get("quality_assessment") or data.get("technical_analysis") or ""),
            security_summary=str(data.get("security_summary") or data.get("security_analysis_summary") or ""),
            stability_summary=str(data.get("stability_summary") or ""),
            crash_summary=str(data.get("crash_summary") or ""),
            screen_insights=list(data.get("screen_insights") or ([data.get("coverage_analysis")] if data.get("coverage_analysis") else [])),
            test_recommendations=list(data.get("test_recommendations") or ([data.get("functional_testing_summary")] if data.get("functional_testing_summary") else [])),
            critical_priorities=list(data.get("critical_priorities") or data.get("critical_observations") or []),
            remediation_recommendations=list(data.get("remediation_recommendations") or data.get("prioritized_recommendations") or []),
            technical_analysis=str(data.get("technical_analysis") or data.get("quality_assessment") or ""),
            functional_testing_summary=str(data.get("functional_testing_summary") or ""),
            security_analysis_summary=str(data.get("security_analysis_summary") or data.get("security_summary") or ""),
            coverage_analysis=str(data.get("coverage_analysis") or ""),
            critical_observations=list(data.get("critical_observations") or data.get("critical_priorities") or []),
            prioritized_recommendations=list(data.get("prioritized_recommendations") or data.get("remediation_recommendations") or []),
            provider_used=str(data.get("provider_used", "")),
            model_used=str(data.get("model_used", "")),
            generated_at=str(data.get("generated_at", datetime.now(timezone.utc).isoformat())),
            is_ai_generated=bool(data.get("is_ai_generated", True)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
