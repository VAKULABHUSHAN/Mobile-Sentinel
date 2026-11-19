"""Contextual test scenario and validation test case generator for Android application screens."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from sentinel.ai.client import AIClient
from sentinel.ai.models import GeneratedTestCase, ScreenUnderstanding
from sentinel.ai.prompts import build_test_generation_prompt
from sentinel.core.logging import logger
from sentinel.ui_testing.models import ScreenState, UIElement
from sentinel.ui_testing.safety import SafetyClassifier

TEST_CATEGORIES = [
    "Functional testing",
    "Input validation",
    "Boundary testing",
    "Navigation testing",
    "UI interaction testing",
    "Authentication testing",
    "Accessibility testing",
]


class TestGenerator:
    """Generates structured, grounded, safe test cases for application screens."""

    __test__ = False  # Prevent pytest from treating TestGenerator as a test class

    def __init__(self, ai_client: Optional[AIClient] = None, safety_classifier: Optional[SafetyClassifier] = None):
        self.client = ai_client or AIClient()
        self.safety = safety_classifier or SafetyClassifier()

    def _match_target_element(
        self,
        target_name: Optional[str],
        state: ScreenState,
    ) -> Optional[UIElement]:
        """Grounds a target element name to an actual UIElement in the view hierarchy."""
        if not target_name:
            return None

        clean_name = target_name.strip().lower()

        # 1. Exact match on element_id
        for elem in state.elements:
            if elem.element_id == target_name:
                return elem

        # 2. Exact match on display_name or resource_id
        for elem in state.interactive_elements:
            if clean_name == elem.display_name.lower():
                return elem
            if elem.resource_id and clean_name in elem.resource_id.lower():
                return elem

        # 3. Substring match on text or content_desc
        for elem in state.interactive_elements:
            if elem.text and clean_name in elem.text.lower():
                return elem
            if elem.content_desc and clean_name in elem.content_desc.lower():
                return elem

        # 4. Semantic match by element type
        for elem in state.interactive_elements:
            if "button" in clean_name and elem.element_type == "button":
                return elem
            if ("input" in clean_name or "field" in clean_name or "text" in clean_name) and elem.element_type in ("edit_text", "password_field"):
                return elem

        return None

    def _classify_risk_level(self, action_name: str, test_desc: str) -> str:
        """Determines risk level using SafetyClassifier rules to prevent unauthorized destruction."""
        combined = f"{action_name} {test_desc}".lower()
        if any(re.search(pat, combined) for pat in SafetyClassifier.DESTRUCTIVE_PATTERNS):
            return "DESTRUCTIVE"
        if any(re.search(pat, combined) for pat in SafetyClassifier.CAUTION_PATTERNS):
            return "CAUTION"
        return "SAFE"

    def generate_tests(
        self,
        state: ScreenState,
        understanding: ScreenUnderstanding,
        has_authorized_credentials: bool = False,
        max_tests: int = 7,
    ) -> List[GeneratedTestCase]:
        """Generates contextual test scenarios for the given screen state."""
        # 1. If AI is disabled, generate deterministic baseline tests
        if not self.client.is_enabled:
            return self._generate_deterministic_tests(state, understanding, has_authorized_credentials, max_tests)

        # 2. Extract screen context and query LLM
        screen_info = {
            "screen_name": state.screen_name,
            "screen_type": understanding.screen_type,
            "purpose": understanding.screen_purpose,
            "interactive_elements": [
                {
                    "id": e.element_id,
                    "name": e.display_name,
                    "type": e.element_type,
                    "resource_id": e.resource_id,
                    "password": e.password,
                    "safety": e.safety_class,
                }
                for e in state.interactive_elements[:25]
            ],
            "input_fields": understanding.input_fields,
            "validation_opportunities": understanding.validation_opportunities,
        }

        prompt = build_test_generation_prompt(
            screen_info=screen_info,
            screen_type=understanding.screen_type,
            has_authorized_credentials=has_authorized_credentials,
        )

        ai_dict = self.client.generate_json(
            prompt=prompt,
            cache_key=f"tests_{state.state_id}_{has_authorized_credentials}",
        )

        # 3. Fallback if response is empty or malformed
        if not ai_dict or "test_cases" not in ai_dict or not isinstance(ai_dict["test_cases"], list):
            logger.warning(f"[TestGenerator] AI returned invalid test response for {state.screen_name}. Falling back to deterministic tests.")
            return self._generate_deterministic_tests(state, understanding, has_authorized_credentials, max_tests)

        # 4. Parse, validate, ground, and deduplicate test cases
        valid_tests: List[GeneratedTestCase] = []
        seen_signatures: Set[str] = set()
        test_counter = 1

        for raw in ai_dict["test_cases"]:
            if not isinstance(raw, dict):
                continue

            test_name = str(raw.get("name", f"Test {test_counter}")).strip()
            desc = str(raw.get("description", "")).strip()
            action = str(raw.get("suggested_action", "tap")).strip().lower()
            val_type = str(raw.get("validation_type", "general")).strip()
            raw_target = raw.get("target_element") or raw.get("target_element_description") or raw.get("target_element_id")

            # Ground target element against actual hierarchy
            matched_elem = self._match_target_element(raw_target, state)

            target_id = matched_elem.element_id if matched_elem else None
            target_display = matched_elem.display_name if matched_elem else (raw_target or state.screen_name)

            # Classify risk strictly
            risk = self._classify_risk_level(test_name, desc)

            # Deduplication key
            sig = f"{state.screen_name}:{action}:{target_id or target_display}:{val_type}".lower()
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)

            # Map category
            cat = str(raw.get("category", raw.get("test_category", "")))
            if cat not in TEST_CATEGORIES:
                if understanding.screen_type == "LOGIN" or "auth" in test_name.lower():
                    cat = "Authentication testing"
                elif val_type in ("empty_field", "invalid_format"):
                    cat = "Input validation"
                elif val_type == "boundary_value":
                    cat = "Boundary testing"
                elif action == "scroll" or "tab" in target_display.lower():
                    cat = "Navigation testing"
                elif state.accessibility_issues and "accessibility" in test_name.lower():
                    cat = "Accessibility testing"
                else:
                    cat = "Functional testing"

            test_case = GeneratedTestCase(
                test_id=f"TC-AI-{test_counter:03d}",
                name=test_name,
                description=desc or f"Validate {action} on {target_display}",
                target_screen=state.screen_name,
                category=cat,
                preconditions=str(raw.get("preconditions", "Screen is visible in foreground")),
                suggested_action=action,
                target_element_id=target_id,
                target_element_description=target_display,
                target_element=target_display,
                test_input=raw.get("test_input"),
                expected_outcome=str(raw.get("expected_outcome", "Application handles action properly without crash")),
                risk_level=risk,
                reason=str(raw.get("reason", "Verify UI integrity and input safety")),
                validation_type=val_type,
                is_ai_generated=True,
            )

            valid_tests.append(test_case)
            test_counter += 1
            if len(valid_tests) >= max_tests:
                break

        # Fallback if no valid tests could be grounded
        if not valid_tests:
            return self._generate_deterministic_tests(state, understanding, has_authorized_credentials, max_tests)

        return valid_tests

    def _generate_deterministic_tests(
        self,
        state: ScreenState,
        understanding: ScreenUnderstanding,
        has_authorized_credentials: bool,
        max_tests: int,
    ) -> List[GeneratedTestCase]:
        """Generates deterministic, evidence-backed test scenarios when AI is unavailable."""
        tests: List[GeneratedTestCase] = []
        counter = 1

        input_elements = [e for e in state.interactive_elements if e.element_type in ("edit_text", "password_field")]
        button_elements = [e for e in state.interactive_elements if e.element_type in ("button", "tab")]

        # 1. Form and input validation tests
        for inp in input_elements[:2]:
            # Empty submission test
            tests.append(
                GeneratedTestCase(
                    test_id=f"TC-DET-{counter:03d}",
                    name=f"Empty Input Validation: '{inp.display_name}'",
                    description=f"Attempt form submission or defocus with '{inp.display_name}' left empty.",
                    target_screen=state.screen_name,
                    category="Input validation",
                    preconditions=f"'{inp.display_name}' field is visible and empty",
                    suggested_action="type_text",
                    target_element_id=inp.element_id,
                    target_element_description=inp.display_name,
                    target_element=inp.display_name,
                    test_input="",
                    expected_outcome="Field displays required field validation error without crashing",
                    risk_level="SAFE",
                    reason="Verify proper required field validation handling",
                    validation_type="empty_field",
                    is_ai_generated=False,
                )
            )
            counter += 1

            # Invalid format test
            is_email = "email" in inp.display_name.lower() or "mail" in inp.display_name.lower()
            synth_input = "invalid-format-test" if is_email else "A" * 60
            tests.append(
                GeneratedTestCase(
                    test_id=f"TC-DET-{counter:03d}",
                    name=f"Format Validation: '{inp.display_name}'",
                    description=f"Enter malformed input '{synth_input}' into '{inp.display_name}'.",
                    target_screen=state.screen_name,
                    category="Boundary testing" if len(synth_input) > 50 else "Input validation",
                    preconditions=f"'{inp.display_name}' is interactive",
                    suggested_action="type_text",
                    target_element_id=inp.element_id,
                    target_element_description=inp.display_name,
                    target_element=inp.display_name,
                    test_input=synth_input,
                    expected_outcome="Application displays format error and prevents invalid processing",
                    risk_level="SAFE",
                    reason="Verify boundary and format checking",
                    validation_type="invalid_format",
                    is_ai_generated=False,
                )
            )
            counter += 1

        # 2. Authentication specific test
        if understanding.screen_type == "LOGIN":
            if has_authorized_credentials:
                tests.append(
                    GeneratedTestCase(
                        test_id=f"TC-DET-{counter:03d}",
                        name="Authorized Test Account Login",
                        description="Execute end-to-end authentication using pre-approved test credentials.",
                        target_screen=state.screen_name,
                        category="Authentication testing",
                        preconditions="Credentials configured in Sentinel auth config",
                        suggested_action="tap",
                        target_element_description="Login Button",
                        target_element="Login Button",
                        test_input=None,
                        expected_outcome="User authenticated and transitioned to home dashboard",
                        risk_level="SAFE",
                        reason="Validate full authorized user login flow",
                        validation_type="valid_flow",
                        is_ai_generated=False,
                    )
                )
            else:
                tests.append(
                    GeneratedTestCase(
                        test_id=f"TC-DET-{counter:03d}",
                        name="Invalid Password Handling",
                        description="Submit login form with incorrect credentials to verify error rejection.",
                        target_screen=state.screen_name,
                        category="Authentication testing",
                        preconditions="Login screen active with no authorized credentials",
                        suggested_action="tap",
                        target_element_description="Login Button",
                        target_element="Login Button",
                        test_input=None,
                        expected_outcome="Login rejected with 'Invalid Credentials' alert",
                        risk_level="SAFE",
                        reason="Verify unauthenticated rejection",
                        validation_type="button_behavior",
                        is_ai_generated=False,
                    )
                )
            counter += 1

        # 3. Interactive button tests
        for btn in button_elements[:2]:
            risk = self._classify_risk_level(btn.display_name, "")
            tests.append(
                GeneratedTestCase(
                    test_id=f"TC-DET-{counter:03d}",
                    name=f"Interactive Tap: '{btn.display_name}'",
                    description=f"Perform standard user tap on '{btn.display_name}'.",
                    target_screen=state.screen_name,
                    category="Navigation testing" if btn.element_type == "tab" else "UI interaction testing",
                    preconditions=f"'{btn.display_name}' is enabled and clickable",
                    suggested_action="tap",
                    target_element_id=btn.element_id,
                    target_element_description=btn.display_name,
                    target_element=btn.display_name,
                    test_input=None,
                    expected_outcome="Control responds visually and navigates smoothly",
                    risk_level=risk,
                    reason=f"Verify {btn.display_name} interaction",
                    validation_type="navigation" if btn.element_type == "tab" else "button_behavior",
                    is_ai_generated=False,
                )
            )
            counter += 1

        # 4. Accessibility compliance test if issues exist
        if state.accessibility_issues:
            a11y_issue = state.accessibility_issues[0]
            tests.append(
                GeneratedTestCase(
                    test_id=f"TC-DET-{counter:03d}",
                    name=f"Accessibility Verification: {a11y_issue.issue_type}",
                    description=f"Verify control '{a11y_issue.element_id}' satisfies accessibility standards.",
                    target_screen=state.screen_name,
                    category="Accessibility testing",
                    preconditions="Accessibility service / TalkBack inspection",
                    suggested_action="wait",
                    target_element_id=a11y_issue.element_id,
                    target_element_description="Accessibility Target",
                    target_element="Accessibility Target",
                    test_input=None,
                    expected_outcome="Control provides 48dp touch target and semantic content description",
                    risk_level="SAFE",
                    reason="Verify accessibility compliance",
                    validation_type="general",
                    is_ai_generated=False,
                )
            )

        return tests[:max_tests]
