"""Screen understanding engine analyzing UI hierarchy, interactive controls, and visual semantics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sentinel.ai.client import AIClient
from sentinel.ai.models import ScreenUnderstanding
from sentinel.ai.prompts import build_screen_understanding_prompt
from sentinel.core.logging import logger
from sentinel.ui_testing.models import ScreenState, UIElement

ALLOWED_SCREEN_TYPES: Set[str] = {
    "LOGIN",
    "REGISTRATION",
    "DASHBOARD",
    "PROFILE",
    "SETTINGS",
    "FORM",
    "LIST",
    "DETAIL",
    "PAYMENT",
    "DIALOG",
    "ONBOARDING",
    "UNKNOWN",
}


class ScreenAnalyzer:
    """Interprets Android screen hierarchies into structured semantic understanding."""

    def __init__(self, ai_client: Optional[AIClient] = None):
        self.client = ai_client or AIClient()
        self._analysis_cache: Dict[str, ScreenUnderstanding] = {}

    def extract_screen_context(self, state: ScreenState) -> Dict[str, Any]:
        """Extracts structured, sanitized summary of ScreenState for LLM analysis."""
        elements_summary = []
        for elem in state.interactive_elements[:35]:  # Limit to 35 most prominent interactive controls
            elements_summary.append({
                "element_id": elem.element_id,
                "type": elem.element_type,
                "name": elem.display_name,
                "resource_id": elem.resource_id,
                "clickable": elem.clickable,
                "password": elem.password,
                "bounds": list(elem.bounds),
                "safety_class": elem.safety_class,
            })

        visible_sample = [t for t in state.visible_text if t.strip()][:30]

        a11y_summary = [
            {"type": issue.issue_type, "title": issue.title, "element_id": issue.element_id}
            for issue in state.accessibility_issues[:10]
        ]

        return {
            "screen_name": state.screen_name,
            "activity": state.activity or "UnknownActivity",
            "package": state.package,
            "interactive_elements_count": len(state.interactive_elements),
            "visible_text_sample": visible_sample,
            "interactive_controls": elements_summary,
            "accessibility_observations": a11y_summary,
            "heuristic_flags": {
                "is_login_screen": state.is_login_screen,
                "is_registration_screen": state.is_registration_screen,
                "is_onboarding_screen": state.is_onboarding_screen,
            },
        }

    def _normalize_screen_type(self, raw_type: Optional[str], state: ScreenState) -> str:
        """Normalizes and bounds screen type to supported categories."""
        if not raw_type:
            raw_type = "UNKNOWN"

        clean = raw_type.strip().upper().replace("_SCREEN", "").replace(" ", "_")

        # Map variations
        if clean in ("SIGNIN", "LOG_IN", "SIGN_IN", "AUTH"):
            clean = "LOGIN"
        elif clean in ("SIGNUP", "REGISTER", "SIGN_UP", "CREATE_ACCOUNT"):
            clean = "REGISTRATION"
        elif clean in ("HOME", "MAIN", "OVERVIEW", "FEED"):
            clean = "DASHBOARD"
        elif clean in ("ACCOUNT", "USER_PROFILE"):
            clean = "PROFILE"
        elif clean in ("PREFERENCES", "CONFIG"):
            clean = "SETTINGS"
        elif clean in ("CHECKOUT", "BILLING"):
            clean = "PAYMENT"
        elif clean in ("MODAL", "POPUP", "ALERT"):
            clean = "DIALOG"
        elif clean in ("TUTORIAL", "WELCOME", "INTRO", "WIZARD"):
            clean = "ONBOARDING"

        if clean not in ALLOWED_SCREEN_TYPES:
            # Fallback to state heuristics if invalid
            if state.is_login_screen:
                clean = "LOGIN"
            elif state.is_registration_screen:
                clean = "REGISTRATION"
            elif state.is_onboarding_screen:
                clean = "ONBOARDING"
            else:
                clean = "UNKNOWN"

        return clean

    def _match_elements_against_hierarchy(
        self,
        referenced_names: List[str],
        actual_elements: List[UIElement],
    ) -> List[str]:
        """Validates AI-referenced elements against the actual view hierarchy to prevent hallucinations.
        
        Returns the list of valid element_ids belonging to actual UI elements.
        """
        matched_ids: List[str] = []
        actual_id_map: Dict[str, UIElement] = {e.element_id: e for e in actual_elements}

        for ref in referenced_names:
            ref_clean = ref.strip().lower()
            if not ref_clean:
                continue

            # Check direct element_id match
            if ref in actual_id_map and ref not in matched_ids:
                matched_ids.append(ref)
                continue

            # Check match against display_name, text, resource_id, or content_desc
            for elem in actual_elements:
                elem_name = elem.display_name.lower()
                res_id = elem.resource_id.lower()
                text = elem.text.lower()
                desc = elem.content_desc.lower()

                if (
                    ref_clean == elem_name
                    or (res_id and ref_clean in res_id)
                    or (text and ref_clean == text)
                    or (desc and ref_clean == desc)
                ):
                    if elem.element_id not in matched_ids:
                        matched_ids.append(elem.element_id)
                        break

        return matched_ids

    def analyze(
        self,
        state: ScreenState,
        screenshot_path: Optional[str | Path] = None,
    ) -> ScreenUnderstanding:
        """Performs semantic understanding of a ScreenState with fallback to deterministic heuristics."""
        # 1. Check in-memory state cache
        if state.state_id in self._analysis_cache:
            return self._analysis_cache[state.state_id]

        # 2. Extract structured screen data
        screen_info = self.extract_screen_context(state)

        # 3. If AI is not enabled or available, generate deterministic fallback understanding
        if not self.client.is_enabled:
            fallback = self._generate_deterministic_fallback(state)
            self._analysis_cache[state.state_id] = fallback
            return fallback

        # 4. Invoke LLM via AIClient
        prompt = build_screen_understanding_prompt(screen_info)
        ai_dict = self.client.generate_json(
            prompt=prompt,
            cache_key=f"screen_understanding_{state.state_id}",
        )

        # 5. Handle empty or malformed LLM response
        if not ai_dict or not isinstance(ai_dict, dict):
            logger.warning(f"[ScreenAnalyzer] LLM returned invalid or empty response for state {state.state_id}. Using fallback.")
            fallback = self._generate_deterministic_fallback(state)
            self._analysis_cache[state.state_id] = fallback
            return fallback

        # 6. Normalize category and validate fields
        raw_type = ai_dict.get("screen_type") or ai_dict.get("category")
        normalized_type = self._normalize_screen_type(raw_type, state)

        # 7. Match AI key elements against actual hierarchy
        raw_key_elements = list(ai_dict.get("key_elements", []))
        matched_ids = self._match_elements_against_hierarchy(raw_key_elements, state.elements)

        # Collect interactive controls & inputs from actual elements
        actual_interactive = [e.display_name for e in state.interactive_elements]
        actual_inputs = [e.display_name for e in state.interactive_elements if e.element_type in ("edit_text", "password_field")]

        # Determine validation opportunities
        val_opps = []
        if actual_inputs:
            val_opps.append("Empty required input field submission")
            val_opps.append("Invalid format boundary check")
        if normalized_type == "LOGIN":
            val_opps.append("Invalid password error display")
            val_opps.append("Password visibility toggle")

        understanding = ScreenUnderstanding(
            screen_purpose=str(ai_dict.get("screen_purpose", f"{normalized_type.title()} interface")),
            screen_type=normalized_type,
            summary=str(ai_dict.get("summary", f"{state.screen_name} with {len(state.interactive_elements)} controls")),
            key_elements=raw_key_elements[:10],
            interactive_controls=actual_interactive[:15],
            input_fields=actual_inputs[:10],
            navigation_possibilities=list(ai_dict.get("navigation_possibilities", []))[:10],
            validation_opportunities=val_opps,
            missing_states=list(ai_dict.get("missing_states", []))[:5],
            usability_issues=list(ai_dict.get("usability_issues", []))[:5],
            accessibility_issues=list(ai_dict.get("accessibility_issues", []))[:5],
            is_auth_screen=(normalized_type in ("LOGIN", "REGISTRATION")),
            has_form=(len(actual_inputs) > 0 or normalized_type in ("FORM", "LOGIN", "REGISTRATION", "PROFILE")),
            matched_element_ids=matched_ids,
            confidence=float(ai_dict.get("confidence", 0.85)),
            is_ai_generated=True,
        )

        self._analysis_cache[state.state_id] = understanding
        return understanding

    def _generate_deterministic_fallback(self, state: ScreenState) -> ScreenUnderstanding:
        """Builds a deterministic, heuristic-based ScreenUnderstanding when AI is unavailable."""
        inputs = [e.display_name for e in state.interactive_elements if e.element_type in ("edit_text", "password_field")]
        interactive = [e.display_name for e in state.interactive_elements]

        if state.is_login_screen:
            screen_type = "LOGIN"
            purpose = "User authentication and login gateway"
        elif state.is_registration_screen:
            screen_type = "REGISTRATION"
            purpose = "New user account registration"
        elif state.is_onboarding_screen:
            screen_type = "ONBOARDING"
            purpose = "Application introduction, tutorial, or onboarding wizard"
        elif "home" in state.screen_name.lower() or "dashboard" in state.screen_name.lower() or any("dashboard" in t.lower() or "account summary" in t.lower() for t in state.visible_text):
            screen_type = "DASHBOARD"
            purpose = "Main application home and dashboard overview"
        elif len(inputs) >= 2:
            screen_type = "FORM"
            purpose = "User data collection form"
        elif any(e.element_type == "scrollable" for e in state.elements):
            screen_type = "LIST"
            purpose = "Data list and item browsing screen"
        elif any("settings" in t.lower() or "preference" in t.lower() for t in state.visible_text):
            screen_type = "SETTINGS"
            purpose = "Application preferences and settings configuration"
        elif any("profile" in t.lower() or "user profile" in t.lower() for t in state.visible_text):
            screen_type = "PROFILE"
            purpose = "User profile overview and management"
        else:
            screen_type = "DASHBOARD" if len(interactive) >= 2 else "UNKNOWN"
            purpose = f"{state.screen_name} application view"

        val_opps = []
        if inputs:
            val_opps.append("Empty required input field submission")
            val_opps.append("Invalid format boundary check")

        return ScreenUnderstanding(
            screen_purpose=purpose,
            screen_type=screen_type,
            summary=f"Deterministic analysis of {state.screen_name} with {len(state.interactive_elements)} interactive controls",
            key_elements=interactive[:8],
            interactive_controls=interactive[:15],
            input_fields=inputs[:10],
            navigation_possibilities=[e for e in interactive if "button" in e.lower() or "tab" in e.lower()][:5],
            validation_opportunities=val_opps,
            missing_states=["Loading state", "Network error retry state"],
            usability_issues=[],
            accessibility_issues=[i.title for i in state.accessibility_issues[:5]],
            is_auth_screen=(screen_type in ("LOGIN", "REGISTRATION")),
            has_form=(len(inputs) > 0 or screen_type in ("FORM", "LOGIN", "REGISTRATION", "PROFILE")),
            matched_element_ids=[e.element_id for e in state.interactive_elements[:10]],
            confidence=0.75,
            is_ai_generated=False,
        )
