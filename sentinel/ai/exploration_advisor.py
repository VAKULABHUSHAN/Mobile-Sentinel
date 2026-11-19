"""Intelligent exploration advisor guiding autonomous UI traversal towards high-value screens."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from sentinel.ai.client import AIClient
from sentinel.ai.models import ExplorationRecommendation, GeneratedTestCase, ScreenUnderstanding
from sentinel.ai.prompts import build_exploration_advisor_prompt
from sentinel.core.logging import logger
from sentinel.ui_testing.models import ScreenState, StateGraph, UIElement
from sentinel.ui_testing.safety import SafetyClassifier


class ExplorationAdvisor:
    """Advises UIExplorer on optimal, safe action prioritization during autonomous testing."""

    def __init__(
        self,
        ai_client: Optional[AIClient] = None,
        safety_classifier: Optional[SafetyClassifier] = None,
    ):
        self.client = ai_client or AIClient()
        self.safety = safety_classifier or SafetyClassifier()
        self._recommendation_cache: Dict[str, ExplorationRecommendation] = {}

    @property
    def is_enabled(self) -> bool:
        return self.client.is_enabled

    def _match_action_to_pending(
        self,
        target_name: Optional[str],
        state: ScreenState,
    ) -> Optional[Tuple[str, UIElement]]:
        """Matches a target element name or ID to an active key in state.pending_action_ids."""
        if not target_name:
            return None

        clean = target_name.strip().lower()

        # 1. Exact match on action_key
        if target_name in state.pending_action_ids:
            elem, _ = state.action_candidate_map[target_name]
            return target_name, elem

        # 2. Match on element_id in pending map
        for ak in state.pending_action_ids:
            elem, _ = state.action_candidate_map[ak]
            if elem.element_id == target_name:
                return ak, elem

        # 3. Match on display_name or resource_id
        for ak in state.pending_action_ids:
            elem, _ = state.action_candidate_map[ak]
            if clean == elem.display_name.lower():
                return ak, elem
            if elem.resource_id and clean in elem.resource_id.lower():
                return ak, elem

        # 4. Substring match on text or content_desc
        for ak in state.pending_action_ids:
            elem, _ = state.action_candidate_map[ak]
            if elem.text and clean in elem.text.lower():
                return ak, elem
            if elem.content_desc and clean in elem.content_desc.lower():
                return ak, elem

        return None

    def recommend_next_action(
        self,
        state: ScreenState,
        graph: StateGraph,
        understanding: Optional[ScreenUnderstanding] = None,
        generated_tests: Optional[List[GeneratedTestCase]] = None,
    ) -> Optional[ExplorationRecommendation]:
        """Recommends the highest-value safe action to test next from the current state."""
        if not state.pending_action_ids:
            return None

        # 1. Check recommendation cache for this screen state
        cache_key = f"{state.state_id}_p_{len(state.pending_action_ids)}"
        if cache_key in self._recommendation_cache:
            return self._recommendation_cache[cache_key]

        # 2. If AI is disabled, generate deterministic recommendation
        if not self.is_enabled:
            rec = self._generate_deterministic_recommendation(state)
            self._recommendation_cache[cache_key] = rec
            return rec

        # 3. Build candidate actions summary for the LLM
        candidate_summaries = []
        for ak in state.pending_action_ids[:15]:
            elem, act_type = state.action_candidate_map[ak]
            candidate_summaries.append({
                "action_key": ak,
                "element_id": elem.element_id,
                "display_name": elem.display_name,
                "type": elem.element_type,
                "resource_id": elem.resource_id,
                "action": act_type,
                "safety": elem.safety_class,
            })

        current_screen_info = {
            "screen_name": state.screen_name,
            "purpose": understanding.screen_purpose if understanding else "Application screen",
            "screen_type": understanding.screen_type if understanding else "UNKNOWN",
            "visited_count": state.visit_count,
            "unexplored_actions_count": len(state.pending_action_ids),
        }

        visited_screens = [s.screen_name for s in graph.states.values()]

        prompt = build_exploration_advisor_prompt(
            current_screen=current_screen_info,
            candidate_actions=candidate_summaries,
            visited_screens=visited_screens,
        )

        ai_dict = self.client.generate_json(prompt=prompt, cache_key=cache_key)

        # 4. Handle malformed or empty response
        if not ai_dict or not isinstance(ai_dict, dict):
            logger.warning(f"[ExplorationAdvisor] LLM returned invalid recommendation for {state.screen_name}. Using deterministic fallback.")
            rec = self._generate_deterministic_recommendation(state)
            self._recommendation_cache[cache_key] = rec
            return rec

        # 5. Extract and ground recommendation
        raw_key = ai_dict.get("recommended_action_key")
        raw_target = ai_dict.get("target_description") or ai_dict.get("target_element_id") or raw_key

        matched = self._match_action_to_pending(raw_key, state) or self._match_action_to_pending(raw_target, state)

        if not matched:
            logger.info(f"[ExplorationAdvisor] AI suggested non-pending or nonexistent element '{raw_target}'. Using deterministic fallback.")
            rec = self._generate_deterministic_recommendation(state)
            self._recommendation_cache[cache_key] = rec
            return rec

        action_key, elem = matched

        # 6. Safety enforcement: check for destructive actions
        is_destructive = elem.safety_class == "DESTRUCTIVE" or any(
            re.search(pat, elem.display_name, re.IGNORECASE) for pat in SafetyClassifier.DESTRUCTIVE_PATTERNS
        )

        if is_destructive:
            logger.warning(
                f"[ExplorationAdvisor] AI recommended DESTRUCTIVE action '{elem.display_name}'. "
                "Excluding from autonomous execution per safety policy."
            )
            state.mark_action_blocked(action_key)
            # Re-run recommendation on remaining pending actions
            return self.recommend_next_action(state, graph, understanding, generated_tests)

        # 7. Build validated recommendation
        rec = ExplorationRecommendation(
            recommendation_id=f"REC-AI-{len(graph.transitions) + 1:03d}",
            target_screen=state.screen_name,
            target_element_id=elem.element_id,
            target_description=elem.display_name,
            suggested_action=str(ai_dict.get("action_type", "tap")).lower(),
            recommended_action_key=action_key,
            suggested_input=ai_dict.get("suggested_input"),
            priority=int(ai_dict.get("priority", 8)),
            expected_value=str(ai_dict.get("workflow_goal", "Explore new screen")),
            reason=str(ai_dict.get("reason", f"High value action on {elem.display_name}")),
            workflow_goal=str(ai_dict.get("workflow_goal", "Deep screen traversal")),
            risk_level="SAFE",
            alternative_paths=list(ai_dict.get("alternative_paths", [])),
            is_ai_generated=True,
        )

        self._recommendation_cache[cache_key] = rec
        return rec

    def prioritize_pending_actions(
        self,
        state: ScreenState,
        recommendation: Optional[ExplorationRecommendation],
    ) -> List[str]:
        """Reorders state.pending_action_ids so the recommended action is evaluated first."""
        if not recommendation or not recommendation.recommended_action_key:
            return state.pending_action_ids

        rec_key = recommendation.recommended_action_key
        if rec_key in state.pending_action_ids:
            state.pending_action_ids.remove(rec_key)
            state.pending_action_ids.insert(0, rec_key)
            logger.info(f"[ExplorationAdvisor] Prioritized action '{rec_key}' to front of frontier.")

        return state.pending_action_ids

    def _generate_deterministic_recommendation(self, state: ScreenState) -> Optional[ExplorationRecommendation]:
        """Provides a safe deterministic fallback recommendation."""
        if not state.pending_action_ids:
            return None

        first_key = state.pending_action_ids[0]
        elem, act_type = state.action_candidate_map[first_key]

        return ExplorationRecommendation(
            recommendation_id="REC-DET-001",
            target_screen=state.screen_name,
            target_element_id=elem.element_id,
            target_description=elem.display_name,
            suggested_action=act_type,
            recommended_action_key=first_key,
            priority=5,
            expected_value="Deterministic frontier traversal",
            reason="Next available action in deterministic priority order",
            workflow_goal="Autonomous DFS traversal",
            risk_level=elem.safety_class,
            is_ai_generated=False,
        )
