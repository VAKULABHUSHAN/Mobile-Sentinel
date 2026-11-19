"""Unit tests for ExplorationAdvisor and its safe integration with UIExplorer."""

import json
from unittest.mock import MagicMock, patch

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.exploration_advisor import ExplorationAdvisor
from sentinel.ai.models import ScreenUnderstanding
from sentinel.ai.provider import AIProviderError, MockLLMProvider
from sentinel.runtime.adb import ADBController
from sentinel.ui_testing.explorer import UIExplorer
from sentinel.ui_testing.models import ScreenState, StateGraph, UIElement
from sentinel.ui_testing.safety import SafetyClassifier


def _create_test_state() -> Tuple[ScreenState, StateGraph]:
    graph = StateGraph()
    btn1 = UIElement(
        element_id="elem_btn1",
        element_type="button",
        text="View Details",
        content_desc="View Details",
        clickable=True,
        bounds=(10, 10, 200, 80),
        safety_class="SAFE",
    )
    btn2 = UIElement(
        element_id="elem_btn2",
        element_type="button",
        text="Add New Item",
        content_desc="Add New Item",
        clickable=True,
        bounds=(10, 100, 200, 180),
        safety_class="SAFE",
    )
    btn_del = UIElement(
        element_id="elem_del",
        element_type="button",
        text="Clear All Data",
        content_desc="Clear All Data",
        clickable=True,
        bounds=(10, 200, 200, 280),
        safety_class="DESTRUCTIVE",
    )

    state = ScreenState(
        state_id="state_main_001",
        screen_name="MainDashboard",
        package="com.example.app",
        elements=[btn1, btn2, btn_del],
        interactive_elements=[btn1, btn2, btn_del],
        visible_text=["Dashboard", "View Details", "Add New Item", "Clear All Data"],
    )

    key1 = "tap:button:view details:2,0"
    key2 = "tap:button:add new item:2,2"
    key_del = "tap:button:clear all data:2,4"

    state.add_pending_action(key1, btn1, "tap")
    state.add_pending_action(key2, btn2, "tap")
    state.action_candidate_map[key_del] = (btn_del, "tap")  # Destructive action

    graph.add_state(state)
    return state, graph


def test_valid_exploration_recommendation():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "recommended_action_key": "tap:button:add new item:2,2",
        "target_description": "Add New Item",
        "action_type": "tap",
        "priority": 9,
        "reason": "Test high value item creation flow",
        "workflow_goal": "Creation flow",
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    advisor = ExplorationAdvisor(client)

    state, graph = _create_test_state()
    # Initially, key1 is at index 0, key2 is at index 1
    assert state.pending_action_ids[0] == "tap:button:view details:2,0"

    rec = advisor.recommend_next_action(state, graph)
    assert rec is not None
    assert rec.target_element_id == "elem_btn2"
    assert rec.priority == 9
    assert rec.is_ai_generated is True

    # Prioritize should move key2 to index 0
    advisor.prioritize_pending_actions(state, rec)
    assert state.pending_action_ids[0] == "tap:button:add new item:2,2"


def test_recommendation_nonexistent_element_fallback():
    mock_prov = MockLLMProvider()
    # Recommends an element that does NOT exist in pending actions
    mock_prov.add_canned_response({
        "recommended_action_key": "nonexistent_action_key",
        "target_description": "Ghost Element That Does Not Exist",
        "priority": 8,
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    advisor = ExplorationAdvisor(client)

    state, graph = _create_test_state()
    rec = advisor.recommend_next_action(state, graph)

    assert rec is not None
    # Must fallback to deterministic recommendation without crashing
    assert rec.is_ai_generated is False
    assert rec.recommended_action_key in state.pending_action_ids


def test_destructive_recommendation_safely_blocked():
    mock_prov = MockLLMProvider()
    # LLM recommends the destructive "Clear All Data" action
    mock_prov.add_canned_response({
        "recommended_action_key": "tap:button:clear all data:2,4",
        "target_description": "Clear All Data",
        "priority": 10,
    })
    # Next canned response for fallback safe action
    mock_prov.add_canned_response({
        "recommended_action_key": "tap:button:add new item:2,2",
        "target_description": "Add New Item",
        "priority": 7,
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    advisor = ExplorationAdvisor(client)

    state, graph = _create_test_state()
    # Add destructive action temporarily to pending to test advisor safety interception
    state.add_pending_action("tap:button:clear all data:2,4", state.elements[2], "tap")

    rec = advisor.recommend_next_action(state, graph)
    assert rec is not None
    # Destructive action must be blocked and excluded
    assert "clear all data" not in rec.target_description.lower()
    assert "tap:button:clear all data:2,4" in state.blocked_action_ids


def test_invalid_ai_response_fallback():
    mock_prov = MockLLMProvider(canned_responses=["NOT VALID JSON"])
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    advisor = ExplorationAdvisor(client)

    state, graph = _create_test_state()
    rec = advisor.recommend_next_action(state, graph)

    assert rec is not None
    assert rec.is_ai_generated is False
    assert rec.recommended_action_key == "tap:button:view details:2,0"


def test_provider_failure_fallback():
    mock_prov = MockLLMProvider()

    def err_fn(p, s, j):
        raise AIProviderError("Provider unavailable")

    mock_prov.set_custom_handler(err_fn)
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    advisor = ExplorationAdvisor(client)

    state, graph = _create_test_state()
    rec = advisor.recommend_next_action(state, graph)

    assert rec is not None
    assert rec.is_ai_generated is False


def test_ai_disabled_mode():
    client = AIClient(AIConfig(enabled=False))
    advisor = ExplorationAdvisor(client)
    assert advisor.is_enabled is False

    state, graph = _create_test_state()
    rec = advisor.recommend_next_action(state, graph)
    assert rec is not None
    assert rec.is_ai_generated is False
    assert rec.recommended_action_key == "tap:button:view details:2,0"


def test_recommendation_caching():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "recommended_action_key": "tap:button:view details:2,0",
        "target_description": "View Details",
        "priority": 8,
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    advisor = ExplorationAdvisor(client)

    state, graph = _create_test_state()
    r1 = advisor.recommend_next_action(state, graph)
    assert len(mock_prov.call_history) == 1

    r2 = advisor.recommend_next_action(state, graph)
    assert len(mock_prov.call_history) == 1
    assert r1 == r2


def test_uiexplorer_integration_prioritizes_ai_action(tmp_path):
    # Integration test showing UIExplorer reordering actions based on advisor recommendations
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "recommended_action_key": "tap:button:add new item:2,2",
        "target_description": "Add New Item",
        "priority": 10,
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    advisor = ExplorationAdvisor(client)

    adb = MagicMock(spec=ADBController)
    adb.get_foreground_package.return_value = "com.example.app"
    adb.is_running.return_value = True
    adb.run_shell.return_value = (0, "Success", "")

    state, _ = _create_test_state()

    explorer = UIExplorer(
        package_name="com.example.app",
        adb=adb,
        exploration_advisor=advisor,
        max_total_actions=1,
    )

    with patch.object(explorer, "_capture_current_state", return_value=state):
        result = explorer.explore("emulator-5554", tmp_path)
        assert result is not None
        # Verify that the action executed was the AI-prioritized "Add New Item" action
        executed_calls = [c[0][0] for c in adb.run_shell.call_args_list if len(c[0]) > 0 and len(c[0][0]) > 1 and c[0][0][1] == "tap"]
        assert len(executed_calls) >= 1
        # Center of elem_btn2 is [105, 140]
        assert executed_calls[0] == ["input", "tap", "105", "140"]


def test_uiexplorer_destructive_actions_never_executed(tmp_path):
    adb = MagicMock(spec=ADBController)
    adb.get_foreground_package.return_value = "com.example.app"
    adb.is_running.return_value = True
    adb.run_shell.return_value = (0, "Success", "")

    state, _ = _create_test_state()

    explorer = UIExplorer(
        package_name="com.example.app",
        adb=adb,
        max_total_actions=2,
    )

    with patch.object(explorer, "_capture_current_state", return_value=state):
        result = explorer.explore("emulator-5554", tmp_path)
        # Verify destructive control was discovered but NOT executed
        assert result.destructive_actions_discovered >= 1
        for act in result.graph.discovered_destructive_controls:
            assert act.status == "DISCOVERED_NOT_EXECUTED"
