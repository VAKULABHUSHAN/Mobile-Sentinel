"""Unit tests for TestGenerator (contextual test case generation, grounding, deduplication, and limits)."""

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.models import ScreenUnderstanding
from sentinel.ai.provider import AIProviderError, MockLLMProvider
from sentinel.ai.test_generator import TestGenerator
from sentinel.ui_testing.models import ScreenState, UIElement


def _create_form_state() -> ScreenState:
    name_field = UIElement(
        element_id="elem_name",
        element_type="edit_text",
        text="Full Name",
        content_desc="Full Name",
        clickable=True,
        bounds=(50, 100, 500, 180),
    )
    email_field = UIElement(
        element_id="elem_email",
        element_type="edit_text",
        text="Email Address",
        content_desc="Email Address",
        clickable=True,
        bounds=(50, 200, 500, 280),
    )
    submit_btn = UIElement(
        element_id="elem_submit",
        element_type="button",
        text="Submit Profile",
        content_desc="Submit Profile",
        clickable=True,
        bounds=(50, 320, 500, 400),
    )
    return ScreenState(
        state_id="state_form_001",
        screen_name="ProfileFormScreen",
        package="com.example.app",
        elements=[name_field, email_field, submit_btn],
        interactive_elements=[name_field, email_field, submit_btn],
        visible_text=["Edit Profile", "Full Name", "Email Address", "Submit Profile"],
    )


def _create_login_state() -> ScreenState:
    email_field = UIElement(
        element_id="elem_login_email",
        element_type="edit_text",
        text="User Email",
        content_desc="Email",
        clickable=True,
        bounds=(50, 150, 500, 230),
    )
    pwd_field = UIElement(
        element_id="elem_login_pwd",
        element_type="password_field",
        text="Password",
        content_desc="Password",
        clickable=True,
        password=True,
        bounds=(50, 250, 500, 330),
    )
    login_btn = UIElement(
        element_id="elem_login_btn",
        element_type="button",
        text="Sign In",
        content_desc="Sign In",
        clickable=True,
        bounds=(50, 360, 500, 440),
    )
    delete_btn = UIElement(
        element_id="elem_delete_btn",
        element_type="button",
        text="Delete Account",
        content_desc="Delete Account",
        clickable=True,
        bounds=(50, 500, 500, 580),
        safety_class="DESTRUCTIVE",
    )
    return ScreenState(
        state_id="state_login_001",
        screen_name="LoginScreen",
        package="com.example.app",
        elements=[email_field, pwd_field, login_btn, delete_btn],
        interactive_elements=[email_field, pwd_field, login_btn, delete_btn],
        visible_text=["Welcome Back", "User Email", "Password", "Sign In", "Delete Account"],
        is_login_screen=True,
    )


def test_test_generation_for_forms():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "test_cases": [
            {
                "test_id": "TC-AI-001",
                "name": "Empty Name Submission",
                "description": "Leave full name empty and tap submit",
                "target_element": "Full Name",
                "suggested_action": "type_text",
                "test_input": "",
                "expected_outcome": "Field validation error",
                "validation_type": "empty_field",
                "risk_level": "SAFE",
            },
            {
                "test_id": "TC-AI-002",
                "name": "Invalid Email Format",
                "description": "Enter invalid email syntax",
                "target_element": "Email Address",
                "suggested_action": "type_text",
                "test_input": "notanemail",
                "expected_outcome": "Email syntax error",
                "validation_type": "invalid_format",
                "risk_level": "SAFE",
            },
        ]
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = TestGenerator(client)

    state = _create_form_state()
    understanding = ScreenUnderstanding(screen_purpose="Edit profile form", screen_type="FORM")

    tests = generator.generate_tests(state, understanding)
    assert len(tests) == 2
    assert tests[0].target_element_id == "elem_name"
    assert tests[1].target_element_id == "elem_email"
    assert tests[0].validation_type == "empty_field"


def test_test_generation_for_authentication_unauthorized():
    # When no authorized credentials exist, login tests must NOT attempt real valid login
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "test_cases": [
            {
                "test_id": "TC-AI-001",
                "name": "Empty Password Validation",
                "description": "Attempt login with empty password",
                "target_element": "Password",
                "suggested_action": "type_text",
                "test_input": "",
                "expected_outcome": "Password required error",
                "validation_type": "empty_field",
                "risk_level": "SAFE",
            }
        ]
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = TestGenerator(client)

    state = _create_login_state()
    understanding = ScreenUnderstanding(screen_purpose="Login screen", screen_type="LOGIN")

    tests = generator.generate_tests(state, understanding, has_authorized_credentials=False)
    assert len(tests) >= 1
    assert any(t.validation_type == "empty_field" for t in tests)


def test_duplicate_test_elimination():
    mock_prov = MockLLMProvider()
    # Provide two identical test cases targeting the same element and action
    mock_prov.add_canned_response({
        "test_cases": [
            {
                "test_id": "TC-001",
                "name": "Test Tap Submit",
                "description": "Tap submit button",
                "target_element": "Submit Profile",
                "suggested_action": "tap",
                "validation_type": "button_behavior",
            },
            {
                "test_id": "TC-002",
                "name": "Duplicate Tap Submit",
                "description": "Tap submit button again",
                "target_element": "Submit Profile",
                "suggested_action": "tap",
                "validation_type": "button_behavior",
            },
        ]
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = TestGenerator(client)

    state = _create_form_state()
    understanding = ScreenUnderstanding(screen_purpose="Profile form", screen_type="FORM")

    tests = generator.generate_tests(state, understanding)
    # The duplicate test must be eliminated
    assert len(tests) == 1


def test_test_generation_limits():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "test_cases": [
            {"name": f"Test {i}", "target_element": f"Element {i}", "validation_type": f"v_{i}"}
            for i in range(10)
        ]
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = TestGenerator(client)

    state = _create_form_state()
    understanding = ScreenUnderstanding(screen_purpose="Profile form", screen_type="FORM")

    tests = generator.generate_tests(state, understanding, max_tests=3)
    assert len(tests) <= 3


def test_ai_disabled_mode_generates_deterministic_tests():
    client = AIClient(AIConfig(enabled=False))
    generator = TestGenerator(client)

    state = _create_form_state()
    understanding = ScreenUnderstanding(screen_purpose="Profile form", screen_type="FORM")

    tests = generator.generate_tests(state, understanding)
    assert len(tests) > 0
    # Deterministic tests should have is_ai_generated=False
    for t in tests:
        assert t.is_ai_generated is False
        assert t.target_screen == "ProfileFormScreen"


def test_provider_failure_fallback():
    mock_prov = MockLLMProvider()

    def err_handler(p, s, j):
        raise AIProviderError("Provider unavailable")

    mock_prov.set_custom_handler(err_handler)

    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    generator = TestGenerator(client)

    state = _create_login_state()
    understanding = ScreenUnderstanding(screen_purpose="Login screen", screen_type="LOGIN")

    tests = generator.generate_tests(state, understanding)
    assert len(tests) > 0
    # Must fallback to deterministic tests cleanly
    for t in tests:
        assert t.is_ai_generated is False


def test_destructive_operation_risk_classification():
    mock_prov = MockLLMProvider()
    # LLM recommends tapping "Delete Account"
    mock_prov.add_canned_response({
        "test_cases": [
            {
                "test_id": "TC-DEL",
                "name": "Delete User Account",
                "description": "Trigger account deletion from screen",
                "target_element": "Delete Account",
                "suggested_action": "tap",
                "validation_type": "destructive_op",
            }
        ]
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    generator = TestGenerator(client)

    state = _create_login_state()
    understanding = ScreenUnderstanding(screen_purpose="Login screen", screen_type="LOGIN")

    tests = generator.generate_tests(state, understanding)
    assert len(tests) == 1
    # Must be classified as DESTRUCTIVE
    assert tests[0].risk_level == "DESTRUCTIVE"
