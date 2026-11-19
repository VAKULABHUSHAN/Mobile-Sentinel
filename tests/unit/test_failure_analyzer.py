"""Unit tests for FailureAnalyzer (crash, ANR, Flutter error triage, grounding, and fallbacks)."""

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.failure_analyzer import FailureAnalyzer
from sentinel.ai.provider import AIProviderError, MockLLMProvider

SAMPLE_CRASH_LOGCAT = """
04-12 10:20:15.123 1234 1234 D AndroidRuntime: Shutting down VM
04-12 10:20:15.124 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main
04-12 10:20:15.124 1234 1234 E AndroidRuntime: Process: com.example.app, PID: 1234
04-12 10:20:15.125 1234 1234 E AndroidRuntime: java.lang.NullPointerException: Null pointer dereference
04-12 10:20:15.125 1234 1234 E AndroidRuntime: 	at com.example.app.MainActivity.onClick(MainActivity.kt:45)
04-12 10:20:15.126 1234 1234 E AndroidRuntime: 	at android.view.View.performClick(View.java:7125)
"""

SAMPLE_ANR_LOGCAT = """
04-12 10:22:00.001 567 567 E ActivityManager: ANR in com.example.app (com.example.app/.MainActivity)
04-12 10:22:00.002 567 567 E ActivityManager: PID: 1234
04-12 10:22:00.003 567 567 E ActivityManager: Reason: Input dispatching timed out
04-12 10:22:00.004 567 567 E ActivityManager: Load: 5.2 / 4.1 / 3.0
"""

SAMPLE_FLUTTER_LOGCAT = """
04-12 10:25:30.500 1234 1250 I flutter : ════════ Exception caught by gesture ════════
04-12 10:25:30.501 1234 1250 I flutter : The following _CastError was thrown while handling a gesture:
04-12 10:25:30.502 1234 1250 I flutter : Null check operator used on a null value
04-12 10:25:30.503 1234 1250 I flutter : #0      _LoginScreenState._submit (login_screen.dart:88)
"""


def test_crash_analysis():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "title": "NullPointerException in MainActivity.onClick",
        "description": "Application encountered an unhandled NullPointerException during click handling.",
        "failure_type": "crash",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "possible_root_cause": "Attempting to access null object reference in onClick handler",
        "reproduction_steps": ["Launch app", "Tap button in MainActivity"],
        "recommended_action": "Add null check before accessing object on line 45",
        "is_confirmed_bug": True,
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    analyzer = FailureAnalyzer(client)

    results = analyzer.analyze_failures(SAMPLE_CRASH_LOGCAT, package_name="com.example.app")
    assert len(results) == 1
    crash = results[0]

    assert crash.failure_category == "crash"
    assert crash.severity == "CRITICAL"
    assert crash.is_confirmed_bug is True
    assert crash.is_ai_generated is True
    assert "NullPointerException" in crash.supporting_evidence["trace"]


def test_anr_analysis():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "title": "Main Thread Blocked: ANR in com.example.app",
        "description": "Application failed to respond to input within 5 seconds.",
        "failure_type": "anr",
        "severity": "CRITICAL",
        "confidence": 0.9,
        "possible_root_cause": "Heavy computational or I/O work performed on main thread",
        "recommended_action": "Move heavy operation to background worker or isolate",
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    analyzer = FailureAnalyzer(client)

    results = analyzer.analyze_failures(SAMPLE_ANR_LOGCAT, package_name="com.example.app")
    assert len(results) == 1
    anr = results[0]

    assert anr.failure_category == "anr"
    assert anr.severity == "CRITICAL"
    assert anr.is_confirmed_bug is True
    assert "Input dispatching timed out" in anr.supporting_evidence["trace"]


def test_flutter_exception_analysis():
    mock_prov = MockLLMProvider()
    mock_prov.add_canned_response({
        "title": "Dart CastError in _LoginScreenState",
        "description": "Flutter runtime caught a null check operator exception.",
        "failure_type": "flutter_exception",
        "severity": "HIGH",
        "confidence": 0.9,
        "possible_root_cause": "Null check assertion failed on uninitialized variable",
        "recommended_action": "Ensure variable is initialized before applying '!' operator",
    })

    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)
    analyzer = FailureAnalyzer(client)

    results = analyzer.analyze_failures(SAMPLE_FLUTTER_LOGCAT, package_name="com.example.app")
    assert len(results) == 1
    fl = results[0]

    assert fl.failure_category == "flutter_exception"
    assert fl.severity == "HIGH"
    assert fl.affected_component == "Flutter Engine"
    assert "Null check operator used" in fl.supporting_evidence["trace"]


def test_empty_logs_returns_empty():
    client = AIClient(AIConfig(enabled=True, provider="mock"))
    analyzer = FailureAnalyzer(client)

    assert analyzer.analyze_failures("", package_name="com.example.app") == []
    assert analyzer.analyze_failures("   \n\t  ", package_name="com.example.app") == []
    assert analyzer.analyze_failures("04-12 Normal app log without errors", package_name="com.example.app") == []


def test_invalid_ai_response_fallback():
    mock_prov = MockLLMProvider(canned_responses=["NOT VALID JSON"])
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    analyzer = FailureAnalyzer(client)

    results = analyzer.analyze_failures(SAMPLE_CRASH_LOGCAT, package_name="com.example.app")
    assert len(results) == 1
    fallback = results[0]

    assert fallback.is_ai_generated is False
    assert fallback.failure_category == "crash"
    assert fallback.severity == "CRITICAL"
    assert "Null pointer dereference" in fallback.supporting_evidence["trace"]


def test_provider_failure_fallback():
    mock_prov = MockLLMProvider()

    def fail_fn(p, s, j):
        raise AIProviderError("API failed")

    mock_prov.set_custom_handler(fail_fn)
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=0), provider=mock_prov)
    analyzer = FailureAnalyzer(client)

    results = analyzer.analyze_failures(SAMPLE_CRASH_LOGCAT, package_name="com.example.app")
    assert len(results) == 1
    assert results[0].is_ai_generated is False


def test_ai_disabled_fallback():
    client = AIClient(AIConfig(enabled=False))
    analyzer = FailureAnalyzer(client)

    results = analyzer.analyze_failures(SAMPLE_CRASH_LOGCAT, package_name="com.example.app")
    assert len(results) == 1
    res = results[0]
    assert res.is_ai_generated is False
    assert res.failure_category == "crash"
    assert res.severity == "CRITICAL"
