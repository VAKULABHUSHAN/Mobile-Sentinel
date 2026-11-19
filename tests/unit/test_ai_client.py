"""Unit tests for AIClient (redaction, retries, JSON parsing, caching, and disabled mode)."""

import json
from unittest.mock import MagicMock

import pytest

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.models import AIResponse
from sentinel.ai.provider import (
    AIProviderAuthenticationError,
    AIProviderRateLimitError,
    MockLLMProvider,
)


def test_ai_client_disabled_by_default():
    client = AIClient(AIConfig(enabled=False))
    assert client.is_enabled is False
    # When disabled, generate_json returns None without invoking anything
    assert client.generate_json("any prompt") is None


def test_secret_redaction_patterns():
    client = AIClient(AIConfig(enabled=True, provider="mock"))

    raw = (
        "Check this key: AIzaSyD9x7ABC1234567890123456789012 and AWS AKIAIOSFODNN7EXAMPLE "
        "and ghp_111122223333444455556666777788889999 and password: 'SecretPassword99!'"
    )
    redacted = client.redact_text(raw)

    assert "AIzaSyD9x" not in redacted
    assert "[REDACTED_GOOGLE_API_KEY]" in redacted

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_KEY]" in redacted

    assert "ghp_111122223333" not in redacted
    assert "[REDACTED_GITHUB_TOKEN]" in redacted

    assert "SecretPassword99!" not in redacted
    assert "password=[REDACTED]" in redacted


def test_dynamic_secret_registration():
    client = AIClient(AIConfig(enabled=True, provider="mock"))
    client.register_sensitive_value("CustomInternalUserPassword99#")

    text = "The user entered CustomInternalUserPassword99# into the input field."
    redacted = client.redact_text(text)

    assert "CustomInternalUserPassword99#" not in redacted
    assert "[REDACTED_CREDENTIAL]" in redacted


def test_extract_json_formats():
    # 1. Plain JSON
    res1 = AIClient.extract_json('{"key": "value"}')
    assert res1 == {"key": "value"}

    # 2. Markdown fenced block
    markdown_str = """
Here is your analysis:
```json
{
  "screen_type": "login",
  "confidence": 0.95
}
```
Hope this helps!
"""
    res2 = AIClient.extract_json(markdown_str)
    assert res2 == {"screen_type": "login", "confidence": 0.95}

    # 3. Outer balanced braces with prose
    prose_str = "Sure! Analysis: {\"status\": \"ok\", \"count\": 2}. Let me know if you need more."
    res3 = AIClient.extract_json(prose_str)
    assert res3 == {"status": "ok", "count": 2}

    # 4. Invalid JSON
    assert AIClient.extract_json("not json at all") is None


def test_caching_identical_prompts():
    mock_prov = MockLLMProvider()
    client = AIClient(AIConfig(enabled=True, provider="mock", cache_enabled=True), provider=mock_prov)

    mock_prov.add_canned_response({"call": 1})
    mock_prov.add_canned_response({"call": 2})

    res1 = client.generate_json("Describe dashboard")
    assert res1 == {"call": 1}

    # Second identical prompt should return cached result, provider not called again
    res2 = client.generate_json("Describe dashboard")
    assert res2 == {"call": 1}
    assert len(mock_prov.call_history) == 1


def test_retries_on_rate_limit():
    mock_prov = MockLLMProvider()
    client = AIClient(AIConfig(enabled=True, provider="mock", max_retries=2), provider=mock_prov)

    # First attempt raises rate limit, second succeeds
    calls = []

    def failing_handler(prompt, system, json_mode):
        calls.append(len(calls))
        if len(calls) == 1:
            raise AIProviderRateLimitError("Rate limit hit")
        return json.dumps({"recovered": True})

    mock_prov.set_custom_handler(failing_handler)

    res = client.generate_json("Perform analysis")
    assert res == {"recovered": True}
    assert len(calls) == 2


def test_auth_error_disables_client():
    mock_prov = MockLLMProvider()
    client = AIClient(AIConfig(enabled=True, provider="mock"), provider=mock_prov)

    def auth_err_handler(prompt, system, json_mode):
        raise AIProviderAuthenticationError("Invalid API key")

    mock_prov.set_custom_handler(auth_err_handler)

    res = client.generate_json("Perform analysis")
    assert res is None
    # Client should be marked disabled immediately
    assert client.is_enabled is False
