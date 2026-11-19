"""Unit tests for LLM providers (Mock, Gemini, OpenAI, Ollama) with mocked HTTP responses."""

import io
import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from sentinel.ai.config import AIConfig
from sentinel.ai.provider import (
    AIProviderAuthenticationError,
    AIProviderError,
    AIProviderNetworkError,
    AIProviderRateLimitError,
    GeminiProvider,
    MockLLMProvider,
    OllamaProvider,
    OpenAIProvider,
    create_provider,
)


def test_mock_provider_defaults():
    mock_prov = MockLLMProvider()
    resp = mock_prov.generate("Analyze screen_purpose for login")
    assert resp.is_mock is True
    assert resp.provider == "mock"
    assert resp.parsed_json is not None
    assert "screen_purpose" in resp.parsed_json
    assert len(mock_prov.call_history) == 1


def test_mock_provider_canned_responses():
    mock_prov = MockLLMProvider(canned_responses=[{"custom_key": "val1"}, "plain string response"])
    resp1 = mock_prov.generate("p1")
    assert resp1.parsed_json == {"custom_key": "val1"}

    resp2 = mock_prov.generate("p2", json_mode=False)
    assert resp2.raw_text == "plain string response"


def test_mock_provider_custom_handler():
    mock_prov = MockLLMProvider()
    mock_prov.set_custom_handler(lambda p, s, j: json.dumps({"echo_prompt": p}))
    resp = mock_prov.generate("test prompt")
    assert resp.parsed_json == {"echo_prompt": "test prompt"}


def test_gemini_provider_missing_key():
    cfg = AIConfig(enabled=True, provider="gemini", api_key=None)
    prov = GeminiProvider(cfg)
    with pytest.raises(AIProviderAuthenticationError) as exc_info:
        prov.generate("test")
    assert "Gemini API key is required" in str(exc_info.value)


def test_gemini_provider_success():
    cfg = AIConfig(enabled=True, provider="gemini", api_key="valid-gemini-key")
    prov = GeminiProvider(cfg)

    fake_resp = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": '{"result": "gemini_success"}'}],
                }
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 10,
            "candidatesTokenCount": 5,
        },
    }

    mock_urlopen = MagicMock()
    mock_response = io.BytesIO(json.dumps(fake_resp).encode("utf-8"))
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", mock_urlopen):
        resp = prov.generate("Summarize screen")
        assert resp.provider == "gemini"
        assert resp.parsed_json == {"result": "gemini_success"}
        assert resp.prompt_tokens == 10
        assert resp.completion_tokens == 5


def test_gemini_provider_http_401():
    cfg = AIConfig(enabled=True, provider="gemini", api_key="bad-key")
    prov = GeminiProvider(cfg)

    err_body = io.BytesIO(b'{"error": {"message": "API key invalid"}}')
    http_err = urllib.error.HTTPError("https://gemini", 401, "Unauthorized", {}, err_body)

    with patch("urllib.request.urlopen", side_effect=http_err):
        with pytest.raises(AIProviderAuthenticationError):
            prov.generate("Test prompt")


def test_gemini_provider_http_429():
    cfg = AIConfig(enabled=True, provider="gemini", api_key="valid-key")
    prov = GeminiProvider(cfg)

    err_body = io.BytesIO(b'{"error": {"message": "Resource exhausted"}}')
    http_err = urllib.error.HTTPError("https://gemini", 429, "Too Many Requests", {}, err_body)

    with patch("urllib.request.urlopen", side_effect=http_err):
        with pytest.raises(AIProviderRateLimitError):
            prov.generate("Test prompt")


def test_openai_provider_success():
    cfg = AIConfig(enabled=True, provider="openai", api_key="sk-test-key")
    prov = OpenAIProvider(cfg)

    fake_resp = {
        "choices": [
            {
                "message": {"content": '{"result": "openai_success"}'},
            }
        ],
        "usage": {
            "prompt_tokens": 15,
            "completion_tokens": 8,
        },
    }

    mock_urlopen = MagicMock()
    mock_response = io.BytesIO(json.dumps(fake_resp).encode("utf-8"))
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", mock_urlopen):
        resp = prov.generate("Test prompt")
        assert resp.provider == "openai"
        assert resp.parsed_json == {"result": "openai_success"}


def test_openai_provider_http_401():
    cfg = AIConfig(enabled=True, provider="openai", api_key="bad-key")
    prov = OpenAIProvider(cfg)

    err_body = io.BytesIO(b'{"error": {"message": "Incorrect API key"}}')
    http_err = urllib.error.HTTPError("https://openai", 401, "Unauthorized", {}, err_body)

    with patch("urllib.request.urlopen", side_effect=http_err):
        with pytest.raises(AIProviderAuthenticationError):
            prov.generate("Test prompt")


def test_ollama_provider_success():
    cfg = AIConfig(enabled=True, provider="ollama", base_url="http://localhost:11434")
    prov = OllamaProvider(cfg)

    fake_resp = {
        "message": {"content": '{"result": "ollama_success"}'},
        "prompt_eval_count": 20,
        "eval_count": 12,
    }

    mock_urlopen = MagicMock()
    mock_response = io.BytesIO(json.dumps(fake_resp).encode("utf-8"))
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", mock_urlopen):
        resp = prov.generate("Test prompt")
        assert resp.provider == "ollama"
        assert resp.parsed_json == {"result": "ollama_success"}


def test_ollama_provider_connection_error():
    cfg = AIConfig(enabled=True, provider="ollama", base_url="http://localhost:11434")
    prov = OllamaProvider(cfg)

    url_err = urllib.error.URLError("Connection refused")
    with patch("urllib.request.urlopen", side_effect=url_err):
        with pytest.raises(AIProviderNetworkError) as exc_info:
            prov.generate("Test prompt")
        assert "Is Ollama running?" in str(exc_info.value)


def test_create_provider_factory():
    prov_mock = create_provider(AIConfig(enabled=True, provider="mock"))
    assert isinstance(prov_mock, MockLLMProvider)

    prov_gemini = create_provider(AIConfig(enabled=True, provider="gemini", api_key="k"))
    assert isinstance(prov_gemini, GeminiProvider)

    prov_openai = create_provider(AIConfig(enabled=True, provider="openai", api_key="k"))
    assert isinstance(prov_openai, OpenAIProvider)

    prov_ollama = create_provider(AIConfig(enabled=True, provider="ollama"))
    assert isinstance(prov_ollama, OllamaProvider)

    with pytest.raises(AIProviderError):
        create_provider(AIConfig(enabled=True, provider="unsupported_provider"))
