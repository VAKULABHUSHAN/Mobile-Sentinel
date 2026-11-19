"""Unit tests for AIConfig and environment loading."""

import os
from unittest.mock import patch

import pytest

from sentinel.ai.config import AIConfig, _parse_bool, load_env_file


def test_parse_bool():
    assert _parse_bool("true") is True
    assert _parse_bool("1") is True
    assert _parse_bool("yes") is True
    assert _parse_bool("on") is True
    assert _parse_bool(True) is True
    assert _parse_bool("false") is False
    assert _parse_bool("0") is False
    assert _parse_bool(None, default=True) is True
    assert _parse_bool(None, default=False) is False


def test_ai_config_defaults():
    config = AIConfig()
    assert config.enabled is False
    assert config.provider == "gemini"
    assert config.model == "gemini-1.5-flash"
    assert config.api_key is None
    assert config.timeout_seconds == 30
    assert config.max_retries == 2


def test_ai_config_provider_model_defaults():
    cfg_openai = AIConfig(provider="openai")
    assert cfg_openai.model == "gpt-4o-mini"

    cfg_ollama = AIConfig(provider="ollama")
    assert cfg_ollama.model == "llama3.2"
    assert cfg_ollama.base_url == "http://localhost:11434"

    cfg_mock = AIConfig(provider="mock")
    assert cfg_mock.model == "mock-sentinel-ai"


def test_ai_config_api_key_masked_in_repr():
    config = AIConfig(api_key="super-secret-key-12345")
    repr_str = repr(config)
    assert "super-secret-key-12345" not in repr_str
    assert "[REDACTED]" in repr_str


def test_ai_config_validation():
    # Disabled config is always valid
    disabled_cfg = AIConfig(enabled=False)
    valid, err = disabled_cfg.validate()
    assert valid is True
    assert err is None

    # Enabled gemini without api_key is invalid
    gemini_no_key = AIConfig(enabled=True, provider="gemini", api_key=None)
    valid, err = gemini_no_key.validate()
    assert valid is False
    assert "API key is required" in err

    # Enabled gemini with api_key is valid
    gemini_with_key = AIConfig(enabled=True, provider="gemini", api_key="valid-key")
    valid, err = gemini_with_key.validate()
    assert valid is True

    # Enabled ollama without key is valid
    ollama_cfg = AIConfig(enabled=True, provider="ollama")
    valid, err = ollama_cfg.validate()
    assert valid is True

    # Unknown provider is invalid
    invalid_prov = AIConfig(enabled=True, provider="unknown_llm")
    valid, err = invalid_prov.validate()
    assert valid is False
    assert "Unsupported AI provider" in err


def test_ai_config_from_env():
    env = {
        "SENTINEL_AI_ENABLED": "true",
        "SENTINEL_AI_PROVIDER": "openai",
        "SENTINEL_AI_MODEL": "gpt-4o",
        "OPENAI_API_KEY": "test-openai-key",
        "SENTINEL_AI_TIMEOUT": "45",
        "SENTINEL_AI_MAX_RETRIES": "3",
    }
    with patch.dict(os.environ, env, clear=True):
        config = AIConfig.from_env()
        assert config.enabled is True
        assert config.provider == "openai"
        assert config.model == "gpt-4o"
        assert config.api_key == "test-openai-key"
        assert config.timeout_seconds == 45
        assert config.max_retries == 3


def test_load_env_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SENTINEL_AI_ENABLED=true\nSENTINEL_AI_PROVIDER=ollama\n# comment\n", encoding="utf-8")

    with patch.dict(os.environ, {}, clear=True):
        loaded = load_env_file(env_file)
        assert loaded.get("SENTINEL_AI_ENABLED") == "true"
        assert loaded.get("SENTINEL_AI_PROVIDER") == "ollama"
        assert os.environ.get("SENTINEL_AI_ENABLED") == "true"
