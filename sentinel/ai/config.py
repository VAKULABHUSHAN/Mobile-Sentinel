"""Configuration and settings management for the Sentinel AI Intelligence Layer."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _parse_bool(val: Any, default: bool = False) -> bool:
    """Safely converts string or boolean representations to bool."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    return s in ("true", "1", "yes", "y", "t", "on", "enable", "enabled")


def load_env_file(filepath: Optional[str | Path] = None) -> Dict[str, str]:
    """Lightweight .env loader that parses key=value pairs into os.environ without external dependencies."""
    path = Path(filepath) if filepath else Path(".env")
    loaded: Dict[str, str] = {}
    if not path.is_file():
        return loaded

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, val = line.partition("=")
                    k = key.strip()
                    v = val.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
                        loaded[k] = v
    except Exception:
        pass
    return loaded


@dataclass
class AIConfig:
    """Configuration for Mobile Sentinel AI Intelligence Layer."""

    enabled: bool = False
    provider: str = "gemini"  # "gemini", "openai", "ollama", "mock"
    model: str = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    timeout_seconds: int = 30
    max_retries: int = 2
    temperature: float = 0.2
    max_tokens: int = 4096
    cache_enabled: bool = True
    redaction_enabled: bool = True
    screen_analysis_depth: int = 10
    known_secrets: List[str] = field(default_factory=list)
    provider_timeouts: Dict[str, int] = field(
        default_factory=lambda: {"gemini": 30, "openai": 30, "ollama": 90, "mock": 5}
    )
    ollama_keep_alive: str = "0s"
    ollama_num_ctx: int = 2048
    ollama_num_predict: int = 1024

    def __post_init__(self) -> None:
        # Normalize provider name
        self.provider = (self.provider or "gemini").strip().lower()

        # Set standard default model per provider if none provided
        if not self.model:
            if self.provider == "gemini":
                self.model = "gemini-1.5-flash"
            elif self.provider == "openai":
                self.model = "gpt-4o-mini"
            elif self.provider == "ollama":
                self.model = "llama3.2"
            elif self.provider == "mock":
                self.model = "mock-sentinel-ai"
            else:
                self.model = "default-model"

        # Set default base URL for Ollama if not specified
        if self.provider == "ollama" and not self.base_url:
            self.base_url = "http://localhost:11434"

        # Apply provider-specific default timeout if user did not override the default 30s
        if self.timeout_seconds == 30 and self.provider in self.provider_timeouts:
            self.timeout_seconds = self.provider_timeouts[self.provider]

        # For local Ollama, cap default retries to avoid multi-minute stalls when saturated
        if self.provider == "ollama" and self.max_retries == 2:
            self.max_retries = 0

    @classmethod
    def from_env(cls, env_file: Optional[str | Path] = None) -> AIConfig:
        """Loads configuration from environment variables with optional .env loading."""
        load_env_file(env_file)

        enabled = _parse_bool(os.environ.get("SENTINEL_AI_ENABLED"), default=False)
        provider = os.environ.get("SENTINEL_AI_PROVIDER", "gemini").strip().lower()
        model = os.environ.get("SENTINEL_AI_MODEL", "")

        # Resolve provider-specific API keys
        api_key: Optional[str] = None
        if provider == "gemini":
            api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("SENTINEL_AI_API_KEY")
        elif provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("SENTINEL_AI_API_KEY")
        else:
            api_key = os.environ.get("SENTINEL_AI_API_KEY")

        base_url = os.environ.get("OLLAMA_BASE_URL") or os.environ.get("SENTINEL_AI_BASE_URL")

        # Provider-specific timeouts with environment override support
        provider_timeouts = {"gemini": 30, "openai": 30, "ollama": 90, "mock": 5}
        if os.environ.get("SENTINEL_AI_GEMINI_TIMEOUT"):
            try:
                provider_timeouts["gemini"] = int(os.environ["SENTINEL_AI_GEMINI_TIMEOUT"])
            except ValueError:
                pass
        if os.environ.get("SENTINEL_AI_OPENAI_TIMEOUT"):
            try:
                provider_timeouts["openai"] = int(os.environ["SENTINEL_AI_OPENAI_TIMEOUT"])
            except ValueError:
                pass
        if os.environ.get("SENTINEL_AI_OLLAMA_TIMEOUT"):
            try:
                provider_timeouts["ollama"] = int(os.environ["SENTINEL_AI_OLLAMA_TIMEOUT"])
            except ValueError:
                pass

        # Global timeout override if explicitly specified
        if os.environ.get("SENTINEL_AI_TIMEOUT"):
            try:
                timeout_seconds = int(os.environ["SENTINEL_AI_TIMEOUT"])
            except ValueError:
                timeout_seconds = provider_timeouts.get(provider, 30)
        else:
            timeout_seconds = provider_timeouts.get(provider, 30)

        # Max retries: default to 0 for local Ollama, 2 for remote APIs
        default_retries = 0 if provider == "ollama" else 2
        try:
            max_retries = int(os.environ.get("SENTINEL_AI_MAX_RETRIES", str(default_retries)))
        except ValueError:
            max_retries = default_retries

        try:
            temperature = float(os.environ.get("SENTINEL_AI_TEMPERATURE", "0.2"))
        except ValueError:
            temperature = 0.2

        ollama_keep_alive = os.environ.get("SENTINEL_AI_OLLAMA_KEEP_ALIVE", "0s")
        try:
            ollama_num_ctx = int(os.environ.get("SENTINEL_AI_OLLAMA_NUM_CTX", "2048"))
        except ValueError:
            ollama_num_ctx = 2048

        try:
            ollama_num_predict = int(os.environ.get("SENTINEL_AI_OLLAMA_NUM_PREDICT", "1024"))
        except ValueError:
            ollama_num_predict = 1024

        cache_enabled = _parse_bool(os.environ.get("SENTINEL_AI_CACHE_ENABLED"), default=True)
        redaction_enabled = _parse_bool(os.environ.get("SENTINEL_AI_REDACTION_ENABLED"), default=True)

        return cls(
            enabled=enabled,
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            temperature=temperature,
            cache_enabled=cache_enabled,
            redaction_enabled=redaction_enabled,
            provider_timeouts=provider_timeouts,
            ollama_keep_alive=ollama_keep_alive,
            ollama_num_ctx=ollama_num_ctx,
            ollama_num_predict=ollama_num_predict,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AIConfig:
        """Instantiates AIConfig from a dictionary."""
        return cls(
            enabled=_parse_bool(data.get("enabled", False)),
            provider=str(data.get("provider", "gemini")),
            model=str(data.get("model", "")),
            api_key=data.get("api_key"),
            base_url=data.get("base_url"),
            timeout_seconds=int(data.get("timeout_seconds", 30)),
            max_retries=int(data.get("max_retries", 2)),
            temperature=float(data.get("temperature", 0.2)),
            cache_enabled=_parse_bool(data.get("cache_enabled", True)),
            redaction_enabled=_parse_bool(data.get("redaction_enabled", True)),
            screen_analysis_depth=int(data.get("screen_analysis_depth", 10)),
            known_secrets=list(data.get("known_secrets", [])),
            provider_timeouts=dict(data.get("provider_timeouts", {"gemini": 30, "openai": 30, "ollama": 90, "mock": 5})),
            ollama_keep_alive=str(data.get("ollama_keep_alive", "0s")),
            ollama_num_ctx=int(data.get("ollama_num_ctx", 2048)),
            ollama_num_predict=int(data.get("ollama_num_predict", 1024)),
        )

    def validate(self) -> Tuple[bool, Optional[str]]:
        """Validates configuration settings."""
        if not self.enabled:
            return True, None

        allowed_providers = {"gemini", "openai", "ollama", "mock"}
        if self.provider not in allowed_providers:
            return False, f"Unsupported AI provider '{self.provider}'. Allowed: {', '.join(sorted(allowed_providers))}"

        if self.provider in ("gemini", "openai") and not self.api_key:
            return False, f"API key is required for provider '{self.provider}'. Set {self.provider.upper()}_API_KEY."

        if self.timeout_seconds <= 0:
            return False, "timeout_seconds must be a positive integer."

        return True, None

    def __repr__(self) -> str:
        """Ensures API keys are never exposed in string representations, logs, or traces."""
        masked_key = "[REDACTED]" if self.api_key else "None"
        return (
            f"AIConfig(enabled={self.enabled}, provider='{self.provider}', "
            f"model='{self.model}', api_key={masked_key}, base_url={self.base_url}, "
            f"timeout={self.timeout_seconds}s, retries={self.max_retries})"
        )
