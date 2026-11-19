"""Resilient AI Client providing secret redaction, robust JSON extraction, caching, and retry logic."""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from sentinel.ai.config import AIConfig
from sentinel.ai.models import AIResponse
from sentinel.ai.prompts import SYSTEM_PROMPT_BASE
from sentinel.ai.provider import (
    AIProviderAuthenticationError,
    AIProviderError,
    AIProviderNetworkError,
    AIProviderRateLimitError,
    AIProviderTimeoutError,
    BaseLLMProvider,
    create_provider,
)
from sentinel.core.logging import logger

# Regex patterns for redacting sensitive secrets before sending to LLM
REDACTION_PATTERNS = [
    (re.compile(r"AIza[0-9A-Za-z\-_]{30,45}"), "[REDACTED_GOOGLE_API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PRIVATE)\s+KEY-----[\s\S]*?-----END\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PRIVATE)\s+KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?:bearer\s+)[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE), "Bearer [REDACTED_BEARER_TOKEN]"),
    (re.compile(r"(?:password|passwd|secret|token|pwd)[\s:=]+['\"]?([^\s'\",&]{3,})['\"]?", re.IGNORECASE), r"password=[REDACTED]"),
    (re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis)://([a-zA-Z0-9_]+):([^\s@]+)@", re.IGNORECASE), r"\1:[REDACTED]@"),
]


class AIClient:
    """High-level client orchestrating LLM interactions with redaction, caching, and retries."""

    def __init__(self, config: Optional[AIConfig] = None, provider: Optional[BaseLLMProvider] = None):
        self.config = config or AIConfig.from_env()
        self.provider: Optional[BaseLLMProvider] = provider
        if not self.provider and self.config.enabled:
            try:
                self.provider = create_provider(self.config)
            except Exception as e:
                logger.warning(f"Failed to initialize AI provider '{self.config.provider}': {e}. Disabling AI layer.")
                self.config.enabled = False

        self._cache: Dict[str, AIResponse] = {}
        self._dynamic_secrets: List[str] = list(self.config.known_secrets)

    @property
    def is_enabled(self) -> bool:
        return bool(self.config.enabled and self.provider is not None)

    def register_sensitive_value(self, secret: Optional[str]) -> None:
        """Registers a dynamic runtime secret (e.g. user password or test token) to be redacted."""
        if secret and len(secret.strip()) >= 3:
            clean = secret.strip()
            if clean not in self._dynamic_secrets:
                self._dynamic_secrets.append(clean)

    def redact_text(self, text: str) -> str:
        """Scrubs any known or pattern-matching credentials from the text before sending to LLM."""
        if not self.config.redaction_enabled or not text:
            return text

        scrubbed = text

        # 1. Redact dynamically registered secrets
        for sec in self._dynamic_secrets:
            if sec and sec in scrubbed:
                scrubbed = scrubbed.replace(sec, "[REDACTED_CREDENTIAL]")

        # 2. Redact pattern-based secrets
        for pat, replacement in REDACTION_PATTERNS:
            scrubbed = pat.sub(replacement, scrubbed)

        return scrubbed

    @staticmethod
    def extract_json(raw_text: str) -> Optional[Dict[str, Any]]:
        """Extracts and parses JSON object or array from LLM output, handling markdown blocks."""
        if not raw_text:
            return None

        clean = raw_text.strip()

        # Try direct parse first
        try:
            val = json.loads(clean)
            if isinstance(val, (dict, list)):
                return val if isinstance(val, dict) else {"items": val}
        except Exception:
            pass

        # Try extracting from markdown ```json ... ``` code fence
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean, re.IGNORECASE)
        if fence_match:
            try:
                val = json.loads(fence_match.group(1).strip())
                if isinstance(val, (dict, list)):
                    return val if isinstance(val, dict) else {"items": val}
            except Exception:
                pass

        # Try finding outer-most balanced curly braces { ... }
        start = clean.find("{")
        end = clean.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = clean[start : end + 1]
            try:
                val = json.loads(candidate)
                if isinstance(val, dict):
                    return val
            except Exception:
                pass

        return None

    def _compute_cache_key(self, prompt: str, system: Optional[str]) -> str:
        h = hashlib.sha256()
        h.update((system or "").encode("utf-8"))
        h.update(b"|||")
        h.update(prompt.encode("utf-8"))
        return h.hexdigest()

    def generate_json(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        cache_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Generates a structured JSON response with retries, redaction, and caching."""
        if not self.is_enabled:
            return None

        # Redact secrets before constructing request
        safe_prompt = self.redact_text(prompt)
        system = system_instruction or SYSTEM_PROMPT_BASE

        # Check cache if enabled
        key = cache_key or self._compute_cache_key(safe_prompt, system)
        if self.config.cache_enabled and key in self._cache:
            cached = self._cache[key]
            if cached.parsed_json is not None:
                return cached.parsed_json

        # Bounded retries
        last_error: Optional[Exception] = None
        max_attempts = self.config.max_retries + 1
        for attempt in range(1, max_attempts + 1):
            try:
                assert self.provider is not None
                response = self.provider.generate(
                    prompt=safe_prompt,
                    system_instruction=system,
                    json_mode=True,
                )

                # Parse JSON if not already parsed
                if response.parsed_json is None:
                    response.parsed_json = self.extract_json(response.raw_text)

                if response.parsed_json is not None:
                    if self.config.cache_enabled:
                        self._cache[key] = response
                    return response.parsed_json

                logger.warning(
                    f"[AIClient] Attempt {attempt}: Received non-JSON response from {self.config.provider}: "
                    f"{response.raw_text[:120]}..."
                )
            except AIProviderAuthenticationError as e:
                # Fatal: do not retry authentication errors
                logger.error(f"[AIClient] Authentication error: {e}. Disabling AI provider.")
                self.config.enabled = False
                return None
            except AIProviderTimeoutError as e:
                last_error = e
                logger.warning(f"[AIClient] Attempt {attempt} timed out for provider '{self.config.provider}': {e}")
                # For local Ollama, fast-fail without retrying to preserve CPU/RAM stability
                if self.config.provider == "ollama":
                    logger.info("[AIClient] Skipping retries for local Ollama timeout to preserve system stability.")
                    break
                if attempt < max_attempts:
                    time.sleep(1.0 * attempt)
            except (AIProviderRateLimitError, AIProviderNetworkError) as e:
                last_error = e
                logger.warning(f"[AIClient] Attempt {attempt} failed ({e}). Retrying...")
                if attempt < max_attempts:
                    time.sleep(1.0 * attempt)
            except Exception as e:
                last_error = e
                logger.warning(f"[AIClient] Attempt {attempt} failed with error: {e}")
                if attempt < max_attempts:
                    time.sleep(1.0 * attempt)

        logger.error(f"[AIClient] All {attempt} attempts failed for prompt: {last_error}")
        return None
