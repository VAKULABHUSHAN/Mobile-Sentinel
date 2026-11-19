"""LLM provider abstraction supporting Gemini, OpenAI, Ollama, and Mock providers."""

from __future__ import annotations

import abc
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from sentinel.ai.config import AIConfig
from sentinel.ai.models import AIResponse
from sentinel.core.exceptions import SentinelError
from sentinel.core.logging import logger


class AIProviderError(SentinelError):
    """Base exception for AI provider invocation errors."""


class AIProviderAuthenticationError(AIProviderError):
    """Raised when an API key is rejected or unauthorized."""


class AIProviderRateLimitError(AIProviderError):
    """Raised when provider rate limits are hit (HTTP 429)."""


class AIProviderNetworkError(AIProviderError):
    """Raised on connection timeout or network level failure."""


class AIProviderTimeoutError(AIProviderNetworkError):
    """Raised specifically when an AI provider request exceeds its allotted timeout."""


class BaseLLMProvider(abc.ABC):
    """Abstract interface that all LLM provider adapters must implement."""

    def __init__(self, config: AIConfig):
        self.config = config

    @property
    def provider_name(self) -> str:
        return self.config.provider

    @property
    def model_name(self) -> str:
        return self.config.model

    @abc.abstractmethod
    def generate(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = True,
    ) -> AIResponse:
        """Sends a completion request to the LLM and returns a normalized AIResponse."""
        pass


class MockLLMProvider(BaseLLMProvider):
    """In-memory mock provider for deterministic testing without external API calls."""

    def __init__(self, config: Optional[AIConfig] = None, canned_responses: Optional[List[str | Dict[str, Any]]] = None):
        cfg = config or AIConfig(enabled=True, provider="mock", model="mock-sentinel-ai")
        super().__init__(cfg)
        self.canned_responses: List[str] = []
        if canned_responses:
            for item in canned_responses:
                if isinstance(item, dict):
                    self.canned_responses.append(json.dumps(item))
                else:
                    self.canned_responses.append(str(item))

        self.call_history: List[Dict[str, Any]] = []
        self.custom_handler: Optional[Callable[[str, Optional[str], bool], str]] = None

    def set_custom_handler(self, handler: Callable[[str, Optional[str], bool], str]) -> None:
        """Sets a callback function to dynamically generate mock responses."""
        self.custom_handler = handler

    def add_canned_response(self, response: str | Dict[str, Any]) -> None:
        """Queues a canned response for upcoming generate calls."""
        if isinstance(response, dict):
            self.canned_responses.append(json.dumps(response))
        else:
            self.canned_responses.append(str(response))

    def generate(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = True,
    ) -> AIResponse:
        start_time = time.time()
        self.call_history.append({
            "prompt": prompt,
            "system": system_instruction,
            "json_mode": json_mode,
            "timestamp": time.time(),
        })

        if self.custom_handler:
            custom_out = self.custom_handler(prompt, system_instruction, json_mode)
            if isinstance(custom_out, AIResponse):
                return custom_out
            elif isinstance(custom_out, dict):
                raw_text = json.dumps(custom_out)
            else:
                raw_text = str(custom_out)
        elif self.canned_responses:
            raw_text = self.canned_responses.pop(0)
        else:
            # Generate default minimal valid JSON matching prompt context
            if "screen_purpose" in prompt or "screen_type" in prompt:
                raw_text = json.dumps({
                    "screen_purpose": "Mock screen analysis",
                    "screen_type": "dashboard",
                    "summary": "Mock dashboard overview",
                    "key_elements": ["mock_button"],
                    "navigation_possibilities": ["settings"],
                    "missing_states": [],
                    "usability_issues": [],
                    "accessibility_issues": [],
                    "confidence": 0.9,
                })
            elif "test_cases" in prompt:
                raw_text = json.dumps({
                    "test_cases": [
                        {
                            "test_id": "TC-MOCK-001",
                            "name": "Mock Test",
                            "description": "Mock description",
                            "target_screen": "MockScreen",
                            "preconditions": "App active",
                            "suggested_action": "tap",
                            "target_element_id": "btn_1",
                            "target_element_description": "Submit Button",
                            "test_input": None,
                            "expected_outcome": "Success",
                            "risk_level": "SAFE",
                            "reason": "Verify submit works",
                            "validation_type": "general",
                        }
                    ]
                })
            elif "recommended_action_key" in prompt:
                raw_text = json.dumps({
                    "recommended_action_key": "tap:button:btn_1:10,20",
                    "target_element_id": "btn_1",
                    "target_description": "Mock Button",
                    "action_type": "tap",
                    "priority": 8,
                    "reason": "Test primary action",
                    "workflow_goal": "Advance workflow",
                    "alternative_paths": [],
                })
            else:
                raw_text = json.dumps({"status": "mock_success", "message": "Default mock response"})

        parsed: Optional[Dict[str, Any]] = None
        if json_mode:
            try:
                parsed = json.loads(raw_text)
            except Exception:
                pass

        return AIResponse(
            raw_text=raw_text,
            parsed_json=parsed,
            provider="mock",
            model=self.model_name,
            duration_seconds=round(time.time() - start_time, 4),
            prompt_tokens=len(prompt) // 4,
            completion_tokens=len(raw_text) // 4,
            is_mock=True,
        )


class GeminiProvider(BaseLLMProvider):
    """Google Gemini REST API provider using v1beta endpoint."""

    BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

    def generate(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = True,
    ) -> AIResponse:
        start_time = time.time()
        if not self.config.api_key:
            raise AIProviderAuthenticationError("Gemini API key is required but missing.")

        url = f"{self.BASE_URL}/{self.model_name}:generateContent?key={self.config.api_key}"

        payload: Dict[str, Any] = {
            "contents": [
                {
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
            },
        }

        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}],
            }

        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = ""
            try:
                err_body = e.read().decode("utf-8")
                parsed_err = json.loads(err_body)
                err_msg = parsed_err.get("error", {}).get("message", "")
            except Exception:
                err_msg = str(e)

            if e.code in (401, 403):
                raise AIProviderAuthenticationError(f"Gemini authentication failed: {err_msg}") from e
            if e.code == 429:
                raise AIProviderRateLimitError(f"Gemini rate limit exceeded: {err_msg}") from e
            raise AIProviderError(f"Gemini API error (HTTP {e.code}): {err_msg}") from e
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", None)
            reason_str = str(reason or e).lower()
            if "timed out" in reason_str or isinstance(reason, (TimeoutError, socket.timeout)):
                raise AIProviderTimeoutError(f"Gemini request timed out after {self.config.timeout_seconds}s: {e}") from e
            raise AIProviderNetworkError(f"Network error connecting to Gemini: {e}") from e
        except TimeoutError as e:
            raise AIProviderTimeoutError(f"Gemini request timed out after {self.config.timeout_seconds}s: {e}") from e
        except Exception as e:
            raise AIProviderError(f"Unexpected error during Gemini generation: {e}") from e

        # Extract text from Gemini response structure
        candidates = resp_data.get("candidates", [])
        if not candidates:
            raise AIProviderError("Gemini returned no candidates in response.")

        parts = candidates[0].get("content", {}).get("parts", [])
        raw_text = parts[0].get("text", "") if parts else ""

        usage = resp_data.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount")
        completion_tokens = usage.get("candidatesTokenCount")

        parsed_json: Optional[Dict[str, Any]] = None
        if json_mode and raw_text:
            try:
                parsed_json = json.loads(raw_text)
            except Exception:
                pass

        return AIResponse(
            raw_text=raw_text,
            parsed_json=parsed_json,
            provider="gemini",
            model=self.model_name,
            duration_seconds=round(time.time() - start_time, 3),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )


class OpenAIProvider(BaseLLMProvider):
    """OpenAI Chat Completions REST API provider."""

    DEFAULT_BASE_URL = "https://api.openai.com/v1"

    def generate(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = True,
    ) -> AIResponse:
        start_time = time.time()
        if not self.config.api_key:
            raise AIProviderAuthenticationError("OpenAI API key is required but missing.")

        base_url = (self.config.base_url or self.DEFAULT_BASE_URL).rstrip("/")
        url = f"{base_url}/chat/completions"

        messages: List[Dict[str, str]] = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = ""
            try:
                err_body = e.read().decode("utf-8")
                parsed_err = json.loads(err_body)
                err_msg = parsed_err.get("error", {}).get("message", "")
            except Exception:
                err_msg = str(e)

            if e.code in (401, 403):
                raise AIProviderAuthenticationError(f"OpenAI authentication failed: {err_msg}") from e
            if e.code == 429:
                raise AIProviderRateLimitError(f"OpenAI rate limit exceeded: {err_msg}") from e
            raise AIProviderError(f"OpenAI API error (HTTP {e.code}): {err_msg}") from e
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", None)
            reason_str = str(reason or e).lower()
            if "timed out" in reason_str or isinstance(reason, (TimeoutError, socket.timeout)):
                raise AIProviderTimeoutError(f"OpenAI request timed out after {self.config.timeout_seconds}s: {e}") from e
            raise AIProviderNetworkError(f"Network error connecting to OpenAI: {e}") from e
        except TimeoutError as e:
            raise AIProviderTimeoutError(f"OpenAI request timed out after {self.config.timeout_seconds}s: {e}") from e
        except Exception as e:
            raise AIProviderError(f"Unexpected error during OpenAI generation: {e}") from e

        choices = resp_data.get("choices", [])
        if not choices:
            raise AIProviderError("OpenAI returned no choices in response.")

        raw_text = choices[0].get("message", {}).get("content", "")
        usage = resp_data.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")

        parsed_json: Optional[Dict[str, Any]] = None
        if json_mode and raw_text:
            try:
                parsed_json = json.loads(raw_text)
            except Exception:
                pass

        return AIResponse(
            raw_text=raw_text,
            parsed_json=parsed_json,
            provider="openai",
            model=self.model_name,
            duration_seconds=round(time.time() - start_time, 3),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )


class OllamaProvider(BaseLLMProvider):
    """Local Ollama REST API provider (/api/chat)."""

    DEFAULT_BASE_URL = "http://localhost:11434"

    def generate(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = True,
    ) -> AIResponse:
        start_time = time.time()
        base_url = (self.config.base_url or self.DEFAULT_BASE_URL).rstrip("/")
        url = f"{base_url}/api/chat"

        messages: List[Dict[str, str]] = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": getattr(self.config, "ollama_num_predict", 1024),
                "num_ctx": getattr(self.config, "ollama_num_ctx", 2048),
            },
            "keep_alive": getattr(self.config, "ollama_keep_alive", "0s"),
        }

        if json_mode:
            payload["format"] = "json"

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_msg = ""
            try:
                err_msg = e.read().decode("utf-8")
            except Exception:
                err_msg = str(e)
            raise AIProviderError(f"Ollama API error (HTTP {e.code}): {err_msg}") from e
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", None)
            reason_str = str(reason or e).lower()
            if "timed out" in reason_str or isinstance(reason, (TimeoutError, socket.timeout)):
                raise AIProviderTimeoutError(
                    f"Ollama request to {url} timed out after {self.config.timeout_seconds}s. "
                    "Local GPU/CPU resources may be saturated."
                ) from e
            raise AIProviderNetworkError(f"Failed to connect to local Ollama at {url}. Is Ollama running? Error: {e}") from e
        except TimeoutError as e:
            raise AIProviderTimeoutError(
                f"Ollama request to {url} timed out after {self.config.timeout_seconds}s."
            ) from e
        except Exception as e:
            raise AIProviderError(f"Unexpected error during Ollama generation: {e}") from e

        raw_text = resp_data.get("message", {}).get("content", "")
        prompt_tokens = resp_data.get("prompt_eval_count")
        completion_tokens = resp_data.get("eval_count")

        parsed_json: Optional[Dict[str, Any]] = None
        if json_mode and raw_text:
            try:
                parsed_json = json.loads(raw_text)
            except Exception:
                pass

        return AIResponse(
            raw_text=raw_text,
            parsed_json=parsed_json,
            provider="ollama",
            model=self.model_name,
            duration_seconds=round(time.time() - start_time, 3),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )


def create_provider(config: AIConfig) -> BaseLLMProvider:
    """Factory creating the appropriate provider instance according to configuration."""
    valid, err = config.validate()
    if not valid:
        raise AIProviderError(f"Invalid AI configuration: {err}")

    provider_type = config.provider.lower()
    if provider_type == "gemini":
        return GeminiProvider(config)
    elif provider_type == "openai":
        return OpenAIProvider(config)
    elif provider_type == "ollama":
        return OllamaProvider(config)
    elif provider_type == "mock":
        return MockLLMProvider(config)
    else:
        raise AIProviderError(f"Unsupported provider '{provider_type}'")
