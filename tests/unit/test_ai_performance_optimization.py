"""Unit tests for Phase 8: AI Performance & Resource Optimization.

Validates:
1. Provider-specific timeouts (Ollama 90s, Gemini/OpenAI 30s) and environment overrides.
2. Ollama provider request optimization (num_predict, num_ctx, keep_alive="0s").
3. AIProviderTimeoutError classification on network/socket timeouts.
4. AIClient retry suppression on Ollama timeouts (fast-fail, no duplicate wait).
5. Batched security finding analysis (1 LLM call instead of N separate calls).
6. SecurityAnalyzer graceful deterministic fallback on timeout or malformed response.
7. ReportGenerator resilience on AI timeout/failure (returns deterministic fallback).
8. AI-disabled isolation (zero provider calls during deterministic testing).
"""

import json
import os
import socket
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.models import AIReportSummary, SecurityExplanation
from sentinel.ai.provider import (
    AIProviderAuthenticationError,
    AIProviderError,
    AIProviderNetworkError,
    AIProviderTimeoutError,
    MockLLMProvider,
    OllamaProvider,
)
from sentinel.ai.report_generator import ReportGenerator
from sentinel.ai.security_analyzer import SecurityAnalyzer
from sentinel.core.enums import FindingCategory, FindingCertainty, Severity
from sentinel.core.models import Finding, RiskScoreSummary, ScanMetadata
from sentinel.orchestrator.pipeline import ScanExecutionResult


# ==============================================================================
# 1. PROVIDER-SPECIFIC TIMEOUTS & OLLAMA CONFIGURATION
# ==============================================================================

def test_ai_config_provider_specific_timeout_defaults():
    """Validates that Ollama defaults to 90s while cloud providers default to 30s."""
    cfg_gemini = AIConfig(provider="gemini")
    assert cfg_gemini.timeout_seconds == 30

    cfg_openai = AIConfig(provider="openai")
    assert cfg_openai.timeout_seconds == 30

    cfg_ollama = AIConfig(provider="ollama")
    assert cfg_ollama.timeout_seconds == 90
    assert cfg_ollama.max_retries == 0  # Default 0 retries for local Ollama to avoid freezing
    assert cfg_ollama.ollama_keep_alive == "0s"
    assert cfg_ollama.ollama_num_ctx == 2048
    assert cfg_ollama.ollama_num_predict == 1024


def test_ai_config_environment_overrides_provider_timeouts():
    """Validates that provider-specific timeout environment variables override defaults."""
    env = {
        "SENTINEL_AI_PROVIDER": "ollama",
        "SENTINEL_AI_OLLAMA_TIMEOUT": "120",
        "SENTINEL_AI_OLLAMA_KEEP_ALIVE": "1m",
        "SENTINEL_AI_OLLAMA_NUM_CTX": "4096",
        "SENTINEL_AI_OLLAMA_NUM_PREDICT": "512",
    }
    with patch.dict(os.environ, env, clear=True):
        cfg = AIConfig.from_env()
        assert cfg.provider == "ollama"
        assert cfg.timeout_seconds == 120
        assert cfg.ollama_keep_alive == "1m"
        assert cfg.ollama_num_ctx == 4096
        assert cfg.ollama_num_predict == 512


# ==============================================================================
# 2. OLLAMA REQUEST PAYLOAD OPTIMIZATION & RESOURCE CAPPING
# ==============================================================================

def test_ollama_provider_payload_includes_resource_caps():
    """Ensures Ollama request payload includes num_predict, num_ctx, and keep_alive."""
    cfg = AIConfig(
        provider="ollama",
        model="qwen2.5:7b",
        ollama_num_predict=512,
        ollama_num_ctx=2048,
        ollama_keep_alive="0s",
    )
    prov = OllamaProvider(cfg)

    captured_req = None

    def mock_urlopen(req, timeout):
        nonlocal captured_req
        captured_req = req
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "message": {"content": '{"status": "ok"}'},
            "prompt_eval_count": 25,
            "eval_count": 50,
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        resp = prov.generate("Hello test", json_mode=True)
        assert resp.parsed_json == {"status": "ok"}

    assert captured_req is not None
    body = json.loads(captured_req.data.decode("utf-8"))
    assert body["model"] == "qwen2.5:7b"
    assert body["format"] == "json"
    assert body["keep_alive"] == "0s"
    assert body["options"]["num_predict"] == 512
    assert body["options"]["num_ctx"] == 2048


# ==============================================================================
# 3. TIMEOUT CLASSIFICATION & FAST-FAIL RETRY SUPPRESSION
# ==============================================================================

def test_ollama_provider_raises_timeout_error():
    """Validates that socket/URLError timeouts are classified as AIProviderTimeoutError."""
    cfg = AIConfig(provider="ollama", timeout_seconds=90)
    prov = OllamaProvider(cfg)

    url_timeout = urllib.error.URLError(socket.timeout("timed out"))
    with patch("urllib.request.urlopen", side_effect=url_timeout):
        with pytest.raises(AIProviderTimeoutError) as exc_info:
            prov.generate("Test prompt")
        assert "timed out after 90s" in str(exc_info.value)


def test_ai_client_skips_retries_on_ollama_timeout():
    """Ensures AIClient fast-fails without retries when Ollama times out."""
    cfg = AIConfig(enabled=True, provider="ollama", timeout_seconds=90, max_retries=2)
    mock_prov = MagicMock()
    mock_prov.generate.side_effect = AIProviderTimeoutError("Ollama request timed out after 90s.")

    client = AIClient(config=cfg, provider=mock_prov)
    result = client.generate_json("Analyze heavy prompt")

    # Fast-fail: Must call generate exactly once (0 retries) to avoid compounding stalls
    assert mock_prov.generate.call_count == 1
    assert result is None


def test_ai_client_allows_bounded_retries_for_cloud_providers():
    """Ensures remote cloud providers still allow bounded retries on transient errors."""
    cfg = AIConfig(enabled=True, provider="gemini", timeout_seconds=30, max_retries=1, api_key="test-key")
    mock_prov = MagicMock()
    mock_prov.generate.side_effect = [
        AIProviderNetworkError("Transient DNS error"),
        MagicMock(raw_text='{"result": "success"}', parsed_json={"result": "success"}),
    ]

    client = AIClient(config=cfg, provider=mock_prov)
    result = client.generate_json("Prompt")

    # 1 initial attempt + 1 retry = 2 attempts
    assert mock_prov.generate.call_count == 2
    assert result == {"result": "success"}


# ==============================================================================
# 4. BATCHED SECURITY FINDING ANALYSIS (N -> 1 CALL)
# ==============================================================================

def test_security_analyzer_batches_multiple_findings():
    """Verifies SecurityAnalyzer explains multiple findings in a single batched LLM request."""
    cfg = AIConfig(enabled=True, provider="mock")
    client = AIClient(config=cfg)

    # Mock LLM provider that handles batched response
    mock_prov = MagicMock()
    mock_prov.generate.return_value = MagicMock(
        raw_text=json.dumps({
            "explanations": [
                {
                    "finding_id": "FINDING-01",
                    "plain_title": "Unprotected Component",
                    "simplified_explanation": "A component is exposed without guard.",
                    "attack_scenario": "Attacker invokes component.",
                    "business_impact": "Unauthorized access.",
                    "remediation_guide": "Set exported=false.",
                    "urgency": "IMMEDIATE",
                },
                {
                    "finding_id": "FINDING-02",
                    "plain_title": "Dangerous Permission",
                    "simplified_explanation": "Permission grants notification access.",
                    "attack_scenario": "App spams alerts.",
                    "business_impact": "User annoyance.",
                    "remediation_guide": "Check need.",
                    "urgency": "INFORMATIONAL",
                },
            ]
        }),
        parsed_json=None,
    )
    client.provider = mock_prov

    analyzer = SecurityAnalyzer(ai_client=client)

    findings = [
        Finding(
            id="FINDING-01",
            title="Exported Receiver",
            category=FindingCategory.ATTACK_SURFACE,
            severity=Severity.HIGH,
            confidence=0.9,
            certainty=FindingCertainty.POTENTIAL,
            description="Receiver is exported",
            impact="Unauthorized invoke",
            recommendation="Set exported=false",
            evidence={"component": "MyReceiver"},
        ),
        Finding(
            id="FINDING-02",
            title="Notification Permission",
            category=FindingCategory.SECURITY,
            severity=Severity.LOW,
            confidence=0.85,
            certainty=FindingCertainty.OBSERVATION,
            description="Permission requested",
            impact="Grants post notifications",
            recommendation="Review usage",
            evidence={"permission": "POST_NOTIFICATIONS"},
        ),
    ]

    explanations = analyzer.explain_all_findings(findings)

    # Crucial assertion: exactly 1 LLM request for all 2 findings
    assert mock_prov.generate.call_count == 1
    assert len(explanations) == 2
    assert explanations[0].finding_id == "FINDING-01"
    assert explanations[0].plain_title == "Unprotected Component"
    assert explanations[0].is_ai_generated is True

    assert explanations[1].finding_id == "FINDING-02"
    assert explanations[1].plain_title == "Dangerous Permission"
    assert explanations[1].is_ai_generated is True


def test_security_analyzer_batched_fallback_on_timeout():
    """Verifies that SecurityAnalyzer falls back to deterministic explanations if batch call times out."""
    cfg = AIConfig(enabled=True, provider="ollama")
    client = AIClient(config=cfg)

    # Provider that raises timeout error
    mock_prov = MagicMock()
    mock_prov.generate.side_effect = AIProviderTimeoutError("Ollama request timed out after 90s.")
    client.provider = mock_prov

    analyzer = SecurityAnalyzer(ai_client=client)

    findings = [
        Finding(
            id="FINDING-TIMEOUT-01",
            title="Unencrypted Communication",
            category=FindingCategory.NETWORK,
            severity=Severity.HIGH,
            confidence=0.9,
            certainty=FindingCertainty.CONFIRMED,
            description="Cleartext HTTP used",
            impact="Traffic interception",
            recommendation="Enforce TLS",
        ),
        Finding(
            id="FINDING-TIMEOUT-02",
            title="Exported Activity",
            category=FindingCategory.ATTACK_SURFACE,
            severity=Severity.MEDIUM,
            confidence=0.85,
            certainty=FindingCertainty.POTENTIAL,
            description="Activity exported",
            impact="Direct launch",
            recommendation="Set exported=false",
        ),
    ]

    explanations = analyzer.explain_all_findings(findings)

    # Only 1 attempt made, 0 retries on Ollama timeout
    assert mock_prov.generate.call_count == 1
    assert len(explanations) == 2

    # Deterministic fallback explanations returned with preserved IDs and evidence
    assert explanations[0].finding_id == "FINDING-TIMEOUT-01"
    assert explanations[0].plain_title == "Unencrypted Communication"
    assert explanations[0].is_ai_generated is False

    assert explanations[1].finding_id == "FINDING-TIMEOUT-02"
    assert explanations[1].plain_title == "Exported Activity"
    assert explanations[1].is_ai_generated is False


# ==============================================================================
# 5. REPORT GENERATOR RESILIENCE ON AI TIMEOUT
# ==============================================================================

def test_report_generator_fallback_on_llm_timeout():
    """Ensures ReportGenerator produces a complete report via deterministic fallback when LLM times out."""
    cfg = AIConfig(enabled=True, provider="ollama")
    client = AIClient(config=cfg)

    mock_prov = MagicMock()
    mock_prov.generate.side_effect = AIProviderTimeoutError("Ollama timed out.")
    client.provider = mock_prov

    gen = ReportGenerator(ai_client=client)

    scan_result = ScanExecutionResult(
        scan_id="MS-FALLBACK-01",
        metadata=ScanMetadata(
            scan_id="MS-FALLBACK-01",
            app_path="app.apk",
            app_hash_sha256="abc",
            app_name="Aurum",
            package_name="com.example.aurum",
        ),
        apk_meta=None,
        device_name="emulator-5554",
        findings=[
            Finding(
                id="F-01",
                title="Finding 1",
                category=FindingCategory.SECURITY,
                severity=Severity.LOW,
                confidence=0.9,
                certainty=FindingCertainty.OBSERVATION,
                description="desc",
                impact="impact",
                recommendation="rec",
            )
        ],
        risk_summary=RiskScoreSummary(overall_score=95.0, risk_level="LOW"),
    )

    report_summary = gen.generate_report(scan_result)

    assert report_summary is not None
    assert isinstance(report_summary, AIReportSummary)
    assert report_summary.is_ai_generated is False
    assert "Mobile Sentinel completed an automated audit" in report_summary.executive_summary
    assert mock_prov.generate.call_count == 1  # Exactly 1 attempt, zero retries


# ==============================================================================
# 6. ZERO-CALL ISOLATION DURING DETERMINISTIC SCANS (--NO-AI)
# ==============================================================================

def test_deterministic_scan_makes_zero_ai_provider_calls():
    """Guarantees that when AI is disabled (--no-ai), no provider is instantiated or called."""
    cfg = AIConfig(enabled=False, provider="ollama")
    client = AIClient(config=cfg)

    assert client.is_enabled is False
    assert client.provider is None  # Never created

    # Test SecurityAnalyzer with disabled AI
    sec_an = SecurityAnalyzer(ai_client=client)
    finding = Finding(
        id="F-DET-01",
        title="Test Finding",
        category=FindingCategory.SECURITY,
        severity=Severity.LOW,
        confidence=0.9,
        certainty=FindingCertainty.OBSERVATION,
        description="Test desc",
        impact="Test impact",
        recommendation="Test rec",
    )
    exps = sec_an.explain_all_findings([finding])
    assert len(exps) == 1
    assert exps[0].is_ai_generated is False

    # Test ReportGenerator with disabled AI
    rep_gen = ReportGenerator(ai_client=client)
    res = rep_gen.generate_report(findings=[finding])
    assert res.is_ai_generated is False
    assert "Mobile Sentinel completed an automated audit" in res.executive_summary
