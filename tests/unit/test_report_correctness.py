"""Targeted regression tests for Report Correctness (Issues 1, 2, 3 and Additional Checks).

Validates:
1. Action and screen coverage calculations (0/0, 7/8, 8/8, tested > discovered).
2. Authentication verdict accuracy (SUCCESS, BLOCKED, FAILED, NOT_REQUIRED, SKIPPED).
3. Memory telemetry handling (dumpsys parsing, missing/null/empty safety, 'Unavailable' rendering).
4. Startup duration and UI frame-jank metric independence.
5. Invariance of finding severity counts across JSON, TXT, and risk models.
6. Honest deterministic reporting when --no-ai is active.
"""

from pathlib import Path
from unittest.mock import MagicMock
import json
import pytest

from sentinel.ai.models import AIReportSummary
from sentinel.core.enums import FindingCategory, FindingCertainty, Severity
from sentinel.core.models import Finding, RiskScoreSummary, ScanMetadata
from sentinel.orchestrator.pipeline import ScanExecutionResult
from sentinel.reporting.json_report import JsonReportGenerator
from sentinel.reporting.text_report import TextReportGenerator, get_authentication_verdict
from sentinel.runtime.adb import ADBController
from sentinel.ui_testing.models import (
    ExplorationResult,
    calculate_action_coverage,
    calculate_screen_coverage,
)


def _make_scan_result(**kwargs) -> ScanExecutionResult:
    """Helper to build ScanExecutionResult with all mandatory fields populated."""
    sid = kwargs.get("scan_id", "MS-TEST-01")
    meta = kwargs.pop("metadata", None) or ScanMetadata(
        scan_id=sid,
        app_path="app.apk",
        app_hash_sha256="abc1234567890abcdef",
        app_name="Aurum",
        package_name="com.example.aurum",
    )
    defaults = {
        "scan_id": sid,
        "metadata": meta,
        "apk_meta": None,
        "device_name": "emulator-5554",
    }
    defaults.update(kwargs)
    return ScanExecutionResult(**defaults)


# ==============================================================================
# ISSUE 1: ACTION & SCREEN COVERAGE REGRESSION TESTS
# ==============================================================================

def test_action_coverage_calculation_boundary_cases():
    """Validates action coverage calculation across 0/0, 7/8, 8/8, and tested > discovered."""
    # 0/0 -> 0.0%
    assert calculate_action_coverage(0, 0) == 0.0
    assert calculate_action_coverage(-1, 0) == 0.0
    assert calculate_action_coverage(0, -5) == 0.0

    # 7/8 -> 87.5%
    assert calculate_action_coverage(7, 8) == 87.5

    # 8/8 -> 100.0%
    assert calculate_action_coverage(8, 8) == 100.0

    # tested exceeds discovered (e.g. 10/8, 9/8) -> capped at 100.0%
    assert calculate_action_coverage(10, 8) == 100.0
    assert calculate_action_coverage(9, 8) == 100.0
    assert calculate_action_coverage(100, 50) == 100.0


def test_screen_coverage_calculation_boundary_cases():
    """Validates screen coverage calculation across 0/0, 2/3, 2/2, and tested > discovered."""
    assert calculate_screen_coverage(0, 0) == 0.0
    assert calculate_screen_coverage(2, 3) == 66.7
    assert calculate_screen_coverage(2, 2) == 100.0
    assert calculate_screen_coverage(4, 2) == 100.0


def test_exploration_result_model_coverage_consistency():
    """Ensures ExplorationResult post-init guarantees mathematical consistency."""
    # 8/8 discovered/tested
    res_full = ExplorationResult(
        screens_discovered=2,
        screens_explored=2,
        actions_discovered=8,
        actions_tested=8,
    )
    assert res_full.actions_discovered == 8
    assert res_full.actions_tested == 8
    assert res_full.action_coverage_pct == 100.0
    assert res_full.screen_coverage_pct == 100.0

    d_full = res_full.to_dict()
    assert d_full["actions_discovered"] == 8
    assert d_full["actions_tested"] == 8
    assert d_full["action_coverage_pct"] == 100.0

    # 7/8 discovered/tested
    res_partial = ExplorationResult(
        screens_discovered=2,
        screens_explored=2,
        actions_discovered=8,
        actions_tested=7,
    )
    assert res_partial.action_coverage_pct == 87.5

    # 0/0 discovered/tested
    res_zero = ExplorationResult(
        screens_discovered=0,
        screens_explored=0,
        actions_discovered=0,
        actions_tested=0,
    )
    assert res_zero.action_coverage_pct == 0.0
    assert res_zero.screen_coverage_pct == 0.0

    # tested exceeds discovered (e.g. 10 tested, 8 discovered)
    res_exceed = ExplorationResult(
        screens_discovered=2,
        screens_explored=3,
        actions_discovered=8,
        actions_tested=10,
    )
    # actions_discovered adjusted to at least tested
    assert res_exceed.actions_discovered >= 10
    assert res_exceed.actions_tested == 10
    assert res_exceed.action_coverage_pct == 100.0
    assert res_exceed.screens_discovered >= 3
    assert res_exceed.screen_coverage_pct == 100.0


# ==============================================================================
# ISSUE 2: AUTHENTICATION VERDICT REGRESSION TESTS
# ==============================================================================

def test_authentication_verdict_wording_all_statuses():
    """Verifies that authentication status produces truthful report wording."""
    # SUCCESS: authenticated exploration claimed
    success_text = get_authentication_verdict("SUCCESS", has_dynamic_exploration=True)
    assert "dynamic authenticated exploration" in success_text

    # BLOCKED: NEVER claims authenticated exploration
    blocked_text = get_authentication_verdict("BLOCKED", has_dynamic_exploration=True)
    assert "authenticated exploration was blocked" in blocked_text
    assert "dynamic unauthenticated exploration" in blocked_text
    assert "dynamic authenticated exploration" not in blocked_text

    # FAILED: NEVER claims authenticated exploration
    failed_text = get_authentication_verdict("FAILED", has_dynamic_exploration=True)
    assert "authentication attempts failed" in failed_text
    assert "dynamic unauthenticated exploration" in failed_text
    assert "dynamic authenticated exploration" not in failed_text

    # NOT_REQUIRED: NEVER claims authenticated exploration
    not_req_text = get_authentication_verdict("NOT_REQUIRED", has_dynamic_exploration=True)
    assert "authentication not required" in not_req_text
    assert "dynamic authenticated exploration" not in not_req_text

    # SKIPPED: NEVER claims authenticated exploration
    skipped_text = get_authentication_verdict("SKIPPED", has_dynamic_exploration=True)
    assert "authentication skipped" in skipped_text
    assert "dynamic authenticated exploration" not in skipped_text

    # Static analysis only (no dynamic exploration performed)
    static_only_text = get_authentication_verdict("BLOCKED", has_dynamic_exploration=False)
    assert "dynamic exploration was not performed" in static_only_text


def test_text_report_renders_accurate_authentication_verdict(tmp_path: Path):
    """Verifies that the generated Text report uses the accurate verdict string."""
    gen = TextReportGenerator()
    res = _make_scan_result(
        scan_id="MS-AUTH-VERIFY-01",
        auth_status="BLOCKED",
        auth_reason="No authorized test credentials supplied",
        exploration_result=ExplorationResult(
            screens_discovered=2,
            screens_explored=2,
            actions_discovered=8,
            actions_tested=8,
            auth_status="BLOCKED",
        ),
    )
    out_file = tmp_path / "report.txt"
    report_content = gen.generate(res, out_file)

    # Must state exploration was unauthenticated and blocked
    assert "authenticated exploration was blocked: no authorized credentials supplied" in report_content
    # Must NOT claim dynamic authenticated exploration
    assert "The application was tested through automated static analysis and dynamic authenticated exploration." not in report_content


# ==============================================================================
# ISSUE 3: MEMORY TELEMETRY REGRESSION TESTS
# ==============================================================================

def test_adb_get_memory_info_dumpsys_parsing():
    """Validates that dumpsys meminfo output is parsed accurately without label fragments."""
    adb = ADBController()

    dumpsys_output = """
Applications Memory Usage (in Kilobytes):
Uptime: 12345 Realtime: 12345

** MEMINFO in pid 5678 [com.example.aurum] **
                   Pss  Private  Private  SwapPss      Rss     Heap     Heap     Heap
                 Total    Dirty    Clean    Dirty    Total     Size    Alloc     Free
                ------   ------   ------   ------   ------   ------   ------   ------
  Native Heap    15380    15360        0        0    21450    32768    15380    17388
  Dalvik Heap     4280     4250        0        0    12340    10240     4280     5960
        TOTAL    44884    42100        0        0    58214    43008    19660    23348

 App Summary
                       Pss(KB)                        Rss(KB)
                        ------                         ------
           Java Heap:     4280                          12340
         Native Heap:    15380                          21450
                Code:    12400                          18200
               Stack:     1024                           1024
            Graphics:     5200                           5200

           TOTAL PSS:    44884            TOTAL RSS:    58214       TOTAL SWAP (KB):        0
"""
    adb.run_shell = MagicMock(return_value=(0, dumpsys_output, ""))

    mem_info = adb.get_memory_info("com.example.aurum")
    assert mem_info["TOTAL PSS"] == "43.8 MB"
    assert mem_info["Native Heap"] == "15.0 MB"
    assert mem_info["Java Heap"] == "4.2 MB"
    for k, v in mem_info.items():
        assert v not in ("Heap:", "PSS:", ":", "None", "")


def test_adb_get_memory_info_handles_empty_and_unavailable():
    """Validates that missing or empty dumpsys output returns empty dict and never fabricates."""
    adb = ADBController()

    # Process not running
    adb.run_shell = MagicMock(return_value=(0, "No process found for: com.example.aurum", ""))
    assert adb.get_memory_info("com.example.aurum") == {}

    # ADB execution failure
    adb.run_shell = MagicMock(return_value=(1, "", "Device offline"))
    assert adb.get_memory_info("com.example.aurum") == {}


def test_text_report_memory_telemetry_unavailable_formatting(tmp_path: Path):
    """Ensures Text report displays 'Unavailable' cleanly when telemetry is empty or malformed."""
    gen = TextReportGenerator()

    # Case A: Empty dict / None
    res_empty = _make_scan_result(
        scan_id="MS-MEM-01",
        perf_stats={"memory_summary": ""},
    )
    txt_empty = gen.generate(res_empty, tmp_path / "report_empty.txt")
    assert "Memory Telemetry: Unavailable" in txt_empty

    # Case B: Legacy buggy string 'Native: Heap:, TOTAL: PSS:' is sanitized to Unavailable
    res_buggy = _make_scan_result(
        scan_id="MS-MEM-02",
        perf_stats={"memory_summary": "Native: Heap:, TOTAL: PSS:"},
    )
    txt_buggy = gen.generate(res_buggy, tmp_path / "report_buggy.txt")
    assert "Memory Telemetry: Unavailable" in txt_buggy
    assert "Native: Heap:, TOTAL: PSS:" not in txt_buggy

    # Case C: Real clean telemetry is displayed
    res_clean = _make_scan_result(
        scan_id="MS-MEM-03",
        perf_stats={"memory_summary": "TOTAL PSS: 43.8 MB, Native Heap: 15.0 MB"},
    )
    txt_clean = gen.generate(res_clean, tmp_path / "report_clean.txt")
    assert "Memory Telemetry: TOTAL PSS: 43.8 MB, Native Heap: 15.0 MB" in txt_clean


# ==============================================================================
# ADDITIONAL CHECKS: METRIC INDEPENDENCE, SEVERITY COUNTS & --NO-AI INTEGRITY
# ==============================================================================

def test_startup_duration_and_frame_jank_metric_independence(tmp_path: Path):
    """Validates that startup duration and frame jank metrics are reported independently."""
    gen = TextReportGenerator()
    res = _make_scan_result(
        scan_id="MS-PERF-01",
        perf_stats={
            "startup_status": "Normal (<3.0s)",
            "skipped_frames": "84 frames dropped (Choreographer)",
            "memory_summary": "TOTAL PSS: 43.8 MB",
        },
    )
    out = gen.generate(res, tmp_path / "report_perf.txt")

    assert "Startup Duration: Normal (<3.0s)" in out
    assert "UI Frame Jank:    84 frames dropped (Choreographer)" in out


def test_finding_severities_agreement_across_models(tmp_path: Path):
    """Verifies that finding counts agree across Findings list, RiskScoreSummary, and JSON/TXT reports."""
    findings = [
        Finding(
            id="FINDING-MED-01",
            title="Exported Receiver",
            category=FindingCategory.ATTACK_SURFACE,
            severity=Severity.MEDIUM,
            confidence=0.85,
            certainty=FindingCertainty.POTENTIAL,
            description="Exported receiver",
            impact="Attack surface",
            recommendation="Restrict export",
        ),
        Finding(
            id="FINDING-LOW-01",
            title="Dangerous Permission",
            category=FindingCategory.SECURITY,
            severity=Severity.LOW,
            confidence=0.90,
            certainty=FindingCertainty.OBSERVATION,
            description="Dangerous permission requested",
            impact="Data exposure",
            recommendation="Review necessity",
        ),
        Finding(
            id="FINDING-LOW-02",
            title="Main Thread Jank",
            category=FindingCategory.PERFORMANCE,
            severity=Severity.LOW,
            confidence=0.95,
            certainty=FindingCertainty.CONFIRMED,
            description="UI thread jank detected",
            impact="Frame drop",
            recommendation="Optimize",
        ),
        Finding(
            id="FINDING-INFO-01",
            title="Launcher Exported",
            category=FindingCategory.ATTACK_SURFACE,
            severity=Severity.INFO,
            confidence=1.0,
            certainty=FindingCertainty.OBSERVATION,
            description="Launcher exported",
            impact="Normal",
            recommendation="Sanitize intents",
        ),
        Finding(
            id="FINDING-INFO-02",
            title="Protected Service",
            category=FindingCategory.ATTACK_SURFACE,
            severity=Severity.INFO,
            confidence=0.9,
            certainty=FindingCertainty.OBSERVATION,
            description="Protected service",
            impact="Guarded",
            recommendation="Check perms",
        ),
        Finding(
            id="FINDING-INFO-03",
            title="Flutter Detected",
            category=FindingCategory.FLUTTER,
            severity=Severity.INFO,
            confidence=1.0,
            certainty=FindingCertainty.CONFIRMED,
            description="Flutter app detected",
            impact="Dart VM",
            recommendation="Obfuscate",
        ),
    ]

    risk_summary = RiskScoreSummary(
        overall_score=97.2,
        security_score=93.0,
        stability_score=100.0,
        performance_score=98.0,
        ux_score=100.0,
        accessibility_score=100.0,
        configuration_score=100.0,
        risk_level="MEDIUM",
        critical_count=0,
        high_count=0,
        medium_count=1,
        low_count=2,
        info_count=3,
    )

    res = _make_scan_result(
        scan_id="MS-SEV-COUNT-01",
        findings=findings,
        risk_summary=risk_summary,
    )

    # Verify JSON agreement
    json_gen = JsonReportGenerator()
    json_str = json_gen.generate(res, tmp_path / "report.json")
    data = json.loads(json_str)
    assert len(data["findings"]) == 6
    assert data["risk_summary"]["critical_count"] == 0
    assert data["risk_summary"]["high_count"] == 0
    assert data["risk_summary"]["medium_count"] == 1
    assert data["risk_summary"]["low_count"] == 2
    assert data["risk_summary"]["info_count"] == 3

    # Verify TXT agreement
    txt_gen = TextReportGenerator()
    txt_str = txt_gen.generate(res, tmp_path / "report.txt")
    assert "MEDIUM:   1" in txt_str
    assert "LOW:      2" in txt_str
    assert "INFO:     3" in txt_str
    assert "CRITICAL: 0" in txt_str
    assert "HIGH:     0" in txt_str


def test_deterministic_no_ai_report_integrity(tmp_path: Path):
    """Verifies that scans with AI disabled do not falsely claim AI generation."""
    gen = TextReportGenerator()

    # Deterministic fallback summary with is_ai_generated=False
    ai_rep = AIReportSummary(
        executive_summary="Mobile Sentinel completed an automated audit via deterministic engine.",
        quality_assessment="Evaluated across deterministic dimensions.",
        is_ai_generated=False,
    )

    res = _make_scan_result(
        scan_id="MS-NOAI-01",
        ai_report=ai_rep,
    )

    report_text = gen.generate(res, tmp_path / "report_no_ai.txt")

    # Section 2 executive summary tag
    assert "Analysis [Deterministic Engine]:" in report_text
    assert "[AI-Generated]" not in report_text

    # Section 6 header and note
    assert "6. SECURITY EXPLANATIONS (DETERMINISTIC CONTEXT)" in report_text
    assert "Note: AI analysis was not enabled for this scan (--no-ai)" in report_text

    # Section 10 header
    assert "10. TEST RECOMMENDATIONS (RULE-BASED)" in report_text
    assert "10. AI TEST RECOMMENDATIONS" not in report_text
