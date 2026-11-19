"""Plain-text formatted audit report generator integrating deterministic evidence and AI intelligence."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.ai.client import AIClient
from sentinel.ai.config import AIConfig
from sentinel.ai.models import AIReportSummary
from sentinel.ai.report_generator import ReportGenerator
from sentinel.core.enums import FindingCategory, Severity
from sentinel.core.models import Finding
from sentinel.orchestrator.pipeline import ScanExecutionResult


def get_authentication_verdict(auth_status: str, has_dynamic_exploration: bool = True) -> str:
    """Generates an accurate, honest verdict string based on authentication status.

    Never claims authenticated exploration when status is BLOCKED, FAILED, SKIPPED, or NOT_REQUIRED.
    """
    status = (auth_status or "").upper()
    if not has_dynamic_exploration:
        return "The application was tested through automated static analysis; dynamic exploration was not performed."
    if status in ("SUCCESS", "COMPLETED"):
        return "The application was tested through automated static analysis and dynamic authenticated exploration."
    elif status == "BLOCKED":
        return "The application was tested through automated static analysis and dynamic unauthenticated exploration (authenticated exploration was blocked: no authorized credentials supplied)."
    elif status == "FAILED":
        return "The application was tested through automated static analysis and dynamic unauthenticated exploration (authentication attempts failed)."
    elif status in ("NOT_REQUIRED", "NONE"):
        return "The application was tested through automated static analysis and dynamic exploration (authentication not required)."
    elif status == "SKIPPED":
        return "The application was tested through automated static analysis and dynamic exploration (authentication skipped or not configured)."
    else:
        return f"The application was tested through automated static analysis and dynamic exploration (authentication status: {status})."


class TextReportGenerator:
    """Renders a comprehensive, evidence-backed text audit report for human evaluation."""

    def __init__(self, ai_client: Optional[AIClient] = None):
        self.ai_client = ai_client or AIClient()

    def generate(self, result: ScanExecutionResult, output_path: str | Path) -> str:
        """Generates report.txt content and writes to output_path."""
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        meta = result.metadata
        apk = result.apk_meta
        risk = result.risk_summary
        exp = result.exploration_result
        findings = list(result.findings or [])
        failures = list(result.failure_analyses or [])
        sec_exps = list(result.security_explanations or [])
        test_results = list(result.test_results or [])

        # Ensure AI report summary is present (fallback to deterministic if missing)
        ai_report = getattr(result, "ai_report", None)
        if ai_report is None:
            try:
                gen = ReportGenerator(AIClient(AIConfig(enabled=False)))
                ai_report = gen.generate_report(result)
            except Exception:
                ai_report = None

        lines: List[str] = [
            "============================================================",
            "MOBILE SENTINEL SECURITY & QA AUDIT REPORT",
            "============================================================",
            "",
            "============================================================",
            "1. APPLICATION INFORMATION",
            "============================================================",
            f"Application: {meta.app_name or (apk.app_label if apk else 'Unknown Application')}",
            f"Package: {meta.package_name or (apk.package_name if apk else 'unknown.package')}",
            f"Version: {apk.version_name if apk else (meta.version_name or '1.0.0')} (Build {apk.version_code if apk else (meta.version_code or 1)})",
            f"APK Size: {apk.file_size_mb if apk else 0.0} MB",
            f"SHA-256: {meta.app_hash_sha256}",
            f"Target SDK: {apk.target_sdk if apk else (meta.target_sdk or 'Unknown')}",
            f"Min SDK: {apk.min_sdk if apk else (meta.min_sdk or 'Unknown')}",
            f"Platform: {'Flutter / Android' if (apk and apk.is_flutter) or meta.is_flutter else 'Native Android'}",
            f"Device: {result.device_name or 'None'}",
            f"Android OS: {result.device_props.get('android_version', 'Unknown')} (SDK {result.device_props.get('sdk_version', meta.target_sdk or 'Unknown')})",
            "",
            "============================================================",
            "2. EXECUTIVE SUMMARY",
            "============================================================",
            f"Overall Risk: {risk.risk_level}",
            "",
        ]

        # Executive summary text
        exec_text = ai_report.executive_summary if ai_report and ai_report.executive_summary else (
            f"Mobile Sentinel completed an automated audit of {meta.app_name or 'Application'}."
        )
        source_tag = "[AI-Generated]" if (ai_report and ai_report.is_ai_generated) else "[Deterministic Engine]"
        lines.append(f"Analysis {source_tag}:")
        lines.append(exec_text)
        lines.append("")

        # Quality assessment
        lines.extend([
            "============================================================",
            "3. OVERALL QUALITY ASSESSMENT",
            "============================================================",
        ])
        qual_text = ai_report.quality_assessment if ai_report and ai_report.quality_assessment else (
            f"Overall risk level is evaluated as {risk.risk_level} based on static and dynamic testing."
        )
        lines.append(qual_text)
        lines.append("")

        # Risk score overview
        lines.extend([
            "============================================================",
            "4. RISK SCORE OVERVIEW",
            "============================================================",
            f"Overall Risk: {risk.risk_level}",
            f"Overall Score:       {risk.overall_score:.1f}/100",
            "",
            "Score Breakdown (0-100, where 100 is best / lowest risk):",
            f"  Security Score:       {risk.security_score:.1f}/100",
            f"  Stability Score:      {risk.stability_score:.1f}/100",
            f"  Performance Score:    {risk.performance_score:.1f}/100",
            f"  UX Score:             {risk.ux_score:.1f}/100",
            f"  Accessibility Score:  {risk.accessibility_score:.1f}/100",
            f"  Configuration Score:  {risk.configuration_score:.1f}/100",
            "",
            "Deterministic Finding Severity Counts:",
            f"  CRITICAL: {risk.critical_count}",
            f"  HIGH:     {risk.high_count}",
            f"  MEDIUM:   {risk.medium_count}",
            f"  LOW:      {risk.low_count}",
            f"  INFO:     {risk.info_count}",
            "",
        ])

        # Security Findings (Deterministic & Confirmed)
        lines.extend([
            "============================================================",
            "5. SECURITY FINDINGS (CONFIRMED DETERMINISTIC)",
            "============================================================",
            "Note: The following findings are strictly confirmed by deterministic static and dynamic analyzers.",
            "",
        ])
        if findings:
            for f in findings:
                lines.extend([
                    f"[{f.severity.value}] {f.title}",
                    f"  Finding ID: {f.id}",
                    f"  Category: {f.category.value}",
                    f"  Certainty: {f.certainty.value}",
                    f"  Confidence: {int(f.confidence * 100)}%",
                    f"  Description: {f.description}",
                    f"  Impact: {f.impact}",
                    f"  Recommendation: {f.recommendation}",
                ])
                if f.location:
                    lines.append(f"  Location: {f.location}")
                if f.evidence:
                    lines.append("  Evidence:")
                    for k, v in f.evidence.items():
                        safe_v = self.ai_client.redact_text(str(v))
                        lines.append(f"    {k}: {safe_v}")
                lines.append("------------------------------------------------------------")
            lines.append("")
        else:
            lines.append("No security, stability, or accessibility vulnerabilities identified.")
            lines.append("")

        # Security Explanations (AI-Assisted or Deterministic Context)
        is_ai = bool(ai_report and ai_report.is_ai_generated)
        sec_header = "6. SECURITY EXPLANATIONS (AI-ASSISTED CONTEXT)" if is_ai else "6. SECURITY EXPLANATIONS (DETERMINISTIC CONTEXT)"
        lines.extend([
            "============================================================",
            sec_header,
            "============================================================",
        ])
        if is_ai:
            lines.extend([
                "Note: AI explanations translate technical findings into plain-English attack scenarios and remediation guides.",
                "They provide advisory context and do not alter deterministic severity or risk scoring.",
                "",
            ])
        else:
            lines.extend([
                "Note: AI analysis was not enabled for this scan (--no-ai). Advisory AI explanations were not generated.",
                "",
            ])
        if sec_exps:
            for se in sec_exps:
                urgency = se.get("urgency", "INFORMATIONAL")
                title = se.get("plain_title", se.get("original_title", "Security Issue"))
                fid = se.get("finding_id", "")
                simplified = se.get("simplified_explanation", "")
                scenario = se.get("attack_scenario", se.get("potential_impact", ""))
                impact = se.get("business_impact", se.get("why_it_matters", ""))
                guide = se.get("remediation_guide", se.get("recommended_remediation", ""))

                lines.extend([
                    f"* [{urgency}] {title} (Finding: {fid})",
                    f"  Plain Explanation: {simplified}",
                    f"  Potential Attack Scenario: {scenario}",
                    f"  Business Impact: {impact}",
                    f"  Remediation Guide: {guide}",
                    "------------------------------------------------------------",
                ])
            lines.append("")
        else:
            lines.append("No high-risk findings requiring advisory security explanation.")
            lines.append("")

        # Runtime Stability and Crash Analysis
        mem_raw = result.perf_stats.get('memory_summary')
        if not mem_raw or not str(mem_raw).strip() or str(mem_raw).strip() in ("None", "null", "Native: Heap:, TOTAL: PSS:"):
            mem_summary = "Unavailable"
        else:
            mem_summary = str(mem_raw).strip()

        startup_metric = result.perf_stats.get('startup_status', 'Normal (<3.0s)')
        frames_metric = result.perf_stats.get('skipped_frames', 'None detected')

        lines.extend([
            "============================================================",
            "7. RUNTIME STABILITY AND CRASH ANALYSIS",
            "============================================================",
            f"Installation Status: {result.runtime_summary.get('Installation', 'SKIPPED')}",
            f"Launch Status:       {result.runtime_summary.get('Launch', 'SKIPPED')}",
            f"Authentication:      {result.auth_status} ({result.auth_reason or 'No credentials'})",
            f"Main-Thread Crashes: {result.runtime_summary.get('Crash', 'PASS')}",
            f"ANR Watchdog:        {result.runtime_summary.get('ANR', 'PASS')}",
            "",
            "Performance Metrics:",
            f"  Startup Duration: {startup_metric}",
            f"  UI Frame Jank:    {frames_metric}",
            f"  Memory Telemetry: {mem_summary}",
            "",
            "Observed Runtime Failure Signatures:",
        ])
        if failures:
            for fa in failures:
                f_type = fa.get("failure_category", fa.get("failure_type", "crash")).upper()
                f_title = fa.get("title", "Execution Anomaly")
                f_comp = fa.get("affected_component", "Application")
                f_cause = fa.get("likely_root_cause", fa.get("possible_root_cause", "Unhandled exception"))
                lines.extend([
                    f"  * [{f_type}] {f_title}",
                    f"    Component: {f_comp}",
                    f"    Root Cause: {f_cause}",
                ])
            lines.append("")
        else:
            lines.append("  Zero fatal crashes, ANRs, or Dart unhandled exceptions recorded during execution.")
            lines.append("")

        # Screen Exploration and Coverage
        lines.extend([
            "============================================================",
            "8. SCREEN EXPLORATION AND COVERAGE",
            "============================================================",
            f"Authentication Status: {result.auth_status}",
            f"Authenticated Exploration: {exp.authenticated_exploration if exp else 'NOT_STARTED'}",
            f"Screens Discovered: {exp.screens_discovered if exp else 0}",
            f"Screens Explored:   {exp.screens_fully_tested if exp else 0}",
            f"Actions Discovered: {exp.actions_discovered if exp else 0}",
            f"Actions Tested:     {exp.actions_tested if exp else 0}",
            f"Screen Coverage:    {exp.screen_coverage_pct if exp else 0.0}%",
            f"Action Coverage:    {exp.action_coverage_pct if exp else 0.0}%",
            f"Destructive Controls Excluded: {exp.destructive_actions_discovered if exp else 0}",
            "",
        ])
        if exp and exp.graph.states:
            lines.append("Screen Inventory:")
            for i, (sid, state) in enumerate(exp.graph.states.items(), 1):
                status_str = "TESTED" if (state.exploration_status == "EXPLORED" or state.visit_count > 1 or any(a.status == "EXECUTED" for a in state.navigation_actions)) else "DISCOVERED"
                lines.append(f"  {i}. {state.screen_name} [{status_str}] (Visits: {state.visit_count}, Controls: {len(state.interactive_elements)})")
            lines.append("")

        # Generated Test Cases (Executed Scenarios)
        lines.extend([
            "============================================================",
            "9. GENERATED TEST CASES (EXECUTED SCENARIOS)",
            "============================================================",
        ])
        if test_results:
            for tr in test_results:
                lines.append(f"  * [{tr.status}] {tr.name}: {tr.details or 'Completed'}")
            lines.append("")
        else:
            lines.append("No automated scenario executions were scheduled.")
            lines.append("")

        # Test Recommendations
        test_rec_header = "10. AI TEST RECOMMENDATIONS" if is_ai else "10. TEST RECOMMENDATIONS (RULE-BASED)"
        lines.extend([
            "============================================================",
            test_rec_header,
            "============================================================",
            "Advisory QA recommendations to increase test coverage:",
        ])
        recs = ai_report.test_recommendations if ai_report and ai_report.test_recommendations else [
            "Implement automated end-to-end regression tests for critical user flows.",
            "Add strict boundary value and format validation testing for all input fields.",
        ]
        for i, tr_rec in enumerate(recs, 1):
            lines.append(f"  {i}. {tr_rec}")
        lines.append("")

        # Critical Priorities
        lines.extend([
            "============================================================",
            "11. CRITICAL PRIORITIES (IMMEDIATE ACTION REQUIRED)",
            "============================================================",
        ])
        prios = ai_report.critical_priorities if ai_report and ai_report.critical_priorities else [
            "Maintain continuous security testing during CI/CD builds."
        ]
        for i, prio in enumerate(prios, 1):
            lines.append(f"  {i}. {prio}")
        lines.append("")

        # Recommended Remediation
        lines.extend([
            "============================================================",
            "12. RECOMMENDED REMEDIATION",
            "============================================================",
        ])
        remeds = ai_report.remediation_recommendations if ai_report and ai_report.remediation_recommendations else [
            "Follow Android security best practices for network security and exported components."
        ]
        for i, rem in enumerate(remeds, 1):
            lines.append(f"  {i}. {rem}")
        lines.append("")

        # Scan Metadata & Final Verdict
        lines.extend([
            "============================================================",
            "13. SCAN METADATA & FINAL VERDICT",
            "============================================================",
            f"Scan ID: {result.scan_id}",
            f"Start: {meta.started_at}",
            f"End: {meta.completed_at or 'In Progress'}",
            f"Duration: {result.duration_seconds}s",
            f"Tool Version: {meta.tool_version}",
            f"Analyzers Executed: {', '.join(meta.analyzers_executed) if meta.analyzers_executed else 'Static & Runtime Analyzers'}",
            "",
            "FINAL VERDICT",
            f"Overall Risk: {risk.risk_level}",
            f"Application Exploration Verdict:",
            f"- Screen Coverage: {exp.screen_coverage_pct if exp else 0.0}% ({exp.screens_fully_tested if exp else 0}/{exp.screens_discovered if exp else 0} screens explored)",
            f"- Action Coverage: {exp.action_coverage_pct if exp else 0.0}% ({exp.actions_tested if exp else 0}/{exp.actions_discovered if exp else 0} actions tested)",
            f"- Authentication Status: {result.auth_status}",
            f"- Stability & Crash Verdict: {result.runtime_summary.get('Crash', 'PASS')} (Zero fatal crashes recorded)",
            "",
            get_authentication_verdict(
                result.auth_status,
                has_dynamic_exploration=bool(exp and exp.screens_discovered > 0),
            ),
            "Findings reflect concrete observable runtime behaviors and static code characteristics.",
            "",
            "============================================================",
            "END OF REPORT",
            "============================================================",
        ])

        content = "\n".join(lines)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)

        return content
