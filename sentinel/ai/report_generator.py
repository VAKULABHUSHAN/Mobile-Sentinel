"""AI-powered audit report generator with deterministic fallback and evidence grounding."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple

from sentinel.ai.client import AIClient
from sentinel.ai.models import AIReportSummary, FailureAnalysis, SecurityExplanation
from sentinel.ai.prompts import build_report_summary_prompt
from sentinel.core.logging import logger
from sentinel.core.models import Finding, RiskScoreSummary, ScanMetadata


def _get_attr(obj: Any, key: str, default: Any = None) -> Any:
    """Safely gets an attribute from a dataclass, object, or dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _ensure_string_list(val: Any) -> List[str]:
    """Ensures input is a list of non-empty strings."""
    if not val:
        return []
    if isinstance(val, str):
        return [val.strip()] if val.strip() else []
    if isinstance(val, (list, tuple, set)):
        result = []
        for item in val:
            s = str(item).strip()
            if s:
                result.append(s)
        return result
    return [str(val).strip()]


class ReportGenerator:
    """Synthesizes complete scan results into executive, security, stability, and remediation reports."""

    def __init__(self, ai_client: Optional[AIClient] = None):
        self.client = ai_client or AIClient()

    def generate(self, *args, **kwargs) -> AIReportSummary:
        """Alias for generate_report."""
        return self.generate_report(*args, **kwargs)

    def generate_report(
        self,
        scan_result: Optional[Any] = None,
        *,
        apk_meta: Optional[Any] = None,
        findings: Optional[List[Any]] = None,
        risk_summary: Optional[Any] = None,
        runtime_summary: Optional[Dict[str, str]] = None,
        failure_analyses: Optional[List[Any]] = None,
        security_explanations: Optional[List[Any]] = None,
        screen_analyses: Optional[List[Any]] = None,
        generated_tests: Optional[List[Any]] = None,
        exploration_result: Optional[Any] = None,
    ) -> AIReportSummary:
        """Generates a structured, evidence-grounded AI audit report with deterministic fallback.
        
        Preserves all original scan findings, severities, and risk scores without modification.
        """
        # 1. Extract and normalize input data from scan_result or kwargs
        if scan_result is not None:
            if hasattr(scan_result, "findings") and findings is None:
                findings = getattr(scan_result, "findings", [])
            if hasattr(scan_result, "apk_meta") and apk_meta is None:
                apk_meta = getattr(scan_result, "apk_meta", None)
            if hasattr(scan_result, "risk_summary") and risk_summary is None:
                risk_summary = getattr(scan_result, "risk_summary", None)
            if hasattr(scan_result, "runtime_summary") and runtime_summary is None:
                runtime_summary = getattr(scan_result, "runtime_summary", {})
            if hasattr(scan_result, "failure_analyses") and failure_analyses is None:
                failure_analyses = getattr(scan_result, "failure_analyses", [])
            if hasattr(scan_result, "security_explanations") and security_explanations is None:
                security_explanations = getattr(scan_result, "security_explanations", [])
            if hasattr(scan_result, "exploration_result") and exploration_result is None:
                exploration_result = getattr(scan_result, "exploration_result", None)

            # Support dict representation of scan_result
            if isinstance(scan_result, dict):
                if findings is None and "findings" in scan_result:
                    findings = scan_result["findings"]
                if apk_meta is None and "apk_metadata" in scan_result:
                    apk_meta = scan_result["apk_metadata"]
                if risk_summary is None and "risk_summary" in scan_result:
                    risk_summary = scan_result["risk_summary"]
                if runtime_summary is None and "runtime_summary" in scan_result:
                    runtime_summary = scan_result["runtime_summary"]
                if failure_analyses is None:
                    failure_analyses = scan_result.get("ai_insights", {}).get("failure_analyses", scan_result.get("failure_analyses", []))
                if security_explanations is None:
                    security_explanations = scan_result.get("ai_insights", {}).get("security_explanations", scan_result.get("security_explanations", []))
                if exploration_result is None and "exploration" in scan_result:
                    exploration_result = scan_result["exploration"]

        # Ensure safe defaults
        raw_findings = list(findings or [])
        raw_failures = list(failure_analyses or [])
        raw_explanations = list(security_explanations or [])
        raw_screen_analyses = list(screen_analyses or [])
        raw_generated_tests = list(generated_tests or [])
        runtime_dict = dict(runtime_summary or {})

        # Extract Application Metadata
        app_name = (
            _get_attr(apk_meta, "app_label")
            or _get_attr(scan_result, "app_name")
            or (_get_attr(_get_attr(scan_result, "metadata"), "app_name") if hasattr(scan_result, "metadata") else None)
            or "Android Application"
        )
        package_name = (
            _get_attr(apk_meta, "package_name")
            or _get_attr(scan_result, "package_name")
            or (_get_attr(_get_attr(scan_result, "metadata"), "package_name") if hasattr(scan_result, "metadata") else None)
            or "unknown.package"
        )
        version_name = _get_attr(apk_meta, "version_name", "1.0.0")
        target_sdk = _get_attr(apk_meta, "target_sdk", 0)
        is_flutter = bool(_get_attr(apk_meta, "is_flutter", False))

        app_info = {
            "name": app_name,
            "package": package_name,
            "version": version_name,
            "target_sdk": target_sdk,
            "is_flutter": is_flutter,
        }

        # Extract Risk Scores
        overall_score = float(_get_attr(risk_summary, "overall_score", 100.0))
        security_score = float(_get_attr(risk_summary, "security_score", 100.0))
        stability_score = float(_get_attr(risk_summary, "stability_score", 100.0))
        performance_score = float(_get_attr(risk_summary, "performance_score", 100.0))
        ux_score = float(_get_attr(risk_summary, "ux_score", 100.0))
        accessibility_score = float(_get_attr(risk_summary, "accessibility_score", 100.0))
        risk_level = str(_get_attr(risk_summary, "risk_level", "LOW")).upper()

        risk_info = {
            "overall": overall_score,
            "security": security_score,
            "stability": stability_score,
            "performance": performance_score,
            "ux": ux_score,
            "accessibility": accessibility_score,
            "risk_level": risk_level,
        }

        # Extract Normalized Findings (and redact secrets in titles, descriptions, recommendations)
        findings_list: List[Dict[str, Any]] = []
        for f in raw_findings:
            f_id = str(_get_attr(f, "id", "UNKNOWN"))
            f_title = self.client.redact_text(str(_get_attr(f, "title", "")))
            f_sev_raw = _get_attr(f, "severity", "LOW")
            f_sev = f_sev_raw.name if hasattr(f_sev_raw, "name") else str(f_sev_raw)
            f_cat_raw = _get_attr(f, "category", "GENERAL")
            f_cat = f_cat_raw.name if hasattr(f_cat_raw, "name") else str(f_cat_raw)
            f_desc = self.client.redact_text(str(_get_attr(f, "description", "")))
            f_impact = self.client.redact_text(str(_get_attr(f, "impact", "")))
            f_remed = self.client.redact_text(str(_get_attr(f, "recommendation", "")))
            f_loc = self.client.redact_text(str(_get_attr(f, "location", "")))

            # Redact evidence dict
            raw_ev = _get_attr(f, "evidence", {})
            clean_ev = {}
            if isinstance(raw_ev, dict):
                for ek, ev_val in raw_ev.items():
                    clean_ev[ek] = self.client.redact_text(str(ev_val))

            findings_list.append({
                "id": f_id,
                "title": f_title,
                "severity": f_sev,
                "category": f_cat,
                "description": f_desc,
                "impact": f_impact,
                "recommendation": f_remed,
                "location": f_loc,
                "evidence": clean_ev,
            })

        # Extract Exploration Stats
        screens_disc = int(_get_attr(exploration_result, "screens_discovered", 0))
        screens_exp = int(_get_attr(exploration_result, "screens_explored", 0))
        actions_tested = int(_get_attr(exploration_result, "actions_tested", 0))
        screen_cov = float(_get_attr(exploration_result, "screen_coverage_pct", 0.0))
        action_cov = float(_get_attr(exploration_result, "action_coverage_pct", 0.0))
        destr_disc = int(_get_attr(exploration_result, "destructive_actions_discovered", 0))

        exploration_info = {
            "screens_discovered": screens_disc,
            "screens_explored": screens_exp,
            "actions_tested": actions_tested,
            "screen_coverage_pct": screen_cov,
            "action_coverage_pct": action_cov,
            "destructive_actions_discovered": destr_disc,
        }

        # Extract Normalized Failures
        norm_failures: List[Dict[str, Any]] = []
        for fa in raw_failures:
            fa_type = str(_get_attr(fa, "failure_category", _get_attr(fa, "failure_type", "crash")))
            fa_title = self.client.redact_text(str(_get_attr(fa, "title", "")))
            fa_cause = self.client.redact_text(str(_get_attr(fa, "likely_root_cause", _get_attr(fa, "possible_root_cause", ""))))
            fa_comp = str(_get_attr(fa, "affected_component", "App"))
            norm_failures.append({
                "type": fa_type,
                "title": fa_title,
                "cause": fa_cause,
                "component": fa_comp,
            })

        # 2. Check if AI is disabled
        if not self.client.is_enabled:
            return self._generate_deterministic_fallback(
                app_info=app_info,
                risk_info=risk_info,
                findings_list=findings_list,
                runtime_info={"runtime_status": runtime_dict},
                exploration_info=exploration_info,
                failure_analyses=norm_failures,
                screen_analyses=raw_screen_analyses,
                generated_tests=raw_generated_tests,
            )

        # 3. Build Safe Prompt Metrics (Scrubbing any leftover sensitive credentials)
        # Prioritize critical and high findings to keep prompt size compact
        sorted_findings = sorted(
            findings_list,
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 5),
        )

        audit_metrics = {
            "application": app_info,
            "risk_scores": risk_info,
            "findings_summary": {
                "total": len(findings_list),
                "critical": sum(1 for f in findings_list if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in findings_list if f["severity"] == "HIGH"),
                "medium": sum(1 for f in findings_list if f["severity"] == "MEDIUM"),
                "low": sum(1 for f in findings_list if f["severity"] == "LOW"),
                "findings": sorted_findings[:10],
            },
            "runtime_stability": {
                "runtime_status": runtime_dict,
                "failures": norm_failures[:5],
            },
            "ui_exploration": exploration_info,
            "screen_analyses": raw_screen_analyses[:3],
            "generated_tests": raw_generated_tests[:3],
        }

        prompt = build_report_summary_prompt(audit_metrics)

        # 4. Generate with bounded retries and fallback
        cache_key = f"report_gen_{package_name}_{hash(app_name + str(overall_score) + str(len(findings_list)))}"
        ai_dict = self.client.generate_json(
            prompt=prompt,
            cache_key=cache_key,
        )

        # 5. Fallback on invalid or empty JSON
        if not ai_dict or not isinstance(ai_dict, dict):
            logger.warning("[ReportGenerator] LLM returned invalid report JSON. Using deterministic fallback.")
            return self._generate_deterministic_fallback(
                app_info=app_info,
                risk_info=risk_info,
                findings_list=findings_list,
                runtime_info={"runtime_status": runtime_dict},
                exploration_info=exploration_info,
                failure_analyses=norm_failures,
                screen_analyses=raw_screen_analyses,
                generated_tests=raw_generated_tests,
            )

        # Baseline deterministic fallback for missing individual fields
        fallback = self._generate_deterministic_fallback(
            app_info=app_info,
            risk_info=risk_info,
            findings_list=findings_list,
            runtime_info={"runtime_status": runtime_dict},
            exploration_info=exploration_info,
            failure_analyses=norm_failures,
            screen_analyses=raw_screen_analyses,
            generated_tests=raw_generated_tests,
        )

        exec_sum = str(ai_dict.get("executive_summary") or fallback.executive_summary).strip()
        qual_assess = str(ai_dict.get("quality_assessment") or ai_dict.get("technical_analysis") or fallback.quality_assessment).strip()
        sec_sum = str(ai_dict.get("security_summary") or ai_dict.get("security_analysis_summary") or fallback.security_summary).strip()
        stab_sum = str(ai_dict.get("stability_summary") or fallback.stability_summary).strip()
        crash_sum = str(ai_dict.get("crash_summary") or fallback.crash_summary).strip()

        screen_in = _ensure_string_list(ai_dict.get("screen_insights") or fallback.screen_insights)
        test_recs = _ensure_string_list(ai_dict.get("test_recommendations") or fallback.test_recommendations)
        crit_prios = _ensure_string_list(ai_dict.get("critical_priorities") or ai_dict.get("critical_observations") or fallback.critical_priorities)
        remed_recs = _ensure_string_list(ai_dict.get("remediation_recommendations") or ai_dict.get("prioritized_recommendations") or fallback.remediation_recommendations)

        return AIReportSummary(
            executive_summary=exec_sum,
            quality_assessment=qual_assess,
            security_summary=sec_sum,
            stability_summary=stab_sum,
            crash_summary=crash_sum,
            screen_insights=screen_in,
            test_recommendations=test_recs,
            critical_priorities=crit_prios,
            remediation_recommendations=remed_recs,
            technical_analysis=qual_assess,
            security_analysis_summary=sec_sum,
            critical_observations=crit_prios,
            prioritized_recommendations=remed_recs,
            provider_used=getattr(self.client.provider, "name", self.client.config.provider),
            model_used=self.client.config.model,
            is_ai_generated=True,
        )

    def _generate_deterministic_fallback(
        self,
        app_info: Dict[str, Any],
        risk_info: Dict[str, Any],
        findings_list: List[Dict[str, Any]],
        runtime_info: Dict[str, Any],
        exploration_info: Dict[str, Any],
        failure_analyses: List[Dict[str, Any]],
        screen_analyses: Optional[List[Any]] = None,
        generated_tests: Optional[List[Any]] = None,
    ) -> AIReportSummary:
        """Constructs a deterministic, evidence-grounded summary when AI is unavailable or disabled."""
        app_name = app_info.get("name") or "Android Application"
        pkg = app_info.get("package") or "unknown.package"
        r_level = risk_info.get("risk_level", "LOW")
        s_score = risk_info.get("security", 100.0)
        st_score = risk_info.get("stability", 100.0)
        p_score = risk_info.get("performance", 100.0)
        ux_score = risk_info.get("ux", 100.0)
        a_score = risk_info.get("accessibility", 100.0)

        total_findings = len(findings_list)
        crit_count = sum(1 for f in findings_list if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings_list if f.get("severity") == "HIGH")
        med_count = sum(1 for f in findings_list if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings_list if f.get("severity") == "LOW")

        # 1. Executive summary
        exec_sum = (
            f"Mobile Sentinel completed an automated audit of {app_name} ({pkg}). "
            f"The application received an overall risk posture rating of {r_level} with a security score of "
            f"{s_score}/100 and a stability score of {st_score}/100. A total of {total_findings} security and "
            f"QA findings were identified ({crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low)."
        )

        # 2. Quality assessment
        quality_assessment = (
            f"Application quality evaluated across six deterministic dimensions: Security: {s_score}/100, "
            f"Stability: {st_score}/100, Performance: {p_score}/100, UX: {ux_score}/100, Accessibility: {a_score}/100. "
            f"Overall risk posture is classified as {r_level}. "
        )
        if crit_count > 0 or high_count > 0:
            quality_assessment += f"Immediate remediation is recommended for {crit_count + high_count} high-severity issue(s)."
        else:
            quality_assessment += "No critical or high-severity vulnerabilities were identified in tested components."

        # 3. Security findings summary
        if total_findings > 0:
            security_summary = (
                f"Identified {total_findings} deterministic static security and architectural findings across inspected components. "
                f"Found {crit_count} critical, {high_count} high, and {med_count} medium severity issues requiring remediation."
            )
        else:
            security_summary = "No static security issues were identified in the examined application manifest, binary secrets, or network configuration."

        # 4. Runtime stability summary & crash summary
        rt_status = runtime_info.get("runtime_status", {})
        install_st = rt_status.get("Installation", "SKIPPED")
        launch_st = rt_status.get("Launch", "SKIPPED")
        fail_count = len(failure_analyses)

        stability_summary = f"Runtime execution status: Installation={install_st}, Application Launch={launch_st}. "
        if fail_count > 0:
            stability_summary += f"Detected {fail_count} runtime anomaly or crash signature(s) during execution."
            crash_summary = f"{fail_count} crash, ANR, or exception event(s) recorded in runtime logcat."
        else:
            stability_summary += "No application crashes, ANRs, or unhandled runtime exceptions were captured."
            crash_summary = "Zero crashes or ANRs detected during automated runtime execution."

        # 5. Screen analysis insights
        screens_disc = exploration_info.get("screens_discovered", 0)
        actions_tested = exploration_info.get("actions_tested", 0)
        screen_cov = exploration_info.get("screen_coverage_pct", 0.0)
        action_cov = exploration_info.get("action_coverage_pct", 0.0)

        screen_insights = [
            f"Discovered {screens_disc} unique screen(s) and executed {actions_tested} UI interaction(s).",
            f"Achieved {screen_cov}% screen coverage and {action_cov}% action coverage across accessible states.",
        ]
        if screen_analyses:
            for sa in screen_analyses[:3]:
                if isinstance(sa, dict) and sa.get("summary"):
                    screen_insights.append(str(sa["summary"]))
                elif hasattr(sa, "summary") and sa.summary:
                    screen_insights.append(str(sa.summary))

        # 6. Generated test recommendations
        test_recommendations = [
            "Implement automated end-to-end regression tests for critical user flows and authentication paths.",
            "Add strict boundary value and format validation testing for all interactive input fields.",
            "Ensure accessibility labels and minimum 48x48dp touch targets are configured across all screens.",
        ]
        if generated_tests:
            for gt in generated_tests[:3]:
                if isinstance(gt, dict) and gt.get("name"):
                    test_recommendations.append(f"Execute scenario: {gt['name']}")
                elif hasattr(gt, "name") and gt.name:
                    test_recommendations.append(f"Execute scenario: {gt.name}")

        # 7. Critical priorities requiring immediate attention
        crit_priorities = [
            f"Address {f.get('title', 'Security Finding')} (Severity: {f.get('severity', 'HIGH')})"
            for f in findings_list
            if f.get("severity") in ("CRITICAL", "HIGH")
        ]
        if not crit_priorities:
            crit_priorities = [
                "Maintain continuous security testing during CI/CD builds.",
                "Verify that all third-party dependencies are kept up-to-date.",
            ]

        # 8. Prioritized remediation recommendations
        remed_recs = [
            f"{f.get('title')}: {f.get('recommendation')}"
            for f in findings_list
            if f.get("recommendation")
        ]
        if not remed_recs:
            remed_recs = [
                "Enforce HTTPS and configure explicit Network Security Configuration for Android 9+.",
                "Disable android:exported on internal components or guard with signature permissions.",
                "Never hardcode sensitive API keys, secrets, or credentials in application assets or source.",
            ]
        remed_recs = remed_recs[:5]

        return AIReportSummary(
            executive_summary=exec_sum,
            quality_assessment=quality_assessment,
            security_summary=security_summary,
            stability_summary=stability_summary,
            crash_summary=crash_summary,
            screen_insights=screen_insights,
            test_recommendations=test_recommendations,
            critical_priorities=crit_priorities,
            remediation_recommendations=remed_recs,
            technical_analysis=quality_assessment,
            security_analysis_summary=security_summary,
            critical_observations=crit_priorities,
            prioritized_recommendations=remed_recs,
            provider_used="deterministic_fallback",
            model_used="sentinel-rule-engine",
            is_ai_generated=False,
        )
