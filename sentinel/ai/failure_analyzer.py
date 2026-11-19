"""AI-assisted runtime failure and crash analysis engine."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from sentinel.ai.client import AIClient
from sentinel.ai.models import FailureAnalysis
from sentinel.ai.prompts import build_failure_analysis_prompt
from sentinel.core.logging import logger
from sentinel.runtime.monitor import (
    ANR_PATTERNS,
    CRASH_PATTERNS,
    FLUTTER_ERROR_PATTERNS,
    RuntimeAnalysisResult,
    RuntimeMonitor,
)


class FailureAnalyzer:
    """Analyzes logcat streams, crashes, ANRs, and Dart exceptions into structured failure reports."""

    def __init__(self, ai_client: Optional[AIClient] = None):
        self.client = ai_client or AIClient()

    def extract_failure_signatures(self, logcat_text: str, package_name: str) -> List[Dict[str, Any]]:
        """Extracts genuine crash, ANR, and exception signatures from logcat text."""
        if not logcat_text or not logcat_text.strip():
            return []

        signatures: List[Dict[str, Any]] = []
        lines = logcat_text.splitlines()

        # 1. Search for Fatal Crashes
        for i, line in enumerate(lines):
            if any(p.search(line) for p in CRASH_PATTERNS):
                # Grab surrounding context window (20 lines)
                start = max(0, i - 2)
                end = min(len(lines), i + 25)
                trace_snippet = "\n".join(lines[start:end])

                signatures.append({
                    "failure_type": "crash",
                    "title": f"Fatal Crash in {package_name}",
                    "severity": "CRITICAL",
                    "header_line": line.strip(),
                    "trace_snippet": trace_snippet,
                    "component": package_name,
                    "is_confirmed": True,
                })
                break  # Deduplicate to primary fatal crash

        # 2. Search for ANRs
        for i, line in enumerate(lines):
            if any(p.search(line) for p in ANR_PATTERNS):
                start = max(0, i - 2)
                end = min(len(lines), i + 15)
                anr_snippet = "\n".join(lines[start:end])

                signatures.append({
                    "failure_type": "anr",
                    "title": f"Application Not Responding (ANR) in {package_name}",
                    "severity": "CRITICAL",
                    "header_line": line.strip(),
                    "trace_snippet": anr_snippet,
                    "component": package_name,
                    "is_confirmed": True,
                })
                break

        # 3. Search for Flutter / Dart Unhandled Exceptions
        for i, line in enumerate(lines):
            if any(p.search(line) for p in FLUTTER_ERROR_PATTERNS):
                start = max(0, i - 2)
                end = min(len(lines), i + 20)
                dart_snippet = "\n".join(lines[start:end])

                signatures.append({
                    "failure_type": "flutter_exception",
                    "title": "Unhandled Dart Exception in Flutter Runtime",
                    "severity": "HIGH",
                    "header_line": line.strip(),
                    "trace_snippet": dart_snippet,
                    "component": "Flutter Engine",
                    "is_confirmed": True,
                })
                break

        return signatures

    def analyze_failures(
        self,
        logcat_text: str,
        package_name: str,
        screen_name: Optional[str] = None,
    ) -> List[FailureAnalysis]:
        """Analyzes logcat for failures with AI reasoning or deterministic fallback."""
        if not logcat_text or not logcat_text.strip():
            return []

        signatures = self.extract_failure_signatures(logcat_text, package_name)
        if not signatures:
            return []

        analyses: List[FailureAnalysis] = []
        for idx, sig in enumerate(signatures, start=1):
            failure_id = f"FAIL-{sig['failure_type'].upper()[:5]}-{idx:03d}"

            # If AI is disabled, generate deterministic analysis
            if not self.client.is_enabled:
                analyses.append(self._generate_deterministic_analysis(sig, failure_id, screen_name))
                continue

            # Build prompt context
            context_data = {
                "failure_id": failure_id,
                "package_name": package_name,
                "screen_name": screen_name or "UnknownScreen",
                "failure_type": sig["failure_type"],
                "header_line": sig["header_line"],
                "trace_snippet": sig["trace_snippet"][:1500],
            }

            prompt = build_failure_analysis_prompt(context_data)
            ai_dict = self.client.generate_json(
                prompt=prompt,
                cache_key=f"failure_{failure_id}_{hash(sig['header_line'])}",
            )

            if not ai_dict or not isinstance(ai_dict, dict):
                logger.warning(f"[FailureAnalyzer] LLM returned invalid analysis for {failure_id}. Using deterministic fallback.")
                analyses.append(self._generate_deterministic_analysis(sig, failure_id, screen_name))
                continue

            analysis = FailureAnalysis(
                failure_id=failure_id,
                finding_id=failure_id,
                failure_category=sig["failure_type"],
                failure_type=sig["failure_type"],
                title=str(ai_dict.get("title", sig["title"])),
                description=str(ai_dict.get("description", sig["header_line"])),
                likely_root_cause=str(ai_dict.get("possible_root_cause", "Exception unhandled by application main thread")),
                possible_root_cause=str(ai_dict.get("possible_root_cause", "Exception unhandled by application main thread")),
                supporting_evidence={
                    "header": sig["header_line"],
                    "trace": sig["trace_snippet"][:800],
                },
                evidence={
                    "header": sig["header_line"],
                    "trace": sig["trace_snippet"][:800],
                },
                affected_component=sig["component"],
                severity=sig["severity"],
                confidence=float(ai_dict.get("confidence", 0.9)),
                recommended_remediation=str(ai_dict.get("recommended_action", "Inspect stack trace and handle exception.")),
                recommended_action=str(ai_dict.get("recommended_action", "Inspect stack trace and handle exception.")),
                screen_name=screen_name or "Runtime",
                reproduction_steps=list(ai_dict.get("reproduction_steps", [])),
                is_confirmed_bug=sig["is_confirmed"],
                is_ai_generated=True,
            )
            analyses.append(analysis)

        return analyses

    def _generate_deterministic_analysis(
        self,
        sig: Dict[str, Any],
        failure_id: str,
        screen_name: Optional[str],
    ) -> FailureAnalysis:
        """Constructs a deterministic, evidence-backed FailureAnalysis without AI."""
        return FailureAnalysis(
            failure_id=failure_id,
            finding_id=failure_id,
            failure_category=sig["failure_type"],
            failure_type=sig["failure_type"],
            title=sig["title"],
            description=f"Runtime error observed in logcat: {sig['header_line']}",
            likely_root_cause="Unhandled exception on application main thread",
            possible_root_cause="Unhandled exception on application main thread",
            supporting_evidence={
                "header": sig["header_line"],
                "trace": sig["trace_snippet"][:800],
            },
            evidence={
                "header": sig["header_line"],
                "trace": sig["trace_snippet"][:800],
            },
            affected_component=sig["component"],
            severity=sig["severity"],
            confidence=0.95,
            recommended_remediation="Add try-catch blocks or exception handlers around the offending component.",
            recommended_action="Add try-catch blocks or exception handlers around the offending component.",
            screen_name=screen_name or "Runtime",
            reproduction_steps=["Launch application", "Perform standard interaction leading to crash"],
            is_confirmed_bug=sig["is_confirmed"],
            is_ai_generated=False,
        )
