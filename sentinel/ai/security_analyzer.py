"""AI-assisted security finding analysis and remediation explainer."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from sentinel.ai.client import AIClient
from sentinel.ai.models import SecurityExplanation
from sentinel.ai.prompts import (
    build_batch_security_explanation_prompt,
    build_security_explanation_prompt,
)
from sentinel.core.enums import Severity
from sentinel.core.logging import logger
from sentinel.core.models import Finding


class SecurityAnalyzer:
    """Translates technical static security findings into plain-English attack scenarios and remediation guides."""

    def __init__(self, ai_client: Optional[AIClient] = None):
        self.client = ai_client or AIClient()

    def _determine_urgency(self, severity: Severity) -> str:
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "IMMEDIATE"
        elif severity == Severity.MEDIUM:
            return "NEAR_TERM"
        return "INFORMATIONAL"

    def explain_finding(self, finding: Finding) -> SecurityExplanation:
        """Explains a single security finding with AI assistance or deterministic fallback."""
        urgency = self._determine_urgency(finding.severity)

        # 1. Deterministic fallback if AI is disabled
        if not self.client.is_enabled:
            return self._generate_deterministic_explanation(finding, urgency)

        # 2. Redact sensitive values before sending to LLM
        safe_evidence = {}
        for k, v in finding.evidence.items():
            safe_evidence[k] = self.client.redact_text(str(v))

        finding_data = {
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity.name,
            "category": finding.category.name,
            "description": self.client.redact_text(finding.description),
            "impact": finding.impact,
            "recommendation": finding.recommendation,
            "evidence": safe_evidence,
        }

        prompt = build_security_explanation_prompt(finding_data)
        ai_dict = self.client.generate_json(
            prompt=prompt,
            cache_key=f"sec_exp_{finding.id}_{finding.fingerprint}",
        )

        # 3. Handle malformed or empty response
        if not ai_dict or not isinstance(ai_dict, dict):
            logger.warning(f"[SecurityAnalyzer] LLM returned invalid explanation for {finding.id}. Using deterministic fallback.")
            return self._generate_deterministic_explanation(finding, urgency)

        return SecurityExplanation(
            finding_id=finding.id,
            original_title=finding.title,
            plain_title=str(ai_dict.get("plain_title", finding.title)),
            simplified_explanation=str(ai_dict.get("simplified_explanation", finding.description)),
            why_it_matters=str(ai_dict.get("business_impact", finding.impact)),
            business_impact=str(ai_dict.get("business_impact", finding.impact)),
            potential_impact=str(ai_dict.get("attack_scenario", "Unauthorized access or misuse")),
            attack_scenario=str(ai_dict.get("attack_scenario", "Unauthorized access or misuse")),
            evidence=finding.evidence,
            remediation_guide=str(ai_dict.get("remediation_guide", finding.recommendation)),
            recommended_remediation=str(ai_dict.get("remediation_guide", finding.recommendation)),
            confidence=finding.confidence,
            urgency=urgency,
            is_ai_generated=True,
        )

    def explain_all_findings(self, findings: List[Finding]) -> List[SecurityExplanation]:
        """Explains all security findings in a batched LLM request, preserving original IDs, severities, and evidence."""
        if not findings:
            return []

        # 1. Deterministic fallback if AI is disabled
        if not self.client.is_enabled:
            return [self._generate_deterministic_explanation(f, self._determine_urgency(f.severity)) for f in findings]

        # 2. If single finding, use individual flow directly
        if len(findings) == 1:
            return [self.explain_finding(findings[0])]

        # 3. Prepare batched finding data with secret redaction
        batch_data: List[Dict[str, Any]] = []
        for f in findings:
            safe_evidence = {}
            for k, v in f.evidence.items():
                safe_evidence[k] = self.client.redact_text(str(v))

            batch_data.append({
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity.name,
                "category": f.category.name,
                "description": self.client.redact_text(f.description),
                "impact": f.impact,
                "recommendation": f.recommendation,
                "evidence": safe_evidence,
            })

        prompt = build_batch_security_explanation_prompt(batch_data)
        batch_hash = hash(tuple((f.id, f.fingerprint) for f in findings))
        cache_key = f"sec_exp_batch_{len(findings)}_{batch_hash}"

        ai_dict = self.client.generate_json(
            prompt=prompt,
            cache_key=cache_key,
        )

        # 4. Fallback on invalid or empty JSON
        if not ai_dict or not isinstance(ai_dict, dict):
            logger.warning("[SecurityAnalyzer] Batched LLM explanation returned invalid JSON or timed out. Using deterministic fallback.")
            return [self._generate_deterministic_explanation(f, self._determine_urgency(f.severity)) for f in findings]

        # Extract explanations list or dict
        raw_exps = ai_dict.get("explanations", ai_dict.get("items", []))
        if isinstance(raw_exps, dict):
            raw_exps = list(raw_exps.values())
        if not isinstance(raw_exps, list):
            raw_exps = []

        # Map by finding_id for O(1) correlation
        exp_by_id: Dict[str, Dict[str, Any]] = {}
        for item in raw_exps:
            if isinstance(item, dict) and item.get("finding_id"):
                exp_by_id[str(item["finding_id"])] = item

        explanations: List[SecurityExplanation] = []
        for f in findings:
            urgency = self._determine_urgency(f.severity)
            if f.id in exp_by_id:
                exp_item = exp_by_id[f.id]
                explanations.append(
                    SecurityExplanation(
                        finding_id=f.id,
                        original_title=f.title,
                        plain_title=str(exp_item.get("plain_title", f.title)),
                        simplified_explanation=str(exp_item.get("simplified_explanation", f.description)),
                        why_it_matters=str(exp_item.get("business_impact", f.impact)),
                        business_impact=str(exp_item.get("business_impact", f.impact)),
                        potential_impact=str(exp_item.get("attack_scenario", "Unauthorized access or misuse")),
                        attack_scenario=str(exp_item.get("attack_scenario", "Unauthorized access or misuse")),
                        evidence=f.evidence,
                        remediation_guide=str(exp_item.get("remediation_guide", f.recommendation)),
                        recommended_remediation=str(exp_item.get("remediation_guide", f.recommendation)),
                        confidence=f.confidence,
                        urgency=urgency,
                        is_ai_generated=True,
                    )
                )
            else:
                # If a specific finding was omitted from the batch response, fallback deterministically
                explanations.append(self._generate_deterministic_explanation(f, urgency))

        return explanations

    def _generate_deterministic_explanation(self, finding: Finding, urgency: str) -> SecurityExplanation:
        """Constructs a deterministic plain-language explanation without AI."""
        return SecurityExplanation(
            finding_id=finding.id,
            original_title=finding.title,
            plain_title=finding.title,
            simplified_explanation=finding.description,
            why_it_matters=finding.impact,
            business_impact=finding.impact,
            potential_impact="Exposure of sensitive application surface or unauthorized operations.",
            attack_scenario="An attacker on the local device or network exploits the unhardened component.",
            evidence=finding.evidence,
            remediation_guide=finding.recommendation,
            recommended_remediation=finding.recommendation,
            confidence=finding.confidence,
            urgency=urgency,
            is_ai_generated=False,
        )
