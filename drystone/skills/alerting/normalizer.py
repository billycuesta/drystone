"""Alerting-specific findings normalization hooks."""

import logging
from typing import List, Optional

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    def __init__(self, context: NormalizerContext):
        super().__init__(context)

    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        evidence = self.context.evidence
        if not refs or not isinstance(evidence, dict):
            return refs
        normalized: List[str] = []
        evidence_keys = {str(k) for k in evidence.keys()}
        for ref in refs:
            rr = str(ref).strip()
            if not rr:
                continue
            base, sep, suffix = rr.partition("#")
            if not base.endswith(".json") and base in evidence_keys:
                base = f"{base}.json"
            normalized.append(f"{base}{sep}{suffix}" if sep else base)
        return normalized

    def ensure_impact(self, finding: Finding) -> bool:
        if finding.id not in {"ALRT-018", "ALRT-019"}:
            return False
        finding.exploitability_status = "theoretical"
        finding.impact = (
            "This is an operational clarity and triage issue rather than a direct "
            "attacker capability. Missing descriptions or ambiguous names can slow "
            "responders because they must infer purpose, scope, and owner from other "
            "configuration fields.\n\n"
            "The business impact is modest but real: incident response and control "
            "ownership become less efficient, and audit evidence is harder to review. "
            "Do not present this as proven attacker dwell-time extension or a direct "
            "PCI violation unless separate incident or compliance evidence supports it."
        )
        return True


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if finding_id not in {"ALRT-001", "ALRT-003"}:
            return None

        # Alerting: CloudTrail disabled
        if finding_id == "ALRT-001":
            trails = self.evidence.get("cloudtrail-trails", [])
            if len(trails) > 0:
                logger.warning(
                    f"Rejected {finding_id} - CloudTrail IS enabled ({len(trails)} trails). "
                    f"Should be ALRT-003 (no logs) or ALRT-005+ (other issues)."
                )
                return False  # CloudTrail IS enabled (should be ALRT-003 or ALRT-005+)

        # Alerting: CloudTrail logs disabled (ALRT-003 only valid if Trail exists)
        if finding_id == "ALRT-003":
            trails = self.evidence.get("cloudtrail-trails", [])
            if len(trails) == 0:
                logger.warning(
                    f"Rejected {finding_id} - CloudTrail is NOT enabled (no trails). "
                    f"Should be ALRT-001 instead."
                )
                return False

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
