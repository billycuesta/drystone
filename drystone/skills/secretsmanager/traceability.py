"""Secrets Manager (SM-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, generic_traceability


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id != "SM-012":
        return None

    refs = []
    if isinstance((evidence or {}).get("cloudwatch_alarms"), dict):
        refs.append("cloudwatch_alarms.json#/regions")
    if isinstance((evidence or {}).get("eventbridge_rules"), dict):
        refs.append("eventbridge_rules.json#/regions")
    if refs:
        return dedupe_refs(refs), {
            "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
            "affected_resources": list(getattr(result, "affected_resources", []) or []),
        }
    return generic_traceability(result, evidence)
