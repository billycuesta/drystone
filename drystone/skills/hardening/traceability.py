"""Hardening (HRD-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, generic_traceability


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if not check_id.startswith("HRD-"):
        return None

    metadata = getattr(result, "metadata", None) or {}
    refs: List[str] = []
    snippet: Dict[str, Any] = {
        "evidence_summary": getattr(result, "evidence_summary", "pre-check fail")
    }

    if check_id == "HRD-004":
        refs.append("security-hub-findings-summary.json#/compliance_status_counts")
        snippet.update(
            {
                "compliance_score": metadata.get("compliance_score"),
                "passed": metadata.get("passed"),
                "failed": metadata.get("failed"),
                "warning": metadata.get("warning"),
            }
        )
    elif check_id in {"HRD-005", "HRD-009", "HRD-012"}:
        severity = str(metadata.get("severity") or "").upper()
        sample_findings = [
            item for item in (metadata.get("sample_findings") or []) if isinstance(item, dict)
        ]
        if severity:
            refs.append(f"security-hub-findings-summary.json#/severity_counts/{severity}")
        for sample in sample_findings:
            idx = sample.get("index")
            if isinstance(idx, int):
                refs.append(f"security-hub-findings.json#/{idx}")
        snippet.update(
            {
                "count": metadata.get("count"),
                "severity": severity,
                "sample_findings": sample_findings[:5],
            }
        )
    elif check_id == "HRD-010":
        refs.append("config-conformance-packs.json#/")
        snippet.update({"conformance_pack_count": metadata.get("conformance_pack_count", 0)})
    elif check_id == "HRD-014":
        refs.append("guardduty-detectors.json#/")
        snippet.update({"enabled": metadata.get("enabled", False), "service": "GuardDuty"})
    else:
        return generic_traceability(result, evidence)

    affected_resources = list(getattr(result, "affected_resources", []) or [])
    if affected_resources:
        snippet["affected_resources"] = affected_resources[:10]
    return dedupe_refs(refs), snippet
