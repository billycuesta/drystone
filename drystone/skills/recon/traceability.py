"""Recon (RECON-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, generic_traceability


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if not check_id.startswith("RECON-"):
        return None

    affected_resources = [str(r) for r in (getattr(result, "affected_resources", []) or [])]
    refs: List[str] = []

    if check_id == "RECON-007":
        affected = set(affected_resources)
        lb_doc = (evidence or {}).get("load-balancer-dns") or {}
        for idx, lb in enumerate(lb_doc.get("load_balancers") or []):
            if not isinstance(lb, dict):
                continue
            dns_name = str(lb.get("DNSName") or "")
            name = str(lb.get("Name") or "")
            if dns_name in affected or name in affected:
                refs.append(f"load-balancer-dns.json#/load_balancers/{idx}")
    elif check_id == "RECON-010":
        affected = set(affected_resources)
        eps_doc = (evidence or {}).get("public-endpoints") or {}
        for idx, gw in enumerate(eps_doc.get("nat_gateway_ips") or []):
            if isinstance(gw, dict) and str(gw.get("PublicIp") or "") in affected:
                refs.append(f"public-endpoints.json#/nat_gateway_ips/{idx}")
    elif check_id == "RECON-016":
        affected = set(affected_resources)
        eps_doc = (evidence or {}).get("public-endpoints") or {}
        for idx, eip in enumerate(eps_doc.get("elastic_ips") or []):
            if isinstance(eip, dict) and str(eip.get("PublicIp") or "") in affected:
                refs.append(f"public-endpoints.json#/elastic_ips/{idx}")
    elif check_id == "RECON-004":
        r53_doc = (evidence or {}).get("route53-zones") or {}
        for zone_idx, zone in enumerate(r53_doc.get("zones") or []):
            if not isinstance(zone, dict):
                continue
            zone_name = str(zone.get("Name") or "")
            for rec_idx, rec in enumerate(zone.get("Records") or []):
                if not isinstance(rec, dict):
                    continue
                marker = f"{rec.get('Name')} ({rec.get('Type')}) in {zone_name}"
                if marker in affected_resources:
                    refs.append(f"route53-zones.json#/zones/{zone_idx}/Records/{rec_idx}")
    elif check_id == "RECON-008":
        if isinstance((evidence or {}).get("attack-surface-score"), dict):
            refs.append("attack-surface-score.json#/")

    if not refs:
        return generic_traceability(result, evidence)

    return dedupe_refs(refs)[:50], {
        "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
        "affected_resources": affected_resources[:10],
        "metadata": getattr(result, "metadata", None) or {},
    }
