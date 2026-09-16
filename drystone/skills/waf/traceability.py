"""WAF (WAF-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, generic_traceability, indexed_ref_for


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if not check_id.startswith("WAF-"):
        return None

    resource_details = [
        item
        for item in ((getattr(result, "metadata", None) or {}).get("resource_details") or [])
        if isinstance(item, dict)
    ]
    affected_resources = list(getattr(result, "affected_resources", []) or [])
    refs: List[str] = []

    if check_id == "WAF-001":
        for detail in resource_details:
            alb_arn = str(detail.get("load_balancer_arn") or "")
            ref = indexed_ref_for(
                evidence,
                "alb-waf-associations",
                lambda item, alb_arn=alb_arn: str(item.get("LoadBalancerArn") or "") == alb_arn,
            )
            if ref:
                refs.append(ref)
        if refs:
            return dedupe_refs(refs), {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                "affected_resources": resource_details or affected_resources,
            }
        return generic_traceability(result, evidence)

    if check_id in {"WAF-004", "WAF-006"}:
        for detail in resource_details:
            web_acl_arn = str(detail.get("web_acl_arn") or "")
            ref = indexed_ref_for(
                evidence,
                "wafv2-web-acls",
                lambda item, web_acl_arn=web_acl_arn: str(item.get("ARN") or "") == web_acl_arn,
            )
            if ref:
                refs.append(ref)
        if refs:
            return dedupe_refs(refs), {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                "affected_resources": resource_details or affected_resources,
            }
        return generic_traceability(result, evidence)

    if check_id == "WAF-010":
        classic = (evidence or {}).get("waf-classic") or {}
        names = {str(d.get("name") or "") for d in resource_details if d.get("name")}

        global_acls = (classic.get("global") or {}).get("web_acls") or []
        for idx, acl in enumerate(global_acls):
            if isinstance(acl, dict) and str(acl.get("Name") or "") in names:
                refs.append(f"waf-classic.json#/global/web_acls/{idx}")

        regional = classic.get("regional") or {}
        if isinstance(regional, dict):
            for region, region_data in regional.items():
                web_acls = (region_data or {}).get("web_acls") or []
                for idx, acl in enumerate(web_acls):
                    if isinstance(acl, dict) and str(acl.get("Name") or "") in names:
                        refs.append(f"waf-classic.json#/regional/{region}/web_acls/{idx}")

        if refs:
            return dedupe_refs(refs), {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                "affected_resources": resource_details or affected_resources,
            }
        return generic_traceability(result, evidence)

    return generic_traceability(result, evidence)
