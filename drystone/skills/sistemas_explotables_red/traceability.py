"""Sistemas Explotables Red (SER-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, generic_traceability


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id == "SER-EC2-002":
        return _ser_ec2_002_traceability(result, evidence)
    if check_id == "SER-LMB-002":
        return _ser_lmb_002_traceability(result, evidence)
    return None


def _ser_ec2_002_traceability(
    result: Any, evidence: Dict[str, Any]
) -> "tuple[List[str], Optional[Dict[str, Any]]]":
    affected_resources = [str(r) for r in (getattr(result, "affected_resources", []) or [])]
    affected_instance_ids = {
        resource.split(":instance/")[-1] if ":instance/" in resource else resource
        for resource in affected_resources
    }
    refs: List[str] = []

    paths_doc = (evidence or {}).get("attack-path-candidates") or {}
    for idx, path in enumerate(paths_doc.get("paths") or []):
        if not isinstance(path, dict):
            continue
        target = str(path.get("target_resource") or "")
        target_iid = target.split(":instance/")[-1] if ":instance/" in target else target
        if target in affected_resources or target_iid in affected_instance_ids:
            refs.append(f"attack-path-candidates.json#/paths/{idx}")

    reach_doc = (evidence or {}).get("reachability-graph") or {}
    for idx, edge in enumerate(reach_doc.get("edges") or []):
        if not isinstance(edge, dict):
            continue
        target = str(edge.get("target") or edge.get("target_resource") or "")
        target_iid = target.split(":instance/")[-1] if ":instance/" in target else target
        if target in affected_resources or target_iid in affected_instance_ids:
            refs.append(f"reachability-graph.json#/edges/{idx}")

    compute_doc = (evidence or {}).get("compute-inventory") or {}
    for idx, instance in enumerate(compute_doc.get("ec2_instances") or []):
        if not isinstance(instance, dict):
            continue
        iid = str(instance.get("InstanceId") or "")
        arn = str(instance.get("Arn") or instance.get("InstanceArn") or "")
        if iid in affected_instance_ids or arn in affected_resources:
            refs.append(f"compute-inventory.json#/ec2_instances/{idx}")

    inspector_doc = (evidence or {}).get("inspector-findings-normalized") or {}
    for idx, finding in enumerate(inspector_doc.get("findings") or []):
        if not isinstance(finding, dict):
            continue
        resource_ids = []
        for resource in finding.get("resources") or []:
            if isinstance(resource, dict):
                rid = str(resource.get("id") or "")
                resource_ids.append(rid.split(":instance/")[-1] if ":instance/" in rid else rid)
        if affected_instance_ids.intersection(resource_ids):
            refs.append(f"inspector-findings-normalized.json#/findings/{idx}")

    metadata = getattr(result, "metadata", None) or {}
    sg_ids: set = set()
    for rules in (metadata.get("sg_rules_context") or {}).values():
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            source = str(rule.get("source") or "")
            if source in {"0.0.0.0/0", "::/0"} and rule.get("sg_id"):
                sg_ids.add(str(rule.get("sg_id")))

    network_doc = (evidence or {}).get("network-controls") or {}
    for idx, sg in enumerate(network_doc.get("security_groups") or []):
        if isinstance(sg, dict) and str(sg.get("GroupId") or "") in sg_ids:
            refs.append(f"network-controls.json#/security_groups/{idx}")

    if not refs:
        return generic_traceability(result, evidence)

    return dedupe_refs(refs), {
        "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
        "affected_resources": affected_resources[:10],
    }


def _ser_lmb_002_traceability(
    result: Any, evidence: Dict[str, Any]
) -> "tuple[List[str], Optional[Dict[str, Any]]]":
    front_doc = evidence.get("front-doors", {})
    routes = front_doc.get("api_gateway_routes", []) if isinstance(front_doc, dict) else []
    affected = set(str(r) for r in (getattr(result, "affected_resources", []) or []))
    matched = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        api_id = str(route.get("ApiId") or "")
        method = str(route.get("Method") or "")
        path = str(route.get("Path") or "")
        key = f"{api_id} {method} {path}".strip()
        ws_key = f"{api_id} (WebSocket API: $connect unauthenticated)"
        if key in affected or ws_key in affected or api_id in affected:
            matched.append(
                {
                    "ApiId": route.get("ApiId"),
                    "ApiType": route.get("ApiType"),
                    "Method": route.get("Method"),
                    "Path": route.get("Path"),
                    "AuthorizationType": route.get("AuthorizationType"),
                    "ApiKeyRequired": route.get("ApiKeyRequired"),
                }
            )
    if matched:
        return (
            ["front-doors.json#/api_gateway_routes"],
            {"api_gateway_routes": matched},
        )
    # Fallback: return all unauth routes from evidence
    unauth_routes = [
        r
        for r in routes
        if isinstance(r, dict)
        and str(r.get("AuthorizationType") or "").upper() in ("NONE", "")
        and str(r.get("Method") or "").upper() not in ("OPTIONS", "$DISCONNECT", "$DEFAULT")
    ]
    if unauth_routes:
        return (
            ["front-doors.json#/api_gateway_routes"],
            {
                "api_gateway_routes": [
                    {
                        "ApiId": r.get("ApiId"),
                        "ApiType": r.get("ApiType"),
                        "Method": r.get("Method"),
                        "Path": r.get("Path"),
                        "AuthorizationType": r.get("AuthorizationType"),
                    }
                    for r in unauth_routes[:5]
                ]
            },
        )
    return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}
