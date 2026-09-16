# ruff: noqa
"""Sistemas Explotables Red deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *
from .exposure import _sg_allows_world

logger = logging.getLogger(__name__)


# SISTEMAS EXPLOTABLES POR RED PRE-CHECKS
# ============================================================================


def _ser_engine_port(engine: str) -> int:
    eng = str(engine or "").lower()
    if "postgres" in eng:
        return 5432
    if "mysql" in eng or "mariadb" in eng:
        return 3306
    if "sqlserver" in eng:
        return 1433
    if "oracle" in eng:
        return 1521
    return 0


@_register("sistemas_explotables_red")
def check_ser_ec2_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 with SSH/RDP world-open ingress."""
    net_doc = evidence.get("network-controls", {})
    inv_doc = evidence.get("compute-inventory", {})

    if not isinstance(net_doc, dict) or not isinstance(inv_doc, dict):
        return PreCheckResult(
            "SER-EC2-001", "SKIP", "missing network-controls/compute-inventory", []
        )

    sgs = net_doc.get("security_groups", []) if isinstance(net_doc, dict) else []
    instances = inv_doc.get("ec2_instances", []) if isinstance(inv_doc, dict) else []
    if not isinstance(sgs, list) or not isinstance(instances, list):
        return PreCheckResult("SER-EC2-001", "SKIP", "invalid SG or EC2 evidence shape", [])

    risky_sg_ids = set()
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = str(sg.get("GroupId") or "")
        if not sg_id:
            continue
        for perm in sg.get("IpPermissions", []) or []:
            if not isinstance(perm, dict):
                continue
            if _sg_allows_world(perm, port=22) or _sg_allows_world(perm, port=3389):
                risky_sg_ids.add(sg_id)
                break

    if not risky_sg_ids:
        return PreCheckResult("SER-EC2-001", "PASS", "no SSH/RDP world-open SG rules", [])

    # D3: Build subnet→route-table and vpc→main-route-table maps for IGW route verification
    route_tables = net_doc.get("route_tables", []) or []
    has_rt_info = isinstance(route_tables, list) and len(route_tables) > 0
    subnet_to_rt: Dict[str, Any] = {}
    vpc_main_rt: Dict[str, Any] = {}
    if has_rt_info:
        for rt in route_tables:
            if not isinstance(rt, dict):
                continue
            vpc_id_rt = str(rt.get("VpcId") or "")
            for assoc in rt.get("Associations", []) or []:
                if not isinstance(assoc, dict):
                    continue
                subnet_id_assoc = str(assoc.get("SubnetId") or "")
                if subnet_id_assoc:
                    subnet_to_rt[subnet_id_assoc] = rt
                if bool(assoc.get("Main")) and vpc_id_rt:
                    vpc_main_rt[vpc_id_rt] = rt

    def _has_igw_route(rt: Any) -> bool:
        if not isinstance(rt, dict):
            return False
        for route in rt.get("Routes", []) or []:
            if not isinstance(route, dict):
                continue
            gw = str(route.get("GatewayId") or "")
            state = str(route.get("State") or "").lower()
            if gw.startswith("igw-") and state == "active":
                return True
        return False

    def _instance_internet_routable(inst: Any) -> bool:
        """Return True if routing is unknown (conservative) or IGW route exists."""
        if not has_rt_info:
            return True  # no route info: conservative, assume possible
        subnet_id = str(inst.get("SubnetId") or "")
        vpc_id = str(inst.get("VpcId") or "")
        rt = subnet_to_rt.get(subnet_id) or vpc_main_rt.get(vpc_id)
        if rt is None:
            return True  # unknown routing: conservative
        return _has_igw_route(rt)

    affected: List[str] = []
    for inst in instances:
        if not isinstance(inst, dict):
            continue
        inst_sgs = inst.get("SecurityGroups", []) or []
        if not isinstance(inst_sgs, list):
            continue
        if not any(
            str(sg.get("GroupId") or "") in risky_sg_ids for sg in inst_sgs if isinstance(sg, dict)
        ):
            continue
        if not _instance_internet_routable(inst):
            continue
        iid = str(inst.get("InstanceId") or "")
        if iid:
            affected.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if affected:
        return PreCheckResult(
            "SER-EC2-001",
            "FAIL",
            f"{len(affected)} EC2 instance(s) linked to SSH/RDP world-open SG with internet route",
            affected[:20],
        )

    if has_rt_info:
        return PreCheckResult(
            "SER-EC2-001",
            "PASS",
            f"{len(risky_sg_ids)} world-open SG(s) found but all attached instances are in private subnets",
            [],
        )

    return PreCheckResult(
        "SER-EC2-001",
        "FAIL",
        f"{len(risky_sg_ids)} world-open SG(s) with SSH/RDP (no EC2 attachment resolved)",
        sorted(risky_sg_ids)[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_lmb_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda Function URL with AuthType NONE."""
    front_doc = evidence.get("front-doors", {})
    if not isinstance(front_doc, dict):
        return PreCheckResult("SER-LMB-001", "SKIP", "missing front-doors evidence", [])

    urls = front_doc.get("lambda_function_urls", [])
    if not isinstance(urls, list):
        return PreCheckResult("SER-LMB-001", "SKIP", "invalid lambda_function_urls shape", [])

    unauth = [
        u for u in urls if isinstance(u, dict) and str(u.get("AuthType") or "").upper() == "NONE"
    ]
    if not unauth:
        return PreCheckResult("SER-LMB-001", "PASS", "no unauthenticated Lambda Function URLs", [])

    affected = [
        str(u.get("FunctionArn") or u.get("FunctionUrl") or "lambda-url-unknown")
        for u in unauth[:20]
    ]
    return PreCheckResult(
        "SER-LMB-001",
        "FAIL",
        f"{len(unauth)} Lambda Function URL(s) with AuthType=NONE",
        affected,
    )


@_register("sistemas_explotables_red")
def check_ser_rds_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """RDS publicly accessible and engine port world-open in SG."""
    net_doc = evidence.get("network-controls", {})
    inv_doc = evidence.get("compute-inventory", {})
    if not isinstance(net_doc, dict) or not isinstance(inv_doc, dict):
        return PreCheckResult(
            "SER-RDS-001", "SKIP", "missing network-controls/compute-inventory", []
        )

    sgs = net_doc.get("security_groups", [])
    rds_items = inv_doc.get("rds_instances", [])
    if not isinstance(sgs, list) or not isinstance(rds_items, list):
        return PreCheckResult("SER-RDS-001", "SKIP", "invalid SG or RDS evidence shape", [])

    sg_by_id = {}
    for sg in sgs:
        if isinstance(sg, dict) and isinstance(sg.get("GroupId"), str):
            sg_by_id[str(sg.get("GroupId"))] = sg

    affected: List[str] = []
    for db in rds_items:
        if not isinstance(db, dict):
            continue
        if not bool(db.get("PubliclyAccessible")):
            continue
        engine_port = _ser_engine_port(str(db.get("Engine") or ""))
        if engine_port <= 0:
            continue

        vpc_sgs = db.get("VpcSecurityGroups", []) or []
        sg_ids = [str(sg.get("VpcSecurityGroupId") or "") for sg in vpc_sgs if isinstance(sg, dict)]
        for sg_id in sg_ids:
            sg_doc = sg_by_id.get(sg_id)
            if not isinstance(sg_doc, dict):
                continue
            perms = sg_doc.get("IpPermissions", []) or []
            if any(isinstance(p, dict) and _sg_allows_world(p, port=engine_port) for p in perms):
                arn = str(db.get("DBInstanceArn") or f"rds:{db.get('DBInstanceIdentifier')}")
                affected.append(arn)
                break

    if not affected:
        return PreCheckResult(
            "SER-RDS-001", "PASS", "no public RDS with world-open engine port", []
        )

    return PreCheckResult(
        "SER-RDS-001",
        "FAIL",
        f"{len(affected)} RDS instance(s) publicly accessible with world-open DB port",
        affected[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_cor_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Resource with combined high reachability + vulnerability + blast-radius signals."""
    paths_doc = evidence.get("attack-path-candidates", {})
    if not isinstance(paths_doc, dict):
        return PreCheckResult("SER-COR-003", "SKIP", "missing attack-path-candidates evidence", [])

    paths = paths_doc.get("paths", [])
    if not isinstance(paths, list) or not paths:
        return PreCheckResult("SER-COR-003", "SKIP", "no attack paths computed", [])

    risky = []
    for p in paths:
        if not isinstance(p, dict):
            continue
        r = float(p.get("reachability_score") or 0.0)
        v = float(p.get("vulnerability_score") or 0.0)
        b = float(p.get("blast_radius_score") or 0.0)
        o = float(p.get("overall_score") or 0.0)
        if r >= 0.8 and v >= 0.7 and b >= 0.7 and o >= 0.75:
            target = str(p.get("target_resource") or "")
            if target:
                risky.append(target)

    if not risky:
        return PreCheckResult(
            "SER-COR-003", "PASS", "no high-confidence correlated attack paths", []
        )

    return PreCheckResult(
        "SER-COR-003",
        "FAIL",
        f"{len(risky)} resource(s) with correlated exploitability signals",
        sorted(set(risky))[:20],
        confidence=0.9,
    )


@_register("sistemas_explotables_red")
def check_ser_ec2_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Internet-reachable EC2 with active Inspector findings."""
    paths_doc = evidence.get("attack-path-candidates", {})
    if not isinstance(paths_doc, dict):
        return PreCheckResult("SER-EC2-002", "SKIP", "missing attack-path-candidates evidence", [])

    paths = paths_doc.get("paths", [])
    if not isinstance(paths, list):
        return PreCheckResult("SER-EC2-002", "SKIP", "invalid attack path shape", [])

    # Build instance_id → CVE titles map from Inspector findings evidence
    inspector_doc = evidence.get("inspector-findings-normalized", {})
    instance_cves: Dict[str, List[str]] = {}
    if isinstance(inspector_doc, dict):
        for f in inspector_doc.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            title = str(f.get("title") or "")
            for r in f.get("resources", []) or []:
                if not isinstance(r, dict):
                    continue
                rid = str(r.get("id") or "")
                if not rid or r.get("type") != "AWS_EC2_INSTANCE":
                    continue
                # Normalize: strip ARN prefix if present
                iid = rid.split(":instance/")[-1] if ":instance/" in rid else rid
                instance_cves.setdefault(iid, [])
                if title and title not in instance_cves[iid]:
                    instance_cves[iid].append(title)

    affected: List[str] = []
    for path in paths:
        if not isinstance(path, dict):
            continue
        target = str(path.get("target_resource") or "")
        if ":instance/" not in target:
            continue
        signal = (
            path.get("inspector_signal", {})
            if isinstance(path.get("inspector_signal"), dict)
            else {}
        )
        crit = int(signal.get("critical", 0) or 0)
        high = int(signal.get("high", 0) or 0)
        med = int(signal.get("medium", 0) or 0)
        reach = int(signal.get("internet_reachability_findings", 0) or 0)
        if (crit + high + med) > 0 and (
            reach > 0 or float(path.get("reachability_score") or 0.0) >= 0.8
        ):
            affected.append(target)

    if not affected:
        return PreCheckResult(
            "SER-EC2-002",
            "PASS",
            "no internet-reachable EC2 with active Inspector findings",
            [],
        )

    unique = sorted(set(affected))

    # Clean evidence_summary — count only; CVE details go to metadata
    summary = f"{len(unique)} internet-reachable EC2 instance(s) with active Inspector findings"

    # Build structured cve_details for metadata
    cve_details: List[Dict[str, Any]] = []
    for arn in unique[:10]:
        iid = arn.split(":instance/")[-1] if ":instance/" in arn else arn
        for title in instance_cves.get(iid, [])[:10]:
            cve_details.append({"id": title, "resource": iid})

    # Read CVE intelligence file if available (enriched CVSS + attack path)
    cve_intel_doc = evidence.get("cve-intelligence", {})
    enriched_cve_details: List[Dict[str, Any]] = []
    per_instance_attack_paths: Dict[str, Any] = {}
    per_instance_sg_rules: Dict[str, Any] = {}
    per_instance_roles: Dict[str, str] = {}
    if isinstance(cve_intel_doc, dict):
        instances_intel = cve_intel_doc.get("instances", {})
        for arn in unique[:10]:
            iid = arn.split(":instance/")[-1] if ":instance/" in arn else arn
            inst_data = instances_intel.get(iid, {})
            if not isinstance(inst_data, dict):
                continue
            for cve_entry in inst_data.get("cves", []):
                if not isinstance(cve_entry, dict):
                    continue
                entry: Dict[str, Any] = {
                    "id": cve_entry.get("id", ""),
                    "package": cve_entry.get("package", ""),
                    "installed_version": cve_entry.get("installed_version", ""),
                    "fixed_version": cve_entry.get("fixed_version", ""),
                    "inspector_severity": cve_entry.get("inspector_severity", ""),
                    "cvss_score": cve_entry.get("cvss_score"),
                    "cvss_vector": cve_entry.get("cvss_vector", ""),
                    "impact_type": cve_entry.get("impact_type", ""),
                    "description": cve_entry.get("description", ""),
                    "attack_vector": cve_entry.get("attack_vector", ""),
                    "exploitable_from_internet": cve_entry.get("exploitable_from_internet", False),
                    "relevant_open_ports": cve_entry.get("relevant_open_ports", []),
                    "resource": iid,
                }
                # Propagate exploit_intel from cve-intelligence enrichment
                if cve_entry.get("exploit_intel"):
                    entry["exploit_intel"] = cve_entry["exploit_intel"]
                enriched_cve_details.append(entry)
            attack_path = inst_data.get("attack_path")
            if isinstance(attack_path, dict) and attack_path:
                per_instance_attack_paths[iid] = attack_path
            sg_rules = inst_data.get("sg_rules")
            if isinstance(sg_rules, list) and sg_rules:
                per_instance_sg_rules[iid] = sg_rules
            iam_role = inst_data.get("iam_role")
            if isinstance(iam_role, str) and iam_role:
                per_instance_roles[iid] = iam_role

    metadata: Dict[str, Any] = {
        "cve_details": enriched_cve_details if enriched_cve_details else cve_details,
    }
    if per_instance_attack_paths:
        metadata["attack_paths"] = per_instance_attack_paths
    if per_instance_sg_rules:
        metadata["sg_rules_context"] = per_instance_sg_rules
    if per_instance_roles:
        metadata["iam_roles"] = per_instance_roles

    # Contextual risk score: escalate when a NETWORK-vector CVSS≥9.0 CVE is present
    # on an internet-reachable instance → effectively a Critical attack path.
    all_cves_enriched = enriched_cve_details if enriched_cve_details else cve_details
    max_cvss = 0.0
    has_network_critical = False
    for cve_e in all_cves_enriched:
        score = cve_e.get("cvss_score") or 0.0
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0.0
        if score > max_cvss:
            max_cvss = score
        vector = str(cve_e.get("attack_vector") or "").upper()
        if score >= 9.0 and "NETWORK" in vector:
            has_network_critical = True

    if has_network_critical:
        risk_score_override = 9.0  # Critical path: CVSS≥9.0 + NETWORK + open port
    elif max_cvss >= 7.0:
        risk_score_override = 8.0  # Elevated high: significant CVSS but no confirmed NETWORK vector
    else:
        risk_score_override = None  # Fall back to checklist severity default (7.0)

    return PreCheckResult(
        "SER-EC2-002",
        "FAIL",
        summary,
        unique[:20],
        confidence=0.92,
        metadata=metadata,
        risk_score_override=risk_score_override,
    )


@_register("sistemas_explotables_red")
def check_ser_ecs_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS service reachable via internet-facing ALB."""
    reach_doc = evidence.get("reachability-graph", {})
    if not isinstance(reach_doc, dict):
        return PreCheckResult("SER-ECS-001", "SKIP", "missing reachability-graph evidence", [])

    edges = reach_doc.get("edges", [])
    if not isinstance(edges, list):
        return PreCheckResult("SER-ECS-001", "SKIP", "invalid edges shape", [])

    affected: List[str] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("path_type") or "") == "alb->ecs-service":
            target = str(edge.get("target") or "")
            if target and target not in affected:
                affected.append(target)

    if not affected:
        return PreCheckResult(
            "SER-ECS-001", "PASS", "no ECS services reachable via internet-facing ALB", []
        )

    return PreCheckResult(
        "SER-ECS-001",
        "FAIL",
        f"{len(affected)} ECS service(s) reachable via internet-facing ALB",
        affected[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_lmb_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda exposed via API Gateway without authorization."""
    front_doc = evidence.get("front-doors", {})
    if not isinstance(front_doc, dict):
        return PreCheckResult("SER-LMB-002", "SKIP", "missing front-doors evidence", [])

    routes = front_doc.get("api_gateway_routes", [])
    if not isinstance(routes, list):
        return PreCheckResult("SER-LMB-002", "SKIP", "invalid api_gateway_routes shape", [])

    if not routes:
        return PreCheckResult("SER-LMB-002", "PASS", "no API Gateway routes found", [])

    # WebSocket API V2 routes: $connect is the handshake (must be authorized),
    # $disconnect and $default only execute after connection is established.
    # Flagging $disconnect/$default as separate issues inflates the count and
    # misleads remediation — the fix is always on $connect.
    _websocket_post_connect = {"$DISCONNECT", "$DEFAULT"}

    unauth: List[str] = []
    websocket_connect_unauth: List[str] = []  # Track WebSocket APIs missing auth on $connect

    for route in routes:
        if not isinstance(route, dict):
            continue
        method = str(route.get("Method") or "").upper()
        # OPTIONS is a CORS preflight — browsers send it automatically and
        # API Gateway requires it to be unauthenticated by design.
        if method == "OPTIONS":
            continue

        auth = str(route.get("AuthorizationType") or "").upper()
        api_id = str(route.get("ApiId") or "")
        path = str(route.get("Path") or "")
        # Detect WebSocket APIs by route method names ($connect/$disconnect/$default)
        # even when ApiType is not labelled as WEBSOCKET in the collector output.
        is_websocket_route = method in {"$CONNECT", "$DISCONNECT", "$DEFAULT"}

        if is_websocket_route and method in _websocket_post_connect:
            # Post-connect routes are only reachable after $connect authenticates;
            # skip them to avoid counting a single WebSocket issue 3× times.
            continue

        if auth in ("NONE", ""):
            key = f"{api_id} {method} {path}".strip()
            if not key:
                continue
            if is_websocket_route and method == "$CONNECT":
                # Report WebSocket issues as a group keyed by API ID
                ws_key = f"{api_id} (WebSocket API: $connect unauthenticated)"
                if ws_key not in websocket_connect_unauth:
                    websocket_connect_unauth.append(ws_key)
            else:
                if key not in unauth:
                    unauth.append(key)

    all_unauth = unauth + websocket_connect_unauth
    if not all_unauth:
        return PreCheckResult(
            "SER-LMB-002",
            "PASS",
            "all API Gateway routes have authorization (OPTIONS excluded)",
            [],
        )

    ws_count = len(websocket_connect_unauth)
    http_count = len(unauth)
    parts = []
    if http_count:
        parts.append(f"{http_count} HTTP/REST route(s) without authorization")
    if ws_count:
        parts.append(f"{ws_count} WebSocket API(s) with unauthenticated $connect")

    return PreCheckResult(
        "SER-LMB-002",
        "FAIL",
        "; ".join(parts),
        all_unauth[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_cve_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """SER-CVE-001: Internet-exposed instance with CISA KEV vulnerability."""
    cve_intel = evidence.get("cve-intelligence")
    if not isinstance(cve_intel, dict):
        return PreCheckResult("SER-CVE-001", "SKIP", "no cve-intelligence evidence", [])

    instances = cve_intel.get("instances")
    if not isinstance(instances, dict) or not instances:
        return PreCheckResult("SER-CVE-001", "SKIP", "no instances in cve-intelligence", [])

    affected: List[str] = []
    for iid, intel in instances.items():
        if not isinstance(intel, dict):
            continue
        for cve in intel.get("cves", []):
            if not isinstance(cve, dict):
                continue
            if not cve.get("exploitable_from_internet"):
                continue
            exploit_intel = cve.get("exploit_intel") or {}
            kev = exploit_intel.get("cisa_kev") or {}
            if kev.get("listed"):
                affected.append(f"{iid}:{cve.get('id', '?')}")
                break  # one KEV CVE per instance is enough

    if not affected:
        return PreCheckResult(
            "SER-CVE-001",
            "PASS",
            "no internet-exposed instances with CISA KEV vulnerabilities",
            [],
        )
    return PreCheckResult(
        "SER-CVE-001",
        "FAIL",
        f"{len(affected)} instance(s) internet-exposed with CISA KEV vulnerability (actively exploited in wild)",
        affected[:20],
    )


# =============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
