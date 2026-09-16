# ruff: noqa
"""Network deterministic pre-checks."""

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


# NETWORK PRE-CHECKS
# ============================================================================


@_register("network")
def check_net_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Sensitive ports exposed to world."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-001", "SKIP", "no security-groups evidence", [])

    sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379]
    exposed = []
    resource_details: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            for p in sensitive_ports:
                if _sg_allows_world(perm, port=p):
                    if sg_id not in exposed:
                        exposed.append(sg_id)
                    cidr = next(
                        (
                            r.get("CidrIp", "0.0.0.0/0")
                            for r in (perm.get("IpRanges") or [])
                            if isinstance(r, dict)
                        ),
                        "0.0.0.0/0",
                    )
                    resource_details.append(
                        {
                            "resource": sg_id,
                            "name": sg.get("GroupName", ""),
                            "port": p,
                            "service": _port_service_name(p),
                            "protocol": perm.get("IpProtocol", "tcp"),
                            "source": cidr,
                        }
                    )
                    break

    if not exposed:
        return PreCheckResult("NET-001", "PASS", "no sensitive ports exposed", [])
    result = PreCheckResult(
        "NET-001", "FAIL", f"{len(exposed)} SGs with exposed ports", exposed[:10]
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Missing descriptions on critical security group rules."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-011", "SKIP", "no security-groups evidence", [])

    crit_ports = {22, 3389, 3306, 5432, 6379, 1433, 27017, 8080}

    def _perm_matches_critical(perm):
        proto = perm.get("IpProtocol")
        if proto == "-1":
            return True
        if proto != "tcp":
            return False
        fp, tp = perm.get("FromPort"), perm.get("ToPort")
        if not isinstance(fp, int) or not isinstance(tp, int):
            return False
        return any(fp <= p <= tp for p in crit_ports)

    def _has_missing_desc(perm):
        for key in ("IpRanges", "Ipv6Ranges", "UserIdGroupPairs"):
            for r in perm.get(key, []) or []:
                if isinstance(r, dict) and not r.get("Description"):
                    return True
        return False

    affected: list = []
    resource_details: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        all_rules = (sg.get("IngressRules", []) or []) + (sg.get("EgressRules", []) or [])
        for perm in all_rules:
            if isinstance(perm, dict) and _perm_matches_critical(perm) and _has_missing_desc(perm):
                if sg_id not in affected:
                    affected.append(sg_id)
                    resource_details.append(
                        {
                            "resource": sg_id,
                            "name": sg.get("GroupName", ""),
                            "port": perm.get("FromPort"),
                            "protocol": perm.get("IpProtocol"),
                            "service": _port_service_name(perm.get("FromPort")),
                            "missing_description": True,
                        }
                    )
                break

    if not affected:
        return PreCheckResult("NET-011", "PASS", "all critical rules have descriptions", [])
    result = PreCheckResult(
        "NET-011",
        "FAIL",
        f"{len(affected)} SG(s) with undescribed critical rules",
        affected,
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_018(evidence: Dict[str, Any]) -> PreCheckResult:
    """VPC should have Flow Logs enabled."""
    vpc_doc = evidence.get("vpcs")
    vpcs = _items_from_doc(vpc_doc)
    if isinstance(vpc_doc, dict) and isinstance(vpc_doc.get("by_id"), dict):
        vpcs = list(vpc_doc["by_id"].values())

    if not vpcs:
        return PreCheckResult("NET-018", "SKIP", "no vpcs evidence", [])

    missing = []
    for v in vpcs:
        if not isinstance(v, dict):
            continue
        flow_logs = v.get("FlowLogs", []) or []
        has_active = any(
            isinstance(fl, dict) and fl.get("FlowLogStatus") in {"ACTIVE", "active"}
            for fl in flow_logs
            if isinstance(flow_logs, list)
        )
        if not has_active:
            missing.append(v.get("VpcId", "unknown"))

    if not missing:
        return PreCheckResult("NET-018", "PASS", "all VPCs have active Flow Logs", [])
    return PreCheckResult("NET-018", "FAIL", f"{len(missing)} VPCs without Flow Logs", missing[:5])


@_register("network")
def check_net_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-002: Security groups allowing ALL traffic (protocol -1) from 0.0.0.0/0."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-002", "SKIP", "no security-groups evidence", [])

    exposed = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict) or perm.get("IpProtocol") != "-1":
                continue
            for r in perm.get("IpRanges", []) or []:
                if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
                    if sg_id not in exposed:
                        exposed.append(sg_id)
            for r in perm.get("Ipv6Ranges", []) or []:
                if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
                    if sg_id not in exposed:
                        exposed.append(sg_id)

    if not exposed:
        return PreCheckResult("NET-002", "PASS", "no SGs with ALL traffic from internet", [])
    return PreCheckResult(
        "NET-002", "FAIL", f"{len(exposed)} SGs allow ALL traffic from 0.0.0.0/0", exposed[:10]
    )


@_register("network")
def check_net_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-003: NACLs with ALLOW ALL rules (protocol -1, allow, 0.0.0.0/0 inbound)."""
    nacl_doc = evidence.get("network-acls")
    nacls = _items_from_doc(nacl_doc)

    if not nacls:
        return PreCheckResult("NET-003", "SKIP", "no network-acls evidence", [])

    flagged = []
    resource_details: list = []
    for nacl in nacls:
        if not isinstance(nacl, dict):
            continue
        nacl_id = nacl.get("NetworkAclId", "unknown")
        matched_entries = []
        for entry in nacl.get("Entries", []) or []:
            if not isinstance(entry, dict):
                continue
            if (
                entry.get("Protocol") == "-1"
                and entry.get("RuleAction") == "allow"
                and entry.get("CidrBlock") == "0.0.0.0/0"
                and not entry.get("Egress", True)  # inbound only
            ):
                if nacl_id not in flagged:
                    flagged.append(nacl_id)
                    matched_entries.append(
                        {
                            "rule_number": entry.get("RuleNumber"),
                            "protocol": entry.get("Protocol"),
                            "cidr": entry.get("CidrBlock"),
                            "egress": entry.get("Egress", False),
                        }
                    )
                break
        if matched_entries:
            resource_details.append(
                {
                    "resource": nacl_id,
                    "network_acl_id": nacl_id,
                    "vpc_id": nacl.get("VpcId"),
                    "is_default": nacl.get("IsDefault", False),
                    "associated_subnet_ids": [
                        assoc.get("SubnetId")
                        for assoc in (nacl.get("Associations") or [])
                        if isinstance(assoc, dict) and assoc.get("SubnetId")
                    ],
                    "allow_all_entries": matched_entries,
                }
            )

    if not flagged:
        return PreCheckResult("NET-003", "PASS", "no NACLs with ALLOW ALL from 0.0.0.0/0", [])
    result = PreCheckResult(
        "NET-003", "FAIL", f"{len(flagged)} NACLs with ALLOW ALL from internet", flagged[:5]
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-009: Security groups allowing overly broad CIDRs (prefix /16 or larger) to non-web ports."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-009", "SKIP", "no security-groups evidence", [])

    # Standard web ports excluded from check (these are expected to have broad access)
    web_ports = {80, 443}
    flagged: list = []
    resource_details: list = []

    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        found = False
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            proto = perm.get("IpProtocol")
            # Skip ALL-traffic rules (covered by NET-002) and non-TCP/UDP
            if proto == "-1" or proto not in ("tcp", "udp", "6", "17"):
                continue
            fp = perm.get("FromPort")
            tp = perm.get("ToPort")
            for r in perm.get("IpRanges", []) or []:
                if not isinstance(r, dict):
                    continue
                cidr = r.get("CidrIp", "")
                if not cidr or "/" not in cidr:
                    continue
                try:
                    prefix_len = int(cidr.split("/")[1])
                except (ValueError, IndexError):
                    continue
                if prefix_len > 16:  # /17 or more specific = not broadly permissive
                    continue
                # Broad CIDR — check if it covers only web ports
                if isinstance(fp, int) and isinstance(tp, int):
                    # If entire port range is within web_ports, skip
                    if fp == tp and fp in web_ports:
                        continue
                    flagged.append(f"{sg_id}:{cidr}:{fp}-{tp}")
                    resource_details.append(
                        {
                            "resource": sg_id,
                            "name": sg.get("GroupName", ""),
                            "cidr": cidr,
                            "port_range": f"{fp}-{tp}" if fp != tp else str(fp),
                            "protocol": proto,
                        }
                    )
                    found = True
                    break
            if found:
                break

    if not flagged:
        return PreCheckResult("NET-009", "PASS", "no overly broad CIDRs to non-web ports", [])
    sg_ids = list(dict.fromkeys(f.split(":")[0] for f in flagged))
    result = PreCheckResult(
        "NET-009",
        "FAIL",
        f"{len(flagged)} SG rule(s) with broad CIDR (>=/16) to non-web port",
        sg_ids[:10],
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-016: Subnets using default VPC NACL instead of a dedicated custom NACL."""
    nacl_doc = evidence.get("network-acls")
    nacls = _items_from_doc(nacl_doc)

    if not nacls:
        return PreCheckResult("NET-016", "SKIP", "no network-acls evidence", [])

    default_subnets: list = []
    resource_details: list = []
    for nacl in nacls:
        if not isinstance(nacl, dict) or not nacl.get("IsDefault", False):
            continue
        for assoc in nacl.get("Associations", []) or []:
            if isinstance(assoc, dict) and assoc.get("SubnetId"):
                default_subnets.append(assoc["SubnetId"])
                resource_details.append(
                    {
                        "resource": assoc["SubnetId"],
                        "subnet_id": assoc["SubnetId"],
                        "network_acl_id": nacl.get("NetworkAclId"),
                        "vpc_id": nacl.get("VpcId"),
                        "is_default": True,
                    }
                )

    if not default_subnets:
        return PreCheckResult("NET-016", "PASS", "all subnets use custom NACLs", [])
    result = PreCheckResult(
        "NET-016",
        "FAIL",
        f"{len(default_subnets)} subnet(s) using default NACL",
        default_subnets,
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_027(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-027: Security groups missing tags."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-027", "SKIP", "no security-groups evidence", [])

    untagged = []
    resource_details: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        tags = sg.get("Tags", []) or []
        if not tags:
            sg_id = sg.get("GroupId", "unknown")
            untagged.append(sg_id)
            resource_details.append(
                {
                    "resource": sg_id,
                    "security_group_id": sg_id,
                    "name": sg.get("GroupName", ""),
                    "vpc_id": sg.get("VpcId"),
                    "tags": [],
                }
            )

    if not untagged:
        return PreCheckResult("NET-027", "PASS", "all security groups have tags", [])
    result = PreCheckResult(
        "NET-027",
        "FAIL",
        f"{len(untagged)} SG(s) missing tags",
        untagged,
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-004: DB/private subnets have a default route to an Internet Gateway."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts:
        return PreCheckResult("NET-004", "SKIP", "no route-tables evidence", [])
    if not subnets:
        return PreCheckResult("NET-004", "SKIP", "no subnets evidence", [])

    # Build map: subnet_id → name tag
    subnet_name: Dict[str, str] = {}
    for s in subnets:
        if not isinstance(s, dict):
            continue
        sid = s.get("SubnetId", "")
        tags = {
            t.get("Key", ""): t.get("Value", "")
            for t in (s.get("Tags") or [])
            if isinstance(t, dict)
        }
        subnet_name[sid] = tags.get("Name", "").lower()

    # Private / DB keywords in subnet names
    private_keywords = ("private", "db", "database", "internal", "app", "cache", "elasticache")

    sensitive: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        igw_routes = [
            r
            for r in (rt.get("Routes") or [])
            if isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
        ]
        if not igw_routes:
            continue
        for assoc in rt.get("Associations") or []:
            if not isinstance(assoc, dict):
                continue
            sid = assoc.get("SubnetId")
            if not sid:
                continue
            name = subnet_name.get(sid, "")
            if any(kw in name for kw in private_keywords):
                sensitive.append(sid)

    if not sensitive:
        return PreCheckResult("NET-004", "PASS", "no DB/private subnets with IGW routes", [])
    return PreCheckResult(
        "NET-004", "FAIL", f"{len(sensitive)} private/DB subnet(s) with IGW route", sensitive[:5]
    )


@_register("network")
def check_net_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-006: Security groups referencing Security Groups from other AWS accounts."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-006", "SKIP", "no security-groups evidence", [])

    # Get account_id from metadata or infer from first local SG reference
    meta = evidence.get("_audit_metadata") or {}
    account_id = meta.get("_account_id", "") if isinstance(meta, dict) else ""

    if not account_id:
        # Infer from first UserIdGroupPairs entry seen
        for sg in sgs:
            if not isinstance(sg, dict):
                continue
            for rule in (sg.get("IngressRules") or []) + (sg.get("EgressRules") or []):
                for pair in rule.get("UserIdGroupPairs") or []:
                    if isinstance(pair, dict) and pair.get("UserId"):
                        account_id = pair["UserId"]
                        break
                if account_id:
                    break
            if account_id:
                break

    if not account_id:
        return PreCheckResult("NET-006", "SKIP", "cannot determine account_id", [])

    cross_account: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for rule in sg.get("IngressRules") or []:
            for pair in rule.get("UserIdGroupPairs") or []:
                if isinstance(pair, dict) and pair.get("UserId") and pair["UserId"] != account_id:
                    cross_account.append(
                        f"{sg_id}→{pair.get('GroupId', 'unknown')}@{pair['UserId']}"
                    )

    if not cross_account:
        return PreCheckResult("NET-006", "PASS", "no cross-account SG references", [])
    return PreCheckResult(
        "NET-006", "FAIL", f"{len(cross_account)} cross-account SG reference(s)", cross_account[:5]
    )


@_register("network")
def check_net_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-008: Critical workloads (RDS, Lambda) deployed in public subnets."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts or not subnets:
        return PreCheckResult(
            "NET-008", "SKIP", "insufficient evidence to determine public subnets", []
        )

    # Find public subnet IDs (route tables with IGW routes)
    public_subnet_ids: set = set()
    public_subnet_route_tables: dict[str, str] = {}
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        igw = any(
            isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
            for r in (rt.get("Routes") or [])
        )
        if not igw:
            continue
        for assoc in rt.get("Associations") or []:
            if isinstance(assoc, dict) and assoc.get("SubnetId"):
                public_subnet_ids.add(assoc["SubnetId"])
                public_subnet_route_tables[assoc["SubnetId"]] = rt.get("RouteTableId", "")

    if not public_subnet_ids:
        return PreCheckResult("NET-008", "PASS", "no public subnets detected", [])

    critical_in_public: list = []
    resource_details: list = []

    # Check Lambda functions with VPC config
    lambda_doc = evidence.get("lambda-functions")
    lambdas = _items_from_doc(lambda_doc)
    for fn in lambdas:
        if not isinstance(fn, dict):
            continue
        vpc_config = fn.get("VpcConfig") or {}
        fn_subnets = vpc_config.get("SubnetIds") or []
        matching_subnets = [sid for sid in fn_subnets if sid in public_subnet_ids]
        if matching_subnets:
            resource = f"lambda:{fn.get('FunctionName', 'unknown')}"
            critical_in_public.append(resource)
            resource_details.append(
                {
                    "resource": resource,
                    "resource_type": "lambda",
                    "identifier": fn.get("FunctionName", "unknown"),
                    "arn": fn.get("FunctionArn"),
                    "public_subnet_ids": matching_subnets,
                    "route_table_ids": [
                        public_subnet_route_tables.get(sid)
                        for sid in matching_subnets
                        if public_subnet_route_tables.get(sid)
                    ],
                }
            )

    # Check RDS instances — handle both collector formats:
    #   1. Drystone collector: flat "SubnetIds" array (e.g. ["subnet-abc", ...])
    #   2. Raw AWS format: "DBSubnetGroup.Subnets" array of objects
    rds_doc = evidence.get("rds-instances")
    rds_items = _items_from_doc(rds_doc)
    for db in rds_items:
        if not isinstance(db, dict):
            continue
        # Try flat SubnetIds first (Drystone collector format)
        flat_subnets = db.get("SubnetIds") or []
        matching_subnets: list = []
        if flat_subnets:
            matching_subnets = [sid for sid in flat_subnets if sid in public_subnet_ids]
        else:
            # Fallback to raw AWS DBSubnetGroup format
            sg_subnets = db.get("DBSubnetGroup", {}).get("Subnets") or []
            for s in sg_subnets:
                sid = s.get("SubnetIdentifier") if isinstance(s, dict) else s
                if sid and sid in public_subnet_ids:
                    matching_subnets.append(sid)
        if matching_subnets:
            identifier = db.get("DBInstanceIdentifier", "unknown")
            resource = f"rds:{identifier}"
            critical_in_public.append(resource)
            resource_details.append(
                {
                    "resource": resource,
                    "resource_type": "rds",
                    "identifier": identifier,
                    "arn": db.get("DBInstanceArn") or db.get("DBInstanceARN"),
                    "vpc_id": (
                        db.get("DBSubnetGroup", {}).get("VpcId")
                        if isinstance(db.get("DBSubnetGroup"), dict)
                        else db.get("VpcId")
                    ),
                    "publicly_accessible": db.get("PubliclyAccessible"),
                    "public_subnet_ids": matching_subnets,
                    "route_table_ids": [
                        public_subnet_route_tables.get(sid)
                        for sid in matching_subnets
                        if public_subnet_route_tables.get(sid)
                    ],
                }
            )

    if not critical_in_public:
        return PreCheckResult("NET-008", "PASS", "no critical workloads in public subnets", [])
    result = PreCheckResult(
        "NET-008",
        "FAIL",
        f"{len(critical_in_public)} critical workload(s) in public subnets",
        critical_in_public[:5],
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-010: Default NACLs are overly permissive (protocol -1 ALLOW from 0.0.0.0/0)."""
    nacl_doc = evidence.get("network-acls")
    nacls = _items_from_doc(nacl_doc)

    if not nacls:
        return PreCheckResult("NET-010", "SKIP", "no network-acls evidence", [])

    permissive: list = []
    resource_details: list = []
    for nacl in nacls:
        if not isinstance(nacl, dict) or not nacl.get("IsDefault", False):
            continue
        nacl_id = nacl.get("NetworkAclId", "unknown")
        matched_entries = []
        for entry in nacl.get("Entries") or []:
            if not isinstance(entry, dict):
                continue
            if (
                entry.get("Protocol") == "-1"
                and entry.get("RuleAction") == "allow"
                and entry.get("CidrBlock") == "0.0.0.0/0"
            ):
                permissive.append(nacl_id)
                matched_entries.append(
                    {
                        "rule_number": entry.get("RuleNumber"),
                        "protocol": entry.get("Protocol"),
                        "cidr": entry.get("CidrBlock"),
                        "egress": entry.get("Egress", False),
                    }
                )
                break
        if matched_entries:
            resource_details.append(
                {
                    "resource": nacl_id,
                    "network_acl_id": nacl_id,
                    "vpc_id": nacl.get("VpcId"),
                    "is_default": True,
                    "associated_subnet_ids": [
                        assoc.get("SubnetId")
                        for assoc in (nacl.get("Associations") or [])
                        if isinstance(assoc, dict) and assoc.get("SubnetId")
                    ],
                    "allow_all_entries": matched_entries,
                }
            )

    if not permissive:
        return PreCheckResult(
            "NET-010", "PASS", "no default NACLs with ALLOW ALL from internet", []
        )
    result = PreCheckResult(
        "NET-010",
        "FAIL",
        f"{len(permissive)} default NACL(s) with ALLOW ALL from 0.0.0.0/0",
        permissive[:5],
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-012: Transit Gateway attachments not inspected by Network Firewall."""
    tgw_doc = evidence.get("transit-gateway-topology")
    if not isinstance(tgw_doc, dict):
        return PreCheckResult("NET-012", "SKIP", "no transit-gateway-topology evidence", [])

    tgws = tgw_doc.get("transit_gateways") or []
    if not tgws:
        return PreCheckResult("NET-012", "SKIP", "no Transit Gateways deployed", [])

    # TGWs exist but we cannot verify Network Firewall inspection from this evidence
    return PreCheckResult(
        "NET-012", "SKIP", f"{len(tgws)} TGW(s) present — manual inspection required", []
    )


@_register("network")
def check_net_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-014: Route tables with active blackhole routes."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)

    if not rts:
        return PreCheckResult("NET-014", "SKIP", "no route-tables evidence", [])

    blackholes: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        for route in rt.get("Routes") or []:
            if isinstance(route, dict) and route.get("State") == "blackhole":
                rt_id = rt.get("RouteTableId", "unknown")
                dst = route.get(
                    "DestinationCidrBlock", route.get("DestinationIpv6CidrBlock", "unknown")
                )
                blackholes.append(f"{rt_id}:{dst}")
                break

    if not blackholes:
        return PreCheckResult("NET-014", "PASS", "no blackhole routes", [])
    rt_ids = [b.split(":")[0] for b in blackholes]
    return PreCheckResult(
        "NET-014", "FAIL", f"{len(blackholes)} route table(s) with blackhole route", rt_ids[:5]
    )


@_register("network")
def check_net_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-017: Private subnets (no 'public' in name) with a default route to an IGW."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts:
        return PreCheckResult("NET-017", "SKIP", "no route-tables evidence", [])
    if not subnets:
        return PreCheckResult("NET-017", "SKIP", "no subnets evidence", [])

    # Build subnet name map
    subnet_name: Dict[str, str] = {}
    for s in subnets:
        if not isinstance(s, dict):
            continue
        sid = s.get("SubnetId", "")
        tags = {
            t.get("Key", ""): t.get("Value", "")
            for t in (s.get("Tags") or [])
            if isinstance(t, dict)
        }
        subnet_name[sid] = tags.get("Name", "").lower()

    flagged: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        igw_routes = [
            r
            for r in (rt.get("Routes") or [])
            if isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
        ]
        if not igw_routes:
            continue
        for assoc in rt.get("Associations") or []:
            if not isinstance(assoc, dict):
                continue
            sid = assoc.get("SubnetId")
            if not sid:
                continue
            name = subnet_name.get(sid, "")
            # Only flag if the subnet name does NOT contain 'public'
            if "public" not in name:
                flagged.append(sid)

    if not flagged:
        return PreCheckResult("NET-017", "PASS", "no private subnets with IGW routes", [])
    return PreCheckResult(
        "NET-017", "FAIL", f"{len(flagged)} private subnet(s) with IGW route", flagged[:5]
    )


@_register("network")
def check_net_019(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-019: Security groups with more than 50 rules (hard to audit)."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-019", "SKIP", "no security-groups evidence", [])

    oversized: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        total_rules = len(sg.get("IngressRules") or []) + len(sg.get("EgressRules") or [])
        if total_rules > 50:
            oversized.append(sg.get("GroupId", "unknown"))

    if not oversized:
        return PreCheckResult("NET-019", "PASS", "no SGs with more than 50 rules", [])
    return PreCheckResult(
        "NET-019", "FAIL", f"{len(oversized)} SG(s) with more than 50 rules", oversized[:10]
    )


@_register("network")
def check_net_021(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-021: Orphaned security groups (no attached resources — requires ENI data)."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-021", "SKIP", "no security-groups evidence", [])

    # ENI attachment counts are not collected — cannot determine orphan status
    return PreCheckResult(
        "NET-021", "SKIP", "ENI attachment data not collected; manual review needed", []
    )


@_register("network")
def check_net_029(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-029: VPC CIDR blocks overlap across VPCs."""
    vpc_doc = evidence.get("vpcs")
    vpcs = _items_from_doc(vpc_doc)
    if isinstance(vpc_doc, dict) and isinstance(vpc_doc.get("by_id"), dict):
        vpcs = list(vpc_doc["by_id"].values())

    if not vpcs:
        return PreCheckResult("NET-029", "SKIP", "no vpcs evidence", [])
    if len(vpcs) < 2:
        return PreCheckResult("NET-029", "PASS", "single VPC — no overlap possible", [])

    # Simple CIDR prefix overlap check (no full IP math — flag same prefixes)
    cidrs: list = []
    overlaps: list = []
    for vpc in vpcs:
        if not isinstance(vpc, dict):
            continue
        cidr = vpc.get("CidrBlock", "")
        vpc_id = vpc.get("VpcId", "unknown")
        if cidr in cidrs:
            overlaps.append(f"{vpc_id}:{cidr}")
        cidrs.append(cidr)

    if not overlaps:
        return PreCheckResult(
            "NET-029", "PASS", f"{len(vpcs)} VPCs with no exact CIDR duplicates", []
        )
    return PreCheckResult("NET-029", "FAIL", f"CIDR overlap detected: {overlaps[:3]}", overlaps[:5])


@_register("network")
def check_net_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-005: VPC peering with broad bidirectional routing without filtering."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)

    if not rts:
        return PreCheckResult("NET-005", "SKIP", "no route-tables evidence", [])

    # VPC peering connections appear as routes with GatewayId starting with 'pcx-'
    peering_routes: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        for route in rt.get("Routes") or []:
            if isinstance(route, dict) and str(route.get("GatewayId", "")).startswith("pcx-"):
                rt_id = rt.get("RouteTableId", "unknown")
                dst = route.get(
                    "DestinationCidrBlock", route.get("DestinationIpv6CidrBlock", "unknown")
                )
                peering_routes.append(f"{rt_id}:{dst}")

    if not peering_routes:
        return PreCheckResult("NET-005", "PASS", "no VPC peering routes detected", [])
    # Peering found — cannot determine filtering adequacy without SG analysis
    return PreCheckResult(
        "NET-005", "SKIP", f"{len(peering_routes)} peering route(s) — review SG filtering", []
    )


@_register("network")
def check_net_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-007: Network Firewall not deployed for internet-facing VPCs."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    vpce_doc = evidence.get("vpc-endpoints")
    vpces = _items_from_doc(vpce_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)
    ec2_doc = evidence.get("ec2-instances")
    ec2_instances = _items_from_doc(ec2_doc)
    rds_doc = evidence.get("rds-instances")
    rds_instances = _items_from_doc(rds_doc)
    lambda_doc = evidence.get("lambda-functions")
    lambda_functions = _items_from_doc(lambda_doc)

    if not rts:
        return PreCheckResult("NET-007", "SKIP", "no route-tables evidence", [])

    subnet_to_vpc = {
        str(subnet.get("SubnetId")): str(subnet.get("VpcId"))
        for subnet in subnets
        if isinstance(subnet, dict) and subnet.get("SubnetId") and subnet.get("VpcId")
    }
    workload_counts: dict[str, int] = {}

    def _mark_workload(vpc_id: str) -> None:
        if vpc_id and vpc_id != "unknown":
            workload_counts[vpc_id] = workload_counts.get(vpc_id, 0) + 1

    for instance in ec2_instances:
        if not isinstance(instance, dict):
            continue
        vpc_id = str(
            instance.get("VpcId") or subnet_to_vpc.get(str(instance.get("SubnetId"))) or ""
        )
        _mark_workload(vpc_id)

    for db in rds_instances:
        if not isinstance(db, dict):
            continue
        vpc_id = str(db.get("VpcId") or "")
        if not vpc_id:
            for subnet_id in db.get("SubnetIds") or []:
                vpc_id = subnet_to_vpc.get(str(subnet_id), "")
                if vpc_id:
                    break
        _mark_workload(vpc_id)

    for fn in lambda_functions:
        if not isinstance(fn, dict):
            continue
        vpc_config = fn.get("VpcConfig") or {}
        for subnet_id in vpc_config.get("SubnetIds") or []:
            vpc_id = subnet_to_vpc.get(str(subnet_id), "")
            if vpc_id:
                _mark_workload(vpc_id)
                break

    # Check if any VPC has a route to an Internet Gateway (north-south traffic)
    internet_facing_vpcs: dict[str, dict] = {}
    empty_internet_facing_vpcs: list[str] = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        for route in rt.get("Routes") or []:
            if not isinstance(route, dict) or not str(route.get("GatewayId", "")).startswith(
                "igw-"
            ):
                continue
            vpc_id = str(rt.get("VpcId") or "unknown")
            if workload_counts.get(vpc_id, 0) == 0:
                if vpc_id not in empty_internet_facing_vpcs:
                    empty_internet_facing_vpcs.append(vpc_id)
                continue
            internet_facing_vpcs.setdefault(
                vpc_id,
                {
                    "resource": vpc_id,
                    "vpc_id": vpc_id,
                    "route_table_ids": [],
                    "internet_gateway_ids": [],
                    "has_network_firewall_endpoint": False,
                    "workload_count": workload_counts.get(vpc_id, 0),
                },
            )
            if rt.get("RouteTableId"):
                internet_facing_vpcs[vpc_id]["route_table_ids"].append(rt.get("RouteTableId"))
            if route.get("GatewayId"):
                internet_facing_vpcs[vpc_id]["internet_gateway_ids"].append(route.get("GatewayId"))

    if not internet_facing_vpcs:
        return PreCheckResult(
            "NET-007", "PASS", "no Internet Gateway routes — north-south traffic absent", []
        )

    # Check VPC endpoints for AWS Network Firewall service
    nfw_vpce = [
        e
        for e in vpces
        if isinstance(e, dict) and "network-firewall" in (e.get("ServiceName") or "").lower()
    ]
    if nfw_vpce:
        return PreCheckResult("NET-007", "PASS", "Network Firewall VPC endpoint detected", [])

    # VPC has IGW but no Network Firewall endpoint visible in collected evidence
    affected = sorted(internet_facing_vpcs)
    resource_details = list(internet_facing_vpcs.values())
    result = PreCheckResult(
        "NET-007",
        "FAIL",
        "VPC has Internet Gateway but no AWS Network Firewall endpoint detected in vpc-endpoints",
        affected,
    )
    result.metadata["resource_details"] = resource_details
    if empty_internet_facing_vpcs:
        result.metadata["empty_internet_facing_vpcs_excluded"] = sorted(empty_internet_facing_vpcs)
    return result


@_register("network")
def check_net_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-013: Private route tables rely on NAT for AWS service egress while VPC endpoints are absent."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    nat_doc = evidence.get("nat-gateway-routes")
    nat_routes = _items_from_doc(nat_doc)
    vpce_doc = evidence.get("vpc-endpoints")
    vpces = _items_from_doc(vpce_doc)

    if not rts:
        return PreCheckResult("NET-013", "SKIP", "no route-tables evidence", [])
    if vpces:
        return PreCheckResult("NET-013", "PASS", "VPC endpoint evidence present", [])

    nat_by_id = {
        str(nat.get("NatGatewayId")): nat
        for nat in nat_routes
        if isinstance(nat, dict) and nat.get("NatGatewayId")
    }
    affected: list[str] = []
    resource_details: list[dict[str, Any]] = []

    for rt in rts:
        if not isinstance(rt, dict):
            continue
        rt_id = str(rt.get("RouteTableId") or "")
        vpc_id = str(rt.get("VpcId") or "")
        for route in rt.get("Routes") or []:
            if not isinstance(route, dict):
                continue
            nat_id = str(route.get("NatGatewayId") or "")
            if route.get("DestinationCidrBlock") != "0.0.0.0/0" or not nat_id:
                continue
            if rt_id:
                affected.append(rt_id)
            nat = nat_by_id.get(nat_id, {})
            resource_details.append(
                {
                    "resource": rt_id,
                    "route_table_id": rt_id,
                    "vpc_id": vpc_id,
                    "nat_gateway_id": nat_id,
                    "nat_gateway_subnet_id": nat.get("SubnetId"),
                    "destination": "0.0.0.0/0",
                    "vpc_endpoints_present": False,
                    "observed_service_traffic": "not_collected",
                }
            )
            break

    if not affected:
        return PreCheckResult(
            "NET-013", "PASS", "no private route tables with NAT default route", []
        )

    result = PreCheckResult(
        "NET-013",
        "FAIL",
        f"{len(affected)} route table(s) rely on NAT default routes and no VPC endpoints are present",
        affected,
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-015: Redundant SG references — SG ref and 0.0.0.0/0 in the same rule."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-015", "SKIP", "no security-groups evidence", [])

    affected: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for rule in (sg.get("EgressRules") or []) + (sg.get("IngressRules") or []):
            ip_ranges = rule.get("IpRanges") or []
            pairs = rule.get("UserIdGroupPairs") or []
            if pairs and any(
                isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges
            ):
                if sg_id not in affected:
                    affected.append(sg_id)

    if not affected:
        return PreCheckResult("NET-015", "PASS", "no redundant SG references detected", [])
    return PreCheckResult(
        "NET-015",
        "FAIL",
        f"{len(affected)} SG(s) with redundant SG ref + 0.0.0.0/0 in same rule",
        affected[:5],
    )


@_register("network")
def check_net_025(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-025: Subnets missing classification tags (Tier/Layer/Classification)."""
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not subnets:
        return PreCheckResult("NET-025", "SKIP", "no subnets evidence", [])

    classification_keys = {"tier", "layer", "classification", "subnet-type", "subnettype"}
    missing: list = []
    resource_details: list = []
    for s in subnets:
        if not isinstance(s, dict):
            continue
        tag_keys = {t.get("Key", "").lower() for t in (s.get("Tags") or []) if isinstance(t, dict)}
        if not (tag_keys & classification_keys):
            subnet_id = s.get("SubnetId", "unknown")
            missing.append(subnet_id)
            resource_details.append(
                {
                    "resource": subnet_id,
                    "subnet_id": subnet_id,
                    "vpc_id": s.get("VpcId"),
                    "cidr_block": s.get("CidrBlock"),
                    "availability_zone": s.get("AvailabilityZone"),
                    "tag_keys": sorted(tag_keys),
                    "missing_classification": True,
                }
            )

    if not missing:
        return PreCheckResult("NET-025", "PASS", "all subnets have classification tags", [])
    result = PreCheckResult(
        "NET-025",
        "FAIL",
        f"{len(missing)} subnet(s) missing classification tags (Tier/Layer)",
        missing,
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-022: Public subnets (0.0.0.0/0 to IGW) — verify no sensitive workloads deployed."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts:
        return PreCheckResult("NET-022", "SKIP", "no route-tables evidence", [])
    if not subnets:
        return PreCheckResult("NET-022", "SKIP", "no subnets evidence", [])

    explicit_route_by_subnet: dict[str, dict] = {}
    main_route_by_vpc: dict[str, dict] = {}
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        for assoc in rt.get("Associations") or []:
            if not isinstance(assoc, dict):
                continue
            if assoc.get("SubnetId"):
                explicit_route_by_subnet[str(assoc["SubnetId"])] = rt
            elif assoc.get("Main") is True and rt.get("VpcId"):
                main_route_by_vpc[str(rt.get("VpcId"))] = rt

    # Find public subnet IDs (route tables with IGW default route, including inherited main routes)
    public_subnet_ids: set = set()
    resource_details: list = []
    for subnet in subnets:
        if not isinstance(subnet, dict) or not subnet.get("SubnetId"):
            continue
        subnet_id = str(subnet.get("SubnetId"))
        vpc_id = str(subnet.get("VpcId") or "")
        rt = explicit_route_by_subnet.get(subnet_id) or main_route_by_vpc.get(vpc_id)
        if not isinstance(rt, dict):
            continue
        has_igw = any(
            isinstance(r, dict)
            and str(r.get("GatewayId", "")).startswith("igw-")
            and r.get("DestinationCidrBlock") == "0.0.0.0/0"
            for r in (rt.get("Routes") or [])
        )
        if not has_igw:
            continue
        inherited_main_route = subnet_id not in explicit_route_by_subnet
        public_subnet_ids.add(subnet_id)
        resource_details.append(
            {
                "resource": subnet_id,
                "subnet_id": subnet_id,
                "route_table_id": rt.get("RouteTableId"),
                "vpc_id": vpc_id or rt.get("VpcId"),
                "internet_gateway_route": True,
                "inherited_main_route": inherited_main_route,
            }
        )

    if not public_subnet_ids:
        return PreCheckResult("NET-022", "PASS", "no public subnets detected", [])
    result = PreCheckResult(
        "NET-022",
        "FAIL",
        f"{len(public_subnet_ids)} public subnet(s) with IGW route require workload verification",
        sorted(public_subnet_ids)[:8],
    )
    result.metadata["resource_details"] = resource_details
    return result


@_register("network")
def check_net_unrestricted_egress(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-EGR-001: Security groups with unrestricted egress (0.0.0.0/0 protocol -1)."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)

    if not sgs:
        return PreCheckResult("NET-EGR-001", "SKIP", "no security-groups evidence", [])

    # Find SGs with unrestricted egress: protocol=-1, cidr=0.0.0.0/0 or ::/0
    unrestricted = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        egress_rules = sg.get("IpPermissionsEgress", [])
        for rule in egress_rules:
            if not isinstance(rule, dict):
                continue
            # protocol -1 = all traffic
            if str(rule.get("IpProtocol", "")) != "-1":
                continue
            # Check for open CIDR
            ip_ranges = rule.get("IpRanges", [])
            ipv6_ranges = rule.get("Ipv6Ranges", [])
            has_open_ipv4 = any(
                isinstance(r, dict) and r.get("CidrIp") in {"0.0.0.0/0", "0.0.0.0"}
                for r in ip_ranges
            )
            has_open_ipv6 = any(
                isinstance(r, dict) and r.get("CidrIpv6") in {"::/0"} for r in ipv6_ranges
            )
            if has_open_ipv4 or has_open_ipv6:
                unrestricted.append(str(sg.get("GroupId") or sg.get("GroupName", "unknown")))
                break  # One open rule is enough to flag this SG

    if not unrestricted:
        return PreCheckResult(
            "NET-EGR-001", "PASS", "no security groups with unrestricted egress (all traffic)", []
        )
    return PreCheckResult(
        "NET-EGR-001",
        "FAIL",
        f"{len(unrestricted)} security group(s) with unrestricted egress (protocol=-1, 0.0.0.0/0)",
        unrestricted[:10],
    )


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
