"""Network (NET-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, indexed_ref_for


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id not in {
        "NET-001",
        "NET-003",
        "NET-007",
        "NET-008",
        "NET-009",
        "NET-010",
        "NET-011",
        "NET-013",
        "NET-016",
        "NET-022",
        "NET-025",
        "NET-027",
    }:
        return None

    resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
    if not resource_details:
        return None

    refs: List[str] = []

    def _add_ref(key: str, field: str, value: Any) -> None:
        value_str = str(value or "")
        if not value_str:
            return
        ref = indexed_ref_for(
            evidence,
            key,
            lambda item, field=field, value_str=value_str: str(item.get(field) or "")
            == value_str,
        )
        if ref:
            refs.append(ref)

    for detail in resource_details:
        if not isinstance(detail, dict):
            continue
        if check_id in {"NET-001", "NET-009", "NET-011", "NET-027"}:
            sg_id = detail.get("security_group_id") or detail.get("resource")
            _add_ref("security-groups", "GroupId", sg_id)
        elif check_id in {"NET-003", "NET-010"}:
            _add_ref(
                "network-acls",
                "NetworkAclId",
                detail.get("network_acl_id") or detail.get("resource"),
            )
        elif check_id == "NET-013":
            _add_ref(
                "route-tables",
                "RouteTableId",
                detail.get("route_table_id") or detail.get("resource"),
            )
            _add_ref("nat-gateway-routes", "NatGatewayId", detail.get("nat_gateway_id"))
            refs.append("vpc-endpoints.json#/items")
        elif check_id in {"NET-016", "NET-022", "NET-025"}:
            _add_ref("subnets", "SubnetId", detail.get("subnet_id") or detail.get("resource"))
            _add_ref("network-acls", "NetworkAclId", detail.get("network_acl_id"))
            _add_ref("route-tables", "RouteTableId", detail.get("route_table_id"))
        elif check_id == "NET-007":
            _add_ref("vpcs", "VpcId", detail.get("vpc_id") or detail.get("resource"))
            for route_table_id in detail.get("route_table_ids") or []:
                _add_ref("route-tables", "RouteTableId", route_table_id)
            for igw_id in detail.get("internet_gateway_ids") or []:
                _add_ref("internet-gateways", "InternetGatewayId", igw_id)
        elif check_id == "NET-008":
            if detail.get("resource_type") == "rds":
                _add_ref("rds-instances", "DBInstanceIdentifier", detail.get("identifier"))
            elif detail.get("resource_type") == "lambda":
                _add_ref("lambda-functions", "FunctionName", detail.get("identifier"))
            for subnet_id in detail.get("public_subnet_ids") or []:
                _add_ref("subnets", "SubnetId", subnet_id)
            for route_table_id in detail.get("route_table_ids") or []:
                _add_ref("route-tables", "RouteTableId", route_table_id)

    summaries = {
        "NET-001": f"{len(resource_details)} SG rule(s) exposing sensitive ports to the internet",
        "NET-003": f"{len(resource_details)} NACL(s) with allow-all inbound internet rules",
        "NET-007": f"{len(resource_details)} internet-facing VPC(s) without Network Firewall evidence",
        "NET-008": f"{len(resource_details)} critical workload(s) in public subnets",
        "NET-009": f"{len(resource_details)} SG rule(s) with overly broad CIDR to non-web ports",
        "NET-010": f"{len(resource_details)} default NACL(s) with allow-all internet rules",
        "NET-011": f"{len(resource_details)} SG(s) with critical rules missing description",
        "NET-013": f"{len(resource_details)} route table(s) with NAT default routes and no VPC endpoints",
        "NET-016": f"{len(resource_details)} subnet(s) associated with default NACLs",
        "NET-022": f"{len(resource_details)} public subnet(s) with IGW route",
        "NET-025": f"{len(resource_details)} subnet(s) missing classification tags",
        "NET-027": f"{len(resource_details)} Security Group(s) missing tags",
    }
    return (
        dedupe_refs(refs)[:50],
        {
            "evidence_summary": summaries[check_id],
            "affected_resources": resource_details,
        },
    )
