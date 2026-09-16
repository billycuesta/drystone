# ruff: noqa
"""Exposure deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .iam import _AWS_SERVICE_ACCOUNTS
from .metadata import *

logger = logging.getLogger(__name__)


# EXPOSURE PRE-CHECKS
# ============================================================================


@_register("exposure")
def check_exp_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public S3 bucket exposure."""
    s3_doc = evidence.get("s3-buckets")
    items = _items_from_doc(s3_doc)
    if not items:
        return PreCheckResult("EXP-001", "SKIP", "no s3-buckets evidence", [])

    def _is_public_acl(grants):
        if not isinstance(grants, list):
            return False
        for g in grants:
            if not isinstance(g, dict):
                continue
            gr = g.get("Grantee")
            if isinstance(gr, dict) and gr.get("Type") == "Group":
                uri = gr.get("URI", "")
                if "AllUsers" in str(uri) or "AuthenticatedUsers" in str(uri):
                    return True
        return False

    def _pab_blocks_all(pab):
        if not isinstance(pab, dict):
            return False
        return all(
            [
                pab.get("BlockPublicAcls"),
                pab.get("BlockPublicPolicy"),
                pab.get("IgnorePublicAcls"),
                pab.get("RestrictPublicBuckets"),
            ]
        )

    _network_condition_keys = (
        "aws:sourceVpce",
        "aws:sourceVpc",
        "aws:sourcevpce",
        "aws:sourcevpc",
        "aws:PrincipalOrgID",
        "aws:PrincipalOrgPaths",
    )

    def _has_public_policy(policy):
        if not isinstance(policy, dict):
            return False
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if principal != "*" and not (
                isinstance(principal, dict) and principal.get("AWS") == "*"
            ):
                continue
            act = st.get("Action")
            actions = [act] if isinstance(act, str) else (act or [])
            if not any(a in actions for a in ("s3:*", "s3:GetObject", "s3:ListBucket")):
                continue
            # Condition restricting to VPC/org = not truly public
            condition = st.get("Condition") or {}
            cond_keys = set()
            for op_dict in condition.values():
                if isinstance(op_dict, dict):
                    cond_keys.update(op_dict.keys())
            if any(k in cond_keys for k in _network_condition_keys):
                continue
            return True
        return False

    # Also try by_name lookup
    by_name = {}
    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
        by_name = s3_doc["by_name"]

    all_buckets = list(by_name.values()) if by_name else items
    public = []
    for b in all_buckets:
        if not isinstance(b, dict):
            continue
        # PublicAccessBlock fully enabled → bucket cannot be public regardless of ACL/policy
        if _pab_blocks_all(b.get("PublicAccessBlock")):
            continue
        if _is_public_acl(b.get("ACL")) or _has_public_policy(b.get("BucketPolicy")):
            public.append(f"arn:aws:s3:::{b.get('Name', 'unknown')}")

    if not public:
        return PreCheckResult("EXP-001", "PASS", "no public S3 buckets", [])
    return PreCheckResult("EXP-001", "FAIL", f"{len(public)} public buckets", public[:10])


@_register("exposure")
def check_exp_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """RDS instances publicly accessible from internet."""
    rds_doc = evidence.get("rds-instances")
    rds_items = _items_from_doc(rds_doc)
    if not rds_items:
        return PreCheckResult("EXP-002", "SKIP", "no rds-instances evidence", [])

    sg_doc = evidence.get("security-groups")
    sg_by_id = sg_doc.get("by_id", {}) if isinstance(sg_doc, dict) else {}
    if not isinstance(sg_by_id, dict):
        sg_by_id = {}

    engine_ports = {
        "mysql": [3306],
        "mariadb": [3306],
        "postgres": [5432],
        "postgresql": [5432],
        "sqlserver": [1433],
        "oracle": [1521],
        "docdb": [27017],
    }
    default_db_ports = [1433, 1521, 27017, 3306, 5432]

    exposed: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for db in rds_items:
        if not isinstance(db, dict) or db.get("PubliclyAccessible") is not True:
            continue
        engine = str(db.get("Engine") or "").lower()
        ports = next((v for k, v in engine_ports.items() if k in engine), default_db_ports)
        open_rules: List[Dict[str, Any]] = []
        for sg_ref in db.get("VpcSecurityGroups", []) or []:
            if not isinstance(sg_ref, dict):
                continue
            sg_id = str(sg_ref.get("VpcSecurityGroupId") or "")
            sg = sg_by_id.get(sg_id)
            if not isinstance(sg, dict):
                continue
            for perm in sg.get("IngressRules", []) or []:
                if not isinstance(perm, dict):
                    continue
                for port in ports:
                    if _sg_allows_world(perm, port=port):
                        sources = [
                            str(r.get("CidrIp"))
                            for r in (perm.get("IpRanges") or [])
                            if isinstance(r, dict) and r.get("CidrIp")
                        ] + [
                            str(r.get("CidrIpv6"))
                            for r in (perm.get("Ipv6Ranges") or [])
                            if isinstance(r, dict) and r.get("CidrIpv6")
                        ]
                        open_rules.append(
                            {
                                "security_group_id": sg_id,
                                "security_group_name": sg.get("GroupName"),
                                "protocol": perm.get("IpProtocol", "tcp"),
                                "port": port,
                                "sources": sources,
                            }
                        )
                        break
        if open_rules:
            name = str(db.get("DBInstanceIdentifier") or "unknown")
            exposed.append(name)
            resource_details.append(
                {
                    "db_instance_identifier": name,
                    "engine": db.get("Engine"),
                    "publicly_accessible": True,
                    "db_subnet_group": db.get("DBSubnetGroup"),
                    "open_rules": open_rules,
                }
            )

    if not exposed:
        return PreCheckResult(
            "EXP-002", "PASS", "no publicly accessible RDS with internet-open DB ports", []
        )
    result = PreCheckResult(
        "EXP-002",
        "FAIL",
        f"{len(exposed)} public RDS instances with internet-open DB ports",
        exposed[:5],
    )
    result.metadata["resource_details"] = resource_details[:10]
    return result


@_register("exposure")
def check_exp_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """SSH/RDP open to 0.0.0.0/0."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    # Also handle by_id shape
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("EXP-003", "SKIP", "no security-groups evidence", [])

    exposed: list = []
    resource_details: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            for port in (22, 3389):
                if _sg_allows_world(perm, port=port):
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
                                "port": port,
                                "service": _port_service_name(port),
                                "protocol": perm.get("IpProtocol", "tcp"),
                                "source": cidr,
                            }
                        )
                    break

    if not exposed:
        return PreCheckResult("EXP-003", "PASS", "no SSH/RDP open to world", [])
    result = PreCheckResult(
        "EXP-003", "FAIL", f"{len(exposed)} SGs with SSH/RDP open", exposed[:10]
    )
    result.metadata["resource_details"] = resource_details[:15]
    return result


@_register("exposure")
def check_exp_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Internet-facing ALB/NLB without WAF association."""
    lbs_doc = evidence.get("load-balancers")
    assoc_doc = evidence.get("wafv2-web-acl-alb-associations")
    if not isinstance(lbs_doc, dict) or not isinstance(assoc_doc, dict):
        return PreCheckResult("EXP-007", "SKIP", "missing LB/WAF evidence", [])

    lbs = _items_from_doc(lbs_doc)
    by_alb = assoc_doc.get("by_alb_arn", {})
    if not isinstance(by_alb, dict):
        by_alb = {}

    internet_albs = [
        lb
        for lb in lbs
        if isinstance(lb, dict)
        and lb.get("Type") == "application"
        and lb.get("Scheme") == "internet-facing"
        and isinstance(lb.get("LoadBalancerArn"), str)
    ]

    if not internet_albs:
        return PreCheckResult("EXP-007", "PASS", "no internet-facing ALBs", [])

    unprotected = []
    resource_details: List[Dict[str, Any]] = []
    for alb in internet_albs:
        arn = alb["LoadBalancerArn"]
        if not (by_alb.get(arn) or []):
            unprotected.append(arn)
            resource_details.append(
                {
                    "load_balancer_arn": arn,
                    "load_balancer_name": alb.get("LoadBalancerName"),
                    "scheme": alb.get("Scheme"),
                    "type": alb.get("Type"),
                    "dns_name": alb.get("DNSName"),
                    "security_groups": alb.get("SecurityGroups") or [],
                    "waf_associations": [],
                }
            )

    if not unprotected:
        return PreCheckResult("EXP-007", "PASS", "all internet ALBs have WAF", [])
    result = PreCheckResult(
        "EXP-007", "FAIL", f"{len(unprotected)} ALBs without WAF", unprotected[:5]
    )
    result.metadata["resource_details"] = resource_details[:10]
    return result


@_register("exposure")
def check_exp_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """Obsolete TLS policies on internet-facing ALB."""
    lbs_doc = evidence.get("load-balancers")
    lis_doc = evidence.get("load-balancer-listeners")
    if not isinstance(lbs_doc, dict) or not isinstance(lis_doc, dict):
        return PreCheckResult("EXP-010", "SKIP", "missing ELBv2 evidence", [])

    lbs = _items_from_doc(lbs_doc)
    scheme_by_arn = {
        lb.get("LoadBalancerArn"): lb.get("Scheme")
        for lb in lbs
        if isinstance(lb, dict) and isinstance(lb.get("LoadBalancerArn"), str)
    }
    listeners = _items_from_doc(lis_doc)

    for li in listeners:
        if not isinstance(li, dict) or li.get("Protocol") != "HTTPS":
            continue
        lb_arn = li.get("LoadBalancerArn")
        if not isinstance(lb_arn, str) or scheme_by_arn.get(lb_arn) != "internet-facing":
            continue
        pol = li.get("SslPolicy")
        if not isinstance(pol, str):
            continue
        if (
            "TLS-1-0" in pol
            or "TLS-1-1" in pol
            or pol in {"ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08"}
        ):
            return PreCheckResult("EXP-010", "FAIL", f"obsolete TLS policy: {pol}", [lb_arn])

    return PreCheckResult("EXP-010", "PASS", "no obsolete TLS policies", [])


@_register("exposure")
def check_exp_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public object listing on S3."""
    s3_doc = evidence.get("s3-buckets")
    items = _items_from_doc(s3_doc)
    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
        items = list(s3_doc["by_name"].values())

    for b in items:
        if not isinstance(b, dict):
            continue
        policy = b.get("BucketPolicy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if principal != "*" and not (
                isinstance(principal, dict) and principal.get("AWS") == "*"
            ):
                continue
            act = st.get("Action")
            actions = [act] if isinstance(act, str) else (act or [])
            if "s3:ListBucket" in actions:
                return PreCheckResult(
                    "EXP-011",
                    "FAIL",
                    f"bucket '{b.get('Name')}' allows public ListBucket",
                    [f"arn:aws:s3:::{b.get('Name', '')}"],
                )

    return PreCheckResult("EXP-011", "PASS", "no public ListBucket", [])


@_register("exposure")
def check_exp_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 TLS enforcement (aws:SecureTransport deny)."""
    s3_doc = evidence.get("s3-buckets")
    if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
        return PreCheckResult("EXP-013", "SKIP", "no indexed s3-buckets", [])

    by_name = s3_doc["by_name"]
    missing: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for bn, b in by_name.items():
        if not isinstance(b, dict):
            continue
        policy = b.get("BucketPolicy")
        if not isinstance(policy, dict):
            missing.append(bn)
            resource_details.append(
                {
                    "bucket_name": bn,
                    "bucket_arn": f"arn:aws:s3:::{bn}",
                    "has_bucket_policy": False,
                    "has_secure_transport_deny": False,
                    "policy_statement_ids": [],
                }
            )
            continue
        has_tls = False
        statement_ids: List[str] = []
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Deny":
                continue
            if st.get("Sid"):
                statement_ids.append(str(st.get("Sid")))
            cond = st.get("Condition")
            if isinstance(cond, dict):
                bl = cond.get("Bool")
                if isinstance(bl, dict) and bl.get("aws:SecureTransport") == "false":
                    has_tls = True
                    break
        if not has_tls:
            missing.append(bn)
            resource_details.append(
                {
                    "bucket_name": bn,
                    "bucket_arn": f"arn:aws:s3:::{bn}",
                    "has_bucket_policy": True,
                    "has_secure_transport_deny": False,
                    "policy_statement_ids": statement_ids,
                }
            )

    if not missing:
        return PreCheckResult("EXP-013", "PASS", "all buckets enforce TLS", [])
    result = PreCheckResult(
        "EXP-013",
        "FAIL",
        f"{len(missing)} buckets without TLS enforcement",
        [f"arn:aws:s3:::{n}" for n in missing],
    )
    result.metadata["resource_details"] = resource_details[:20]
    return result


@_register("exposure")
def check_exp_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 audit/log buckets should have versioning enabled."""
    s3_doc = evidence.get("s3-buckets")
    if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
        return PreCheckResult("EXP-014", "SKIP", "no indexed s3-buckets", [])

    by_name = s3_doc["by_name"]
    unversioned: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for bn, b in by_name.items():
        if not isinstance(b, dict):
            continue
        if (b.get("Versioning") or "") != "Enabled":
            unversioned.append(bn)
            resource_details.append(
                {
                    "bucket_name": bn,
                    "bucket_arn": f"arn:aws:s3:::{bn}",
                    "versioning": b.get("Versioning"),
                }
            )

    if not unversioned:
        return PreCheckResult("EXP-014", "PASS", "all buckets have versioning", [])
    result = PreCheckResult(
        "EXP-014",
        "FAIL",
        f"{len(unversioned)} buckets without versioning",
        [f"arn:aws:s3:::{n}" for n in unversioned],
    )
    result.metadata["resource_details"] = resource_details[:20]
    return result


@_register("exposure")
def check_exp_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 public/cross-account bucket policy access without effective conditions."""
    s3_doc = evidence.get("s3-buckets")
    items = _items_from_doc(s3_doc)
    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
        items = list(s3_doc["by_name"].values())

    meta = evidence.get("_audit_metadata")
    audit_account = meta.get("_account_id") if isinstance(meta, dict) else None

    if not audit_account:
        return PreCheckResult("EXP-015", "SKIP", "no audit account metadata", [])

    affected: List[str] = []
    resource_details: List[Dict[str, Any]] = []

    def _condition_status(condition: Any) -> tuple[bool, str]:
        if not isinstance(condition, dict) or not condition:
            return False, "missing_condition"
        for op_values in condition.values():
            if not isinstance(op_values, dict):
                continue
            for key in ("aws:SourceAccount", "aws:PrincipalOrgID"):
                if key not in op_values:
                    continue
                value = op_values.get(key)
                values = value if isinstance(value, list) else [value]
                if any(str(v or "").strip() for v in values):
                    return True, "effective_condition"
                return False, f"empty_{key}"
        return False, "missing_source_or_org_condition"

    for b in items:
        if not isinstance(b, dict):
            continue
        bucket_name = str(b.get("Name") or "")
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        policy = b.get("BucketPolicy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            condition_ok, condition_status = _condition_status(st.get("Condition"))
            if principal == "*":
                if condition_ok:
                    continue
                affected.append(bucket_arn)
                resource_details.append(
                    {
                        "bucket_name": bucket_name,
                        "bucket_arn": bucket_arn,
                        "statement_sid": st.get("Sid"),
                        "principal": principal,
                        "action": st.get("Action"),
                        "resource": st.get("Resource"),
                        "condition_status": condition_status,
                        "condition": st.get("Condition"),
                    }
                )
                continue
            if isinstance(principal, dict):
                aws_p = principal.get("AWS")
                principals = (
                    [aws_p]
                    if isinstance(aws_p, str)
                    else (aws_p if isinstance(aws_p, list) else [])
                )
                for p in principals:
                    if not isinstance(p, str):
                        continue
                    parts = p.split(":")
                    if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                        # Skip known AWS service accounts (e.g. ELB access logging)
                        if parts[4] in _AWS_SERVICE_ACCOUNTS:
                            continue
                        if condition_ok:
                            continue
                        affected.append(bucket_arn)
                        affected.append(p)
                        resource_details.append(
                            {
                                "bucket_name": bucket_name,
                                "bucket_arn": bucket_arn,
                                "statement_sid": st.get("Sid"),
                                "principal": p,
                                "action": st.get("Action"),
                                "resource": st.get("Resource"),
                                "condition_status": condition_status,
                                "condition": st.get("Condition"),
                            }
                        )

    if affected:
        bucket_count = len({d["bucket_arn"] for d in resource_details})
        result = PreCheckResult(
            "EXP-015",
            "FAIL",
            f"{bucket_count} S3 bucket policy statement(s) with public/cross-account principals and ineffective conditions",
            affected[:10],
        )
        result.metadata["resource_details"] = resource_details[:20]
        return result

    return PreCheckResult("EXP-015", "PASS", "no cross-account S3 policies", [])


@_register("exposure")
def check_exp_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda function URLs without authentication (AuthType=NONE)."""
    urls_doc = evidence.get("lambda-function-urls")
    items = _items_from_doc(urls_doc)
    if not items:
        return PreCheckResult("EXP-016", "SKIP", "no lambda-function-urls evidence", [])

    unauth = [
        u for u in items if isinstance(u, dict) and str(u.get("AuthType") or "").upper() == "NONE"
    ]
    if not unauth:
        return PreCheckResult("EXP-016", "PASS", "all Lambda URLs have authorization", [])

    resources = [str(u.get("FunctionArn") or u.get("FunctionUrl") or "unknown") for u in unauth[:5]]
    return PreCheckResult(
        "EXP-016",
        "FAIL",
        f"{len(unauth)} Lambda URL(s) without authorization",
        resources,
    )


@_register("exposure")
def check_exp_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 management/database ports (22, 3389, 3306, 5432) open to internet via SG."""
    ec2_doc = (
        evidence.get("ec2-instances") or evidence.get("instances") or evidence.get("ec2_instances")
    )
    instances = _items_from_doc(ec2_doc)
    if isinstance(ec2_doc, dict) and isinstance(ec2_doc.get("by_id"), dict):
        instances = list(ec2_doc["by_id"].values())
    if not instances:
        return PreCheckResult("EXP-004", "SKIP", "no EC2 instance evidence", [])

    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())
    if not sgs:
        return PreCheckResult("EXP-004", "SKIP", "no security-groups evidence", [])

    mgmt_ports = {22, 3389, 3306, 5432, 1433}

    sg_by_id = {str(sg.get("GroupId")): sg for sg in sgs if isinstance(sg, dict)}
    risky: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for inst in instances:
        if not isinstance(inst, dict):
            continue
        public_ip = inst.get("PublicIpAddress") or inst.get("PublicIp") or inst.get("public_ip")
        public_dns = inst.get("PublicDnsName") or inst.get("public_dns")
        if not public_ip and not public_dns:
            continue
        sg_refs = inst.get("SecurityGroups") or inst.get("security_groups") or []
        for sg_ref in sg_refs:
            if isinstance(sg_ref, dict):
                sg_id = str(sg_ref.get("GroupId") or sg_ref.get("group_id") or "")
            else:
                sg_id = str(sg_ref)
            sg = sg_by_id.get(sg_id)
            if not isinstance(sg, dict):
                continue
            for perm in sg.get("IngressRules", []) or []:
                if not isinstance(perm, dict):
                    continue
                for port in sorted(mgmt_ports):
                    if not _sg_allows_world(perm, port=port):
                        continue
                    instance_id = str(inst.get("InstanceId") or inst.get("id") or "unknown")
                    resource = f"{instance_id}:{sg_id}:{port}"
                    risky.append(resource)
                    resource_details.append(
                        {
                            "instance_id": instance_id,
                            "public_ip": public_ip,
                            "public_dns": public_dns,
                            "security_group_id": sg_id,
                            "security_group_name": sg.get("GroupName"),
                            "protocol": perm.get("IpProtocol", "tcp"),
                            "port": port,
                            "service": _port_service_name(port),
                            "sources": [
                                str(r.get("CidrIp"))
                                for r in (perm.get("IpRanges") or [])
                                if isinstance(r, dict) and r.get("CidrIp")
                            ]
                            + [
                                str(r.get("CidrIpv6"))
                                for r in (perm.get("Ipv6Ranges") or [])
                                if isinstance(r, dict) and r.get("CidrIpv6")
                            ],
                        }
                    )
                    break

    if not risky:
        return PreCheckResult("EXP-004", "PASS", "no management ports open to internet", [])
    result = PreCheckResult(
        "EXP-004",
        "FAIL",
        f"{len(resource_details)} EC2 management/DB exposure(s) open to internet",
        [d["instance_id"] for d in resource_details[:10]],
    )
    result.metadata["resource_details"] = resource_details[:20]
    return result


@_register("exposure")
def check_exp_020(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudFront S3 origins should enforce OAI/OAC-style origin access controls."""
    cf_doc = evidence.get("cloudfront-distributions")
    dists = _items_from_doc(cf_doc)
    if not dists:
        return PreCheckResult("EXP-020", "SKIP", "no cloudfront-distributions evidence", [])

    risky = []
    for d in dists:
        if not isinstance(d, dict) or not d.get("Enabled"):
            continue
        did = str(d.get("Id") or "unknown")
        origins_obj = d.get("Origins")
        origins: List[Any] = []
        if isinstance(origins_obj, dict):
            maybe_items = origins_obj.get("Items")
            if isinstance(maybe_items, list):
                origins = maybe_items
        elif isinstance(origins_obj, list):
            origins = origins_obj

        for o in origins:
            if not isinstance(o, dict):
                continue
            domain = str(o.get("DomainName") or "").lower()
            if not domain or ".s3." not in domain and not domain.endswith(".s3.amazonaws.com"):
                continue

            s3_cfg = o.get("S3OriginConfig") if isinstance(o.get("S3OriginConfig"), dict) else {}
            oai = str(s3_cfg.get("OriginAccessIdentity") or "")
            has_oai = bool(oai.strip())

            # With list_distributions evidence we don't always get full OAC details.
            # Treat missing OAI as risky signal requiring follow-up verification.
            if not has_oai:
                risky.append(f"arn:aws:cloudfront::distribution/{did}")
                break

    if not risky:
        return PreCheckResult("EXP-020", "PASS", "no risky CloudFront S3 origins detected", [])
    return PreCheckResult(
        "EXP-020",
        "FAIL",
        f"{len(risky)} CloudFront distributions with S3 origin lacking clear OAI/OAC signal",
        risky[:10],
    )


@_register("exposure")
def check_exp_021(evidence: Dict[str, Any]) -> PreCheckResult:
    """API routes with mutating methods should not be unauthenticated."""
    routes_doc = evidence.get("api-gateway-routes")
    routes = _items_from_doc(routes_doc)
    if not routes:
        return PreCheckResult("EXP-021", "SKIP", "no api-gateway-routes evidence", [])

    mutating = {"POST", "PUT", "PATCH", "DELETE", "ANY"}
    exposed = []
    for r in routes:
        if not isinstance(r, dict):
            continue
        method = str(r.get("Method") or "").upper()
        if method not in mutating:
            continue
        auth = str(r.get("AuthorizationType") or "NONE").upper()
        if auth in {"NONE", ""}:
            api_id = str(r.get("ApiId") or "unknown")
            path = str(r.get("Path") or "")
            exposed.append(f"arn:aws:execute-api:*:*:{api_id}/*/{method}{path}")

    if not exposed:
        return PreCheckResult("EXP-021", "PASS", "no unauthenticated mutating API routes", [])
    return PreCheckResult(
        "EXP-021",
        "FAIL",
        f"{len(exposed)} unauthenticated mutating API routes",
        exposed[:10],
    )


@_register("exposure")
def check_exp_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """Wildcard proxy routes (ANY/{proxy+}) should not be unauthenticated."""
    routes_doc = evidence.get("api-gateway-routes")
    routes = _items_from_doc(routes_doc)
    if not routes:
        return PreCheckResult("EXP-022", "SKIP", "no api-gateway-routes evidence", [])

    risky = []
    for r in routes:
        if not isinstance(r, dict):
            continue
        method = str(r.get("Method") or "").upper()
        path = str(r.get("Path") or "")
        auth = str(r.get("AuthorizationType") or "NONE").upper()
        is_proxy = method == "ANY" or "{proxy+}" in path
        if is_proxy and auth in {"NONE", ""}:
            api_id = str(r.get("ApiId") or "unknown")
            risky.append(f"arn:aws:execute-api:*:*:{api_id}/*/{method}{path}")

    if not risky:
        return PreCheckResult("EXP-022", "PASS", "no unauthenticated wildcard API routes", [])
    return PreCheckResult(
        "EXP-022",
        "FAIL",
        f"{len(risky)} unauthenticated wildcard API routes",
        risky[:10],
    )


@_register("exposure")
def check_exp_023(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-023: Resource-based policies with Principal:* without effective conditions.

    Detects SQS, SNS, Secrets Manager, ECR, and OpenSearch resources whose resource-based
    policies allow any AWS identity (Principal: * or Principal.AWS: *) without conditions
    that restrict access.

    Severity:
      - Critical: Principal:* without ANY Condition clause (completely unrestricted)
      - High: Principal:* WITH Condition (but condition may be ineffective)

    A Principal:* without conditions allows any AWS identity from any account to access
    the resource, which is analogous to a public S3 bucket.
    """
    rbp_doc = evidence.get("resource-based-policies") or {}
    items = rbp_doc.get("items") if isinstance(rbp_doc, dict) else None

    if not isinstance(items, list):
        return PreCheckResult("EXP-023", "SKIP", "no resource-based-policies evidence", [])

    if not items:
        return PreCheckResult(
            "EXP-023", "PASS", "no resource-based policies found across checked services", []
        )

    critical_resources = []  # Principal:* without Condition
    high_resources = []  # Principal:* with Condition
    detailed_findings = []

    # Service principals that should always have SourceArn/SourceAccount conditions.
    # Without these conditions, any resource of that service type in any account can invoke the resource.
    _require_source_conditions = {"s3.amazonaws.com", "sns.amazonaws.com", "events.amazonaws.com"}
    _source_conditions_rbp = {"aws:sourcearn", "aws:sourceaccount", "aws:sourcevpce"}

    for item in items:
        if not isinstance(item, dict):
            continue

        resource_arn = str(item.get("ResourceArn") or "unknown")
        service = str(item.get("Service") or "unknown")
        policy_analysis = item.get("PolicyAnalysis", {})

        # Use enriched policy analysis if available, otherwise parse Policy directly
        wildcard_stmts = policy_analysis.get("WildcardStatements", [])

        # If no PolicyAnalysis, fall back to parsing Policy directly (for backward compatibility with tests)
        if not wildcard_stmts:
            policy_raw = item.get("Policy") or ""
            # Conditions that restrict the open Principal:* to a meaningful scope
            _scope_conditions_rbp = {
                "aws:sourceaccount",
                "aws:sourcearn",
                "aws:principalorgid",
                "aws:sourceorgid",
                "aws:sourcevpc",
                "aws:sourcevpce",
                "aws:principalaccount",
                "aws:sourceowner",
            }

            try:
                policy_doc = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
                if isinstance(policy_doc, dict):
                    for stmt in _stmts_from_policy(policy_doc):
                        if not isinstance(stmt, dict):
                            continue
                        if str(stmt.get("Effect", "")).upper() != "ALLOW":
                            continue

                        principal = stmt.get("Principal")
                        # Detect open principal: "*" string or {"AWS": "*"}
                        is_open_principal = False
                        if principal == "*":
                            is_open_principal = True
                        elif isinstance(principal, dict):
                            aws_p = principal.get("AWS")
                            if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
                                is_open_principal = True

                        if not is_open_principal:
                            continue

                        # Check for scope-restricting conditions (PASS if found)
                        cond = stmt.get("Condition") or {}
                        cond_text = json.dumps(cond, default=str).lower()
                        has_scope_cond = any(k in cond_text for k in _scope_conditions_rbp)

                        if has_scope_cond:
                            # If there's a restrictive condition, skip it (it's OK)
                            continue

                        # No restrictive condition found - this is a FAIL
                        if resource_arn not in [r["resource"] for r in critical_resources]:
                            critical_resources.append(
                                {
                                    "resource": resource_arn,
                                    "statement": stmt.get("Sid", "Unnamed"),
                                }
                            )

                        # Build detailed finding
                        detailed_findings.append(
                            {
                                "ResourceArn": resource_arn,
                                "Service": service,
                                "Severity": "Critical",
                                "Principal": principal,
                                "Action": stmt.get("Action"),
                                "Condition": stmt.get("Condition"),
                                "HasCondition": bool(stmt.get("Condition")),
                                "ReplacementPolicy": _generate_replacement_policy(
                                    resource_arn, service, stmt
                                ),
                            }
                        )
                        break  # one violation per resource
            except Exception:
                continue
            continue  # skip to next item after fallback parsing

        for stmt in wildcard_stmts:
            if not isinstance(stmt, dict):
                continue

            # Skip if has mitigating condition (scope-restricting)
            has_mitigating_cond = stmt.get("HasMitigatingCondition", False)
            if has_mitigating_cond:
                continue  # This is acceptable, skip to next statement

            # No mitigating condition - this is a FAIL
            if resource_arn not in [r["resource"] for r in critical_resources]:
                critical_resources.append(
                    {
                        "resource": resource_arn,
                        "statement": stmt.get("Sid", "Unnamed"),
                    }
                )

            # Build detailed finding for snippet
            detailed_findings.append(
                {
                    "ResourceArn": resource_arn,
                    "Service": service,
                    "Severity": "Critical",
                    "Principal": stmt.get("Principal"),
                    "Action": stmt.get("Action"),
                    "Condition": stmt.get("Condition"),
                    "HasCondition": bool(stmt.get("Condition")),
                    "ReplacementPolicy": _generate_replacement_policy(resource_arn, service, stmt),
                }
            )
            break  # one violation per resource

        # Also check service principals (confused deputy) in all policy statements
        # (Not covered by wildcard_stmts which only handles Principal:*)
        all_policy_raw = item.get("Policy") or ""
        try:
            all_policy_doc = (
                json.loads(all_policy_raw) if isinstance(all_policy_raw, str) else all_policy_raw
            )
            if isinstance(all_policy_doc, dict):
                for stmt in _stmts_from_policy(all_policy_doc):
                    if not isinstance(stmt, dict):
                        continue
                    if str(stmt.get("Effect", "")).upper() != "ALLOW":
                        continue
                    principal = stmt.get("Principal", {})
                    svc_principal = None
                    if isinstance(principal, dict):
                        svc = principal.get("Service")
                        if isinstance(svc, str):
                            svc_principal = svc.lower()
                        elif isinstance(svc, list):
                            for s in svc:
                                if str(s).lower() in _require_source_conditions:
                                    svc_principal = str(s).lower()
                                    break
                    if svc_principal and svc_principal in _require_source_conditions:
                        cond = stmt.get("Condition") or {}
                        cond_text = json.dumps(cond, default=str).lower()
                        has_source_cond = any(k in cond_text for k in _source_conditions_rbp)
                        if (
                            not has_source_cond
                            and resource_arn not in [r["resource"] for r in high_resources]
                            and resource_arn not in [r["resource"] for r in critical_resources]
                        ):
                            high_resources.append(
                                {
                                    "resource": resource_arn,
                                    "statement": stmt.get("Sid", "Unnamed"),
                                    "note": f"service principal {svc_principal} without SourceArn/SourceAccount",
                                }
                            )
                            detailed_findings.append(
                                {
                                    "ResourceArn": resource_arn,
                                    "Service": service,
                                    "Severity": "High",
                                    "Principal": principal,
                                    "Action": stmt.get("Action"),
                                    "Condition": stmt.get("Condition"),
                                    "Note": f"Confused deputy risk: {svc_principal} has no SourceArn condition",
                                }
                            )
                            break
        except Exception:
            pass

    if not critical_resources and not high_resources:
        return PreCheckResult(
            "EXP-023",
            "PASS",
            "no resource-based policies with unrestricted Principal:* found",
            [],
        )

    # Affected resources list (critical first)
    affected_labels = [r["resource"] for r in critical_resources] + [
        r["resource"] for r in high_resources
    ]

    # Summary
    summary_parts = []
    if critical_resources:
        summary_parts.append(f"{len(critical_resources)} CRITICAL (no Condition)")
    if high_resources:
        summary_parts.append(f"{len(high_resources)} HIGH (with Condition)")
    summary = "Principal:* found: " + ", ".join(summary_parts)

    return PreCheckResult(
        "EXP-023",
        "FAIL",
        summary,
        affected_labels[:10],
        metadata={"detailed_findings": detailed_findings[:5]},
    )


def _generate_replacement_policy(
    resource_arn: str, service: str, statement: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate a suggested replacement policy statement restricting Principal:*.

    Returns a sample replacement policy that scopes access to a specific role/account.
    """
    actions = statement.get("Action", ["*"])
    if isinstance(actions, str):
        actions = [actions]

    # Suggest restricting to a service role
    suggested_principal = {"AWS": "arn:aws:iam::ACCOUNT_ID:role/SERVICE_ROLE"}  # Placeholder

    # Use the existing condition if present, otherwise suggest one
    suggested_condition = statement.get("Condition") or {
        "StringEquals": {"aws:PrincipalAccount": "ACCOUNT_ID"}
    }

    replacement_statement = {
        "Sid": statement.get("Sid", "RestrictedAccess"),
        "Effect": "Allow",
        "Principal": suggested_principal,
        "Action": actions,
        "Resource": "*",
        "Condition": suggested_condition,
    }

    return {
        "Statement": [replacement_statement],
        "Comment": "Replace the unrestricted Principal:* with a specific role/account and Condition",
    }


@_register("exposure")
def check_exp_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-024: S3 buckets used for audit/logging without KMS encryption.

    AWS enables AES256 (SSE-S3) by default on all S3 buckets since 2023, but KMS (SSE-KMS)
    provides additional controls: key rotation auditing, per-operation CloudTrail events,
    key revocation capability, and cross-account access control.

    This check flags audit/log/config buckets that use AES256 instead of KMS, as these
    often contain sensitive security data (CloudTrail logs, Config snapshots, VPC flow logs).
    Buckets with no encryption at all are flagged as FAIL regardless of purpose.
    """
    s3_doc = evidence.get("s3-buckets") or {}
    items = s3_doc.get("items") if isinstance(s3_doc, dict) else None

    if not isinstance(items, list) or not items:
        return PreCheckResult("EXP-024", "SKIP", "no s3-buckets evidence", [])

    # Heuristic: bucket names suggesting audit/logging/compliance data
    _audit_pattern = re.compile(
        r"(?i)(log|audit|cloudtrail|config|compliance|security|siem|flow|access[_\-]log)",
        re.IGNORECASE,
    )

    no_encryption: List[str] = []  # FAIL: no encryption at all
    aes256_audit: List[str] = []  # WARN: AES256 on audit bucket (should be KMS)
    resource_details: List[Dict[str, Any]] = []

    for bucket in items:
        if not isinstance(bucket, dict):
            continue
        name = str(bucket.get("Name") or "unknown")
        algorithm = bucket.get("EncryptionAlgorithm")  # None, "AES256", or "aws:kms"

        if algorithm is None:
            # No server-side encryption configured
            no_encryption.append(name)
            resource_details.append(
                {
                    "bucket_name": name,
                    "bucket_arn": f"arn:aws:s3:::{name}",
                    "encryption_algorithm": algorithm,
                    "kms_master_key_id": bucket.get("KMSMasterKeyID"),
                    "reason": "no_server_side_encryption",
                }
            )
        elif algorithm == "AES256":
            # AES256 is fine for most buckets, but audit buckets should use KMS
            if _audit_pattern.search(name):
                aes256_audit.append(name)
                resource_details.append(
                    {
                        "bucket_name": name,
                        "bucket_arn": f"arn:aws:s3:::{name}",
                        "encryption_algorithm": algorithm,
                        "kms_master_key_id": bucket.get("KMSMasterKeyID"),
                        "reason": "audit_log_bucket_without_customer_managed_kms",
                    }
                )
        # aws:kms → compliant, no action needed

    if not no_encryption and not aes256_audit:
        return PreCheckResult(
            "EXP-024",
            "PASS",
            "all S3 buckets have encryption; audit/log buckets use KMS",
            [],
        )

    affected = [f"arn:aws:s3:::{name}" for name in (no_encryption + aes256_audit)]
    parts = []
    if no_encryption:
        parts.append(f"{len(no_encryption)} bucket(s) with no encryption")
    if aes256_audit:
        parts.append(f"{len(aes256_audit)} audit/log bucket(s) using AES256 instead of KMS")
    status = "FAIL" if no_encryption else "FAIL"
    result = PreCheckResult("EXP-024", status, "; ".join(parts), affected[:10])
    result.metadata["resource_details"] = resource_details[:20]
    return result


@_register("exposure")
def check_exp_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-005: Lambda function URLs without authentication (AuthType=NONE)."""
    urls_doc = evidence.get("lambda-function-urls")
    urls = _items_from_doc(urls_doc)
    if urls_doc is None:
        return PreCheckResult("EXP-005", "SKIP", "no lambda-function-urls evidence", [])

    risky: List[str] = []
    for u in urls:
        if not isinstance(u, dict):
            continue
        auth = str(u.get("AuthType") or u.get("auth_type") or "").upper()
        if auth in {"NONE", ""}:
            fn = str(
                u.get("FunctionArn") or u.get("function_arn") or u.get("FunctionName", "unknown")
            )
            risky.append(fn)

    if not risky:
        return PreCheckResult(
            "EXP-005", "PASS", "no unauthenticated Lambda function URLs found", []
        )
    return PreCheckResult(
        "EXP-005",
        "FAIL",
        f"{len(risky)} Lambda function URL(s) without authentication (AuthType=NONE)",
        risky[:5],
    )


@_register("exposure")
def check_exp_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-006: API Gateway routes without authentication or rate limiting."""
    routes_doc = evidence.get("api-gateway-routes")
    routes = _items_from_doc(routes_doc)
    if not routes:
        return PreCheckResult("EXP-006", "SKIP", "no api-gateway-routes evidence", [])

    _non_data_methods = {"OPTIONS", "HEAD"}
    risky: List[str] = []
    for r in routes:
        if not isinstance(r, dict):
            continue
        method = str(r.get("Method") or "").upper()
        if method in _non_data_methods:
            continue  # skip preflight/head-only routes
        auth = str(r.get("AuthorizationType") or "").upper()
        if auth in {"NONE", ""}:
            api_id = str(r.get("ApiId") or "unknown")
            path = str(r.get("Path") or "")
            key = f"{api_id}/{method}{path}"
            if key not in risky:
                risky.append(key)

    if not risky:
        return PreCheckResult(
            "EXP-006", "PASS", "all API Gateway data routes have authentication", []
        )
    return PreCheckResult(
        "EXP-006",
        "FAIL",
        f"{len(risky)} API Gateway route(s) without authentication",
        risky[:10],
    )


def _sg_allows_world(perm: Dict[str, Any], *, port: int) -> bool:
    """Check if a security group permission allows traffic from 0.0.0.0/0 or ::/0 on given port."""
    proto = perm.get("IpProtocol")
    from_p = perm.get("FromPort")
    to_p = perm.get("ToPort")

    port_match = False
    if proto == "-1":
        port_match = True
    elif proto == "tcp" and isinstance(from_p, int) and isinstance(to_p, int):
        port_match = from_p <= port <= to_p

    if not port_match:
        return False

    for r in perm.get("IpRanges", []) or []:
        if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
            return True
    for r in perm.get("Ipv6Ranges", []) or []:
        if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
            return True
    return False


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
