"""Exposure (EXP-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, indexed_ref_for


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id in {
        "EXP-002",
        "EXP-004",
        "EXP-007",
        "EXP-013",
        "EXP-014",
        "EXP-015",
        "EXP-024",
    }:
        resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
        if resource_details:
            refs: List[str] = []
            if check_id == "EXP-002":
                for detail in resource_details:
                    db_id = str(detail.get("db_instance_identifier") or "")
                    ref = indexed_ref_for(
                        evidence,
                        "rds-instances",
                        lambda item, db_id=db_id: str(item.get("DBInstanceIdentifier") or "")
                        == db_id,
                    )
                    if ref:
                        refs.append(ref)
                refs.extend(_sg_refs_from_details(evidence, resource_details))
            elif check_id == "EXP-004":
                for detail in resource_details:
                    instance_id = str(detail.get("instance_id") or "")
                    for key in ("ec2-instances", "instances", "ec2_instances"):
                        ref = indexed_ref_for(
                            evidence,
                            key,
                            lambda item, instance_id=instance_id: str(
                                item.get("InstanceId") or item.get("id") or ""
                            )
                            == instance_id,
                        )
                        if ref:
                            refs.append(ref)
                            break
                refs.extend(_sg_refs_from_details(evidence, resource_details))
            elif check_id == "EXP-007":
                for detail in resource_details:
                    lb_arn = str(detail.get("load_balancer_arn") or "")
                    ref = indexed_ref_for(
                        evidence,
                        "load-balancers",
                        lambda item, lb_arn=lb_arn: str(item.get("LoadBalancerArn") or "")
                        == lb_arn,
                    )
                    if ref:
                        refs.append(ref)
                    refs.append("wafv2-web-acl-alb-associations.json#by_alb_arn")
            elif check_id in {"EXP-013", "EXP-014", "EXP-015", "EXP-024"}:
                refs.extend(_s3_refs(evidence, resource_details))

            summaries = {
                "EXP-002": f"{len(resource_details)} public RDS instance(s) with internet-open DB ports",
                "EXP-004": f"{len(resource_details)} EC2 management/DB exposure(s) open to the internet",
                "EXP-007": f"{len(resource_details)} internet-facing ALB(s) without WAF",
                "EXP-013": f"{len(resource_details)} S3 bucket(s) without SecureTransport deny",
                "EXP-014": f"{len(resource_details)} S3 bucket(s) without versioning",
                "EXP-015": f"{len(resource_details)} S3 policy statement(s) with ineffective public/cross-account conditions",
                "EXP-024": f"{len(resource_details)} audit/log S3 bucket(s) without customer-managed KMS",
            }
            return (
                dedupe_refs(refs)[:30],
                {
                    "evidence_summary": summaries[check_id],
                    "affected_resources": resource_details,
                },
            )

    if check_id == "EXP-003":
        resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
        if resource_details:
            return (
                ["security-groups.json"],
                {
                    "evidence_summary": f"{len(resource_details)} SG(s) with SSH/RDP open to 0.0.0.0/0 or ::/0",
                    "affected_resources": resource_details,
                },
            )

    return None


def _s3_refs(evidence: Dict[str, Any], details: List[Dict[str, Any]]) -> List[str]:
    refs: List[str] = []
    for detail in details:
        if not isinstance(detail, dict):
            continue
        bucket = str(detail.get("bucket_name") or "")
        if not bucket:
            arn = str(detail.get("bucket_arn") or "")
            bucket = arn.rsplit(":::", 1)[-1] if ":::" in arn else ""
        if not bucket:
            continue
        ref = indexed_ref_for(
            evidence,
            "s3-buckets",
            lambda item, bucket=bucket: str(item.get("Name") or "") == bucket,
        )
        if ref:
            refs.append(ref)
    return refs


def _sg_refs_from_details(evidence: Dict[str, Any], details: List[Dict[str, Any]]) -> List[str]:
    refs: List[str] = []
    for detail in details:
        if not isinstance(detail, dict):
            continue
        sg_ids = []
        if detail.get("security_group_id"):
            sg_ids.append(str(detail.get("security_group_id")))
        for rule in detail.get("open_rules") or []:
            if isinstance(rule, dict) and rule.get("security_group_id"):
                sg_ids.append(str(rule.get("security_group_id")))
        for sg_id in sg_ids:
            ref = indexed_ref_for(
                evidence,
                "security-groups",
                lambda item, sg_id=sg_id: str(item.get("GroupId") or "") == sg_id,
            )
            if ref:
                refs.append(ref)
    return refs
