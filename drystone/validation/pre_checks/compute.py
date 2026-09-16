# ruff: noqa
"""Compute deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# COMPUTE PRE-CHECKS
# ============================================================================


@_register("compute")
def check_comp_eks_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """EKS public endpoint access."""
    eks_doc = evidence.get("eks-inventory")
    clusters = eks_doc.get("clusters") if isinstance(eks_doc, dict) else None
    if not isinstance(clusters, list) or not clusters:
        return PreCheckResult("COMP-EKS-001", "SKIP", "no eks-inventory evidence", [])

    for c in clusters:
        if not isinstance(c, dict):
            continue
        vpc_cfg = c.get("resourcesVpcConfig")
        if isinstance(vpc_cfg, dict) and vpc_cfg.get("endpointPublicAccess") is True:
            return PreCheckResult(
                "COMP-EKS-001",
                "FAIL",
                f"cluster {c.get('name')} has public endpoint",
                [c.get("arn", c.get("name", "unknown"))],
            )

    return PreCheckResult("COMP-EKS-001", "PASS", "no EKS clusters with public endpoint", [])


@_register("compute")
def check_comp_eks_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """EKS control plane logging should be fully enabled."""
    eks_doc = evidence.get("eks-inventory")
    clusters = eks_doc.get("clusters") if isinstance(eks_doc, dict) else None
    if not isinstance(clusters, list) or not clusters:
        return PreCheckResult("COMP-EKS-002", "SKIP", "no eks-inventory evidence", [])

    required = {"api", "audit", "authenticator", "controllerManager", "scheduler"}

    for c in clusters:
        if not isinstance(c, dict):
            continue
        logging_cfg = c.get("logging")
        if not isinstance(logging_cfg, dict):
            return PreCheckResult(
                "COMP-EKS-002",
                "FAIL",
                f"cluster {c.get('name')} has no logging config",
                [c.get("arn", c.get("name", "unknown"))],
            )
        cl = logging_cfg.get("clusterLogging")
        if not isinstance(cl, list):
            return PreCheckResult(
                "COMP-EKS-002",
                "FAIL",
                "missing clusterLogging",
                [c.get("arn", c.get("name", "unknown"))],
            )
        enabled_types = set()
        for entry in cl:
            if isinstance(entry, dict) and entry.get("enabled") is True:
                types = entry.get("types")
                if isinstance(types, list):
                    enabled_types.update(t for t in types if isinstance(t, str))
        if not required.issubset(enabled_types):
            missing = required - enabled_types
            return PreCheckResult(
                "COMP-EKS-002",
                "FAIL",
                f"cluster {c.get('name')} missing log types: {missing}",
                [c.get("arn", c.get("name", "unknown"))],
            )

    return PreCheckResult("COMP-EKS-002", "PASS", "all EKS clusters have full logging", [])


@_register("compute")
def check_comp_ecs_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Scheduled EventBridge rules targeting ECS RunTask."""
    ev_doc = evidence.get("eventbridge-rules")
    rules = ev_doc.get("rules") if isinstance(ev_doc, dict) else None
    if not isinstance(rules, list) or not rules:
        return PreCheckResult("COMP-ECS-001", "SKIP", "no eventbridge-rules evidence", [])

    for r in rules:
        if not isinstance(r, dict) or not r.get("ScheduleExpression"):
            continue
        targets = r.get("Targets")
        if not isinstance(targets, list):
            continue
        for t in targets:
            if not isinstance(t, dict):
                continue
            if t.get("EcsParameters"):
                return PreCheckResult(
                    "COMP-ECS-001",
                    "FAIL",
                    "scheduled ECS RunTask rule found",
                    [r.get("Arn", r.get("Name", "unknown"))],
                )
            arn = str(t.get("Arn") or "")
            if ":ecs:" in arn:
                return PreCheckResult(
                    "COMP-ECS-001",
                    "FAIL",
                    "scheduled ECS target found",
                    [r.get("Arn", r.get("Name", "unknown"))],
                )

    return PreCheckResult("COMP-ECS-001", "PASS", "no scheduled ECS rules", [])


@_register("compute")
def check_comp_ecs_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS task definitions with suspicious image patterns."""
    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-002", "SKIP", "no ecs-inventory evidence", [])

    def _suspicious(img: str) -> bool:
        img_l = img.lower()
        if "@sha256:" in img_l:
            return False
        if img_l.endswith(":latest") or ":latest" in img_l:
            return True
        for reg in ("docker.io/", "ghcr.io/", "quay.io/"):
            if reg in img_l:
                return True
        return False

    affected_arns: List[str] = []
    affected_images: List[str] = []
    for td in tdefs:
        if not isinstance(td, dict):
            continue
        cds = td.get("containerDefinitions")
        if not isinstance(cds, list):
            continue
        arn = td.get("taskDefinitionArn", "unknown")
        for cd in cds:
            if (
                isinstance(cd, dict)
                and isinstance(cd.get("image"), str)
                and _suspicious(cd["image"])
            ):
                if arn not in affected_arns:
                    affected_arns.append(arn)
                if cd["image"] not in affected_images:
                    affected_images.append(cd["image"])
                break  # one hit per task definition is enough

    if not affected_arns:
        return PreCheckResult("COMP-ECS-002", "PASS", "no suspicious container images", [])

    images_str = ", ".join(affected_images[:5])
    return PreCheckResult(
        "COMP-ECS-002",
        "FAIL",
        f"{len(affected_arns)} task definition(s) with suspicious images: {images_str}",
        affected_arns[:10],
    )


@_register("compute")
def check_comp_ecs_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS workloads should have centralized logging (awslogs)."""
    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-003", "SKIP", "no ecs-inventory evidence", [])

    for td in tdefs:
        if not isinstance(td, dict):
            continue
        cds = td.get("containerDefinitions")
        if not isinstance(cds, list):
            continue
        for cd in cds:
            if not isinstance(cd, dict):
                continue
            log_cfg = cd.get("logConfiguration")
            if not isinstance(log_cfg, dict):
                return PreCheckResult(
                    "COMP-ECS-003",
                    "FAIL",
                    "container missing logConfiguration",
                    [td.get("taskDefinitionArn", "unknown")],
                )
            if str(log_cfg.get("logDriver") or "").lower() != "awslogs":
                return PreCheckResult(
                    "COMP-ECS-003",
                    "FAIL",
                    f"container has logDriver={log_cfg.get('logDriver')} (not awslogs)",
                    [td.get("taskDefinitionArn", "unknown")],
                )

    return PreCheckResult("COMP-ECS-003", "PASS", "all containers have awslogs", [])


@_register("compute")
def check_comp_ecs_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS task definitions without a scoped task role (no taskRoleArn)."""
    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-004", "SKIP", "no ecs-inventory evidence", [])

    affected: List[str] = []
    seen: set = set()
    for td in tdefs:
        if not isinstance(td, dict):
            continue
        arn = td.get("taskDefinitionArn", "unknown")
        if arn in seen:
            continue
        seen.add(arn)
        if not td.get("taskRoleArn"):
            affected.append(arn)

    if not affected:
        return PreCheckResult(
            "COMP-ECS-004", "PASS", "all task definitions have a scoped task role", []
        )
    return PreCheckResult(
        "COMP-ECS-004",
        "FAIL",
        f"{len(affected)} task definition(s) without taskRoleArn (no scoped task identity)",
        affected[:10],
    )


@_register("compute")
def check_comp_ecs_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS task definitions must not embed plaintext credentials in environment variables."""
    import re as _re

    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-005", "SKIP", "no ecs-inventory evidence", [])

    _secret_keywords = _re.compile(
        r"(pass(word)?|secret|api[_\-]?key|token|credential|private[_\-]?key|auth)",
        _re.IGNORECASE,
    )

    affected: List[str] = []
    seen: set = set()
    for td in tdefs:
        if not isinstance(td, dict):
            continue
        arn = td.get("taskDefinitionArn", "unknown")
        if arn in seen:
            continue
        cds = td.get("containerDefinitions")
        if not isinstance(cds, list):
            continue
        for cd in cds:
            if not isinstance(cd, dict):
                continue
            env_vars = cd.get("environment")
            if not isinstance(env_vars, list):
                continue
            for env in env_vars:
                if not isinstance(env, dict):
                    continue
                name = str(env.get("name") or "")
                value = str(env.get("value") or "")
                if _secret_keywords.search(name) and len(value) > 4:
                    affected.append(arn)
                    seen.add(arn)
                    break  # one hit per task definition is enough

    if not affected:
        return PreCheckResult(
            "COMP-ECS-005", "PASS", "no plaintext credentials detected in env vars", []
        )
    return PreCheckResult(
        "COMP-ECS-005",
        "FAIL",
        f"{len(affected)} task definition(s) with suspected plaintext credentials in env vars",
        affected[:10],
    )


@_register("compute")
def check_comp_ec2_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 instances with IMDSv1/optional tokens and instance profile attached."""
    ec2_doc = evidence.get("ec2-inventory")
    instances = ec2_doc.get("instances") if isinstance(ec2_doc, dict) else None
    if not isinstance(instances, list) or not instances:
        return PreCheckResult("COMP-EC2-001", "SKIP", "no ec2-inventory evidence", [])

    affected = []
    for it in instances:
        if not isinstance(it, dict):
            continue
        profile = it.get("IamInstanceProfile")
        if not isinstance(profile, dict) or not profile:
            continue
        md = it.get("MetadataOptions")
        md = md if isinstance(md, dict) else {}
        if str(md.get("HttpTokens") or "optional").lower() != "required":
            iid = str(it.get("InstanceId") or "unknown")
            affected.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not affected:
        return PreCheckResult("COMP-EC2-001", "PASS", "no IMDSv1+instance-profile combinations", [])
    return PreCheckResult(
        "COMP-EC2-001",
        "FAIL",
        f"{len(affected)} instances with IMDSv1/optional tokens and instance profile",
        affected[:10],
    )


@_register("compute")
def check_comp_ec2_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 user-data contains secrets or remote bootstrap risk patterns."""
    ec2_doc = evidence.get("ec2-inventory")
    instances = ec2_doc.get("instances") if isinstance(ec2_doc, dict) else None
    if not isinstance(instances, list) or not instances:
        return PreCheckResult("COMP-EC2-002", "SKIP", "no ec2-inventory evidence", [])

    affected = []
    for it in instances:
        if not isinstance(it, dict):
            continue
        contains = it.get("ContainsSecrets")
        has_secrets = isinstance(contains, dict) and any(bool(v) for v in contains.values())
        has_remote = bool(it.get("HasRemoteBootstrap"))
        if has_secrets or has_remote:
            iid = str(it.get("InstanceId") or "unknown")
            affected.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not affected:
        return PreCheckResult("COMP-EC2-002", "PASS", "no risky user-data patterns", [])
    return PreCheckResult(
        "COMP-EC2-002",
        "FAIL",
        f"{len(affected)} instances with risky user-data patterns",
        affected[:10],
    )


@_register("compute")
def check_comp_lmb_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda function URLs should not be unauthenticated."""
    lmb_doc = evidence.get("lambda-inventory")
    funcs = lmb_doc.get("functions") if isinstance(lmb_doc, dict) else None
    if not isinstance(funcs, list) or not funcs:
        return PreCheckResult("COMP-LMB-001", "SKIP", "no lambda-inventory evidence", [])

    exposed = []
    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        if str(fn.get("AuthType") or "").upper() == "NONE" and fn.get("FunctionUrl"):
            exposed.append(str(fn.get("FunctionArn") or fn.get("FunctionName") or "unknown"))

    if not exposed:
        return PreCheckResult("COMP-LMB-001", "PASS", "no unauthenticated Lambda function URLs", [])
    return PreCheckResult(
        "COMP-LMB-001",
        "FAIL",
        f"{len(exposed)} Lambda functions with AuthType=NONE",
        exposed[:10],
    )


@_register("compute")
def check_comp_lmb_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda execution roles should avoid obviously over-privileged managed policies."""
    lmb_doc = evidence.get("lambda-inventory")
    funcs = lmb_doc.get("functions") if isinstance(lmb_doc, dict) else None
    if not isinstance(funcs, list) or not funcs:
        return PreCheckResult("COMP-LMB-002", "SKIP", "no lambda-inventory evidence", [])

    risky_tokens = ["administratoraccess", "admin", "poweruser", "fullaccess"]
    affected = []
    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        attached = fn.get("AttachedPolicies")
        if not isinstance(attached, list):
            continue
        for p in attached:
            if not isinstance(p, dict):
                continue
            name = str(p.get("PolicyName") or "").lower()
            if any(tok in name for tok in risky_tokens):
                affected.append(str(fn.get("FunctionArn") or fn.get("FunctionName") or "unknown"))
                break

    if not affected:
        return PreCheckResult(
            "COMP-LMB-002", "PASS", "no over-privileged Lambda execution roles", []
        )
    return PreCheckResult(
        "COMP-LMB-002",
        "FAIL",
        f"{len(affected)} Lambda functions with over-privileged execution roles",
        affected[:10],
    )


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
