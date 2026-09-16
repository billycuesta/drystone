# ruff: noqa
"""Ecr deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *
from .alerting import _principal_is_wildcard

logger = logging.getLogger(__name__)


# ECR PRE-CHECKS
# ============================================================================


@_register("ecr")
def check_ecr_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public wildcard principals in ECR repository policies."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []

    for r in repos_list if isinstance(repos_list, list) else []:
        if not isinstance(r, dict):
            continue
        policy = r.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            if _principal_is_wildcard(st.get("Principal")):
                return PreCheckResult(
                    "ECR-001",
                    "FAIL",
                    "repo has Principal:*",
                    [r.get("RepositoryArn", r.get("repositoryName", "unknown"))],
                )

    return PreCheckResult("ECR-001", "PASS", "no wildcard principals in ECR", [])


@_register("ecr")
def check_ecr_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Image tags should be immutable."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []
    if not isinstance(repos_list, list) or not repos_list:
        return PreCheckResult("ECR-002", "SKIP", "no repositories evidence", [])

    mutable = []
    for r in repos_list:
        if not isinstance(r, dict):
            continue
        if str(r.get("ImageTagMutability") or "").upper() == "MUTABLE":
            mutable.append(str(r.get("RepositoryArn") or r.get("RepositoryName") or "unknown"))

    if mutable:
        return PreCheckResult(
            "ECR-002", "FAIL", f"{len(mutable)} repositories with mutable tags", mutable[:10]
        )
    return PreCheckResult("ECR-002", "PASS", "all repositories use immutable tags", [])


@_register("ecr")
def check_ecr_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Repositories should use KMS customer-managed keys when required."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []
    if not isinstance(repos_list, list) or not repos_list:
        return PreCheckResult("ECR-005", "SKIP", "no repositories evidence", [])

    non_cmk = []
    for r in repos_list:
        if not isinstance(r, dict):
            continue
        enc = str(r.get("EncryptionType") or "").upper()
        kms_key = str(r.get("KmsKey") or "")
        if enc != "KMS" or not kms_key:
            non_cmk.append(str(r.get("RepositoryArn") or r.get("RepositoryName") or "unknown"))

    if non_cmk:
        return PreCheckResult(
            "ECR-005", "FAIL", f"{len(non_cmk)} repositories without CMK encryption", non_cmk[:10]
        )
    return PreCheckResult("ECR-005", "PASS", "all repositories use KMS customer-managed keys", [])


@_register("ecr")
def check_ecr_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lifecycle policies should be configured to expire unused images."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []
    if not isinstance(repos_list, list) or not repos_list:
        return PreCheckResult("ECR-006", "SKIP", "no repositories evidence", [])

    missing = []
    for r in repos_list:
        if not isinstance(r, dict):
            continue
        has_policy = r.get("HasLifecyclePolicy")
        lifecycle = r.get("LifecyclePolicy")
        if has_policy is False or not lifecycle:
            missing.append(str(r.get("RepositoryArn") or r.get("RepositoryName") or "unknown"))

    if missing:
        return PreCheckResult(
            "ECR-006", "FAIL", f"{len(missing)} repositories without lifecycle policy", missing[:10]
        )
    return PreCheckResult("ECR-006", "PASS", "all repositories have lifecycle policies", [])


@_register("ecr")
def check_ecr_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Image scanning on push."""
    # If registry has ENHANCED scanning, this may be covered at registry level
    reg_doc = evidence.get("registry")
    if isinstance(reg_doc, dict):
        reg_scanning = reg_doc.get("registry_scanning")
        if isinstance(reg_scanning, dict):
            scan_cfg = reg_scanning.get("scanningConfiguration")
            if isinstance(scan_cfg, dict) and scan_cfg.get("scanType") == "ENHANCED":
                return PreCheckResult("ECR-003", "PASS", "ENHANCED scanning at registry level", [])

    return PreCheckResult("ECR-003", "SKIP", "requires AI analysis of per-repo scanning", [])


@_register("ecr")
def check_ecr_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Registry scanning configuration should be defined."""
    reg_doc = evidence.get("registry")
    if not isinstance(reg_doc, dict):
        return PreCheckResult("ECR-004", "SKIP", "no registry evidence", [])

    reg_scanning = reg_doc.get("registry_scanning")
    if isinstance(reg_scanning, dict) and reg_scanning.get("error"):
        return PreCheckResult(
            "ECR-004", "SKIP", f"scanning collection error: {reg_scanning.get('error')}", []
        )

    if isinstance(reg_scanning, dict) and reg_scanning.get("scanningConfiguration"):
        return PreCheckResult("ECR-004", "PASS", "registry scanning configured", [])

    return PreCheckResult("ECR-004", "FAIL", "no registry scanning configuration", [])


@_register("ecr")
def check_ecr_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Cross-account repository access review."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []

    # Determine current account
    current_account = None
    reg_doc = evidence.get("registry")
    if isinstance(reg_doc, dict):
        reg = reg_doc.get("registry")
        if isinstance(reg, dict) and reg.get("registryId"):
            current_account = str(reg["registryId"])

    if not current_account:
        for r in repos_list if isinstance(repos_list, list) else []:
            if isinstance(r, dict) and r.get("RepositoryArn"):
                parts = str(r["RepositoryArn"]).split(":")
                if len(parts) > 4:
                    current_account = parts[4]
                    break

    for r in repos_list if isinstance(repos_list, list) else []:
        if not isinstance(r, dict):
            continue
        policy = r.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if _principal_is_wildcard(principal):
                return PreCheckResult(
                    "ECR-007",
                    "FAIL",
                    "wildcard principal implies cross-account",
                    [r.get("RepositoryArn", "unknown")],
                )
            if isinstance(principal, dict) and "AWS" in principal:
                aws_p = principal["AWS"]
                aws_list = (
                    [aws_p]
                    if isinstance(aws_p, str)
                    else (aws_p if isinstance(aws_p, list) else [])
                )
                for p in aws_list:
                    if not isinstance(p, str):
                        continue
                    if p.isdigit() and current_account and p != current_account:
                        return PreCheckResult(
                            "ECR-007",
                            "FAIL",
                            f"cross-account principal: {p}",
                            [r.get("RepositoryArn", "unknown")],
                        )
                    if p.startswith("arn:aws:iam::"):
                        acct = p.split(":")[4] if len(p.split(":")) > 4 else ""
                        if acct and current_account and acct != current_account:
                            return PreCheckResult(
                                "ECR-007",
                                "FAIL",
                                f"cross-account ARN: {p}",
                                [r.get("RepositoryArn", "unknown")],
                            )

    return PreCheckResult("ECR-007", "PASS", "no cross-account ECR access", [])


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
