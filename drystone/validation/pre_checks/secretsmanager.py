# ruff: noqa
"""Secretsmanager deterministic pre-checks."""

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


# SECRETS MANAGER PRE-CHECKS
# ============================================================================


@_register("secretsmanager")
def check_sm_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public wildcard resource policy on secrets."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        policy = s.get("ResourcePolicy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict):
                continue
            principal = st.get("Principal", {})
            if _principal_is_wildcard(principal):
                return PreCheckResult(
                    "SM-001",
                    "FAIL",
                    "secret has Principal:*",
                    [s.get("ARN", s.get("Name", "unknown"))],
                )

    return PreCheckResult("SM-001", "PASS", "no wildcard principals in secrets", [])


@_register("secretsmanager")
def check_sm_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Rotation interval > 90 days."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        if not s.get("RotationEnabled"):
            continue
        rules = s.get("RotationRules")
        if not isinstance(rules, dict):
            continue
        try:
            days = rules.get("AutomaticallyAfterDays")
            if days is not None and int(days) > 90:
                return PreCheckResult(
                    "SM-003",
                    "FAIL",
                    f"rotation interval={days} days (>90)",
                    [s.get("ARN", s.get("Name", "unknown"))],
                )
        except (ValueError, TypeError):
            continue

    return PreCheckResult("SM-003", "PASS", "no secrets with rotation >90 days", [])


@_register("secretsmanager")
def check_sm_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets resource policy grants external account access."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        secret_arn = str(s.get("ARN") or "")
        secret_account = _account_from_arn(secret_arn)
        if not secret_account:
            continue
        policy = s.get("ResourcePolicy")
        if not isinstance(policy, dict):
            continue

        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            continue

        for st in stmts:
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            principal = st.get("Principal")
            aws_p = None
            if isinstance(principal, dict):
                aws_p = principal.get("AWS")
            principals = (
                [aws_p] if isinstance(aws_p, str) else aws_p if isinstance(aws_p, list) else []
            )
            for p in principals:
                ps = str(p)
                if ps.startswith("arn:aws:iam::"):
                    p_account = _account_from_arn(ps)
                    if p_account and p_account != secret_account:
                        return PreCheckResult(
                            "SM-013",
                            "FAIL",
                            f"secret policy allows external account {p_account}",
                            [secret_arn or s.get("Name", "unknown")],
                        )

    return PreCheckResult(
        "SM-013", "PASS", "no external account principals in resource policies", []
    )


@_register("secretsmanager")
def check_sm_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """Rotation enabled but Lambda rotation config missing/inconsistent."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        if not bool(s.get("RotationEnabled")):
            continue
        lambda_arn = str(s.get("RotationLambdaARN") or "").strip()
        if not lambda_arn:
            return PreCheckResult(
                "SM-014",
                "FAIL",
                "rotation enabled without RotationLambdaARN",
                [s.get("ARN", s.get("Name", "unknown"))],
            )
        if not lambda_arn.startswith("arn:aws:lambda:"):
            return PreCheckResult(
                "SM-014",
                "FAIL",
                "rotation lambda ARN is malformed",
                [s.get("ARN", s.get("Name", "unknown"))],
            )

    return PreCheckResult("SM-014", "PASS", "rotation lambda configuration appears consistent", [])


@_register("secretsmanager")
def check_sm_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets encrypted with KMS keys from different account."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        secret_arn = str(s.get("ARN") or "")
        secret_account = _account_from_arn(secret_arn)
        kms_key = str(s.get("KmsKeyId") or "")
        if not secret_account or not kms_key.startswith("arn:aws:kms:"):
            continue
        kms_account = _account_from_arn(kms_key)
        if kms_account and kms_account != secret_account:
            return PreCheckResult(
                "SM-015",
                "FAIL",
                f"secret uses cross-account KMS key ({kms_account})",
                [secret_arn or s.get("Name", "unknown")],
            )

    return PreCheckResult("SM-015", "PASS", "no cross-account KMS key usage in secrets", [])


@_register("secretsmanager")
def check_sm_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """Replication + permissive/external resource policy increases backdoor risk."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        rep = s.get("ReplicationStatus")
        if not isinstance(rep, list) or not rep:
            continue

        secret_arn = str(s.get("ARN") or "")
        secret_account = _account_from_arn(secret_arn)
        policy = s.get("ResourcePolicy")
        if not isinstance(policy, dict):
            continue

        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            continue

        for st in stmts:
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if _principal_is_wildcard(st.get("Principal")):
                return PreCheckResult(
                    "SM-017",
                    "FAIL",
                    "replicated secret has wildcard resource policy",
                    [secret_arn or s.get("Name", "unknown")],
                )

            principal = st.get("Principal")
            aws_p = principal.get("AWS") if isinstance(principal, dict) else None
            principals = (
                [aws_p] if isinstance(aws_p, str) else aws_p if isinstance(aws_p, list) else []
            )
            for p in principals:
                ps = str(p)
                if ps.startswith("arn:aws:iam::"):
                    p_account = _account_from_arn(ps)
                    if p_account and secret_account and p_account != secret_account:
                        return PreCheckResult(
                            "SM-017",
                            "FAIL",
                            f"replicated secret policy allows external account {p_account}",
                            [secret_arn or s.get("Name", "unknown")],
                        )

    return PreCheckResult(
        "SM-017", "PASS", "no risky replication + permissive policy combination", []
    )


@_register("secretsmanager")
def check_sm_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Automatic rotation disabled on secrets."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-002", "SKIP", "no secrets data available", [])

    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and not s.get("RotationEnabled")
    ]
    if not failed:
        return PreCheckResult("SM-002", "PASS", "all secrets have rotation enabled", [])
    return PreCheckResult(
        "SM-002",
        "FAIL",
        f"{len(failed)} secret(s) have automatic rotation disabled",
        failed,
    )


@_register("secretsmanager")
def check_sm_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets using AWS-managed KMS key instead of customer-managed key."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-004", "SKIP", "no secrets data available", [])

    # AWS-managed key indicators (explicit patterns + missing KmsKeyId = AWS default)
    _aws_kms_patterns = ("alias/aws/secretsmanager", "aws/secretsmanager", "Default AWS managed")

    failed = []
    for s in secrets_list:
        if not isinstance(s, dict):
            continue
        kms_key = str(s.get("KmsKeyId") or "").strip()
        if not kms_key or any(p in kms_key for p in _aws_kms_patterns):
            failed.append(s.get("ARN", s.get("Name", "unknown")))

    if not failed:
        return PreCheckResult("SM-004", "PASS", "all secrets use customer-managed KMS keys", [])
    return PreCheckResult(
        "SM-004",
        "FAIL",
        f"{len(failed)} secret(s) use AWS-managed KMS key or missing KMS config",
        failed,
    )


@_register("secretsmanager")
def check_sm_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets never rotated OR not changed in >365 days (stale credentials)."""
    from datetime import datetime, timezone

    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-005", "SKIP", "no secrets data available", [])

    now = datetime.now(tz=timezone.utc)
    never_rotated = []
    stale = []

    for s in secrets_list:
        if not isinstance(s, dict):
            continue
        arn = s.get("ARN", s.get("Name", "unknown"))

        # Case 1: LastRotatedDate is empty/null = never rotated
        # Only flag if the secret is also >90 days old (gives time to set up rotation)
        last_rotated = str(s.get("LastRotatedDate") or "").strip()
        rotation_enabled = bool(s.get("RotationEnabled"))
        if not last_rotated and not rotation_enabled:
            raw_created = s.get("CreatedDate") or s.get("LastChangedDate")
            secret_age_days = 0
            if raw_created:
                try:
                    dt_str = str(raw_created).replace(" ", "T")
                    if "+" in dt_str[10:] or dt_str.endswith("Z"):
                        dt_created = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                    else:
                        dt_created = datetime.fromisoformat(dt_str).replace(tzinfo=timezone.utc)
                    secret_age_days = (now - dt_created).days
                except (ValueError, TypeError):
                    pass
            if secret_age_days > 90:
                never_rotated.append(arn)
            continue

        # Case 2: LastChangedDate > 365 days ago
        raw = s.get("LastChangedDate") or s.get("CreatedDate")
        if not raw:
            continue
        try:
            dt_str = str(raw).replace(" ", "T")
            if "+" in dt_str[10:] or dt_str.endswith("Z"):
                dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(dt_str).replace(tzinfo=timezone.utc)
            if (now - dt).days > 365:
                stale.append(arn)
        except (ValueError, TypeError):
            continue

    failed = never_rotated + stale
    if not failed:
        return PreCheckResult("SM-005", "PASS", "no stale or never-rotated secrets", [])

    parts = []
    if never_rotated:
        parts.append(f"{len(never_rotated)} never rotated")
    if stale:
        parts.append(f"{len(stale)} unchanged >365 days")
    return PreCheckResult(
        "SM-005",
        "FAIL",
        f"stale credentials detected: {', '.join(parts)}",
        failed,
    )


@_register("secretsmanager")
def check_sm_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets missing required governance tags (Owner, DataClassification)."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-006", "SKIP", "no secrets data available", [])

    _required = {"Owner", "DataClassification"}
    failed = []
    for s in secrets_list:
        if not isinstance(s, dict):
            continue
        existing = {t["Key"] for t in (s.get("Tags") or []) if isinstance(t, dict) and "Key" in t}
        if _required - existing:
            failed.append(s.get("ARN", s.get("Name", "unknown")))

    if not failed:
        return PreCheckResult("SM-006", "PASS", "all secrets have required governance tags", [])
    return PreCheckResult(
        "SM-006",
        "FAIL",
        f"{len(failed)} secret(s) missing Owner or DataClassification tag",
        failed,
    )


@_register("secretsmanager")
def check_sm_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets without description (governance / discoverability)."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-007", "SKIP", "no secrets data available", [])

    _empty = {"", "no description", "none", "n/a"}
    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and str(s.get("Description") or "").strip().lower() in _empty
    ]
    if not failed:
        return PreCheckResult("SM-007", "PASS", "all secrets have descriptions", [])
    return PreCheckResult(
        "SM-007",
        "FAIL",
        f"{len(failed)} secret(s) have no description",
        failed,
    )


@_register("secretsmanager")
def check_sm_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Production secrets without cross-region replication."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-008", "SKIP", "no secrets data available", [])

    failed = []
    for s in secrets_list:
        if not isinstance(s, dict):
            continue
        # Only flag production secrets
        tags = {t.get("Key"): t.get("Value") for t in (s.get("Tags") or []) if isinstance(t, dict)}
        env = str(tags.get("Environment") or tags.get("env") or "").lower()
        if env not in ("prod", "production", ""):
            continue
        rep = s.get("ReplicationStatus")
        if isinstance(rep, list) and not rep:
            failed.append(s.get("ARN", s.get("Name", "unknown")))

    if not failed:
        return PreCheckResult(
            "SM-008", "PASS", "secrets have cross-region replication or are non-prod", []
        )
    return PreCheckResult(
        "SM-008",
        "FAIL",
        f"{len(failed)} production secret(s) not replicated to any secondary region",
        failed,
    )


@_register("secretsmanager")
def check_sm_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets resource policies missing MFA condition (empty policy = no MFA)."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-011", "SKIP", "no secrets data available", [])

    def _policy_has_mfa(policy: Any) -> bool:
        if not isinstance(policy, dict) or not policy:
            return False
        for st in policy.get("Statement", []) or []:
            cond = st.get("Condition", {}) if isinstance(st, dict) else {}
            for _op, kv in cond.items() if isinstance(cond, dict) else []:
                if isinstance(kv, dict) and "aws:MultiFactorAuthPresent" in kv:
                    return True
        return False

    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and not _policy_has_mfa(s.get("ResourcePolicy"))
    ]
    if not failed:
        return PreCheckResult("SM-011", "PASS", "all secret resource policies require MFA", [])
    return PreCheckResult(
        "SM-011",
        "FAIL",
        f"{len(failed)} secret(s) lack MFA condition in resource policy",
        failed,
    )


@_register("secretsmanager")
def check_sm_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """No rotation failure alerting configured (CloudWatch + EventBridge)."""
    secrets_doc = evidence.get("secrets")
    if isinstance(secrets_doc, dict):
        secrets_list = secrets_doc.get("secrets")
        if isinstance(secrets_list, list) and not secrets_list:
            return PreCheckResult(
                "SM-012",
                "SKIP",
                "no Secrets Manager secrets found; rotation failure alerting is not applicable",
                [],
            )

    cw = evidence.get("cloudwatch_alarms", {})
    eb = evidence.get("eventbridge_rules", {})

    cw_relevant = sum(
        int(r.get("likely_relevant_count", 0))
        for r in (cw.get("regions", {}) or {}).values()
        if isinstance(r, dict)
    )
    eb_relevant = sum(
        int(r.get("relevant_rule_count", 0))
        for r in (eb.get("regions", {}) or {}).values()
        if isinstance(r, dict)
    )

    if cw_relevant == 0 and eb_relevant == 0:
        # Only FAIL if we have evidence data (not just missing files)
        if not cw and not eb:
            return PreCheckResult("SM-012", "SKIP", "alerting evidence files not collected", [])
        return PreCheckResult(
            "SM-012",
            "FAIL",
            "no CloudWatch alarms or EventBridge rules monitor Secrets Manager rotation failures",
            [],
            metadata={
                "evidence_refs": [
                    "cloudwatch_alarms.json#/regions",
                    "eventbridge_rules.json#/regions",
                ]
            },
        )
    return PreCheckResult(
        "SM-012",
        "PASS",
        f"rotation monitoring found: {cw_relevant} CW alarm(s), {eb_relevant} EventBridge rule(s)",
        [],
    )


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
