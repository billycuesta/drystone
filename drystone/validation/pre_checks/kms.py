# ruff: noqa
"""Kms deterministic pre-checks."""

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


# KMS PRE-CHECKS
# ============================================================================


def _kms_id_to_arn(evidence: Dict[str, Any]) -> Dict[str, str]:
    """Build a KeyId → KeyArn map from kms-keys evidence for use in pre-checks."""
    keys_doc = evidence.get("kms-keys")
    items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
    if not isinstance(items, list):
        return {}
    result: Dict[str, str] = {}
    for k in items:
        if not isinstance(k, dict):
            continue
        key_id = str(k.get("KeyId") or (k.get("Metadata") or {}).get("KeyId") or "")
        key_arn = str(k.get("KeyArn") or (k.get("Metadata") or {}).get("Arn") or "")
        if key_id and key_arn:
            result[key_id] = key_arn
    return result


def _kms_stmt_has_binding_conditions(stmt: Dict[str, Any]) -> bool:
    """Return True if the policy statement has conditions that restrict access to:
    - The same AWS account (kms:CallerAccount), AND
    - A specific AWS service (kms:ViaService or StringLike kms:ViaService).
    Together these constitute an unambiguous binding restriction equivalent to an
    account-scoped service principal — NOT a public wildcard exposure.
    """
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return False
    # Flatten all condition operators to a merged key→value map for inspection
    merged: Dict[str, Any] = {}
    for op_val in cond.values():
        if isinstance(op_val, dict):
            merged.update({k.lower(): v for k, v in op_val.items()})
    has_caller_account = "kms:calleraccount" in merged
    has_via_service = "kms:viaservice" in merged
    return has_caller_account and has_via_service


@_register("kms")
def check_kms_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Key policy with wildcard/broad principals not constrained to same account + service."""
    pol_doc = evidence.get("kms-key-policies")
    items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-001", "SKIP", "no kms-key-policies evidence", [])

    arn_map = _kms_id_to_arn(evidence)
    flagged_arns: List[str] = []

    for rec in items:
        if not isinstance(rec, dict):
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if not _principal_is_wildcard(st.get("Principal")):
                continue
            # Standard AWS service-integrated CMK pattern:
            # Principal=* WITH kms:CallerAccount + kms:ViaService is NOT a wildcard risk.
            # It restricts access to the same account and a specific service (e.g. Secrets Manager).
            if _kms_stmt_has_binding_conditions(st):
                continue
            key_id = rec.get("KeyId", "unknown")
            key_arn = arn_map.get(key_id, rec.get("KeyArn", key_id))
            if key_arn not in flagged_arns:
                flagged_arns.append(key_arn)
            break  # one match per key is enough

    if flagged_arns:
        count = len(flagged_arns)
        return PreCheckResult(
            "KMS-001",
            "FAIL",
            f"{count} key(s) with wildcard principal without account+service binding conditions",
            flagged_arns[:10],
        )

    return PreCheckResult("KMS-001", "PASS", "no unbound wildcard principals in key policies", [])


@_register("kms")
def check_kms_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Unexpected grants with Decrypt/GenerateDataKey operations.

    Ignore expected service-managed grants (RDS/Lambda/etc.) when they have
    encryption-context constraints and service principals.
    """
    grants_doc = evidence.get("kms-grants")
    items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-002", "SKIP", "no kms-grants evidence", [])

    def _is_sensitive(ops: List[Any]) -> bool:
        ops_norm = {str(o) for o in ops if o is not None}
        return "Decrypt" in ops_norm or any(o.startswith("GenerateDataKey") for o in ops_norm)

    def _has_context_constraints(grant: Dict[str, Any]) -> bool:
        cons = grant.get("Constraints")
        if not isinstance(cons, dict):
            return False
        return bool(cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset"))

    def _is_service_managed_principal(grant: Dict[str, Any]) -> bool:
        grantee = str(grant.get("GranteePrincipal") or "")
        issuing = str(grant.get("IssuingAccount") or "")
        if grantee.endswith(".amazonaws.com"):
            return True
        if ":assumed-role/" in grantee and "arn:aws:sts::" in grantee:
            return True
        if issuing.endswith(".amazonaws.com"):
            return True
        return False

    flagged_keys: list = []
    resource_details: list = []
    now = datetime.now(tz=timezone.utc)

    for g in items:
        if not isinstance(g, dict):
            continue
        ops = g.get("Operations")
        if not isinstance(ops, list):
            continue

        if not _is_sensitive(ops):
            continue

        # Expected service grants with tight encryption-context constraints are noisy.
        if _is_service_managed_principal(g) and _has_context_constraints(g):
            continue

        key_id = str(g.get("KeyId") or "unknown")
        grant_id = str(g.get("GrantId") or "unknown")
        creation_date = g.get("CreationDate")
        days_active: Optional[int] = None
        if creation_date:
            dt = _parse_date(creation_date)
            if dt:
                days_active = (now - dt).days

        if key_id not in flagged_keys:
            flagged_keys.append(key_id)
        resource_details.append(
            {
                "key_id": key_id,
                "grant_id": grant_id,
                "grantee": str(g.get("GranteePrincipal") or ""),
                "operations": list(ops),
                "has_constraints": _has_context_constraints(g),
                "days_active": days_active,
            }
        )

    if not flagged_keys:
        return PreCheckResult("KMS-002", "PASS", "no sensitive grants", [])
    result = PreCheckResult(
        "KMS-002",
        "FAIL",
        f"{len(resource_details)} unexpected sensitive grant(s) on {len(flagged_keys)} key(s)",
        flagged_keys[:10],
    )
    result.metadata["resource_details"] = resource_details[:15]
    return result


@_register("kms")
def check_kms_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Policy allows admin modification (PutKeyPolicy/CreateGrant)."""
    pol_doc = evidence.get("kms-key-policies")
    items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-003", "SKIP", "no kms-key-policies evidence", [])

    arn_map = _kms_id_to_arn(evidence)
    flagged_arns: List[str] = []

    for rec in items:
        if not isinstance(rec, dict):
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        key_id = rec.get("KeyId", "unknown")
        key_arn = arn_map.get(key_id, rec.get("KeyArn", key_id))
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            for act in _actions_from_stmt(st):
                if act.lower() in {"kms:putkeypolicy", "kms:creategrant", "kms:*"}:
                    if key_arn not in flagged_arns:
                        flagged_arns.append(key_arn)
                    break  # one match per key is enough

    if flagged_arns:
        return PreCheckResult(
            "KMS-003",
            "FAIL",
            f"{len(flagged_arns)} key(s) allow admin modification (PutKeyPolicy/CreateGrant/kms:*)",
            flagged_arns[:10],
        )
    return PreCheckResult("KMS-003", "PASS", "no admin modification permissions", [])


@_register("kms")
def check_kms_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Customer-managed key rotation should be enabled."""
    keys_doc = evidence.get("kms-keys")
    items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-004", "SKIP", "no kms-keys evidence", [])

    for k in items:
        if not isinstance(k, dict):
            continue
        meta = k.get("Metadata")
        if isinstance(meta, dict) and str(meta.get("KeyManager") or "").upper() != "CUSTOMER":
            continue
        rot = k.get("KeyRotationEnabled")
        if rot is False or rot in {"false", "False", 0, "0"}:
            key_id = k.get("KeyId", (meta or {}).get("KeyId", "unknown"))
            return PreCheckResult(
                "KMS-004", "FAIL", f"key {key_id} rotation disabled", [k.get("KeyArn", key_id)]
            )

    return PreCheckResult("KMS-004", "PASS", "all customer keys have rotation enabled", [])


@_register("kms")
def check_kms_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Policies allowing destructive KMS actions to non-root, non-standard principals."""
    pol_doc = evidence.get("kms-key-policies")
    items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-005", "SKIP", "no kms-key-policies evidence", [])

    destructive = {
        "kms:disablekey",
        "kms:schedulekeydeletion",
        "kms:deleteimportedkeymaterial",
        "kms:deletealias",
        "kms:updatealias",
        "kms:*",
    }

    arn_map = _kms_id_to_arn(evidence)

    for rec in items:
        if not isinstance(rec, dict):
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue

            # Skip the AWS-required "Enable IAM User Permissions" root statement.
            # kms:* granted to the account root (arn:aws:iam::<account>:root) is the
            # standard, mandatory delegation pattern recommended by AWS KMS documentation.
            # It does NOT grant direct access to any entity — it only enables IAM policies.
            principal = st.get("Principal")
            if isinstance(principal, dict):
                aws_p = principal.get("AWS", "")
                if isinstance(aws_p, str) and aws_p.endswith(":root"):
                    continue
                if isinstance(aws_p, list) and all(
                    isinstance(p, str) and p.endswith(":root") for p in aws_p
                ):
                    continue

            for act in _actions_from_stmt(st):
                if str(act).lower() in destructive:
                    key_id = rec.get("KeyId", "unknown")
                    key_arn = arn_map.get(key_id, rec.get("KeyArn", key_id))
                    return PreCheckResult(
                        "KMS-005",
                        "FAIL",
                        f"key {key_id} allows destructive action {act} to non-root principal",
                        [key_arn],
                    )

    return PreCheckResult(
        "KMS-005", "PASS", "no destructive key actions to non-root principals", []
    )


@_register("kms")
def check_kms_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Imported key material can be deleted if policy allows it."""
    keys_doc = evidence.get("kms-keys")
    key_items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
    pol_doc = evidence.get("kms-key-policies")
    pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else None

    if not isinstance(key_items, list) or not key_items:
        return PreCheckResult("KMS-006", "SKIP", "no kms-keys evidence", [])
    if not isinstance(pol_items, list) or not pol_items:
        return PreCheckResult("KMS-006", "SKIP", "no kms-key-policies evidence", [])

    external_ids = set()
    for k in key_items:
        if not isinstance(k, dict):
            continue
        meta = k.get("Metadata") if isinstance(k.get("Metadata"), dict) else {}
        if str(meta.get("Origin") or "").upper() == "EXTERNAL":
            key_id = str(meta.get("KeyId") or k.get("KeyId") or "")
            if key_id:
                external_ids.add(key_id)

    if not external_ids:
        return PreCheckResult("KMS-006", "PASS", "no EXTERNAL origin keys found", [])

    for rec in pol_items:
        if not isinstance(rec, dict):
            continue
        key_id = str(rec.get("KeyId") or "")
        if key_id not in external_ids:
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            for act in _actions_from_stmt(st):
                if str(act).lower() in {"kms:deleteimportedkeymaterial", "kms:*"}:
                    return PreCheckResult(
                        "KMS-006",
                        "FAIL",
                        f"EXTERNAL key {key_id} policy allows {act}",
                        [rec.get("KeyArn", key_id)],
                    )

    return PreCheckResult("KMS-006", "PASS", "no delete-imported-key-material risk found", [])


@_register("kms")
def check_kms_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Grants that delegate CreateGrant can allow persistence."""
    grants_doc = evidence.get("kms-grants")
    items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-007", "SKIP", "no kms-grants evidence", [])

    flagged_keys: List[str] = []
    flagged_grants: List[str] = []

    for g in items:
        if not isinstance(g, dict):
            continue
        ops = g.get("Operations")
        if not isinstance(ops, list):
            continue
        if "CreateGrant" not in {str(o) for o in ops if o is not None}:
            continue

        cons = g.get("Constraints")
        has_ctx = isinstance(cons, dict) and bool(
            cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset")
        )
        if has_ctx:
            # constrained service grant - lower risk/noisy
            continue

        key_id = str(g.get("KeyId") or "unknown")
        grant_id = str(g.get("GrantId") or "unknown")
        if key_id not in flagged_keys:
            flagged_keys.append(key_id)
        flagged_grants.append(grant_id[:12])  # abbreviated for readability

    if flagged_keys:
        count = len(flagged_keys)
        return PreCheckResult(
            "KMS-007",
            "FAIL",
            f"{count} key(s) with grants that delegate CreateGrant without encryption context constraints",
            flagged_keys[:10],
        )

    return PreCheckResult("KMS-007", "PASS", "no unconstrained CreateGrant delegation", [])


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
