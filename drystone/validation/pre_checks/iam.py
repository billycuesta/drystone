# ruff: noqa
"""Iam deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# IAM PRE-CHECKS
# ============================================================================


@_register("iam")
def check_iam_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Root account MFA enabled?"""
    summary_map = _get_summary_map(evidence)
    mfa = summary_map.get("AccountMFAEnabled")

    if _truthy(mfa):
        return PreCheckResult("IAM-001", "PASS", f"AccountMFAEnabled={mfa}", [])

    # Fallback: credential report
    by_user = _get_credential_report_by_user(evidence)
    for key in ("<root_account>", "root", "<root>"):
        root = by_user.get(key, {})
        if isinstance(root, dict) and _truthy(root.get("mfa_active")):
            return PreCheckResult("IAM-001", "PASS", "credential-report.mfa_active=true", [])

    return PreCheckResult("IAM-001", "FAIL", f"AccountMFAEnabled={mfa}", ["arn:aws:iam::*:root"])


@_register("iam")
def check_iam_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-002: IAM users with console access must have MFA enabled."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-002", "SKIP", "no users evidence", [])

    cred = evidence.get("credential-report", {})
    by_user: Dict[str, Any] = cred.get("by_user", {}) if isinstance(cred, dict) else {}

    affected: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("UserName") or "")
        row = by_user.get(uname, {})

        has_console = str(row.get("password_enabled", "false")).lower() == "true"
        # Users with active access keys also require MFA under PCI DSS 8.4.2
        has_active_keys = bool(u.get("AccessKeys"))
        if not has_console and not has_active_keys:
            continue

        has_mfa = bool(u.get("MFADevices"))
        if not has_mfa:
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)
            resource_details.append(
                {
                    "user": uname,
                    "arn": arn,
                    "password_enabled": has_console,
                    "has_console_access": has_console,
                    "has_active_access_keys": has_active_keys,
                    "mfa_devices": len(u.get("MFADevices") or []),
                    "permission_context": _user_permission_context(evidence, u),
                }
            )

    if affected:
        result = PreCheckResult(
            "IAM-002",
            "FAIL",
            f"{len(affected)} user(s) without MFA (console or active access keys)",
            affected,
        )
        result.metadata["resource_details"] = resource_details[:10]
        return result
    return PreCheckResult(
        "IAM-002", "PASS", "all users with console or active access keys have MFA enabled", []
    )


@_register("iam")
def check_iam_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-010: Administrative users must have MFA enabled."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-010", "SKIP", "no users evidence", [])

    _admin_policy_names = {"AdministratorAccess", "PowerUserAccess"}

    affected: List[str] = []
    for u in users:
        if not isinstance(u, dict):
            continue

        # Check if user has admin-level attached policy
        attached = u.get("AttachedPolicies") or []
        if not isinstance(attached, list):
            continue
        policy_names = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        is_admin = bool(policy_names & _admin_policy_names)
        if not is_admin:
            continue

        has_mfa = bool(u.get("MFADevices"))
        if not has_mfa:
            uname = str(u.get("UserName") or "")
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)

    if affected:
        return PreCheckResult(
            "IAM-010", "FAIL", f"{len(affected)} admin user(s) without MFA", affected
        )
    return PreCheckResult("IAM-010", "PASS", "all admin users have MFA enabled", [])


@_register("iam")
def check_iam_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Access keys should be rotated every 90 days."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-004", "SKIP", "no users evidence", [])

    now = datetime.now(timezone.utc)
    old_users = []
    resource_details = []
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("UserName") or "unknown")
        arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
        for k in u.get("AccessKeys", []) or []:
            if not isinstance(k, dict):
                continue
            if str(k.get("Status") or "").lower() != "active":
                continue
            cd = k.get("CreateDate")
            if not isinstance(cd, str) or not cd:
                continue
            try:
                created = datetime.fromisoformat(cd.replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            key_age_days = (now - created).days
            if key_age_days > 90:
                old_users.append(arn)
                last_used = k.get("LastUsed") if isinstance(k.get("LastUsed"), dict) else {}
                resource_details.append(
                    {
                        "user": uname,
                        "arn": arn,
                        "access_key_id": _mask_key_id(str(k.get("AccessKeyId") or "")),
                        "key_age_days": key_age_days,
                        "create_date": cd,
                        "last_used_date": last_used.get("LastUsedDate"),
                        "last_used_service": last_used.get("ServiceName"),
                        "last_used_region": last_used.get("Region"),
                        "permission_context": _user_permission_context(evidence, u),
                    }
                )
                break

    if not old_users:
        return PreCheckResult("IAM-004", "PASS", "no active keys >90 days", [])
    result = PreCheckResult("IAM-004", "FAIL", f"{len(old_users)} users with old keys", old_users)
    result.metadata["resource_details"] = resource_details[:10]
    return result


@_register("iam")
def check_iam_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """No policy should have full administrative permissions (*:*)."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-008", "SKIP", "no policies evidence", [])

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = [a.lower() for a in _actions_from_stmt(st)]
            if "*" not in acts and "iam:*" not in acts:
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            if not res_list or any(r == "*" for r in res_list):
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-008",
                    "FAIL",
                    f"Policy '{pname}' has Action:*/Resource:*",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-008", "PASS", "no wildcard admin policies", [])


@_register("iam")
def check_iam_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """Root account should not have active access keys."""
    summary_map = _get_summary_map(evidence)
    keys_present = summary_map.get("AccountAccessKeysPresent")

    if _falsy(keys_present):
        return PreCheckResult("IAM-009", "PASS", f"AccountAccessKeysPresent={keys_present}", [])

    # Fallback: credential report
    by_user = _get_credential_report_by_user(evidence)
    for key in ("<root_account>", "root", "<root>"):
        root = by_user.get(key, {})
        if isinstance(root, dict):
            k1 = root.get("access_key_1_active")
            k2 = root.get("access_key_2_active")
            if _falsy(k1) and _falsy(k2):
                return PreCheckResult(
                    "IAM-009", "PASS", "root keys inactive (credential-report)", []
                )

    return PreCheckResult(
        "IAM-009", "FAIL", f"AccountAccessKeysPresent={keys_present}", ["arn:aws:iam::*:root"]
    )


@_register("iam")
def check_iam_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Role trust policies should not allow public access (*)."""
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-011", "SKIP", "no roles evidence", [])

    for r in roles:
        if not isinstance(r, dict):
            continue
        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue
        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if _principal_is_wildcard_any(st.get("Principal")):
                rname = r.get("RoleName", "unknown")
                return PreCheckResult(
                    "IAM-011",
                    "FAIL",
                    f"Role '{rname}' trust has Principal:*",
                    [r.get("Arn", f"role/{rname}")],
                )

    return PreCheckResult("IAM-011", "PASS", "no public trust policies", [])


@_register("iam")
def check_iam_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """Inactive users (>90 days no activity) should be reviewed.

    Note: Root account inactivity is expected and excluded.
    """
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-012", "SKIP", "no users evidence", [])

    inactive = []
    resource_details = []
    now = datetime.now(timezone.utc)
    threshold_days = 90
    by_user = _get_credential_report_by_user(evidence)

    for u in users:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("UserName") or "")
        # Skip root
        if uname in ("<root_account>", "root"):
            continue
        arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
        if isinstance(arn, str) and arn.endswith(":root"):
            continue

        row = by_user.get(uname, {}) if by_user else {}

        # Credential report is the source of truth for last activity when present.
        pwd_last_used = row.get("password_last_used") if isinstance(row, dict) else None
        if not _credential_value_is_date(pwd_last_used):
            pwd_last_used = u.get("PasswordLastUsed")

        key_last_candidates: List[Any] = []
        if isinstance(row, dict):
            for field_name in ("access_key_1_last_used_date", "access_key_2_last_used_date"):
                val = row.get(field_name)
                if _credential_value_is_date(val):
                    key_last_candidates.append(val)
        for k in u.get("AccessKeys") or []:
            if not isinstance(k, dict):
                continue
            lu = (k.get("LastUsed") or {}).get("LastUsedDate")
            if _credential_value_is_date(lu):
                key_last_candidates.append(lu)

        key_last_used_raw = None
        for candidate in key_last_candidates:
            candidate_dt = _parse_date(candidate)
            current_dt = _parse_date(key_last_used_raw)
            if candidate_dt and (current_dt is None or candidate_dt > current_dt):
                key_last_used_raw = candidate

        last_console_dt = _parse_date(pwd_last_used)
        last_key_dt = _parse_date(key_last_used_raw)
        last_activity_dt = max(filter(None, [last_console_dt, last_key_dt]), default=None)
        days_inactive = int((now - last_activity_dt).days) if last_activity_dt else 999

        if days_inactive >= threshold_days:
            user_arn = arn
            inactive.append(user_arn)
            resource_details.append(
                {
                    "user": uname,
                    "arn": user_arn,
                    "last_console_login": str(pwd_last_used) if pwd_last_used else "N/A",
                    "last_access_key_use": str(key_last_used_raw) if key_last_used_raw else "N/A",
                    "days_since_last_activity": days_inactive,
                }
            )

    if not inactive:
        return PreCheckResult("IAM-012", "PASS", "no inactive non-root users (>90 days)", [])
    result = PreCheckResult(
        "IAM-012", "FAIL", f"{len(inactive)} inactive users (>90 days)", inactive[:10]
    )
    result.metadata["resource_details"] = resource_details[:10]
    return result


@_register("iam")
def check_iam_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """Users should not have multiple active access keys."""
    users = evidence.get("users")
    if not isinstance(users, list):
        # Try credential report fallback (no rich metadata available here)
        by_user = _get_credential_report_by_user(evidence)
        if not by_user:
            return PreCheckResult("IAM-014", "SKIP", "no users/credential-report evidence", [])

        for uname, row in by_user.items():
            if not isinstance(row, dict):
                continue
            if _truthy(row.get("access_key_1_active")) and _truthy(row.get("access_key_2_active")):
                return PreCheckResult(
                    "IAM-014",
                    "FAIL",
                    f"User '{uname}' has 2 active keys",
                    [f"arn:aws:iam::*:user/{uname}"],
                    metadata={
                        "resource_details": [
                            {
                                "user": uname,
                                "arn": f"arn:aws:iam::*:user/{uname}",
                                "rotation_status": "unknown",
                            }
                        ]
                    },
                )
        return PreCheckResult("IAM-014", "PASS", "no users with multiple active keys", [])

    multi = []
    resource_details = []
    now = datetime.now(timezone.utc)

    for u in users:
        if not isinstance(u, dict):
            continue
        keys = u.get("AccessKeys")
        if not isinstance(keys, list):
            continue
        active = [
            k
            for k in keys
            if isinstance(k, dict) and str(k.get("Status") or "").lower() == "active"
        ]
        if len(active) >= 2:
            uname = u.get("UserName", "unknown")
            user_arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            multi.append(user_arn)

            key_details = []
            for k in active:
                lu_raw = (k.get("LastUsed") or {}).get("LastUsedDate")
                create_raw = k.get("CreateDate")
                lu_dt = _parse_date(lu_raw)
                days_last_use = int((now - lu_dt).days) if lu_dt else None
                key_details.append(
                    {
                        "access_key_id": _mask_key_id(k.get("AccessKeyId", "")),
                        "status": k.get("Status"),
                        "create_date": str(create_raw) if create_raw else "N/A",
                        "last_used_date": str(lu_raw) if lu_raw else "N/A",
                        "days_since_last_use": days_last_use,
                    }
                )
            resource_details.append(
                {
                    "user": uname,
                    "arn": user_arn,
                    "active_access_keys": key_details,
                    "rotation_status": "unknown",
                }
            )

    if not multi:
        return PreCheckResult("IAM-014", "PASS", "no users with multiple active keys", [])
    result = PreCheckResult(
        "IAM-014", "FAIL", f"{len(multi)} users with 2+ active keys", multi[:10]
    )
    result.metadata["resource_details"] = resource_details[:10]
    return result


@_register("iam")
def check_iam_020(evidence: Dict[str, Any]) -> PreCheckResult:
    """Users should belong to at least one group."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-020", "SKIP", "no users evidence", [])

    ungrouped = []
    for u in users:
        if not isinstance(u, dict):
            continue
        groups = u.get("Groups")
        if isinstance(groups, list) and len(groups) == 0:
            # Use the full ARN from evidence if available (avoids * wildcard in account ID)
            arn = str(u.get("Arn") or "")
            if not arn:
                uname = u.get("UserName", "unknown")
                arn = f"arn:aws:iam::*:user/{uname}"
            ungrouped.append(arn)

    if not ungrouped:
        return PreCheckResult("IAM-020", "PASS", "all users belong to groups", [])
    return PreCheckResult(
        "IAM-020", "FAIL", f"{len(ungrouped)} users without groups", ungrouped[:10]
    )


@_register("iam")
def check_iam_029(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-029: Detect privilege escalation via cross-role AssumeRole chains.

    Flags roles that can be assumed by another IAM role (not a service) AND
    have AdministratorAccess or iam:* permissions attached — the classic
    'hop-to-admin' privilege escalation path.
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-029", "SKIP", "no roles evidence", [])

    _admin_policies = {"AdministratorAccess", "PowerUserAccess"}

    # Build a map: role ARN → attached policy names
    role_policies: Dict[str, set] = {}
    for r in roles:
        if not isinstance(r, dict):
            continue
        arn = str(r.get("Arn") or "")
        attached = r.get("AttachedPolicies") or []
        pnames = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        role_policies[arn] = pnames

    affected: List[str] = []
    for r in roles:
        if not isinstance(r, dict):
            continue
        role_arn = str(r.get("Arn") or "")

        # Does this role have admin-level policies?
        if not (role_policies.get(role_arn, set()) & _admin_policies):
            continue

        # Is it trusted by another IAM role (not an AWS service)?
        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue

        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            principal = st.get("Principal")
            aws_p = principal.get("AWS") if isinstance(principal, dict) else None
            principal_list = [aws_p] if isinstance(aws_p, str) else (aws_p or [])
            if not isinstance(principal_list, list):
                continue

            for p in principal_list:
                ps = str(p)
                # Flag if trusted by an IAM role (privilege escalation hop)
                if ":role/" in ps and not ps.endswith(".amazonaws.com"):
                    if role_arn not in affected:
                        affected.append(role_arn)
                    break

    if affected:
        return PreCheckResult(
            "IAM-029",
            "FAIL",
            f"{len(affected)} admin role(s) trusted by other IAM role(s) — escalation path",
            affected,
        )
    return PreCheckResult("IAM-029", "PASS", "no privilege escalation via role chain detected", [])


@_register("iam")
def check_iam_032(evidence: Dict[str, Any]) -> PreCheckResult:
    """OIDC trust policies for GitHub Actions should be tightly scoped."""
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-032", "SKIP", "no roles evidence", [])

    def _has_web_identity_action(stmt: Dict[str, Any]) -> bool:
        actions = [str(a).lower() for a in _actions_from_stmt(stmt)]
        return any(a in {"sts:assumerolewithwebidentity", "sts:*", "*"} for a in actions)

    def _collect_condition_values(condition: Any, key: str) -> List[str]:
        if not isinstance(condition, dict):
            return []
        out: List[str] = []
        for _, block in condition.items():
            if not isinstance(block, dict):
                continue
            val = block.get(key)
            if isinstance(val, str):
                out.append(val)
            elif isinstance(val, list):
                out.extend([str(x) for x in val if x is not None])
        return out

    for r in roles:
        if not isinstance(r, dict):
            continue
        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue
        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if not _has_web_identity_action(st):
                continue

            principal = st.get("Principal")
            federated = principal.get("Federated") if isinstance(principal, dict) else None
            fed_list = [federated] if isinstance(federated, str) else federated
            if not isinstance(fed_list, list):
                continue

            if not any(
                isinstance(x, str) and "token.actions.githubusercontent.com" in x for x in fed_list
            ):
                continue

            condition = st.get("Condition")
            aud_values = _collect_condition_values(
                condition, "token.actions.githubusercontent.com:aud"
            )
            sub_values = _collect_condition_values(
                condition, "token.actions.githubusercontent.com:sub"
            )

            has_aud = any(v == "sts.amazonaws.com" for v in aud_values)
            if not has_aud:
                return PreCheckResult(
                    "IAM-032",
                    "FAIL",
                    "GitHub OIDC trust missing strict aud=sts.amazonaws.com",
                    [r.get("Arn", f"role/{r.get('RoleName', 'unknown')}")],
                )

            if not sub_values:
                return PreCheckResult(
                    "IAM-032",
                    "FAIL",
                    "GitHub OIDC trust missing sub condition",
                    [r.get("Arn", f"role/{r.get('RoleName', 'unknown')}")],
                )

            if any("*" in str(v) for v in sub_values):
                return PreCheckResult(
                    "IAM-032",
                    "FAIL",
                    "GitHub OIDC trust has wildcard sub condition",
                    [r.get("Arn", f"role/{r.get('RoleName', 'unknown')}")],
                )

    return PreCheckResult("IAM-032", "PASS", "OIDC trust conditions appear scoped", [])


# Roles whose cross-account trust without ExternalId is by design
# (AWS-managed or AWS Organizations roles that use management-account trust).
_IAM_033_ROLE_EXCEPTIONS = frozenset(
    {
        "OrganizationAccountAccessRole",
        "AWSServiceRoleForOrganizations",
    }
)


@_register("iam")
def check_iam_033(evidence: Dict[str, Any]) -> PreCheckResult:
    """Cross-account role trust should require sts:ExternalId."""
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-033", "SKIP", "no roles evidence", [])

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    def _stmt_has_assume_role(stmt: Dict[str, Any]) -> bool:
        actions = [str(a).lower() for a in _actions_from_stmt(stmt)]
        return any(a in {"sts:assumerole", "sts:*", "*"} for a in actions)

    affected: List[str] = []

    for r in roles:
        if not isinstance(r, dict):
            continue
        role_name = str(r.get("RoleName") or "")
        role_arn = str(r.get("Arn") or "")

        # Skip AWS-managed roles where cross-account trust without ExternalId
        # is expected by design (e.g. AWS Organizations management account).
        if role_name in _IAM_033_ROLE_EXCEPTIONS:
            continue

        role_account = _account_from_arn(role_arn)
        if not role_account:
            continue

        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue

        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if not _stmt_has_assume_role(st):
                continue

            principal = st.get("Principal")
            aws_p = principal.get("AWS") if isinstance(principal, dict) else None
            principal_list = [aws_p] if isinstance(aws_p, str) else aws_p
            if not isinstance(principal_list, list):
                continue

            has_external = False
            for p in principal_list:
                ps = str(p)
                if ps.startswith("arn:aws:iam::"):
                    p_account = _account_from_arn(ps)
                    if p_account and p_account != role_account:
                        has_external = True
                        break

            if not has_external:
                continue

            cond_text = json.dumps(st.get("Condition", {}), default=str)
            if "sts:ExternalId" not in cond_text:
                # Check for alternative strong-scoping conditions that mitigate
                # confused-deputy without sts:ExternalId (e.g. PrincipalArn scope,
                # SourceAccount, PrincipalOrgID).
                _strong_conds = {
                    "aws:principalarn",
                    "aws:sourceaccount",
                    "aws:principalorgid",
                    "aws:principalorgpaths",
                    "aws:sourceorgid",
                }
                cond_lower = cond_text.lower()
                if any(c in cond_lower for c in _strong_conds):
                    continue  # alternative confused-deputy protection present
                affected.append(role_arn or f"role/{role_name or 'unknown'}")
                break  # one violation per role is enough; move to next role

    if affected:
        return PreCheckResult(
            "IAM-033",
            "FAIL",
            f"{len(affected)} cross-account trust(s) without sts:ExternalId",
            affected,
        )
    return PreCheckResult(
        "IAM-033", "PASS", "cross-account trusts enforce ExternalId or are absent", []
    )


@_register("iam")
def check_iam_043(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-043: Confused Deputy — service trust policies without aws:SourceAccount or aws:SourceArn.

    Roles whose trust policy has a Service principal (e.g. lambda.amazonaws.com) but lacks
    a condition scoping the caller to a specific account/ARN are vulnerable to the Confused
    Deputy attack: a malicious service in another account could request AssumeRole on this role.

    Services excluded by design (instance profiles, cross-service internal use):
      - ec2.amazonaws.com, ecs-tasks.amazonaws.com, eks.amazonaws.com
      - edgelambda.amazonaws.com (Lambda@Edge, managed by CloudFront)
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-043", "SKIP", "no roles evidence", [])

    # Services where Confused Deputy condition is not applicable by design
    _excluded_services = {
        "ec2.amazonaws.com",
        "ecs-tasks.amazonaws.com",
        "eks.amazonaws.com",
        "edgelambda.amazonaws.com",
        "ec2.amazonaws.com.cn",
    }

    # Conditions that scope the service call to a specific origin (mitigate confused deputy)
    _source_conditions = {
        "aws:sourceaccount",
        "aws:sourcearn",
        "aws:sourceorgid",
        "aws:sourceorgpaths",
    }

    affected_fail: List[str] = []  # No source condition at all
    affected_warn: List[str] = []  # Has aws:SourceArn but not aws:SourceAccount (weaker)

    for role in roles:
        if not isinstance(role, dict):
            continue
        role_name = str(role.get("RoleName") or "unknown")
        role_arn = str(role.get("Arn") or f"role/{role_name}")
        role_path = str(role.get("Path") or "/")

        # Service-Linked Roles are managed by AWS and cannot have conditions added.
        # They are not actionable findings for Confused Deputy.
        if role_path.startswith("/aws-service-role/"):
            continue

        trust = role.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue

        for stmt in _stmts_from_policy(trust):
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).upper() != "ALLOW":
                continue

            principal = stmt.get("Principal")
            if not isinstance(principal, dict):
                continue

            service_p = principal.get("Service")
            services: List[str] = (
                [service_p]
                if isinstance(service_p, str)
                else service_p if isinstance(service_p, list) else []
            )

            # Filter out excluded services
            relevant = [s for s in services if s not in _excluded_services]
            if not relevant:
                continue

            cond = stmt.get("Condition") or {}
            cond_text = json.dumps(cond, default=str).lower()

            has_source_cond = any(k in cond_text for k in _source_conditions)

            if not has_source_cond:
                # No scope restriction at all → Confused Deputy risk
                label = f"{role_arn} (service: {', '.join(relevant[:2])})"
                if label not in affected_fail:
                    affected_fail.append(label)
                break  # one violation per role
            # has_source_cond=True (SourceAccount, SourceArn, or SourceOrgId) → sufficient

    if not affected_fail and not affected_warn:
        return PreCheckResult(
            "IAM-043",
            "PASS",
            "all service trust policies have aws:SourceAccount, aws:SourceArn, or aws:SourceOrgID conditions",
            [],
        )

    all_affected = affected_fail + affected_warn
    count_fail = len(affected_fail)
    summary_parts = []
    if count_fail:
        summary_parts.append(
            f"{count_fail} role(s) with service trust and no source-scoping condition"
        )
    return PreCheckResult("IAM-043", "FAIL", "; ".join(summary_parts), all_affected[:10])


@_register("iam")
def check_iam_034(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow IdP takeover actions broadly."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-034", "SKIP", "no policies evidence", [])

    risky = {
        "iam:updatesamlprovider",
        "iam:updateopenidconnectproviderthumbprint",
        "iam:createopenidconnectprovider",
        "iam:createsamlprovider",
        "iam:deleteopenidconnectprovider",
        "iam:deletesamlprovider",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue

            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-034",
                    "FAIL",
                    f"policy '{pname}' allows IdP mutation actions broadly",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-034", "PASS", "no broad IdP mutation permissions found", [])


@_register("iam")
def check_iam_035(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow policy-version backdoor actions broadly."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-035", "SKIP", "no policies evidence", [])

    risky = {"iam:createpolicyversion", "iam:setdefaultpolicyversion"}

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue

            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue

            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(
                str(r) in {"*", "arn:aws:iam::*:policy/*"} for r in res_list
            )
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-035",
                    "FAIL",
                    f"policy '{pname}' allows policy-version escalation actions",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-035", "PASS", "no broad policy-version backdoor actions found", [])


@_register("iam")
def check_iam_036(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow broad service-specific credential takeover."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-036", "SKIP", "no policies evidence", [])

    risky = {
        "iam:createservicespecificcredential",
        "iam:resetservicespecificcredential",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-036",
                    "FAIL",
                    f"policy '{pname}' allows broad service-specific credential takeover",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult(
        "IAM-036", "PASS", "no broad service-specific credential takeover actions", []
    )


@_register("iam")
def check_iam_037(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow broad MFA device manipulation."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-037", "SKIP", "no policies evidence", [])

    risky = {
        "iam:enablemfadevice",
        "iam:createvirtualmfadevice",
        "iam:deactivatemfadevice",
        "iam:resyncmfadevice",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-037",
                    "FAIL",
                    f"policy '{pname}' allows broad MFA manipulation actions",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-037", "PASS", "no broad MFA manipulation actions", [])


@_register("iam")
def check_iam_038(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM wildcard delete permissions should be prohibited."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-038", "SKIP", "no policies evidence", [])

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if "iam:delete*" not in acts and "iam:*" not in acts and "*" not in acts:
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-038",
                    "FAIL",
                    f"policy '{pname}' allows iam:Delete* broadly",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-038", "PASS", "no broad iam:Delete* permissions", [])


@_register("iam")
def check_iam_039(evidence: Dict[str, Any]) -> PreCheckResult:
    """Broad policy detachment/deletion actions should be restricted."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-039", "SKIP", "no policies evidence", [])

    risky = {
        "iam:detachuserpolicy",
        "iam:detachrolepolicy",
        "iam:detachgrouppolicy",
        "iam:deletepolicyversion",
        "iam:deletepolicy",
        "iam:deleteuserpolicy",
        "iam:deleterolepolicy",
        "iam:deletegrouppolicy",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-039",
                    "FAIL",
                    f"policy '{pname}' allows broad policy-detach/deletion actions",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-039", "PASS", "no broad policy-detach/deletion actions", [])


@_register("iam")
def check_iam_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-005: Password policy minimum length should be 14+ characters."""
    pp_doc = evidence.get("password-policy")
    if not isinstance(pp_doc, dict):
        return PreCheckResult("IAM-005", "SKIP", "no password-policy evidence", [])

    policy = pp_doc.get("PasswordPolicy")
    if not isinstance(policy, dict):
        return PreCheckResult("IAM-005", "SKIP", "password-policy missing PasswordPolicy key", [])

    min_len = policy.get("MinimumPasswordLength")
    if min_len is None:
        return PreCheckResult("IAM-005", "SKIP", "MinimumPasswordLength not set", [])

    if int(min_len) >= 14:
        return PreCheckResult("IAM-005", "PASS", f"MinimumPasswordLength={min_len} (≥14)", [])
    return PreCheckResult(
        "IAM-005",
        "FAIL",
        f"MinimumPasswordLength={min_len} (required ≥14)",
        ["arn:aws:iam::*:account-password-policy"],
    )


@_register("iam")
def check_iam_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-015: IAM users should not have direct policy attachments — use groups instead."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-015", "SKIP", "no users evidence", [])

    policies = evidence.get("policies")
    policy_map: Dict[str, Dict[str, Any]] = {}
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            for key in ("Arn", "PolicyArn", "PolicyName"):
                val = policy.get(key)
                if val:
                    policy_map[str(val)] = policy

    affected: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        # Flag users that have attached/inline policies but belong to no groups
        has_attached = bool(u.get("AttachedPolicies"))
        has_inline = bool(u.get("InlinePolicies"))
        in_groups = bool(u.get("Groups"))
        if (has_attached or has_inline) and not in_groups:
            uname = str(u.get("UserName") or "unknown")
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)
            direct_policies = []
            for pol in u.get("AttachedPolicies") or []:
                if not isinstance(pol, dict):
                    continue
                pname = str(pol.get("PolicyName") or "")
                parn = str(pol.get("PolicyArn") or "")
                resolved = policy_map.get(parn) or policy_map.get(pname) or {}
                actions = []
                doc = resolved.get("PolicyDocument") if isinstance(resolved, dict) else None
                for stmt in _stmts_from_policy(doc):
                    actions.extend(_actions_from_stmt(stmt))
                direct_policies.append(
                    {
                        "type": "managed",
                        "policy_name": pname,
                        "policy_arn": parn,
                        "resolved_actions_sample": sorted(set(actions))[:10],
                        "resources": _resources_from_policy_doc(doc) if doc else [],
                    }
                )
            inline = u.get("InlinePolicies") or []
            inline_names = list(inline.keys()) if isinstance(inline, dict) else inline
            resource_details.append(
                {
                    "user": uname,
                    "arn": arn,
                    "groups": u.get("Groups") or [],
                    "direct_policies": direct_policies,
                    "inline_policies": inline_names,
                }
            )

    if not affected:
        return PreCheckResult(
            "IAM-015", "PASS", "no users with direct permissions outside group", []
        )
    result = PreCheckResult(
        "IAM-015",
        "FAIL",
        f"{len(affected)} user(s) with direct policy attachments and no group membership",
        affected[:5],
    )
    result.metadata["resource_details"] = resource_details[:5]
    return result


@_register("iam")
def check_iam_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-016: Programmatic-only IAM users should use roles or temporary credentials."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-016", "SKIP", "no users evidence", [])

    cred = evidence.get("credential-report", {})
    by_user: Dict[str, Any] = cred.get("by_user", {}) if isinstance(cred, dict) else {}

    affected: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("UserName") or "")
        row = by_user.get(uname, {})

        # Service account pattern: no console password + active access key
        password_enabled = str(row.get("password_enabled", "false")).lower()
        has_active_key = any(
            str(k.get("Status") or "").lower() == "active"
            for k in (u.get("AccessKeys") or [])
            if isinstance(k, dict)
        )
        if password_enabled == "false" and has_active_key:
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)
            classification = (
                "service_account_pattern"
                if re.search(r"(svc|service|bot|automation|ci|cd|deploy)", uname, re.IGNORECASE)
                else "ambiguous"
            )
            resource_details.append(
                {
                    "user": uname,
                    "arn": arn,
                    "classification": classification,
                    "service_account_pattern": classification == "service_account_pattern",
                    "has_console_password": False,
                    "has_active_access_key": True,
                    "last_used_services": sorted(
                        {
                            str((k.get("LastUsed") or {}).get("ServiceName"))
                            for k in (u.get("AccessKeys") or [])
                            if isinstance(k, dict) and (k.get("LastUsed") or {}).get("ServiceName")
                        }
                    ),
                    "permission_context": _user_permission_context(evidence, u),
                }
            )

    if not affected:
        return PreCheckResult("IAM-016", "PASS", "no programmatic-only IAM users found", [])
    result = PreCheckResult(
        "IAM-016",
        "FAIL",
        f"{len(affected)} programmatic-only IAM user(s) with no console password and active access keys",
        affected[:5],
    )
    result.metadata["resource_details"] = resource_details[:5]
    return result


@_register("iam")
def check_iam_040(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-040: Organization SCPs should impose Deny restrictions on all accounts."""
    scps_doc = evidence.get("effective-scps")
    if not isinstance(scps_doc, dict):
        return PreCheckResult("IAM-040", "SKIP", "effective-scps evidence not available", [])

    error = scps_doc.get("error")
    scps = scps_doc.get("service_control_policies", [])

    # If error and no SCPs: not in org or no permissions → SKIP
    if error and not scps:
        return PreCheckResult(
            "IAM-040",
            "SKIP",
            f"Account not in Organization or no org permissions: {str(error)[:100]}",
            [],
        )

    if not isinstance(scps, list) or not scps:
        return PreCheckResult("IAM-040", "SKIP", "No SCPs found (not in Organization)", [])

    # Check if any SCP has Deny statements (not just the AWS-managed FullAWSAccess)
    has_deny_scp = False
    non_managed_scps = [s for s in scps if isinstance(s, dict) and not s.get("AwsManaged", False)]

    for scp in non_managed_scps:
        doc = scp.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for stmt in doc.get("Statement", []) or []:
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).upper() == "DENY":
                has_deny_scp = True
                break
        if has_deny_scp:
            break

    if has_deny_scp:
        return PreCheckResult(
            "IAM-040",
            "PASS",
            f"{len(non_managed_scps)} custom SCP(s) found; at least one has Deny statements",
            [],
        )

    # In org, SCPs exist, but no Deny-based SCPs — only Allow (FullAWSAccess default)
    scp_names = [str(s.get("Name", "unknown")) for s in scps if isinstance(s, dict)]
    return PreCheckResult(
        "IAM-040",
        "FAIL",
        f"Account in Organization with {len(scps)} SCP(s) but no Deny-based custom SCPs: "
        + ", ".join(scp_names[:5]),
        [],
    )


@_register("iam")
def check_iam_041(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-041: Roles with AdministratorAccess or PowerUserAccess.

    Privileged roles are flagged unless they are ServiceLinkedRole.
    Severity is dynamic based on Access Advisor:
      - Never used (AccessAdvisorDaysAgo=None) or >90 days → Critical (zombi role)
      - <=90 days ago → High (active but privileged)

    Also checks Trust Policy for MFA condition.
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-041", "SKIP", "no roles evidence", [])

    admin_policies = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }

    affected_roles: List[Dict[str, Any]] = []

    for role in roles:
        if not isinstance(role, dict):
            continue

        # Skip ServiceLinkedRole (AWS-managed, not customer risk)
        role_type = role.get("RoleType", "Unknown")
        if role_type == "ServiceLinkedRole":
            continue

        role_name = str(role.get("RoleName") or "unknown")
        role_arn = str(role.get("Arn") or f"role/{role_name}")
        attached = role.get("AttachedPolicies") or []

        # Check AWS-managed admin policies
        matched_admin_policies: List[str] = []
        for policy in attached:
            if not isinstance(policy, dict):
                continue
            policy_arn = str(policy.get("PolicyArn") or "")
            if policy_arn in admin_policies:
                matched_admin_policies.append(policy_arn)

        if not matched_admin_policies:
            continue

        # This role has privileged access; determine severity
        access_advisor_days = role.get("AccessAdvisorDaysAgo")

        # Determine severity based on last access
        if access_advisor_days is None or access_advisor_days > 90:
            severity = "Critical"  # Never used or zombi
        else:
            severity = "High"  # Active but privileged

        # Check Trust Policy for MFA condition
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        has_mfa_condition = _has_mfa_condition_in_policy(trust_policy)

        # Extract trusted principals for context
        principals: List[str] = []
        for stmt in trust_policy.get("Statement") or []:
            p = stmt.get("Principal")
            if isinstance(p, str):
                principals.append(p)
            elif isinstance(p, dict):
                for v in p.values():
                    if isinstance(v, list):
                        principals.extend(v)
                    elif isinstance(v, str):
                        principals.append(v)

        affected_roles.append(
            {
                "role_name": role_name,
                "role_arn": role_arn,
                "role_type": role_type,
                "attached_admin_policies": matched_admin_policies,
                "severity": severity,
                "access_days_ago": access_advisor_days,
                "has_mfa_condition": has_mfa_condition,
                "principals": principals[:2],  # Keep first 2 for display
            }
        )

    if not affected_roles:
        return PreCheckResult(
            "IAM-041",
            "PASS",
            "no customer-managed roles with AdministratorAccess/PowerUserAccess",
            [],
        )

    # Build evidence snippet with detailed role analysis
    snippet_roles = []
    affected_labels = []
    for r in affected_roles[:10]:
        snippet_roles.append(
            {
                "RoleName": r["role_name"],
                "RoleArn": r["role_arn"],
                "RoleType": r["role_type"],
                "AttachedAdminPolicies": r["attached_admin_policies"],
                "Severity": r["severity"],
                "AccessAdvisorDaysAgo": r["access_days_ago"],
                "HasMFACondition": r["has_mfa_condition"],
                "TrustedBy": r["principals"],
            }
        )
        affected_labels.append(r["role_arn"])

    # Determine overall severity
    has_critical = any(r["severity"] == "Critical" for r in affected_roles)
    overall_summary = f"{len(affected_roles)} privileged role(s) detected"
    if has_critical:
        overall_summary += (
            f" ({sum(1 for r in affected_roles if r['severity'] == 'Critical')} unused/zombi)"
        )

    return PreCheckResult(
        "IAM-041",
        "FAIL",
        overall_summary,
        affected_labels,
        metadata={"detailed_roles": snippet_roles},
    )


def _has_mfa_condition_in_policy(policy: Dict[str, Any]) -> bool:
    """Check if policy has aws:MultiFactorAuthPresent condition."""
    for stmt in policy.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        conditions = stmt.get("Condition", {})
        if "aws:MultiFactorAuthPresent" in str(conditions):
            return True
    return False


@_register("iam")
def check_iam_042(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-042: Privilege escalation paths via dangerous IAM permissions without MFA condition.

    Detects policies granting escalation-capable permissions (based on Rhino Security Labs taxonomy)
    without requiring aws:MultiFactorAuthPresent:true. These permissions allow a low-privilege
    identity to elevate to admin without additional authentication.

    Escalation categories:
      - Credential creation: iam:CreateAccessKey, iam:CreateLoginProfile, iam:UpdateLoginProfile
      - Policy attachment: iam:AttachUserPolicy, iam:AttachRolePolicy, iam:AttachGroupPolicy
      - Policy modification: iam:PutUserPolicy, iam:PutRolePolicy, iam:PutGroupPolicy
      - Role passing: iam:PassRole (combined with other services = privilege escalation vector)
      - MFA bypass: iam:CreateVirtualMFADevice without scoped resource
    """
    policies = evidence.get("policies")
    if not isinstance(policies, list) or not policies:
        return PreCheckResult("IAM-042", "SKIP", "no policies evidence", [])

    # Escalation permissions — must be checked with broad Resource scope
    _escalation_perms = {
        "iam:createaccesskey",
        "iam:createloginprofile",
        "iam:updateloginprofile",
        "iam:attachuserpolicy",
        "iam:attachrolepolicy",
        "iam:attachgrouppolicy",
        "iam:putuserpolicy",
        "iam:putrolepolicy",
        "iam:putgrouppolicy",
        "iam:passrole",
        "iam:createvirtualmfadevice",
    }

    affected: List[str] = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue

        policy_arn = str(policy.get("Arn") or policy.get("PolicyName") or "unknown")
        # Skip AWS-managed policies — we can't change them; focus on customer-managed
        if policy_arn.startswith("arn:aws:iam::aws:policy/"):
            continue

        doc = policy.get("PolicyDocument") or {}
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except Exception:
                continue
        if not isinstance(doc, dict):
            continue

        for stmt in _stmts_from_policy(doc):
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).upper() != "ALLOW":
                continue

            # Check resource scope — only broad resources are dangerous
            resource = stmt.get("Resource", "")
            resource_list = [resource] if isinstance(resource, str) else resource
            has_broad_resource = any(
                str(r) in ("*", "arn:aws:iam::*:*", "arn:aws:iam:::*") for r in resource_list
            )
            if not has_broad_resource:
                continue

            # Check for escalation actions
            actions_raw = stmt.get("Action", [])
            if isinstance(actions_raw, str):
                actions_raw = [actions_raw]
            actions_lower = [str(a).lower() for a in actions_raw]

            found_escalation = set()
            for act in actions_lower:
                if act == "*" or act == "iam:*":
                    found_escalation.add(act)
                elif act in _escalation_perms:
                    found_escalation.add(act)

            if not found_escalation:
                continue

            # Check if MFA condition is present
            cond = stmt.get("Condition") or {}
            cond_text = json.dumps(cond, default=str).lower()
            has_mfa_cond = "aws:multifactorauthpresent" in cond_text and '"true"' in cond_text

            if not has_mfa_cond:
                label = f"{policy_arn} ({', '.join(sorted(found_escalation)[:3])})"
                if label not in affected:
                    affected.append(label)
                break  # One violation per policy is enough

    if not affected:
        return PreCheckResult(
            "IAM-042",
            "PASS",
            "no customer-managed policies with unguarded escalation permissions found",
            [],
        )
    return PreCheckResult(
        "IAM-042",
        "FAIL",
        f"{len(affected)} policy(ies) with privilege escalation permissions without MFA condition",
        affected[:10],
    )


@_register("iam")
def check_iam_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-007: Inline policies must not be used on IAM roles — use managed policies instead."""
    roles = evidence.get("roles")
    if not isinstance(roles, list):
        return PreCheckResult("IAM-007", "SKIP", "no roles evidence", [])

    affected: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for r in roles:
        if not isinstance(r, dict):
            continue
        inline = r.get("InlinePolicies") or []
        if inline:
            arn = str(r.get("Arn") or f"arn:aws:iam::*:role/{r.get('RoleName', 'unknown')}")
            affected.append(arn)
            inline_names = list(inline.keys()) if isinstance(inline, dict) else inline
            resource_details.append(
                {
                    "role_name": r.get("RoleName"),
                    "arn": arn,
                    "inline_policies": inline_names,
                }
            )

    if not affected:
        return PreCheckResult("IAM-007", "PASS", "no roles with inline policies", [])
    result = PreCheckResult(
        "IAM-007",
        "FAIL",
        f"{len(affected)} role(s) have inline policies",
        affected[:5],
    )
    result.metadata["resource_details"] = resource_details[:5]
    return result


@_register("iam")
def check_iam_018(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-018: IAM password policy should enforce maximum password age (90 days or less)."""
    pp_doc = evidence.get("password-policy")
    if not isinstance(pp_doc, dict):
        return PreCheckResult("IAM-018", "SKIP", "no password-policy evidence", [])

    policy = pp_doc.get("PasswordPolicy")
    if not isinstance(policy, dict):
        return PreCheckResult("IAM-018", "SKIP", "password-policy missing PasswordPolicy key", [])

    expire_passwords = policy.get("ExpirePasswords")
    max_age = policy.get("MaxPasswordAge")

    if not _truthy(expire_passwords):
        return PreCheckResult(
            "IAM-018",
            "FAIL",
            "ExpirePasswords=false — password expiry not enforced",
            ["arn:aws:iam::*:account-password-policy"],
        )

    if max_age is None:
        return PreCheckResult("IAM-018", "SKIP", "MaxPasswordAge not set", [])

    try:
        max_age_int = int(max_age)
    except (TypeError, ValueError):
        return PreCheckResult(
            "IAM-018", "SKIP", f"MaxPasswordAge={max_age!r} is not an integer", []
        )

    if max_age_int <= 90:
        return PreCheckResult(
            "IAM-018",
            "PASS",
            f"MaxPasswordAge={max_age_int} (≤90 days, ExpirePasswords=true)",
            [],
        )
    return PreCheckResult(
        "IAM-018",
        "FAIL",
        f"MaxPasswordAge={max_age_int} days (required ≤90)",
        ["arn:aws:iam::*:account-password-policy"],
    )


@_register("iam")
def check_iam_019(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-019: IAM password policy should require symbol characters."""
    pp_doc = evidence.get("password-policy")
    if not isinstance(pp_doc, dict):
        return PreCheckResult("IAM-019", "SKIP", "no password-policy evidence", [])

    policy = pp_doc.get("PasswordPolicy")
    if not isinstance(policy, dict):
        return PreCheckResult("IAM-019", "SKIP", "password-policy missing PasswordPolicy key", [])

    require_symbols = policy.get("RequireSymbols")
    if _truthy(require_symbols):
        return PreCheckResult("IAM-019", "PASS", "RequireSymbols=true", [])
    return PreCheckResult(
        "IAM-019",
        "FAIL",
        f"RequireSymbols={require_symbols!r}",
        ["arn:aws:iam::*:account-password-policy"],
    )


# AWS service account IDs that are legitimately used in bucket policies by design.
# These are documented AWS-managed accounts for services like ELB, CloudFront, etc.
# Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
_AWS_SERVICE_ACCOUNTS: Dict[str, str] = {
    # ELB access logging (per-region accounts)
    "127311923021": "ELB us-east-1",
    "033677994240": "ELB us-east-2",
    "027434742980": "ELB us-west-1",
    "797873946194": "ELB us-west-2/CloudFront logs",
    "098369216593": "ELB af-south-1",
    "600734575887": "ELB ap-east-1",
    "718504428378": "ELB ap-southeast-3/ap-south-2",
    "383597477331": "ELB ap-southeast-4",
    "754344448648": "ELB ap-south-1",
    "589379963580": "ELB ap-northeast-3",
    "507241528517": "ELB ap-northeast-2",
    "582318560864": "ELB ap-southeast-1",
    "114774131450": "ELB ap-southeast-2",
    "783225319266": "ELB ap-northeast-1",
    "985666609251": "ELB ca-central-1",
    "045080605973": "ELB cn-north-1",
    "638102146993": "ELB cn-northwest-1/eu-south-2",
    "897822967062": "ELB eu-central-1/eu-north-1",
    "635631232610": "ELB eu-central-2",
    "054676820928": "ELB eu-west-1",
    "156460612806": "ELB eu-west-2",
    "009996457667": "ELB eu-south-1",
    "076674570225": "ELB eu-west-3/me-central-1",
    "086441151436": "ELB me-south-1",
    "507936923172": "ELB sa-east-1",
    "048591011584": "ELB us-gov-west-1",
    "190560391635": "ELB us-gov-east-1",
    # CloudFront access logging
    "210479947434": "CloudFront logs",
}


_IAM_ADMIN_ACTIONS = {
    "iam:*",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putrolepolicy",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:createpolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateassumerolepolicy",
    "iam:passrole",
}


def _policy_doc_has_iam_admin_actions(doc: Any) -> bool:
    for stmt in _stmts_from_policy(doc):
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect") or "").upper() != "ALLOW":
            continue
        actions = {a.lower() for a in _actions_from_stmt(stmt)}
        if "*" in actions or actions & _IAM_ADMIN_ACTIONS:
            return True
        if any(a.startswith("iam:") and a.endswith("*") for a in actions):
            return True
    return False


def _role_has_iam_admin_actions(
    role: Dict[str, Any], policy_map: Dict[str, Dict[str, Any]]
) -> bool:
    return bool(_role_iam_admin_evidence(role, policy_map))


def _role_iam_admin_evidence(
    role: Dict[str, Any], policy_map: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    for inline_doc in (
        (role.get("InlinePolicies") or {}).values()
        if isinstance(role.get("InlinePolicies"), dict)
        else role.get("InlinePolicies") or []
    ):
        actions = []
        for stmt in _stmts_from_policy(inline_doc):
            if isinstance(stmt, dict) and str(stmt.get("Effect") or "").upper() == "ALLOW":
                actions.extend(_actions_from_stmt(stmt))
        if _policy_doc_has_iam_admin_actions(inline_doc):
            evidence.append(
                {
                    "policy_type": "inline",
                    "policy_arn": None,
                    "policy_name": None,
                    "iam_admin_actions": sorted(set(actions))[:20],
                    "resources": _resources_from_policy_doc(inline_doc),
                }
            )

    for policy in role.get("AttachedPolicies") or []:
        if not isinstance(policy, dict):
            continue
        policy_arn = str(policy.get("PolicyArn") or "")
        policy_name = str(policy.get("PolicyName") or "")
        if policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess":
            evidence.append(
                {
                    "policy_type": "managed",
                    "policy_arn": policy_arn,
                    "policy_name": policy_name,
                    "iam_admin_actions": ["*"],
                    "resources": ["*"],
                }
            )
            continue
        resolved = policy_map.get(policy_arn) or policy_map.get(policy_name)
        if resolved and _policy_doc_has_iam_admin_actions(resolved.get("PolicyDocument")):
            actions = []
            for stmt in _stmts_from_policy(resolved.get("PolicyDocument")):
                if isinstance(stmt, dict) and str(stmt.get("Effect") or "").upper() == "ALLOW":
                    actions.extend(_actions_from_stmt(stmt))
            evidence.append(
                {
                    "policy_type": "managed",
                    "policy_arn": policy_arn,
                    "policy_name": policy_name,
                    "iam_admin_actions": sorted(set(actions))[:20],
                    "resources": _resources_from_policy_doc(resolved.get("PolicyDocument")),
                }
            )
    return evidence


@_register("iam")
def check_iam_030(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-030: Resource-based policies with cross-account access — whitelist known AWS service accounts.

    Flags cross-account principals in S3/SQS/SNS/Lambda resource-based policies,
    excluding known AWS service accounts (ELB logging, CloudFront) that are documented
    and required by AWS for specific integrations.
    """
    rbp = evidence.get("resource-based-policies")
    if not isinstance(rbp, dict):
        return PreCheckResult("IAM-030", "SKIP", "no resource-based-policies evidence", [])

    meta = evidence.get("_audit_metadata")
    audit_account = meta.get("_account_id") if isinstance(meta, dict) else None

    # Infer audit account from IAM evidence ARNs when metadata is unavailable
    if not audit_account:
        for src_key in ("users", "roles"):
            for item in evidence.get(src_key) or []:
                arn = str(item.get("Arn") or "") if isinstance(item, dict) else ""
                parts = arn.split(":")
                if len(parts) > 4 and parts[4].isdigit():
                    audit_account = parts[4]
                    break
            if audit_account:
                break

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    affected: List[str] = []
    whitelisted: List[str] = []

    for service, resources in rbp.items():
        if not isinstance(resources, list):
            continue
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            policy = resource.get("Policy") or {}
            if not isinstance(policy, dict):
                continue
            resource_arn = resource.get("Arn") or ""
            resource_account = _account_from_arn(resource_arn) if resource_arn else audit_account
            resource_name = resource.get("Name") or resource_arn or "unknown"
            for stmt in policy.get("Statement", []) or []:
                if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal")
                if not isinstance(principal, dict):
                    continue
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
                    p_account = parts[4] if len(parts) > 4 else ""
                    if not p_account or not p_account.isdigit():
                        continue
                    # Same-account access is never cross-account
                    effective_account = resource_account or audit_account
                    if effective_account and p_account == effective_account:
                        continue
                    service_label = _AWS_SERVICE_ACCOUNTS.get(p_account)
                    if service_label:
                        whitelisted.append(f"{resource_name} → {p} ({service_label})")
                    else:
                        affected.append(f"{resource_name} → {p}")

    if affected:
        return PreCheckResult(
            "IAM-030",
            "FAIL",
            f"{len(affected)} resource-based policy(ies) grant cross-account access to non-whitelisted accounts",
            affected[:10],
        )
    if whitelisted:
        return PreCheckResult(
            "IAM-030",
            "PASS",
            f"cross-account access only to whitelisted AWS service accounts ({len(whitelisted)} entries)",
            [],
        )
    return PreCheckResult("IAM-030", "PASS", "no cross-account resource-based policies", [])


@_register("iam")
def check_iam_026(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-026: IAM roles should use PermissionsBoundary to limit maximum privilege.

    Flags when a significant portion of customer-managed roles lack PermissionsBoundary,
    indicating no boundary controls on privilege escalation paths.
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-026", "SKIP", "no roles evidence", [])

    customer_roles = [
        r
        for r in roles
        if isinstance(r, dict)
        and not str(r.get("Path") or "/").startswith("/aws-service-role/")
        and not str(r.get("RoleName") or "").startswith("AWSReserved")
    ]
    if not customer_roles:
        return PreCheckResult("IAM-026", "SKIP", "no customer-managed roles found", [])

    policies = evidence.get("policies")
    policy_map: Dict[str, Dict[str, Any]] = {}
    if isinstance(policies, list):
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            for key in ("Arn", "PolicyArn", "PolicyName"):
                val = policy.get(key)
                if val:
                    policy_map[str(val)] = policy

    without_boundary = [r for r in customer_roles if not r.get("PermissionsBoundary")]
    admin_without_boundary = [
        r for r in without_boundary if _role_has_iam_admin_actions(r, policy_map)
    ]

    ratio = len(without_boundary) / len(customer_roles)

    if ratio >= 0.5:
        sample_roles = admin_without_boundary or without_boundary
        sample = [str(r.get("Arn") or r.get("RoleName") or "unknown") for r in sample_roles[:5]]
        classification = (
            "missing_boundary_with_iam_admin_actions"
            if admin_without_boundary
            else "missing_boundary_no_iam_admin_actions_detected"
        )
        resource_details = [
            {
                "role_name": r.get("RoleName"),
                "arn": str(r.get("Arn") or r.get("RoleName") or "unknown"),
                "has_permissions_boundary": False,
                "has_iam_admin_actions": r in admin_without_boundary,
                "classification": classification,
                "iam_admin_evidence": _role_iam_admin_evidence(r, policy_map),
            }
            for r in sample_roles[:5]
        ]
        return PreCheckResult(
            "IAM-026",
            "FAIL",
            f"{len(without_boundary)}/{len(customer_roles)} customer-managed roles lack PermissionsBoundary ({ratio:.0%}); "
            f"{len(admin_without_boundary)} have IAM administrative actions",
            sample,
            metadata={
                "classification": classification,
                "resource_details": resource_details,
                "roles_without_boundary": len(without_boundary),
                "roles_without_boundary_and_iam_admin_actions": len(admin_without_boundary),
            },
        )
    return PreCheckResult(
        "IAM-026",
        "PASS",
        f"most customer-managed roles have PermissionsBoundary ({len(customer_roles) - len(without_boundary)}/{len(customer_roles)})",
        [],
    )


@_register("iam")
def check_iam_044(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-044: Privileged roles should not have MaxSessionDuration greater than 3600 seconds (1 hour).

    Long session durations on privileged roles extend the window of exposure if a
    temporary credential is leaked, violating PCI DSS 8.3.9 (credential validity).
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-044", "SKIP", "no roles evidence", [])

    _privileged_policy_names = {"AdministratorAccess", "PowerUserAccess"}
    _max_session_threshold = 3600  # 1 hour

    affected: List[str] = []
    for role in roles:
        if not isinstance(role, dict):
            continue
        role_path = str(role.get("Path") or "/")
        if role_path.startswith("/aws-service-role/"):
            continue

        max_session = role.get("MaxSessionDuration")
        if not isinstance(max_session, int) or max_session <= _max_session_threshold:
            continue

        # Only flag roles with privileged policies attached
        attached = role.get("AttachedPolicies") or []
        policy_names = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        is_privileged = bool(policy_names & _privileged_policy_names)

        # Also flag SSO roles (they are often privileged)
        role_name = str(role.get("RoleName") or "")
        is_sso = "AWSReservedSSO" in role_name

        if is_privileged or is_sso:
            arn = str(role.get("Arn") or f"role/{role_name}")
            affected.append(f"{arn} (MaxSessionDuration={max_session}s / {max_session // 3600}h)")

    if affected:
        return PreCheckResult(
            "IAM-044",
            "FAIL",
            f"{len(affected)} privileged/SSO role(s) with MaxSessionDuration > 1h",
            affected,
        )
    return PreCheckResult(
        "IAM-044",
        "PASS",
        "all privileged roles have MaxSessionDuration ≤ 1h",
        [],
    )


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
