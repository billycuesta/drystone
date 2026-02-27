"""Deterministic pre-checks executed BEFORE AI analysis.

Tier 1 of the 3-tier validation architecture:
  Tier 1: Pre-checks (deterministic, binary PASS/FAIL/SKIP)
  Tier 2: AI analysis (constrained by pre-computed facts)
  Tier 3: Post-validation (reconciliation + existing normalizer)

Each check function inspects raw evidence and returns a deterministic verdict.
The AI receives these verdicts as <pre_computed_facts> and must not contradict them.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, cast

logger = logging.getLogger(__name__)


@dataclass
class PreCheckResult:
    """Result of a single deterministic pre-check."""

    check_id: str  # e.g. "IAM-001"
    status: str  # "PASS" | "FAIL" | "SKIP"
    evidence_summary: str  # e.g. "AccountMFAEnabled=0"
    affected_resources: List[str] = field(default_factory=list)
    confidence: float = 1.0


# Type alias for check functions
PreCheckFn = Callable[[Dict[str, Any]], PreCheckResult]


# ---------------------------------------------------------------------------
# Registry: maps skill name → list of (check_id, check_function) pairs
# ---------------------------------------------------------------------------
PRE_CHECK_REGISTRY: Dict[str, List[PreCheckFn]] = {}


def _register(skill: str):
    """Decorator to register a pre-check function for a skill."""

    def decorator(fn: PreCheckFn) -> PreCheckFn:
        PRE_CHECK_REGISTRY.setdefault(skill, []).append(fn)
        return fn

    return decorator


def run_pre_checks(
    skill_name: str, evidence: Dict[str, Any], checklist: Dict[str, Any]
) -> List[PreCheckResult]:
    """Run all registered pre-checks for a skill.

    Args:
        skill_name: Skill identifier (e.g. 'iam', 'hardening')
        evidence: Evidence dict (file stems → parsed JSON)
        checklist: Checklist dict with 'items' array

    Returns:
        List of PreCheckResult for each check that could be evaluated
    """
    checks = PRE_CHECK_REGISTRY.get(skill_name.lower(), [])
    if not checks:
        return []

    results = []
    for check_fn in checks:
        try:
            result = check_fn(evidence)
            results.append(result)
        except Exception as e:
            # Pre-check failure → SKIP (let AI handle it)
            logger.debug(f"Pre-check {check_fn.__name__} failed: {e}")
    return results


def format_pre_checks_for_prompt(
    pre_checks: List[PreCheckResult], checklist: Optional[Dict[str, Any]] = None
) -> str:
    """Format pre-check results as XML for prompt injection.

    Args:
        pre_checks: List of pre-check results
        checklist: Optional checklist to look up severities

    Returns:
        XML string for SKILL_ADDENDUM injection
    """
    if not pre_checks:
        return ""

    # Build severity lookup from checklist
    severity_map: Dict[str, str] = {}
    if checklist and "items" in checklist:
        for item in checklist["items"]:
            if isinstance(item, dict) and "id" in item:
                severity_map[item["id"]] = item.get("severity", "Medium")

    lines = [
        "<pre_computed_facts>",
        "  <instructions>",
        "    These facts were verified deterministically against collected evidence.",
        "    They are AUTHORITATIVE — do not contradict them.",
        "    - For PASS items: DO NOT generate a finding (the check passed).",
        "    - For FAIL items: Generate a finding with professional description and remediation.",
        "    - For SKIP items: DO NOT generate a finding (the check is not applicable to this environment).",
        "    - For items NOT listed: Analyze evidence yourself.",
        "  </instructions>",
        "",
    ]

    for r in pre_checks:
        sev = severity_map.get(r.check_id, "")
        sev_attr = f' severity="{sev}"' if sev else ""
        resources = ""
        if r.affected_resources:
            resources = (
                f"\n    <affected_resources>{', '.join(r.affected_resources)}</affected_resources>"
            )
        lines.append(
            f'  <fact id="{r.check_id}" status="{r.status}"{sev_attr}>'
            f"\n    <evidence>{r.evidence_summary}</evidence>"
            f"{resources}"
            f"\n  </fact>"
        )

    lines.append("</pre_computed_facts>")
    return "\n".join(lines)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _get_summary_map(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Extract SummaryMap from account-summary evidence (handles both shapes)."""
    acct = evidence.get("account-summary", {})
    if not isinstance(acct, dict):
        return {}
    if "SummaryMap" in acct:
        sm = acct.get("SummaryMap")
        return sm if isinstance(sm, dict) else {}
    # Flattened shape (test fixtures)
    return acct


def _get_credential_report_by_user(evidence: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract by_user dict from credential-report evidence."""
    cred = evidence.get("credential-report")
    if isinstance(cred, dict):
        by_user = cred.get("by_user")
        if isinstance(by_user, dict):
            return by_user
    return {}


def _truthy(val: Any) -> bool:
    """Check if a value is truthy in the AWS evidence sense."""
    return val in {1, True, "1", "true", "True"}


def _falsy(val: Any) -> bool:
    """Check if a value is falsy in the AWS evidence sense."""
    return val in {0, False, "0", "false", "False"}


def _items_from_doc(doc: Any) -> list:
    """Extract items list from evidence doc (handles dict with 'items' or raw list)."""
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):
        return doc["items"]
    if isinstance(doc, list):
        return doc
    return []


def _stmts_from_policy(policy: Any) -> list:
    """Extract Statement list from a policy document."""
    if not isinstance(policy, dict):
        return []
    stmts = policy.get("Statement")
    if isinstance(stmts, list):
        return stmts
    if isinstance(stmts, dict):
        return [stmts]
    return []


def _actions_from_stmt(stmt: Dict[str, Any]) -> List[str]:
    """Extract normalized action list from a statement."""
    a = stmt.get("Action")
    if isinstance(a, str):
        return [a]
    if isinstance(a, list):
        return [str(x) for x in a if x is not None]
    return []


def _principal_is_wildcard_any(principal: Any) -> bool:
    """Check if principal is '*' (public access)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and any(x == "*" for x in aws):
            return True
    return False


def _stmt_has_same_account_restriction(stmt: dict) -> bool:
    """Return True if the policy statement has a condition that restricts
    access to the same AWS account (AWS:SourceOwner or aws:SourceAccount).

    The default AWS SNS resource policy uses Principal:* + StringEquals
    AWS:SourceOwner = <account-id>, which is NOT a public exposure.
    """
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return False
    # Normalise keys to lower-case for comparison
    cond_lower = {k.lower(): v for k, v in cond.items()}
    # StringEquals or StringEqualsIgnoreCase operators
    for op_key in ("stringequals", "stringequalsignorecase"):
        op_val = cond_lower.get(op_key)
        if not isinstance(op_val, dict):
            continue
        for cond_key in op_val:
            if cond_key.lower() in (
                "aws:sourceowner",
                "aws:sourceaccount",
            ):
                return True
    return False


# ============================================================================
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
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("UserName") or "")
        row = by_user.get(uname, {})

        # Only console users need MFA (password_enabled=true in credential report)
        has_console = str(row.get("password_enabled", "false")).lower() == "true"
        if not has_console:
            continue

        has_mfa = bool(u.get("MFADevices"))
        if not has_mfa:
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)

    if affected:
        return PreCheckResult(
            "IAM-002", "FAIL", f"{len(affected)} console user(s) without MFA", affected
        )
    return PreCheckResult("IAM-002", "PASS", "all console users have MFA enabled", [])


@_register("iam")
def check_iam_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-010: Administrative users must have MFA enabled."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-010", "SKIP", "no users evidence", [])

    _ADMIN_POLICY_NAMES = {"AdministratorAccess", "PowerUserAccess"}

    affected: List[str] = []
    for u in users:
        if not isinstance(u, dict):
            continue

        # Check if user has admin-level attached policy
        attached = u.get("AttachedPolicies") or []
        if not isinstance(attached, list):
            continue
        policy_names = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        is_admin = bool(policy_names & _ADMIN_POLICY_NAMES)
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
    for u in users:
        if not isinstance(u, dict):
            continue
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
            if (now - created).days > 90:
                uname = str(u.get("UserName") or "unknown")
                arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
                old_users.append(arn)
                break

    if not old_users:
        return PreCheckResult("IAM-004", "PASS", "no active keys >90 days", [])
    return PreCheckResult("IAM-004", "FAIL", f"{len(old_users)} users with old keys", old_users)


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

    now = datetime.now(timezone.utc)
    inactive = []
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = u.get("UserName", "")
        # Skip root
        if uname in ("<root_account>", "root"):
            continue
        arn = u.get("Arn", "")
        if isinstance(arn, str) and arn.endswith(":root"):
            continue

        last_used = u.get("PasswordLastUsed")
        has_keys = bool(u.get("AccessKeys"))
        if not last_used and not has_keys:
            inactive.append(f"arn:aws:iam::*:user/{uname}")

    if not inactive:
        return PreCheckResult("IAM-012", "PASS", "no inactive non-root users", [])
    return PreCheckResult("IAM-012", "FAIL", f"{len(inactive)} inactive users", inactive[:10])


@_register("iam")
def check_iam_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """Users should not have multiple active access keys."""
    users = evidence.get("users")
    if not isinstance(users, list):
        # Try credential report fallback
        by_user = _get_credential_report_by_user(evidence)
        if not by_user:
            return PreCheckResult("IAM-014", "SKIP", "no users/credential-report evidence", [])

        for uname, row in by_user.items():
            if not isinstance(row, dict):
                continue
            if _truthy(row.get("access_key_1_active")) and _truthy(row.get("access_key_2_active")):
                return PreCheckResult("IAM-014", "FAIL", f"User '{uname}' has 2 active keys", [])
        return PreCheckResult("IAM-014", "PASS", "no users with multiple active keys", [])

    multi = []
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
            multi.append(f"arn:aws:iam::*:user/{uname}")

    if not multi:
        return PreCheckResult("IAM-014", "PASS", "no users with multiple active keys", [])
    return PreCheckResult("IAM-014", "FAIL", f"{len(multi)} users with 2+ active keys", multi[:10])


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

    _ADMIN_POLICIES = {"AdministratorAccess", "PowerUserAccess"}

    # Build a map: role ARN → attached policy names
    role_policies: Dict[str, set] = {}
    for r in roles:
        if not isinstance(r, dict):
            continue
        arn = str(r.get("Arn") or "")
        attached = r.get("AttachedPolicies") or []
        pnames = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        # Also check InlinePolicies for wildcard iam actions
        inline = r.get("InlinePolicies") or []
        role_policies[arn] = pnames

    affected: List[str] = []
    for r in roles:
        if not isinstance(r, dict):
            continue
        role_arn = str(r.get("Arn") or "")

        # Does this role have admin-level policies?
        if not (role_policies.get(role_arn, set()) & _ADMIN_POLICIES):
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
    return PreCheckResult(
        "IAM-029", "PASS", "no privilege escalation via role chain detected", []
    )


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


# ============================================================================
# HARDENING PRE-CHECKS
# ============================================================================


@_register("hardening")
def check_hrd_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """AWS Config should be enabled."""
    config_recorders = evidence.get("config-recorders", {})
    recorders = (
        config_recorders.get("ConfigurationRecorders", [])
        if isinstance(config_recorders, dict)
        else []
    )
    if len(recorders) > 0:
        return PreCheckResult("HRD-001", "PASS", f"Config enabled ({len(recorders)} recorders)", [])
    return PreCheckResult("HRD-001", "FAIL", "ConfigurationRecorders=[]", [])


@_register("hardening")
def check_hrd_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub should be enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict):
        hub_status = {}
    hub_arn = hub_status.get("HubArn")
    if hub_arn:
        return PreCheckResult("HRD-002", "PASS", f"HubArn={hub_arn}", [])
    return PreCheckResult("HRD-002", "FAIL", "HubArn is empty/missing", [])


@_register("hardening")
def check_hrd_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub should have standards enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict) or not hub_status.get("HubArn"):
        return PreCheckResult("HRD-003", "SKIP", "Security Hub not enabled", [])

    enabled_standards = evidence.get("security-hub-enabled-standards", [])
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-003", "SKIP", "no standards evidence", [])

    ready = 0
    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        status = str(std.get("Status") or "").upper()
        controls = std.get("ControlsSummary") or {}
        enabled_controls = int(controls.get("enabled", 0)) if isinstance(controls, dict) else 0
        if status in {"READY", "ENABLED"} or enabled_controls > 0:
            ready += 1

    if ready > 0:
        return PreCheckResult("HRD-003", "PASS", f"{ready} standards enabled/ready", [])
    return PreCheckResult("HRD-003", "FAIL", "0 standards enabled", [])


@_register("hardening")
def check_hrd_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be >= 50%."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-004", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if score >= 50.0:
        return PreCheckResult("HRD-004", "PASS", f"compliance_score={score:.1f}%", [])
    return PreCheckResult("HRD-004", "FAIL", f"compliance_score={score:.1f}% (<50%)", [])


@_register("hardening")
def check_hrd_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical Security Hub findings should be zero."""
    sev_counts, _ = _get_hardening_counts(evidence)
    critical = sev_counts.get("CRITICAL", 0)
    if critical <= 0:
        return PreCheckResult("HRD-005", "PASS", f"CRITICAL count={critical}", [])
    return PreCheckResult("HRD-005", "FAIL", f"CRITICAL count={critical}", [])


@_register("hardening")
def check_hrd_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """AWS Config recorder should be recording with delivery channel."""
    config_recorders = evidence.get("config-recorders", {})
    if not isinstance(config_recorders, dict):
        config_recorders = {}
    recorders = config_recorders.get("ConfigurationRecorders", [])
    if not isinstance(recorders, list) or len(recorders) == 0:
        return PreCheckResult("HRD-006", "SKIP", "Config not enabled (HRD-001 applies)", [])

    recorder_status_doc = evidence.get("config-recorder-status", {})
    status_items = (
        recorder_status_doc.get("ConfigurationRecordersStatus", [])
        if isinstance(recorder_status_doc, dict)
        else []
    )

    recording_ok = False
    if isinstance(status_items, list):
        for s in status_items:
            if isinstance(s, dict) and s.get("recording") is True:
                recording_ok = True
                break

    channels_doc = evidence.get("config-delivery-channels", {})
    channels = channels_doc.get("DeliveryChannels", []) if isinstance(channels_doc, dict) else []
    channel_ok = False
    if isinstance(channels, list):
        for c in channels:
            if isinstance(c, dict) and c.get("s3BucketName"):
                channel_ok = True
                break

    if recording_ok and channel_ok:
        return PreCheckResult("HRD-006", "PASS", "recorder active, delivery channel configured", [])
    issues = []
    if not recording_ok:
        issues.append("recording=false")
    if not channel_ok:
        issues.append("no delivery channel")
    return PreCheckResult("HRD-006", "FAIL", "; ".join(issues), [])


@_register("hardening")
def check_hrd_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """High severity Security Hub findings should be <= 10."""
    sev_counts, _ = _get_hardening_counts(evidence)
    high = sev_counts.get("HIGH", 0)
    if high <= 10:
        return PreCheckResult("HRD-009", "PASS", f"HIGH count={high} (<=10)", [])
    return PreCheckResult("HRD-009", "FAIL", f"HIGH count={high} (>10)", [])


@_register("hardening")
def check_hrd_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """Medium severity Security Hub findings should be <= 20."""
    sev_counts, _ = _get_hardening_counts(evidence)
    medium = sev_counts.get("MEDIUM", 0)
    if medium <= 20:
        return PreCheckResult("HRD-012", "PASS", f"MEDIUM count={medium} (<=20)", [])
    return PreCheckResult("HRD-012", "FAIL", f"MEDIUM count={medium} (>20)", [])


@_register("hardening")
def check_hrd_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """Outdated Security Hub standards should be updated."""
    # SKIP when evidence key is entirely missing (cannot evaluate)
    if "security-hub-enabled-standards" not in evidence:
        return PreCheckResult("HRD-013", "SKIP", "no standards evidence", [])

    enabled_standards = evidence["security-hub-enabled-standards"]
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-013", "SKIP", "unexpected standards format", [])

    # ARNs use slash-separated versions: ".../benchmark/v/1.2.0"
    # Use path fragments (with leading slash) — "v1.2.0" would NOT match "v/1.2.0".
    outdated_fragments = ["/1.2.0", "/1.3.0", "/2016", "/2017"]
    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        arn = str(std.get("StandardsArn") or std.get("StandardsSubscriptionArn") or "")
        for fragment in outdated_fragments:
            if fragment in arn:
                return PreCheckResult("HRD-013", "FAIL", f"outdated standard: {arn}", [])

    return PreCheckResult("HRD-013", "PASS", "no outdated standards", [])


@_register("hardening")
def check_hrd_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """GuardDuty should be enabled."""
    gd_detectors = evidence.get("guardduty-detectors", [])
    if isinstance(gd_detectors, list) and len(gd_detectors) > 0:
        return PreCheckResult("HRD-014", "PASS", f"{len(gd_detectors)} detectors", [])
    # Also check dict shape
    if isinstance(gd_detectors, dict) and gd_detectors.get("DetectorIds"):
        ids = gd_detectors["DetectorIds"]
        if isinstance(ids, list) and len(ids) > 0:
            return PreCheckResult("HRD-014", "PASS", f"{len(ids)} detectors", [])
    return PreCheckResult("HRD-014", "FAIL", "no GuardDuty detectors", [])


@_register("hardening")
def check_hrd_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Low severity Security Hub findings should be zero."""
    sev_counts, _ = _get_hardening_counts(evidence)
    low = sev_counts.get("LOW", 0)
    if low <= 0:
        return PreCheckResult("HRD-016", "PASS", f"LOW count={low}", [])
    return PreCheckResult("HRD-016", "FAIL", f"LOW count={low} (>0)", [])


@_register("hardening")
def check_hrd_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub PCI DSS standard should be enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict) or not hub_status.get("HubArn"):
        return PreCheckResult("HRD-007", "SKIP", "Security Hub not enabled", [])

    enabled_standards = evidence.get("security-hub-enabled-standards", [])
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-007", "SKIP", "no standards evidence", [])

    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        arn = str(std.get("StandardsArn") or std.get("StandardsSubscriptionArn") or "")
        status = str(std.get("Status") or "").upper()
        if "pci-dss" in arn.lower() and status in {"READY", "ENABLED"}:
            return PreCheckResult("HRD-007", "PASS", f"PCI DSS standard enabled: {arn}", [])

    return PreCheckResult("HRD-007", "FAIL", "no PCI DSS standard enabled", [])


@_register("hardening")
def check_hrd_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 50-70% range (medium risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-008", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 50.0 <= score < 70.0:
        return PreCheckResult("HRD-008", "FAIL", f"compliance_score={score:.1f}% (50-70%)", [])
    return PreCheckResult("HRD-008", "PASS", f"compliance_score={score:.1f}% (not in 50-70% band)", [])


@_register("hardening")
def check_hrd_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """No conformance packs configured."""
    packs = evidence.get("config-conformance-packs", None)
    if packs is None:
        return PreCheckResult("HRD-010", "SKIP", "no conformance-packs evidence", [])
    if not isinstance(packs, list):
        return PreCheckResult("HRD-010", "SKIP", "unexpected conformance-packs format", [])
    if len(packs) == 0:
        return PreCheckResult("HRD-010", "FAIL", "0 conformance packs configured", [])
    return PreCheckResult("HRD-010", "PASS", f"{len(packs)} conformance pack(s) configured", [])


@_register("hardening")
def check_hrd_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 70-85% range (acceptable risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-011", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 70.0 <= score < 85.0:
        return PreCheckResult("HRD-011", "FAIL", f"compliance_score={score:.1f}% (70-85%)", [])
    return PreCheckResult("HRD-011", "PASS", f"compliance_score={score:.1f}% (not in 70-85% band)", [])


@_register("hardening")
def check_hrd_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 85-95% range (low risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-015", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 85.0 <= score < 95.0:
        return PreCheckResult("HRD-015", "FAIL", f"compliance_score={score:.1f}% (85-95%)", [])
    return PreCheckResult("HRD-015", "PASS", f"compliance_score={score:.1f}% (not in 85-95% band)", [])


def _get_hardening_counts(evidence: Dict[str, Any]):
    """Return (severity_counts, compliance_counts) from hardening evidence."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
    comp_counts = {"PASSED": 0, "FAILED": 0, "WARNING": 0, "NOT_AVAILABLE": 0, "OTHER": 0}

    summary = evidence.get("security-hub-findings-summary")
    if isinstance(summary, dict):
        sc = summary.get("severity_counts")
        if isinstance(sc, dict):
            for k in sev_counts:
                sev_counts[k] = int(sc.get(k, 0) or 0)
        cc = summary.get("compliance_status_counts")
        if isinstance(cc, dict):
            for k in comp_counts:
                comp_counts[k] = int(cc.get(k, 0) or 0)

    # Fallback: derive from raw findings
    if sum(sev_counts.values()) == 0:
        findings = evidence.get("security-hub-findings")
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                sev = str(((f.get("Severity") or {}).get("Label") or "")).upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                comp = str(((f.get("Compliance") or {}).get("Status") or "")).upper()
                if comp in comp_counts:
                    comp_counts[comp] += 1

    return sev_counts, comp_counts


# ============================================================================
# ALERTING PRE-CHECKS
# ============================================================================


@_register("alerting")
def check_alr_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudTrail should have CloudWatch Logs integration."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or len(trails) == 0:
        return PreCheckResult("ALRT-001", "SKIP", "no trails (ALR-001 applies)", [])

    for trail in trails:
        if isinstance(trail, dict) and trail.get("CloudWatchLogsLogGroupArn"):
            return PreCheckResult("ALRT-001", "PASS", "LogGroupArn present", [])
    return PreCheckResult("ALRT-001", "FAIL", "no trail with CloudWatch Logs", [])


def _alerting_critical_topic_arns(evidence: Dict[str, Any]) -> List[str]:
    arns: List[str] = []
    alarms = evidence.get("cloudwatch-alarms")
    if isinstance(alarms, list):
        for a in alarms:
            if not isinstance(a, dict):
                continue
            for act in a.get("AlarmActions", []) or []:
                if isinstance(act, str) and act.startswith("arn:aws:sns:"):
                    arns.append(act)

    rules = evidence.get("eventbridge-rules")
    if isinstance(rules, list):
        for r in rules:
            if not isinstance(r, dict):
                continue
            for t in r.get("Targets", []) or []:
                if isinstance(t, dict):
                    arn = t.get("Arn")
                    if isinstance(arn, str) and arn.startswith("arn:aws:sns:"):
                        arns.append(arn)
    return list(dict.fromkeys(arns))


def _parse_policy_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and any(x == "*" for x in aws):
            return True
    return False


@_register("alerting")
def check_alr_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should not allow broad publish access."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-022", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:publish", "sns:*", "*"} for a in actions_list):
                continue
            if _principal_is_wildcard_any(st.get("Principal")) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "ALRT-022", "FAIL", "alert SNS topic allows broad Publish", [arn]
                )

    return PreCheckResult(
        "ALRT-022", "PASS", "no broad publish permissions on alert SNS topics", []
    )


@_register("alerting")
def check_alr_023(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should not allow broad subscribe access."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-023", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:subscribe", "sns:*", "*"} for a in actions_list):
                continue
            if _principal_is_wildcard(st.get("Principal")) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "ALRT-023", "FAIL", "alert SNS topic allows broad Subscribe", [arn]
                )

    return PreCheckResult(
        "ALRT-023", "PASS", "no broad subscribe permissions on alert SNS topics", []
    )


@_register("alerting")
def check_alr_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should avoid risky HTTP/HTTPS subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-024", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    risky = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        subs = t.get("Subscriptions") if isinstance(t.get("Subscriptions"), list) else []
        for s in subs:
            if not isinstance(s, dict):
                continue
            protocol = str(s.get("Protocol") or "").lower()
            if protocol in {"http", "https"}:
                risky.append(arn)
                break

    if not risky:
        return PreCheckResult(
            "ALRT-024", "PASS", "no risky HTTP/HTTPS subscriptions on alert topics", []
        )
    return PreCheckResult(
        "ALRT-024",
        "FAIL",
        f"{len(risky)} alert SNS topics with HTTP/HTTPS subscriptions",
        risky[:10],
    )


@_register("alerting")
def check_alr_025(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical EventBridge rules should forward to SNS alerting topics."""
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list) or not rules:
        return PreCheckResult("ALRT-025", "SKIP", "no eventbridge-rules evidence", [])

    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        # Skip AWS-managed service rules (e.g. Amazon Inspector managed rules)
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        is_security_rule = (
            "cloudtrail" in pattern or "consolelogin" in pattern or "stoplogging" in pattern
        )
        if not is_security_rule:
            continue
        targets = r.get("Targets") if isinstance(r.get("Targets"), list) else []
        has_sns = any(
            isinstance(t, dict) and str(t.get("Arn") or "").startswith("arn:aws:sns:")
            for t in targets
        )
        if not has_sns:
            return PreCheckResult(
                "ALRT-025",
                "FAIL",
                "security EventBridge rule without SNS target",
                [str(r.get("Arn") or r.get("Name") or "unknown")],
            )

    return PreCheckResult(
        "ALRT-025", "PASS", "critical security EventBridge rules route to SNS", []
    )


@_register("alerting")
def check_alrt_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-005: Critical alert SNS topics should have confirmed subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-005", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    no_subs = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        confirmed = int(attrs.get("SubscriptionsConfirmed", 0) or 0)
        if confirmed == 0:
            no_subs.append(arn)

    if no_subs:
        return PreCheckResult(
            "ALRT-005", "FAIL", "alert SNS topic(s) have no confirmed subscriptions", no_subs[:5]
        )
    return PreCheckResult("ALRT-005", "PASS", "alert SNS topics have confirmed subscriptions", [])


@_register("alerting")
def check_alrt_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-006: Critical alert SNS topics should not have pending subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-006", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    pending_topics = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pending = int(attrs.get("SubscriptionsPending", 0) or 0)
        if pending > 0:
            pending_topics.append(arn)

    if pending_topics:
        return PreCheckResult(
            "ALRT-006",
            "FAIL",
            f"{len(pending_topics)} alert SNS topic(s) with pending subscriptions",
            pending_topics[:5],
        )
    return PreCheckResult(
        "ALRT-006", "PASS", "no pending subscriptions on alert SNS topics", []
    )


@_register("alerting")
def check_alrt_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-008: At least one CloudTrail trail should be multi-region."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-008", "SKIP", "no cloudtrail-trails evidence", [])

    for trail in trails:
        if isinstance(trail, dict) and trail.get("IsMultiRegionTrail"):
            return PreCheckResult("ALRT-008", "PASS", "multi-region trail present", [])

    single_region_names = [
        str(t.get("Name") or "") for t in trails if isinstance(t, dict)
    ]
    return PreCheckResult(
        "ALRT-008",
        "FAIL",
        "no multi-region trail configured",
        single_region_names[:5],
    )


@_register("alerting")
def check_alrt_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-013: CloudTrail trails should have log file validation enabled."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-013", "SKIP", "no cloudtrail-trails evidence", [])

    # Only check trails we own (not org trails from other accounts)
    invalid = []
    has_checkable_trail = False
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip org trails where we can't verify status (Status is empty dict)
        if trail.get("IsOrganizationTrail") and not trail.get("Status", {}).get("IsLogging"):
            continue
        has_checkable_trail = True
        if not trail.get("LogFileValidationEnabled"):
            invalid.append(str(trail.get("Name") or "unknown"))

    if not has_checkable_trail:
        return PreCheckResult("ALRT-013", "SKIP", "no locally-owned trails to check", [])
    if invalid:
        return PreCheckResult(
            "ALRT-013",
            "FAIL",
            f"{len(invalid)} trail(s) without log file validation",
            invalid[:5],
        )
    return PreCheckResult("ALRT-013", "PASS", "all trails have log file validation enabled", [])


@_register("alerting")
def check_alrt_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-014: CloudTrail trails should encrypt logs with KMS."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-014", "SKIP", "no cloudtrail-trails evidence", [])

    no_kms = []
    has_checkable_trail = False
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip org trails we don't own
        if trail.get("IsOrganizationTrail") and not trail.get("Status", {}).get("IsLogging"):
            continue
        has_checkable_trail = True
        if not trail.get("KMSKeyId"):
            no_kms.append(str(trail.get("Name") or "unknown"))

    if not has_checkable_trail:
        return PreCheckResult("ALRT-014", "SKIP", "no locally-owned trails to check", [])
    if no_kms:
        return PreCheckResult(
            "ALRT-014",
            "FAIL",
            f"{len(no_kms)} trail(s) without KMS encryption",
            no_kms[:5],
        )
    return PreCheckResult("ALRT-014", "PASS", "all trails encrypted with KMS", [])


@_register("alerting")
def check_alrt_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-002: CloudTrail should be integrated with EventBridge (active security rules)."""
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list):
        return PreCheckResult("ALRT-002", "SKIP", "no eventbridge-rules evidence", [])

    cloudtrail_rules: List[str] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        # Skip AWS-managed service rules (e.g. Inspector managed rules)
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        # Must be ENABLED
        if str(r.get("State") or "").upper() != "ENABLED":
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        if "aws.cloudtrail" in pattern or '"cloudtrail"' in pattern:
            cloudtrail_rules.append(name)

    if cloudtrail_rules:
        return PreCheckResult(
            "ALRT-002",
            "PASS",
            f"{len(cloudtrail_rules)} enabled EventBridge rule(s) processing CloudTrail events",
            [],
        )

    return PreCheckResult(
        "ALRT-002",
        "FAIL",
        "no enabled EventBridge rules processing CloudTrail events",
        [],
    )


@_register("alerting")
def check_alrt_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-003: Metric filters should have associated CloudWatch alarms."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-003", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = evidence collected but zero filters exist → no alarms possible → FAIL
    if not metric_filters:
        return PreCheckResult(
            "ALRT-003",
            "FAIL",
            "no metric filters configured (zero filters means no alarm coverage possible)",
            [],
        )

    alarms = evidence.get("cloudwatch-alarms")
    if not isinstance(alarms, list):
        alarms = []

    # Build set of metric names that have at least one alarm
    alarm_metric_names = {
        str(a.get("MetricName") or "")
        for a in alarms
        if isinstance(a, dict) and a.get("MetricName")
    }

    filters_without_alarm: List[str] = []
    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        for mt in mf.get("metricTransformations") or []:
            if not isinstance(mt, dict):
                continue
            metric_name = str(mt.get("metricName") or "")
            if metric_name and metric_name not in alarm_metric_names:
                filters_without_alarm.append(str(mf.get("filterName") or "unknown"))
                break

    if filters_without_alarm:
        return PreCheckResult(
            "ALRT-003",
            "FAIL",
            f"{len(filters_without_alarm)} metric filter(s) without associated CloudWatch alarm",
            filters_without_alarm[:10],
        )
    return PreCheckResult(
        "ALRT-003", "PASS", "all metric filters have associated CloudWatch alarms", []
    )


@_register("alerting")
def check_alrt_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-004: Security EventBridge rules should have SNS notification targets."""
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list):
        return PreCheckResult("ALRT-004", "SKIP", "no eventbridge-rules evidence", [])

    security_rules_without_sns: List[str] = []
    has_security_rules = False
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        if str(r.get("State") or "").upper() != "ENABLED":
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        if not ("aws.cloudtrail" in pattern or "cloudtrail" in pattern):
            continue
        has_security_rules = True
        targets = r.get("Targets") if isinstance(r.get("Targets"), list) else []
        has_sns = any(
            isinstance(t, dict) and str(t.get("Arn") or "").startswith("arn:aws:sns:")
            for t in targets
        )
        if not has_sns:
            security_rules_without_sns.append(name)

    if not has_security_rules:
        return PreCheckResult("ALRT-004", "SKIP", "no security-relevant EventBridge rules found", [])
    if security_rules_without_sns:
        return PreCheckResult(
            "ALRT-004",
            "FAIL",
            f"{len(security_rules_without_sns)} security EventBridge rule(s) without SNS target",
            security_rules_without_sns[:5],
        )
    return PreCheckResult(
        "ALRT-004", "PASS", "all security EventBridge rules have SNS targets", []
    )


@_register("alerting")
def check_alrt_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-007: Critical security events should be covered by metric filters."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-007", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = ALL critical events uncovered → FAIL

    # Critical events that must be covered by at least one metric filter
    critical_events = {
        "StopLogging": False,
        "DeleteTrail": False,
        "CreateUser": False,
        "ConsoleLogin": False,
    }

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        for event in list(critical_events.keys()):
            if event.lower() in pattern:
                critical_events[event] = True

    missing = [e for e, covered in critical_events.items() if not covered]
    if missing:
        return PreCheckResult(
            "ALRT-007",
            "FAIL",
            f"critical events not covered by metric filters: {', '.join(missing)}",
            missing,
        )
    return PreCheckResult(
        "ALRT-007", "PASS", "all critical security events covered by metric filters", []
    )


@_register("alerting")
def check_alrt_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-009: CloudTrail log group should have metric filters for security events."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-009", "SKIP", "no cloudtrail-trails evidence", [])

    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-009", "SKIP", "no cloudwatch-metric-filters evidence", [])

    # Find the local (non-org) CloudTrail-integrated log group name from the trail's ARN.
    # Org trails belong to a management account and cannot have metric filters added
    # from this account — always prefer non-org trails.
    ct_log_group: str = ""
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip organization trails — they're owned by a parent account
        if trail.get("IsOrganizationTrail"):
            continue
        if trail.get("CloudWatchLogsLogGroupArn"):
            arn = str(trail["CloudWatchLogsLogGroupArn"])
            # ARN format: arn:aws:logs:region:account:log-group:NAME:*
            parts = arn.split(":")
            if len(parts) >= 7:
                ct_log_group = parts[6]
                break

    if not ct_log_group:
        return PreCheckResult("ALRT-009", "SKIP", "no CloudTrail log group configured", [])

    filters_for_ct = [
        mf for mf in metric_filters
        if isinstance(mf, dict) and mf.get("logGroupName") == ct_log_group
    ]

    if filters_for_ct:
        return PreCheckResult(
            "ALRT-009",
            "PASS",
            f"{len(filters_for_ct)} metric filter(s) on CloudTrail log group '{ct_log_group}'",
            [],
        )
    return PreCheckResult(
        "ALRT-009",
        "FAIL",
        f"no metric filters on CloudTrail log group '{ct_log_group}'",
        [ct_log_group],
    )


@_register("alerting")
def check_alrt_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-017: CloudWatch log groups should have adequate retention (>=90 days)."""
    log_groups = evidence.get("cloudwatch-log-groups")
    if not isinstance(log_groups, list) or not log_groups:
        return PreCheckResult("ALRT-017", "SKIP", "no cloudwatch-log-groups evidence", [])

    short_retention: List[str] = []
    for lg in log_groups:
        if not isinstance(lg, dict):
            continue
        retention = lg.get("RetentionInDays")
        # None means "never expire" — acceptable
        if retention is not None and int(retention) < 90:
            short_retention.append(str(lg.get("LogGroupName") or "unknown"))

    if short_retention:
        return PreCheckResult(
            "ALRT-017",
            "FAIL",
            f"{len(short_retention)} log group(s) with retention < 90 days",
            short_retention[:15],
        )
    return PreCheckResult(
        "ALRT-017", "PASS", "all log groups have retention >= 90 days or unlimited", []
    )


@_register("alerting")
def check_alrt_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-010: CloudWatch alarms should not be in INSUFFICIENT_DATA state."""
    alarms = evidence.get("cloudwatch-alarms")
    if not isinstance(alarms, list) or not alarms:
        return PreCheckResult("ALRT-010", "SKIP", "no cloudwatch-alarms evidence", [])

    # Only check alarms that have a StateValue (collector must include it)
    alarms_with_state = [a for a in alarms if isinstance(a, dict) and a.get("StateValue")]
    if not alarms_with_state:
        return PreCheckResult(
            "ALRT-010", "SKIP", "no StateValue data in alarms (collector may not collect it)", []
        )

    insufficient = [
        str(a.get("AlarmName") or "unknown")
        for a in alarms_with_state
        if str(a.get("StateValue") or "").upper() == "INSUFFICIENT_DATA"
    ]

    if insufficient:
        return PreCheckResult(
            "ALRT-010",
            "FAIL",
            f"{len(insufficient)} alarm(s) in INSUFFICIENT_DATA state",
            insufficient[:10],
        )
    return PreCheckResult(
        "ALRT-010", "PASS", "no alarms in INSUFFICIENT_DATA state", []
    )


@_register("alerting")
def check_alrt_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-011: Alert SNS topics should restrict Publish to authorized principals."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-011", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    if not critical:
        return PreCheckResult(
            "ALRT-011", "SKIP", "no alert SNS topics found (no alarm/EB actions)", []
        )

    # Authorized publishers: CloudWatch Alarms and EventBridge services
    _AUTHORIZED_SERVICE_PRINCIPALS = {
        "cloudwatch.amazonaws.com",
        "events.amazonaws.com",
        "lambda.amazonaws.com",
    }

    broad_topics: List[str] = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:publish", "sns:*", "*"} for a in actions_list):
                continue
            principal = st.get("Principal")
            # PASS: service principal (e.g. cloudwatch.amazonaws.com)
            if isinstance(principal, dict):
                service = principal.get("Service")
                services = [service] if isinstance(service, str) else (service if isinstance(service, list) else [])
                if all(str(s) in _AUTHORIZED_SERVICE_PRINCIPALS for s in services if s):
                    continue
            # PASS: same-account restriction (Principal:* + SourceOwner condition) is
            # the AWS default policy. We only flag it if there is NO condition at all
            # or the condition does not restrict to same account.
            if _principal_is_wildcard_any(principal):
                if not _stmt_has_same_account_restriction(st):
                    broad_topics.append(arn)
                    break
                # Has same-account condition but still allows any IAM principal to Publish.
                # This is the AWS default policy — flag as informational (PASS here, LLM catches nuance)
                # We don't fail here because AWS auto-creates this policy for every new topic.

    if broad_topics:
        return PreCheckResult(
            "ALRT-011",
            "FAIL",
            f"{len(broad_topics)} alert topic(s) allow broad Publish without account restriction",
            broad_topics[:5],
        )
    return PreCheckResult(
        "ALRT-011", "PASS", "alert topics restrict Publish to authorized principals", []
    )


@_register("alerting")
def check_alrt_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-015: A metric filter should cover IAM change events."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-015", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = IAM events not monitored

    _IAM_EVENTS = [
        "putuseropolicy",
        "attachuserpolicy",
        "attachgrouppolicy",
        "putgrouppolicy",
        "putrolepolicy",
        "attachrolepolicy",
        "createaccesskey",
        "putuserpolicy",  # alternate casing
    ]

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        if any(event in pattern for event in _IAM_EVENTS):
            return PreCheckResult(
                "ALRT-015", "PASS", "metric filter covers IAM change events", []
            )

    return PreCheckResult(
        "ALRT-015",
        "FAIL",
        "no metric filter covering IAM change events (PutUserPolicy, AttachUserPolicy, etc.)",
        [],
    )


@_register("alerting")
def check_alrt_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-016: A metric filter should cover Security Group change events."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-016", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = SG events not monitored

    _SG_EVENTS = [
        "authorizesecuritygroupingress",
        "authorizesecuritygroupegress",
        "revokesecuritygroupingress",
        "revokesecuritygroupegress",
        "createsecuritygroup",
        "deletesecuritygroup",
    ]

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        if any(event in pattern for event in _SG_EVENTS):
            return PreCheckResult(
                "ALRT-016", "PASS", "metric filter covers Security Group change events", []
            )

    return PreCheckResult(
        "ALRT-016",
        "FAIL",
        "no metric filter covering Security Group change events (AuthorizeSecurityGroupIngress, etc.)",
        [],
    )


@_register("alerting")
def check_alrt_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-012: Critical security events (ConsoleLogin, CreateUser, StopLogging) should be alerted via metric filter or EventBridge rule."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    rules = evidence.get("eventbridge-rules")

    # Need at least one evidence source to evaluate
    if not isinstance(metric_filters, list) and not isinstance(rules, list):
        return PreCheckResult("ALRT-012", "SKIP", "no metric-filter or eventbridge evidence", [])

    _CRITICAL_EVENTS = ["consolelogin", "createuser", "stoplogging"]

    # Check metric filters for coverage
    if isinstance(metric_filters, list):
        for mf in metric_filters:
            if not isinstance(mf, dict):
                continue
            pattern = str(mf.get("filterPattern") or "").lower()
            if any(evt in pattern for evt in _CRITICAL_EVENTS):
                return PreCheckResult(
                    "ALRT-012",
                    "PASS",
                    "metric filter covers critical security events (ConsoleLogin/CreateUser/StopLogging)",
                    [],
                )

    # Check EventBridge rules for security event coverage
    if isinstance(rules, list):
        for r in rules:
            if not isinstance(r, dict):
                continue
            name = str(r.get("Name") or "")
            if name.startswith("DO-NOT-DELETE-Amazon"):
                continue
            if str(r.get("State") or "").upper() != "ENABLED":
                continue
            pattern = str(r.get("EventPattern") or "").lower()
            if any(evt in pattern for evt in _CRITICAL_EVENTS):
                return PreCheckResult(
                    "ALRT-012",
                    "PASS",
                    "EventBridge rule covers critical security events (ConsoleLogin/CreateUser/StopLogging)",
                    [],
                )

    return PreCheckResult(
        "ALRT-012",
        "FAIL",
        "no alert configured for critical events: ConsoleLogin, CreateUser, StopLogging",
        [],
    )


# ============================================================================
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
            if any(a in actions for a in ("s3:*", "s3:GetObject", "s3:ListBucket")):
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

    public = [i for i in rds_items if isinstance(i, dict) and i.get("PubliclyAccessible") is True]
    if not public:
        return PreCheckResult("EXP-002", "PASS", "no publicly accessible RDS", [])
    names = [p.get("DBInstanceIdentifier", "unknown") for p in public[:5]]
    return PreCheckResult("EXP-002", "FAIL", f"{len(public)} public RDS instances", names)


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

    exposed = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            if _sg_allows_world(perm, port=22) or _sg_allows_world(perm, port=3389):
                exposed.append(sg.get("GroupId", "unknown"))
                break

    if not exposed:
        return PreCheckResult("EXP-003", "PASS", "no SSH/RDP open to world", [])
    return PreCheckResult("EXP-003", "FAIL", f"{len(exposed)} SGs with SSH/RDP open", exposed[:10])


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
    for alb in internet_albs:
        arn = alb["LoadBalancerArn"]
        if not (by_alb.get(arn) or []):
            unprotected.append(arn)

    if not unprotected:
        return PreCheckResult("EXP-007", "PASS", "all internet ALBs have WAF", [])
    return PreCheckResult(
        "EXP-007", "FAIL", f"{len(unprotected)} ALBs without WAF", unprotected[:5]
    )


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
    missing = []
    for bn, b in by_name.items():
        if not isinstance(b, dict):
            continue
        policy = b.get("BucketPolicy")
        if not isinstance(policy, dict):
            missing.append(bn)
            continue
        has_tls = False
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Deny":
                continue
            cond = st.get("Condition")
            if isinstance(cond, dict):
                bl = cond.get("Bool")
                if isinstance(bl, dict) and bl.get("aws:SecureTransport") == "false":
                    has_tls = True
                    break
        if not has_tls:
            missing.append(bn)

    if not missing:
        return PreCheckResult("EXP-013", "PASS", "all buckets enforce TLS", [])
    return PreCheckResult(
        "EXP-013",
        "FAIL",
        f"{len(missing)} buckets without TLS enforcement",
        [f"arn:aws:s3:::{n}" for n in missing[:5]],
    )


@_register("exposure")
def check_exp_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 audit/log buckets should have versioning enabled."""
    s3_doc = evidence.get("s3-buckets")
    if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
        return PreCheckResult("EXP-014", "SKIP", "no indexed s3-buckets", [])

    by_name = s3_doc["by_name"]
    unversioned = []
    for bn, b in by_name.items():
        if not isinstance(b, dict):
            continue
        if (b.get("Versioning") or "") != "Enabled":
            unversioned.append(bn)

    if not unversioned:
        return PreCheckResult("EXP-014", "PASS", "all buckets have versioning", [])
    return PreCheckResult(
        "EXP-014",
        "FAIL",
        f"{len(unversioned)} buckets without versioning",
        [f"arn:aws:s3:::{n}" for n in unversioned[:5]],
    )


@_register("exposure")
def check_exp_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 cross-account bucket policy access."""
    s3_doc = evidence.get("s3-buckets")
    items = _items_from_doc(s3_doc)
    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
        items = list(s3_doc["by_name"].values())

    meta = evidence.get("_audit_metadata")
    audit_account = meta.get("_account_id") if isinstance(meta, dict) else None

    if not audit_account:
        return PreCheckResult("EXP-015", "SKIP", "no audit account metadata", [])

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
            if principal == "*":
                return PreCheckResult(
                    "EXP-015",
                    "FAIL",
                    f"bucket '{b.get('Name')}' has Principal:*",
                    [f"arn:aws:s3:::{b.get('Name', '')}"],
                )
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
                        return PreCheckResult(
                            "EXP-015",
                            "FAIL",
                            f"cross-account principal {p}",
                            # Include both bucket and cross-account principal for traceability
                            [f"arn:aws:s3:::{b.get('Name', '')}", p],
                        )

    return PreCheckResult("EXP-015", "PASS", "no cross-account S3 policies", [])


@_register("exposure")
def check_exp_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda function URLs without authentication (AuthType=NONE)."""
    urls_doc = evidence.get("lambda-function-urls")
    items = _items_from_doc(urls_doc)
    if not items:
        return PreCheckResult("EXP-016", "SKIP", "no lambda-function-urls evidence", [])

    unauth = [
        u for u in items
        if isinstance(u, dict) and str(u.get("AuthType") or "").upper() == "NONE"
    ]
    if not unauth:
        return PreCheckResult("EXP-016", "PASS", "all Lambda URLs have authorization", [])

    resources = [
        str(u.get("FunctionArn") or u.get("FunctionUrl") or "unknown")
        for u in unauth[:5]
    ]
    return PreCheckResult(
        "EXP-016",
        "FAIL",
        f"{len(unauth)} Lambda URL(s) without authorization",
        resources,
    )


@_register("exposure")
def check_exp_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 management/database ports (22, 3389, 3306, 5432) open to internet via SG."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())
    if not sgs:
        return PreCheckResult("EXP-004", "SKIP", "no security-groups evidence", [])

    MGMT_PORTS = {22, 3389, 3306, 5432, 1433}

    risky: List[str] = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = str(sg.get("GroupId") or "unknown")
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            if any(_sg_allows_world(perm, port=p) for p in MGMT_PORTS):
                risky.append(sg_id)
                break

    if not risky:
        return PreCheckResult("EXP-004", "PASS", "no management ports open to internet", [])
    return PreCheckResult(
        "EXP-004",
        "FAIL",
        f"{len(risky)} security group(s) with management/DB ports open to internet",
        risky[:10],
    )


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
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            for p in sensitive_ports:
                if _sg_allows_world(perm, port=p):
                    exposed.append(sg.get("GroupId", "unknown"))
                    break
            if sg.get("GroupId") in exposed:
                break

    if not exposed:
        return PreCheckResult("NET-001", "PASS", "no sensitive ports exposed", [])
    return PreCheckResult("NET-001", "FAIL", f"{len(exposed)} SGs with exposed ports", exposed[:10])


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

    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        all_rules = (sg.get("IngressRules", []) or []) + (sg.get("EgressRules", []) or [])
        for perm in all_rules:
            if isinstance(perm, dict) and _perm_matches_critical(perm) and _has_missing_desc(perm):
                return PreCheckResult(
                    "NET-011",
                    "FAIL",
                    f"SG {sg.get('GroupId')} has undescribed critical rules",
                    [sg.get("GroupId", "unknown")],
                )

    return PreCheckResult("NET-011", "PASS", "all critical rules have descriptions", [])


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


# ============================================================================
# WAF PRE-CHECKS
# ============================================================================


def _waf_collection_has_failures(evidence: Dict[str, Any]) -> bool:
    """Check if WAF collection status indicates failures."""
    coll_status = evidence.get("waf-collection-status")
    if not isinstance(coll_status, dict):
        return False
    try:
        if (coll_status.get("cloudfront") or {}).get("ok") is False:
            return True
        if ((coll_status.get("wafv2") or {}).get("CLOUDFRONT") or {}).get("ok") is False:
            return True
        for _, r in (
            ((coll_status.get("wafv2") or {}).get("REGIONAL") or {}).get("regions", {}).items()
        ):
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        for _, r in (coll_status.get("alb") or {}).get("regions", {}).items():
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        for _, r in (coll_status.get("api_entrypoints") or {}).items():
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        if (coll_status.get("waf_classic") or {}).get("ok") is False:
            return True
    except Exception:
        return False
    return False


@_register("waf")
def check_waf_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Internet-facing ALBs should have WAF protection."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-001", "SKIP", "WAF collection failures (WAF-013)", [])
    albs = evidence.get("alb-waf-associations")
    if not isinstance(albs, list) or len(albs) == 0:
        return PreCheckResult("WAF-001", "PASS", "no internet-facing ALBs detected", [])
    # Full deterministic check: WAFv2WebACL must be a dict without 'error' key
    unprotected = [
        a.get("LoadBalancerArn") or a.get("LoadBalancerName", "unknown")
        for a in albs
        if not isinstance(a.get("WAFv2WebACL"), dict)
        or "error" in (a.get("WAFv2WebACL") or {})
        or not a.get("WAFv2WebACL")
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-001", "FAIL",
            f"{len(unprotected)} internet-facing ALB(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-001", "PASS", "all internet-facing ALBs are WAF-protected", [])


@_register("waf")
def check_waf_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudFront distributions should have WAF protection."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-002", "SKIP", "WAF collection failures (WAF-013)", [])
    dists = evidence.get("cloudfront-distributions")
    if not isinstance(dists, list) or len(dists) == 0:
        return PreCheckResult("WAF-002", "PASS", "no CloudFront distributions detected", [])
    # Full deterministic check: WebACLId must be non-empty
    unprotected = [
        d.get("DomainName") or d.get("Id", "unknown")
        for d in dists
        if not d.get("WebACLId")
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-002", "FAIL",
            f"{len(unprotected)} CloudFront distribution(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-002", "PASS", "all CloudFront distributions are WAF-protected", [])


@_register("waf")
def check_waf_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAFv2 Web ACL logging should be enabled."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-003", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-003", "PASS", "no Web ACLs (N/A)", [])
    not_logging = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not (acl.get("Logging") or {}).get("enabled", False)
    ]
    if not_logging:
        return PreCheckResult(
            "WAF-003", "FAIL",
            f"{len(not_logging)} Web ACL(s) without logging enabled",
            not_logging[:5],
        )
    return PreCheckResult("WAF-003", "PASS", "all Web ACLs have logging enabled", [])


@_register("waf")
def check_waf_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF logging RedactedFields should cover sensitive headers."""
    _SENSITIVE_HEADERS = {"cookie", "x-api-key", "authorization", "x-auth-token"}
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-004", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-004", "PASS", "no Web ACLs (N/A)", [])
    incomplete: list = []
    all_missing: set = set()
    for acl in web_acls:
        logging_cfg = acl.get("Logging") or {}
        if not logging_cfg.get("enabled", False):
            continue  # WAF-003 covers disabled logging
        redacted = {
            (r.get("SingleHeader") or {}).get("Name", "").lower()
            for r in (logging_cfg.get("RedactedFields") or [])
        }
        missing = _SENSITIVE_HEADERS - redacted
        if missing:
            all_missing |= missing
            incomplete.append(acl.get("ARN") or acl.get("Name", "unknown"))
    if incomplete:
        missing_str = "/".join(sorted(all_missing))
        return PreCheckResult(
            "WAF-004", "FAIL",
            f"{len(incomplete)} Web ACL(s) with incomplete log redaction (missing: {missing_str})",
            incomplete[:5],
        )
    return PreCheckResult("WAF-004", "PASS", "all Web ACLs have complete log redaction", [])


@_register("waf")
def check_waf_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACL VisibilityConfig should have SampledRequestsEnabled=true."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-005", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-005", "PASS", "no Web ACLs (N/A)", [])
    failing = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not (acl.get("WebACL") or {})
        .get("VisibilityConfig", {})
        .get("SampledRequestsEnabled", True)
    ]
    if failing:
        return PreCheckResult(
            "WAF-005", "FAIL",
            f"{len(failing)} Web ACL(s) with SampledRequestsEnabled=false",
            failing[:5],
        )
    return PreCheckResult("WAF-005", "PASS", "all Web ACLs have sampled requests enabled", [])


_WAF_BASELINE_MANAGED_RULES = {
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
}


@_register("waf")
def check_waf_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs should include at least one baseline AWS Managed Rule group."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-006", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-006", "PASS", "no Web ACLs (N/A)", [])
    missing_baseline = []
    for acl in web_acls:
        rules = (acl.get("WebACL") or {}).get("Rules", [])
        used_managed = {
            (r.get("Statement") or {})
            .get("ManagedRuleGroupStatement", {})
            .get("Name", "")
            for r in rules
        }
        if not used_managed & _WAF_BASELINE_MANAGED_RULES:
            missing_baseline.append(acl.get("ARN") or acl.get("Name", "unknown"))
    if missing_baseline:
        return PreCheckResult(
            "WAF-006", "FAIL",
            f"{len(missing_baseline)} Web ACL(s) lack baseline AWS Managed Rules",
            missing_baseline[:5],
        )
    return PreCheckResult("WAF-006", "PASS", "all Web ACLs have baseline managed rules", [])


@_register("waf")
def check_waf_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Managed rule groups should not be overridden to Count-only mode in production."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-007", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-007", "PASS", "no Web ACLs (N/A)", [])
    count_only: list = []
    for acl in web_acls:
        rules = (acl.get("WebACL") or {}).get("Rules", [])
        for rule in rules:
            override = rule.get("OverrideAction") or {}
            if "Count" in override:
                count_only.append(f"{acl.get('Name', 'unknown')}/{rule.get('Name', 'unknown')}")
    if count_only:
        return PreCheckResult(
            "WAF-007", "FAIL",
            f"{len(count_only)} managed rule group(s) in Count-only mode",
            count_only[:5],
        )
    return PreCheckResult("WAF-007", "PASS", "no managed rule groups in Count-only mode", [])


@_register("waf")
def check_waf_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs should include at least one rate-based rule to limit abuse."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-008", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-008", "PASS", "no Web ACLs (N/A)", [])
    no_rate_rules = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not any(
            "RateBasedStatement" in (r.get("Statement") or {})
            for r in (acl.get("WebACL") or {}).get("Rules", [])
        )
    ]
    if no_rate_rules:
        return PreCheckResult(
            "WAF-008", "FAIL",
            f"{len(no_rate_rules)} Web ACL(s) without rate-based rules",
            no_rate_rules[:5],
        )
    return PreCheckResult("WAF-008", "PASS", "all Web ACLs have rate-based rules", [])


@_register("waf")
def check_waf_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF IP sets should not contain overly broad CIDRs (0.0.0.0/0 or ::/0)."""
    _BROAD_CIDRS = {"0.0.0.0/0", "::/0"}
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-009", "SKIP", "WAF collection failures", [])
    ip_sets = evidence.get("wafv2-ip-sets")
    if not isinstance(ip_sets, list) or len(ip_sets) == 0:
        return PreCheckResult("WAF-009", "PASS", "no WAFv2 IP sets", [])
    broad = [
        ip_set.get("Name", "unknown")
        for ip_set in ip_sets
        if _BROAD_CIDRS & set(ip_set.get("Addresses", []))
    ]
    if broad:
        return PreCheckResult(
            "WAF-009", "FAIL",
            f"{len(broad)} IP set(s) with broad CIDRs (0.0.0.0/0 or ::/0)",
            broad[:5],
        )
    return PreCheckResult("WAF-009", "PASS", "no IP sets with broad CIDRs", [])


@_register("waf")
def check_waf_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF Classic Web ACLs should be migrated to WAFv2."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-010", "SKIP", "WAF collection failures", [])
    classic = evidence.get("waf-classic") or {}
    global_acls = (classic.get("global") or {}).get("web_acls", [])
    regional_acls: list = []
    for region_data in (classic.get("regional") or {}).values():
        regional_acls.extend((region_data or {}).get("web_acls", []))
    total = len(global_acls) + len(regional_acls)
    if total > 0:
        names = [a.get("Name", "unknown") for a in global_acls + regional_acls]
        return PreCheckResult(
            "WAF-010", "FAIL",
            f"{total} WAF Classic Web ACL(s) detected; migrate to WAFv2",
            names[:5],
        )
    return PreCheckResult("WAF-010", "PASS", "no WAF Classic Web ACLs detected", [])


@_register("waf")
def check_waf_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs with no associated resources should be reviewed for cleanup."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-011", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-011", "PASS", "no Web ACLs (N/A)", [])
    unassociated = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not acl.get("AssociatedResourceArns")
    ]
    if unassociated:
        return PreCheckResult(
            "WAF-011", "FAIL",
            f"{len(unassociated)} Web ACL(s) with no associated resources",
            unassociated[:5],
        )
    return PreCheckResult("WAF-011", "PASS", "all Web ACLs have associated resources", [])


@_register("waf")
def check_waf_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF collection status indicates failures or unverifiable associations."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-013", "FAIL", "WAF collection has failures", [])
    # Detect HTTP API entries where GetWebACLForResource returned WAFInvalidParameterException.
    # This is an AWS SDK limitation: HTTP API V2 ARNs are not supported by that API call.
    # These endpoints have UNKNOWN WAF protection status and should be noted.
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if isinstance(api_eps, list):
        http_api_errors = [
            f"{e.get('Name', 'unknown')}/{e.get('Stage', '')}"
            for e in api_eps
            if e.get("ApiType") == "HTTP"
            and isinstance(e.get("WAFv2WebACL"), dict)
            and "error" in e["WAFv2WebACL"]
        ]
        if http_api_errors:
            return PreCheckResult(
                "WAF-013", "FAIL",
                f"WAF status unverifiable for {len(http_api_errors)} HTTP API stage(s) "
                f"(AWS GetWebACLForResource does not support HTTP API V2 ARN format): "
                f"{', '.join(http_api_errors[:3])}",
                http_api_errors[:5],
            )
    return PreCheckResult("WAF-013", "PASS", "no WAF collection failures", [])


@_register("waf")
def check_waf_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """API Gateway REST stages should be protected by AWS WAF."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-014", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-014", "SKIP", "no api-entrypoints evidence", [])
    # Only evaluate REST APIs (HTTP APIs return WAFInvalidParameterException — AWS limitation)
    rest_entries = [e for e in api_eps if e.get("Service") == "apigateway" and e.get("ApiType") == "REST"]
    if not rest_entries:
        return PreCheckResult("WAF-014", "PASS", "no API Gateway REST stages detected", [])
    unprotected = [
        f"{e.get('Name', 'unknown')}/{e.get('Stage', '')}"
        for e in rest_entries
        if not isinstance(e.get("WAFv2WebACL"), dict)
        or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-014", "FAIL",
            f"{len(unprotected)} API Gateway REST stage(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-014", "PASS", "all API Gateway REST stages are WAF-protected", [])


@_register("waf")
def check_waf_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """AppSync GraphQL APIs should be protected by AWS WAF."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-015", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-015", "SKIP", "no api-entrypoints evidence", [])
    appsync_entries = [e for e in api_eps if e.get("Service") == "appsync"]
    if not appsync_entries:
        return PreCheckResult("WAF-015", "PASS", "no AppSync APIs detected (N/A)", [])
    unprotected = [
        e.get("Name", e.get("ApiId", "unknown"))
        for e in appsync_entries
        if not isinstance(e.get("WAFv2WebACL"), dict)
        or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-015", "FAIL",
            f"{len(unprotected)} AppSync API(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-015", "PASS", "all AppSync APIs are WAF-protected", [])


@_register("waf")
def check_waf_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Cognito User Pools should be protected by AWS WAF when publicly exposed."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-016", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-016", "SKIP", "no api-entrypoints evidence", [])
    cognito_entries = [e for e in api_eps if e.get("Service") == "cognito"]
    if not cognito_entries:
        return PreCheckResult("WAF-016", "PASS", "no Cognito User Pools detected (N/A)", [])
    unprotected = [
        e.get("Name", e.get("ApiId", "unknown"))
        for e in cognito_entries
        if not isinstance(e.get("WAFv2WebACL"), dict)
        or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-016", "FAIL",
            f"{len(unprotected)} Cognito User Pool(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-016", "PASS", "all Cognito User Pools are WAF-protected", [])


# ============================================================================
# VULNS PRE-CHECKS
# ============================================================================


@_register("vulns")
def check_vuln_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Inspector v2 should be enabled (inferred from inspector-findings presence)."""
    findings = evidence.get("inspector-findings")
    if isinstance(findings, list):
        # Collector successfully queried Inspector v2 → service is enabled
        return PreCheckResult(
            "VULN-001", "PASS",
            f"Inspector v2 is enabled ({len(findings)} finding(s) returned)", [],
        )
    return PreCheckResult("VULN-001", "SKIP", "no inspector-findings evidence to determine status", [])


@_register("vulns")
def check_vuln_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """CRITICAL CVEs not remediated — scan inspector-findings for CRITICAL+ACTIVE entries."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-002", "SKIP", "no inspector-findings evidence", [])

    critical_active = [
        f.get("resources", [{}])[0].get("id", "unknown")
        for f in findings
        if isinstance(f, dict)
        and str(f.get("severity", "")).upper() == "CRITICAL"
        and str(f.get("status", "")).upper() == "ACTIVE"
    ]

    if not critical_active:
        return PreCheckResult("VULN-002", "PASS", "no CRITICAL active Inspector findings", [])
    return PreCheckResult(
        "VULN-002", "FAIL",
        f"{len(critical_active)} CRITICAL active Inspector finding(s)",
        critical_active[:10],
    )


@_register("vulns")
def check_vuln_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """Multiple CVEs on same resource — count ACTIVE Inspector findings per resource."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list) or not findings:
        return PreCheckResult("VULN-009", "SKIP", "no inspector-findings evidence", [])

    from collections import Counter

    resource_counts: Counter = Counter()
    for f in findings:
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        for res in f.get("resources", []):
            rid = res.get("id") if isinstance(res, dict) else None
            if rid:
                resource_counts[rid] += 1

    multi_vuln = {rid: cnt for rid, cnt in resource_counts.items() if cnt >= 3}
    if not multi_vuln:
        return PreCheckResult("VULN-009", "PASS", "no resource has 3+ active CVEs", [])

    top = sorted(multi_vuln.items(), key=lambda x: x[1], reverse=True)
    resources = [f"{rid} ({cnt} CVEs)" for rid, cnt in top[:5]]
    return PreCheckResult(
        "VULN-009", "FAIL",
        f"{len(multi_vuln)} resource(s) with 3+ active CVEs",
        resources,
    )


@_register("vulns")
def check_vuln_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect EC2 instances with IMDSv1/optional tokens enabled."""
    imds_doc = evidence.get("imds-configuration") or {}
    items = imds_doc.get("items") if isinstance(imds_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-022", "SKIP", "no imds-configuration evidence", [])

    vulnerable = []
    for it in items:
        if not isinstance(it, dict):
            continue
        if it.get("VulnerableToSSRF"):
            iid = it.get("InstanceId", "unknown")
            vulnerable.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not vulnerable:
        return PreCheckResult("VULN-022", "PASS", "all instances require IMDSv2", [])
    return PreCheckResult(
        "VULN-022",
        "FAIL",
        f"{len(vulnerable)} instances with IMDSv1/optional metadata tokens",
        vulnerable[:10],
    )


@_register("vulns")
def check_vuln_023(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect EC2 user-data scripts containing likely secrets."""
    user_data_doc = evidence.get("ec2-user-data") or {}
    items = user_data_doc.get("items") if isinstance(user_data_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-023", "SKIP", "no ec2-user-data evidence", [])

    exposed = []
    for it in items:
        if not isinstance(it, dict):
            continue
        flags = it.get("ContainsSecrets")
        if not isinstance(flags, dict):
            continue
        if any(bool(v) for v in flags.values()):
            iid = it.get("InstanceId", "unknown")
            exposed.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not exposed:
        return PreCheckResult("VULN-023", "PASS", "no user-data secret patterns detected", [])
    return PreCheckResult(
        "VULN-023", "FAIL", f"{len(exposed)} instances with secret-like user-data", exposed[:10]
    )


@_register("vulns")
def check_vuln_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect Lambda functions with potentially sensitive env var keys."""
    env_doc = evidence.get("lambda-environment-variables") or {}
    items = env_doc.get("items") if isinstance(env_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-024", "SKIP", "no lambda-environment-variables evidence", [])

    exposed = []
    for it in items:
        if not isinstance(it, dict):
            continue
        keys = it.get("PotentialSecretKeys")
        if isinstance(keys, list) and len(keys) > 0:
            arn = it.get("FunctionArn") or f"lambda/{it.get('FunctionName', 'unknown')}"
            exposed.append(str(arn))

    if not exposed:
        return PreCheckResult("VULN-024", "PASS", "no sensitive Lambda env keys detected", [])
    return PreCheckResult(
        "VULN-024", "FAIL", f"{len(exposed)} Lambda functions with sensitive env keys", exposed[:10]
    )


@_register("vulns")
def check_vuln_025(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect over-privileged instance profiles via attached policy names."""
    prof_doc = evidence.get("instance-profiles-permissions") or {}
    items = prof_doc.get("items") if isinstance(prof_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-025", "SKIP", "no instance-profiles-permissions evidence", [])

    risky_tokens = ["administratoraccess", "admin", "poweruser", "fullaccess"]
    affected = []

    for item in items:
        if not isinstance(item, dict):
            continue
        roles = item.get("Roles")
        if not isinstance(roles, list):
            continue
        for role in roles:
            if not isinstance(role, dict):
                continue
            attached = role.get("AttachedPolicies")
            if not isinstance(attached, list):
                continue
            for pol in attached:
                if not isinstance(pol, dict):
                    continue
                name = str(pol.get("PolicyName") or "").lower()
                if any(tok in name for tok in risky_tokens):
                    role_arn = role.get("RoleArn") or role.get("RoleName") or "unknown-role"
                    affected.append(str(role_arn))
                    break

    if not affected:
        return PreCheckResult(
            "VULN-025", "PASS", "no over-privileged instance profiles detected", []
        )
    return PreCheckResult(
        "VULN-025",
        "FAIL",
        f"{len(affected)} instance-profile roles with over-privileged policies",
        affected[:10],
    )


@_register("vulns")
def check_vuln_028(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect public EBS snapshots (createVolumePermission Group=all)."""
    snap_doc = evidence.get("ebs-snapshot-sharing") or {}
    items = snap_doc.get("items") if isinstance(snap_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-028", "SKIP", "no ebs-snapshot-sharing evidence", [])

    public_ids = []
    for it in items:
        if not isinstance(it, dict):
            continue
        if bool(it.get("IsPublic")):
            sid = str(it.get("SnapshotId") or "unknown")
            public_ids.append(sid)

    if not public_ids:
        return PreCheckResult("VULN-028", "PASS", "no public EBS snapshots detected", [])
    return PreCheckResult(
        "VULN-028", "FAIL", f"{len(public_ids)} public EBS snapshots", public_ids[:10]
    )


@_register("vulns")
def check_vuln_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-004: CVEs with known active exploit (exploitAvailable=YES + status=ACTIVE)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-004", "SKIP", "no inspector-findings evidence", [])

    exploitable = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if (
            str(f.get("exploitAvailable", "")).upper() == "YES"
            and str(f.get("status", "")).upper() == "ACTIVE"
        ):
            title = f.get("title", "unknown")
            resources = f.get("resources", [])
            rid = resources[0].get("id", "unknown") if resources else "unknown"
            exploitable.append(f"{title} @ {rid}")

    if not exploitable:
        return PreCheckResult("VULN-004", "PASS", "no actively exploitable CVEs detected", [])
    return PreCheckResult(
        "VULN-004",
        "FAIL",
        f"{len(exploitable)} CVE(s) with known active exploit and ACTIVE status",
        exploitable[:10],
    )


@_register("vulns")
def check_vuln_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-006: EC2 scanning by Inspector (inferred from EC2 findings presence)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-006", "SKIP", "no inspector-findings evidence", [])

    ec2_resources = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for res in f.get("resources", []):
            if isinstance(res, dict) and str(res.get("type", "")).upper() == "AWS_EC2_INSTANCE":
                rid = res.get("id", "unknown")
                if rid not in ec2_resources:
                    ec2_resources.append(rid)

    if ec2_resources:
        return PreCheckResult(
            "VULN-006",
            "PASS",
            f"Inspector EC2 scanning active ({len(ec2_resources)} instance(s) scanned)",
            ec2_resources[:5],
        )
    return PreCheckResult(
        "VULN-006", "SKIP", "no EC2 findings in inspector-findings — cannot confirm EC2 scanning status", []
    )


@_register("vulns")
def check_vuln_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-007: ECR container scanning by Inspector (inferred from ECR findings presence)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-007", "SKIP", "no inspector-findings evidence", [])

    ecr_resources = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for res in f.get("resources", []):
            if isinstance(res, dict) and str(res.get("type", "")).upper() == "AWS_ECR_CONTAINER_IMAGE":
                rid = res.get("id", "unknown")
                if rid not in ecr_resources:
                    ecr_resources.append(rid)

    if ecr_resources:
        return PreCheckResult(
            "VULN-007",
            "PASS",
            f"Inspector ECR scanning active ({len(ecr_resources)} image(s) scanned)",
            ecr_resources[:5],
        )
    return PreCheckResult(
        "VULN-007", "SKIP", "no ECR findings in inspector-findings — cannot confirm ECR scanning status", []
    )


@_register("vulns")
def check_vuln_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-008: HIGH severity vulnerabilities without remediation plan (accurate count)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-008", "SKIP", "no inspector-findings evidence", [])

    high_active = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if (
            str(f.get("severity", "")).upper() == "HIGH"
            and str(f.get("status", "")).upper() == "ACTIVE"
        ):
            resources = f.get("resources", [])
            rid = resources[0].get("id", "unknown") if resources else "unknown"
            high_active.append(rid)

    if not high_active:
        return PreCheckResult("VULN-008", "PASS", "no ACTIVE HIGH Inspector findings", [])

    unique_resources = list(dict.fromkeys(high_active))
    return PreCheckResult(
        "VULN-008",
        "FAIL",
        f"{len(high_active)} ACTIVE HIGH Inspector finding(s) across {len(unique_resources)} resource(s) — no remediation plan evident",
        unique_resources[:10],
    )


# ============================================================================
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
                    f"secret has Principal:*",
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

    # AWS-managed key indicators
    _aws_kms_patterns = ("alias/aws/secretsmanager", "aws/secretsmanager", "Default AWS managed")

    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and any(p in str(s.get("KmsKeyId") or "") for p in _aws_kms_patterns)
    ]
    if not failed:
        return PreCheckResult("SM-004", "PASS", "all secrets use customer-managed KMS keys", [])
    return PreCheckResult(
        "SM-004",
        "FAIL",
        f"{len(failed)} secret(s) use AWS-managed KMS key (not customer-managed)",
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

        # Case 1: LastRotatedDate is empty/null = never rotated (always FAIL)
        last_rotated = str(s.get("LastRotatedDate") or "").strip()
        rotation_enabled = bool(s.get("RotationEnabled"))
        if not last_rotated and not rotation_enabled:
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
        return PreCheckResult("SM-008", "PASS", "secrets have cross-region replication or are non-prod", [])
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
            for _op, kv in (cond.items() if isinstance(cond, dict) else []):
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
        )
    return PreCheckResult(
        "SM-012",
        "PASS",
        f"rotation monitoring found: {cw_relevant} CW alarm(s), {eb_relevant} EventBridge rule(s)",
        [],
    )


# ============================================================================
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
                    f"repo has Principal:*",
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
        return PreCheckResult(
            "KMS-002",
            "FAIL",
            f"unexpected sensitive grant {grant_id} on {key_id}",
            [key_id],
        )

    return PreCheckResult("KMS-002", "PASS", "no sensitive grants", [])


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

    return PreCheckResult("KMS-005", "PASS", "no destructive key actions to non-root principals", [])


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
# MESSAGING PRE-CHECKS
# ============================================================================


@_register("messaging")
def check_msg_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """SQS queue policy should include OrgID condition."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-001", "SKIP", "no sqs-queues evidence", [])

    for q in items:
        if not isinstance(q, dict):
            continue
        pol = q.get("Policy")
        if not isinstance(pol, dict):
            continue
        cond_text = json.dumps(pol, default=str)
        if "aws:PrincipalOrgID" in cond_text or "aws:PrincipalOrgId" in cond_text:
            return PreCheckResult("MSG-001", "PASS", "OrgID condition found", [])

    # No OrgID found → FAIL (if queues have policies)
    has_policy = any(isinstance(q, dict) and q.get("Policy") for q in items)
    if has_policy:
        return PreCheckResult("MSG-001", "FAIL", "no aws:PrincipalOrgID in queue policies", [])
    return PreCheckResult("MSG-001", "SKIP", "no queue policies to evaluate", [])


@_register("messaging")
def check_msg_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """DLQ/Redrive configuration presence."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-002", "SKIP", "no sqs-queues evidence", [])

    for q in items:
        if isinstance(q, dict) and (q.get("RedrivePolicy") or q.get("RedriveAllowPolicy")):
            return PreCheckResult("MSG-002", "PASS", "redrive config present", [])

    return PreCheckResult("MSG-002", "FAIL", "no redrive configuration", [])


@_register("messaging")
def check_msg_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS->SQS injection: SendMessage from SNS without SourceArn/SourceAccount."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-003", "SKIP", "no sqs-queues evidence", [])

    for q in items:
        if not isinstance(q, dict):
            continue
        pol = q.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            # Check action includes SendMessage
            acts = _actions_from_stmt(st)
            has_send = any(a.lower() in {"sqs:sendmessage", "sqs:*", "*"} for a in acts)
            if not has_send:
                continue
            # Check principal is SNS
            principal = st.get("Principal")
            if isinstance(principal, dict):
                svc = principal.get("Service")
                if isinstance(svc, str) and svc.lower() == "sns.amazonaws.com":
                    pass
                elif isinstance(svc, list) and any(
                    isinstance(x, str) and x.lower() == "sns.amazonaws.com" for x in svc
                ):
                    pass
                else:
                    continue
            else:
                continue
            # Check missing SourceArn/SourceAccount
            cond = st.get("Condition")
            cond_text = json.dumps(cond, default=str) if isinstance(cond, dict) else ""
            if "aws:SourceArn" not in cond_text and "aws:SourceAccount" not in cond_text:
                return PreCheckResult(
                    "MSG-003",
                    "FAIL",
                    "SNS->SQS without SourceArn check",
                    [q.get("QueueUrl", q.get("QueueArn", "unknown"))],
                )

    return PreCheckResult("MSG-003", "PASS", "SNS->SQS policies have proper conditions", [])


@_register("messaging")
def check_msg_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Message move task risk (only applies when DLQs exist)."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-004", "SKIP", "no sqs-queues evidence", [])

    has_dlq = any(isinstance(q, dict) and q.get("RedrivePolicy") for q in items)
    if not has_dlq:
        return PreCheckResult("MSG-004", "PASS", "no DLQs configured (N/A)", [])
    return PreCheckResult("MSG-004", "SKIP", "requires AI analysis of DLQ security", [])


@_register("messaging")
def check_msg_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Wildcard principals should not have SQS data-plane actions."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-005", "SKIP", "no sqs-queues evidence", [])

    risky_actions = {
        "sqs:sendmessage",
        "sqs:sendmessagebatch",
        "sqs:receivemessage",
        "sqs:deletemessage",
        "sqs:changemessagevisibility",
        "sqs:*",
        "*",
    }

    for q in items:
        if not isinstance(q, dict):
            continue
        pol = q.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            if not (actions & risky_actions):
                continue
            if _principal_is_wildcard_any(st.get("Principal")):
                return PreCheckResult(
                    "MSG-005",
                    "FAIL",
                    "queue policy allows wildcard principal data-plane actions",
                    [str(q.get("QueueArn") or q.get("QueueUrl") or "unknown")],
                )

    return PreCheckResult("MSG-005", "PASS", "no wildcard data-plane access in SQS policies", [])


@_register("messaging")
def check_msg_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """SQS queues should have encryption enabled."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-006", "SKIP", "no sqs-queues evidence", [])

    unencrypted = []
    for q in items:
        if not isinstance(q, dict):
            continue
        kms = q.get("KmsMasterKeyId")
        sse = str(q.get("SqsManagedSseEnabled") or "").lower() == "true"
        if not kms and not sse:
            unencrypted.append(str(q.get("QueueArn") or q.get("QueueUrl") or "unknown"))

    if not unencrypted:
        return PreCheckResult("MSG-006", "PASS", "all queues encrypted at rest", [])
    return PreCheckResult(
        "MSG-006", "FAIL", f"{len(unencrypted)} queues without encryption", unencrypted[:10]
    )


@_register("messaging")
def check_msg_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS topics should not allow wildcard Subscribe."""
    t_doc = evidence.get("sns-topics")
    items = t_doc.get("items") if isinstance(t_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-007", "SKIP", "no sns-topics evidence", [])

    for t in items:
        if not isinstance(t, dict):
            continue
        attrs = t.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        pol = attrs.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            if not ({"sns:subscribe", "sns:*", "*"} & actions):
                continue
            if _principal_is_wildcard_any(st.get("Principal")) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "MSG-007",
                    "FAIL",
                    "topic policy allows wildcard Subscribe",
                    [str(t.get("TopicArn") or "unknown")],
                )

    return PreCheckResult("MSG-007", "PASS", "no wildcard Subscribe in SNS topic policies", [])


@_register("messaging")
def check_msg_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS topics should not allow wildcard Publish."""
    t_doc = evidence.get("sns-topics")
    items = t_doc.get("items") if isinstance(t_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-008", "SKIP", "no sns-topics evidence", [])

    for t in items:
        if not isinstance(t, dict):
            continue
        attrs = t.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        pol = attrs.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            if not ({"sns:publish", "sns:*", "*"} & actions):
                continue
            if _principal_is_wildcard_any(st.get("Principal")) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "MSG-008",
                    "FAIL",
                    "topic policy allows wildcard Publish",
                    [str(t.get("TopicArn") or "unknown")],
                )

    return PreCheckResult("MSG-008", "PASS", "no wildcard Publish in SNS topic policies", [])


@_register("messaging")
def check_msg_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS topic policy grants administrative actions (DeleteTopic, SetTopicAttributes,
    AddPermission, RemovePermission) to a wildcard principal."""
    _ADMIN_ACTIONS = {
        "sns:deletetopic",
        "sns:settopicattributes",
        "sns:addpermission",
        "sns:removepermission",
        "sns:*",
        "*",
    }
    t_doc = evidence.get("sns-topics")
    items = t_doc.get("items") if isinstance(t_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-009", "SKIP", "no sns-topics evidence", [])

    for t in items:
        if not isinstance(t, dict):
            continue
        attrs = t.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        pol = attrs.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            matched = _ADMIN_ACTIONS & actions
            if not matched:
                continue
            if _principal_is_wildcard_any(st.get("Principal")) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "MSG-009",
                    "FAIL",
                    f"topic policy allows wildcard principal to perform admin actions: {sorted(matched)}",
                    [str(t.get("TopicArn") or "unknown")],
                )

    return PreCheckResult("MSG-009", "PASS", "no wildcard admin actions in SNS topic policies", [])


# ============================================================================
# CICD PRE-CHECKS
# ============================================================================


@_register("cicd")
def check_cicd_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """CodeBuild source credentials exist."""
    sc_doc = evidence.get("codebuild-source-credentials")
    items = sc_doc.get("items") if isinstance(sc_doc, dict) else None
    if not isinstance(items, list) or len(items) == 0:
        return PreCheckResult("CICD-001", "PASS", "no CodeBuild source credentials", [])
    return PreCheckResult("CICD-001", "FAIL", f"{len(items)} source credentials found", [])


@_register("cicd")
def check_cicd_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Insecure SSL or proxy config in CodeBuild projects."""
    proj_doc = evidence.get("codebuild-projects")
    items = proj_doc.get("items") if isinstance(proj_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("CICD-002", "SKIP", "no codebuild-projects evidence", [])

    for p in items:
        if not isinstance(p, dict):
            continue
        source = p.get("source") or {}
        if isinstance(source, dict) and source.get("insecureSsl") is True:
            return PreCheckResult(
                "CICD-002",
                "FAIL",
                f"project has insecureSsl=true",
                [p.get("arn", p.get("name", "unknown"))],
            )
        env = p.get("environment") or {}
        if isinstance(env, dict):
            evs = env.get("environmentVariables")
            if isinstance(evs, list):
                for ev in evs:
                    if isinstance(ev, dict) and ev.get("looks_like_proxy") is True:
                        return PreCheckResult(
                            "CICD-002",
                            "FAIL",
                            "project has proxy-like env vars",
                            [p.get("arn", p.get("name", "unknown"))],
                        )

    return PreCheckResult("CICD-002", "PASS", "no insecure SSL/proxy config", [])


# ============================================================================
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

    _SECRET_KEYWORDS = _re.compile(
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
                if _SECRET_KEYWORDS.search(name) and len(value) > 4:
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
