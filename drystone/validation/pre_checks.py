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
                uname = u.get("UserName", u.get("Arn", "unknown"))
                old_users.append(f"arn:aws:iam::*:user/{uname}")
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
            uname = u.get("UserName", "unknown")
            ungrouped.append(f"arn:aws:iam::*:user/{uname}")

    if not ungrouped:
        return PreCheckResult("IAM-020", "PASS", "all users belong to groups", [])
    return PreCheckResult(
        "IAM-020", "FAIL", f"{len(ungrouped)} users without groups", ungrouped[:10]
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

    for r in roles:
        if not isinstance(r, dict):
            continue
        role_arn = str(r.get("Arn") or "")
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
                return PreCheckResult(
                    "IAM-033",
                    "FAIL",
                    "cross-account trust without sts:ExternalId",
                    [role_arn or f"role/{r.get('RoleName', 'unknown')}"],
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
    enabled_standards = evidence.get("security-hub-enabled-standards", [])
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-013", "SKIP", "no standards evidence", [])

    outdated_keywords = ["v1.2.0", "v1.3.0", "2016", "2017"]
    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        arn = str(std.get("StandardsArn") or std.get("StandardsSubscriptionArn") or "")
        for kw in outdated_keywords:
            if kw in arn:
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
def check_alr_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudTrail should be enabled."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list):
        trails = []
    if len(trails) > 0:
        return PreCheckResult("ALR-001", "PASS", f"{len(trails)} trails enabled", [])
    return PreCheckResult("ALR-001", "FAIL", "no CloudTrail trails", [])


@_register("alerting")
def check_alr_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudTrail should have CloudWatch Logs integration."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or len(trails) == 0:
        return PreCheckResult("ALR-003", "SKIP", "no trails (ALR-001 applies)", [])

    for trail in trails:
        if isinstance(trail, dict) and trail.get("CloudWatchLogsLogGroupArn"):
            return PreCheckResult("ALR-003", "PASS", "LogGroupArn present", [])
    return PreCheckResult("ALR-003", "FAIL", "no trail with CloudWatch Logs", [])


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
            if _principal_is_wildcard_any(st.get("Principal")):
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
            if _principal_is_wildcard(st.get("Principal")):
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
                            [f"arn:aws:s3:::{b.get('Name', '')}"],
                        )

    return PreCheckResult("EXP-015", "PASS", "no cross-account S3 policies", [])


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
    if isinstance(albs, list) and len(albs) == 0:
        return PreCheckResult("WAF-001", "PASS", "no internet-facing ALBs detected", [])
    # Cannot determine PASS/FAIL without deeper analysis → SKIP for AI
    return PreCheckResult("WAF-001", "SKIP", "requires AI analysis of ALB associations", [])


@_register("waf")
def check_waf_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudFront distributions should have WAF protection."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-002", "SKIP", "WAF collection failures (WAF-013)", [])
    dists = evidence.get("cloudfront-distributions")
    if isinstance(dists, list) and len(dists) == 0:
        return PreCheckResult("WAF-002", "PASS", "no CloudFront distributions detected", [])
    return PreCheckResult("WAF-002", "SKIP", "requires AI analysis", [])


@_register("waf")
def check_waf_003_to_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACL configuration checks (WAF-003..008) - gate on Web ACL existence."""
    if _waf_collection_has_failures(evidence):
        # Return one SKIP per gate (AI should not evaluate these)
        return PreCheckResult("WAF-003", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if isinstance(web_acls, list) and len(web_acls) == 0:
        return PreCheckResult("WAF-003", "PASS", "no Web ACLs (N/A)", [])
    return PreCheckResult("WAF-003", "SKIP", "requires AI analysis of Web ACL config", [])


@_register("waf")
def check_waf_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF IP sets should be reviewed."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-009", "SKIP", "WAF collection failures", [])
    ip_sets = evidence.get("wafv2-ip-sets")
    if isinstance(ip_sets, list) and len(ip_sets) == 0:
        return PreCheckResult("WAF-009", "PASS", "no WAFv2 IP sets", [])
    return PreCheckResult("WAF-009", "SKIP", "requires AI analysis", [])


@_register("waf")
def check_waf_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF collection status indicates failures."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-013", "FAIL", "WAF collection has failures", [])
    return PreCheckResult("WAF-013", "PASS", "no WAF collection failures", [])


@_register("waf")
def check_waf_014_to_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """API entry points WAF protection (WAF-014..016) - gate on existence."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-014", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if isinstance(api_eps, list) and len(api_eps) == 0:
        return PreCheckResult("WAF-014", "PASS", "no API entry points", [])
    return PreCheckResult("WAF-014", "SKIP", "requires AI analysis", [])


# ============================================================================
# VULNS PRE-CHECKS
# ============================================================================


@_register("vulns")
def check_vuln_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Inspector v2 should be enabled."""
    inspector = evidence.get("inspector-coverage")
    if isinstance(inspector, dict):
        status = inspector.get("status") or inspector.get("Status")
        if status in ("ENABLED", "ACTIVE"):
            return PreCheckResult("VULN-001", "PASS", f"Inspector status={status}", [])
    return PreCheckResult("VULN-001", "SKIP", "requires AI analysis of inspector state", [])


@_register("vulns")
def check_vuln_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """GuardDuty findings review."""
    gd = evidence.get("guardduty-findings")
    if isinstance(gd, list) and len(gd) == 0:
        return PreCheckResult("VULN-002", "PASS", "no GuardDuty findings", [])
    return PreCheckResult("VULN-002", "SKIP", "requires AI analysis", [])


@_register("vulns")
def check_vuln_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """Macie sensitive data findings."""
    macie = evidence.get("macie-findings")
    if isinstance(macie, list) and len(macie) == 0:
        return PreCheckResult("VULN-009", "PASS", "no Macie findings", [])
    return PreCheckResult("VULN-009", "SKIP", "requires AI analysis", [])


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


@_register("kms")
def check_kms_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Key policy with wildcard/broad principals."""
    pol_doc = evidence.get("kms-key-policies")
    items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-001", "SKIP", "no kms-key-policies evidence", [])

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
            if _principal_is_wildcard(st.get("Principal")):
                key_id = rec.get("KeyId", "unknown")
                return PreCheckResult(
                    "KMS-001",
                    "FAIL",
                    f"key {key_id} has wildcard principal",
                    [rec.get("KeyArn", key_id)],
                )

    return PreCheckResult("KMS-001", "PASS", "no wildcard principals in key policies", [])


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
            for act in _actions_from_stmt(st):
                if act.lower() in {"kms:putkeypolicy", "kms:creategrant", "kms:*"}:
                    return PreCheckResult(
                        "KMS-003",
                        "FAIL",
                        f"key has {act} permission",
                        [rec.get("KeyArn", "unknown")],
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
    """Policies allowing destructive availability-impacting KMS actions."""
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
            for act in _actions_from_stmt(st):
                if str(act).lower() in destructive:
                    key_id = rec.get("KeyId", "unknown")
                    return PreCheckResult(
                        "KMS-005",
                        "FAIL",
                        f"key {key_id} allows destructive action {act}",
                        [rec.get("KeyArn", key_id)],
                    )

    return PreCheckResult("KMS-005", "PASS", "no destructive key actions in policy", [])


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
        return PreCheckResult(
            "KMS-007",
            "FAIL",
            f"grant {grant_id} delegates CreateGrant without constraints",
            [key_id],
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
            if _principal_is_wildcard_any(st.get("Principal")):
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
            if _principal_is_wildcard_any(st.get("Principal")):
                return PreCheckResult(
                    "MSG-008",
                    "FAIL",
                    "topic policy allows wildcard Publish",
                    [str(t.get("TopicArn") or "unknown")],
                )

    return PreCheckResult("MSG-008", "PASS", "no wildcard Publish in SNS topic policies", [])


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

    for td in tdefs:
        if not isinstance(td, dict):
            continue
        cds = td.get("containerDefinitions")
        if not isinstance(cds, list):
            continue
        for cd in cds:
            if (
                isinstance(cd, dict)
                and isinstance(cd.get("image"), str)
                and _suspicious(cd["image"])
            ):
                return PreCheckResult(
                    "COMP-ECS-002",
                    "FAIL",
                    f"suspicious image: {cd['image']}",
                    [td.get("taskDefinitionArn", "unknown")],
                )

    return PreCheckResult("COMP-ECS-002", "PASS", "no suspicious container images", [])


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
