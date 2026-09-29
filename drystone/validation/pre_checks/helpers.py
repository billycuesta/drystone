# ruff: noqa
"""Shared helpers for deterministic pre-check modules."""

import functools
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .core import (
    PRE_CHECK_STATUS_FAIL,
    PRE_CHECK_STATUS_PASS,
    PRE_CHECK_STATUS_WARN,
    PreCheckFn,
    PreCheckResult,
)


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


def _credential_value_is_date(val: Any) -> bool:
    """Return true when a credential-report field contains a real timestamp."""
    if val is None:
        return False
    sval = str(val).strip().lower()
    return bool(sval) and sval not in {
        "n/a",
        "no_information",
        "not_supported",
        "none",
        "null",
        "false",
    }


def _policy_index(evidence: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    policies = evidence.get("policies")
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(policies, list):
        return out
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        for key in ("Arn", "PolicyArn", "PolicyName"):
            val = policy.get(key)
            if val:
                out[str(val)] = policy
    return out


def _user_permission_context(evidence: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize direct/group policy context for user-scoped IAM findings."""
    policy_map = _policy_index(evidence)
    group_docs = evidence.get("groups")
    groups_by_name = (
        {str(g.get("GroupName")): g for g in group_docs if isinstance(g, dict)}
        if isinstance(group_docs, list)
        else {}
    )

    attached_policy_arns: List[str] = []
    attached_policy_names: List[str] = []
    group_names: List[str] = []
    group_policy_arns: List[str] = []
    actions: List[str] = []

    def _add_policy(pol: Dict[str, Any]) -> None:
        pname = str(pol.get("PolicyName") or "")
        parn = str(pol.get("PolicyArn") or pol.get("Arn") or "")
        if pname:
            attached_policy_names.append(pname)
        if parn:
            attached_policy_arns.append(parn)
        resolved = policy_map.get(parn) or policy_map.get(pname) or pol
        for stmt in _stmts_from_policy(
            resolved.get("PolicyDocument") if isinstance(resolved, dict) else None
        ):
            actions.extend(_actions_from_stmt(stmt))

    for pol in user.get("AttachedPolicies") or []:
        if isinstance(pol, dict):
            _add_policy(pol)

    for group_ref in user.get("Groups") or []:
        if not isinstance(group_ref, dict):
            continue
        gname = str(group_ref.get("GroupName") or "")
        if not gname:
            continue
        group_names.append(gname)
        group = groups_by_name.get(gname) or {}
        for pol in group.get("AttachedPolicies") or []:
            if not isinstance(pol, dict):
                continue
            parn = str(pol.get("PolicyArn") or "")
            if parn:
                group_policy_arns.append(parn)
            _add_policy(pol)

    return {
        "groups": group_names,
        "direct_policy_arns": sorted(set(attached_policy_arns)),
        "direct_policy_names": sorted(set(attached_policy_names)),
        "group_policy_arns": sorted(set(group_policy_arns)),
        "resolved_actions_sample": sorted(set(actions))[:20],
    }


def _resources_from_policy_doc(doc: Any) -> List[str]:
    resources: List[str] = []
    for stmt in _stmts_from_policy(doc):
        if not isinstance(stmt, dict):
            continue
        raw = stmt.get("Resource")
        if isinstance(raw, str):
            resources.append(raw)
        elif isinstance(raw, list):
            resources.extend(str(r) for r in raw if r is not None)
    return sorted(set(resources))[:20]


def _truthy(val: Any) -> bool:
    """Check if a value is truthy in the AWS evidence sense."""
    return val in {1, True, "1", "true", "True"}


def _falsy(val: Any) -> bool:
    """Check if a value is falsy in the AWS evidence sense."""
    return val in {0, False, "0", "false", "False"}


def _parse_date(val: Any) -> Optional[datetime]:
    """Parse datetime string or object to timezone-aware UTC datetime."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val.replace(tzinfo=timezone.utc) if val.tzinfo is None else val
    try:
        from dateutil.parser import parse as _du_parse

        dt = _du_parse(str(val))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except Exception:
        return None


def _mask_key_id(key_id: str) -> str:
    """Mask access key ID keeping first 4 and last 4 chars."""
    if len(key_id) > 8:
        return f"{key_id[:4]}{'*' * (len(key_id) - 8)}{key_id[-4:]}"
    return "****"


_PORT_SERVICES: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2181: "Zookeeper",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _port_service_name(port: Any) -> str:
    """Return well-known service name for a port number, or the port string."""
    try:
        return _PORT_SERVICES.get(int(port), str(port))
    except (TypeError, ValueError):
        return str(port) if port is not None else "unknown"


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


def _coverage_gap_warning(check_id: str, reason_code: str, summary: str, key: str) -> PreCheckResult:
    """Build a WARN PreCheckResult for a deterministic-coverage gap.

    See `check_evidence_or_warn` for when this is used. `reason_code` is one
    of the reason codes documented there (`missing_evidence`,
    `evidence_parse_failed`, `collection_failed`).
    """
    return PreCheckResult(
        check_id,
        PRE_CHECK_STATUS_WARN,
        summary,
        [],
        confidence=0.0,
        metadata={"reason_code": reason_code, "evidence_key": key},
    )


def check_evidence_or_warn(
    check_id: str,
    evidence: Dict[str, Any],
    keys: List[str],
    *,
    expected_type: type = list,
) -> Optional[PreCheckResult]:
    """Return a WARN result when evidence required by `check_id` is missing
    or malformed; otherwise return None so the caller runs its normal
    PASS/FAIL/SKIP logic unchanged.

    This is the up-front half of the shared "cannot evaluate
    deterministically" guard for checks whose PASS/FAIL result would
    otherwise be computed on missing or malformed evidence. It only covers
    the case where a check literally cannot run at all — there is no FAIL to
    compute without the data, so it is always safe to short-circuit here:

      1. Each key in `keys` must be present in `evidence` — a missing key
         returns WARN with `reason_code="missing_evidence"`.
      2. Each key's value must be an instance of `expected_type` — a wrong
         type returns WARN with `reason_code="evidence_parse_failed"`.

    A *collection-failed* signal (an inline `errors`/`error` field, a
    `<skill>-collection-status` component reporting `ok: False`, or a
    per-item error marker) is deliberately NOT checked here, because once
    the required keys are present, the check CAN run and may find a real
    FAIL — and a genuine violation must never be masked as an unevaluated
    coverage gap just because collection was also incomplete elsewhere. See
    `pass_or_warn`, which applies that signal only at the would-be-PASS
    return site, mirroring the CloudTrail Events pre-checks in
    `cloudtrail_events.py` (FAIL branch computed first, warning only
    consulted afterwards, PASS last).
    """
    for key in keys:
        if key not in evidence:
            return _coverage_gap_warning(
                check_id, "missing_evidence", f"Missing evidence: {key}", key
            )
        doc = evidence.get(key)
        if not isinstance(doc, expected_type):
            return _coverage_gap_warning(
                check_id, "evidence_parse_failed", f"Evidence is not well-formed: {key}", key
            )

    return None


def pass_or_warn(
    result: PreCheckResult,
    evidence: Dict[str, Any],
    check_id: str,
    key: str,
    extra_failure_check: Callable[[Dict[str, Any]], Optional[str]],
) -> PreCheckResult:
    """Downgrade a PASS to WARN when `extra_failure_check` reports a
    collection failure; return any other result (FAIL, SKIP, ...) unchanged.

    Call this only at a check's would-be-PASS return site, after every FAIL
    condition has already been evaluated — never up front. A check that
    already found a genuine violation must FAIL exactly as it does today;
    only a PASS reached because required evidence might be incomplete
    should be downgraded to a coverage-gap WARN.

    `extra_failure_check` receives the full evidence dict and should inspect
    whatever collection-failure signal is available for this check (an
    inline `errors`/`error` field inside the evidence doc itself, a
    `<skill>-collection-status` component reporting `ok: False`, or a
    per-item error marker), returning a human-readable reason string when
    one is found, or `None` when the evidence looks trustworthy. It stays a
    callback (instead of a hardcoded shape) because collection-status
    envelopes differ across skills: flat `errors` dicts (ecr, waf), nested
    per-component dicts (hardening), or per-item error markers
    (secretsmanager) — see
    `drystone/skills/base.py: BaseSkill._save_collection_status()` and each
    skill's own collector for the exact shape.

    Backward compatibility (same rule as the CloudTrail Events pre-checks):
    when `extra_failure_check` finds nothing wrong — including when the
    relevant collection-status document does not exist at all (legacy
    sessions predating it) — `result` is returned unchanged.
    """
    if result.status != PRE_CHECK_STATUS_PASS:
        return result
    reason = extra_failure_check(evidence)
    if reason:
        return _coverage_gap_warning(check_id, "collection_failed", reason, key)
    return result


def component_status(evidence: Dict[str, Any], skill: str, stem: str) -> Optional[Dict[str, Any]]:
    """Return one standardized collection-status component, if the status doc exists.

    Missing status documents mean legacy evidence and must not change behavior.
    A present status document with a missing component means the required
    evidence key is missing from the contract the pre-check is about to use.
    """
    status_doc = evidence.get(f"{skill}-collection-status")
    if not isinstance(status_doc, dict):
        return None
    components = status_doc.get("components")
    if not isinstance(components, dict):
        return {"ok": False, "reason_code": "missing_evidence"}
    component = components.get(stem)
    if isinstance(component, dict):
        return component
    return {"ok": False, "reason_code": "missing_evidence"}


def warn_from_component_status(
    result: PreCheckResult,
    evidence: Dict[str, Any],
    *,
    skill: str,
    stems: List[str],
) -> PreCheckResult:
    """Turn a would-be PASS/SKIP into WARN when collection status is incomplete.

    Rules:
      - FAIL is authoritative and is never masked.
      - No status document preserves legacy behavior.
      - Status doc present + absent required evidence key becomes missing_evidence.
      - Any required component with ok=False converts PASS/SKIP to WARN using its
        reason_code, typically collection_failed or partial_collection.
      - Component ok=True with empty/absent resource class leaves the result unchanged.
    """
    if result.status == PRE_CHECK_STATUS_FAIL:
        return result
    status_doc = evidence.get(f"{skill}-collection-status")
    if not isinstance(status_doc, dict):
        return result

    for stem in stems:
        status = component_status(evidence, skill, stem)
        if isinstance(status, dict) and status.get("ok") is False:
            reason_code = str(status.get("reason_code") or "collection_failed")
            summary = (
                result.evidence_summary
                if result.status != PRE_CHECK_STATUS_PASS
                else str(status.get("error") or f"Collection incomplete: {stem}")
            )
            return _coverage_gap_warning(result.check_id, reason_code, summary, stem)
        if stem not in evidence:
            return _coverage_gap_warning(
                result.check_id,
                "missing_evidence",
                f"Missing evidence: {stem}",
                stem,
            )

    return result


def requires_components(skill: str, *stems: str) -> Callable[[PreCheckFn], PreCheckFn]:
    """Decorator declaring the evidence components a check needs to be trustworthy.

    Wraps a check function so its result is passed through
    `warn_from_component_status` for the given `skill` and component `stems`
    before being returned. This makes a check's evidence-completeness
    dependency an explicit, per-function declaration instead of an
    out-of-band mapping applied via registry rewriting.

    The decorated function's `required_components` attribute carries
    `(skill, stems)` for introspection (e.g. tests asserting the declared
    dependency matches an expected checklist).
    """

    def decorator(check_fn: PreCheckFn) -> PreCheckFn:
        @functools.wraps(check_fn)
        def wrapper(evidence: Dict[str, Any]) -> PreCheckResult:
            result = check_fn(evidence)
            return warn_from_component_status(result, evidence, skill=skill, stems=list(stems))

        wrapper.required_components = (skill, stems)
        return wrapper

    return decorator


# ============================================================================

__all__ = [name for name in globals() if not name.startswith("__")]
