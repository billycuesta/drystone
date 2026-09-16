# ruff: noqa
"""Cloudtrail Events deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# CLOUDTRAIL EVENTS PRE-CHECKS (CTEF-*)
# Deterministic checks on historical CloudTrail event evidence.
# Each check loads its evidence file(s) and returns PASS/FAIL/SKIP.
# =============================================================================


def _load_ctef_events(evidence: dict, key: str) -> list:
    """Helper: return event list for a given evidence key (default [])."""
    val = evidence.get(key, [])
    return val if isinstance(val, list) else []


@_register("cloudtrail_events")
def check_ctef_001(evidence: dict) -> PreCheckResult:
    """CTEF-001: Root account activity detected in audit period."""
    root_events = _load_ctef_events(evidence, "root-events")
    if root_events:
        sample = root_events[0].get("EventName", "unknown")
        return PreCheckResult(
            "CTEF-001",
            "FAIL",
            f"Root account used {len(root_events)} time(s); first event: {sample}",
            ["arn:aws:iam::*:root"],
        )
    return PreCheckResult("CTEF-001", "PASS", "No root account activity detected", [])


@_register("cloudtrail_events")
def check_ctef_002(evidence: dict) -> PreCheckResult:
    """CTEF-002: Excessive failed console login attempts (brute-force indicator)."""
    console_events = _load_ctef_events(evidence, "console-login-events")
    # ConsoleLogin failures have ErrorMessage = "Failed authentication"
    failed = [
        e
        for e in console_events
        if e.get("ErrorCode") or "failed" in str(e.get("ErrorMessage", "")).lower()
    ]
    threshold = 5
    if len(failed) >= threshold:
        usernames = list({e.get("Username", "unknown") for e in failed})[:5]
        return PreCheckResult(
            "CTEF-002",
            "FAIL",
            f"{len(failed)} failed login attempt(s) detected; affected users: {usernames}",
            [f"user:{u}" for u in usernames],
        )
    return PreCheckResult(
        "CTEF-002", "PASS", f"Failed logins below threshold ({len(failed)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_003(evidence: dict) -> PreCheckResult:
    """CTEF-003: CloudTrail audit tampering detected (StopLogging / DeleteTrail / UpdateTrail)."""
    tampering = _load_ctef_events(evidence, "audit-tampering-events")
    if tampering:
        event_names = sorted({str(e.get("EventName", "unknown")) for e in tampering})
        usernames = sorted({str(e.get("Username", "unknown")) for e in tampering})[:5]
        affected_resources: List[str] = []
        for username in usernames:
            if username and username != "unknown":
                affected_resources.append(f"user:{username}")
        for event in tampering:
            for resource in event.get("Resources") or []:
                if not isinstance(resource, dict):
                    continue
                resource_name = resource.get("ResourceName")
                if resource_name:
                    affected_resources.append(str(resource_name))
            request_name = (event.get("requestParameters") or {}).get("name")
            if request_name:
                affected_resources.append(str(request_name))
            caller_arn = event.get("callerArn")
            if caller_arn:
                affected_resources.append(str(caller_arn))

        affected_resources = list(dict.fromkeys(affected_resources))
        return PreCheckResult(
            "CTEF-003",
            "FAIL",
            f"Audit trail tampering detected: {event_names} by {usernames}",
            affected_resources,
            confidence=1.0,
        )
    return PreCheckResult("CTEF-003", "PASS", "No CloudTrail tampering events detected", [])


@_register("cloudtrail_events")
def check_ctef_004(evidence: dict) -> PreCheckResult:
    """CTEF-004: Privilege escalation events detected (policy attachment, access key creation)."""
    priv_esc = _load_ctef_events(evidence, "privilege-escalation-events")
    if priv_esc:
        event_names = list({e.get("EventName", "unknown") for e in priv_esc})
        actors = list({e.get("Username", "unknown") for e in priv_esc})[:5]
        return PreCheckResult(
            "CTEF-004",
            "FAIL",
            f"{len(priv_esc)} privilege escalation event(s): {event_names} by {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult("CTEF-004", "PASS", "No privilege escalation events detected", [])


@_register("cloudtrail_events")
def check_ctef_005(evidence: dict) -> PreCheckResult:
    """CTEF-005: API throttling spike (service disruption indicator)."""
    throttled = _load_ctef_events(evidence, "throttling-events")
    threshold = 50
    if len(throttled) >= threshold:
        sources = list({e.get("EventSource", "unknown") for e in throttled})[:5]
        return PreCheckResult(
            "CTEF-005",
            "FAIL",
            f"{len(throttled)} throttling events detected; services: {sources}",
            [],
        )
    return PreCheckResult(
        "CTEF-005",
        "PASS",
        f"Throttling events below threshold ({len(throttled)} < {threshold})",
        [],
    )


@_register("cloudtrail_events")
def check_ctef_006(evidence: dict) -> PreCheckResult:
    """CTEF-006: IAM permission denial storm (AccessDenied spike)."""
    denied = _load_ctef_events(evidence, "access-denied-events")
    threshold = 20
    if len(denied) >= threshold:
        actors = list({e.get("Username", "unknown") for e in denied})[:5]
        return PreCheckResult(
            "CTEF-006",
            "FAIL",
            f"{len(denied)} AccessDenied events detected; actors: {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-006", "PASS", f"AccessDenied events below threshold ({len(denied)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_007(evidence: dict) -> PreCheckResult:
    """CTEF-007: Unusual off-hours console logins detected."""
    console_events = _load_ctef_events(evidence, "console-login-events")
    # Filter successful logins only
    successful = [
        e
        for e in console_events
        if not e.get("ErrorCode") and "failed" not in str(e.get("ErrorMessage", "")).lower()
    ]
    off_hours = []
    for e in successful:
        event_time_str = e.get("EventTime", "")
        try:
            from datetime import datetime as _dt, timezone as _tz

            if isinstance(event_time_str, str):
                et = _dt.fromisoformat(event_time_str.replace("Z", "+00:00"))
            else:
                continue
            # Always compare in UTC — EventTime may carry local timezone offset
            et_utc = et.astimezone(_tz.utc)
            # Off-hours: before 07:00 or after 20:00 UTC
            if et_utc.hour < 7 or et_utc.hour >= 20:
                off_hours.append(e)
        except (ValueError, AttributeError):
            continue

    threshold = 3
    if len(off_hours) >= threshold:
        users = list({e.get("Username", "unknown") for e in off_hours})[:5]
        return PreCheckResult(
            "CTEF-007",
            "FAIL",
            f"{len(off_hours)} off-hours console login(s) detected; users: {users}",
            [f"user:{u}" for u in users],
        )
    return PreCheckResult(
        "CTEF-007", "PASS", f"Off-hours logins below threshold ({len(off_hours)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_008(evidence: dict) -> PreCheckResult:
    """CTEF-008: Mass resource deletion detected (data destruction indicator)."""
    delete_events = _load_ctef_events(evidence, "delete-events")
    threshold = 10
    if len(delete_events) >= threshold:
        event_names = list({e.get("EventName", "unknown") for e in delete_events})[:5]
        actors = list({e.get("Username", "unknown") for e in delete_events})[:5]
        return PreCheckResult(
            "CTEF-008",
            "FAIL",
            f"{len(delete_events)} deletion event(s) detected: {event_names} by {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-008",
        "PASS",
        f"Deletion events below threshold ({len(delete_events)} < {threshold})",
        [],
    )


@_register("cloudtrail_events")
def check_ctef_009(evidence: dict) -> PreCheckResult:
    """CTEF-009: Credential report accessed (reconnaissance indicator)."""
    gen_events = _load_ctef_events(evidence, "credential-report-events")
    get_events = _load_ctef_events(evidence, "get-credential-report-events")
    all_events = gen_events + get_events
    if all_events:
        actors = list({e.get("Username", "unknown") for e in all_events})[:5]
        return PreCheckResult(
            "CTEF-009",
            "FAIL",
            f"Credential report accessed {len(all_events)} time(s) by: {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult("CTEF-009", "PASS", "No credential report access detected", [])


@_register("cloudtrail_events")
def check_ctef_010(evidence: dict) -> PreCheckResult:
    """CTEF-010: Cross-account AssumeRole from unrecognized external accounts.

    Uses callerAccountId extracted from the nested CloudTrailEvent blob (added in
    distiller fix) to reliably detect external principals. Falls back to Username
    heuristic if callerAccountId is unavailable for older evidence.
    """
    assume_role_events = _load_ctef_events(evidence, "assume-role-events")

    # Derive the audited account ID from the _summary metadata if available
    summary = evidence.get("_summary") or {}
    local_account_id = str(summary.get("account_id") or "")

    # Service types that always assume roles legitimately within the same account
    _AWS_SERVICE_CALLER_TYPES = {"AWSService", "Service", "AWS"}

    cross_account = []
    for e in assume_role_events:
        caller_account = str(e.get("callerAccountId") or "")
        caller_type = str(e.get("callerType") or "")

        if caller_account:
            # Primary detection: caller's account differs from audited account
            if local_account_id and caller_account == local_account_id:
                continue  # same-account call — expected
            if caller_account and caller_account != local_account_id and local_account_id:
                cross_account.append(e)
                continue
        else:
            # Fallback for older evidence without callerAccountId:
            # Username ':' heuristic (cross-account ARN format)
            username = str(e.get("Username") or "")
            if ":" in username and not username.startswith("AROA"):
                cross_account.append(e)

    threshold = 1
    if len(cross_account) >= threshold:
        actors = list(
            {e.get("callerArn") or e.get("Username") or "unknown" for e in cross_account}
        )[:5]
        return PreCheckResult(
            "CTEF-010",
            "FAIL",
            f"{len(cross_account)} cross-account AssumeRole event(s) from external account(s): {actors}",
            [f"principal:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-010", "PASS", "No cross-account AssumeRole events from external accounts detected", []
    )


@_register("cloudtrail_events")
def check_ctef_011(evidence: dict) -> PreCheckResult:
    """CTEF-011: Security monitoring service disabled (GuardDuty / SecurityHub / CloudWatch Alarms)."""
    disabled = (
        _load_ctef_events(evidence, "disable-security-hub-events")
        + _load_ctef_events(evidence, "delete-detector-events")
        + _load_ctef_events(evidence, "disable-alarm-actions-events")
    )
    if disabled:
        event_names = list({e.get("EventName", "unknown") for e in disabled})[:5]
        actors = list({e.get("Username", "unknown") for e in disabled})[:5]
        return PreCheckResult(
            "CTEF-011",
            "FAIL",
            f"{len(disabled)} security monitoring service disabling event(s): {event_names} by {actors}",
            [f"actor:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-011", "PASS", "No security monitoring service disabling events detected", []
    )


@_register("cloudtrail_events")
def check_ctef_012(evidence: dict) -> PreCheckResult:
    """CTEF-012: Secrets and credentials accessed (Secrets Manager / SSM Parameter Store)."""
    accessed = _load_ctef_events(evidence, "get-secret-value-events") + _load_ctef_events(
        evidence, "get-parameter-events"
    )
    if accessed:
        event_names = list({e.get("EventName", "unknown") for e in accessed})[:5]
        actors = list({e.get("Username", "unknown") for e in accessed})[:5]
        resources = list(
            {
                r.get("ResourceName", "unknown")
                for e in accessed
                for r in (e.get("Resources") or [])
                if r.get("ResourceName")
            }
        )[:5]
        summary = f"{len(accessed)} secret/parameter access event(s): {event_names} by {actors}"
        if resources:
            summary += f"; resources: {resources}"
        return PreCheckResult(
            "CTEF-012",
            "FAIL",
            summary,
            [f"actor:{a}" for a in actors],
        )
    return PreCheckResult("CTEF-012", "PASS", "No secret or parameter access events detected", [])


@_register("cloudtrail_events")
def check_ctef_013(evidence: dict) -> PreCheckResult:
    """CTEF-013: IAM trust or inline policy modified (privilege escalation via trust relationships)."""
    modified = _load_ctef_events(evidence, "update-assume-role-events") + _load_ctef_events(
        evidence, "put-role-policy-events"
    )
    if modified:
        event_names = list({e.get("EventName", "unknown") for e in modified})[:5]
        actors = list({e.get("Username", "unknown") for e in modified})[:5]
        roles = list(
            {
                r.get("ResourceName", "unknown")
                for e in modified
                for r in (e.get("Resources") or [])
                if r.get("ResourceName")
            }
        )[:5]
        summary = f"{len(modified)} IAM trust/inline policy modification event(s): {event_names} by {actors}"
        if roles:
            summary += f"; roles: {roles}"
        return PreCheckResult(
            "CTEF-013",
            "FAIL",
            summary,
            [f"actor:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-013", "PASS", "No IAM trust or inline policy modification events detected", []
    )

__all__ = [name for name in globals() if name.startswith("check_")]
