"""CloudTrail Events skill - detects security incidents in historical CloudTrail events."""

import json
import logging
from datetime import datetime, timedelta, timezone
from time import sleep as _sleep
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Maps scan_depth to number of days to look back
SCAN_DEPTH_DAYS = {
    "shallow": 7,
    "normal": 30,
    "deep": 90,
    "very-deep": 180,
}

# Max events per targeted lookup (per EventName/Username filter)
MAX_EVENTS_PER_CATEGORY = 500

# Max write events pulled for general analysis (mass deletions, access denied)
MAX_WRITE_EVENTS = 1000

# Bounded retry/backoff for transient CloudTrail LookupEvents throttling.
_LOOKUP_RETRYABLE_ERROR_CODES = {
    "ThrottlingException",
    "ThrottledException",
    "TooManyRequestsException",
    "RequestLimitExceeded",
}
_LOOKUP_MAX_ATTEMPTS = 3
_LOOKUP_BACKOFF_BASE_SECONDS = 1.0

# Fields to KEEP per event (distillation — reduces size ~80%)
_KEEP_FIELDS = {
    "EventId",
    "EventName",
    "EventTime",
    "EventSource",
    "Username",
    "ReadOnly",
    "Resources",
    "ErrorCode",
    "ErrorMessage",
}

# CloudTrail event selectors — each generates a separate lookup_events call
_TARGETED_EVENT_NAMES = [
    # Root activity
    ("root-events", "Username", "root"),
    # Authentication
    ("console-login-events", "EventName", "ConsoleLogin"),
    ("assume-role-events", "EventName", "AssumeRole"),
    # Audit tampering
    ("stop-logging-events", "EventName", "StopLogging"),
    ("delete-trail-events", "EventName", "DeleteTrail"),
    ("update-trail-events", "EventName", "UpdateTrail"),
    # Privilege escalation
    ("create-access-key-events", "EventName", "CreateAccessKey"),
    ("attach-user-policy-events", "EventName", "AttachUserPolicy"),
    ("attach-role-policy-events", "EventName", "AttachRolePolicy"),
    ("create-login-profile-events", "EventName", "CreateLoginProfile"),
    # Reconnaissance / credential access
    ("credential-report-events", "EventName", "GenerateCredentialReport"),
    ("get-credential-report-events", "EventName", "GetCredentialReport"),
    # Security service tampering
    ("disable-security-hub-events", "EventName", "DisableSecurityHub"),
    ("delete-detector-events", "EventName", "DeleteDetector"),
    ("disable-alarm-actions-events", "EventName", "DisableAlarmActions"),
    # Secrets and credential exfiltration (CTEF-012)
    ("get-secret-value-events", "EventName", "GetSecretValue"),
    ("get-parameter-events", "EventName", "GetParameter"),
    # IAM trust and inline policy modifications (CTEF-013)
    ("update-assume-role-events", "EventName", "UpdateAssumeRolePolicy"),
    ("put-role-policy-events", "EventName", "PutRolePolicy"),
]


def _distill_event(event: dict) -> dict:
    """Extract essential fields from a CloudTrail event (reduces payload ~80%)."""
    distilled: dict[str, Any] = {}

    for field in _KEEP_FIELDS:
        if field in event:
            distilled[field] = event[field]

    # Normalize EventTime to ISO string for JSON serialization
    if "EventTime" in distilled and isinstance(distilled["EventTime"], datetime):
        distilled["EventTime"] = distilled["EventTime"].isoformat()

    # Extract fields from nested CloudTrailEvent JSON blob
    if "CloudTrailEvent" in event:
        try:
            ct_event = json.loads(event["CloudTrailEvent"])
            distilled["sourceIPAddress"] = ct_event.get("sourceIPAddress")
            # Keep requestParameters only if small (< 500 chars) to limit size
            req_params = ct_event.get("requestParameters")
            if req_params:
                serialized = json.dumps(req_params)
                if len(serialized) < 500:
                    distilled["requestParameters"] = req_params
            # Preserve errorCode/errorMessage from nested event if not in top-level
            if not distilled.get("ErrorCode"):
                distilled["ErrorCode"] = ct_event.get("errorCode")
                distilled["ErrorMessage"] = ct_event.get("errorMessage")
            # Extract caller identity for cross-account detection (CTEF-010).
            # The top-level Username field is often "unknown" for service-initiated
            # AssumeRole events; userIdentity contains the authoritative caller info.
            user_identity = ct_event.get("userIdentity") or {}
            caller_account = user_identity.get("accountId")
            caller_arn = user_identity.get("arn") or user_identity.get("principalId")
            caller_type = user_identity.get("type")  # e.g. "AssumedRole", "IAMUser", "Service"
            if caller_account:
                distilled["callerAccountId"] = caller_account
            if caller_arn:
                distilled["callerArn"] = caller_arn
            if caller_type:
                distilled["callerType"] = caller_type
        except (json.JSONDecodeError, TypeError):
            pass

    # Remove None values
    return {k: v for k, v in distilled.items() if v is not None}


def _client_error_code(error: ClientError) -> str:
    """Return the AWS error code from a botocore ClientError."""
    return str(error.response.get("Error", {}).get("Code", ""))


def _is_lookup_throttling_error(error: ClientError) -> bool:
    """Return True when CloudTrail LookupEvents failed due to retryable throttling."""
    return _client_error_code(error) in _LOOKUP_RETRYABLE_ERROR_CODES


def _record_category_status(
    status_recorder: Optional[dict[str, dict[str, Any]]],
    category: Optional[str],
    *,
    ok: bool,
    reason_code: Optional[str] = None,
    event_count: int = 0,
    error: Optional[ClientError] = None,
) -> None:
    if status_recorder is None or category is None:
        return
    entry: dict[str, Any] = {"ok": ok, "event_count": event_count}
    if reason_code:
        entry["reason_code"] = reason_code
    if error is not None:
        entry["error_code"] = _client_error_code(error)
        entry["error"] = str(error)
    status_recorder[category] = entry


def _paginate_lookup_events(
    ct_client: Any,
    lookup_attributes: list[dict[str, str]],
    start_time: datetime,
    end_time: datetime,
    max_events: int,
    warning_context: str,
    sleep_fn: Callable[[float], None] = _sleep,
    status_recorder: Optional[dict[str, dict[str, Any]]] = None,
    category: Optional[str] = None,
) -> list[dict]:
    """Paginate CloudTrail lookup_events with bounded throttling retry/backoff."""
    last_events: list[dict] = []

    for attempt in range(1, _LOOKUP_MAX_ATTEMPTS + 1):
        events: list[dict] = []
        paginator = ct_client.get_paginator("lookup_events")
        try:
            page_iterator = paginator.paginate(
                LookupAttributes=lookup_attributes,
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": max_events, "PageSize": 50},
            )
            for page in page_iterator:
                for event in page.get("Events", []):
                    events.append(_distill_event(event))
                    if len(events) >= max_events:
                        _record_category_status(
                            status_recorder,
                            category,
                            ok=False,
                            reason_code="partial_collection",
                            event_count=len(events),
                        )
                        return events
            _record_category_status(status_recorder, category, ok=True, event_count=len(events))
            return events
        except ClientError as e:
            last_events = events
            if not _is_lookup_throttling_error(e):
                logger.warning("lookup_events failed for %s: %s", warning_context, e)
                _record_category_status(
                    status_recorder,
                    category,
                    ok=False,
                    reason_code="collection_failed",
                    event_count=len(last_events),
                    error=e,
                )
                return last_events

            if attempt >= _LOOKUP_MAX_ATTEMPTS:
                logger.warning(
                    "lookup_events throttled for %s after %d attempts: %s",
                    warning_context,
                    attempt,
                    e,
                )
                _record_category_status(
                    status_recorder,
                    category,
                    ok=False,
                    reason_code="partial_collection",
                    event_count=len(last_events),
                    error=e,
                )
                return last_events

            delay = _LOOKUP_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
            logger.warning(
                "lookup_events throttled for %s (attempt %d/%d); retrying in %.1fs: %s",
                warning_context,
                attempt,
                _LOOKUP_MAX_ATTEMPTS,
                delay,
                e,
            )
            sleep_fn(delay)

    return last_events


def _paginate_lookup(
    ct_client: Any,
    start_time: datetime,
    end_time: datetime,
    attribute_key: str,
    attribute_value: str,
    max_events: int = MAX_EVENTS_PER_CATEGORY,
    sleep_fn: Callable[[float], None] = _sleep,
    status_recorder: Optional[dict[str, dict[str, Any]]] = None,
    category: Optional[str] = None,
) -> list[dict]:
    """Paginate CloudTrail lookup_events for a single attribute filter."""
    return _paginate_lookup_events(
        ct_client=ct_client,
        lookup_attributes=[{"AttributeKey": attribute_key, "AttributeValue": attribute_value}],
        start_time=start_time,
        end_time=end_time,
        max_events=max_events,
        warning_context=f"{attribute_key}={attribute_value}",
        sleep_fn=sleep_fn,
        status_recorder=status_recorder,
        category=category,
    )


def _paginate_write_events(
    ct_client: Any,
    start_time: datetime,
    end_time: datetime,
    max_events: int = MAX_WRITE_EVENTS,
    sleep_fn: Callable[[float], None] = _sleep,
    status_recorder: Optional[dict[str, dict[str, Any]]] = None,
    category: str = "write-events",
) -> list[dict]:
    """Collect all write events (ReadOnly=false) for general analysis."""
    return _paginate_lookup_events(
        ct_client=ct_client,
        lookup_attributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
        start_time=start_time,
        end_time=end_time,
        max_events=max_events,
        warning_context="write events",
        sleep_fn=sleep_fn,
        status_recorder=status_recorder,
        category=category,
    )


class CloudTrailEventsSkill(BaseSkill):
    """Detects security incidents in historical CloudTrail events."""

    def _skill_specific_traceability(
        self,
        check_id: str,
        result: Any,
        evidence: Dict[str, Any],
    ) -> Optional["tuple[List[str], Optional[Dict[str, Any]]]"]:
        """P1 #2 (2026-09-16): check-ID-specific evidence traceability, extracted
        from BaseSkill._build_precheck_traceability into cloudtrail_events/traceability.py.
        """
        from drystone.skills.cloudtrail_events.traceability import build_traceability

        return build_traceability(check_id, result, evidence)

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "cloudtrail_events"

    def _record_aggregate_category_status(
        self,
        category_status: dict[str, dict[str, Any]],
        aggregate_name: str,
        source_names: tuple[str, ...],
        event_count: int,
    ) -> None:
        failed = [dict(category_status.get(name, {})) for name in source_names if not category_status.get(name, {}).get("ok", True)]
        if not failed:
            category_status[aggregate_name] = {"ok": True, "event_count": event_count}
            return
        reason_code = "partial_collection" if any(f.get("reason_code") == "partial_collection" for f in failed) else "collection_failed"
        category_status[aggregate_name] = {
            "ok": False,
            "reason_code": reason_code,
            "event_count": event_count,
            "error": "; ".join(str(f.get("error") or f.get("error_code") or reason_code) for f in failed),
        }

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        """Collect and categorize CloudTrail events from the audit period.

        Generates evidence files:
            - targeted event files per EventName/Username (15 categories)
            - write-events.json: all write events for mass-deletion + access-denied analysis
            - _summary.json: collection metadata and event counts

        Args:
            aws_client: Authenticated AWS client
            session: Audit session for evidence storage
        """
        client_kwargs = aws_client.client_kwargs()

        # Resolve scan_depth → days
        scan_depth = getattr(session, "scan_depth", "normal")
        days_back = SCAN_DEPTH_DAYS.get(scan_depth, 30)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days_back)

        evidence_path = session.get_evidence_path(self.name)

        print(f"  CloudTrail Events: scanning last {days_back} days ({scan_depth})...")

        ct_client = boto3.client("cloudtrail", **client_kwargs)

        account_id = aws_client.get_account_id() or getattr(session, "account_id", "") or ""

        summary: dict[str, Any] = {
            "scan_depth": scan_depth,
            "days_back": days_back,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "region": aws_client.region_name,
            "account_id": account_id,
            "categories_collected": {},
        }
        category_status: dict[str, dict[str, Any]] = {}

        # === TARGETED LOOKUPS (one per EventName / Username) ===
        for filename, attr_key, attr_value in _TARGETED_EVENT_NAMES:
            print(f"    Collecting {filename}...")
            events = _paginate_lookup(
                ct_client,
                start_time,
                end_time,
                attr_key,
                attr_value,
                status_recorder=category_status,
                category=filename,
            )
            output_file = evidence_path / f"{filename}.json"
            output_file.write_text(json.dumps(events, indent=2, default=str))
            summary["categories_collected"][filename] = len(events)
            logger.debug("Collected %d events for %s", len(events), filename)

        # === GENERAL WRITE EVENTS (for mass deletions + access denied) ===
        print("    Collecting write-events (mass deletions / access denied)...")
        write_events = _paginate_write_events(
            ct_client, start_time, end_time, status_recorder=category_status
        )

        # Derive sub-categories from write events
        access_denied = [
            e for e in write_events if e.get("ErrorCode") in ("AccessDenied", "Client.UnauthorizedOperation")
        ]
        throttled = [
            e for e in write_events if e.get("ErrorCode") in ("Throttling", "RequestLimitExceeded")
        ]
        delete_events = [
            e for e in write_events if str(e.get("EventName", "")).startswith("Delete")
        ]

        (evidence_path / "write-events.json").write_text(
            json.dumps(write_events, indent=2, default=str)
        )
        (evidence_path / "access-denied-events.json").write_text(
            json.dumps(access_denied, indent=2, default=str)
        )
        (evidence_path / "throttling-events.json").write_text(
            json.dumps(throttled, indent=2, default=str)
        )
        (evidence_path / "delete-events.json").write_text(
            json.dumps(delete_events, indent=2, default=str)
        )

        summary["categories_collected"].update(
            {
                "write-events": len(write_events),
                "access-denied-events": len(access_denied),
                "throttling-events": len(throttled),
                "delete-events": len(delete_events),
            }
        )
        write_status = dict(category_status.get("write-events", {"ok": True}))
        for derived_name, count in (
            ("access-denied-events", len(access_denied)),
            ("throttling-events", len(throttled)),
            ("delete-events", len(delete_events)),
        ):
            derived_status = dict(write_status)
            derived_status["event_count"] = count
            category_status[derived_name] = derived_status

        # === AUDIT METADATA ===
        audit_tampering = []
        for name in ("stop-logging-events", "delete-trail-events", "update-trail-events"):
            f = evidence_path / f"{name}.json"
            if f.exists():
                audit_tampering.extend(json.loads(f.read_text()))
        (evidence_path / "audit-tampering-events.json").write_text(
            json.dumps(audit_tampering, indent=2, default=str)
        )
        summary["categories_collected"]["audit-tampering-events"] = len(audit_tampering)
        self._record_aggregate_category_status(
            category_status,
            "audit-tampering-events",
            ("stop-logging-events", "delete-trail-events", "update-trail-events"),
            len(audit_tampering),
        )

        # === PRIVILEGE ESCALATION (aggregate) ===
        priv_esc = []
        for name in (
            "create-access-key-events",
            "attach-user-policy-events",
            "attach-role-policy-events",
            "create-login-profile-events",
        ):
            f = evidence_path / f"{name}.json"
            if f.exists():
                priv_esc.extend(json.loads(f.read_text()))
        (evidence_path / "privilege-escalation-events.json").write_text(
            json.dumps(priv_esc, indent=2, default=str)
        )
        summary["categories_collected"]["privilege-escalation-events"] = len(priv_esc)
        self._record_aggregate_category_status(
            category_status,
            "privilege-escalation-events",
            (
                "create-access-key-events",
                "attach-user-policy-events",
                "attach-role-policy-events",
                "create-login-profile-events",
            ),
            len(priv_esc),
        )

        # === SUMMARY ===
        (evidence_path / "_summary.json").write_text(json.dumps(summary, indent=2, default=str))
        self._save_collection_status(
            evidence_path,
            {
                "categories": category_status,
                "scan_depth": scan_depth,
                "days_back": days_back,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
            },
        )

        total_events = sum(summary["categories_collected"].values())
        print(
            f"  ✅ CloudTrail Events: {total_events} events collected across "
            f"{len(summary['categories_collected'])} categories"
        )


# --- Skill registry manifest (see drystone/skills/registry.py) ---
# Declaring these here is what lets drystone auto-discover this skill —
# no other file needs to list it by name.
SKILL_NAME = "cloudtrail_events"
SKILL_DISPLAY_NAME = "CloudTrail Events Audit"
SKILL_CLASS = CloudTrailEventsSkill
SKILL_WIZARD_SELECTABLE = True
SKILL_WIZARD_LABEL = "CloudTrail Events Audit"
SKILL_WIZARD_ORDER = 6
