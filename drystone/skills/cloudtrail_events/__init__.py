"""CloudTrail Events skill - detects security incidents in historical CloudTrail events."""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

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

    # Extract source IP from CloudTrailEvent JSON string
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
        except (json.JSONDecodeError, TypeError):
            pass

    # Remove None values
    return {k: v for k, v in distilled.items() if v is not None}


def _paginate_lookup(
    ct_client: Any,
    start_time: datetime,
    end_time: datetime,
    attribute_key: str,
    attribute_value: str,
    max_events: int = MAX_EVENTS_PER_CATEGORY,
) -> list[dict]:
    """Paginate CloudTrail lookup_events for a single attribute filter."""
    events: list[dict] = []
    paginator = ct_client.get_paginator("lookup_events")

    try:
        page_iterator = paginator.paginate(
            LookupAttributes=[{"AttributeKey": attribute_key, "AttributeValue": attribute_value}],
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": max_events, "PageSize": 50},
        )
        for page in page_iterator:
            for event in page.get("Events", []):
                events.append(_distill_event(event))
                if len(events) >= max_events:
                    return events
    except ClientError as e:
        logger.warning("lookup_events failed for %s=%s: %s", attribute_key, attribute_value, e)

    return events


def _paginate_write_events(
    ct_client: Any,
    start_time: datetime,
    end_time: datetime,
    max_events: int = MAX_WRITE_EVENTS,
) -> list[dict]:
    """Collect all write events (ReadOnly=false) for general analysis."""
    events: list[dict] = []
    paginator = ct_client.get_paginator("lookup_events")

    try:
        page_iterator = paginator.paginate(
            LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": max_events, "PageSize": 50},
        )
        for page in page_iterator:
            for event in page.get("Events", []):
                events.append(_distill_event(event))
                if len(events) >= max_events:
                    return events
    except ClientError as e:
        logger.warning("lookup_events (write events) failed: %s", e)

    return events


class CloudTrailEventsSkill(BaseSkill):
    """Detects security incidents in historical CloudTrail events."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "cloudtrail_events"

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
        client_kwargs = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        # Resolve scan_depth → days
        scan_depth = getattr(session, "scan_depth", "normal")
        days_back = SCAN_DEPTH_DAYS.get(scan_depth, 30)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days_back)

        evidence_path = session.get_evidence_path(self.name)

        print(f"  CloudTrail Events: scanning last {days_back} days ({scan_depth})...")

        ct_client = boto3.client("cloudtrail", **client_kwargs)

        summary: dict[str, Any] = {
            "scan_depth": scan_depth,
            "days_back": days_back,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "region": aws_client.region_name,
            "categories_collected": {},
        }

        # === TARGETED LOOKUPS (one per EventName / Username) ===
        for filename, attr_key, attr_value in _TARGETED_EVENT_NAMES:
            print(f"    Collecting {filename}...")
            events = _paginate_lookup(
                ct_client, start_time, end_time, attr_key, attr_value
            )
            output_file = evidence_path / f"{filename}.json"
            output_file.write_text(json.dumps(events, indent=2, default=str))
            summary["categories_collected"][filename] = len(events)
            logger.debug("Collected %d events for %s", len(events), filename)

        # === GENERAL WRITE EVENTS (for mass deletions + access denied) ===
        print("    Collecting write-events (mass deletions / access denied)...")
        write_events = _paginate_write_events(ct_client, start_time, end_time)

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

        # === SUMMARY ===
        (evidence_path / "_summary.json").write_text(json.dumps(summary, indent=2, default=str))

        total_events = sum(summary["categories_collected"].values())
        print(
            f"  ✅ CloudTrail Events: {total_events} events collected across "
            f"{len(summary['categories_collected'])} categories"
        )
