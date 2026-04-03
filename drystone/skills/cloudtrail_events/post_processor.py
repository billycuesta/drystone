"""CloudTrail Events post-processor: timeline, top users, event distribution."""

import json
import logging
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from drystone.storage.session import AuditSession

logger = logging.getLogger(__name__)

# Evidence files to load (filename stem → dict key)
_EVIDENCE_FILES = {
    "root-events": "root-events",
    "console-login-events": "console-login-events",
    "assume-role-events": "assume-role-events",
    "stop-logging-events": "stop-logging-events",
    "delete-trail-events": "delete-trail-events",
    "update-trail-events": "update-trail-events",
    "create-access-key-events": "create-access-key-events",
    "attach-user-policy-events": "attach-user-policy-events",
    "attach-role-policy-events": "attach-role-policy-events",
    "create-login-profile-events": "create-login-profile-events",
    "credential-report-events": "credential-report-events",
    "get-credential-report-events": "get-credential-report-events",
    "disable-security-hub-events": "disable-security-hub-events",
    "delete-detector-events": "delete-detector-events",
    "disable-alarm-actions-events": "disable-alarm-actions-events",
    "audit-tampering-events": "audit-tampering-events",
    "privilege-escalation-events": "privilege-escalation-events",
    "access-denied-events": "access-denied-events",
    "throttling-events": "throttling-events",
    "delete-events": "delete-events",
    "write-events": "write-events",
    "_summary": "_summary",
}

# Severity per event category (for color coding)
_CATEGORY_SEVERITY = {
    "root-events": "CRITICAL",
    "audit-tampering-events": "CRITICAL",
    "stop-logging-events": "CRITICAL",
    "delete-trail-events": "CRITICAL",
    "privilege-escalation-events": "HIGH",
    "attach-user-policy-events": "HIGH",
    "attach-role-policy-events": "HIGH",
    "create-access-key-events": "HIGH",
    "create-login-profile-events": "HIGH",
    "access-denied-events": "HIGH",
    "delete-events": "HIGH",
    "console-login-events": "MEDIUM",
    "assume-role-events": "MEDIUM",
    "credential-report-events": "MEDIUM",
    "get-credential-report-events": "MEDIUM",
    "throttling-events": "MEDIUM",
    "update-trail-events": "MEDIUM",
    "disable-security-hub-events": "HIGH",
    "delete-detector-events": "HIGH",
    "disable-alarm-actions-events": "HIGH",
}


class CloudTrailEventsPostProcessor:
    """Post-processor: adds timeline, top users, and event distribution to findings."""

    def __init__(self, session: AuditSession):
        """Initialize with audit session.

        Args:
            session: AuditSession instance for accessing evidence files
        """
        self.session = session
        self.evidence_path = session.get_evidence_path("cloudtrail_events")

    def process(self, findings: dict) -> dict:
        """Enhance findings with visual analytics.

        Adds:
            - findings["cloudtrail_timeline"]: events grouped by day
            - findings["cloudtrail_top_users"]: top 10 most active users
            - findings["cloudtrail_event_distribution"]: events by category + severity

        Args:
            findings: Raw findings dict from agent analysis

        Returns:
            Enhanced findings dict
        """
        evidence = self._load_evidence()

        findings["cloudtrail_timeline"] = self._build_timeline(evidence)
        findings["cloudtrail_top_users"] = self._top_users(evidence)
        findings["cloudtrail_event_distribution"] = self._event_distribution(evidence)

        return findings

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _load_evidence(self) -> dict[str, Any]:
        """Load all CloudTrail evidence files."""
        evidence: dict[str, Any] = {}
        for stem, key in _EVIDENCE_FILES.items():
            file_path = self.evidence_path / f"{stem}.json"
            if file_path.exists():
                try:
                    evidence[key] = json.loads(file_path.read_text())
                except (json.JSONDecodeError, OSError) as e:
                    logger.warning("Failed to load %s: %s", file_path, e)
                    evidence[key] = [] if key != "_summary" else {}
        return evidence

    def _all_events(self, evidence: dict) -> list[dict]:
        """Flatten all event lists (excluding summary and write-events to avoid duplication)."""
        skip_keys = {"write-events", "_summary"}
        all_evts: list[dict] = []
        for key, val in evidence.items():
            if key in skip_keys:
                continue
            if isinstance(val, list):
                all_evts.extend(val)
        return all_evts

    def _build_timeline(self, evidence: dict) -> dict:
        """Group events by date for a daily timeline view.

        Returns:
            {
                "by_day": {"2026-03-01": {"total": N, "CRITICAL": N, "HIGH": N, ...}},
                "total_events": N,
                "days_with_activity": N,
            }
        """
        by_day: dict[str, dict] = defaultdict(
            lambda: {"total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        )

        # Map each event back to its category to determine severity
        for category, val in evidence.items():
            if category in ("write-events", "_summary") or not isinstance(val, list):
                continue
            severity = _CATEGORY_SEVERITY.get(category, "UNKNOWN")
            for event in val:
                event_time_str = event.get("EventTime", "")
                day = self._parse_day(event_time_str)
                if day:
                    by_day[day]["total"] += 1
                    by_day[day][severity] += 1

        sorted_days = dict(sorted(by_day.items()))
        return {
            "by_day": sorted_days,
            "total_events": sum(d["total"] for d in sorted_days.values()),
            "days_with_activity": len(sorted_days),
        }

    def _top_users(self, evidence: dict) -> dict:
        """Compute top 10 users by total activity and error rate.

        Returns:
            {
                "top_by_activity": [{"username": str, "total_events": N, "error_events": N}],
                "top_by_errors": [{"username": str, "error_events": N, "total_events": N}],
            }
        """
        activity: Counter = Counter()
        errors: Counter = Counter()

        for event in self._all_events(evidence):
            username = event.get("Username") or "unknown"
            activity[username] += 1
            if event.get("ErrorCode"):
                errors[username] += 1

        top_activity = [
            {
                "username": u,
                "total_events": cnt,
                "error_events": errors.get(u, 0),
            }
            for u, cnt in activity.most_common(10)
        ]
        top_errors = [
            {
                "username": u,
                "error_events": cnt,
                "total_events": activity.get(u, 0),
            }
            for u, cnt in errors.most_common(10)
        ]

        return {
            "top_by_activity": top_activity,
            "top_by_errors": top_errors,
        }

    def _event_distribution(self, evidence: dict) -> dict:
        """Compute event distribution by category and severity.

        Returns:
            {
                "by_category": {"root-events": N, ...},
                "by_severity": {"CRITICAL": N, "HIGH": N, ...},
                "total_events": N,
            }
        """
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = defaultdict(int)

        for category, val in evidence.items():
            if category in ("write-events", "_summary") or not isinstance(val, list):
                continue
            count = len(val)
            if count == 0:
                continue
            by_category[category] = count
            severity = _CATEGORY_SEVERITY.get(category, "UNKNOWN")
            by_severity[severity] += count

        total = sum(by_category.values())
        return {
            "by_category": dict(sorted(by_category.items(), key=lambda x: x[1], reverse=True)),
            "by_severity": dict(by_severity),
            "total_events": total,
        }

    @staticmethod
    def _parse_day(event_time_str: Any) -> str | None:
        """Parse EventTime string into YYYY-MM-DD. Returns None if unparseable."""
        if not event_time_str or not isinstance(event_time_str, str):
            return None
        try:
            dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d")
        except (ValueError, AttributeError):
            return None
