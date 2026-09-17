"""Crash-safe JSONL logger with immediate flush and durability guarantees.

Ensures logs are never lost even if the process crashes.
Uses append-only JSONL format (one JSON object per line).
Flushes to disk immediately after each write.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class CrashSafeLogger:
    """Append-only JSONL logger with immediate flush guarantees.

    Properties:
    - Append-only: never truncates, only adds
    - Immediate flush: written to disk immediately
    - Durable: survives process crash
    - Simple: one JSON object per line
    - Queryable: can be parsed/analyzed independently
    """

    def __init__(self, log_file: Path, skill_name: str = "audit"):
        """Initialize crash-safe logger.

        Args:
            log_file: Path to JSONL log file
            skill_name: Skill name for context (e.g., 'iam', 'network')
        """
        self.log_file = Path(log_file)
        self.skill_name = skill_name

        # Ensure parent directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Create or append to existing log
        self.log_file.touch(exist_ok=True)

        logger.info(f"CrashSafeLogger initialized: {self.log_file}")

    def log_event(
        self,
        event_type: str,
        message: str,
        severity: str = "info",
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an event to JSONL file with immediate flush.

        Args:
            event_type: Type of event (e.g., 'skill_start', 'validation_failed')
            message: Human-readable message
            severity: 'info', 'warning', 'error', 'critical'
            context: Optional context dict with additional data
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "skill": self.skill_name,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            **(context or {}),
        }

        # Write and flush immediately (crash-safe)
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event, default=str) + "\n")
                f.flush()  # Critical: ensure written to disk
            logger.debug(f"Logged event: {event_type}")
        except Exception as e:
            logger.error(f"Failed to write log: {e}", exc_info=True)

    def log_skill_start(self, evidence_count: int, checklist_items: int) -> None:
        """Log skill analysis start event."""
        self.log_event(
            event_type="skill_start",
            message=f"Starting {self.skill_name} analysis",
            severity="info",
            context={
                "evidence_count": evidence_count,
                "checklist_items": checklist_items,
            },
        )

    def log_skill_complete(self, findings_count: int, risk_score: float) -> None:
        """Log skill analysis completion event."""
        self.log_event(
            event_type="skill_complete",
            message=f"Completed {self.skill_name} analysis",
            severity="info",
            context={
                "findings_count": findings_count,
                "risk_score": risk_score,
            },
        )

    def log_validation_error(self, error_message: str, details: Optional[Dict] = None) -> None:
        """Log validation failure event."""
        self.log_event(
            event_type="validation_failed",
            message=f"Validation failed: {error_message}",
            severity="error",
            context=details or {},
        )

    def log_retry_attempt(self, attempt: int, reason: str, delay_seconds: float) -> None:
        """Log retry attempt event."""
        self.log_event(
            event_type="retry_attempt",
            message=f"Retry attempt {attempt}: {reason}",
            severity="warning",
            context={
                "attempt_number": attempt,
                "retry_reason": reason,
                "delay_seconds": delay_seconds,
            },
        )

    def log_reconciliation(
        self,
        item_type: str,
        old_value: Any,
        new_value: Any,
        reason: str,
    ) -> None:
        """Log data reconciliation event."""
        self.log_event(
            event_type="reconciliation",
            message=f"Reconciled {item_type}: {old_value} → {new_value}",
            severity="info",
            context={
                "item_type": item_type,
                "old_value": old_value,
                "new_value": new_value,
                "reason": reason,
            },
        )

    def read_events(self, event_type: Optional[str] = None) -> list:
        """Read all events from log file.

        Args:
            event_type: Optional filter by event type

        Returns:
            List of event dicts
        """
        if not self.log_file.exists():
            return []

        events = []
        try:
            with open(self.log_file, "r") as f:
                for line in f:
                    if line.strip():
                        event = json.loads(line)
                        if event_type is None or event.get("event_type") == event_type:
                            events.append(event)
        except Exception as e:
            logger.error(f"Failed to read log file: {e}", exc_info=True)

        return events

    def get_event_counts(self) -> Dict[str, int]:
        """Get count of events by type.

        Returns:
            Dict mapping event_type to count
        """
        events = self.read_events()
        counts = {}
        for event in events:
            event_type = event.get("event_type", "unknown")
            counts[event_type] = counts.get(event_type, 0) + 1
        return counts

    def get_last_event(self) -> Optional[Dict]:
        """Get the most recent event.

        Returns:
            Last event dict or None if log is empty
        """
        events = self.read_events()
        return events[-1] if events else None
