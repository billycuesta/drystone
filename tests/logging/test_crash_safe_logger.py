"""Tests for crash-safe JSONL logger with durability guarantees."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from drystone.logging import CrashSafeLogger


class TestCrashSafeLogger:
    """Test crash-safe JSONL logger."""

    def test_init_creates_log_file(self):
        """Test that logger creates log file on init."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            assert log_file.exists(), "Log file should be created"

    def test_log_event_appends_to_file(self):
        """Test that events are appended to log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="iam")

            logger.log_event("test_event", "Test message", "info", {"key": "value"})

            # Read and verify
            with open(log_file, "r") as f:
                lines = f.readlines()

            assert len(lines) == 1, "Should have one event"
            event = json.loads(lines[0])
            assert event["event_type"] == "test_event"
            assert event["message"] == "Test message"
            assert event["skill"] == "iam"
            assert event["key"] == "value"

    def test_append_only_property(self):
        """Test that logger never truncates, only appends."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"

            # First logger instance
            logger1 = CrashSafeLogger(log_file, skill_name="test1")
            logger1.log_event("event1", "First event")

            # Second logger instance (should append, not truncate)
            logger2 = CrashSafeLogger(log_file, skill_name="test2")
            logger2.log_event("event2", "Second event")

            # Verify both events exist
            with open(log_file, "r") as f:
                lines = f.readlines()

            assert len(lines) == 2, "Should have two events (append-only)"
            event1 = json.loads(lines[0])
            event2 = json.loads(lines[1])
            assert event1["message"] == "First event"
            assert event2["message"] == "Second event"

    def test_log_skill_start(self):
        """Test logging skill start event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="network")

            logger.log_skill_start(evidence_count=42, checklist_items=28)

            with open(log_file, "r") as f:
                event = json.loads(f.readline())

            assert event["event_type"] == "skill_start"
            assert event["evidence_count"] == 42
            assert event["checklist_items"] == 28

    def test_log_skill_complete(self):
        """Test logging skill completion event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="exposure")

            logger.log_skill_complete(findings_count=5, risk_score=7.5)

            with open(log_file, "r") as f:
                event = json.loads(f.readline())

            assert event["event_type"] == "skill_complete"
            assert event["findings_count"] == 5
            assert event["risk_score"] == 7.5

    def test_log_validation_error(self):
        """Test logging validation failure event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="vulns")

            logger.log_validation_error(
                "Severity breakdown mismatch",
                {"expected": 18, "actual": 16}
            )

            with open(log_file, "r") as f:
                event = json.loads(f.readline())

            assert event["event_type"] == "validation_failed"
            assert event["severity"] == "error"
            assert event["expected"] == 18

    def test_log_retry_attempt(self):
        """Test logging retry attempt event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="iam")

            logger.log_retry_attempt(attempt=2, reason="validation_failed", delay_seconds=2.0)

            with open(log_file, "r") as f:
                event = json.loads(f.readline())

            assert event["event_type"] == "retry_attempt"
            assert event["attempt_number"] == 2
            assert event["retry_reason"] == "validation_failed"
            assert event["delay_seconds"] == 2.0

    def test_log_reconciliation(self):
        """Test logging data reconciliation event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="hardening")

            logger.log_reconciliation(
                item_type="total_findings",
                old_value=18,
                new_value=16,
                reason="Reconciled to match actual findings array"
            )

            with open(log_file, "r") as f:
                event = json.loads(f.readline())

            assert event["event_type"] == "reconciliation"
            assert event["item_type"] == "total_findings"
            assert event["old_value"] == 18
            assert event["new_value"] == 16

    def test_read_events_all(self):
        """Test reading all events from log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="alerting")

            logger.log_event("event1", "First")
            logger.log_event("event2", "Second")
            logger.log_event("event3", "Third")

            events = logger.read_events()
            assert len(events) == 3
            assert events[0]["message"] == "First"
            assert events[2]["message"] == "Third"

    def test_read_events_filtered(self):
        """Test reading events with type filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            logger.log_event("event_a", "Message A")
            logger.log_event("event_b", "Message B")
            logger.log_event("event_a", "Message C")

            events = logger.read_events(event_type="event_a")
            assert len(events) == 2
            assert all(e["event_type"] == "event_a" for e in events)

    def test_get_event_counts(self):
        """Test counting events by type."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            logger.log_event("skill_start", "Start")
            logger.log_event("validation_failed", "Error")
            logger.log_event("skill_start", "Start again")
            logger.log_event("validation_failed", "Error again")
            logger.log_event("skill_complete", "Done")

            counts = logger.get_event_counts()
            assert counts["skill_start"] == 2
            assert counts["validation_failed"] == 2
            assert counts["skill_complete"] == 1

    def test_get_last_event(self):
        """Test getting most recent event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            logger.log_event("event1", "First")
            logger.log_event("event2", "Last")

            last = logger.get_last_event()
            assert last["message"] == "Last"

    def test_get_last_event_empty_log(self):
        """Test get_last_event on empty log."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            last = logger.get_last_event()
            assert last is None

    def test_timestamp_recorded(self):
        """Test that events include timestamp."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            logger.log_event("test", "Message")

            with open(log_file, "r") as f:
                event = json.loads(f.readline())

            assert "timestamp" in event
            # Verify timestamp format (ISO 8601)
            try:
                datetime.fromisoformat(event["timestamp"])
            except ValueError:
                pytest.fail(f"Invalid timestamp format: {event['timestamp']}")

    def test_skill_name_recorded(self):
        """Test that skill name is recorded in all events."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="custom_skill")

            logger.log_event("test", "Message")

            with open(log_file, "r") as f:
                event = json.loads(f.readline())

            assert event["skill"] == "custom_skill"

    def test_nonexistent_directory_created(self):
        """Test that logger creates parent directories if they don't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "deep" / "nested" / "path" / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            assert log_file.parent.exists(), "Parent directories should be created"
            assert log_file.exists(), "Log file should be created"

    def test_read_events_empty_log(self):
        """Test reading events from empty log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.jsonl"
            logger = CrashSafeLogger(log_file, skill_name="test")

            events = logger.read_events()
            assert events == []

    def test_multiple_concurrent_logs(self):
        """Test that multiple loggers to different files work independently."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log1 = Path(tmpdir) / "log1.jsonl"
            log2 = Path(tmpdir) / "log2.jsonl"

            logger1 = CrashSafeLogger(log1, skill_name="skill1")
            logger2 = CrashSafeLogger(log2, skill_name="skill2")

            logger1.log_event("event1", "From log1")
            logger2.log_event("event2", "From log2")

            # Verify independence
            events1 = logger1.read_events()
            events2 = logger2.read_events()

            assert len(events1) == 1
            assert len(events2) == 1
            assert events1[0]["message"] == "From log1"
            assert events2[0]["message"] == "From log2"
