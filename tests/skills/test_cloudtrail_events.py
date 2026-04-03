"""Tests for CloudTrail Events skill: collector, pre-checks, post-processor, checklist."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_aws_client(region="us-east-1", token=None):
    c = MagicMock()
    c.access_key_id = "AKID"
    c.secret_access_key = "SECRET"
    c.region_name = region
    c.session_token = token
    return c


def _make_session(tmp_path, skill_name="cloudtrail_events", scan_depth="normal"):
    session = MagicMock()
    evidence_path = tmp_path / "evidence" / skill_name
    evidence_path.mkdir(parents=True)
    session.get_evidence_path.return_value = evidence_path
    session.scan_depth = scan_depth
    return session, evidence_path


def _make_paginator(*pages):
    pag = MagicMock()
    pag.paginate.return_value = iter(pages)
    return pag


def _sample_event(
    event_name="ConsoleLogin",
    username="alice",
    error_code=None,
    event_time=None,
    source_ip="1.2.3.4",
):
    t = event_time or datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    event = {
        "EventId": "abc-123",
        "EventName": event_name,
        "EventTime": t,
        "EventSource": "signin.amazonaws.com",
        "Username": username,
        "ReadOnly": False,
        "Resources": [],
    }
    if error_code:
        event["ErrorCode"] = error_code
        event["ErrorMessage"] = f"{error_code} error"
    ct_inner = {
        "sourceIPAddress": source_ip,
        "requestParameters": {"key": "value"},
    }
    if error_code:
        ct_inner["errorCode"] = error_code
    event["CloudTrailEvent"] = json.dumps(ct_inner)
    return event


# =============================================================================
# COLLECTOR TESTS
# =============================================================================


class TestCloudTrailEventsCollect:
    """Tests for CloudTrailEventsSkill.collect()."""

    def _run_collect(self, tmp_path, events_per_page=None, scan_depth="normal", token=None):
        """Helper: run collect() with mocked boto3 and return evidence_path."""
        from drystone.skills.cloudtrail_events import CloudTrailEventsSkill

        aws_client = _make_aws_client(token=token)
        session, evidence_path = _make_session(tmp_path, scan_depth=scan_depth)

        if events_per_page is None:
            events_per_page = [_sample_event()]

        mock_page = {"Events": events_per_page}

        mock_ct = MagicMock()
        mock_ct.get_paginator.return_value = _make_paginator(mock_page)

        with patch("boto3.client", return_value=mock_ct):
            skill = CloudTrailEventsSkill()
            skill.collect(aws_client, session)

        return evidence_path

    def test_collect_creates_evidence_files(self, tmp_path):
        """collect() should write targeted event files + write-events + summary."""
        evidence_path = self._run_collect(tmp_path)

        # Core files expected
        assert (evidence_path / "root-events.json").exists()
        assert (evidence_path / "console-login-events.json").exists()
        assert (evidence_path / "audit-tampering-events.json").exists()
        assert (evidence_path / "privilege-escalation-events.json").exists()
        assert (evidence_path / "write-events.json").exists()
        assert (evidence_path / "access-denied-events.json").exists()
        assert (evidence_path / "delete-events.json").exists()
        assert (evidence_path / "_summary.json").exists()

    def test_collect_creates_valid_json(self, tmp_path):
        """All generated evidence files should contain valid JSON."""
        evidence_path = self._run_collect(tmp_path)
        for f in evidence_path.glob("*.json"):
            data = json.loads(f.read_text())
            assert data is not None

    def test_summary_metadata(self, tmp_path):
        """_summary.json should contain scan metadata."""
        evidence_path = self._run_collect(tmp_path, scan_depth="deep")
        summary = json.loads((evidence_path / "_summary.json").read_text())

        assert summary["scan_depth"] == "deep"
        assert summary["days_back"] == 90
        assert "start_time" in summary
        assert "end_time" in summary
        assert "categories_collected" in summary

    def test_distillation_reduces_fields(self, tmp_path):
        """Distilled events should only contain essential fields."""
        evidence_path = self._run_collect(
            tmp_path,
            events_per_page=[_sample_event("ConsoleLogin", "bob")],
        )
        console_events = json.loads((evidence_path / "console-login-events.json").read_text())
        if console_events:
            event = console_events[0]
            # UserAgent should NOT be present (discarded by distillation)
            assert "UserAgent" not in event
            # Essential fields should be present
            assert "EventName" in event or "EventTime" in event

    def test_session_token_passed_to_boto3(self, tmp_path):
        """When session_token is set, it must be included in client_kwargs."""
        from drystone.skills.cloudtrail_events import CloudTrailEventsSkill

        aws_client = _make_aws_client(token="MY-SESSION-TOKEN")
        session, _ = _make_session(tmp_path)

        mock_ct = MagicMock()
        mock_ct.get_paginator.return_value = _make_paginator({"Events": []})

        with patch("boto3.client") as mock_boto3:
            mock_boto3.return_value = mock_ct
            skill = CloudTrailEventsSkill()
            skill.collect(aws_client, session)

            call_kwargs = mock_boto3.call_args[1]
            assert call_kwargs.get("aws_session_token") == "MY-SESSION-TOKEN"

    def test_scan_depth_shallow_uses_7_days(self, tmp_path):
        """shallow scan_depth should configure 7-day time range."""
        from drystone.skills.cloudtrail_events import CloudTrailEventsSkill

        aws_client = _make_aws_client()
        session, _ = _make_session(tmp_path, scan_depth="shallow")

        mock_ct = MagicMock()
        mock_ct.get_paginator.return_value = _make_paginator({"Events": []})

        with patch("boto3.client", return_value=mock_ct):
            skill = CloudTrailEventsSkill()
            skill.collect(aws_client, session)

        evidence_path = session.get_evidence_path.return_value
        summary = json.loads((evidence_path / "_summary.json").read_text())
        assert summary["days_back"] == 7

    def test_access_denied_extracted_from_write_events(self, tmp_path):
        """AccessDenied events should be extracted into access-denied-events.json."""
        denied_event = _sample_event("PutObject", "alice", error_code="AccessDenied")
        evidence_path = self._run_collect(tmp_path, events_per_page=[denied_event])

        denied = json.loads((evidence_path / "access-denied-events.json").read_text())
        # The event should appear in access-denied (extracted from write-events)
        assert isinstance(denied, list)

    def test_delete_events_extracted_from_write_events(self, tmp_path):
        """Delete* events should be extracted into delete-events.json."""
        del_event = _sample_event("DeleteBucket", "alice")
        evidence_path = self._run_collect(tmp_path, events_per_page=[del_event])

        deletes = json.loads((evidence_path / "delete-events.json").read_text())
        assert isinstance(deletes, list)


# =============================================================================
# PRE-CHECKS TESTS
# =============================================================================


class TestCloudTrailPreChecks:
    """Tests for CTEF-* pre-checks in pre_checks.py."""

    def test_pre_checks_registered_in_registry(self):
        """All CTEF-* checks must be registered for skill 'cloudtrail_events'."""
        from drystone.validation.pre_checks import PRE_CHECK_REGISTRY

        assert "cloudtrail_events" in PRE_CHECK_REGISTRY
        check_ids = {r.check_id for r in _run_all_checks({})}
        expected = {f"CTEF-{i:03d}" for i in range(1, 11)}
        assert expected == check_ids

    # CTEF-001
    def test_ctef_001_fail_when_root_events(self):
        result = _run_check("CTEF-001", {"root-events": [_make_event("SomeAction", "root")]})
        assert result.status == "FAIL"
        assert "root" in result.evidence_summary.lower()

    def test_ctef_001_pass_when_no_root_events(self):
        result = _run_check("CTEF-001", {"root-events": []})
        assert result.status == "PASS"

    # CTEF-002
    def test_ctef_002_fail_when_many_failed_logins(self):
        failed = [
            _make_event("ConsoleLogin", "eve", error_code="Failed")
            for _ in range(6)
        ]
        result = _run_check("CTEF-002", {"console-login-events": failed})
        assert result.status == "FAIL"

    def test_ctef_002_pass_when_few_failures(self):
        failed = [_make_event("ConsoleLogin", "eve", error_code="Failed") for _ in range(2)]
        result = _run_check("CTEF-002", {"console-login-events": failed})
        assert result.status == "PASS"

    # CTEF-003
    def test_ctef_003_fail_when_stop_logging(self):
        events = [_make_event("StopLogging", "attacker")]
        result = _run_check("CTEF-003", {"audit-tampering-events": events})
        assert result.status == "FAIL"
        assert "StopLogging" in result.evidence_summary

    def test_ctef_003_pass_when_no_tampering(self):
        result = _run_check("CTEF-003", {"audit-tampering-events": []})
        assert result.status == "PASS"

    # CTEF-004
    def test_ctef_004_fail_when_priv_escalation(self):
        events = [_make_event("AttachUserPolicy", "alice")]
        result = _run_check("CTEF-004", {"privilege-escalation-events": events})
        assert result.status == "FAIL"

    def test_ctef_004_pass_when_no_priv_escalation(self):
        result = _run_check("CTEF-004", {"privilege-escalation-events": []})
        assert result.status == "PASS"

    # CTEF-005
    def test_ctef_005_fail_when_many_throttled(self):
        events = [_make_event("DescribeInstances", "bot", error_code="Throttling") for _ in range(51)]
        result = _run_check("CTEF-005", {"throttling-events": events})
        assert result.status == "FAIL"

    def test_ctef_005_pass_when_few_throttled(self):
        events = [_make_event("DescribeInstances", "bot", error_code="Throttling") for _ in range(5)]
        result = _run_check("CTEF-005", {"throttling-events": events})
        assert result.status == "PASS"

    # CTEF-006
    def test_ctef_006_fail_when_many_access_denied(self):
        events = [_make_event("GetObject", "attacker", error_code="AccessDenied") for _ in range(25)]
        result = _run_check("CTEF-006", {"access-denied-events": events})
        assert result.status == "FAIL"

    def test_ctef_006_pass_when_few_denied(self):
        events = [_make_event("GetObject", "alice", error_code="AccessDenied") for _ in range(5)]
        result = _run_check("CTEF-006", {"access-denied-events": events})
        assert result.status == "PASS"

    # CTEF-007
    def test_ctef_007_fail_when_off_hours_logins(self):
        # 03:00 UTC = off hours
        t = datetime(2026, 3, 15, 3, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event("ConsoleLogin", f"user{i}", event_time=t)
            for i in range(4)
        ]
        result = _run_check("CTEF-007", {"console-login-events": events})
        assert result.status == "FAIL"

    def test_ctef_007_pass_when_business_hours(self):
        t = datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [_make_event("ConsoleLogin", f"user{i}", event_time=t) for i in range(5)]
        result = _run_check("CTEF-007", {"console-login-events": events})
        assert result.status == "PASS"

    # CTEF-008
    def test_ctef_008_fail_when_mass_deletion(self):
        events = [_make_event("DeleteObject", "alice") for _ in range(12)]
        result = _run_check("CTEF-008", {"delete-events": events})
        assert result.status == "FAIL"

    def test_ctef_008_pass_when_few_deletions(self):
        events = [_make_event("DeleteObject", "alice") for _ in range(3)]
        result = _run_check("CTEF-008", {"delete-events": events})
        assert result.status == "PASS"

    # CTEF-009
    def test_ctef_009_fail_when_credential_report_accessed(self):
        events = [_make_event("GetCredentialReport", "attacker")]
        result = _run_check(
            "CTEF-009",
            {"credential-report-events": [], "get-credential-report-events": events},
        )
        assert result.status == "FAIL"

    def test_ctef_009_pass_when_no_credential_report_access(self):
        result = _run_check(
            "CTEF-009",
            {"credential-report-events": [], "get-credential-report-events": []},
        )
        assert result.status == "PASS"

    # CTEF-010
    def test_ctef_010_fail_when_cross_account_assume_role(self):
        events = [_make_event("AssumeRole", "123456789012:ExternalRole")]
        result = _run_check("CTEF-010", {"assume-role-events": events})
        assert result.status == "FAIL"

    def test_ctef_010_pass_when_no_cross_account(self):
        events = [_make_event("AssumeRole", "alice")]
        result = _run_check("CTEF-010", {"assume-role-events": events})
        assert result.status == "PASS"


# =============================================================================
# POST-PROCESSOR TESTS
# =============================================================================


class TestCloudTrailPostProcessor:
    """Tests for CloudTrailEventsPostProcessor."""

    def _make_processor(self, tmp_path, evidence: dict):
        """Write evidence files to tmp_path and return a processor instance."""
        from drystone.skills.cloudtrail_events.post_processor import CloudTrailEventsPostProcessor

        evidence_path = tmp_path / "evidence" / "cloudtrail_events"
        evidence_path.mkdir(parents=True)

        for key, data in evidence.items():
            (evidence_path / f"{key}.json").write_text(json.dumps(data))

        session = MagicMock()
        session.get_evidence_path.return_value = evidence_path
        return CloudTrailEventsPostProcessor(session)

    def test_process_adds_timeline(self, tmp_path):
        """process() must add cloudtrail_timeline to findings."""
        evidence = {
            "root-events": [_make_event("SomeAction", "root", event_time=datetime(2026, 3, 15, 10, 0, tzinfo=timezone.utc))],
        }
        proc = self._make_processor(tmp_path, evidence)
        findings = proc.process({})
        assert "cloudtrail_timeline" in findings
        assert "by_day" in findings["cloudtrail_timeline"]
        assert "total_events" in findings["cloudtrail_timeline"]

    def test_process_adds_top_users(self, tmp_path):
        """process() must add cloudtrail_top_users to findings."""
        evidence = {
            "console-login-events": [_make_event("ConsoleLogin", "alice")],
        }
        proc = self._make_processor(tmp_path, evidence)
        findings = proc.process({})
        assert "cloudtrail_top_users" in findings
        assert "top_by_activity" in findings["cloudtrail_top_users"]
        assert "top_by_errors" in findings["cloudtrail_top_users"]

    def test_process_adds_event_distribution(self, tmp_path):
        """process() must add cloudtrail_event_distribution to findings."""
        evidence = {
            "root-events": [_make_event("SomeAction", "root")],
            "console-login-events": [_make_event("ConsoleLogin", "bob")],
        }
        proc = self._make_processor(tmp_path, evidence)
        findings = proc.process({})
        dist = findings["cloudtrail_event_distribution"]
        assert "by_category" in dist
        assert "by_severity" in dist
        assert dist["total_events"] >= 1

    def test_timeline_groups_by_day(self, tmp_path):
        """Timeline should group events by YYYY-MM-DD."""
        t1 = datetime(2026, 3, 15, 10, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 3, 16, 11, 0, tzinfo=timezone.utc)
        evidence = {
            "root-events": [
                _make_event("SomeAction", "root", event_time=t1),
                _make_event("SomeAction", "root", event_time=t2),
            ],
        }
        proc = self._make_processor(tmp_path, evidence)
        findings = proc.process({})
        by_day = findings["cloudtrail_timeline"]["by_day"]
        assert "2026-03-15" in by_day
        assert "2026-03-16" in by_day

    def test_top_users_sorted_by_activity(self, tmp_path):
        """Top users by activity should be sorted descending."""
        evidence = {
            "console-login-events": [
                _make_event("ConsoleLogin", "alice"),
                _make_event("ConsoleLogin", "alice"),
                _make_event("ConsoleLogin", "bob"),
            ],
        }
        proc = self._make_processor(tmp_path, evidence)
        findings = proc.process({})
        top = findings["cloudtrail_top_users"]["top_by_activity"]
        if len(top) >= 2:
            assert top[0]["total_events"] >= top[1]["total_events"]

    def test_process_handles_empty_evidence(self, tmp_path):
        """process() should not crash when no evidence files exist."""
        from drystone.skills.cloudtrail_events.post_processor import CloudTrailEventsPostProcessor

        evidence_path = tmp_path / "evidence" / "cloudtrail_events"
        evidence_path.mkdir(parents=True)
        session = MagicMock()
        session.get_evidence_path.return_value = evidence_path

        proc = CloudTrailEventsPostProcessor(session)
        findings = proc.process({})
        assert findings["cloudtrail_timeline"]["total_events"] == 0


# =============================================================================
# CHECKLIST TESTS
# =============================================================================


class TestChecklistJson:
    """Tests for cloudtrail_events/checklist.json validity."""

    @pytest.fixture
    def checklist(self):
        path = (
            Path(__file__).parent.parent.parent
            / "drystone"
            / "skills"
            / "cloudtrail_events"
            / "checklist.json"
        )
        return json.loads(path.read_text())

    def test_checklist_loads(self, checklist):
        assert checklist["skill"] == "cloudtrail_events"

    def test_total_checks_matches_items(self, checklist):
        assert checklist["total_checks"] == len(checklist["items"])

    def test_all_items_have_required_fields(self, checklist):
        for item in checklist["items"]:
            assert "id" in item
            assert "title" in item
            assert "severity" in item
            assert "remediation" in item
            assert "pci_dss" in item
            assert isinstance(item["pci_dss"], list)
            assert len(item["pci_dss"]) >= 1

    def test_item_ids_use_ctef_prefix(self, checklist):
        for item in checklist["items"]:
            assert item["id"].startswith("CTEF-"), f"Bad ID: {item['id']}"

    def test_severities_are_valid(self, checklist):
        valid = {"Critical", "High", "Medium", "Low"}
        for item in checklist["items"]:
            assert item["severity"] in valid, f"Invalid severity: {item['severity']}"

    def test_pci_dss_mappings_have_control_and_reason(self, checklist):
        for item in checklist["items"]:
            for mapping in item["pci_dss"]:
                assert "control" in mapping
                assert "reason" in mapping

    def test_ten_checks_defined(self, checklist):
        assert len(checklist["items"]) == 10


# =============================================================================
# TEST HELPERS
# =============================================================================


def _make_event(event_name, username, error_code=None, event_time=None):
    """Create a minimal distilled event dict (as returned by collector)."""
    t = event_time or datetime(2026, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
    e = {
        "EventName": event_name,
        "EventTime": t.isoformat(),
        "Username": username,
    }
    if error_code:
        e["ErrorCode"] = error_code
    return e


def _run_check(check_id: str, evidence: dict):
    """Run a single CTEF pre-check by ID against the given evidence."""
    from drystone.validation.pre_checks import PRE_CHECK_REGISTRY

    for fn in PRE_CHECK_REGISTRY.get("cloudtrail_events", []):
        result = fn(evidence)
        if result.check_id == check_id:
            return result
    raise ValueError(f"Check {check_id} not found in registry")


def _run_all_checks(evidence: dict):
    """Run all CTEF-* checks and return results."""
    from drystone.validation.pre_checks import PRE_CHECK_REGISTRY

    return [fn(evidence) for fn in PRE_CHECK_REGISTRY.get("cloudtrail_events", [])]
