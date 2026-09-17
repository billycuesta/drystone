"""Tests for multi-run trend analysis (P2 #3)."""

import json
from pathlib import Path

from drystone.core.trend_analysis import (
    TrendResult,
    compute_trend,
    find_previous_session,
)


def _make_session_dir(base: Path, client: str, timestamp: str, findings: dict) -> Path:
    session_dir = base / f"{client}_{timestamp}"
    findings_dir = session_dir / "findings"
    findings_dir.mkdir(parents=True)
    for skill, data in findings.items():
        (findings_dir / f"{skill}.json").write_text(json.dumps(data))
    return session_dir


class TestFindPreviousSession:
    def test_no_audit_logs_dir_returns_none(self, tmp_path):
        assert find_previous_session("ACME", tmp_path / "missing", tmp_path / "current") is None

    def test_no_prior_sessions_returns_none(self, tmp_path):
        current = _make_session_dir(tmp_path, "ACME", "2026-09-17T12-00-00", {})
        assert find_previous_session("ACME", tmp_path, current) is None

    def test_picks_most_recent_prior_session(self, tmp_path):
        _make_session_dir(tmp_path, "ACME", "2026-09-01T10-00-00", {})
        older_recent = _make_session_dir(tmp_path, "ACME", "2026-09-10T10-00-00", {})
        current = _make_session_dir(tmp_path, "ACME", "2026-09-17T12-00-00", {})

        result = find_previous_session("ACME", tmp_path, current)
        assert result == older_recent

    def test_ignores_other_clients(self, tmp_path):
        _make_session_dir(tmp_path, "OtherClient", "2026-09-16T10-00-00", {})
        current = _make_session_dir(tmp_path, "ACME", "2026-09-17T12-00-00", {})

        assert find_previous_session("ACME", tmp_path, current) is None

    def test_ignores_sessions_at_or_after_current(self, tmp_path):
        """A concurrent/later run for the same client is never "prior"."""
        current = _make_session_dir(tmp_path, "ACME", "2026-09-17T12-00-00", {})
        _make_session_dir(tmp_path, "ACME", "2026-09-17T13-00-00", {})  # later

        assert find_previous_session("ACME", tmp_path, current) is None

    def test_ignores_non_directory_entries(self, tmp_path):
        current = _make_session_dir(tmp_path, "ACME", "2026-09-17T12-00-00", {})
        (tmp_path / "ACME_notasession.txt").write_text("not a session")

        assert find_previous_session("ACME", tmp_path, current) is None


class TestComputeTrendNoBaseline:
    def test_none_previous_session_returns_empty_result(self):
        result = compute_trend({"iam": {"findings": []}}, None)
        assert isinstance(result, TrendResult)
        assert result.has_baseline is False
        assert result.previous_session is None
        assert result.skills == []


class TestComputeTrendDiffing:
    def _finding(self, id_, resources=None):
        return {"id": id_, "severity": "High", "affected_resources": resources or []}

    def test_new_finding_detected(self, tmp_path):
        prev = _make_session_dir(
            tmp_path, "ACME", "2026-09-10T10-00-00", {"iam": {"findings": []}}
        )
        current = {"iam": {"findings": [self._finding("IAM-001", ["arn:aws:iam::1:role/x"])]}}

        result = compute_trend(current, prev)
        assert len(result.skills) == 1
        assert result.skills[0].skill == "iam"
        assert [f["id"] for f in result.skills[0].new] == ["IAM-001"]
        assert result.skills[0].fixed == []
        assert result.skills[0].persisting_count == 0

    def test_fixed_finding_detected(self, tmp_path):
        prev_findings = {"iam": {"findings": [self._finding("IAM-001", ["arn:role/x"])]}}
        prev = _make_session_dir(tmp_path, "ACME", "2026-09-10T10-00-00", prev_findings)
        current = {"iam": {"findings": []}}

        result = compute_trend(current, prev)
        assert [f["id"] for f in result.skills[0].fixed] == ["IAM-001"]
        assert result.skills[0].new == []

    def test_persisting_finding_not_reported_as_new_or_fixed(self, tmp_path):
        finding = self._finding("IAM-001", ["arn:role/x"])
        prev = _make_session_dir(tmp_path, "ACME", "2026-09-10T10-00-00", {"iam": {"findings": [finding]}})
        current = {"iam": {"findings": [finding]}}

        result = compute_trend(current, prev)
        assert result.skills[0].new == []
        assert result.skills[0].fixed == []
        assert result.skills[0].persisting_count == 1

    def test_same_id_different_resources_is_new_and_fixed_not_persisting(self, tmp_path):
        """A different affected_resources set is a different finding instance."""
        prev_finding = self._finding("NET-003", ["sg-old"])
        prev = _make_session_dir(
            tmp_path, "ACME", "2026-09-10T10-00-00", {"network": {"findings": [prev_finding]}}
        )
        current_finding = self._finding("NET-003", ["sg-new"])
        current = {"network": {"findings": [current_finding]}}

        result = compute_trend(current, prev)
        assert [f["affected_resources"] for f in result.skills[0].new] == [["sg-new"]]
        assert [f["affected_resources"] for f in result.skills[0].fixed] == [["sg-old"]]
        assert result.skills[0].persisting_count == 0

    def test_skill_missing_in_previous_session_skipped_not_all_new(self, tmp_path):
        """A skill audited only this time has no baseline -- not diffed at all."""
        prev = _make_session_dir(tmp_path, "ACME", "2026-09-10T10-00-00", {"iam": {"findings": []}})
        current = {
            "iam": {"findings": []},
            "network": {"findings": [self._finding("NET-001")]},
        }

        result = compute_trend(current, prev)
        skill_names = [s.skill for s in result.skills]
        assert "network" not in skill_names

    def test_skill_missing_in_current_session_not_reported_as_fixed(self, tmp_path):
        """A skill audited only last time is out of scope now, not "fixed"."""
        prev_findings = {
            "iam": {"findings": []},
            "vulns": {"findings": [self._finding("VULN-001")]},
        }
        prev = _make_session_dir(tmp_path, "ACME", "2026-09-10T10-00-00", prev_findings)
        current = {"iam": {"findings": []}}

        result = compute_trend(current, prev)
        skill_names = [s.skill for s in result.skills]
        assert "vulns" not in skill_names

    def test_skill_with_no_changes_omitted_from_result(self, tmp_path):
        prev = _make_session_dir(tmp_path, "ACME", "2026-09-10T10-00-00", {"iam": {"findings": []}})
        current = {"iam": {"findings": []}}

        result = compute_trend(current, prev)
        assert result.skills == []

    def test_malformed_previous_json_skipped_gracefully(self, tmp_path):
        session_dir = tmp_path / "ACME_2026-09-10T10-00-00"
        (session_dir / "findings").mkdir(parents=True)
        (session_dir / "findings" / "iam.json").write_text("{not valid json")
        current = {"iam": {"findings": [self._finding("IAM-001")]}}

        result = compute_trend(current, session_dir)
        assert result.skills == []

    def test_to_dict_shape(self, tmp_path):
        prev = _make_session_dir(tmp_path, "ACME", "2026-09-10T10-00-00", {"iam": {"findings": []}})
        current = {"iam": {"findings": [self._finding("IAM-001")]}}

        result = compute_trend(current, prev)
        as_dict = result.to_dict()
        assert as_dict["previous_session"] == prev.name
        assert as_dict["skills"][0]["skill"] == "iam"
        assert len(as_dict["skills"][0]["new"]) == 1
        assert as_dict["skills"][0]["persisting_count"] == 0
