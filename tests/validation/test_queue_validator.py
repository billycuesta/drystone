"""Tests for queue validation before correlation."""

import json

from drystone.validation.queue_validator import QueueValidator


def test_validate_skill_output_accepts_symmetric_outputs(tmp_path):
    session_dir = tmp_path / "session"
    evidence_dir = session_dir / "evidence" / "iam"
    findings_dir = session_dir / "findings"
    evidence_dir.mkdir(parents=True)
    findings_dir.mkdir(parents=True)

    (evidence_dir / "users.json").write_text(json.dumps([{"UserName": "alice"}]))
    (findings_dir / "iam.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "IAM-001",
                        "evidence_refs": ["users.json#0"],
                    }
                ]
            }
        )
    )

    result = QueueValidator().validate_skill_output("iam", session_dir)
    assert result.valid is True
    assert result.should_correlate is True


def test_validate_skill_output_rejects_asymmetric_outputs(tmp_path):
    session_dir = tmp_path / "session"
    evidence_dir = session_dir / "evidence" / "iam"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "users.json").write_text(json.dumps([{"UserName": "alice"}]))

    result = QueueValidator().validate_skill_output("iam", session_dir)
    assert result.valid is False
    assert "findings" in (result.error or "")


def test_validate_skill_output_rejects_unresolved_refs(tmp_path):
    session_dir = tmp_path / "session"
    evidence_dir = session_dir / "evidence" / "iam"
    findings_dir = session_dir / "findings"
    evidence_dir.mkdir(parents=True)
    findings_dir.mkdir(parents=True)

    (evidence_dir / "users.json").write_text(json.dumps([{"UserName": "alice"}]))
    (findings_dir / "iam.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "IAM-001",
                        "evidence_refs": ["roles.json#admin"],
                    }
                ]
            }
        )
    )

    result = QueueValidator().validate_skill_output("iam", session_dir)
    assert result.valid is False
    assert "unresolved" in (result.error or "")


# ── Additional branch coverage ────────────────────────────────────────────────


class TestQueueValidatorBranches:
    def test_legacy_layout_fallback(self, tmp_path):
        """Lines 46-47: legacy <skill>/evidence + <skill>/findings layout."""
        leg_ev = tmp_path / "iam" / "evidence"
        leg_ev.mkdir(parents=True)
        (leg_ev / "raw.json").write_text(json.dumps({"users": []}))
        findings = tmp_path / "iam" / "findings" / "findings.json"
        findings.parent.mkdir(parents=True)
        findings.write_text(json.dumps({"findings": []}))

        result = QueueValidator().validate_skill_output("iam", tmp_path)
        assert result.valid is True
        assert result.should_correlate is True

    def test_both_missing_returns_valid_no_correlate(self, tmp_path):
        """Line 64: both evidence and findings absent → valid but excluded."""
        result = QueueValidator().validate_skill_output("iam", tmp_path)
        assert result.valid is True
        assert result.should_correlate is False
        assert result.retryable is False

    def test_invalid_json_in_findings(self, tmp_path):
        """Lines 69-70: JSONDecodeError branch."""
        ev = tmp_path / "evidence" / "iam"
        ev.mkdir(parents=True)
        (ev / "users.json").write_text("{}")
        fp = tmp_path / "findings" / "iam.json"
        fp.parent.mkdir(parents=True)
        fp.write_text("NOT JSON{{")
        result = QueueValidator().validate_skill_output("iam", tmp_path)
        assert result.valid is False
        assert "invalid JSON" in result.error

    def test_findings_not_a_list(self, tmp_path):
        """Line 79: findings field is not a list."""
        ev = tmp_path / "evidence" / "iam"
        ev.mkdir(parents=True)
        (ev / "users.json").write_text("{}")
        fp = tmp_path / "findings" / "iam.json"
        fp.parent.mkdir(parents=True)
        fp.write_text(json.dumps({"findings": "not-a-list"}))
        result = QueueValidator().validate_skill_output("iam", tmp_path)
        assert result.valid is False
        assert "missing array field" in result.error

    def test_finding_not_a_dict_is_skipped(self, tmp_path):
        """Line 90: non-dict entries in findings list are skipped."""
        ev = tmp_path / "evidence" / "iam"
        ev.mkdir(parents=True)
        (ev / "users.json").write_text("{}")
        fp = tmp_path / "findings" / "iam.json"
        fp.parent.mkdir(parents=True)
        fp.write_text(json.dumps({"findings": ["not-a-dict", 42]}))
        result = QueueValidator().validate_skill_output("iam", tmp_path)
        assert result.valid is True

    def test_refs_not_a_list_is_skipped(self, tmp_path):
        """Line 94: evidence_refs that is not a list is skipped."""
        ev = tmp_path / "evidence" / "iam"
        ev.mkdir(parents=True)
        (ev / "users.json").write_text("{}")
        fp = tmp_path / "findings" / "iam.json"
        fp.parent.mkdir(parents=True)
        fp.write_text(json.dumps({"findings": [{"id": "IAM-001", "evidence_refs": "not-list"}]}))
        result = QueueValidator().validate_skill_output("iam", tmp_path)
        assert result.valid is True

    def test_non_string_ref_is_skipped(self, tmp_path):
        """Line 97: non-string items in refs list are skipped."""
        ev = tmp_path / "evidence" / "iam"
        ev.mkdir(parents=True)
        (ev / "users.json").write_text("{}")
        fp = tmp_path / "findings" / "iam.json"
        fp.parent.mkdir(parents=True)
        fp.write_text(json.dumps({"findings": [{"id": "IAM-001", "evidence_refs": [123, None]}]}))
        result = QueueValidator().validate_skill_output("iam", tmp_path)
        assert result.valid is True

    def test_build_evidence_index_skips_corrupt_file(self, tmp_path):
        """Lines 115-116: Exception in _build_evidence_index is silenced."""
        bad = tmp_path / "bad.json"
        bad.write_text("NOT JSON")
        index = QueueValidator()._build_evidence_index([bad])
        assert "bad.json" not in index

    def test_get_existence_error_findings_without_evidence(self):
        """Line 127: findings exist but evidence missing."""
        msg = QueueValidator()._get_existence_error("iam", False, True)
        assert "evidence is missing" in msg

    def test_resolve_evidence_ref_empty_file_ref(self):
        """Line 144: empty file_ref after hash split returns False."""
        result = QueueValidator()._resolve_evidence_ref("#fragment-only", {})
        assert result is False
