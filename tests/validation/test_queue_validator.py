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
