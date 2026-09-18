import json
from unittest.mock import MagicMock, patch

import pytest

from drystone.verification.active_verifier import VerificationResult
from drystone.verification.runner import (
    _region_from_evidence_metadata,
    _role_arns_from_correlated,
    _s3_buckets_from_findings,
    run_active_verification,
)


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


class TestTargetExtraction:
    def test_role_arns_from_correlated_matches_pattern_only(self, tmp_path):
        correlated = tmp_path / "correlated.json"
        _write(
            correlated,
            {
                "correlations": [
                    {
                        "id": "CORR-001",
                        "pattern_id": "iam_assume_role_privilege_escalation",
                        "affected_resources": [
                            "arn:aws:iam::111111111111:role/AdminRole",
                            "arn:aws:s3:::unrelated-bucket",
                        ],
                    },
                    {
                        "id": "CORR-002",
                        "pattern_id": "some_other_pattern",
                        "affected_resources": ["arn:aws:iam::111111111111:role/Ignored"],
                    },
                ]
            },
        )

        targets = _role_arns_from_correlated(correlated)

        assert targets == [("CORR-001", "arn:aws:iam::111111111111:role/AdminRole")]

    def test_role_arns_missing_file_returns_empty(self, tmp_path):
        assert _role_arns_from_correlated(tmp_path / "nope.json") == []

    def test_s3_buckets_from_exp_001_only(self, tmp_path):
        findings_dir = tmp_path / "findings"
        _write(
            findings_dir / "exposure.json",
            {
                "findings": [
                    {
                        "id": "EXP-001",
                        "affected_resources": ["arn:aws:s3:::public-bucket"],
                    },
                    {
                        "id": "EXP-002",
                        "affected_resources": ["arn:aws:rds:us-east-1:111111111111:db:mydb"],
                    },
                ]
            },
        )

        targets = _s3_buckets_from_findings(findings_dir)

        assert targets == [("EXP-001", "public-bucket")]

    def test_s3_buckets_missing_exposure_file_returns_empty(self, tmp_path):
        assert _s3_buckets_from_findings(tmp_path / "findings") == []

    def test_region_from_evidence_metadata_uses_collected_region(self, tmp_path):
        metadata = tmp_path / "evidence" / "exposure" / "_audit_metadata.json"
        _write(metadata, {"_region": "eu-west-1"})

        assert _region_from_evidence_metadata(tmp_path, "exposure") == "eu-west-1"

    def test_region_from_evidence_metadata_defaults_when_missing(self, tmp_path):
        assert _region_from_evidence_metadata(tmp_path, "exposure") == "us-east-1"


class TestRunActiveVerification:
    def test_writes_log_and_annotates_successful_findings(self, tmp_path):
        findings_dir = tmp_path / "findings"
        _write(
            findings_dir / "correlated.json",
            {
                "correlations": [
                    {
                        "id": "CORR-001",
                        "pattern_id": "iam_assume_role_privilege_escalation",
                        "affected_resources": ["arn:aws:iam::111111111111:role/AdminRole"],
                    }
                ]
            },
        )
        _write(
            findings_dir / "exposure.json",
            {"findings": [{"id": "EXP-001", "affected_resources": ["arn:aws:s3:::pub-bucket"]}]},
        )

        assume_result = VerificationResult(
            method="sts_assume_role",
            target="arn:aws:iam::111111111111:role/AdminRole",
            attempted=True,
            result="success",
            detail="confirmed",
        )
        s3_result = VerificationResult(
            method="s3_unauthenticated_head_bucket",
            target="pub-bucket",
            attempted=True,
            result="denied",
            detail="403",
        )

        _write(tmp_path / "evidence" / "exposure" / "_audit_metadata.json", {"_region": "eu-west-1"})

        with (
            patch(
                "drystone.verification.runner.verify_assume_role", return_value=assume_result
            ),
            patch(
                "drystone.verification.runner.verify_s3_public_access", return_value=s3_result
            ) as s3_verify,
        ):
            summary = run_active_verification(tmp_path, MagicMock())

        s3_verify.assert_called_once_with("pub-bucket", region_name="eu-west-1")

        assert summary["attempted"] == 2
        assert summary["succeeded"] == 1
        assert summary["denied"] == 1
        assert summary["errored"] == 0

        log_data = json.loads((tmp_path / "active_verification_log.json").read_text())
        assert log_data["attempt_count"] == 2
        methods = {a["method"] for a in log_data["attempts"]}
        assert methods == {"sts_assume_role", "s3_unauthenticated_head_bucket"}

        # Only the successful AssumeRole should be annotated onto correlated.json.
        correlated_after = json.loads((findings_dir / "correlated.json").read_text())
        assert correlated_after["correlations"][0]["active_verification"]["result"] == "success"

        # The denied S3 attempt must NOT annotate exposure.json (no false "validated" claim).
        exposure_after = json.loads((findings_dir / "exposure.json").read_text())
        assert "active_verification" not in exposure_after["findings"][0]

    def test_no_targets_writes_empty_log_without_error(self, tmp_path):
        (tmp_path / "findings").mkdir()

        summary = run_active_verification(tmp_path, MagicMock())

        assert summary["attempted"] == 0
        assert (tmp_path / "active_verification_log.json").exists()

    def test_never_raises_even_if_a_verifier_blows_up(self, tmp_path):
        findings_dir = tmp_path / "findings"
        _write(
            findings_dir / "correlated.json",
            {
                "correlations": [
                    {
                        "id": "CORR-001",
                        "pattern_id": "iam_assume_role_privilege_escalation",
                        "affected_resources": ["arn:aws:iam::111111111111:role/AdminRole"],
                    }
                ]
            },
        )

        with patch(
            "drystone.verification.runner.verify_assume_role",
            side_effect=RuntimeError("boom"),
        ):
            # Should propagate: run_active_verification only guards against errors
            # *reported by* a verifier (VerificationResult with result="error"),
            # not against a verifier crashing outright -- that's a bug, not a
            # denied/erroring attempt, and the CLI phase wraps this call in its
            # own try/except so an audit run still can't be aborted by it.
            with pytest.raises(RuntimeError):
                run_active_verification(tmp_path, MagicMock())
