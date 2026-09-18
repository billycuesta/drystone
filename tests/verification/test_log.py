import json

from drystone.verification.active_verifier import VerificationResult
from drystone.verification.log import LOG_FILENAME, write_verification_log


def test_write_verification_log_persists_all_attempt_fields(tmp_path):
    results = [
        VerificationResult(
            method="s3_unauthenticated_head_bucket",
            target="public-bucket",
            attempted=True,
            result="success",
            detail="HEAD succeeded",
            timestamp="2026-09-18T10:00:00+00:00",
        ),
        VerificationResult(
            method="sts_assume_role",
            target="arn:aws:iam::123456789012:role/Admin",
            attempted=True,
            result="denied",
            detail="AccessDenied",
            timestamp="2026-09-18T10:01:00+00:00",
        ),
    ]

    path = write_verification_log(tmp_path, results)

    assert path == tmp_path / LOG_FILENAME
    payload = json.loads(path.read_text())
    assert payload["attempt_count"] == 2
    assert payload["attempts"] == [
        {
            "method": "s3_unauthenticated_head_bucket",
            "target": "public-bucket",
            "attempted": True,
            "result": "success",
            "detail": "HEAD succeeded",
            "timestamp": "2026-09-18T10:00:00+00:00",
        },
        {
            "method": "sts_assume_role",
            "target": "arn:aws:iam::123456789012:role/Admin",
            "attempted": True,
            "result": "denied",
            "detail": "AccessDenied",
            "timestamp": "2026-09-18T10:01:00+00:00",
        },
    ]


def test_write_verification_log_creates_empty_audit_record(tmp_path):
    path = write_verification_log(tmp_path, [])

    payload = json.loads(path.read_text())
    assert payload["attempt_count"] == 0
    assert payload["attempts"] == []
    assert payload["generated_at"]
