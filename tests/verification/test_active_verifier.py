"""Unit tests for the two active verifiers (AssumeRole, S3 public access).

moto isn't in this repo's dev dependencies, so these mock boto3/botocore
clients directly rather than simulating real AWS behavior.
"""

from unittest.mock import MagicMock, patch

import botocore.exceptions

from drystone.verification.active_verifier import (
    _role_session_name,
    verify_assume_role,
    verify_s3_public_access,
)


def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "boom"}}, "SomeOperation"
    )


class TestRoleSessionName:
    def test_prefixed_and_labeled(self):
        name = _role_session_name("CORR-abc123-001")
        assert name.startswith("drystone-authorized-security-audit-")
        assert "CORR-abc123-001" in name

    def test_sanitizes_invalid_characters(self):
        name = _role_session_name("weird/label with spaces!")
        assert "/" not in name
        assert " " not in name
        assert "!" not in name

    def test_truncated_to_64_chars(self):
        name = _role_session_name("x" * 100)
        assert len(name) <= 64


class TestVerifyAssumeRole:
    def test_success_confirms_identity_change(self):
        session = MagicMock()
        sts_client = MagicMock()
        sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA...",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }
        session.client.return_value = sts_client

        assumed_sts = MagicMock()
        assumed_sts.get_caller_identity.return_value = {
            "Arn": "arn:aws:sts::111111111111:assumed-role/AdminRole/drystone-audit"
        }

        with patch("drystone.verification.active_verifier.boto3.client", return_value=assumed_sts):
            result = verify_assume_role(
                session, "arn:aws:iam::111111111111:role/AdminRole", "CORR-001"
            )

        assert result.result == "success"
        assert result.attempted is True
        assert "AdminRole/drystone-audit" in result.detail
        sts_client.assume_role.assert_called_once()
        call_kwargs = sts_client.assume_role.call_args.kwargs
        assert call_kwargs["RoleArn"] == "arn:aws:iam::111111111111:role/AdminRole"
        assert call_kwargs["DurationSeconds"] == 900

    def test_denied_does_not_raise_and_is_not_success(self):
        session = MagicMock()
        sts_client = MagicMock()
        sts_client.assume_role.side_effect = _client_error("AccessDenied")
        session.client.return_value = sts_client

        result = verify_assume_role(session, "arn:aws:iam::111111111111:role/X", "CORR-002")

        assert result.result == "denied"
        assert result.attempted is True
        assert "AccessDenied" in result.detail

    def test_success_even_if_confirmation_call_fails(self):
        """AssumeRole itself succeeding is real proof even if the follow-up
        get_caller_identity call errors -- must not be discarded."""
        session = MagicMock()
        sts_client = MagicMock()
        sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA...",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }
        session.client.return_value = sts_client

        with patch(
            "drystone.verification.active_verifier.boto3.client",
            side_effect=Exception("network blip"),
        ):
            result = verify_assume_role(session, "arn:aws:iam::111111111111:role/X", "CORR-003")

        assert result.result == "success"

    def test_unexpected_error_is_captured_not_raised(self):
        session = MagicMock()
        session.client.side_effect = RuntimeError("credentials expired")

        result = verify_assume_role(session, "arn:aws:iam::111111111111:role/X", "CORR-004")

        assert result.result == "error"
        assert "credentials expired" in result.detail


class TestVerifyS3PublicAccess:
    def test_head_bucket_success(self):
        s3 = MagicMock()
        s3.head_bucket.return_value = {}

        result = verify_s3_public_access("my-bucket", s3_client_factory=lambda: s3)

        assert result.method == "s3_unauthenticated_head_bucket"
        assert result.result == "success"
        s3.list_objects_v2.assert_not_called()

    def test_head_denied_falls_back_to_list_objects(self):
        s3 = MagicMock()
        s3.head_bucket.side_effect = _client_error("403")
        s3.list_objects_v2.return_value = {"KeyCount": 3}

        result = verify_s3_public_access("my-bucket", s3_client_factory=lambda: s3)

        assert result.method == "s3_unauthenticated_list_objects"
        assert result.result == "success"
        assert "KeyCount=3" in result.detail

    def test_head_and_list_both_denied(self):
        s3 = MagicMock()
        s3.head_bucket.side_effect = _client_error("403")
        s3.list_objects_v2.side_effect = _client_error("AccessDenied")

        result = verify_s3_public_access("my-bucket", s3_client_factory=lambda: s3)

        assert result.result == "denied"

    def test_bucket_not_found_skips_list_objects(self):
        s3 = MagicMock()
        s3.head_bucket.side_effect = _client_error("404")

        result = verify_s3_public_access("my-bucket", s3_client_factory=lambda: s3)

        assert result.result == "denied"
        s3.list_objects_v2.assert_not_called()

    def test_never_calls_get_object(self):
        """Hard safety invariant: this verifier must never read object content."""
        s3 = MagicMock()
        s3.head_bucket.return_value = {}

        verify_s3_public_access("my-bucket", s3_client_factory=lambda: s3)

        s3.get_object.assert_not_called()
