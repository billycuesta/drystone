"""Tests for AWS credential validation client."""

from unittest.mock import MagicMock, patch

import botocore.exceptions

from drystone.cloud.aws.client import AWSClient, validate_aws_credentials
from drystone.models.config import WizardConfig

# ── fixtures ──────────────────────────────────────────────────────────────────

VALID_IDENTITY = {
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/alice",
    "UserId": "AIDIOSFODNN7EXAMPLE",
}


def make_config(**kwargs) -> WizardConfig:
    defaults = dict(
        client_name="test",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="us-east-1",
        skills=["iam"],
        output_formats=["markdown"],
        ai_provider="claude-cli",
    )
    defaults.update(kwargs)
    return WizardConfig(**defaults)


def client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": code}}, "GetCallerIdentity"
    )


# ── AWSClient initialisation ──────────────────────────────────────────────────


class TestAWSClientInit:
    def test_stores_credentials_from_config(self):
        config = make_config()
        aws = AWSClient(config)
        assert aws.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert aws.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert aws.region_name == "us-east-1"

    def test_session_token_is_none_by_default(self):
        config = make_config()
        aws = AWSClient(config)
        assert aws.session_token is None

    def test_session_token_stored_when_provided(self):
        config = make_config(aws_session_token="token123")
        aws = AWSClient(config)
        assert aws.session_token == "token123"

    def test_account_id_and_identity_initially_none(self):
        config = make_config()
        aws = AWSClient(config)
        assert aws.get_account_id() is None
        assert aws.get_identity() is None


# ── AWSClient.validate_credentials: success ───────────────────────────────────


class TestValidateCredentialsSuccess:
    def _mock_sts(self, identity=None):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = identity or VALID_IDENTITY
        return mock_sts

    def test_returns_true_on_valid_credentials(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            is_valid, _, _ = aws.validate_credentials()
        assert is_valid is True

    def test_returns_account_id_on_success(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            _, _, account_id = aws.validate_credentials()
        assert account_id == "123456789012"

    def test_message_contains_account_id(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            _, message, _ = aws.validate_credentials()
        assert "123456789012" in message

    def test_message_contains_username(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            _, message, _ = aws.validate_credentials()
        assert "alice" in message

    def test_get_account_id_after_validation(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            aws.validate_credentials()
        assert aws.get_account_id() == "123456789012"

    def test_get_identity_after_validation(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            aws.validate_credentials()
        assert aws.get_identity()["Account"] == "123456789012"

    def test_session_token_passed_to_boto3_session(self):
        config = make_config(aws_session_token="mytoken")
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            aws.validate_credentials()
        call_kwargs = mock_session_cls.call_args.kwargs
        assert call_kwargs.get("aws_session_token") == "mytoken"

    def test_no_session_token_not_passed_to_boto3(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            aws.validate_credentials()
        call_kwargs = mock_session_cls.call_args.kwargs
        assert "aws_session_token" not in call_kwargs

    def test_root_arn_shows_root_as_identity(self):
        identity = {**VALID_IDENTITY, "Arn": "arn:aws:iam::123456789012:root"}
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts(identity)
            _, message, _ = aws.validate_credentials()
        assert "root" in message


# ── AWSClient.validate_credentials: failures ─────────────────────────────────


class TestValidateCredentialsFailure:
    def test_access_denied_returns_false(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value.get_caller_identity.side_effect = (
                client_error("AccessDenied")
            )
            is_valid, _, account_id = aws.validate_credentials()
        assert is_valid is False
        assert account_id is None

    def test_access_denied_message_is_clear(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value.get_caller_identity.side_effect = (
                client_error("AccessDenied")
            )
            _, message, _ = aws.validate_credentials()
        assert "access denied" in message.lower() or "insufficient" in message.lower()

    def test_invalid_token_returns_false(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value.get_caller_identity.side_effect = (
                client_error("InvalidClientTokenId")
            )
            is_valid, message, _ = aws.validate_credentials()
        assert is_valid is False
        assert "invalid" in message.lower()

    def test_unknown_error_code_included_in_message(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value.get_caller_identity.side_effect = (
                client_error("SomeUnknownError")
            )
            _, message, _ = aws.validate_credentials()
        assert "SomeUnknownError" in message

    def test_network_error_returns_false(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value.get_caller_identity.side_effect = (
                ConnectionError("Network unreachable")
            )
            is_valid, message, _ = aws.validate_credentials()
        assert is_valid is False
        assert "Failed to validate" in message

    def test_account_id_none_after_failed_validation(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value.get_caller_identity.side_effect = (
                client_error("AccessDenied")
            )
            aws.validate_credentials()
        assert aws.get_account_id() is None


# ── validate_aws_credentials convenience function ─────────────────────────────


class TestValidateAwsCredentials:
    def test_valid_credentials_return_true(self):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = VALID_IDENTITY
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = mock_sts
            is_valid, _, account_id = validate_aws_credentials(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "us-east-1",
            )
        assert is_valid is True
        assert account_id == "123456789012"

    def test_invalid_credentials_return_false(self):
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value.get_caller_identity.side_effect = (
                client_error("InvalidClientTokenId")
            )
            is_valid, _, account_id = validate_aws_credentials("BAD", "KEY", "us-east-1")
        assert is_valid is False
        assert account_id is None

    def test_session_token_forwarded(self):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = VALID_IDENTITY
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = mock_sts
            validate_aws_credentials("KEY", "SECRET", "us-east-1", session_token="tok")
        call_kwargs = mock_session_cls.call_args.kwargs
        assert call_kwargs.get("aws_session_token") == "tok"
