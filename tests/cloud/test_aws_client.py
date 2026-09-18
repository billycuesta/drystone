"""Tests for AWS credential validation client."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import botocore.exceptions
from botocore.credentials import Credentials

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


# ── AWSClient managed session/client factory ──────────────────────────────────


class TestManagedSession:
    def test_boto3_session_is_lazy_and_cached(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            first = aws.boto3_session()
            second = aws.boto3_session()
        assert first is second
        assert mock_session_cls.call_count == 1

    def test_client_uses_managed_session_and_region_override(self):
        config = make_config()
        aws = AWSClient(config)
        session = MagicMock()
        with patch.object(aws, "boto3_session", return_value=session):
            aws.client("ec2", region_name="eu-west-1", config="x")
        session.client.assert_called_once_with("ec2", region_name="eu-west-1", config="x")

    def test_profile_session_does_not_freeze_credentials_at_construction(self):
        config = make_config(
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_profile="audit-profile",
        )
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            aws.boto3_session()
        assert mock_session_cls.call_args.kwargs == {
            "region_name": "us-east-1",
            "profile_name": "audit-profile",
        }

    def test_default_chain_session_does_not_pass_static_credentials(self):
        config = make_config(aws_access_key_id=None, aws_secret_access_key=None)
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            aws.boto3_session()
        assert mock_session_cls.call_args.kwargs == {"region_name": "us-east-1"}

    def test_client_kwargs_derives_current_session_credentials(self):
        config = make_config(aws_access_key_id=None, aws_secret_access_key=None)
        aws = AWSClient(config)
        session = MagicMock()
        session.get_credentials.return_value = Credentials("fresh-key", "fresh-secret", "fresh-token")
        with patch.object(aws, "boto3_session", return_value=session):
            kwargs = aws.client_kwargs(region_name="eu-west-1")
        assert kwargs == {
            "aws_access_key_id": "fresh-key",
            "aws_secret_access_key": "fresh-secret",
            "aws_session_token": "fresh-token",
            "region_name": "eu-west-1",
        }


# ── AWSClient AssumeRole ───────────────────────────────────────────────────────


class TestAssumeRole:
    def test_assume_role_args_include_role_settings(self):
        config = make_config(
            aws_role_arn="arn:aws:iam::123456789012:role/Audit",
            aws_role_session_name="drystone-test",
            aws_external_id="external-secret",
            aws_role_duration_seconds=1800,
        )
        source_session = MagicMock()
        sts = source_session.client.return_value
        sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIAKEY",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime.now(timezone.utc) + timedelta(hours=1),
            }
        }
        with patch("boto3.Session", side_effect=[source_session, MagicMock()]):
            AWSClient(config).boto3_session()
        sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/Audit",
            RoleSessionName="drystone-test",
            ExternalId="external-secret",
            DurationSeconds=1800,
        )

    def test_assume_role_refreshes_when_expiration_is_near(self):
        config = make_config(aws_role_arn="arn:aws:iam::123456789012:role/Audit")
        aws = AWSClient(config)
        aws.session = MagicMock()
        aws._assumed_expiration = datetime.now(timezone.utc) + timedelta(minutes=1)
        with patch.object(aws, "_build_session", return_value=MagicMock()) as build:
            aws.boto3_session()
        build.assert_called_once()

    def test_missing_assume_role_expiration_uses_safe_refresh_deadline(self):
        config = make_config(aws_role_arn="arn:aws:iam::123456789012:role/Audit")
        source_session = MagicMock()
        assumed_session = MagicMock()
        sts = source_session.client.return_value
        sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIAKEY",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
            }
        }

        with patch("boto3.Session", side_effect=[source_session, assumed_session]):
            aws = AWSClient(config)
            first = aws.boto3_session()
            second = aws.boto3_session()

        assert first is assumed_session
        assert second is assumed_session
        assert aws._assumed_expiration is not None
        sts.assume_role.assert_called_once()


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

    def test_validate_populates_session(self):
        config = make_config()
        aws = AWSClient(config)
        with patch("boto3.Session") as mock_session_cls:
            mock_session_cls.return_value.client.return_value = self._mock_sts()
            aws.validate_credentials()
        assert aws.session is mock_session_cls.return_value

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
