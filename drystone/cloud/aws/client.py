"""AWS client wrapper for credential validation and operations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Tuple

import boto3
import botocore.exceptions

from drystone.models import WizardConfig


class AWSCredentialError(Exception):
    """Raised when AWS credentials are invalid or insufficient."""

    pass


class AWSClient:
    """AWS SDK client wrapper with a managed boto3 session.

    The wrapper intentionally centralizes credential resolution so profile,
    environment, SSO, container/instance metadata, and default-chain providers
    remain refresh-friendly. Direct credentials and custom JSON credential files
    are still loaded as static values for backward compatibility.

    AssumeRole MVP note: target role credentials are obtained centrally and used
    to build a managed session. They are refreshed by rebuilding that managed
    session when close to expiration, including through ``client_kwargs()``.
    Existing boto3 clients keep the credentials they were created with; new
    clients should be requested through this wrapper.
    """

    _ASSUME_ROLE_REFRESH_WINDOW = timedelta(minutes=5)

    def __init__(self, config: WizardConfig):
        """Initialize AWS client from a WizardConfig object."""

        self.config = config
        self.region_name = config.aws_region
        self.access_key_id: Optional[str] = config.aws_access_key_id
        self.secret_access_key: Optional[str] = config.aws_secret_access_key
        self.session_token: Optional[str] = config.aws_session_token
        self.session: Optional[boto3.Session] = None
        self._source_session: Optional[boto3.Session] = None
        self.sts_client = None
        self.iam_client = None
        self._account_id: Optional[str] = None
        self._identity: Optional[dict] = None
        self._assumed_expiration: Optional[datetime] = None

    def _base_session_kwargs(self) -> dict[str, Any]:
        """Return boto3.Session kwargs for the configured source identity."""

        kwargs: dict[str, Any] = {"region_name": self.region_name}

        # Direct credentials take precedence and are intentionally static.
        if self.config.aws_access_key_id and self.config.aws_secret_access_key:
            kwargs.update(
                {
                    "aws_access_key_id": self.config.aws_access_key_id,
                    "aws_secret_access_key": self.config.aws_secret_access_key,
                }
            )
            if self.config.aws_session_token:
                kwargs["aws_session_token"] = self.config.aws_session_token
            return kwargs

        # Custom JSON credentials are also static for backward compatibility.
        if self.config.aws_credentials_file:
            access_key, secret_key, token = self.config._load_from_file(
                self.config.aws_credentials_file
            )
            kwargs.update(
                {
                    "aws_access_key_id": access_key,
                    "aws_secret_access_key": secret_key,
                }
            )
            if token:
                kwargs["aws_session_token"] = token
            return kwargs

        # Profiles and the default chain must not be resolved here: boto3 owns
        # refresh for profile/Sso/env/web-identity/container/metadata providers.
        if self.config.aws_profile:
            kwargs["profile_name"] = self.config.aws_profile
        return kwargs

    def _assume_role_kwargs(self) -> dict[str, Any]:
        """Build STS AssumeRole kwargs without exposing sensitive values."""

        if not self.config.aws_role_arn:
            return {}

        kwargs: dict[str, Any] = {
            "RoleArn": self.config.aws_role_arn,
            "RoleSessionName": self.config.aws_role_session_name or "drystone-audit",
        }
        if self.config.aws_external_id:
            kwargs["ExternalId"] = self.config.aws_external_id
        if self.config.aws_role_duration_seconds:
            kwargs["DurationSeconds"] = self.config.aws_role_duration_seconds
        return kwargs

    def _needs_assume_role_refresh(self) -> bool:
        if not self.config.aws_role_arn:
            return False
        if self.session is None or self._assumed_expiration is None:
            return True
        now = datetime.now(timezone.utc)
        expiration = self._assumed_expiration
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        return expiration - now <= self._ASSUME_ROLE_REFRESH_WINDOW

    def _build_session(self) -> boto3.Session:
        """Create or refresh the managed boto3 session."""

        self._source_session = boto3.Session(**self._base_session_kwargs())

        if not self.config.aws_role_arn:
            self._assumed_expiration = None
            return self._source_session

        sts = self._source_session.client("sts")
        response = sts.assume_role(**self._assume_role_kwargs())
        credentials = response["Credentials"]
        self._assumed_expiration = credentials.get("Expiration")
        if self._assumed_expiration is None:
            duration = self.config.aws_role_duration_seconds or 3600
            self._assumed_expiration = datetime.now(timezone.utc) + timedelta(seconds=duration)
        self.access_key_id = credentials["AccessKeyId"]
        self.secret_access_key = credentials["SecretAccessKey"]
        self.session_token = credentials.get("SessionToken")
        return boto3.Session(
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            aws_session_token=self.session_token,
            region_name=self.region_name,
        )

    def boto3_session(self) -> boto3.Session:
        """Return the managed boto3 session, creating/refreshing it lazily."""

        if self.session is None or self._needs_assume_role_refresh():
            self.session = self._build_session()
        return self.session

    def client(self, service_name: str, region_name: Optional[str] = None, **kwargs: Any):
        """Create a boto3 client from the managed session."""

        client_region = region_name if region_name is not None else self.region_name
        return self.boto3_session().client(service_name, region_name=client_region, **kwargs)

    def client_kwargs(self, region_name: Optional[str] = None) -> dict[str, Any]:
        """Return legacy boto3.client kwargs derived from current session credentials.

        This transitional adapter is for older skill helpers that still call
        ``boto3.client(..., **client_kwargs)``. It asks the managed session for
        current credentials instead of reusing constructor strings, preserving
        profile/default-chain refresh behavior as much as legacy call sites allow.
        """

        session = self.boto3_session()
        credentials = session.get_credentials()
        if credentials is None:
            raise AWSCredentialError("No AWS credentials available from managed session")
        frozen = credentials.get_frozen_credentials()
        kwargs: dict[str, Any] = {
            "aws_access_key_id": frozen.access_key,
            "aws_secret_access_key": frozen.secret_key,
            "region_name": region_name if region_name is not None else self.region_name,
        }
        if frozen.token:
            kwargs["aws_session_token"] = frozen.token
        return kwargs

    def validate_credentials(self) -> Tuple[bool, str, Optional[str]]:
        """Validate AWS credentials.

        Returns:
            Tuple of (is_valid, message, account_id)
            - is_valid: True if credentials are valid
            - message: Human-readable message
            - account_id: AWS Account ID if valid, None otherwise
        """
        try:
            self.session = self.boto3_session()
            self.sts_client = self.client("sts")
            identity = self.sts_client.get_caller_identity()

            self._identity = identity
            self._account_id = identity.get("Account")
            account_id = self._account_id
            arn = identity.get("Arn", "")
            user_name = arn.split("/")[-1] if "/" in arn else "root"

            message = f"✅ Valid credentials | Account: {account_id} | Identity: {user_name}"
            return True, message, account_id

        except botocore.exceptions.ClientError as e:
            self._account_id = None
            self._identity = None
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDenied":
                message = "❌ Access denied - insufficient permissions"
            elif error_code == "InvalidClientTokenId":
                message = "❌ Invalid AWS credentials (bad access key or secret)"
            else:
                message = f"❌ AWS error: {error_code}"
            return False, message, None

        except Exception as e:
            self._account_id = None
            self._identity = None
            message = f"❌ Failed to validate credentials: {str(e)}"
            return False, message, None

    def get_account_id(self) -> Optional[str]:
        """Get AWS Account ID (must call validate_credentials first)."""
        return self._account_id

    def get_identity(self) -> Optional[dict]:
        """Get caller identity details."""
        return self._identity


def validate_aws_credentials(
    access_key_id: str,
    secret_access_key: str,
    region_name: str = "us-east-1",
    session_token: Optional[str] = None,
) -> Tuple[bool, str, Optional[str]]:
    """Validate direct AWS credentials.

    This backward-compatible convenience function creates a temporary config and
    validates it through AWSClient's managed session path.
    """
    config = WizardConfig(
        client_name="validation",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_region=region_name,
        aws_session_token=session_token,
        skills=["iam"],
        output_formats=["markdown"],
        ai_provider="claude-cli",
    )
    client = AWSClient(config)
    return client.validate_credentials()
