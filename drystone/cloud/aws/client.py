"""AWS client wrapper for credential validation and operations."""

from typing import Optional, Tuple

import boto3
import botocore.exceptions


class AWSCredentialError(Exception):
    """Raised when AWS credentials are invalid or insufficient."""

    pass


class AWSClient:
    """AWS SDK client wrapper."""

    def __init__(self, access_key_id: str, secret_access_key: str, region_name: str = "us-east-1", session_token: Optional[str] = None):
        """Initialize AWS client.

        Args:
            access_key_id: AWS Access Key ID
            secret_access_key: AWS Secret Access Key
            region_name: AWS region
            session_token: Optional AWS Session Token for temporary credentials

        Raises:
            AWSCredentialError: If credentials are invalid
        """
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.region_name = region_name
        self.session = None
        self.sts_client = None
        self.iam_client = None
        self._account_id = None
        self._identity = None

    def validate_credentials(self) -> Tuple[bool, str, Optional[str]]:
        """Validate AWS credentials.

        Returns:
            Tuple of (is_valid, message, account_id)
            - is_valid: True if credentials are valid
            - message: Human-readable message
            - account_id: AWS Account ID if valid, None otherwise
        """
        try:
            # Create session with provided credentials
            session_kwargs = {
                'aws_access_key_id': self.access_key_id,
                'aws_secret_access_key': self.secret_access_key,
                'region_name': self.region_name,
            }
            # Add session token only if provided (for temporary credentials)
            if self.session_token:
                session_kwargs['aws_session_token'] = self.session_token

            self.session = boto3.Session(**session_kwargs)

            # Try to get STS client and call get_caller_identity
            self.sts_client = self.session.client("sts")
            identity = self.sts_client.get_caller_identity()

            self._identity = identity
            self._account_id = identity.get("Account")
            account_id = self._account_id
            arn = identity.get("Arn", "")
            user_name = arn.split("/")[-1] if "/" in arn else "root"

            message = f"✅ Valid credentials | Account: {account_id} | Identity: {user_name}"
            return True, message, account_id

        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDenied":
                message = "❌ Access denied - insufficient permissions"
            elif error_code == "InvalidClientTokenId":
                message = "❌ Invalid AWS credentials (bad access key or secret)"
            else:
                message = f"❌ AWS error: {error_code}"
            return False, message, None

        except Exception as e:
            message = f"❌ Failed to validate credentials: {str(e)}"
            return False, message, None

    def get_account_id(self) -> Optional[str]:
        """Get AWS Account ID (must call validate_credentials first).

        Returns:
            AWS Account ID or None if not validated
        """
        return self._account_id

    def get_identity(self) -> Optional[dict]:
        """Get caller identity details.

        Returns:
            Identity dict from STS get_caller_identity or None
        """
        return self._identity


def validate_aws_credentials(access_key_id: str, secret_access_key: str, region_name: str = "us-east-1", session_token: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """Validate AWS credentials.

    This is a convenience function that creates a client and validates in one call.

    Args:
        access_key_id: AWS Access Key ID
        secret_access_key: AWS Secret Access Key
        region_name: AWS region
        session_token: Optional AWS Session Token for temporary credentials

    Returns:
        Tuple of (is_valid, message, account_id)
    """
    client = AWSClient(access_key_id=access_key_id, secret_access_key=secret_access_key, region_name=region_name, session_token=session_token)
    return client.validate_credentials()
