"""AWS SDK integration."""

from .client import AWSClient, AWSCredentialError, validate_aws_credentials

__all__ = ["AWSClient", "AWSCredentialError", "validate_aws_credentials"]
