"""Fixtures for pytest."""

import pytest

@pytest.fixture
def example_aws_credentials():
    """Example AWS credentials for testing (NOT REAL)."""
    return {
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

@pytest.fixture
def example_bedrock_credentials():
    """Example Bedrock credentials for testing (NOT REAL)."""
    return {
        "bedrock_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "bedrock_secret_access_key": "wJalrXUtnFEMI/BEDROCK/bPxRfiCYEXAMPLEKEY",
    }
