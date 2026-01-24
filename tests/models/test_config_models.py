"""Unit tests for configuration models."""

import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from pydantic import ValidationError

from drystone.models.config import WizardConfig

# --- Fixtures ---

@pytest.fixture
def basic_config_data():
    """Fixture for basic wizard config data."""
    return {
        "client_name": "TestClient",
        "skills": ["iam"],
        "output_formats": ["markdown"],
    }

@pytest.fixture
def temp_credential_file(tmp_path: Path) -> Path:
    """Fixture to create a temporary credential file."""
    cred_file = tmp_path / "creds.json"
    cred_data = {
        "aws_access_key_id": "FILE_ACCESS_KEY",
        "aws_secret_access_key": "FILE_SECRET_KEY",
        "aws_session_token": "FILE_SESSION_TOKEN",
    }
    with open(cred_file, "w") as f:
        json.dump(cred_data, f)
    return cred_file
    
# --- AWS Credential Tests ---

def test_get_aws_credentials_manual_priority(basic_config_data):
    """Test that manual credentials have the highest priority."""
    config = WizardConfig(
        **basic_config_data,
        aws_access_key_id="MANUAL_KEY",
        aws_secret_access_key="MANUAL_SECRET",
        aws_profile="some-profile"  # This should be ignored
    )
    key, secret, token = config.get_aws_credentials()
    assert key == "MANUAL_KEY"
    assert secret == "MANUAL_SECRET"
    assert token is None

@patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "ENV_KEY", "AWS_SECRET_ACCESS_KEY": "ENV_SECRET"})
def test_get_aws_credentials_env_vars(basic_config_data):
    """Test loading AWS credentials from environment variables."""
    config = WizardConfig(**basic_config_data)
    key, secret, token = config.get_aws_credentials()
    assert key == "ENV_KEY"
    assert secret == "ENV_SECRET"
    assert token is None

def test_get_aws_credentials_from_file(basic_config_data, temp_credential_file: Path):
    """Test loading AWS credentials from a JSON file."""
    config = WizardConfig(**basic_config_data, aws_credentials_file=temp_credential_file)
    key, secret, token = config.get_aws_credentials()
    assert key == "FILE_ACCESS_KEY"
    assert secret == "FILE_SECRET_KEY"
    assert token == "FILE_SESSION_TOKEN"

def test_get_aws_credentials_file_not_found(basic_config_data):
    """Test FileNotFoundError is raised for a non-existent credential file."""
    non_existent_file = Path("/tmp/non-existent-creds.json")
    config = WizardConfig(**basic_config_data, aws_credentials_file=non_existent_file)
    with pytest.raises(FileNotFoundError):
        config.get_aws_credentials()

@patch("boto3.Session")
def test_get_aws_credentials_from_profile(mock_boto_session, basic_config_data):
    """Test loading AWS credentials from an AWS profile."""
    # Mocking boto3 session and credentials
    mock_creds = MagicMock()
    mock_creds.access_key = "PROFILE_KEY"
    mock_creds.secret_key = "PROFILE_SECRET"
    mock_creds.token = "PROFILE_TOKEN"
    
    mock_session_instance = MagicMock()
    mock_session_instance.get_credentials.return_value = mock_creds
    mock_boto_session.return_value = mock_session_instance

    config = WizardConfig(**basic_config_data, aws_profile="my-profile")
    key, secret, token = config.get_aws_credentials()

    mock_boto_session.assert_called_with(profile_name="my-profile")
    assert key == "PROFILE_KEY"
    assert secret == "PROFILE_SECRET"
    assert token == "PROFILE_TOKEN"

def test_get_aws_credentials_no_creds_configured(basic_config_data):
    """Test that a ValueError is raised when no credentials are provided."""
    config = WizardConfig(**basic_config_data)
    with pytest.raises(ValueError, match="No AWS credentials configured"):
        config.get_aws_credentials()

# --- Bedrock Credential Tests ---

def test_get_bedrock_credentials_same_as_aws(basic_config_data):
    """Test Bedrock using the same credentials as AWS."""
    config = WizardConfig(
        **basic_config_data,
        aws_access_key_id="AWS_KEY",
        aws_secret_access_key="AWS_SECRET",
        bedrock_use_same_credentials=True
    )
    b_key, b_secret, _ = config.get_bedrock_credentials()
    assert b_key == "AWS_KEY"
    assert b_secret == "AWS_SECRET"

def test_get_bedrock_credentials_manual_priority(basic_config_data):
    """Test that manual Bedrock credentials have priority."""
    config = WizardConfig(
        **basic_config_data,
        bedrock_access_key_id="BEDROCK_MANUAL_KEY",
        bedrock_secret_access_key="BEDROCK_MANUAL_SECRET",
        bedrock_profile="some-profile" # Should be ignored
    )
    key, secret, _ = config.get_bedrock_credentials()
    assert key == "BEDROCK_MANUAL_KEY"
    assert secret == "BEDROCK_MANUAL_SECRET"

@patch.dict(os.environ, {"BEDROCK_AWS_ACCESS_KEY_ID": "BEDROCK_ENV_KEY", "BEDROCK_AWS_SECRET_ACCESS_KEY": "BEDROCK_ENV_SECRET"})
def test_get_bedrock_credentials_from_specific_env_vars(basic_config_data):
    """Test loading Bedrock credentials from BEDROCK_AWS_* environment variables."""
    config = WizardConfig(**basic_config_data)
    key, secret, _ = config.get_bedrock_credentials()
    assert key == "BEDROCK_ENV_KEY"
    assert secret == "BEDROCK_ENV_SECRET"

@patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AWS_ENV_KEY", "AWS_SECRET_ACCESS_KEY": "AWS_ENV_SECRET"})
def test_get_bedrock_credentials_fallback_to_aws_env_vars(basic_config_data):
    """Test Bedrock credentials falling back to standard AWS_* environment variables."""
    config = WizardConfig(**basic_config_data)
    key, secret, _ = config.get_bedrock_credentials()
    assert key == "AWS_ENV_KEY"
    assert secret == "AWS_ENV_SECRET"
    
# --- Serialization Tests (`dict_for_json`) ---

def test_dict_for_json_manual_creds(basic_config_data):
    """Test that manual credentials ARE included in the JSON output."""
    config = WizardConfig(
        **basic_config_data,
        aws_access_key_id="KEY",
        aws_secret_access_key="SECRET"
    )
    data = config.dict_for_json()
    assert "aws_access_key_id" in data
    assert "aws_secret_access_key" in data

def test_dict_for_json_omits_creds_with_profile(basic_config_data):
    """Test that credentials ARE NOT included in JSON when a profile is used."""
    config = WizardConfig(
        **basic_config_data,
        aws_access_key_id="KEY", # This would be from a previous run
        aws_secret_access_key="SECRET",
        aws_profile="my-profile"
    )
    data = config.dict_for_json()
    assert "aws_access_key_id" not in data
    assert "aws_secret_access_key" not in data
    assert "aws_profile" in data

def test_dict_for_json_omits_creds_with_file(basic_config_data, temp_credential_file):
    """Test that credentials ARE NOT included in JSON when a file is used."""
    config = WizardConfig(
        **basic_config_data,
        aws_access_key_id="KEY", # This would be from a previous run
        aws_secret_access_key="SECRET",
        aws_credentials_file=temp_credential_file
    )
    data = config.dict_for_json()
    assert "aws_access_key_id" not in data
    assert "aws_secret_access_key" not in data
    assert "aws_credentials_file" in data
    assert data["aws_credentials_file"] == str(temp_credential_file)
