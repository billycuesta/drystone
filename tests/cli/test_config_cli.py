"""Tests for configuration management."""

import json
from pathlib import Path
from unittest.mock import patch

from drystone.cli.config import save_config, load_last_config
from drystone.models.config import WizardConfig

def test_save_and_load_config_with_profile(tmp_path: Path):
    """
    Test saving a config that uses a profile and ensures no sensitive data is written.
    Then, test loading it back.
    """
    config_file = tmp_path / "last-run.json"

    # 1. Create and save a config that uses an AWS profile
    config = WizardConfig(
        client_name="ProfileClient",
        aws_profile="my-test-profile",
        skills=["iam"],
        output_formats=["markdown"]
    )

    with patch("drystone.cli.config.LAST_RUN_FILE", config_file):
        saved_path = save_config(config)
        assert saved_path == config_file

    # 2. Verify the saved file contents
    assert config_file.exists()
    with open(config_file, "r") as f:
        data = json.load(f)

    # CRITICAL: Ensure raw keys are NOT saved
    assert "aws_access_key_id" not in data
    assert "aws_secret_access_key" not in data
    
    # Ensure the profile name IS saved
    assert data["aws_profile"] == "my-test-profile"
    assert data["client_name"] == "ProfileClient"

    # 3. Load the config back and verify its contents
    with patch("drystone.cli.config.LAST_RUN_FILE", config_file):
        loaded_config = load_last_config()

    assert isinstance(loaded_config, WizardConfig)
    assert loaded_config.aws_profile == "my-test-profile"
    assert loaded_config.client_name == "ProfileClient"
    # The raw key fields should be None when loaded
    assert loaded_config.aws_access_key_id is None
    assert loaded_config.aws_secret_access_key is None

def test_save_and_load_config_with_credential_file(tmp_path: Path):
    """
    Test saving a config that uses a credential file and ensures no sensitive data is written.
    Then, test loading it back.
    """
    config_file = tmp_path / "last-run.json"
    cred_file_path = tmp_path / "my-creds.json"


    # 1. Create and save a config that uses a credential file
    config = WizardConfig(
        client_name="FileClient",
        aws_credentials_file=cred_file_path,
        skills=["exposure"],
        output_formats=["json"]
    )
    with patch("drystone.cli.config.LAST_RUN_FILE", config_file):
        save_config(config)

    # 2. Verify the saved file contents
    assert config_file.exists()
    with open(config_file, "r") as f:
        data = json.load(f)

    assert "aws_access_key_id" not in data
    assert "aws_secret_access_key" not in data
    assert data["aws_credentials_file"] == str(cred_file_path)
    assert data["client_name"] == "FileClient"

    # 3. Load the config back and verify its contents
    with patch("drystone.cli.config.LAST_RUN_FILE", config_file):
        loaded_config = load_last_config()
    
    assert loaded_config.aws_credentials_file == cred_file_path
    assert loaded_config.client_name == "FileClient"
    assert loaded_config.aws_access_key_id is None
