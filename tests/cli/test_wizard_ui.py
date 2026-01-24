"""Tests for the interactive wizard UI."""

import os
from unittest.mock import patch, MagicMock

import pytest

from drystone.cli.ui.wizard import run_setup_wizard, run_project_menu, run_ai_menu
from drystone.models.config import WizardConfig

# --- Mocks ---

@pytest.fixture
def mock_questionary():
    """Fixture to mock questionary user inputs."""
    with patch("questionary.text") as mock_text, \
         patch("questionary.password") as mock_password, \
         patch("questionary.select") as mock_select, \
         patch("questionary.checkbox") as mock_checkbox:
        
        # Each call to a questionary function (e.g., text()) returns a Question object
        # that then has its .ask() method called. We need to mock this chain.
        mock_text.return_value = MagicMock()
        mock_password.return_value = MagicMock()
        mock_select.return_value = MagicMock()
        mock_checkbox.return_value = MagicMock()

        mocks = {
            "text": mock_text,
            "password": mock_password,
            "select": mock_select,
            "checkbox": mock_checkbox,
        }
        yield mocks

@patch("drystone.cli.ui.wizard.validate_aws_creds", return_value=True)
def test_run_project_menu_manual_creds(mock_validate, mock_questionary):
    """Test the project menu with manual credential entry."""
    # Setup mock returns for each question
    mock_questionary["text"].return_value.ask.side_effect = ["TestClient", "MANUAL_KEY"] # client_name, access_key_id
    mock_questionary["password"].return_value.ask.side_effect = ["MANUAL_SECRET", ""] # secret_key, session_token
    mock_questionary["select"].return_value.ask.side_effect = ["manual", "us-east-1"] # cred_choice, region
    mock_questionary["checkbox"].return_value.ask.side_effect = [["iam"], ["markdown"]]

    config = run_project_menu()

    assert config["client_name"] == "TestClient"
    assert config["aws_access_key_id"] == "MANUAL_KEY"
    assert config["aws_secret_access_key"] == "MANUAL_SECRET"
    assert config["aws_profile"] is None
    assert config["aws_credentials_file"] is None

@patch("drystone.cli.ui.wizard.validate_aws_creds", return_value=True)
def test_run_project_menu_profile_creds(mock_validate, mock_questionary):
    """Test the project menu using an AWS profile."""
    mock_questionary["text"].return_value.ask.side_effect = ["TestClient", "my-profile"] # client_name, profile_name
    mock_questionary["select"].return_value.ask.side_effect = ["profile", "us-east-1"] # cred_choice, region
    mock_questionary["checkbox"].return_value.ask.side_effect = [["iam"], ["markdown"]]

    config = run_project_menu()

    assert config["aws_profile"] == "my-profile"
    assert config["aws_access_key_id"] is None
    assert config["aws_credentials_file"] is None

@patch("drystone.cli.ui.wizard.validate_aws_creds", return_value=True)
def test_run_project_menu_file_creds(mock_validate, mock_questionary):
    """Test the project menu using a credential file."""
    mock_questionary["text"].return_value.ask.side_effect = ["TestClient", "~/.aws/my-creds.json"] # client_name, file_path
    mock_questionary["select"].return_value.ask.side_effect = ["file", "us-east-1"] # cred_choice, region
    mock_questionary["checkbox"].return_value.ask.side_effect = [["iam"], ["markdown"]]

    config = run_project_menu()

    assert config["aws_credentials_file"] == "~/.aws/my-creds.json"
    assert config["aws_access_key_id"] is None
    assert config["aws_profile"] is None

@patch("drystone.cli.ui.wizard.validate_aws_creds", return_value=True)
def test_run_ai_menu_bedrock_same_creds(mock_validate, mock_questionary):
    """Test the AI menu selecting 'same' credentials for Bedrock."""
    mock_questionary["select"].return_value.ask.side_effect = ["bedrock", "same"] # ai_provider, bedrock_choice

    config = run_ai_menu()

    assert config["ai_provider"] == "bedrock"
    assert config["bedrock_use_same_credentials"] is True
    assert config["bedrock_access_key_id"] is None
    assert config["bedrock_profile"] is None
    assert config["bedrock_credentials_file"] is None

@patch("drystone.cli.ui.wizard.validate_aws_creds", return_value=True)
def test_run_ai_menu_bedrock_manual_creds(mock_validate, mock_questionary):
    """Test the AI menu with manual entry for Bedrock credentials."""
    mock_questionary["select"].return_value.ask.side_effect = ["bedrock", "manual"]
    mock_questionary["text"].return_value.ask.side_effect = ["BEDROCK_KEY"]
    mock_questionary["password"].return_value.ask.side_effect = ["BEDROCK_SECRET", ""]

    config = run_ai_menu()

    assert config["ai_provider"] == "bedrock"
    assert config["bedrock_use_same_credentials"] is False
    assert config["bedrock_access_key_id"] == "BEDROCK_KEY"
    assert config["bedrock_secret_access_key"] == "BEDROCK_SECRET"

@patch("drystone.models.config.WizardConfig.get_aws_credentials", return_value=("key", "secret", "token"))
@patch("drystone.models.config.WizardConfig.get_bedrock_credentials", return_value=("key", "secret", "token"))
@patch("drystone.cli.ui.wizard.validate_aws_creds", return_value=True)
def test_run_setup_wizard_full_flow(mock_validate, mock_get_bedrock, mock_get_aws, mock_questionary):
    """Test the full wizard flow from start to finish."""
    # Mock the sequence of choices for all 'select' prompts
    mock_questionary["select"].return_value.ask.side_effect = [
        "edit_project", # 1. Main menu: edit project
        "manual",       # 2. Project menu: cred choice
        "us-east-1",    # 3. Project menu: region
        "edit_ai",      # 4. Main menu: edit ai
        "bedrock",      # 5. AI menu: provider
        "same",         # 6. AI menu: bedrock choice
        "continue",     # 7. Main menu: continue
    ]
    # Mock the sequence for all 'text' prompts
    mock_questionary["text"].return_value.ask.side_effect = ["FinalClient", "FINAL_KEY"]
    # Mock the sequence for all 'password' prompts
    mock_questionary["password"].return_value.ask.side_effect = ["FINAL_SECRET", ""]
    # Mock the sequence for all 'checkbox' prompts
    mock_questionary["checkbox"].return_value.ask.side_effect = [["exposure"], ["json"]]

    # Run the full wizard
    final_config = run_setup_wizard()

    assert isinstance(final_config, WizardConfig)
    assert final_config.client_name == "FinalClient"
    assert final_config.aws_access_key_id == "FINAL_KEY"
    assert final_config.skills == ["exposure"]
    assert final_config.output_formats == ["json"]
    assert final_config.ai_provider == "bedrock"
    assert final_config.bedrock_use_same_credentials is True

