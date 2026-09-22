"""Tests for the interactive wizard's AI provider selection (P2 #7: claude CLI preflight) and project menu."""

from unittest.mock import MagicMock, patch

import pytest

from drystone.cli.ui.wizard import (
    display_config_summary,
    run_ai_menu,
    run_project_menu,
    validate_ai_provider_credentials,
)
from drystone.models.config import PENTEST_CORE_SKILLS


def _ask_mock(*return_values):
    """Build a MagicMock whose .ask() returns each value in turn, in order."""
    mock = MagicMock()
    mock.ask.side_effect = list(return_values)
    return mock


class TestDisplayConfigSummary:
    def test_skill_names_use_registry_display_names(self, capsys):
        display_config_summary(
            {
                "client_name": "ACME",
                "aws_region": "us-east-1",
                "aws_access_key_id": None,
                "aws_credentials_file": None,
                "aws_profile": None,
                "skills": ["cloudtrail_events", "messaging"],
                "output_formats": ["markdown"],
                "report_type": "general",
            },
            {
                "ai_provider": "claude-api",
                "ai_api_key": None,
                "scan_depth": "normal",
            },
        )
        out = capsys.readouterr().out
        assert "CloudTrail Events" in out
        assert "Messaging" in out
        assert "Cloudtrail_events" not in out


class TestValidateAiProviderCredentialsClaudeCli:
    def test_available_returns_true_and_prints_nothing_bad(self, capsys):
        with patch(
            "drystone.agent.client.check_claude_cli_available",
            return_value=(True, "/usr/bin/claude"),
        ):
            assert validate_ai_provider_credentials("claude-cli", None) is True
        assert "❌" not in capsys.readouterr().out

    def test_unavailable_returns_false_with_actionable_message(self, capsys):
        with patch(
            "drystone.agent.client.check_claude_cli_available",
            return_value=(False, "Claude Code CLI not found in PATH.\nInstall with: npm install -g @anthropic-ai/claude-code"),
        ):
            assert validate_ai_provider_credentials("claude-cli", None) is False
        out = capsys.readouterr().out
        assert "not found in PATH" in out
        assert "ANTHROPIC_API_KEY" in out


class TestRunAiMenuClaudeCliPreflight:
    """run_ai_menu() drives multiple sequential questionary prompts; each
    questionary.<kind> call is mocked with the return values in call order.
    """

    def test_cli_available_proceeds_without_fallback_prompt(self):
        select_prompts = [
            _ask_mock("claude-cli"),  # provider choice
            _ask_mock("sonnet"),  # model choice
            _ask_mock("normal"),  # scan depth
        ]
        confirm_prompts = [_ask_mock(True)]  # active verification only

        with (
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.confirm", side_effect=confirm_prompts),
            patch(
                "drystone.agent.client.check_claude_cli_available",
                return_value=(True, "/usr/bin/claude"),
            ),
        ):
            result = run_ai_menu()

        assert result["ai_provider"] == "claude-cli"
        assert result["claude_cli_model"] == "sonnet"

    def test_cli_unavailable_user_switches_to_api(self):
        select_prompts = [
            _ask_mock("claude-cli"),  # provider choice
            _ask_mock("sonnet"),  # model choice
            _ask_mock("normal"),  # scan depth
        ]
        confirm_prompts = [
            _ask_mock(True),  # "switch to API?" -> yes
            _ask_mock(True),  # active verification
        ]

        with (
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.confirm", side_effect=confirm_prompts),
            patch("questionary.password", return_value=_ask_mock("sk-ant-test-key")),
            patch(
                "drystone.agent.client.check_claude_cli_available",
                return_value=(False, "Claude Code CLI not found in PATH."),
            ),
            patch(
                "drystone.cli.ui.wizard.validate_ai_provider_credentials",
                side_effect=[False, True],  # claude-cli check fails, then claude-api key check passes
            ),
        ):
            result = run_ai_menu()

        assert result["ai_provider"] == "claude-api"
        assert result["ai_api_key"] == "sk-ant-test-key"

    def test_cli_unavailable_user_declines_switch_cancels_wizard(self):
        select_prompts = [
            _ask_mock("claude-cli"),
            _ask_mock("sonnet"),
        ]
        confirm_prompts = [_ask_mock(False)]  # "switch to API?" -> no

        with (
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.confirm", side_effect=confirm_prompts),
            patch(
                "drystone.cli.ui.wizard.validate_ai_provider_credentials",
                return_value=False,
            ),
            pytest.raises(KeyboardInterrupt),
        ):
            run_ai_menu()


class TestRunProjectMenu:
    """run_project_menu() drives multiple sequential questionary prompts.
    Each questionary.<kind> call is mocked with the return values in call order.
    """

    def test_happy_path_manual_credentials(self):
        """Full flow: client name -> skill -> manual credentials -> region -> qsa_depth -> formats -> report type."""
        text_prompts = [
            _ask_mock("Acme Corp"),  # client name
            _ask_mock("AKIAIOSFODNN7EXAMPLE"),  # access key id
            _ask_mock("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),  # secret key
        ]
        password_prompts = [
            _ask_mock("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),  # secret key (alternative)
            _ask_mock(""),  # session token (empty)
        ]
        select_prompts = [
            _ask_mock("iam"),  # skill selection
            _ask_mock("manual"),  # credentials method
            _ask_mock("us-east-1"),  # region
            _ask_mock("standard"),  # qsa_depth
            _ask_mock("general"),  # report type
        ]
        checkbox_prompts = [
            _ask_mock(["markdown"]),  # output formats
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
        ):
            result = run_project_menu()

        assert result["client_name"] == "Acme Corp"
        assert result["skills"] == ["iam"]
        assert result["aws_access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert result["aws_secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert result["aws_session_token"] is None  # empty string converted to None
        assert result["aws_region"] == "us-east-1"
        assert result["qsa_depth"] == "standard"
        assert result["output_formats"] == ["markdown"]
        assert result["report_type"] == "general"
        # Credential file and profile should be None when using manual method
        assert result["aws_credentials_file"] is None
        assert result["aws_profile"] is None

    def test_client_name_cancellation(self):
        """User cancels at client name prompt -> KeyboardInterrupt."""
        text_prompts = [_ask_mock(None)]  # client name cancelled

        with (
            patch("questionary.text", side_effect=text_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()

    def test_skill_selection_cancellation(self):
        """User cancels at skill selection -> KeyboardInterrupt."""
        text_prompts = [_ask_mock("TestCorp")]
        select_prompts = [_ask_mock(None)]  # skill selection cancelled

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.select", side_effect=select_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()

    def test_credentials_method_cancellation(self):
        """User cancels at credentials method selection -> KeyboardInterrupt."""
        text_prompts = [_ask_mock("TestCorp")]
        select_prompts = [
            _ask_mock("iam"),  # skill
            _ask_mock(None),  # credentials method cancelled
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.select", side_effect=select_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()

    def test_manual_credentials_access_key_cancellation(self):
        """User cancels at access key prompt during manual flow -> KeyboardInterrupt."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
            _ask_mock(None),  # access key cancelled
        ]
        select_prompts = [
            _ask_mock("iam"),  # skill
            _ask_mock("manual"),  # credentials method
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.select", side_effect=select_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()

    def test_manual_credentials_secret_key_cancellation(self):
        """User cancels at secret key prompt during manual flow -> KeyboardInterrupt."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
            _ask_mock("AKIAIOSFODNN7EXAMPLE"),  # access key
        ]
        password_prompts = [
            _ask_mock(None),  # secret key cancelled
        ]
        select_prompts = [
            _ask_mock("iam"),  # skill
            _ask_mock("manual"),  # credentials method
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()

    def test_credentials_file_method(self):
        """File-based credentials method succeeds with valid path."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
            _ask_mock("/tmp/test-creds.json"),  # credentials file path
        ]
        select_prompts = [
            _ask_mock("iam"),  # skill
            _ask_mock("file"),  # credentials method
            _ask_mock("eu-west-1"),  # region
            _ask_mock("deep"),  # qsa_depth
            _ask_mock("general"),  # report type
        ]
        checkbox_prompts = [
            _ask_mock(["json", "pdf"]),  # output formats
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
            patch(
                "drystone.cli.ui.wizard.validate_credentials_file",
                return_value=True,
            ),
        ):
            result = run_project_menu()

        assert result["client_name"] == "TestCorp"
        assert result["aws_credentials_file"] == "/tmp/test-creds.json"
        assert result["aws_access_key_id"] is None
        assert result["aws_profile"] is None
        assert result["aws_region"] == "eu-west-1"
        assert result["qsa_depth"] == "deep"
        assert result["output_formats"] == ["json", "pdf"]

    def test_credentials_profile_method(self):
        """AWS profile method succeeds with valid profile name."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
            _ask_mock("staging"),  # profile name
        ]
        select_prompts = [
            _ask_mock("exposure"),  # skill
            _ask_mock("profile"),  # credentials method
            _ask_mock("ap-southeast-1"),  # region
            _ask_mock("obvious"),  # qsa_depth
            _ask_mock("pci-dss"),  # report type
        ]
        checkbox_prompts = [
            _ask_mock(["markdown"]),  # output formats
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
            patch(
                "drystone.cli.ui.wizard.validate_aws_profile",
                return_value=True,
            ),
        ):
            result = run_project_menu()

        assert result["client_name"] == "TestCorp"
        assert result["aws_profile"] == "staging"
        assert result["aws_access_key_id"] is None
        assert result["aws_credentials_file"] is None
        assert result["aws_region"] == "ap-southeast-1"
        assert result["qsa_depth"] == "obvious"

    def test_credentials_env_method(self):
        """Environment variable method skips credential prompts."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
        ]
        select_prompts = [
            _ask_mock("network"),  # skill
            _ask_mock("env"),  # credentials method (env vars)
            _ask_mock("us-west-2"),  # region
            _ask_mock("standard"),  # qsa_depth
            _ask_mock("general"),  # report type
        ]
        checkbox_prompts = [
            _ask_mock(["markdown"]),  # output formats
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
        ):
            result = run_project_menu()

        assert result["client_name"] == "TestCorp"
        assert result["skills"] == ["network"]
        # All credential fields should be None when using env method
        assert result["aws_access_key_id"] is None
        assert result["aws_secret_access_key"] is None
        assert result["aws_credentials_file"] is None
        assert result["aws_profile"] is None
        assert result["aws_region"] == "us-west-2"

    def test_pentest_skill_selection(self):
        """Selecting 'pentest' populates all PENTEST_CORE_SKILLS and auto-sets report_type='pentest'."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
        ]
        password_prompts = [
            _ask_mock("secret123"),  # secret key
            _ask_mock(""),  # session token
        ]
        select_prompts = [
            _ask_mock("pentest"),  # skill selection -> pentest
            _ask_mock("manual"),  # credentials method
            _ask_mock("us-east-1"),  # region
            _ask_mock("standard"),  # qsa_depth
            # Note: no report_type prompt when skill == pentest
        ]
        text_for_creds = [
            _ask_mock("AKIA123"),  # access key
        ]
        checkbox_prompts = [
            _ask_mock(["markdown"]),  # output formats
        ]

        with (
            patch("questionary.text", side_effect=text_prompts + text_for_creds),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
        ):
            result = run_project_menu()

        assert result["client_name"] == "TestCorp"
        assert result["skills"] == list(PENTEST_CORE_SKILLS)
        assert result["report_type"] == "pentest"  # Auto-set for pentest skill

    def test_pentest_default_selection_with_current_config(self):
        """When current_config has pentest skills, default skill selection is 'pentest'."""
        text_prompts = [
            _ask_mock("AnotherCorp"),  # client name
        ]
        password_prompts = [
            _ask_mock("secret456"),  # secret key
            _ask_mock(""),  # session token
        ]
        select_prompts = [
            _ask_mock("pentest"),  # skill selection -> pentest (default)
            _ask_mock("manual"),  # credentials method
            _ask_mock("eu-central-1"),  # region
            _ask_mock("deep"),  # qsa_depth
        ]
        text_for_creds = [
            _ask_mock("AKIA456"),  # access key
        ]
        checkbox_prompts = [
            _ask_mock(["json"]),  # output formats
        ]

        current_config = {
            "client_name": "OldCorp",
            "skills": list(PENTEST_CORE_SKILLS),
            "aws_region": "ap-northeast-1",
        }

        with (
            patch("questionary.text", side_effect=text_prompts + text_for_creds),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
        ):
            result = run_project_menu(current_config=current_config)

        # Should use new user input, not defaults from current_config
        assert result["client_name"] == "AnotherCorp"
        assert result["aws_region"] == "eu-central-1"
        assert result["skills"] == list(PENTEST_CORE_SKILLS)

    def test_current_config_provides_defaults(self):
        """Passing current_config pre-fills default values in prompts."""
        text_prompts = [
            _ask_mock("UpdatedCorp"),  # client name (updated)
            _ask_mock("AKIA789"),  # access key
        ]
        password_prompts = [
            _ask_mock("newsecret"),  # secret key
            _ask_mock("token123"),  # session token (with value)
        ]
        select_prompts = [
            _ask_mock("vulns"),  # skill
            _ask_mock("manual"),  # credentials method
            _ask_mock("us-west-1"),  # region
            _ask_mock("deep"),  # qsa_depth
            _ask_mock("pci-dss"),  # report type
        ]
        checkbox_prompts = [
            _ask_mock(["markdown", "pdf"]),  # output formats
        ]

        current_config = {
            "client_name": "OldCorp",
            "aws_region": "eu-west-1",
            "aws_access_key_id": "AKIA111",
            "output_formats": ["json"],
            "report_type": "general",
        }

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
        ):
            result = run_project_menu(current_config=current_config)

        # Verify user input overrides defaults
        assert result["client_name"] == "UpdatedCorp"
        assert result["aws_region"] == "us-west-1"
        assert result["skills"] == ["vulns"]
        assert result["aws_session_token"] == "token123"
        assert result["output_formats"] == ["markdown", "pdf"]
        assert result["report_type"] == "pci-dss"

    def test_region_selection_cancellation(self):
        """User cancels at region prompt -> KeyboardInterrupt."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
            _ask_mock("AKIA123"),  # access key
        ]
        password_prompts = [
            _ask_mock("secret123"),  # secret key
            _ask_mock(""),  # session token
        ]
        select_prompts = [
            _ask_mock("iam"),  # skill
            _ask_mock("manual"),  # credentials method
            _ask_mock(None),  # region cancelled
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()

    def test_output_formats_cancellation(self):
        """User cancels at output formats -> KeyboardInterrupt."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
            _ask_mock("AKIA123"),  # access key
        ]
        password_prompts = [
            _ask_mock("secret123"),  # secret key
            _ask_mock(""),  # session token
        ]
        select_prompts = [
            _ask_mock("iam"),  # skill
            _ask_mock("manual"),  # credentials method
            _ask_mock("us-east-1"),  # region
            _ask_mock("standard"),  # qsa_depth
        ]
        checkbox_prompts = [
            _ask_mock(None),  # output formats cancelled
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()

    def test_report_type_cancellation(self):
        """User cancels at report type prompt (non-pentest skill) -> KeyboardInterrupt."""
        text_prompts = [
            _ask_mock("TestCorp"),  # client name
            _ask_mock("AKIA123"),  # access key
        ]
        password_prompts = [
            _ask_mock("secret123"),  # secret key
            _ask_mock(""),  # session token
        ]
        select_prompts = [
            _ask_mock("exposure"),  # skill (not pentest)
            _ask_mock("manual"),  # credentials method
            _ask_mock("us-east-1"),  # region
            _ask_mock("standard"),  # qsa_depth
            _ask_mock(None),  # report type cancelled
        ]
        checkbox_prompts = [
            _ask_mock(["markdown"]),  # output formats
        ]

        with (
            patch("questionary.text", side_effect=text_prompts),
            patch("questionary.password", side_effect=password_prompts),
            patch("questionary.select", side_effect=select_prompts),
            patch("questionary.checkbox", side_effect=checkbox_prompts),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_project_menu()
