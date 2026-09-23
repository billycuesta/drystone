"""Tests for the interactive wizard's AI provider selection (P2 #7: claude CLI preflight)."""

from unittest.mock import MagicMock, patch

import pytest

from drystone.cli.ui.wizard import (
    display_config_summary,
    run_ai_menu,
    run_setup_wizard,
    validate_ai_provider_credentials,
)


def _ask_mock(*return_values):
    """Build a MagicMock whose .ask() returns each value in turn, in order."""
    mock = MagicMock()
    mock.ask.side_effect = list(return_values)
    return mock


@pytest.fixture
def project_config():
    return {
        "client_name": "ACME",
        "aws_region": "us-east-1",
        "skills": ["iam"],
        "qsa_depth": "standard",
        "output_formats": ["markdown"],
        "report_type": "general",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "test-secret",
        "aws_session_token": None,
        "aws_credentials_file": None,
        "aws_profile": None,
        "aws_role_arn": None,
        "aws_role_session_name": None,
        "aws_external_id": None,
        "aws_role_duration_seconds": None,
    }


def _choice_values(select_call):
    return [choice.value for choice in select_call.kwargs["choices"]]


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
        confirm_prompts = [
            _ask_mock(True),  # active verification
            _ask_mock(False),  # terraform state scan opt-in
        ]

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
            _ask_mock(False),  # terraform state scan opt-in
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


class TestRunSetupWizard:
    def test_retries_aws_validation_and_only_offers_continue_after_success(self, project_config):
        action_prompts = [
            _ask_mock("edit_project"),
            _ask_mock("edit_project"),
            _ask_mock("continue"),
        ]

        with (
            patch("questionary.select", side_effect=action_prompts) as select,
            patch(
                "drystone.cli.ui.wizard.run_project_menu",
                side_effect=[project_config, project_config],
            ) as run_project_menu,
            patch("drystone.cli.ui.wizard.validate_aws_config", side_effect=[False, True]) as validate_aws,
            patch(
                "drystone.cli.ui.wizard.validate_ai_provider_credentials",
                return_value=True,
            ) as validate_ai,
            patch("drystone.cli.ui.wizard.display_config_summary") as display_summary,
        ):
            config = run_setup_wizard()

        assert config.client_name == "ACME"
        assert run_project_menu.call_count == 2
        assert validate_aws.call_count == 2
        assert validate_ai.call_count == 1
        assert display_summary.call_count == 2
        assert "continue" not in _choice_values(select.call_args_list[1])
        assert "continue" in _choice_values(select.call_args_list[2])

    def test_revalidates_ai_after_editing_ai_menu(self, project_config):
        ai_config = {
            "ai_provider": "claude-api",
            "ai_api_key": "sk-ant-test-key",
            "claude_cli_model": "sonnet",
            "scan_depth": "deep",
            "active_verification": False,
        }
        action_prompts = [
            _ask_mock("edit_project"),
            _ask_mock("edit_ai"),
            _ask_mock("continue"),
        ]

        with (
            patch("questionary.select", side_effect=action_prompts),
            patch("drystone.cli.ui.wizard.run_project_menu", return_value=project_config),
            patch("drystone.cli.ui.wizard.run_ai_menu", return_value=ai_config) as run_ai_menu,
            patch("drystone.cli.ui.wizard.validate_aws_config", return_value=True) as validate_aws,
            patch(
                "drystone.cli.ui.wizard.validate_ai_provider_credentials",
                return_value=True,
            ) as validate_ai,
            patch("drystone.cli.ui.wizard.display_config_summary"),
        ):
            config = run_setup_wizard()

        assert config.ai_api_key == "sk-ant-test-key"
        assert config.scan_depth == "deep"
        assert config.active_verification is False
        assert run_ai_menu.call_args.kwargs["current_config"]["ai_provider"] == "claude-api"
        assert validate_aws.call_count == 1
        assert validate_ai.call_count == 2

    def test_cancelling_navigation_interrupts_wizard(self):
        with (
            patch("questionary.select", return_value=_ask_mock(None)),
            pytest.raises(KeyboardInterrupt, match="Wizard cancelled"),
        ):
            run_setup_wizard()
