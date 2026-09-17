"""Tests for the interactive wizard's AI provider selection (P2 #7: claude CLI preflight)."""

from unittest.mock import MagicMock, patch

import pytest

from drystone.cli.ui.wizard import run_ai_menu, validate_ai_provider_credentials


def _ask_mock(*return_values):
    """Build a MagicMock whose .ask() returns each value in turn, in order."""
    mock = MagicMock()
    mock.ask.side_effect = list(return_values)
    return mock


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
