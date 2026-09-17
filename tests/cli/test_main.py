"""Tests for drystone CLI main entry point."""

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from drystone.cli.main import cli
from drystone.models.config import PENTEST_CORE_SKILLS, WizardConfig


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_config():
    return WizardConfig(
        client_name="ACME Corp",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="us-east-1",
        skills=["iam"],
        output_formats=["markdown"],
        report_type="general",
    )


def _stop_at_credentials(runner, config, *args):
    """Helper: invoke audit, stop execution at credential validation step.

    Mocks all cosmetic/IO side effects so tests focus on config resolution logic.
    AWSClient(config).validate_credentials() raises to terminate the command
    before Phase 2.
    """
    with (
        patch("drystone.cli.main.load_last_config", return_value=config),
        patch("drystone.cli.main.print_banner"),
        patch("drystone.cli.main.print_summary"),
        patch("drystone.cli.main.save_config", return_value=Path("/tmp/last-run.json")),
        patch("drystone.cli.main.AWSClient") as mock_aws_client,
    ):
        mock_aws_client.return_value.validate_credentials.side_effect = Exception("stop here")
        return runner.invoke(cli, ["audit", *args])


# ── version ───────────────────────────────────────────────────────────────────


class TestVersionCommand:
    def test_version_flag(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "drystone" in result.output

    def test_version_command(self, runner):
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "Drystone" in result.output


# ── skill ─────────────────────────────────────────────────────────────────────


class TestSkillCommand:
    def test_list_all_skills(self, runner):
        result = runner.invoke(cli, ["skill"])
        assert result.exit_code == 0
        assert "iam" in result.output
        assert "exposure" in result.output
        assert "network" in result.output

    def test_known_skill(self, runner):
        result = runner.invoke(cli, ["skill", "iam"])
        assert result.exit_code == 0
        assert "iam" in result.output

    def test_unknown_skill_exits_with_error(self, runner):
        result = runner.invoke(cli, ["skill", "notaskill"])
        assert result.exit_code == 1
        assert "Unknown skill" in result.output


# ── logs ──────────────────────────────────────────────────────────────────────


class TestLogsCommand:
    def test_no_audit_logs_directory(self, runner):
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["logs"])
        assert result.exit_code == 0
        assert "No audit logs found" in result.output

    def test_empty_audit_logs_directory(self, runner):
        with runner.isolated_filesystem():
            Path("audit-logs").mkdir()
            result = runner.invoke(cli, ["logs"])
        assert result.exit_code == 0
        assert "No audit sessions found" in result.output

    def test_lists_existing_sessions(self, runner):
        with runner.isolated_filesystem():
            Path("audit-logs/acme-2026-01-01").mkdir(parents=True)
            Path("audit-logs/acme-2026-01-02").mkdir(parents=True)
            result = runner.invoke(cli, ["logs"])
        assert result.exit_code == 0
        assert "acme-2026-01-01" in result.output
        assert "acme-2026-01-02" in result.output


# ── audit: config resolution branches ─────────────────────────────────────────


class TestAuditConfigResolution:
    """The 3 branches in main.py that determine how config is obtained."""

    # Branch 1: non-interactive, no args ─────────────────────────────────────

    def test_non_interactive_without_saved_config_exits(self, runner):
        with (
            patch("drystone.cli.main.load_last_config", return_value=None),
            patch("drystone.cli.main.print_banner"),
        ):
            result = runner.invoke(cli, ["audit", "--non-interactive"])
        assert result.exit_code == 1
        assert "No saved configuration found" in result.output
        assert "drystone audit" in result.output

    def test_non_interactive_with_saved_config_loads_it(self, runner, sample_config):
        result = _stop_at_credentials(runner, sample_config, "--non-interactive")
        assert "Using saved configuration" in result.output

    # Branch 2: has_cli_args ──────────────────────────────────────────────────

    def test_cli_args_without_saved_config_exits(self, runner):
        with (
            patch("drystone.cli.main.load_last_config", return_value=None),
            patch("drystone.cli.main.print_banner"),
        ):
            result = runner.invoke(cli, ["audit", "--client", "ACME"])
        assert result.exit_code == 1
        assert "No saved configuration found" in result.output

    def test_cli_args_with_saved_config_loads_it(self, runner, sample_config):
        result = _stop_at_credentials(runner, sample_config, "--client", "ACME")
        assert "Using saved configuration with CLI overrides" in result.output

    # Branch 3: interactive wizard ────────────────────────────────────────────

    def test_wizard_returns_none_exits(self, runner):
        with (
            patch("drystone.cli.main.run_setup_wizard", return_value=None),
            patch("drystone.cli.main.print_banner"),
        ):
            result = runner.invoke(cli, ["audit"])
        assert result.exit_code == 1
        assert "Wizard returned empty configuration" in result.output

    def test_wizard_keyboard_interrupt_exits_cleanly(self, runner):
        with (
            patch("drystone.cli.main.run_setup_wizard", side_effect=KeyboardInterrupt),
            patch("drystone.cli.main.print_banner"),
        ):
            result = runner.invoke(cli, ["audit"])
        assert result.exit_code == 1
        assert "Audit cancelled" in result.output

    def test_wizard_unexpected_exception_exits_with_message(self, runner):
        with (
            patch("drystone.cli.main.run_setup_wizard", side_effect=RuntimeError("boom")),
            patch("drystone.cli.main.print_banner"),
        ):
            result = runner.invoke(cli, ["audit"])
        assert result.exit_code == 1
        assert "Error during wizard" in result.output


# ── audit: CLI overrides ──────────────────────────────────────────────────────


class TestAuditCliOverrides:
    """CLI flags must override the corresponding fields in the loaded config."""

    def test_client_override(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--client", "NewClient")
        assert sample_config.client_name == "NewClient"

    def test_region_override(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--region", "eu-west-1")
        assert sample_config.aws_region == "eu-west-1"

    def test_skills_single_skill_override(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--skills", "network")
        assert sample_config.skills == ["network"]

    def test_skills_pentest_expands_to_core_skills(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--skills", "pentest")
        assert sample_config.skills == list(PENTEST_CORE_SKILLS)
        assert sample_config.report_type == "pentest"

    def test_min_severity_override(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--min-severity", "high")
        assert sample_config.min_severity == "high"

    def test_report_type_override(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--report-type", "pci-dss")
        assert sample_config.report_type == "pci-dss"

    def test_scan_depth_override(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--scan-depth", "deep")
        assert sample_config.scan_depth == "deep"

    def test_no_active_verification_flag_disables_it(self, runner, sample_config):
        assert sample_config.active_verification is True  # default
        _stop_at_credentials(runner, sample_config, "--no-active-verification")
        assert sample_config.active_verification is False

    def test_active_verification_stays_on_by_default(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--client", "ACME")
        assert sample_config.active_verification is True

    def test_formats_override(self, runner, sample_config):
        _stop_at_credentials(runner, sample_config, "--formats", "json")
        assert "json" in sample_config.output_formats

    def test_invalid_skill_value_rejected_by_click(self, runner):
        result = runner.invoke(cli, ["audit", "--skills", "notvalid"])
        assert result.exit_code != 0

    def test_invalid_report_type_rejected_by_click(self, runner):
        result = runner.invoke(cli, ["audit", "--report-type", "bogus"])
        assert result.exit_code != 0

    def test_invalid_min_severity_rejected_by_click(self, runner):
        result = runner.invoke(cli, ["audit", "--min-severity", "extreme"])
        assert result.exit_code != 0

    def test_invalid_scan_depth_rejected_by_click(self, runner):
        result = runner.invoke(cli, ["audit", "--scan-depth", "ultra"])
        assert result.exit_code != 0


# ── audit: credential safety ──────────────────────────────────────────────────


class TestAuditCredentialSafety:
    """AWS credentials must never appear in CLI output."""

    def test_access_key_not_printed(self, runner, sample_config):
        result = _stop_at_credentials(runner, sample_config, "--non-interactive")
        assert sample_config.aws_access_key_id not in result.output

    def test_secret_key_not_printed(self, runner, sample_config):
        result = _stop_at_credentials(runner, sample_config, "--non-interactive")
        assert sample_config.aws_secret_access_key not in result.output


# ── audit: account-ID resolution goes through the full, AssumeRole-aware ──────
# AWSClient(config) instead of a role-blind reconstruction of raw keys.


class TestAuditAccountIdResolution:
    def _run_past_credentials(self, runner, config, validate_return, *args):
        """Invoke audit() through to run_audit(), mocking AWSClient's
        validate_credentials() and capturing what account_id run_audit() is
        actually called with.
        """
        captured = {}

        def _fake_run_audit(cfg, account_id, **kwargs):
            captured["account_id"] = account_id
            from drystone.core.audit_runner import AuditRunResult

            return AuditRunResult(session=object(), all_findings={}, qa_passed=True)

        with (
            patch("drystone.cli.main.load_last_config", return_value=config),
            patch("drystone.cli.main.print_banner"),
            patch("drystone.cli.main.print_summary"),
            patch("drystone.cli.main.save_config", return_value=Path("/tmp/last-run.json")),
            patch("drystone.cli.main.AWSClient") as mock_aws_client,
            patch("drystone.core.audit_runner.run_audit", side_effect=_fake_run_audit),
        ):
            mock_aws_client.return_value.validate_credentials.return_value = validate_return
            runner.invoke(cli, ["audit", *args])

        return mock_aws_client, captured

    def test_account_id_comes_from_awsclient_validate_credentials(self, runner, sample_config):
        """The resolved account_id must be whatever AWSClient(config) resolves --
        not a value reconstructed from raw keys behind AssumeRole's back."""
        mock_aws_client, captured = self._run_past_credentials(
            runner, sample_config, (True, "ok", "999999999999"), "--non-interactive"
        )
        assert captured["account_id"] == "999999999999"

    def test_awsclient_constructed_with_the_full_config_object(self, runner, sample_config):
        """AWSClient must receive the whole config (so it sees aws_role_arn),
        not a role-blind reconstruction from get_aws_credentials()."""
        sample_config.aws_role_arn = "arn:aws:iam::999999999999:role/DrystoneAuditRole"
        mock_aws_client, _ = self._run_past_credentials(
            runner, sample_config, (True, "ok", "999999999999"), "--non-interactive"
        )
        mock_aws_client.assert_called_once_with(sample_config)

    def test_invalid_credentials_still_exits_before_run_audit(self, runner, sample_config):
        mock_aws_client, captured = self._run_past_credentials(
            runner, sample_config, (False, "denied", None), "--non-interactive"
        )
        assert "account_id" not in captured
