"""Tests for the main CLI entry point."""

from unittest.mock import patch

from click.testing import CliRunner

from drystone.cli.main import cli
from drystone.models.config import WizardConfig

def test_min_severity_cli_option():
    """Test that the --min-severity CLI option correctly updates the config."""
    runner = CliRunner()

    # We need to mock the functions that would otherwise make the app hang
    # waiting for user input or performing long operations.
    with patch("drystone.cli.main.run_setup_wizard") as mock_wizard, \
         patch("drystone.cli.main.validate_aws_credentials", return_value=(True, "OK", "123456789012")), \
         patch("drystone.cli.main.print_summary"), \
         patch("drystone.cli.main.save_config"), \
         patch("drystone.reports.generator.ReportGenerator") as MockReportGenerator, \
         patch("drystone.agent.client.AgentClient") as MockAgentClient, \
         patch("drystone.skills.iam.IAMSkill.collect"), \
         patch("drystone.skills.iam.IAMSkill.analyze"):
        
        # We need a base config to load when CLI args are used
        base_config = WizardConfig(
            client_name="Test",
            skills=["iam"],
            output_formats=["markdown"],
            aws_access_key_id="key",
            aws_secret_access_key="secret"
        )
        
        with patch("drystone.cli.main.load_last_config", return_value=base_config):
            # Run the audit command with the --min-severity flag
            result = runner.invoke(cli, ["audit", "--min-severity", "high", "--non-interactive"])

            assert result.exit_code == 0
            
            # The config object inside the `audit` function should be updated.
            # Since we can't directly inspect it, we check the object that would
            # be passed to ReportGenerator.
            
            # Let's get the config object passed to print_summary
            from drystone.cli.main import print_summary
            call_args, _ = print_summary.call_args
            config_passed = call_args[0]
            
            assert isinstance(config_passed, WizardConfig)
            assert config_passed.min_severity == "high"

