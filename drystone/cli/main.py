"""Main CLI entry point for Drystone."""

import sys
from pathlib import Path

import click

from drystone.cli import __version__
from drystone.cli.config import load_last_config, save_config, use_last_config
from drystone.cli.ui import print_banner, run_setup_wizard
from drystone.cli.ui.branding import print_summary
from drystone.cloud.aws import validate_aws_credentials
from drystone.models import WizardConfig


def validate_and_show_aws_creds(access_key_id: str, secret_access_key: str, region: str) -> bool:
    """Validate AWS credentials and show result to user.

    Args:
        access_key_id: AWS Access Key ID
        secret_access_key: AWS Secret Access Key
        region: AWS region

    Returns:
        True if credentials are valid, False otherwise
    """
    masked_key = f"{access_key_id[:4]}...{access_key_id[-4:]}"
    click.echo(f"\nValidating AWS credentials (Key: {masked_key})...")
    is_valid, message, account_id = validate_aws_credentials(access_key_id, secret_access_key, region)
    click.echo(message)
    return is_valid


@click.group()
@click.version_option(__version__, prog_name="drystone")
def cli() -> None:
    """🪨 Drystone - AWS Security Audit CLI powered by Claude."""
    pass


@cli.command()
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Skip wizard, use last saved config",
)
@click.option(
    "--client",
    help="Client/project name",
)
@click.option(
    "--region",
    help="AWS region",
)
@click.option(
    "--skills",
    multiple=True,
    type=click.Choice(["iam", "exposure", "network", "vulns"]),
    help="Skills to execute (can specify multiple times)",
)
@click.option(
    "--formats",
    multiple=True,
    type=click.Choice(["markdown", "html", "json"]),
    help="Output formats (can specify multiple times)",
)
def audit(
    non_interactive: bool,
    client: str = None,
    region: str = None,
    skills: tuple = (),
    formats: tuple = (),
) -> None:
    """Run AWS security audit."""

    print_banner()
    click.echo("📋 Configuration Setup")
    click.echo("━" * 50 + "\n")

    # Load config
    config: WizardConfig = None

    # Determine if we should use interactive mode
    has_cli_args = bool(client or region or skills or formats)
    should_use_interactive = not non_interactive and not has_cli_args

    if should_use_interactive and use_last_config():
        # Try to load last config
        config = load_last_config()
        if config:
            click.echo("✅ Using saved configuration\n")

    if not config:
        if should_use_interactive:
            # Run wizard
            try:
                config = run_setup_wizard()
            except KeyboardInterrupt:
                click.echo("\n❌ Audit cancelled")
                sys.exit(1)
        elif has_cli_args:
            # CLI args provided but credentials must come from wizard
            click.echo("⚠️  Credentials must be entered interactively for security reasons")
            click.echo("Please run: drystone audit\n")
            sys.exit(1)
        else:
            # No interactive mode and no CLI args - try last config
            config = load_last_config()
            if not config:
                click.echo("❌ No saved configuration found. Please run: drystone audit")
                sys.exit(1)
            click.echo("✅ Using saved configuration\n")

    # Validate AWS credentials
    if not validate_and_show_aws_creds(config.aws_access_key_id, config.aws_secret_access_key, config.aws_region):
        click.echo("\n❌ Invalid AWS credentials. Please check your credentials and try again.")
        sys.exit(1)

    # Show summary
    print_summary(config)

    # Save config
    saved_path = save_config(config)
    click.echo(f"💾 Configuration saved to {saved_path}\n")

    # Ready to execute
    click.echo("🚀 [Audit execution pending - Phase 1+]")
    click.echo("   ✅ Config validated and saved")
    click.echo("   ⏳ Awaiting orchestrator implementation")
    click.echo()


@cli.command()
def version() -> None:
    """Show version."""
    click.echo(f"Drystone {__version__}")


@cli.command()
@click.argument("skill_name", required=False)
def skill(skill_name: str = None) -> None:
    """Manage security skills."""
    available_skills = ["iam", "exposure", "network", "vulns"]

    if not skill_name:
        click.echo("Available Skills:")
        for s in available_skills:
            click.echo(f"  • {s}")
        return

    if skill_name not in available_skills:
        click.echo(f"❌ Unknown skill: {skill_name}")
        sys.exit(1)

    click.echo(f"ℹ️  Skill: {skill_name}")


@cli.command()
@click.option(
    "--format",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
def logs(format: str) -> None:
    """View audit logs and reports."""
    audit_logs_dir = Path.cwd() / "audit-logs"

    if not audit_logs_dir.exists():
        click.echo("No audit logs found")
        return

    sessions = sorted([d for d in audit_logs_dir.iterdir() if d.is_dir()])

    if not sessions:
        click.echo("No audit sessions found")
        return

    click.echo("📋 Audit Sessions:")
    for session in sessions:
        click.echo(f"  • {session.name}")


def main() -> None:
    """Entry point for console script."""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
