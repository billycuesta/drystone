"""Main CLI entry point for Drystone."""

import sys
from pathlib import Path

import click

from drystone.cli import __version__
from drystone.cli.config import load_last_config, save_config, use_last_config
from drystone.cli.ui import print_banner, run_setup_wizard
from drystone.cli.ui.branding import print_summary
from drystone.models import WizardConfig


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
    "--profile",
    help="AWS profile to use",
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
    profile: str = None,
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
    has_cli_args = bool(client or profile or region or skills or formats)
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
            # Create config from CLI args
            config = WizardConfig(
                client_name=client or "Default",
                aws_profile=profile or "default",
                aws_region=region or "us-east-1",
                skills=list(skills) if skills else ["iam"],
                output_formats=list(formats) if formats else ["markdown"],
            )
            click.echo("✅ Using CLI arguments\n")
        else:
            # No interactive mode and no CLI args - try last config
            config = load_last_config()
            if not config:
                click.echo("❌ No saved configuration found and --non-interactive mode requires --client or saved config")
                sys.exit(1)
            click.echo("✅ Using saved configuration\n")


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
