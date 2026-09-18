"""Main CLI entry point for Drystone."""

import json
import sys
from pathlib import Path
from typing import Literal, Optional, cast

import click

from drystone.cli import __version__
from drystone.cli.config import load_last_config, save_config
from drystone.cli.ui import print_banner, run_setup_wizard
from drystone.cli.ui.branding import print_summary
from drystone.cloud.aws.client import AWSClient
from drystone.models import WizardConfig
from drystone.skills.registry import skill_names as _registry_skill_names

_DEBUG = False


@click.group()
@click.option(
    "--debug",
    "-v",
    is_flag=True,
    help="Show full tracebacks on error, instead of a one-line message.",
)
@click.version_option(__version__, prog_name="drystone")
def cli(debug: bool) -> None:
    """🐡 Drystone - AWS Security Audit CLI powered by Claude."""
    global _DEBUG
    _DEBUG = debug


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
    type=click.Choice(["pentest"] + _registry_skill_names()),
    help="Single skill to execute (use 'pentest' for multi-skill preset)",
)
@click.option(
    "--formats",
    multiple=True,
    type=click.Choice(["markdown", "json", "pdf"]),
    help="Output formats (can specify multiple times)",
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to report",
)
@click.option(
    "--report-type",
    type=click.Choice(["general", "pci-dss", "pentest"], case_sensitive=False),
    help="Report type (general, pci-dss, pentest)",
)
@click.option(
    "--scan-depth",
    type=click.Choice(["shallow", "normal", "deep", "very-deep"]),
    help="Scan depth controlling chunk budget and token usage",
)
@click.option(
    "--no-active-verification",
    is_flag=True,
    default=False,
    help=(
        "Skip active verification (real, non-destructive AWS API calls -- AssumeRole, "
        "unauthenticated S3 HEAD/List -- that prove specific findings are exploitable). "
        "Active verification runs by default; this activity appears in the target "
        "account's CloudTrail logs, so disable it for engagements whose authorized "
        "scope doesn't cover active testing."
    ),
)
def audit(
    non_interactive: bool,
    client: Optional[str] = None,
    region: Optional[str] = None,
    skills: Optional[str] = None,
    formats: tuple = (),
    min_severity: Literal["low", "medium", "high", "critical"] = "low",
    report_type: Optional[Literal["general", "pci-dss", "pentest"]] = None,
    scan_depth: Optional[Literal["shallow", "normal", "deep", "very-deep"]] = None,
    no_active_verification: bool = False,
) -> None:
    """Run AWS security audit."""

    click.echo()  # Blank line before banner
    print_banner()
    click.echo()  # Blank line after banner

    # Load config
    config: Optional[WizardConfig] = None

    # Determine if we should use interactive mode
    has_cli_args = bool(
        client
        or region
        or skills
        or formats
        or min_severity != "low"
        or report_type
        or scan_depth
        or no_active_verification
    )
    should_use_interactive = not non_interactive and not has_cli_args

    if not config:
        if should_use_interactive:
            # Run wizard directly
            try:
                config = run_setup_wizard()
                if not config:
                    click.echo("\n❌ Wizard returned empty configuration")
                    sys.exit(1)
            except KeyboardInterrupt:
                click.echo("\n❌ Audit cancelled")
                sys.exit(1)
            except Exception as e:
                click.echo(f"\n❌ Error during wizard: {e}")
                import traceback

                traceback.print_exc()
                sys.exit(1)
        elif has_cli_args:
            # For now, CLI args only work with a saved config. Load that specific
            # client's own config when --client is given, so CLI-arg runs never
            # silently inherit a different client's saved skills/formats/provider.
            config = load_last_config(client=client)
            if not config:
                if client:
                    click.echo(
                        f"❌ No saved configuration found for client '{client}'. "
                        "Run the interactive wizard for this client first: drystone audit --client "
                        f'"{client}"'
                    )
                else:
                    click.echo(
                        "❌ No saved configuration found. Please run 'drystone audit' first to create one."
                    )
                sys.exit(1)
            click.echo("✅ Using saved configuration with CLI overrides\n")
            # Override config with CLI args
            if client:
                config.client_name = client
            if region:
                config.aws_region = region
            if skills:
                if skills == "pentest":
                    from drystone.models.config import PENTEST_CORE_SKILLS

                    config.skills = list(PENTEST_CORE_SKILLS)
                    config.report_type = "pentest"
                else:
                    config.skills = [skills]
            if formats:
                config.output_formats = list(formats)
            if min_severity:
                config.min_severity = min_severity
            if report_type:
                config.report_type = cast(Literal["general", "pci-dss", "pentest"], report_type)
            if scan_depth:
                config.scan_depth = scan_depth

        else:  # non-interactive and no other args
            # No interactive mode and no CLI args - try last config
            config = load_last_config()
            if not config:
                click.echo("❌ No saved configuration found. Please run: drystone audit")
                sys.exit(1)
            click.echo("✅ Using saved configuration\n")

    # After config is loaded or created, update min_severity if passed via CLI
    # This ensures CLI flag takes precedence
    if min_severity and min_severity != "low" and config is not None:
        config.min_severity = cast(Literal["low", "medium", "high", "critical"], min_severity)
    if report_type and config is not None:
        config.report_type = cast(Literal["general", "pci-dss", "pentest"], report_type)
    if scan_depth and config is not None:
        config.scan_depth = scan_depth
    if no_active_verification and config is not None:
        config.active_verification = False
    # Show summary
    try:
        print_summary(config)
    except Exception as e:
        click.echo(f"\n❌ Error displaying summary: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Save config
    try:
        saved_path = save_config(config)
        click.echo(f"💾 Configuration saved to {saved_path}\n")
    except Exception as e:
        click.echo(f"\n❌ Error saving configuration: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Extract account ID from validation. Goes through AWSClient(config)
    # directly (the full config, not a role-blind reconstruction of raw
    # keys) so AssumeRole is actually exercised here: the resolved
    # account_id must reflect the target role's account, not the source
    # identity's, whenever aws_role_arn is configured.
    account_id: str
    try:
        is_valid, message, validated_account_id = AWSClient(config).validate_credentials()
        if not is_valid or not validated_account_id:
            raise ValueError(
                message or "Could not determine AWS account ID from credential validation"
            )
        account_id = validated_account_id
    except Exception as e:
        click.echo(f"\n❌ Error validating credentials: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Evidence collection, AI analysis, correlation, active verification,
    # chain-of-custody manifest, report generation, and the QA gate all live
    # in the CLI-agnostic core so they can be invoked programmatically (not
    # just from this command) -- see drystone/core/audit_runner.py.
    from drystone.core.audit_runner import run_audit

    result = run_audit(config, account_id, on_message=click.echo)

    if not result.qa_passed:
        sys.exit(2)


@cli.command()
def version() -> None:
    """Show version."""
    click.echo(f"Drystone {__version__}")


@cli.command()
@click.argument("skill_name", required=False)
def skill(skill_name: Optional[str] = None) -> None:
    """Manage security skills."""
    available_skills = _registry_skill_names()

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
        if format == "json":
            click.echo(json.dumps([]))
        else:
            click.echo("No audit logs found")
        return

    sessions = sorted([d for d in audit_logs_dir.iterdir() if d.is_dir()])

    if format == "json":
        click.echo(
            json.dumps(
                [{"name": session.name, "path": str(session)} for session in sessions],
                indent=2,
            )
        )
        return

    if not sessions:
        click.echo("No audit sessions found")
        return

    click.echo("📋 Audit Sessions:")
    for session in sessions:
        click.echo(f"  • {session.name}")


@cli.command(name="verify-integrity")
@click.argument("session_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
def verify_integrity(session_dir: Path) -> None:
    """Verify evidence/findings haven't been tampered with since the audit ran.

    SESSION_DIR is an audit-logs/{client}_{timestamp}/ directory containing
    a manifest.json written during the audit.
    """
    from drystone.storage.manifest import verify_manifest

    result = verify_manifest(session_dir)

    if result["error"]:
        click.echo(f"❌ {result['error']}")
        sys.exit(1)

    click.echo(f"🔒 Checked {result['checked_files']} evidence/findings file(s)")
    click.echo(f"   Manifest generated: {result['manifest_generated_at']}")

    if result["ok"]:
        click.echo("✅ Integrity verified — no tampering detected")
        return

    if result["tampered"]:
        click.echo(f"\n❌ {len(result['tampered'])} file(s) modified since the audit ran:")
        for rel in result["tampered"]:
            click.echo(f"   • {rel}")
    if result["missing"]:
        click.echo(f"\n❌ {len(result['missing'])} file(s) recorded but no longer present:")
        for rel in result["missing"]:
            click.echo(f"   • {rel}")
    if result["added"]:
        click.echo(f"\n⚠️  {len(result['added'])} file(s) present but not in the manifest:")
        for rel in result["added"]:
            click.echo(f"   • {rel}")
    sys.exit(1)


def main() -> None:
    """Entry point for console script."""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        if _DEBUG:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
