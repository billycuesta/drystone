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
from drystone.cloud.aws import validate_aws_credentials
from drystone.models import WizardConfig


@click.group()
@click.version_option(__version__, prog_name="drystone")
def cli() -> None:
    """🐡 Drystone - AWS Security Audit CLI powered by Claude."""
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
    type=click.Choice(
        [
            "pentest",
            "iam",
            "exposure",
            "network",
            "vulns",
            "alerting",
            "hardening",
            "ecr",
            "secretsmanager",
            "waf",
            "kms",
            "messaging",
            "cicd",
            "compute",
        ]
    ),
    help="Skills to execute (can specify multiple times)",
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
def audit(
    non_interactive: bool,
    client: Optional[str] = None,
    region: Optional[str] = None,
    skills: tuple = (),
    formats: tuple = (),
    min_severity: Literal["low", "medium", "high", "critical"] = "low",
    report_type: Optional[Literal["general", "pci-dss", "pentest"]] = None,
) -> None:
    """Run AWS security audit."""

    click.echo()  # Blank line before banner
    print_banner()
    click.echo()  # Blank line after banner

    # Load config
    config: Optional[WizardConfig] = None

    # Determine if we should use interactive mode
    has_cli_args = bool(
        client or region or skills or formats or min_severity != "low" or report_type
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
            # For now, CLI args only work with a saved config
            config = load_last_config()
            if not config:
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
                config.skills = list(skills)
            if formats:
                config.output_formats = list(formats)
            if min_severity:
                config.min_severity = min_severity
            if report_type:
                config.report_type = cast(Literal["general", "pci-dss", "pentest"], report_type)

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

    # Extract account ID from validation
    try:
        aws_access_key_id, aws_secret_access_key, aws_session_token = config.get_aws_credentials()
        _, _, account_id = validate_aws_credentials(
            aws_access_key_id, aws_secret_access_key, config.aws_region, aws_session_token
        )
        if not account_id:
            raise ValueError("Could not determine AWS account ID from credential validation")
    except Exception as e:
        click.echo(f"\n❌ Error validating credentials: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # === PHASE 2: EVIDENCE COLLECTION ===
    click.echo()
    from drystone.cloud.aws.client import AWSClient
    from drystone.storage.session import AuditSession

    # Create audit session
    click.echo("📁 Creating audit session...")
    session = AuditSession(config.client_name, account_id)
    click.echo(f"   Session: {session.base_path}\n")

    # Metrics tracker (per-session)
    from drystone.logging import MetricsTracker

    metrics_file = session.base_path / "metrics.json"
    metrics_tracker = MetricsTracker(metrics_file)

    # Create AWS client for all skills
    aws_client = AWSClient(config)

    # Dynamically load and execute skills
    skills_map = {
        "iam": ("drystone.skills.iam", "IAMSkill"),
        "exposure": ("drystone.skills.exposure", "ExposureSkill"),
        "network": ("drystone.skills.network", "NetworkSkill"),
        "vulns": ("drystone.skills.vulns", "VulnsSkill"),
        "alerting": ("drystone.skills.alerting", "AlertingSkill"),
        "hardening": ("drystone.skills.hardening", "HardeningSkill"),
        "ecr": ("drystone.skills.ecr", "ECRSkill"),
        "secretsmanager": ("drystone.skills.secretsmanager", "SecretsManagerSkill"),
        "waf": ("drystone.skills.waf", "WAFSkill"),
        "kms": ("drystone.skills.kms", "KMSSkill"),
        "messaging": ("drystone.skills.messaging", "MessagingSkill"),
        "cicd": ("drystone.skills.cicd", "CICDSkill"),
        "compute": ("drystone.skills.compute", "ComputeSkill"),
    }

    skill_instances = {}
    for skill_name in config.skills:
        if skill_name not in skills_map:
            click.echo(f"⚠️  Unknown skill: {skill_name}")
            continue

        module_name, class_name = skills_map[skill_name]
        try:
            # Dynamically import skill
            module = __import__(module_name, fromlist=[class_name])
            skill_class = getattr(module, class_name)
            skill = skill_class()
            skill_instances[skill_name] = skill

            # Execute collector
            click.echo(f"🔍 Executing {skill_name.capitalize()} Security Audit...")
            skill.collect(aws_client, session)

            # List generated files
            evidence_path = session.get_evidence_path(skill_name)
            files = sorted(evidence_path.glob("*"))

            click.echo(f"   ✅ Evidence saved ({len(files)} files):")
            for file in files:
                size_kb = file.stat().st_size / 1024
                click.echo(f"      - {file.name} ({size_kb:.1f} KB)")
            click.echo()

        except Exception as e:
            click.echo(f"   ❌ Error collecting {skill_name}: {e}")
            import traceback

            traceback.print_exc()

    # === PHASE 3: AGENT ANALYSIS ===
    click.echo("🤖 Analyzing evidence with AI...\n")

    from drystone.agent.client import AgentClient

    # Create provider configuration once
    aws_access_key_id, aws_secret_access_key, aws_session_token = config.get_aws_credentials()

    provider_config = {
        "type": config.ai_provider,
        "api_key": config.ai_api_key,
    }

    agent = AgentClient(provider_config=provider_config)
    agent.metrics_tracker = metrics_tracker

    # Analyze skills in PARALLEL using ThreadPoolExecutor
    # This dramatically speeds up multi-skill audits (4-5x faster)
    from concurrent.futures import ThreadPoolExecutor, as_completed

    click.echo("   🚀 Running skills in PARALLEL for maximum speed...\n")

    all_findings = {}

    with ThreadPoolExecutor(max_workers=len(skill_instances)) as executor:
        futures = {}

        # Submit all skills to executor
        for skill_name, skill in skill_instances.items():
            future = executor.submit(
                lambda sn=skill_name, sk=skill: (sn, sk.analyze(session, agent))
            )
            futures[future] = skill_name

        # Collect results as they complete (order-independent)
        for future in as_completed(futures):
            skill_name = futures[future]
            try:
                sn, findings_path = future.result()

                # Load findings data
                with open(findings_path) as f:
                    findings_data = json.load(f)
                    all_findings[skill_name] = findings_data

                # Show summary
                summary = findings_data["summary"]
                click.echo(f"   ✅ {skill_name.capitalize()}:")
                click.echo(
                    f"      Total: {summary['total_findings']} | "
                    f"Critical: {summary['critical']} | "
                    f"High: {summary['high']} | "
                    f"Risk: {summary['overall_risk_score']:.1f}/10\n"
                )

            except Exception as e:
                click.echo(f"   ❌ Analysis error for {skill_name}: {e}\n")

    # === PHASE 4: REPORT GENERATION ===
    if all_findings:
        click.echo("📄 Generating reports...\n")

        try:
            from drystone.reports import ReportGenerator

            generator = ReportGenerator(session, config)

            # Pentest reports are most useful as a consolidated output.
            if config.report_type == "pentest":
                generated_reports = generator.generate_consolidated_reports(
                    [str(f) for f in config.output_formats]
                )
                click.echo("   Consolidated Reports:")
                for format_name, report_path in generated_reports.items():
                    size_kb = report_path.stat().st_size / 1024
                    click.echo(
                        f"      ✅ {format_name.upper():8} {report_path.name:30} ({size_kb:.1f} KB)"
                    )
            else:
                # Generate reports for each skill
                for skill_name in all_findings.keys():
                    generated_reports = generator.generate_reports(
                        skill_name, [str(f) for f in config.output_formats]
                    )

                    click.echo(f"   {skill_name.capitalize()} Reports:")
                    for format_name, report_path in generated_reports.items():
                        size_kb = report_path.stat().st_size / 1024
                        click.echo(
                            f"      ✅ {format_name.upper():8} {report_path.name:30} ({size_kb:.1f} KB)"
                        )

            # Show how to view reports
            if "markdown" in config.output_formats:
                reports_path = session.get_findings_path()
                click.echo("\n📝 View reports:")
                click.echo(f"   ls {reports_path.parent}/")

            click.echo("\n✅ Phase 4 Complete (Report Generation)")

        except Exception as e:
            click.echo(f"\n⚠️  Report generation failed: {e}")
            click.echo("   Evidence and findings are saved, but reports could not be generated")
    else:
        click.echo("⚠️  Skipping Phase 4 (no findings to report)")

    # Show completion
    click.echo("\n✅ Audit Complete")
    click.echo(f"   Audit data: {session.base_path}")
    click.echo()


@cli.command()
def version() -> None:
    """Show version."""
    click.echo(f"Drystone {__version__}")


@cli.command()
@click.argument("skill_name", required=False)
def skill(skill_name: Optional[str] = None) -> None:
    """Manage security skills."""
    available_skills = [
        "iam",
        "exposure",
        "network",
        "vulns",
        "alerting",
        "hardening",
        "ecr",
        "secretsmanager",
        "waf",
    ]

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
