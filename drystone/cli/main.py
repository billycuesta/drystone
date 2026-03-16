"""Main CLI entry point for Drystone."""

import json
import sys
import threading
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
    type=click.Choice(
        [
            "pentest",
            "recon",
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
            "sistemas_explotables_red",
        ]
    ),
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
    "--client-context",
    type=click.Path(exists=True),
    help="Path to client-context.md file for report enrichment",
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
    client_context: Optional[str] = None,
) -> None:
    """Run AWS security audit."""

    click.echo()  # Blank line before banner
    print_banner()
    click.echo()  # Blank line after banner

    # Load config
    config: Optional[WizardConfig] = None

    # Determine if we should use interactive mode
    has_cli_args = bool(
        client or region or skills or formats or min_severity != "low" or report_type or scan_depth or client_context
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
    if client_context and config is not None:
        config.client_context_file = Path(client_context)

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
    account_id: str
    try:
        aws_access_key_id, aws_secret_access_key, aws_session_token = config.get_aws_credentials()
        _, _, validated_account_id = validate_aws_credentials(
            aws_access_key_id, aws_secret_access_key, config.aws_region, aws_session_token
        )
        if not validated_account_id:
            raise ValueError("Could not determine AWS account ID from credential validation")
        account_id = validated_account_id
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

    phase_total = 3
    phase_done = 0

    def _print_progress(phase_label: str, completed: int, total: int) -> None:
        pct = int((completed / max(1, total)) * 100)
        click.echo(f"📊 Progress: {completed}/{total} phases ({pct}%) - {phase_label}")

    _print_progress("Starting collection", phase_done, phase_total)

    # Create AWS client
    aws_client = AWSClient(config)

    if str(getattr(config, "report_type", "")).lower() == "pentest":
        try:
            from drystone.pentest.inventory import collect_pentest_inventory

            click.echo("🧭 Collecting high-level platform inventory for pentest scope...")
            inventory_path = collect_pentest_inventory(aws_client, session)
            click.echo(f"   ✅ Inventory saved: {inventory_path.name}\n")
        except Exception as e:
            click.echo(f"   ⚠️  Could not collect pentest inventory: {e}\n")

    # Dynamically load and execute skills
    skills_map = {
        "recon": ("drystone.skills.recon", "ReconSkill"),
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
        "sistemas_explotables_red": (
            "drystone.skills.sistemas_explotables_red",
            "SistemasExplotablesRedSkill",
        ),
    }

    skill_display_names = {
        "sistemas_explotables_red": "Network-Exploitable Systems Detection",
        "iam": "IAM",
        "exposure": "Exposure",
        "network": "Network",
        "vulns": "Vulnerabilities",
        "hardening": "Hardening",
        "secretsmanager": "Secrets Manager",
        "waf": "WAF",
        "ecr": "ECR",
        "alerting": "Alerting",
        "recon": "Recon",
        "kms": "KMS",
        "cicd": "CI/CD",
        "compute": "Compute",
    }

    skill_instances = {}
    collection_total = max(1, len(config.skills))
    collection_done = 0
    click.echo(f"🔄 Phase 1/3 Collection: 0/{collection_total} skills")
    for skill_name in config.skills:
        if skill_name not in skills_map:
            click.echo(f"⚠️  Unknown skill: {skill_name}")
            collection_done += 1
            click.echo(f"   Phase 1/3 progress: {collection_done}/{collection_total}")
            continue

        module_name, class_name = skills_map[skill_name]
        try:
            # Dynamically import skill
            module = __import__(module_name, fromlist=[class_name])
            skill_class = getattr(module, class_name)
            skill = skill_class()
            skill_instances[skill_name] = skill

            # Execute collector
            skill_display = skill_display_names.get(skill_name, skill_name.capitalize())
            click.echo(f"🔍 Executing {skill_display} Security Audit...")
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
        finally:
            collection_done += 1
            click.echo(f"   Phase 1/3 progress: {collection_done}/{collection_total}")
    phase_done += 1
    _print_progress("Collection complete", phase_done, phase_total)

    # === PHASE 3: AGENT ANALYSIS ===
    click.echo("🤖 Analyzing evidence with AI...\n")

    from drystone.agent.client import AgentClient

    # Create provider configuration once
    config.get_aws_credentials()  # validates creds are still accessible (no-op for analysis)

    provider_config = {
        "type": config.ai_provider,
        "api_key": config.ai_api_key,
        "model": config.claude_cli_model,
        "scan_depth": getattr(config, "scan_depth", "normal"),
    }

    agent = AgentClient(provider_config=provider_config)
    agent.metrics_tracker = metrics_tracker

    # Inject client context XML for AI prompt enrichment
    if hasattr(config, "_client_context") and config._client_context:
        ctx = config._client_context
        ctx_parts = ["<client_context>"]
        if ctx.organization:
            ctx_parts.append(f"  <organization>{ctx.organization}</organization>")
        if ctx.industry:
            ctx_parts.append(f"  <industry>{ctx.industry}</industry>")
        if ctx.business_context:
            ctx_parts.append(f"  <business_context>{ctx.business_context}</business_context>")
        if ctx.compliance_reqs:
            ctx_parts.append(f"  <compliance_requirements>{ctx.compliance_reqs}</compliance_requirements>")
        ctx_parts.append("</client_context>")
        agent._client_context_xml = "\n".join(ctx_parts)

    # Analyze skills in PARALLEL using ThreadPoolExecutor
    # This dramatically speeds up multi-skill audits (4-5x faster)
    from concurrent.futures import ThreadPoolExecutor, as_completed

    max_workers = len(skill_instances)
    if config.ai_provider == "claude-cli":
        max_workers = 1
        click.echo("   🚀 Running skills in SEQUENTIAL mode (claude-cli quota-safe)...\n")
    else:
        click.echo("   🚀 Running skills in PARALLEL for maximum speed...\n")

    all_findings = {}
    analysis_total = max(1, len(skill_instances))
    analysis_done = 0
    click.echo(f"🔄 Phase 2/3 Analysis: 0/{analysis_total} skills")

    chunk_state = {}
    chunk_lock = threading.Lock()

    def _on_chunk_progress(
        skill_name: str, current: int, total: int, stage: str, _note: str
    ) -> None:
        with chunk_lock:
            if stage == "start":
                chunk_state[skill_name] = {"current": 0, "total": max(1, total)}
                click.echo(f"   📦 {skill_name}: chunking started (0/{max(1, total)})")
            elif stage in {"advance", "done"}:
                safe_total = max(1, total)
                safe_current = min(max(0, current), safe_total)
                prev = chunk_state.get(skill_name, {}).get("current", -1)
                if safe_current != prev:
                    chunk_state[skill_name] = {"current": safe_current, "total": safe_total}
                    click.echo(f"   📦 {skill_name}: chunks {safe_current}/{safe_total}")

    agent.progress_callback = _on_chunk_progress

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}

        # Submit all skills to executor
        for skill_name, skill in skill_instances.items():
            metrics_tracker.record_skill_start(skill_name)
            metrics_tracker.record_skill_provider(skill_name, config.ai_provider)
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
                metrics_tracker.record_skill_findings(
                    skill_name,
                    int(summary.get("total_findings", 0)),
                    float(summary.get("overall_risk_score", 0.0)),
                )
                metrics_tracker.record_skill_complete(skill_name, True)
                click.echo(f"   ✅ {skill_name.capitalize()}:")
                click.echo(
                    f"      Total: {summary['total_findings']} | "
                    f"Critical: {summary['critical']} | "
                    f"High: {summary['high']} | "
                    f"Risk: {summary['overall_risk_score']:.1f}/10\n"
                )
                analysis_done += 1
                click.echo(f"   Phase 2/3 progress: {analysis_done}/{analysis_total}")

            except Exception as e:
                metrics_tracker.record_skill_complete(skill_name, False)
                click.echo(f"   ❌ Analysis error for {skill_name}: {e}\n")
                analysis_done += 1
                click.echo(f"   Phase 2/3 progress: {analysis_done}/{analysis_total}")

                err = str(e).lower()
                if "out of extra usage" in err or "quota" in err or "rate limit" in err:
                    for pending_future, pending_skill in futures.items():
                        if pending_future is future:
                            continue
                        if pending_future.cancel():
                            metrics_tracker.record_skill_complete(pending_skill, False)
                            click.echo(
                                f"   ⚠️  Cancelled {pending_skill} analysis due to provider quota exhaustion"
                            )
                            analysis_done += 1
                            click.echo(f"   Phase 2/3 progress: {analysis_done}/{analysis_total}")
                    break
    phase_done += 1
    _print_progress("Analysis complete", phase_done, phase_total)

    # === PHASE 3b: CROSS-SKILL CORRELATION ===
    if all_findings and len(all_findings) > 1:
        try:
            from drystone.correlation.engine import CorrelationEngine
            _engine = CorrelationEngine(session_dir=session.base_path)
            _corr_result = _engine.run()
            _n_chains = _corr_result.get("total_correlations", 0)
            if _n_chains:
                click.echo(f"  🔗 {_n_chains} attack chain(s) correlated\n")
        except Exception as _corr_err:
            pass  # Non-blocking: report generates with empty chains if correlation fails

    # === PHASE 4: REPORT GENERATION ===
    if all_findings:
        click.echo("📄 Generating reports...\n")

        try:
            from drystone.reports import ReportGenerator

            generator = ReportGenerator(session, config)
            reporting_units = 1 if config.report_type == "pentest" else max(1, len(all_findings))
            reporting_done = 0
            click.echo(f"🔄 Phase 3/3 Reporting: 0/{reporting_units} units")

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
                reporting_done += 1
                click.echo(f"   Phase 3/3 progress: {reporting_done}/{reporting_units}")
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
                    reporting_done += 1
                    click.echo(f"   Phase 3/3 progress: {reporting_done}/{reporting_units}")

            # Show how to view reports
            if "markdown" in config.output_formats:
                reports_path = session.get_findings_path()
                click.echo("\n📝 View reports:")
                click.echo(f"   ls {reports_path.parent}/")

            click.echo("\n✅ Phase 4 Complete (Report Generation)")
            phase_done += 1
            _print_progress("Reporting complete", phase_done, phase_total)

        except Exception as e:
            click.echo(f"\n⚠️  Report generation failed: {e}")
            click.echo("   Evidence and findings are saved, but reports could not be generated")
    else:
        click.echo("⚠️  Skipping Phase 4 (no findings to report)")
        phase_done += 1
        _print_progress("Reporting skipped", phase_done, phase_total)

    # Show completion
    try:
        from drystone.agent.optimizer import optimize_budgets_from_metrics

        opt = optimize_budgets_from_metrics(metrics_file)
        updated = int(opt.get("updated", 0))
        if updated > 0:
            click.echo(f"   ⚙️  P3 optimizer updated {updated} budget override(s)")
    except Exception:
        pass

    # Post-scan QA gate
    qa_failed = False
    try:
        from drystone.validation.qa_gate import run_qa_gate

        qa = run_qa_gate(session.base_path, list(config.skills))
        if qa.passed:
            click.echo("✅ QA Gate: PASS (critical coverage 100%, no placeholders)")
        else:
            qa_failed = True
            click.echo("⚠️  QA Gate: FAIL")
            for issue in qa.issues:
                click.echo(f"   - {issue}")
    except Exception as e:
        click.echo(f"⚠️  QA Gate execution error: {e}")

    click.echo("\n✅ Audit Complete")
    try:
        metrics = metrics_tracker.get_metrics()
        total_tokens = int(metrics.get("total_tokens_est", 0))
        prompt_tokens = int(metrics.get("total_prompt_tokens_est", 0))
        response_tokens = int(metrics.get("total_response_tokens_est", 0))
        if total_tokens > 0:
            click.echo(
                f"   Estimated token usage (heuristic, not provider-billed): total={total_tokens:,} "
                f"(prompt={prompt_tokens:,}, response={response_tokens:,})"
            )
    except Exception:
        pass
    click.echo(f"   Audit data: {session.base_path}")
    click.echo()

    if qa_failed:
        sys.exit(2)


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
        "sistemas_explotables_red",
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
