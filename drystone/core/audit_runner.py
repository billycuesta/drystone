"""CLI-agnostic audit orchestration core.

Runs evidence collection, AI analysis, correlation, active verification,
chain-of-custody manifest, report generation, and the QA gate for an
already-configured and already-credential-validated audit.

This module must stay free of `click` (and of `sys.exit`) so it can be
called programmatically -- not only from the `drystone audit` CLI command --
by future features such as trend analysis, scheduling, or multi-account runs.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional

from drystone.models import WizardConfig

if TYPE_CHECKING:
    # Imports kept lazy at runtime (inside run_audit(), matching the original
    # module-local imports in cli/main.py) -- these are type-checking only.
    from drystone.storage.session import AuditSession


@dataclass
class AuditRunResult:
    """Outcome of a single `run_audit()` call."""

    session: "AuditSession"
    all_findings: dict = field(default_factory=dict)
    qa_passed: bool = True


def run_audit(
    config: WizardConfig,
    account_id: str,
    *,
    on_message: Optional[Callable[[str], None]] = None,
) -> AuditRunResult:
    """Run the full audit pipeline for an already-validated configuration.

    Args:
        config: Fully-resolved wizard/CLI configuration.
        account_id: AWS account ID, already resolved via credential validation.
        on_message: Optional callback invoked with each progress/status message
            (mirrors what the CLI used to send straight to `click.echo`). When
            omitted, messages are silently discarded (silent/programmatic mode).

    Returns:
        AuditRunResult with the session, aggregated findings, and whether the
        post-scan QA gate passed.
    """
    _msg = on_message or (lambda _m: None)

    # === PHASE 2: EVIDENCE COLLECTION ===
    _msg("")
    from drystone.cloud.aws.client import AWSClient
    from drystone.storage.session import AuditSession

    # Create audit session
    _msg("📁 Creating audit session...")
    session = AuditSession(config.client_name, account_id)
    session.scan_depth = getattr(config, "scan_depth", "normal")  # propagate to skills
    _msg(f"   Session: {session.base_path}\n")

    # Metrics tracker (per-session)
    from drystone.logging import MetricsTracker

    metrics_file = session.base_path / "metrics.json"
    metrics_tracker = MetricsTracker(metrics_file)

    phase_total = 3
    phase_done = 0

    def _print_progress(phase_label: str, completed: int, total: int) -> None:
        pct = int((completed / max(1, total)) * 100)
        _msg(f"📊 Progress: {completed}/{total} phases ({pct}%) - {phase_label}")

    _print_progress("Starting collection", phase_done, phase_total)

    # Create AWS client
    aws_client = AWSClient(config)

    if str(getattr(config, "report_type", "")).lower() == "pentest":
        try:
            from drystone.pentest.inventory import collect_pentest_inventory

            _msg("🧭 Collecting high-level platform inventory for pentest scope...")
            inventory_path = collect_pentest_inventory(aws_client, session)
            _msg(f"   ✅ Inventory saved: {inventory_path.name}\n")
        except Exception as e:
            _msg(f"   ⚠️  Could not collect pentest inventory: {e}\n")

    # Dynamically load and execute skills (auto-discovered — see
    # drystone/skills/registry.py; a new skill needs zero edits here)
    from drystone.skills.registry import skill_display_names as _registry_display_names
    from drystone.skills.registry import skill_import_map as _registry_import_map

    skills_map = _registry_import_map()
    skill_display_names = _registry_display_names()

    skill_instances = {}
    collection_total = max(1, len(config.skills))
    collection_done = 0
    _msg(f"🔄 Phase 1/3 Collection: 0/{collection_total} skills")
    for skill_name in config.skills:
        if skill_name not in skills_map:
            _msg(f"⚠️  Unknown skill: {skill_name}")
            collection_done += 1
            _msg(f"   Phase 1/3 progress: {collection_done}/{collection_total}")
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
            _msg(f"🔍 Executing {skill_display} Security Audit...")
            skill.collect(aws_client, session)

            # List generated files
            evidence_path = session.get_evidence_path(skill_name)
            files = sorted(evidence_path.glob("*"))

            _msg(f"   ✅ Evidence saved ({len(files)} files):")
            for file in files:
                size_kb = file.stat().st_size / 1024
                _msg(f"      - {file.name} ({size_kb:.1f} KB)")
            _msg("")

        except Exception as e:
            _msg(f"   ❌ Error collecting {skill_name}: {e}")
            import traceback

            traceback.print_exc()
        finally:
            collection_done += 1
            _msg(f"   Phase 1/3 progress: {collection_done}/{collection_total}")
    phase_done += 1
    _print_progress("Collection complete", phase_done, phase_total)

    # === PHASE 3: AGENT ANALYSIS ===
    _msg("🤖 Analyzing evidence with AI...\n")

    from drystone.agent.client import AgentClient

    # Create provider configuration once
    provider_config = {
        "type": config.ai_provider,
        "api_key": config.ai_api_key,
        "model": config.claude_cli_model,
        "scan_depth": getattr(config, "scan_depth", "normal"),
        "qsa_depth": getattr(config, "qsa_depth", "standard"),
    }

    agent = AgentClient(provider_config=provider_config)
    agent.metrics_tracker = metrics_tracker

    # Analyze skills in PARALLEL using ThreadPoolExecutor
    # This dramatically speeds up multi-skill audits (4-5x faster)
    from concurrent.futures import ThreadPoolExecutor, as_completed

    max_workers = len(skill_instances)
    if config.ai_provider == "claude-cli":
        max_workers = 1
        _msg("   🚀 Running skills in SEQUENTIAL mode (claude-cli quota-safe)...\n")
    else:
        _msg("   🚀 Running skills in PARALLEL for maximum speed...\n")

    all_findings: dict[str, Any] = {}
    analysis_total = max(1, len(skill_instances))
    analysis_done = 0
    _msg(f"🔄 Phase 2/3 Analysis: 0/{analysis_total} skills")

    chunk_state: dict[str, Any] = {}
    chunk_lock = threading.Lock()

    def _on_chunk_progress(
        skill_name: str, current: int, total: int, stage: str, _note: str
    ) -> None:
        with chunk_lock:
            if stage == "start":
                chunk_state[skill_name] = {"current": 0, "total": max(1, total)}
                _sdn = skill_display_names.get(skill_name, skill_name)
                _msg(f"   📦 {_sdn}: chunking started (0/{max(1, total)})")
            elif stage in {"advance", "done"}:
                safe_total = max(1, total)
                safe_current = min(max(0, current), safe_total)
                prev = chunk_state.get(skill_name, {}).get("current", -1)
                if safe_current != prev:
                    chunk_state[skill_name] = {"current": safe_current, "total": safe_total}
                    _sdn = skill_display_names.get(skill_name, skill_name)
                    _msg(f"   📦 {_sdn}: chunks {safe_current}/{safe_total}")

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
                _msg(f"   ✅ {skill_display_names.get(skill_name, skill_name.capitalize())}:")
                _msg(
                    f"      Total: {summary['total_findings']} | "
                    f"Critical: {summary['critical']} | "
                    f"High: {summary['high']} | "
                    f"Risk: {summary['overall_risk_score']:.1f}/10\n"
                )
                analysis_done += 1
                _msg(f"   Phase 2/3 progress: {analysis_done}/{analysis_total}")

            except Exception as e:
                metrics_tracker.record_skill_complete(skill_name, False)
                _msg(f"   ❌ Analysis error for {skill_name}: {e}\n")
                analysis_done += 1
                _msg(f"   Phase 2/3 progress: {analysis_done}/{analysis_total}")

                err = str(e).lower()
                if "out of extra usage" in err or "quota" in err or "rate limit" in err:
                    for pending_future, pending_skill in futures.items():
                        if pending_future is future:
                            continue
                        if pending_future.cancel():
                            metrics_tracker.record_skill_complete(pending_skill, False)
                            _msg(
                                f"   ⚠️  Cancelled {pending_skill} analysis due to provider "
                                "quota exhaustion"
                            )
                            analysis_done += 1
                            _msg(f"   Phase 2/3 progress: {analysis_done}/{analysis_total}")
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
                _msg(f"  🔗 {_n_chains} attack chain(s) correlated\n")
        except Exception:
            pass  # Non-blocking: report generates with empty chains if correlation fails

    # === PHASE 3c: ACTIVE VERIFICATION ===
    # Real, non-destructive AWS API calls (AssumeRole, unauthenticated S3
    # HEAD/List) that prove specific findings are actually exploitable, not
    # just inferred. Runs before the integrity manifest below, since it
    # modifies correlated.json/exposure.json in place -- the manifest must
    # hash the post-verification state, not a stale one. Non-blocking: a
    # verification failure shouldn't stop the audit from producing a report.
    if getattr(config, "active_verification", True):
        from drystone.verification.runner import WARNING_BANNER, run_active_verification

        _msg(WARNING_BANNER)
        try:
            _verification_summary = run_active_verification(session.base_path, aws_client.session)
            _msg(
                f"  🔒 Active verification: {_verification_summary['attempted']} attempted, "
                f"{_verification_summary['succeeded']} succeeded, "
                f"{_verification_summary['denied']} denied, "
                f"{_verification_summary['errored']} errored "
                f"(log: {Path(_verification_summary['log_path']).name})\n"
            )
        except Exception as _verify_err:
            _msg(f"  ⚠️  Active verification failed: {_verify_err}\n")
    else:
        _msg("  ⏭️  Active verification skipped (--no-active-verification)\n")

    # === PHASE 3d: CHAIN-OF-CUSTODY MANIFEST ===
    # Hash every evidence/findings JSON now that collection, analysis, and
    # active verification are all done, so post-audit tampering with any of
    # it is detectable later via `drystone verify-integrity`. Non-blocking:
    # a manifest failure shouldn't stop the audit from producing a report.
    try:
        from drystone.storage.manifest import write_manifest

        _manifest_path, _manifest_hash = write_manifest(session.base_path)
        session.integrity_manifest_sha256 = _manifest_hash
        _msg(f"  🔒 Evidence integrity manifest written ({_manifest_path.name})\n")
    except Exception as _manifest_err:
        _msg(f"  ⚠️  Could not write integrity manifest: {_manifest_err}\n")

    # === PHASE 4: REPORT GENERATION ===
    if all_findings:
        _msg("📄 Generating reports...\n")

        try:
            from drystone.reports import ReportGenerator

            generator = ReportGenerator(session, config)
            reporting_units = 1 if config.report_type == "pentest" else max(1, len(all_findings))
            reporting_done = 0
            _msg(f"🔄 Phase 3/3 Reporting: 0/{reporting_units} units")

            # Pentest reports are most useful as a consolidated output.
            if config.report_type == "pentest":
                generated_reports = generator.generate_consolidated_reports(
                    [str(f) for f in config.output_formats]
                )
                _msg("   Consolidated Reports:")
                for format_name, report_path in generated_reports.items():
                    size_kb = report_path.stat().st_size / 1024
                    _msg(
                        f"      ✅ {format_name.upper():8} {report_path.name:30} ({size_kb:.1f} KB)"
                    )
                reporting_done += 1
                _msg(f"   Phase 3/3 progress: {reporting_done}/{reporting_units}")
            else:
                # Generate reports for each skill
                for skill_name in all_findings.keys():
                    generated_reports = generator.generate_reports(
                        skill_name, [str(f) for f in config.output_formats]
                    )

                    _msg(
                        f"   {skill_display_names.get(skill_name, skill_name.capitalize())} Reports:"
                    )
                    for format_name, report_path in generated_reports.items():
                        size_kb = report_path.stat().st_size / 1024
                        _msg(
                            f"      ✅ {format_name.upper():8} {report_path.name:30} ({size_kb:.1f} KB)"
                        )
                    reporting_done += 1
                    _msg(f"   Phase 3/3 progress: {reporting_done}/{reporting_units}")

            # Show how to view reports
            if "markdown" in config.output_formats:
                reports_path = session.get_findings_path()
                _msg("\n📝 View reports:")
                _msg(f"   ls {reports_path.parent}/")

            _msg("\n✅ Phase 4 Complete (Report Generation)")
            phase_done += 1
            _print_progress("Reporting complete", phase_done, phase_total)

        except Exception as e:
            _msg(f"\n⚠️  Report generation failed: {e}")
            _msg("   Evidence and findings are saved, but reports could not be generated")
    else:
        _msg("⚠️  Skipping Phase 4 (no findings to report)")
        phase_done += 1
        _print_progress("Reporting skipped", phase_done, phase_total)

    # Show completion
    try:
        from drystone.agent.optimizer import optimize_budgets_from_metrics

        opt = optimize_budgets_from_metrics(metrics_file)
        updated = int(opt.get("updated", 0))
        if updated > 0:
            _msg(f"   ⚙️  P3 optimizer updated {updated} budget override(s)")
    except Exception:
        pass

    # Post-scan QA gate
    qa_failed = False
    try:
        from drystone.validation.qa_gate import run_qa_gate

        qa = run_qa_gate(session.base_path, list(config.skills))
        if qa.passed:
            _msg("✅ QA Gate: PASS (critical coverage 100%, no placeholders)")
        else:
            qa_failed = True
            _msg("⚠️  QA Gate: FAIL")
            for issue in qa.issues:
                _msg(f"   - {issue}")
    except Exception as e:
        _msg(f"⚠️  QA Gate execution error: {e}")

    _msg("\n✅ Audit Complete")
    try:
        metrics = metrics_tracker.get_metrics()
        total_tokens = int(metrics.get("total_tokens_est", 0))
        prompt_tokens = int(metrics.get("total_prompt_tokens_est", 0))
        response_tokens = int(metrics.get("total_response_tokens_est", 0))
        if total_tokens > 0:
            _msg(
                f"   Estimated token usage (heuristic, not provider-billed): total={total_tokens:,} "
                f"(prompt={prompt_tokens:,}, response={response_tokens:,})"
            )
    except Exception:
        pass
    _msg(f"   Audit data: {session.base_path}")
    _msg("")

    return AuditRunResult(session=session, all_findings=all_findings, qa_passed=not qa_failed)
