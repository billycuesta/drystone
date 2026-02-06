"""Orchestrator for audit workflow with validation integration.

Coordinates the full audit flow:
1. Collect evidence from AWS
2. Analyze with Gemini agent
3. Validate results (NEW - hybrid validation)
4. Generate reports
5. Save session data

Key principle: App orchestrates, agent analyzes, validator reviews.
"""

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from drystone.models.config import WizardConfig
from drystone.validation import (
    validate_checklist_coverage,
    FindingsReviewer,
    validate_report_completeness,
)
from drystone.logging import MetricsTracker, CrashSafeLogger

logger = logging.getLogger(__name__)


class SkillProgressTracker:
    """Track and report skill progress during parallel execution.

    Provides real-time progress updates with ETA estimation.
    Thread-safe using locks for concurrent access.

    Example:
        >>> tracker = SkillProgressTracker(6)
        >>> tracker.start()
        >>> tracker.record_completion("iam", "PASS")
        [1/6] iam (PASS) - ETA: 45s
    """

    def __init__(self, total_skills: int):
        """Initialize progress tracker.

        Args:
            total_skills: Total number of skills to audit
        """
        self.total = total_skills
        self.completed = 0
        self.lock = threading.Lock()
        self.start_time = None
        self.skill_times = {}

    def start(self) -> None:
        """Mark the start of audit."""
        self.start_time = datetime.now()
        logger.info(f"Progress tracker started: {self.total} skills")

    def record_completion(
        self,
        skill_name: str,
        status: str,
        duration: Optional[float] = None,
    ) -> None:
        """Record completion of a skill.

        Thread-safe. Updates progress, calculates ETA.

        Args:
            skill_name: Name of the completed skill
            status: Completion status ("PASS", "FAIL", "NEEDS_REVIEW")
            duration: Optional duration in seconds
        """
        with self.lock:
            self.completed += 1
            if duration:
                self.skill_times[skill_name] = duration

            elapsed = (datetime.now() - self.start_time).total_seconds()
            avg_time = elapsed / self.completed if self.completed > 0 else 0
            remaining_skills = self.total - self.completed
            est_remaining = avg_time * remaining_skills

            # Format ETA
            eta_str = f"{est_remaining:.0f}s" if est_remaining > 0 else "done"

            logger.info(
                f"[{self.completed}/{self.total}] {skill_name:15} ({status:11}) "
                f"- ETA: {eta_str}"
            )

    def summary(self) -> str:
        """Get progress summary string."""
        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        pct = 100 * self.completed / self.total if self.total > 0 else 0

        return (
            f"Progress: {self.completed}/{self.total} ({pct:.0f}%) "
            f"- Elapsed: {elapsed:.1f}s"
        )


class AuditOrchestrator:
    """Main orchestrator for AWS security audits with validation."""

    def __init__(self, config: WizardConfig):
        """Initialize orchestrator.

        Args:
            config: WizardConfig with credentials and settings
        """
        self.config = config
        self.audit_id = datetime.now().isoformat()
        self.results = {}
        self.results_lock = threading.Lock()  # Protect self.results in parallel execution

    def run_skill_audit(
        self,
        skill_name: str,
        collector_class: Any,
        analyzer_class: Any,
        checklist_path: Path,
    ) -> Dict[str, Any]:
        """Run single skill audit with full validation pipeline.

        Flow:
        1. Collect evidence from AWS
        2. Analyze with Gemini agent
        3. Validate checklist coverage (programmatic, free)
        4. Validate findings quality (agent review, $0.02)
        5. Generate report
        6. Validate report structure (static checks)
        7. Optional: Re-analyze if critical gaps found

        Args:
            skill_name: Skill identifier (iam, exposure, network, vulns)
            collector_class: Collector class to instantiate
            analyzer_class: Analyzer class to instantiate
            checklist_path: Path to checklist.json

        Returns:
            dict: {
                "skill": str,
                "evidence": dict,
                "findings": list,
                "report": str,
                "validation": {
                    "coverage": dict,      # checklist coverage
                    "quality": dict,       # agent review
                    "report": dict,        # report validation
                    "status": "PASS" | "FAIL" | "NEEDS_REVIEW"
                }
            }
        """

        logger.info(f"Starting {skill_name} skill audit")

        try:
            # Phase 1: Collect evidence
            logger.info(f"Collecting evidence for {skill_name}...")
            collector = collector_class(self.config.aws_credentials)
            evidence = collector.collect()

            # Phase 2: Load checklist
            logger.info(f"Loading checklist for {skill_name}...")
            with open(checklist_path) as f:
                checklist = json.load(f)

            # Phase 3: Analyze with agent
            logger.info(f"Analyzing evidence for {skill_name}...")
            analyzer = analyzer_class(self.config.anthropic_client)
            findings = analyzer.analyze(evidence, checklist)

            # Phase 4a: Validate checklist coverage (PROGRAMMATIC - FREE)
            logger.info(f"Validating checklist coverage for {skill_name}...")
            coverage_validation = validate_checklist_coverage(checklist, findings)
            logger.info(
                f"Coverage: {coverage_validation['coverage_percentage']:.1f}% "
                f"({coverage_validation['evaluated_checks']}/{coverage_validation['total_checks']})"
            )

            # Phase 4b: Validate findings quality (AGENT REVIEW - $0.02)
            logger.info(f"Validating findings quality for {skill_name}...")
            reviewer = FindingsReviewer(self.config.anthropic_client)
            quality_validation = reviewer.validate(
                skill=skill_name,
                evidence=evidence.data if hasattr(evidence, 'data') else evidence,
                checklist=checklist,
                findings=findings,
            )
            logger.info(
                f"Quality review: {quality_validation['validation_status']} "
                f"(confidence: {quality_validation['confidence_score']:.2f})"
            )

            # Phase 5: Handle validation failures (optional re-analysis)
            if quality_validation["validation_status"] == "FAIL":
                if coverage_validation["missing_checks"]:
                    logger.warning(
                        f"Re-analyzing {len(coverage_validation['missing_checks'])} "
                        f"missing checks for {skill_name}..."
                    )
                    # Get only unevaluated checks
                    from drystone.validation.checklist_coverage import (
                        get_unevaluated_checks
                    )
                    unevaluated = get_unevaluated_checks(checklist, findings)

                    # Re-analyze focused on missing checks
                    focused_findings = analyzer.analyze(
                        evidence,
                        {"items": unevaluated},
                    )

                    # Merge with original findings
                    findings.extend(focused_findings)
                    logger.info(f"Added {len(focused_findings)} findings from re-analysis")

            # Phase 6: Generate report
            logger.info(f"Generating report for {skill_name}...")
            report = self._generate_report(skill_name, findings, checklist)

            # Phase 7: Validate report structure
            logger.info(f"Validating report for {skill_name}...")
            report_validation = validate_report_completeness(report, findings)
            logger.info(
                f"Report validation: "
                f"{'✅ PASS' if report_validation['report_valid'] else '⚠️ FAIL'}"
            )

            # Compile overall validation status
            overall_status = self._determine_validation_status(
                coverage_validation,
                quality_validation,
                report_validation,
            )

            result = {
                "skill": skill_name,
                "evidence": evidence.data if hasattr(evidence, 'data') else evidence,
                "findings": findings,
                "report": report,
                "validation": {
                    "coverage": coverage_validation,
                    "quality": quality_validation,
                    "report": report_validation,
                    "status": overall_status,
                },
                "timestamp": datetime.now().isoformat(),
            }

            self.results[skill_name] = result
            logger.info(f"✅ {skill_name} audit complete (status: {overall_status})")

            return result

        except Exception as e:
            logger.error(f"❌ Error auditing {skill_name}: {e}")
            raise

    def _generate_report(
        self,
        skill: str,
        findings: List[Dict[str, Any]],
        checklist: Dict[str, Any],
    ) -> str:
        """Generate markdown report for a skill.

        Args:
            skill: Skill name
            findings: List of findings
            checklist: Checklist for reference

        Returns:
            str: Markdown report
        """

        report_lines = [
            f"# {skill.upper()} Security Audit Report",
            "",
            "## Executive Summary",
            f"This audit evaluated {len(checklist.get('items', []))} security checks.",
            f"Found {len(findings)} security findings.",
            "",
            "## Findings",
        ]

        if not findings:
            report_lines.append("✅ No findings detected.")
        else:
            for finding in findings:
                report_lines.extend([
                    f"\n### {finding.get('id', 'UNKNOWN')}: {finding.get('title', 'Untitled')}",
                    f"**Severity:** {finding.get('severity', 'Unknown')}",
                    f"**Risk Score:** {finding.get('risk_score', 'N/A')}",
                    "",
                    f"{finding.get('description', '')}",
                ])

        report_lines.extend([
            "",
            "## Remediation",
            "Recommended remediation steps for each finding:",
            "",
        ])

        for finding in findings:
            report_lines.append(
                f"- **{finding.get('id')}:** {finding.get('remediation', 'N/A')}"
            )

        return "\n".join(report_lines)

    def _determine_validation_status(
        self,
        coverage: Dict[str, Any],
        quality: Dict[str, Any],
        report: Dict[str, Any],
    ) -> str:
        """Determine overall validation status.

        Status levels:
        - PASS: All validations pass
        - NEEDS_REVIEW: Minor issues found
        - FAIL: Critical issues found

        Args:
            coverage: Coverage validation result
            quality: Quality validation result
            report: Report validation result

        Returns:
            str: "PASS", "NEEDS_REVIEW", or "FAIL"
        """

        # FAIL if coverage < 100% or quality FAIL
        if not coverage["coverage_valid"] or quality["validation_status"] == "FAIL":
            return "FAIL"

        # FAIL if report validation fails
        if not report["report_valid"]:
            return "FAIL"

        # NEEDS_REVIEW if quality is NEEDS_REVIEW
        if quality["validation_status"] == "NEEDS_REVIEW":
            return "NEEDS_REVIEW"

        # PASS otherwise
        return "PASS"

    def _run_skill_audit_thread_safe(
        self,
        skill: Dict[str, Any],
    ) -> Tuple[str, Dict[str, Any]]:
        """Thread-safe wrapper for run_skill_audit.

        Can be safely called from multiple threads concurrently.
        Handles result storage with lock protection.

        Args:
            skill: Skill config dict with name, collector, analyzer, checklist_path

        Returns:
            Tuple of (skill_name, result_dict)

        Raises:
            Exception: Any exception from run_skill_audit (caller handles)
        """
        skill_name = skill["name"]
        logger.debug(f"[Thread-{threading.current_thread().name}] Starting {skill_name}")

        try:
            # Run the actual audit (thread-safe AWS API calls)
            result = self.run_skill_audit(
                skill_name=skill_name,
                collector_class=skill["collector"],
                analyzer_class=skill["analyzer"],
                checklist_path=skill["checklist_path"],
            )

            # Store result with lock protection
            with self.results_lock:
                self.results[skill_name] = result

            logger.debug(f"[Thread-{threading.current_thread().name}] Completed {skill_name}")
            return skill_name, result

        except Exception as e:
            logger.error(f"[Thread-{threading.current_thread().name}] Error in {skill_name}: {e}")
            raise

    def run_full_audit(
        self,
        skills: List[Dict[str, Any]],
        max_workers: Optional[int] = None,
        metrics_file: Optional[Path] = None,
        logs_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Run full audit across multiple skills IN PARALLEL.

        Uses ThreadPoolExecutor to run skill audits concurrently.
        If one skill fails, others continue (error resilience).

        Args:
            skills: List of skill configs with collector, analyzer, checklist_path
            max_workers: Number of parallel workers (default: number of skills)
            metrics_file: Optional path to metrics JSON file (for tracking)
            logs_dir: Optional directory for audit logs

        Returns:
            dict: {
                "audit_id": str,
                "status": "PASS" | "NEEDS_REVIEW" | "FAIL",
                "timestamp": str,
                "skills": {skill_name: result} for each skill,
                "summary": {
                    "total_skills": int,
                    "passed_skills": int,
                    "review_skills": int,
                    "failed_skills": int,
                    "total_findings": int,
                }
            }
        """

        if not skills:
            logger.warning("No skills to audit")
            return self._create_empty_audit_result()

        # Determine parallelism (default: all skills in parallel)
        max_workers = max_workers or len(skills)
        logger.info(
            f"Starting parallel audit: {len(skills)} skills, {max_workers} workers"
        )

        # Initialize metrics tracker (for concurrent execution monitoring)
        metrics_tracker = None
        if metrics_file:
            metrics_tracker = MetricsTracker(metrics_file)

        # Initialize progress tracker
        tracker = SkillProgressTracker(len(skills))
        tracker.start()

        # PARALLEL EXECUTION with ThreadPoolExecutor
        failed = []
        skill_durations = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all skill audit tasks with start time
            futures = {}
            start_times = {}

            for skill in skills:
                skill_name = skill["name"]
                start_times[skill_name] = datetime.now()

                # Record skill start in metrics
                if metrics_tracker:
                    metrics_tracker.record_skill_start(skill_name)

                futures[
                    executor.submit(self._run_skill_audit_thread_safe, skill)
                ] = skill_name

            # Collect results as they complete (order independent)
            for future in as_completed(futures):
                skill_name = futures[future]
                try:
                    result_name, result = future.result()
                    status = result["validation"]["status"]

                    # Calculate duration
                    duration = (datetime.now() - start_times[skill_name]).total_seconds()
                    skill_durations[skill_name] = duration

                    # Record metrics on completion
                    if metrics_tracker:
                        findings_count = len(result.get("findings", []))
                        risk_score = result.get("findings", [{}])[0].get("risk_score", 0.0) if result.get("findings") else 0.0
                        metrics_tracker.record_skill_findings(skill_name, findings_count, risk_score)
                        metrics_tracker.record_skill_complete(skill_name, status == "PASS")

                    # Record in progress tracker
                    tracker.record_completion(skill_name, status, duration)

                except Exception as e:
                    # Calculate duration even on error
                    duration = (datetime.now() - start_times[skill_name]).total_seconds()
                    skill_durations[skill_name] = duration

                    # Record failure in metrics
                    if metrics_tracker:
                        metrics_tracker.record_skill_complete(skill_name, False)

                    failed.append((skill_name, str(e)))
                    tracker.record_completion(skill_name, "FAIL", duration)
                    # Continue with other skills (error resilience)

        # Log summary of failures
        if failed:
            logger.warning(f"⚠️  {len(failed)} skill(s) failed during audit:")
            for skill_name, error in failed:
                logger.warning(f"   - {skill_name}: {error}")

        # Log progress summary
        logger.info(tracker.summary())

        # Log metrics summary if tracking was enabled
        if metrics_tracker:
            metrics_summary = metrics_tracker.get_summary()
            logger.info(
                f"📊 Metrics Summary: {metrics_summary['completion_rate']} skills completed, "
                f"{metrics_summary['total_findings']} total findings, "
                f"{metrics_summary['validation_failures']} validation failures, "
                f"elapsed time: {metrics_summary['elapsed_time']}"
            )

        # Compute summary statistics
        statuses = [r["validation"]["status"] for r in self.results.values()]
        total_findings = sum(
            len(r["findings"]) for r in self.results.values()
        )

        summary = {
            "total_skills": len(self.results),
            "passed_skills": statuses.count("PASS"),
            "review_skills": statuses.count("NEEDS_REVIEW"),
            "failed_skills": statuses.count("FAIL"),
            "total_findings": total_findings,
        }

        # Overall status
        if summary["failed_skills"] > 0:
            overall_status = "FAIL"
        elif summary["review_skills"] > 0:
            overall_status = "NEEDS_REVIEW"
        else:
            overall_status = "PASS"

        logger.info(
            f"✅ Parallel audit complete: "
            f"{summary['passed_skills']} passed, "
            f"{summary['review_skills']} review, "
            f"{summary['failed_skills']} failed"
        )

        return {
            "audit_id": self.audit_id,
            "status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "skills": self.results,
            "summary": summary,
            "metrics": metrics_tracker.get_metrics() if metrics_tracker else None,
        }

    def _create_empty_audit_result(self) -> Dict[str, Any]:
        """Create empty audit result when no skills provided."""
        return {
            "audit_id": self.audit_id,
            "status": "PASS",
            "timestamp": datetime.now().isoformat(),
            "skills": {},
            "summary": {
                "total_skills": 0,
                "passed_skills": 0,
                "review_skills": 0,
                "failed_skills": 0,
                "total_findings": 0,
            },
        }

    def save_results(self, output_dir: Path) -> None:
        """Save audit results to disk.

        Args:
            output_dir: Directory to save results
        """

        output_dir = Path(output_dir) / self.audit_id
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save individual skill results
        for skill_name, result in self.results.items():
            skill_dir = output_dir / skill_name

            # Save evidence
            evidence_dir = skill_dir / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            with open(evidence_dir / "raw.json", "w") as f:
                json.dump(result["evidence"], f, indent=2, default=str)

            # Save findings
            findings_dir = skill_dir / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            with open(findings_dir / "findings.json", "w") as f:
                json.dump(result["findings"], f, indent=2, default=str)

            # Save validation results
            with open(findings_dir / "validation.json", "w") as f:
                json.dump(result["validation"], f, indent=2, default=str)

            # Save report
            report_dir = skill_dir / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            with open(report_dir / f"{skill_name}_report.md", "w") as f:
                f.write(result["report"])

        logger.info(f"Audit results saved to {output_dir}")
