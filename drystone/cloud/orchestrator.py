"""Orchestrator for audit workflow with validation integration.

Coordinates the full audit flow:
1. Collect evidence from AWS
2. Analyze with Claude agent
3. Validate results (NEW - hybrid validation)
4. Generate reports
5. Save session data

Key principle: App orchestrates, agent analyzes, validator reviews.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from drystone.models.config import WizardConfig
from drystone.validation import (
    validate_checklist_coverage,
    FindingsReviewer,
    validate_report_completeness,
)

logger = logging.getLogger(__name__)


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
        2. Analyze with Claude agent
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

    def run_full_audit(
        self,
        skills: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Run full audit across multiple skills.

        Args:
            skills: List of skill configs with collector, analyzer, checklist_path

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

        logger.info("Starting full audit across all skills")

        for skill in skills:
            self.run_skill_audit(
                skill_name=skill["name"],
                collector_class=skill["collector"],
                analyzer_class=skill["analyzer"],
                checklist_path=skill["checklist_path"],
            )

        # Compute summary
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

        return {
            "audit_id": self.audit_id,
            "status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "skills": self.results,
            "summary": summary,
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
