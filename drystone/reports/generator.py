"""Report generator orchestrator."""

import json
from pathlib import Path
from typing import Dict, List

from drystone.models.config import WizardConfig
from drystone.reports.formats import (
    JSONFormatter,
    MarkdownFormatter,
    PCIDSSFormatter,
    PDFFormatter,
    PentestFormatter,
    PentestPDFFormatter,
)
from drystone.pentest.exploitation_enricher import PentestExploitationEnricher
from drystone.storage.session import AuditSession
from drystone.validation.cross_skill_dedup import deduplicate_cross_skill


class ReportGenerator:
    """Orchestrates report generation in multiple formats."""

    # Map format names to formatter classes
    FORMATTERS = {
        "markdown": MarkdownFormatter,
        "json": JSONFormatter,
        "pdf": PDFFormatter,
    }

    def __init__(self, session: AuditSession, config: WizardConfig):
        """Initialize report generator.

        Args:
            session: Audit session for file paths and metadata
            config: WizardConfig object with settings like min_severity
        """
        self.session = session
        self.config = config

    def generate_reports(self, skill: str, formats: List[str]) -> Dict[str, Path]:
        """Generate reports in requested formats.

        Args:
            skill: Skill name (e.g., 'iam')
            formats: List of format names ('markdown', 'html', 'json')

        Returns:
            Dictionary mapping format names to generated report paths

        Raises:
            FileNotFoundError: If findings file not found
            ValueError: If findings JSON is invalid
        """
        # Load findings JSON
        findings_path = self.session.get_findings_path() / f"{skill}.json"

        if not findings_path.exists():
            raise FileNotFoundError(
                f"Findings file not found: {findings_path}\n"
                f"Run analysis first to generate findings."
            )

        try:
            with open(findings_path) as f:
                findings_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid findings JSON: {e}\nFile: {findings_path}")

        # Enforce skill metadata consistency in per-skill files.
        expected_skill = str(skill)
        actual_skill = str(findings_data.get("skill") or "")
        if actual_skill.lower() == "aggregated" or not actual_skill:
            findings_data["skill"] = expected_skill
        if not findings_data.get("evidence_count"):
            evidence_dir = self.session.get_evidence_path(expected_skill)
            if isinstance(evidence_dir, Path) and evidence_dir.exists():
                findings_data["evidence_count"] = len(list(evidence_dir.glob("*.json")))
        # Always read the canonical version from the checklist file — never rely on
        # the LLM/repair-pass value which may be stale or hardcoded to "1.0".
        checklist_path = (
            Path(__file__).parents[1] / "skills" / expected_skill / "checklist.json"
        )
        try:
            with open(checklist_path) as cf:
                canonical_version = str((json.load(cf) or {}).get("version") or "1.0")
            findings_data["checklist_version"] = canonical_version
        except Exception:
            if not findings_data.get("checklist_version") or findings_data.get(
                "checklist_version"
            ) in {"N/A", "1.0"}:
                findings_data["checklist_version"] = "1.0"

        # Post-process alerting skill to add architecture diagram
        if skill == "alerting":
            from drystone.skills.alerting.post_processor import AlertingPostProcessor

            processor = AlertingPostProcessor(self.session)
            findings_data = processor.process(findings_data)

            # Persist derived architecture context so reports and findings stay consistent.
            try:
                with open(findings_path, "w") as f:
                    json.dump(findings_data, f, indent=2, default=str)
            except Exception:
                # Best-effort only; report generation should not fail due to persistence.
                pass

        # Post-process WAF skill to add protection flow diagram
        if skill == "waf":
            from drystone.skills.waf.post_processor import WAFPostProcessor

            processor = WAFPostProcessor(self.session)
            findings_data = processor.process(findings_data)

            # Persist derived architecture context so reports and findings stay consistent.
            try:
                with open(findings_path, "w") as f:
                    json.dump(findings_data, f, indent=2, default=str)
            except Exception:
                # Best-effort only; report generation should not fail due to persistence.
                pass

        # Post-process network skill to add topology diagram
        if skill == "network":
            from drystone.skills.network.post_processor import NetworkPostProcessor

            processor = NetworkPostProcessor(self.session)
            findings_data = processor.process(findings_data)

            # Persist derived architecture context so reports and findings stay consistent.
            try:
                with open(findings_path, "w") as f:
                    json.dump(findings_data, f, indent=2, default=str)
            except Exception:
                pass

        # Filter findings by severity.
        # IMPORTANT: For PCI DSS reports, do NOT filter by severity.
        # Compliance should consider all executed controls regardless of severity threshold,
        # otherwise controls may incorrectly appear OK.
        if self.config.report_type == "pci-dss":
            filtered_findings_data = findings_data
        else:
            filtered_findings_data = self._filter_findings_by_severity(findings_data)

        # Generate reports
        generated_reports = {}

        # Inject report context (without mutating original source semantics)
        report_context = dict(filtered_findings_data)
        if self.config.report_type == "pentest":
            enricher = PentestExploitationEnricher(
                session_base_path=self.session.base_path,
                region=str(getattr(self.config, "aws_region", "us-east-1")),
                account_id=str(getattr(self.session, "account_id", "<account-id>")),
            )
            report_context = enricher.enrich(report_context)
        report_metadata = dict(report_context.get("report_metadata") or {})
        report_metadata["report_skill"] = skill
        report_context["report_metadata"] = report_metadata

        for format_name in formats:
            if self.config.report_type == "pci-dss" and format_name == "markdown":
                formatter_class = PCIDSSFormatter
            elif self.config.report_type == "pentest" and format_name == "markdown":
                formatter_class = PentestFormatter
            elif self.config.report_type == "pentest" and format_name == "pdf":
                formatter_class = PentestPDFFormatter
            elif format_name in self.FORMATTERS:
                formatter_class = self.FORMATTERS[format_name]
            else:
                raise ValueError(
                    f"Unknown format: {format_name}\nAvailable: {', '.join(self.FORMATTERS.keys())}"
                )

            try:
                # Pass config to the formatter
                formatter = formatter_class(report_context, self.session, self.config)
                report_path = formatter.generate()
                generated_reports[format_name] = report_path
            except Exception as e:
                raise RuntimeError(f"Failed to generate {format_name} report: {e}")

        return generated_reports

    def generate_consolidated_reports(self, formats: List[str]) -> Dict[str, Path]:
        """Generate a consolidated report across all skills.

        Intended primarily for pentest report_type, where cross-skill attack chains
        are the main output.
        """

        findings_data = self._load_and_merge_all_findings()

        # Cross-skill dedup: remove duplicate findings covering the same resources
        raw_findings = findings_data.get("findings", [])
        deduped = deduplicate_cross_skill(raw_findings)
        if len(deduped) != len(raw_findings):
            findings_data["findings"] = deduped
            # Recalculate summary counts
            findings_data["summary"]["total_findings"] = len(deduped)
            for sev in ("critical", "high", "medium", "low"):
                sev_cap = sev.capitalize()
                findings_data["summary"][sev] = sum(
                    1 for f in deduped if f.get("severity") == sev_cap
                )

        # Apply the same severity filtering rules (PCI DSS excluded)
        if self.config.report_type == "pci-dss":
            filtered_findings_data = findings_data
        else:
            filtered_findings_data = self._filter_findings_by_severity(findings_data)

        generated_reports: Dict[str, Path] = {}
        report_context = dict(filtered_findings_data)
        if self.config.report_type == "pentest":
            enricher = PentestExploitationEnricher(
                session_base_path=self.session.base_path,
                region=str(getattr(self.config, "aws_region", "us-east-1")),
                account_id=str(getattr(self.session, "account_id", "<account-id>")),
            )
            report_context = enricher.enrich(report_context)
        report_metadata = dict(report_context.get("report_metadata") or {})
        report_metadata["report_skill"] = "aggregated"
        report_context["report_metadata"] = report_metadata
        for format_name in formats:
            if self.config.report_type == "pci-dss" and format_name == "markdown":
                formatter_class = PCIDSSFormatter
            elif self.config.report_type == "pentest" and format_name == "markdown":
                formatter_class = PentestFormatter
            elif self.config.report_type == "pentest" and format_name == "pdf":
                formatter_class = PentestPDFFormatter
            elif format_name in self.FORMATTERS:
                formatter_class = self.FORMATTERS[format_name]
            else:
                raise ValueError(
                    f"Unknown format: {format_name}\nAvailable: {', '.join(self.FORMATTERS.keys())}"
                )

            formatter = formatter_class(report_context, self.session, self.config)
            report_path = formatter.generate()
            generated_reports[format_name] = report_path

        return generated_reports

    def _load_and_merge_all_findings(self) -> Dict:
        """Merge findings/*.json into a single findings object."""

        findings_dir = self.session.get_findings_path()
        if not findings_dir.exists():
            raise FileNotFoundError(f"Findings directory not found: {findings_dir}")

        skill_files = sorted(
            [p for p in findings_dir.glob("*.json") if p.name != "correlated.json"],
            key=lambda p: p.name,
        )
        if not skill_files:
            raise FileNotFoundError(
                f"No findings JSON files found in: {findings_dir} (expected <skill>.json)"
            )

        merged_findings: List[Dict] = []
        skills_included: List[str] = []

        for fp in skill_files:
            try:
                with open(fp) as f:
                    data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid findings JSON: {e}\nFile: {fp}")

            raw_skill_name = str(data.get("skill") or fp.stem)
            skill_name = fp.stem if raw_skill_name.lower() == "aggregated" else raw_skill_name
            skills_included.append(skill_name)
            for finding in data.get("findings", []) or []:
                if isinstance(finding, dict):
                    # Track skill provenance for consolidated remediation.
                    finding.setdefault("skill", skill_name)
                    merged_findings.append(finding)

        summary: Dict[str, object] = {
            "total_findings": len(merged_findings),
            "critical": sum(1 for f in merged_findings if f.get("severity") == "Critical"),
            "high": sum(1 for f in merged_findings if f.get("severity") == "High"),
            "medium": sum(1 for f in merged_findings if f.get("severity") == "Medium"),
            "low": sum(1 for f in merged_findings if f.get("severity") == "Low"),
        }

        weights = {"Critical": 3.0, "High": 2.0, "Medium": 1.0, "Low": 0.5}
        weighted_sum = 0.0
        total_weight = 0.0
        for f in merged_findings:
            sev = f.get("severity")
            rs = f.get("risk_score")
            if sev in weights and rs is not None:
                weighted_sum += float(rs) * weights[sev]
                total_weight += weights[sev]
        summary["overall_risk_score"] = (
            round(weighted_sum / total_weight, 1) if total_weight else 0.0
        )

        return {
            "skill": "aggregated",
            "skills_included": sorted(set(skills_included)),
            "summary": summary,
            "findings": merged_findings,
        }

    def _filter_findings_by_severity(self, findings_data: Dict) -> Dict:
        """Filter findings based on the min_severity setting and recalculate summary."""
        min_severity = self.config.min_severity
        if not min_severity or min_severity == "low":
            return findings_data  # No filtering needed

        severity_levels = ["low", "medium", "high", "critical"]
        try:
            min_index = severity_levels.index(min_severity)
        except ValueError:
            return findings_data  # Invalid severity, do no filtering

        # Severities to include in the report
        allowed_severities = set(severity_levels[min_index:])

        original_findings = findings_data.get("findings", [])

        # Filter the findings
        filtered_findings = [
            f for f in original_findings if f.get("severity", "low").lower() in allowed_severities
        ]

        # Create a new data object with filtered findings
        new_data = findings_data.copy()
        new_data["findings"] = filtered_findings

        raw_total = len(original_findings)
        filtered_total = len(filtered_findings)
        filtered_out = max(0, raw_total - filtered_total)
        report_metadata = dict(new_data.get("report_metadata") or {})
        report_metadata.update(
            {
                "min_severity": min_severity,
                "raw_total_findings": raw_total,
                "filtered_out_findings": filtered_out,
            }
        )
        new_data["report_metadata"] = report_metadata

        # Recalculate the summary
        summary: Dict[str, object] = {
            "total_findings": len(filtered_findings),
            "critical": sum(1 for f in filtered_findings if f.get("severity") == "Critical"),
            "high": sum(1 for f in filtered_findings if f.get("severity") == "High"),
            "medium": sum(1 for f in filtered_findings if f.get("severity") == "Medium"),
            "low": sum(1 for f in filtered_findings if f.get("severity") == "Low"),
        }

        # Recalculate overall risk score using the same weighted approach as FindingsNormalizer.
        weights = {
            "Critical": 3.0,
            "High": 2.0,
            "Medium": 1.0,
            "Low": 0.5,
        }
        weighted_sum = 0.0
        total_weight = 0.0
        for f in filtered_findings:
            sev = f.get("severity")
            rs = f.get("risk_score")
            if sev in weights and rs is not None:
                weighted_sum += float(rs) * weights[sev]
                total_weight += weights[sev]
        summary["overall_risk_score"] = (
            round(weighted_sum / total_weight, 1) if total_weight else 0.0
        )

        new_data["summary"] = summary

        return new_data
