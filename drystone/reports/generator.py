"""Report generator orchestrator."""

import json
from pathlib import Path
from typing import Dict, List

from drystone.storage.session import AuditSession
from drystone.reports.formats import (
    MarkdownFormatter,
    JSONFormatter,
    PCIDSSFormatter,
)
from drystone.models.config import WizardConfig


class ReportGenerator:
    """Orchestrates report generation in multiple formats."""

    # Map format names to formatter classes
    FORMATTERS = {
        "markdown": MarkdownFormatter,
        "json": JSONFormatter,
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

        for format_name in formats:
            if self.config.report_type == "pci-dss" and format_name == "markdown":
                formatter_class = PCIDSSFormatter
            elif format_name in self.FORMATTERS:
                formatter_class = self.FORMATTERS[format_name]
            else:
                raise ValueError(
                    f"Unknown format: {format_name}\nAvailable: {', '.join(self.FORMATTERS.keys())}"
                )

            try:
                # Pass config to the formatter
                formatter = formatter_class(filtered_findings_data, self.session, self.config)
                report_path = formatter.generate()
                generated_reports[format_name] = report_path
            except Exception as e:
                raise RuntimeError(f"Failed to generate {format_name} report: {e}")

        return generated_reports

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
