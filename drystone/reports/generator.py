"""Report generator orchestrator."""

import json
from pathlib import Path
from typing import Dict, List

from drystone.storage.session import AuditSession
from drystone.reports.formats import (
    MarkdownFormatter,
    JSONFormatter,
)


class ReportGenerator:
    """Orchestrates report generation in multiple formats."""

    # Map format names to formatter classes
    FORMATTERS = {
        "markdown": MarkdownFormatter,
        "json": JSONFormatter,
    }

    def __init__(self, session: AuditSession):
        """Initialize report generator.

        Args:
            session: Audit session for file paths and metadata
        """
        self.session = session

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
            raise ValueError(
                f"Invalid findings JSON: {e}\n"
                f"File: {findings_path}"
            )

        # Generate reports
        generated_reports = {}

        for format_name in formats:
            if format_name not in self.FORMATTERS:
                raise ValueError(
                    f"Unknown format: {format_name}\n"
                    f"Available: {', '.join(self.FORMATTERS.keys())}"
                )

            formatter_class = self.FORMATTERS[format_name]

            try:
                formatter = formatter_class(findings_data, self.session)
                report_path = formatter.generate()
                generated_reports[format_name] = report_path
            except Exception as e:
                raise RuntimeError(
                    f"Failed to generate {format_name} report: {e}"
                )

        return generated_reports
