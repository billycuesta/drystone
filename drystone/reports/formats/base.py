"""Base formatter for report generation."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict

from drystone.models.config import WizardConfig
from drystone.storage.session import AuditSession


class BaseFormatter(ABC):
    """Abstract base class for report formatters."""

    def __init__(self, findings_data: Dict[str, Any], session: AuditSession, config: WizardConfig):
        """Initialize formatter.

        Args:
            findings_data: Parsed findings JSON (SkillFindings dict)
            session: Audit session for file paths
            config: Audit configuration object
        """
        self.findings = findings_data
        self.session = session
        self.config = config
        self.reports_path = session.get_reports_path()
        self.reports_path.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def generate(self) -> Path:
        """Generate report in specific format.

        Returns:
            Path to generated report file
        """
        pass

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension for this format (e.g., 'html', 'md')."""
        pass

    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        return {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
        }.get(severity, "⚪")

    def _report_skill_slug(self) -> str:
        """Return a filename-safe slug for the skill being reported.

        Used to build report filenames like audit-report-network.md.
        Falls back to 'unknown' if skill metadata is missing.
        """
        skill = str(self.findings.get("skill") or "unknown")
        return skill.lower().replace(" ", "-")

    def _format_risk_score(self, score: float) -> str:
        """Format risk score with color indicator."""
        # Align with FindingsNormalizer.SEVERITY_RANGES.
        if score >= 8.5:
            return f"🔴 {score:.1f}/10 (Critical)"
        elif score >= 6.0:
            return f"🟠 {score:.1f}/10 (High)"
        elif score >= 3.0:
            return f"🟡 {score:.1f}/10 (Medium)"
        else:
            return f"🟢 {score:.1f}/10 (Low)"
