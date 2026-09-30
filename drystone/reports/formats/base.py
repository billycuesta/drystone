"""Base formatter for report generation."""

import html
import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from drystone.models.config import WizardConfig
from drystone.reports.context import ReportContext
from drystone.storage.session import AuditSession


class BaseFormatter(ABC):
    """Abstract base class for report formatters."""

    # Schema/shape version of the report output itself (JSON/PDF/Markdown),
    # distinct from a per-skill checklist_version. Bump when the structure a
    # downstream consumer (SIEM/ticket export, trend analysis) relies on
    # changes in a way that isn't backward compatible.
    REPORT_FORMAT_VERSION = "1.0"

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
        self.report_context = ReportContext.from_findings(
            findings_data,
            session,
            report_format_version=self.REPORT_FORMAT_VERSION,
        )
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

    def _coverage_gap_rows(self) -> List[Dict[str, Any]]:
        """Return report-safe coverage gaps from ReportContext."""
        return [dict(gap) for gap in self.report_context.coverage_gaps]

    def _coverage_gaps_markdown_section(self, *, heading: str = "##") -> str:
        """Render client-facing deterministic coverage gaps, omitting empty state."""
        gaps = self._coverage_gap_rows()
        if not gaps:
            return ""

        lines = [
            f"{heading} ⚠️ Coverage Gaps / Controls Not Evaluated",
            "",
            (
                "The controls below were not evaluated deterministically because required "
                "evidence was unavailable, incomplete, unsupported, or could not be parsed. "
                "These entries are coverage gaps, not pass/fail compliance results."
            ),
            "",
            "| Check ID | Skill | Control | Reason Code | Reason |",
            "|----------|-------|---------|-------------|--------|",
        ]
        for gap in gaps:
            lines.append(
                "| {check_id} | {skill} | {title} | {reason_code} | {reason} |".format(
                    check_id=self._escape_markdown_table(str(gap.get("check_id", "N/A"))),
                    skill=self._escape_markdown_table(str(gap.get("skill", "unknown"))),
                    title=self._escape_markdown_table(str(gap.get("title", "Unknown control"))),
                    reason_code=self._escape_markdown_table(str(gap.get("reason_code", "unknown"))),
                    reason=self._escape_markdown_table(str(gap.get("reason", "Coverage gap recorded."))),
                )
            )
        return "\n".join(lines)

    def _coverage_gaps_html_section(self) -> str:
        """Render report-safe coverage gaps as HTML for PDF output."""
        gaps = self._coverage_gap_rows()
        if not gaps:
            return ""

        rows = []
        for gap in gaps:
            rows.append(
                "<tr>"
                f"<td>{html.escape(str(gap.get('check_id', 'N/A')))}</td>"
                f"<td>{html.escape(str(gap.get('skill', 'unknown')))}</td>"
                f"<td>{html.escape(str(gap.get('title', 'Unknown control')))}</td>"
                f"<td><code>{html.escape(str(gap.get('reason_code', 'unknown')))}</code></td>"
                f"<td>{html.escape(str(gap.get('reason', 'Coverage gap recorded.')))}</td>"
                "</tr>"
            )
        return (
            "<section class='section-card coverage-gaps-section'>"
            "<h2>Coverage Gaps / Controls Not Evaluated</h2>"
            "<p>The controls below were not evaluated deterministically because required "
            "evidence was unavailable, incomplete, unsupported, or could not be parsed. "
            "These entries are coverage gaps, not pass/fail compliance results.</p>"
            "<table><thead><tr><th>Check ID</th><th>Skill</th><th>Control</th>"
            "<th>Reason Code</th><th>Reason</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></section>"
        )

    @staticmethod
    def _escape_markdown_table(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ")

    # ------------------------------------------------------------------
    # PCI DSS helpers moved here so all formatters can reuse them.
    # These were previously implemented in pci_dss.py; keeping them
    # as instance helpers on BaseFormatter reduces duplication.
    # ------------------------------------------------------------------
    _REQUIREMENT_NAMES: Dict[str, str] = {
        "1": "Network Security Controls",
        "2": "Secure Configurations",
        "3": "Data Protection",
        "4": "Transmission Security",
        "5": "Malware Protection",
        "6": "Secure Development",
        "7": "Access Control",
        "8": "Identification & Authentication",
        "9": "Physical Access",
        "10": "Logging & Monitoring",
        "11": "Testing Security",
        "12": "Security Policies",
    }

    def _get_requirement_name(self, req_num: str) -> str:
        """Return PCI DSS requirement name from its number."""
        return self._REQUIREMENT_NAMES.get(req_num, f"Requirement {req_num}")

    def _get_checklist_path(self, skill: str) -> Path:
        """Get the path to a skill's checklist.json (project-root relative)."""
        return Path(__file__).parent.parent.parent / "skills" / skill / "checklist.json"

    def _build_pci_controls_map(self, findings: List[Dict], skills: List[str]) -> Dict:
        """Build a structured map of PCI DSS controls from checklists and findings.

        Returns same shape as the previous build_pci_controls_map helper used by
        the specialized PCIDSS formatter.
        """
        all_controls: Dict[str, Dict] = {}
        for skill_name in skills:
            checklist_path = self._get_checklist_path(skill_name)
            if not checklist_path.exists():
                # Fallback: resolve relative to this module file
                checklist_path = (
                    Path(__file__).parent.parent.parent / "skills" / skill_name / "checklist.json"
                )
            if not checklist_path.exists():
                continue
            try:
                with open(checklist_path) as f:
                    checklist = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            for item in checklist.get("items", []):
                for pci in item.get("pci_dss", []):
                    cid = pci.get("control")
                    if not cid:
                        continue
                    if cid not in all_controls:
                        req_num = cid.split(".")[0]
                        all_controls[cid] = {
                            "control": cid,
                            "requirement": req_num,
                            "req_name": self._get_requirement_name(req_num),
                            "reason": pci.get("reason", "Control mapping found in checklist."),
                            "checks": [],
                            "findings": [],
                            "status": "ok",
                        }
                    if item.get("id") and item.get("title"):
                        all_controls[cid]["checks"].append({"id": item["id"], "title": item["title"]})

        # Map findings to controls
        for finding in findings:
            for pci in finding.get("pci_dss") or []:
                cid = pci.get("control")
                if cid and cid in all_controls:
                    all_controls[cid]["findings"].append(finding)
                    all_controls[cid]["status"] = "ko"

        # Natural sort helper
        def _sort_key(c: Dict) -> List:
            return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", c["control"])]

        sorted_controls = sorted(all_controls.values(), key=_sort_key)
        ok = sum(1 for c in sorted_controls if c["status"] == "ok")
        ko = len(sorted_controls) - ok

        return {"controls": sorted_controls, "summary": {"total": len(sorted_controls), "ok": ok, "ko": ko}}
