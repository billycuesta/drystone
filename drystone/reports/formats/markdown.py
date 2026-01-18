"""Markdown report formatter."""

from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from drystone.reports.formats.base import BaseFormatter


class MarkdownFormatter(BaseFormatter):
    """Formats findings as a Markdown report."""

    @property
    def file_extension(self) -> str:
        """File extension for Markdown."""
        return "md"

    def generate(self) -> Path:
        """Generate Markdown report.

        Returns:
            Path to generated markdown file
        """
        markdown_content = self._build_markdown()
        report_path = self.reports_path / f"audit-report.{self.file_extension}"

        with open(report_path, "w") as f:
            f.write(markdown_content)

        return report_path

    def _build_markdown(self) -> str:
        """Build complete markdown report."""
        parts = [
            self._header(),
            self._executive_summary(),
            self._findings_by_severity(),
            self._remediation_guide(),
            self._footer(),
        ]
        return "\n\n".join(parts)

    def _header(self) -> str:
        """Generate report header."""
        skill = self.findings.get("skill", "Unknown")
        timestamp = self.findings.get("analyzed_at", datetime.utcnow().isoformat())
        account_id = self.session.account_id
        client_name = self.session.client_name

        return f"""# 🪨 Drystone Security Audit Report

**Client:** {client_name}
**Skill:** {skill.upper()}
**AWS Account:** {account_id}
**Generated:** {timestamp}
**Version:** {self.findings.get('checklist_version', '1.0')}

---

## 📋 Quick Summary

This report presents security findings from the {skill.upper()} security assessment.
"""

    def _executive_summary(self) -> str:
        """Generate executive summary section."""
        summary = self.findings.get("summary", {})

        total = summary.get("total_findings", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        risk_score = summary.get("overall_risk_score", 0)

        risk_label = self._get_risk_level(risk_score)

        return f"""## 📊 Executive Summary

### Risk Overview

| Metric | Value |
|--------|-------|
| **Overall Risk Score** | {risk_score:.1f}/10 {risk_label} |
| **Total Findings** | {total} |
| **Critical** | 🔴 {critical} |
| **High** | 🟠 {high} |
| **Medium** | 🟡 {medium} |
| **Low** | 🟢 {low} |
| **Evidence Analyzed** | {self.findings.get('evidence_count', 0)} files |

### Risk Assessment

Based on the {total} findings identified, the overall security posture is assessed at **{risk_score:.1f}/10**.
"""

    def _findings_by_severity(self) -> str:
        """Generate findings grouped by severity."""
        findings = self.findings.get("findings", [])

        if not findings:
            return "## 🔍 Findings\n\nNo findings detected."

        # Group by severity
        severity_order = ["Critical", "High", "Medium", "Low"]
        grouped = {sev: [] for sev in severity_order}

        for finding in findings:
            severity = finding.get("severity", "Low")
            grouped.get(severity, []).append(finding)

        sections = []
        for severity in severity_order:
            sev_findings = grouped[severity]
            if sev_findings:
                sections.append(self._severity_section(severity, sev_findings))

        return "\n\n".join(sections)

    def _severity_section(self, severity: str, findings: List[Dict[str, Any]]) -> str:
        """Generate section for findings of a specific severity."""
        emoji = self._get_severity_emoji(severity)
        count = len(findings)

        section = f"## {emoji} {severity.capitalize()} Severity ({count})\n\n"

        for finding in findings:
            section += self._finding_detail(finding)
            section += "\n"

        return section.strip()

    def _finding_detail(self, finding: Dict[str, Any]) -> str:
        """Format a single finding."""
        finding_id = finding.get("id", "N/A")
        title = finding.get("title", "Unknown")
        description = finding.get("description", "")
        risk_score = finding.get("risk_score", 0)
        remediation = finding.get("remediation", "")
        affected = finding.get("affected_resources", [])
        cis_ref = finding.get("cis_reference")

        detail = f"""### [{finding_id}] {title}

**Risk Score:** {self._format_risk_score(risk_score)}

**Description:**
{description}
"""

        if affected:
            detail += f"\n**Affected Resources:**\n"
            for resource in affected[:5]:  # Limit to 5
                detail += f"- `{resource}`\n"
            if len(affected) > 5:
                detail += f"- ... and {len(affected) - 5} more\n"

        detail += f"\n**Remediation:**  \n{remediation}\n"

        if cis_ref:
            detail += f"\n**CIS Reference:** {cis_ref}\n"

        return detail

    def _remediation_guide(self) -> str:
        """Generate remediation priority guide."""
        findings = self.findings.get("findings", [])

        # Group by severity for remediation priority
        critical = [f for f in findings if f.get("severity") == "Critical"]
        high = [f for f in findings if f.get("severity") == "High"]

        guide = "## 🔧 Remediation Priority\n\n"
        guide += "### 1. Address Critical Issues First\n\n"

        if critical:
            for f in critical[:3]:
                finding_id = f.get("id", "N/A")
                title = f.get("title", "")
                guide += f"- **[{finding_id}]** {title}\n"
            if len(critical) > 3:
                guide += f"- ... and {len(critical) - 3} more critical issues\n"
        else:
            guide += "- ✅ No critical issues identified\n"

        guide += "\n### 2. Then Address High-Severity Issues\n\n"

        if high:
            for f in high[:3]:
                finding_id = f.get("id", "N/A")
                title = f.get("title", "")
                guide += f"- **[{finding_id}]** {title}\n"
            if len(high) > 3:
                guide += f"- ... and {len(high) - 3} more high-severity issues\n"
        else:
            guide += "- ✅ No high-severity issues identified\n"

        guide += "\n### 3. Monitor Medium and Low Issues\n\n"
        guide += "- Schedule remediation based on operational impact\n"
        guide += "- Review with security team quarterly\n"

        return guide

    def _footer(self) -> str:
        """Generate report footer."""
        return """---

## 📝 Notes

- This report contains sensitive security information. Handle with care.
- Recommendations are based on AWS security best practices and CIS Benchmarks.
- For questions or clarifications, contact your security team.

---

**Generated by Drystone** 🪨
AWS Security Audit CLI powered by Claude
"""

    def _get_risk_level(self, score: float) -> str:
        """Get risk level emoji and label."""
        if score >= 9.0:
            return "🔴 **CRITICAL**"
        elif score >= 7.0:
            return "🟠 **HIGH**"
        elif score >= 4.0:
            return "🟡 **MEDIUM**"
        else:
            return "🟢 **LOW**"
