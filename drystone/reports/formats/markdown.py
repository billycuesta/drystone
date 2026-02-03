"""Markdown report formatter."""

import json
import re
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
        """Build complete markdown report.

        Note: PCI DSS sections only included for PCI DSS compliance reports,
        not for general security reports.
        """
        parts = [
            self._header(),
            self._executive_summary(),
            self._architecture_diagram(),
            self._remediation_timeline(),
        ]

        # Only include PCI DSS summary for PCI compliance reports
        if self.config.report_type == "pci-dss":
            parts.append(self._pci_dss_compliance_summary())

        parts.extend([
            self._findings_by_severity(),
            self._observations(),
            self._references(),
            self._footer(),
        ])

        # Filter out empty sections
        parts = [p for p in parts if p]
        return "\n\n".join(parts)

    def _header(self) -> str:
        """Generate report header."""
        skill = self.findings.get("skill", "Unknown")
        timestamp = self.findings.get("analyzed_at", datetime.utcnow().isoformat())
        account_id = self.session.account_id
        client_name = self.session.client_name

        banner = """ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝"""

        return f"""{banner}

# AWS Security Audit Report

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
        risk_label = self._get_risk_level(risk_score).replace("*", "")

        risk_overview = "### Risk Overview\n"
        risk_overview += "┌─────────────────────────────────────────────┐\n"
        risk_overview += f"│ Overall Risk Score: {risk_score:.1f} / 10.0 ({risk_label.strip()})".ljust(45) + "│\n"
        risk_overview += f"│ Total Findings: {total}".ljust(45) + "│\n"
        risk_overview += f"│ Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}".ljust(45) + "│\n"
        risk_overview += "└─────────────────────────────────────────────┘"
        
        severity_dist = self._severity_distribution_chart()
        top_resources = self._top_affected_resources()

        return f"""## 📊 Executive Summary

{risk_overview}

{severity_dist}

{top_resources}
"""

    def _severity_distribution_chart(self) -> str:
        """Generate ASCII bar chart for severity distribution."""
        summary = self.findings.get("summary", {})
        total = summary.get("total_findings", 1)

        severities = {
            "Critical": summary.get("critical", 0),
            "High": summary.get("high", 0),
            "Medium": summary.get("medium", 0),
            "Low": summary.get("low", 0),
        }

        chart = "### Severity Distribution\n"
        for severity, count in severities.items():
            percentage = int((count / total) * 100) if total > 0 else 0
            bars = "█" * (percentage // 10) + "░" * (10 - percentage // 10)
            chart += f"{severity:<10} {bars}  {percentage}%\n"

        return chart

    def _architecture_diagram(self) -> str:
        """Render architecture diagram if present in findings.

        Returns empty string if no architecture field exists (non-alerting skills).
        """
        architecture = self.findings.get("architecture")
        if not architecture:
            return ""

        diagram = architecture.get("flow_diagram", "")
        critical_gaps = architecture.get("critical_gaps", [])

        section = "## 🏗️ Architecture Overview\n\n"
        section += "```\n"
        section += diagram
        section += "\n```\n"

        if critical_gaps:
            section += "\n### 🚨 Critical Gaps Identified\n\n"
            for gap in critical_gaps:
                section += f"- {gap}\n"

        return section

    def _remediation_timeline(self) -> str:
        """Generate prioritized remediation timeline."""
        findings = self.findings.get("findings", [])

        immediate = [f for f in findings if f.get("severity") == "Critical"]
        short_term = [f for f in findings if f.get("severity") == "High"]
        medium_term = [f for f in findings if f.get("severity") == "Medium"]

        timeline = "## 📅 Remediation Timeline (Recommended)\n\n"

        timeline += "### Immediate (0-7 days) - Critical Priority\n"
        for f in immediate[:5]:  # Limit to top 5
            timeline += f"- [ ] {f.get('id')}: {f.get('title')}\n"

        timeline += "\n### Short-term (8-30 days) - High Priority\n"
        for f in short_term[:5]:
            timeline += f"- [ ] {f.get('id')}: {f.get('title')}\n"

        timeline += "\n### Medium-term (31-90 days) - Medium Priority\n"
        for f in medium_term[:3]:
            timeline += f"- [ ] {f.get('id')}: {f.get('title')}\n"

        return timeline

    def _top_affected_resources(self) -> str:
        """Show top 5 resources with most findings."""
        findings = self.findings.get("findings", [])

        # Count findings per resource
        resource_counts = {}
        for finding in findings:
            for resource in finding.get("affected_resources", []):
                resource_counts[resource] = resource_counts.get(resource, 0) + 1

        # Sort by count
        top_resources = sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        result = "### Top 5 Affected Resources\n"
        for i, (resource, count) in enumerate(top_resources, 1):
            result += f"{i}. {resource} ({count} findings)\n"

        return result

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
        evidence_snippet = finding.get("evidence_snippet")
        evidence_refs = finding.get("evidence_refs", [])

        detail = f"""### [{finding_id}] {title}

**Risk Score:** {self._format_risk_score(risk_score)}

**Description:**
{description}
"""

        # Render evidence snippet if present
        if evidence_snippet or evidence_refs:
            detail += "\n**Evidence:**\n"

            if evidence_snippet:
                detail += "```json\n"
                detail += json.dumps(evidence_snippet, indent=2, ensure_ascii=False)
                detail += "\n```\n"

            if evidence_refs:
                detail += "\n*References:*\n"
                for ref in evidence_refs[:5]:
                    detail += f"- `{ref}`\n"
                if len(evidence_refs) > 5:
                    detail += f"- ... and {len(evidence_refs) - 5} more\n"

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

    def _observations(self) -> str:
        """Generate observations section."""
        return """## 📝 Observations

- **Positive:** Observations about positive security controls will be listed here.
- **Concerns:** General concerns or patterns of weakness will be listed here.
- **Recommendations:** High-level recommendations will be listed here.
"""

    def _references(self) -> str:
        """Generate references section.

        Note: PCI DSS references only included in PCI compliance reports.
        """
        refs = """## 📚 References

- CIS AWS Foundations Benchmark v1.5.0
- AWS Security Best Practices"""

        if self.config.report_type == "pci-dss":
            refs += "\n- PCI DSS v4.0 Requirements"

        return refs + "\n"

    def _footer(self) -> str:
        """Generate report footer."""
        return """---

## 📝 Notes

- This report contains sensitive security information. Handle with care.
- Recommendations are based on AWS security best practices.
- For questions or clarifications, contact your security team.

---

🔒 **Drystone** v1.0.0 - AWS Security Audit CLI
Generated with [Drystone](https://github.com/billycuesta/drystone)
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

    def _natural_sort_key(self, s: str) -> List:
        """Natural sort key for control IDs (7.2.1 < 8.4.1)."""
        return [int(part) if part.isdigit() else part for part in re.split(r'(\d+)', s)]

    def _get_all_checklist_controls(self) -> List[str]:
        """Extract all unique PCI DSS controls from checklist.json."""
        try:
            # Get skill name from findings (NO default)
            skill = self.findings.get("skill")
            if not skill:
                raise ValueError("Skill name missing in findings")
            # Build path to checklist
            checklist_path = Path(__file__).parent.parent.parent / "skills" / skill / "checklist.json"

            if not checklist_path.exists():
                return []

            with open(checklist_path, "r") as f:
                checklist = json.load(f)

            # Extract unique control IDs
            controls = set()
            for item in checklist.get("items", []):
                for pci_control in item.get("pci_dss", []):
                    control_id = pci_control.get("control")
                    if control_id:
                        controls.add(control_id)

            # Return sorted by natural sort
            return sorted(controls, key=self._natural_sort_key)

        except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError):
            return []

    def _extract_pci_controls_map(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by PCI control ID."""
        control_map = {}
        for finding in findings:
            for pci_control in finding.get("pci_dss", []):
                control_id = pci_control.get("control")
                if control_id:
                    if control_id not in control_map:
                        control_map[control_id] = []
                    control_map[control_id].append(finding)
        return control_map

    def _format_findings_count(self, findings: List[Dict]) -> str:
        """Format findings count by severity (e.g., '2 Critical, 1 High')."""
        if not findings:
            return "-"

        # Count by severity
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            severity = finding.get("severity", "Low")
            if severity in counts:
                counts[severity] += 1

        # Build formatted string
        parts = []
        for severity in ["Critical", "High", "Medium", "Low"]:
            if counts[severity] > 0:
                parts.append(f"{counts[severity]} {severity}")

        return ", ".join(parts) if parts else "-"

    def _pci_dss_compliance_summary(self) -> str:
        """Generate PCI DSS compliance summary section."""
        findings = self.findings.get("findings", [])
        skill_name = self.findings.get("skill", "unknown").upper()

        # Get all PCI controls from checklist
        all_controls = self._get_all_checklist_controls()
        if not all_controls:
            return ""  # No PCI mappings, skip section

        # Extract control map from findings
        control_map = self._extract_pci_controls_map(findings)

        # Calculate stats
        total = len(all_controls)
        ko_controls = len(control_map)  # Controls with findings = KO
        ok_controls = total - ko_controls
        compliance_pct = (ok_controls / total * 100) if total > 0 else 0.0

        # Build section header
        section = f"""## 🛡️ PCI DSS v4.0 Compliance Summary

**Compliance Rate**: {ok_controls}/{total} controles OK ({compliance_pct:.1f}%)

| Control ID | Status | # Findings |
|------------|--------|------------|
"""

        # Build table rows
        for control_id in all_controls:
            if control_id in control_map:
                status = "❌ KO"
                findings_text = self._format_findings_count(control_map[control_id])
            else:
                status = "✅ OK"
                findings_text = "-"

            section += f"| {control_id} | {status} | {findings_text} |\n"

        # Add legend and notes
        section += f"""
**Legend:**
- ✅ OK: No violations found for this control
- ❌ KO: Violations detected (see detailed findings below)

**Note:** This table shows PCI DSS v4.0 controls evaluated by the {skill_name} skill. For a complete PCI compliance assessment, all 12 requirement categories must be evaluated across multiple skills (Network, Exposure, Vulnerabilities, etc.)."""

        return section.strip()
