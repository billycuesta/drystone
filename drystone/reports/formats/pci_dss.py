"""PCI DSS compliance report formatter."""

import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from .base import BaseFormatter

class PCIDSSFormatter(BaseFormatter):
    """Generate PCI DSS v4.0 compliance report."""

    @property
    def file_extension(self) -> str:
        """File extension for the report."""
        return "md"

    def generate(self) -> Path:
        """Generate the PCI DSS markdown report file."""
        markdown_content = self._build_pci_report()
        # Note: The plan shows pci-dss-compliance.md. This might need adjustment in generator.
        report_path = self.reports_path / f"pci-dss-compliance-report.{self.file_extension}"
        with open(report_path, "w") as f:
            f.write(markdown_content)
        return report_path

    def _build_pci_report(self) -> str:
        """Build the complete PCI DSS compliance report as a markdown string."""
        parts = [
            self._header(),
            self._executive_summary(),
            self._architecture_diagram(),
            self._compliance_table(),
            self._critical_non_compliances(),
            self._compliance_statistics(),
            self._recommendations(),
            self._footer()
        ]
        return "\n\n".join([p for p in parts if p])

    def _header(self) -> str:
        """Generate the report header."""
        client_name = self.session.client_name
        account_id = self.session.account_id
        skills_audited = ", ".join(self.config.skills).upper()
        timestamp = self.findings.get("analyzed_at", datetime.utcnow().isoformat())
        return f"""# PCI DSS v4.0 Compliance Report - {client_name}

**AWS Account:** {account_id} | **Skills Audited:** {skills_audited} | **Date:** {timestamp}
"""

    def _executive_summary(self) -> str:
        """Generate the executive summary section."""
        all_controls = self._get_all_pci_controls_from_checklists()
        findings_map = self._map_findings_to_controls()
        
        total_controls = len(all_controls)
        ko_controls = len(findings_map)
        ok_controls = total_controls - ko_controls
        compliance_rate = (ok_controls / total_controls * 100) if total_controls > 0 else 0
        status = "❌ NON-COMPLIANT" if ko_controls > 0 else "✅ COMPLIANT"

        critical_findings = [f for f in self.findings.get("findings", []) if f.get("severity") == "Critical"]
        
        skills_evaluated_str = "\n".join([f"- ✅ {s.upper()} ({self._get_checklist_version(s)})" for s in self.config.skills])

        return f"""## 📊 Executive Summary

**Overall Compliance Rate:** {compliance_rate:.0f}% ({ok_controls}/{total_controls} controls)
**Status:** {status}

**Skills Evaluated:**
{skills_evaluated_str}

**Critical Non-Compliances:** {len(critical_findings)} controls
**Remediation Effort:** High (estimated 30-60 days)
"""

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
        section += "```\n"

        if critical_gaps:
            section += "\n### 🚨 Critical Gaps Identified\n\n"
            for gap in critical_gaps:
                section += f"- {gap}\n"

        return section

    def _compliance_table(self) -> str:
        """Generate the main PCI DSS control compliance table."""
        all_controls = self._get_all_pci_controls_from_checklists()
        if not all_controls:
            return ""

        findings_map = self._map_findings_to_controls()
        table = "## 📋 PCI DSS Control Compliance Table\n\n"
        table += "| Control ID | Status | Justification / Evidence |\n"
        table += "|------------|--------|--------------------------|\n"

        current_requirement = None
        sorted_controls = sorted(all_controls, key=lambda x: [int(p) if p.isdigit() else p for p in re.split(r'(\d+)', x['control'])])

        for control in sorted_controls:
            control_id = control['control']
            req_num = control_id.split('.')[0]
            if req_num != current_requirement:
                current_requirement = req_num
                req_name = self._get_requirement_name(req_num)
                table += f"| **Requirement {req_num}: {req_name}** | | |\n"

            if control_id in findings_map:
                finding = findings_map[control_id]
                status = "❌ KO"
                justification = f"**Finding {finding['id']}:** {finding['title']}. {control['reason']}"
            else:
                status = "✅ OK"
                justification = control.get('ok_justification', f"Control '{control['check_title']}' passed.")

            table += f"| {control_id} | {status} | {justification} |\n"
        return table

    def _get_all_pci_controls_from_checklists(self) -> List[Dict]:
        """Extract all unique PCI controls from the checklists of all executed skills."""
        all_controls = {}
        for skill_name in self.config.skills:
            checklist_path = self._get_checklist_path(skill_name)
            if not checklist_path.exists():
                continue
            with open(checklist_path) as f:
                checklist = json.load(f)
            for item in checklist.get("items", []):
                for pci in item.get("pci_dss", []):
                    if pci["control"] not in all_controls:
                         all_controls[pci["control"]] = {
                            "control": pci["control"],
                            "reason": pci["reason"],
                            "check_id": item["id"],
                            "check_title": item["title"],
                            "ok_justification": item.get("title", ""),
                        }
        return list(all_controls.values())

    def _get_checklist_path(self, skill: str) -> Path:
        """Get the path to a skill's checklist.json."""
        # This assumes the script is run from the project root.
        return Path(f"drystone/skills/{skill}/checklist.json")

    def _get_checklist_version(self, skill: str) -> str:
        """Get the version of a skill's checklist."""
        checklist_path = self._get_checklist_path(skill)
        if not checklist_path.exists():
            return "N/A"
        with open(checklist_path) as f:
            checklist = json.load(f)
        return checklist.get("version", "N/A")

    def _map_findings_to_controls(self) -> Dict[str, Dict]:
        """Map findings to their PCI DSS controls for quick lookup."""
        mapping = {}
        for finding in self.findings.get("findings", []):
            for pci in finding.get("pci_dss", []):
                control_id = pci["control"]
                if control_id not in mapping:
                    mapping[control_id] = finding
        return mapping

    def _get_requirement_name(self, req_num: str) -> str:
        """Get PCI DSS requirement name from its number."""
        requirements = {
            "1": "Network Security Controls", "2": "Secure Configurations",
            "3": "Data Protection", "4": "Transmission Security",
            "5": "Malware Protection", "6": "Secure Development",
            "7": "Access Control", "8": "Identification & Authentication",
            "10": "Logging & Monitoring", "12": "Security Policies"
        }
        return requirements.get(req_num, "Unknown Requirement")

    def _critical_non_compliances(self) -> str:
        """List the top critical non-compliant findings."""
        critical_findings = [f for f in self.findings.get("findings", []) if f.get("severity") == "Critical"]
        if not critical_findings:
            return ""
        
        lines = ["## 🎯 Critical Non-Compliances (Must Fix)\n"]
        for i, finding in enumerate(critical_findings[:3], 1):
             lines.append(f"1. **{finding.get('pci_dss', [{'control': 'N/A'}])[0]['control']}** - {finding['title']} (Finding {finding['id']})")
        return "\n".join(lines)

    def _compliance_statistics(self) -> str:
        """Generate compliance statistics by PCI requirement."""
        # Placeholder - a full implementation would be more complex
        return "## 📊 Compliance Statistics\n\n- (Statistics by requirement TBD)"

    def _recommendations(self) -> str:
        """Generate prioritized remediation recommendations."""
        # Placeholder
        return "## 📝 Recommendations\n\n- (Prioritized recommendations TBD)"

    def _footer(self) -> str:
        """Generate the report footer."""
        versions = "\n".join([f"- {s.upper()}: {self._get_checklist_version(s)}" for s in self.config.skills])
        return f"""---
**Report Generated:** {datetime.utcnow().isoformat()}
**Checklist Versions:**
{versions}

🤖 Generated with Drystone - AWS Security Audit CLI
"""
