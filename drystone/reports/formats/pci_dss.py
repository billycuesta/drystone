"""PCI DSS compliance report formatter."""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .base import BaseFormatter


# ---------------------------------------------------------------------------
# Standalone data function — importable by any formatter
# ---------------------------------------------------------------------------

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


def get_requirement_name(req_num: str) -> str:
    """Return PCI DSS requirement name from its number."""
    return _REQUIREMENT_NAMES.get(req_num, f"Requirement {req_num}")


def build_pci_controls_map(findings: List[Dict], skills: List[str]) -> Dict:
    """Build a structured map of PCI DSS controls from checklists and findings.

    Args:
        findings: List of finding dicts (each may contain a ``pci_dss`` array).
        skills: List of skill names executed in this audit (used to locate checklists).

    Returns:
        Dict with keys:
            ``controls`` — list of control dicts, each with:
                - control: str  (e.g. "7.2.1")
                - requirement: str  (e.g. "7")
                - req_name: str  (e.g. "Access Control")
                - reason: str   (representative reason from checklist)
                - checks: list of {"id": str, "title": str}
                - findings: list of finding dicts that map to this control
                - status: "ok" | "ko"
            ``summary`` — {"total": N, "ok": N, "ko": N}
    """
    # 1. Load all controls from checklists
    all_controls: Dict[str, Dict] = {}
    for skill_name in skills:
        checklist_path = Path(f"drystone/skills/{skill_name}/checklist.json")
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
                        "req_name": get_requirement_name(req_num),
                        "reason": pci.get("reason", "Control mapping found in checklist."),
                        "checks": [],
                        "findings": [],
                        "status": "ok",
                    }
                if item.get("id") and item.get("title"):
                    all_controls[cid]["checks"].append(
                        {"id": item["id"], "title": item["title"]}
                    )

    # 2. Map findings to controls
    for finding in findings:
        for pci in finding.get("pci_dss") or []:
            cid = pci.get("control")
            if cid and cid in all_controls:
                all_controls[cid]["findings"].append(finding)
                all_controls[cid]["status"] = "ko"

    # 3. Sort by natural sort key
    def _sort_key(c: Dict) -> List:
        return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", c["control"])]

    sorted_controls = sorted(all_controls.values(), key=_sort_key)
    ok = sum(1 for c in sorted_controls if c["status"] == "ok")
    ko = len(sorted_controls) - ok

    return {
        "controls": sorted_controls,
        "summary": {"total": len(sorted_controls), "ok": ok, "ko": ko},
    }


class PCIDSSFormatter(BaseFormatter):
    """Generate PCI DSS v4.0 compliance report."""

    @property
    def file_extension(self) -> str:
        """File extension for the report."""
        return "md"

    def generate(self) -> Path:
        """Generate the PCI DSS markdown report file."""
        markdown_content = self._build_pci_report()

        # Include skill name in filename to avoid overwriting when multiple skills
        skill_name = self.findings.get("skill", "audit").lower()
        report_path = (
            self.reports_path / f"pci-dss-compliance-report-{skill_name}.{self.file_extension}"
        )

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
            self._footer(),
        ]
        return "\n\n".join([p for p in parts if p])

    def _header(self) -> str:
        """Generate the report header."""
        client_name = self.session.client_name
        account_id = self.session.account_id
        skills_audited = ", ".join(self.config.skills).upper()
        timestamp = self.findings.get("analyzed_at", datetime.utcnow().isoformat())

        banner = """ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝"""

        return f"""{banner}

# PCI DSS v4.0 Compliance Report - {client_name}

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

        # Count critical non-compliances by *control*, not by finding.
        critical_ko_controls = [
            cid for cid, f in findings_map.items() if (f or {}).get("severity") == "Critical"
        ]

        skills_evaluated_str = "\n".join(
            [f"- ✅ {s.upper()} ({self._get_checklist_version(s)})" for s in self.config.skills]
        )

        return f"""## 📊 Executive Summary

**Overall Compliance Rate:** {compliance_rate:.0f}% ({ok_controls}/{total_controls} controls)
**Status:** {status}

**Skills Evaluated:**
{skills_evaluated_str}

**Critical Non-Compliances:** {len(critical_ko_controls)} controls
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
        section += "\n```\n"

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
        sorted_controls = sorted(
            all_controls,
            key=lambda x: [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", x["control"])],
        )

        for control in sorted_controls:
            control_id = control["control"]
            req_num = control_id.split(".")[0]
            if req_num != current_requirement:
                current_requirement = req_num
                req_name = self._get_requirement_name(req_num)
                table += f"| **Requirement {req_num}: {req_name}** | | |\n"

            if control_id in findings_map:
                finding = findings_map[control_id]
                status = "❌ KO"
                # Prefer the reason provided by the finding for this specific control.
                finding_reason = None
                for pci in finding.get("pci_dss") or []:
                    if pci.get("control") == control_id:
                        finding_reason = pci.get("reason")
                        break
                reason = finding_reason or control.get(
                    "reason", "Control not met based on findings."
                )
                mapped_checks = control.get("checks") or []
                check_ids = [
                    str(c.get("id"))
                    for c in mapped_checks
                    if isinstance(c, dict) and isinstance(c.get("id"), str)
                ]
                checks_str = ", ".join(check_ids)

                justification = f"**Finding {finding.get('id', 'N/A')}:** {finding.get('title', 'Unknown')}. {reason}"
                if checks_str:
                    justification += f" (Mapped checks: {checks_str})"
            else:
                status = "✅ OK"
                mapped_checks = control.get("checks") or []
                if (
                    isinstance(mapped_checks, list)
                    and len(mapped_checks) == 1
                    and isinstance(mapped_checks[0], dict)
                ):
                    check_id = mapped_checks[0].get("id", "N/A")
                    check_title = mapped_checks[0].get("title", "Unknown check")
                    justification = f"No mapped findings for {check_id}: {check_title}."
                else:
                    check_ids = [
                        str(c.get("id"))
                        for c in mapped_checks
                        if isinstance(c, dict) and isinstance(c.get("id"), str)
                    ]
                    checks_str = ", ".join(check_ids) if check_ids else "N/A"
                    justification = f"No mapped findings for checks: {checks_str}."

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
                    cid = pci.get("control")
                    if not cid:
                        continue
                    if cid not in all_controls:
                        all_controls[cid] = {
                            "control": cid,
                            # Keep one representative reason from checklist as fallback.
                            "reason": pci.get("reason", "Control mapping found in checklist."),
                            # Keep all checks mapping to this control.
                            "checks": [],
                        }

                    # Append this checklist item as a check mapping.
                    if isinstance(item, dict) and item.get("id") and item.get("title"):
                        all_controls[cid]["checks"].append(
                            {"id": item.get("id"), "title": item.get("title")}
                        )
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
            "1": "Network Security Controls",
            "2": "Secure Configurations",
            "3": "Data Protection",
            "4": "Transmission Security",
            "5": "Malware Protection",
            "6": "Secure Development",
            "7": "Access Control",
            "8": "Identification & Authentication",
            "10": "Logging & Monitoring",
            "12": "Security Policies",
        }
        return requirements.get(req_num, "Unknown Requirement")

    def _critical_non_compliances(self) -> str:
        """List critical non-compliances by PCI control."""

        all_controls = {c["control"]: c for c in self._get_all_pci_controls_from_checklists()}
        findings_map = self._map_findings_to_controls()

        critical_controls = [
            cid for cid, f in findings_map.items() if (f or {}).get("severity") == "Critical"
        ]
        if not critical_controls:
            return ""

        lines = ["## 🎯 Critical Non-Compliances (Must Fix)\n"]
        for i, control_id in enumerate(sorted(critical_controls), 1):
            finding = findings_map[control_id]
            finding_id = finding.get("id", "N/A")
            title = finding.get("title", "Unknown")
            risk_score = float(finding.get("risk_score", 0) or 0)
            remediation = finding.get("remediation", "")
            evidence_snippet = finding.get("evidence_snippet")
            evidence_refs = finding.get("evidence_refs", [])

            # Prefer per-control reason from finding; fallback to checklist mapping.
            reason = None
            for pci in finding.get("pci_dss") or []:
                if pci.get("control") == control_id:
                    reason = pci.get("reason")
                    break
            if not reason:
                reason = (all_controls.get(control_id) or {}).get("reason")

            lines.append(f"### {i}. **[{control_id}]** {title} (ID: {finding_id})\n")
            if reason:
                lines.append(f"**Justification:** {reason}\n")
            lines.append(f"**Risk Score:** {risk_score:.1f}/10\n")

            # Render evidence snippet if present
            if evidence_snippet:
                lines.append("\n**Evidence:**\n")
                lines.append("```json\n")
                lines.append(json.dumps(evidence_snippet, indent=2, ensure_ascii=False))
                lines.append("\n```\n")
            elif evidence_refs:
                lines.append(f"\n**Evidence:** `{', '.join(evidence_refs[:3])}`\n")

            lines.append(f"\n**Remediation:**\n{remediation}\n\n")

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
        versions = "\n".join(
            [f"- {s.upper()}: {self._get_checklist_version(s)}" for s in self.config.skills]
        )
        return f"""---
**Report Generated:** {datetime.utcnow().isoformat()}
**Checklist Versions:**
{versions}

🔒 **Drystone** v1.0.0 - AWS Security Audit CLI
Generated with [Drystone](https://github.com/billycuesta/drystone)
"""
