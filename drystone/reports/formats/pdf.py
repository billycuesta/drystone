"""PDF report formatter using XML-backed HTML template."""

from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from drystone.reports.formats.base import BaseFormatter
from drystone.reports.validation_commands import suggest_aws_cli_commands


class PDFFormatter(BaseFormatter):
    def _finding_sort_key(self, finding: Dict[str, Any]) -> tuple:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        return (
            sev_order.get(str(finding.get("severity", "Low")), 4),
            -float(finding.get("risk_score", 0.0)),
            str(finding.get("id", "")),
        )

    @property
    def file_extension(self) -> str:
        return "pdf"

    def generate(self) -> Path:
        html_content = self._build_html_from_xml_template()
        skill_name = self.findings.get("skill", "audit").lower()
        report_path = self.reports_path / f"audit-report-{skill_name}.{self.file_extension}"

        try:
            from weasyprint import HTML  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "PDF generation requires 'weasyprint'. Install it with: pip install weasyprint"
            ) from e

        HTML(string=html_content).write_pdf(str(report_path))
        return report_path

    def _build_html_from_xml_template(self) -> str:
        template_path = Path(__file__).parent.parent / "templates" / "pdf_report.xml"
        root = ET.parse(template_path).getroot()
        html_block = root.findtext("html", default="")
        if not html_block.strip():
            raise ValueError(f"Invalid XML PDF template: {template_path}")

        return self._replace_placeholders(html_block, self._build_placeholders())

    def _replace_placeholders(self, content: str, values: Dict[str, str]) -> str:
        rendered = content
        for key, value in values.items():
            rendered = rendered.replace(f"{{{{{key}}}}}", value)
        return re.sub(r"\{\{[A-Z0-9_]+\}\}", "", rendered)

    def _build_placeholders(self) -> Dict[str, str]:
        findings = self.findings.get("findings", [])
        summary = self.findings.get("summary", {})
        report_date = self.findings.get("analyzed_at") or datetime.utcnow().isoformat()
        report_date = report_date.replace("T", " ").split(".")[0]

        architecture_html = self._architecture_section_html()
        correlation_html = self._correlation_section_html()
        findings_html = self._findings_by_severity_html(findings)

        pagebreak_arch_corr = (
            "<div class='page-break'></div>" if (architecture_html or correlation_html) else ""
        )
        has_findings = bool(findings) and "No findings detected" not in findings_html
        pagebreak_findings = "<div class='page-break'></div>" if has_findings else ""

        return {
            "DRYSTONE_BANNER_HTML": self._drystone_ascii_banner_gradient_html(),
            "ANALYSIS_TITLE": html.escape(self._analysis_title()),
            "CLIENT_NAME": html.escape(self.session.client_name or "Unknown Client"),
            "REPORT_DATE": html.escape(report_date),
            "AWS_ACCOUNT_ID": html.escape(self._resolved_account_id(findings)),
            "SKILL": html.escape(self._display_skill()),
            "MIN_SEVERITY": html.escape(str(getattr(self.config, "min_severity", "low")).upper()),
            "REPORT_TYPE": html.escape(str(getattr(self.config, "report_type", "general")).upper()),
            "AWS_REGION": html.escape(str(getattr(self.config, "aws_region", "unknown"))),
            "AI_PROVIDER": html.escape(str(getattr(self.config, "ai_provider", "unknown"))),
            "AI_MODEL": html.escape(str(getattr(self.config, "ai_model", "auto"))),
            "TOTAL_FINDINGS": str(summary.get("total_findings", len(findings))),
            "RISK_SCORE": f"{float(summary.get('overall_risk_score', 0.0)):.1f}",
            "SCOPE_DEFINITION": self._scope_definition_html(summary, findings),
            "METHODOLOGY_SECTION": self._methodology_section_html(),
            "SEVERITY_CHART": self._severity_distribution_chart_html(summary),
            "TOP_RESOURCES": self._top_resources_html(findings),
            "TOP_FINDINGS_ROWS": self._top_findings_rows_html(findings),
            "ARCHITECTURE_SECTION": architecture_html,
            "CORRELATION_SECTION": correlation_html,
            "PAGEBREAK_ARCH_CORR": pagebreak_arch_corr,
            "FINDINGS_BY_SEVERITY": findings_html,
            "PAGEBREAK_FINDINGS": pagebreak_findings,
            "OBSERVATIONS": self._observations_html(),
            "REMEDIATION_TIMELINE": self._remediation_timeline_html(findings),
            "REFERENCES": self._references_html(),
            "FOOTER_NOTES": self._footer_notes_html(),
        }

    def _display_skill(self) -> str:
        report_meta = self.findings.get("report_metadata", {})
        skill = report_meta.get("report_skill") or self.findings.get("skill", "unknown")
        return str(skill).upper()

    def _drystone_ascii_banner(self) -> str:
        return (
            " ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗\n"
            " ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝\n"
            " ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗\n"
            " ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝\n"
            " ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗\n"
            " ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝"
        )

    def _drystone_ascii_banner_gradient_html(self) -> str:
        """Render ASCII banner with per-character gradient for PDF compatibility."""
        raw_banner = self._drystone_ascii_banner()
        banner = raw_banner.split("\n")
        flat_chars = sum(len(line) for line in banner) or 1

        start = (180, 100, 220)
        end = (255, 165, 0)

        def _color_at(position: float) -> str:
            r = int(start[0] + (end[0] - start[0]) * position)
            g = int(start[1] + (end[1] - start[1]) * position)
            b = int(start[2] + (end[2] - start[2]) * position)
            return f"rgb({r},{g},{b})"

        html_lines: List[str] = []
        index = 0
        for line in banner:
            chunks: List[str] = []
            for ch in line:
                pos = index / max(1, flat_chars - 1)
                color = _color_at(pos)
                chunks.append(f"<span style='color:{color}'>{html.escape(ch)}</span>")
                index += 1
            html_lines.append(f"<div class='drystone-logo-line'>{''.join(chunks)}</div>")

        # Keep raw banner text in HTML comments for testability/regression checks.
        return f"<!-- {raw_banner} -->" + "".join(html_lines)

    def _analysis_title(self) -> str:
        skill = self._display_skill()
        return f"Security Audit Report: {skill} Security Analysis"

    def _looks_spanish(self, text: str) -> bool:
        t = str(text or "").lower()
        markers = [
            " sin ",
            " con ",
            " para ",
            " debe ",
            " deben ",
            "múltiples",
            "hallazgos",
            " misma vuln",
            " publico",
            " pública",
            " publica",
            " politicas",
            " políticas",
            " auditoria",
            " auditoría",
            " habilitado",
            " proteccion",
            " protección",
            " deshabilitado",
            " vulnerabilidades",
        ]
        return any(m in t for m in markers)

    def _translate_to_english(self, text: str) -> str:
        out = str(text or "")
        replacements = [
            ("Múltiples CVEs en mismo recurso", "Multiple CVEs in the same resource"),
            (
                "Hallazgos duplicados (misma vuln en múltiples recursos)",
                "Duplicate findings (same vulnerability in multiple resources)",
            ),
            (
                "(misma vuln en múltiples recursos)",
                "(same vulnerability in multiple resources)",
            ),
            ("Múltiples", "Multiple"),
            ("múltiples", "multiple"),
            ("Hallazgos duplicados", "Duplicate findings"),
            ("hallazgos duplicados", "duplicate findings"),
            ("Hallazgos", "Findings"),
            ("hallazgos", "findings"),
            ("duplicados", "duplicate"),
            ("Vulnerabilidades", "Vulnerabilities"),
            ("vulnerabilidades", "vulnerabilities"),
            ("deshabilitado", "disabled"),
            ("sin plan de remediación", "without remediation plan"),
            ("sin remediar", "unremediated"),
            ("Variables de entorno", "Environment variables"),
            ("claves sensibles", "sensitive keys"),
            ("imágenes privadas", "private images"),
            ("sin auditar", "unaudited"),
            (" en mismo recurso", " in same resource"),
            (" en múltiples", " in multiple"),
            (" para ECR", " for ECR"),
            (" con sensitive", " with sensitive"),
            (" mismo recurso", "same resource"),
            ("misma vuln", "same vulnerability"),
            ("recursos", "resources"),
            ("recurso", "resource"),
            ("público", "public"),
            ("publico", "public"),
            ("políticas", "policies"),
            ("politicas", "policies"),
            ("protección", "protection"),
            ("proteccion", "protection"),
        ]
        for src, dst in replacements:
            out = out.replace(src, dst)
        return out

    def _normalize_finding_language(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        if str(getattr(self.config, "report_language", "en")).lower() != "en":
            return finding
        out = dict(finding)
        for key in ("title", "description", "remediation"):
            val = str(out.get(key, ""))
            if self._looks_spanish(val):
                out[key] = self._translate_to_english(val)
        return out

    def _scope_definition_html(
        self, summary: Dict[str, Any], findings: List[Dict[str, Any]]
    ) -> str:
        def item(label: str, value: str) -> str:
            return (
                "<div class='scope-row'>"
                f"<span class='scope-label'>{html.escape(label)}</span>"
                f"<span class='scope-value'>{html.escape(value)}</span>"
                "</div>"
            )

        access_key = self._masked_access_key()
        report_date = self.findings.get("analyzed_at", datetime.utcnow().isoformat())
        report_date = report_date.replace("T", " ").split(".")[0]
        fields = [
            ("Client", str(self.session.client_name or "Unknown")),
            ("Analysis Date", report_date),
            ("Scope Skill", self._display_skill()),
            ("Report Type", self._report_type_label()),
            ("AWS Account ID", self._resolved_account_id(findings)),
            ("AWS Region", str(getattr(self.config, "aws_region", "unknown"))),
            ("Access Key Used", access_key),
            ("AI Provider", str(getattr(self.config, "ai_provider", "unknown"))),
            ("AI Model", str(getattr(self.config, "ai_model", "auto"))),
        ]

        return "".join(item(label, value) for label, value in fields)

    def _resolved_account_id(self, findings: List[Dict[str, Any]]) -> str:
        account_id = str(getattr(self.session, "account_id", "") or "").strip()
        if account_id and account_id.lower() != "unknown":
            return account_id

        arn_pattern = re.compile(r"arn:aws:[^:]+:[^:]*:(\d{12}):")
        for finding in findings:
            for resource in finding.get("affected_resources", []) or []:
                match = arn_pattern.search(str(resource))
                if match:
                    return match.group(1)

        full_text = json.dumps(self.findings, default=str)
        match = re.search(r"\b(\d{12})\b", full_text)
        if match:
            return match.group(1)

        return "unknown"

    def _report_type_label(self) -> str:
        report_type = str(getattr(self.config, "report_type", "general")).lower()
        labels = {
            "general": "Security Assessment",
            "pci-dss": "PCI DSS Compliance Assessment",
            "pentest": "Infrastructure Penetration Test",
        }
        return labels.get(report_type, report_type.upper())

    def _masked_access_key(self) -> str:
        access_key = getattr(self.config, "aws_access_key_id", None)
        if isinstance(access_key, str) and access_key:
            return f"{access_key[:4]}...{access_key[-4:]}"
        if getattr(self.config, "aws_profile", None):
            return f"Profile: {self.config.aws_profile}"
        if getattr(self.config, "aws_credentials_file", None):
            return f"File: {self.config.aws_credentials_file}"
        return "Environment variables"

    def _severity_distribution_chart_html(self, summary: Dict[str, Any]) -> str:
        total = max(1, int(summary.get("total_findings", 0)))
        rows = []
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = int(summary.get(sev.lower(), 0))
            pct = int((count / total) * 100)
            rows.append(
                "<tr>"
                f"<td>{sev}</td>"
                f"<td><div class='bar'><span class='bar-fill severity-{sev.lower()}' style='width:{pct}%;'></span></div></td>"
                f"<td>{count} ({pct}%)</td>"
                "</tr>"
            )
        return "".join(rows)

    def _top_resources_html(self, findings: List[Dict[str, Any]]) -> str:
        counts: Dict[str, int] = {}
        for finding in findings:
            for resource in finding.get("affected_resources", []):
                key = str(resource)
                counts[key] = counts.get(key, 0) + 1

        top = sorted(counts.items(), key=lambda item: item[1], reverse=True)[:5]
        if not top:
            return "<li>No affected resources identified</li>"
        return "".join(
            f"<li><code>{html.escape(resource)}</code> ({count} findings)</li>"
            for resource, count in top
        )

    def _top_findings_rows_html(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return '<tr><td colspan="5">No findings</td></tr>'

        ordered = sorted(findings, key=self._finding_sort_key)

        rows = []
        for finding in ordered:
            finding = self._normalize_finding_language(finding)
            finding_id = html.escape(str(finding.get("id", "N/A")))
            title = html.escape(str(finding.get("title", "Untitled"))[:72])
            severity = html.escape(str(finding.get("severity", "Unknown")))
            risk = float(finding.get("risk_score", 0.0))
            resources = len(finding.get("affected_resources", []))
            rows.append(
                "<tr>"
                f"<td>{finding_id}</td><td>{title}</td>"
                f"<td class='severity-{severity.lower()}'>{severity}</td>"
                f"<td>{risk:.1f}/10</td><td>{resources}</td>"
                "</tr>"
            )
        return "".join(rows)

    def _architecture_section_html(self) -> str:
        architecture = self.findings.get("architecture")
        if not architecture:
            return ""
        flow = html.escape(str(architecture.get("flow_diagram", "")))
        if not flow.strip():
            return ""
        return (
            "<h2>Architecture Overview</h2>"
            '<div class="individual-finding"><pre class="code-block">'
            f"{flow}"
            "</pre></div>"
        )

    def _correlation_section_html(self) -> str:
        corr_file = self.session.base_path / "findings" / "correlated.json"
        if not corr_file.exists():
            return ""

        try:
            with open(corr_file, "r") as f:
                corr_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return ""

        correlations = corr_data.get("correlations", []) or []
        if not correlations:
            return (
                "<h2>Cross-Skill Correlations</h2>"
                "<p>No cross-skill attack patterns detected. Individual findings analyzed separately.</p>"
            )

        blocks = []
        for corr in correlations[:10]:
            title = html.escape(str(corr.get("title", "Attack chain")))
            corr_id = html.escape(str(corr.get("id", "CORR")))
            severity = html.escape(str(corr.get("severity", "High")))
            risk = float(corr.get("compound_risk_score", 0.0))
            desc = html.escape(str(corr.get("description", "")))
            blocks.append(
                '<div class="individual-finding">'
                f"<h3>[{corr_id}] {title}</h3>"
                f"<p><strong>Severity:</strong> <span class='severity-{severity.lower()}'>{severity}</span> "
                f"| <strong>Compound Risk:</strong> {risk:.1f}/10</p>"
                f"<p>{desc}</p>"
                "</div>"
            )

        return "<h2>Cross-Skill Correlations</h2>" + "".join(blocks)

    def _findings_by_severity_html(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return "<p>No findings detected.</p>"

        groups = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for finding in findings:
            groups.setdefault(str(finding.get("severity", "Low")), []).append(finding)

        sections = []
        for severity in ["Critical", "High", "Medium", "Low"]:
            sev_findings = sorted(groups.get(severity, []), key=self._finding_sort_key)
            if not sev_findings:
                continue
            sections.append(f"<h2>{severity} Severity ({len(sev_findings)})</h2>")
            for finding in sev_findings:
                sections.append(self._finding_card_html(finding))
        return "".join(sections)

    def _finding_card_html(self, finding: Dict[str, Any]) -> str:
        finding = self._normalize_finding_language(finding)
        finding_id = html.escape(str(finding.get("id", "N/A")))
        title = html.escape(str(finding.get("title", "Untitled")))
        severity = html.escape(str(finding.get("severity", "Unknown")))
        risk = float(finding.get("risk_score", 0.0))
        description = html.escape(str(finding.get("description", "")))
        remediation = html.escape(str(finding.get("remediation", "")))
        cis_ref = html.escape(str(finding.get("cis_reference", "N/A")))

        evidence_snippet = finding.get("evidence_snippet")
        if evidence_snippet:
            dumped = json.dumps(evidence_snippet, indent=2, ensure_ascii=False)
            evidence_block = (
                "<div class='finding-resources finding-evidence'><h4>Evidence</h4>"
                f"<pre class='code-block'>{html.escape(dumped)}</pre></div>"
            )
        else:
            evidence_block = (
                "<div class='finding-resources finding-evidence'><h4>Evidence</h4>"
                "<p>No raw evidence snippet available for this finding.</p></div>"
            )

        resources = finding.get("affected_resources", [])[:8]
        res_items = "".join(f"<li><code>{html.escape(str(res))}</code></li>" for res in resources)
        if not res_items:
            res_items = "<li>No affected resources listed</li>"

        commands, commands_suggested = self._collect_validation_commands(finding)
        commands_block = self._validation_commands_block_html(commands, commands_suggested)
        is_pentest_report = str(getattr(self.config, "report_type", "general")) == "pentest"
        exploitation_block = (
            self._exploitation_block_html(finding, commands) if is_pentest_report else ""
        )

        return (
            '<div class="individual-finding">'
            f"<h3>[{finding_id}] {title}</h3>"
            f"<p><strong>Risk Score:</strong> {risk:.1f}/10 | <strong>Severity:</strong> "
            f"<span class='severity-{severity.lower()}'>{severity}</span></p>"
            f"<div class='finding-description'><p>{description}</p></div>"
            "<div class='finding-resources'><h4>Affected Resources</h4>"
            f"<ul class='resource-list'>{res_items}</ul></div>"
            f"{commands_block}"
            f"{evidence_block}"
            f"{exploitation_block}"
            f"<div class='finding-remediation'><h4>Remediation</h4><p>{remediation}</p></div>"
            f"<p><strong>CIS Reference:</strong> {cis_ref}</p>"
            "</div>"
        )

    def _collect_validation_commands(self, finding: Dict[str, Any]) -> tuple[List[str], bool]:
        commands = (
            finding.get("validation_commands")
            or finding.get("cli_commands")
            or finding.get("test_commands")
            or finding.get("verification_commands")
            or []
        )

        if not isinstance(commands, list):
            commands = []

        cleaned = [str(cmd).strip() for cmd in commands if str(cmd).strip()]
        suggested = False
        if not cleaned:
            cleaned = suggest_aws_cli_commands(
                skill=self._skill_for_finding(finding),
                evidence_refs=[str(ref) for ref in (finding.get("evidence_refs", []) or [])],
                region=str(getattr(self.config, "aws_region", "us-east-1")),
                account_id=self._resolved_account_id(self.findings.get("findings", [])),
                finding_id=str(finding.get("id", "")),
            )
            suggested = bool(cleaned)
        return cleaned, suggested

    def _validation_commands_block_html(self, cleaned: List[str], suggested: bool) -> str:
        if not cleaned:
            return ""

        items = "".join(f"<li><code>{html.escape(cmd)}</code></li>" for cmd in cleaned[:8])
        if len(cleaned) > 8:
            items += f"<li>... and {len(cleaned) - 8} more</li>"

        heading = "Validation Commands (AWS CLI Suggested)" if suggested else "Validation Commands"

        return (
            f"<div class='finding-resources'><h4>{heading}</h4>"
            f"<ul class='resource-list'>{items}</ul></div>"
        )

    def _exploitation_block_html(
        self, finding: Dict[str, Any], validation_commands: List[str]
    ) -> str:
        description = (
            finding.get("exploitation")
            or finding.get("exploitation_description")
            or finding.get("attack_scenario")
            or ""
        )

        cmd_source = (
            finding.get("exploitation_commands")
            or finding.get("poc_commands")
            or finding.get("proof_of_concept")
            or []
        )
        exploit_commands: List[str] = []
        if isinstance(cmd_source, str) and cmd_source.strip():
            exploit_commands = [cmd_source.strip()]
        elif isinstance(cmd_source, list):
            exploit_commands = [str(c).strip() for c in cmd_source if str(c).strip()]

        if not exploit_commands and validation_commands:
            exploit_commands = validation_commands[:3]

        if not description and not exploit_commands:
            return ""

        narrative = (
            html.escape(str(description).strip())
            if str(description).strip()
            else "Potential exploitation path inferred from the affected resources and misconfiguration evidence."
        )

        cmd_html = ""
        if exploit_commands:
            items = "".join(
                f"<li><code>{html.escape(cmd)}</code></li>" for cmd in exploit_commands[:5]
            )
            cmd_html = f"<ul class='resource-list'>{items}</ul>"

        return (
            "<div class='finding-exploitation'><h4>Exploitation (Theoretical)</h4>"
            f"<p>{narrative}</p>{cmd_html}</div>"
        )

    def _skill_for_finding(self, finding: Dict[str, Any]) -> str:
        report_meta = self.findings.get("report_metadata", {})
        report_skill = str(report_meta.get("report_skill") or "").strip().lower()
        if report_skill and report_skill != "aggregated":
            return report_skill

        finding_id = str(finding.get("id", "")).upper()
        if finding_id.startswith("IAM-"):
            return "iam"
        if finding_id.startswith("NET-"):
            return "network"
        if finding_id.startswith("EXP-"):
            return "exposure"
        if finding_id.startswith("WAF-"):
            return "waf"

        raw_skill = str(self.findings.get("skill", "") or "").strip().lower()
        return raw_skill if raw_skill and raw_skill != "aggregated" else "iam"

    def _observations_html(self) -> str:
        return (
            "<ul>"
            "<li><strong>Positive:</strong> Positive security controls appear in findings context.</li>"
            "<li><strong>Concerns:</strong> Prioritize recurring identity and privilege management patterns.</li>"
            "<li><strong>Recommendations:</strong> Address critical and high severity findings first.</li>"
            "</ul>"
        )

    def _methodology_section_html(self) -> str:
        report_type = str(getattr(self.config, "report_type", "general")).lower()
        if report_type != "pentest":
            return ""

        return (
            "<h2>Methodology</h2>"
            "<div class='card'>"
            "<p>This engagement follows a PTES-oriented methodology (Penetration Testing Execution Standard), adapted for AWS control-plane assessments and evidence-driven analysis.</p>"
            "<h3>Pentest Phases Applied</h3>"
            "<ol>"
            "<li><strong>Pre-Engagement:</strong> scope definition, account boundaries, legal and operational constraints.</li>"
            "<li><strong>Intelligence Gathering:</strong> AWS evidence collection across IAM, Exposure, Network, and Vulnerability domains.</li>"
            "<li><strong>Threat Modeling & Analysis:</strong> deterministic checks + AI-assisted analysis + normalization/reconciliation.</li>"
            "<li><strong>Exploitation (Theoretical):</strong> attack-path simulation through cross-skill chain correlation.</li>"
            "<li><strong>Post-Exploitation (Simulated Impact):</strong> blast radius and privilege propagation analysis.</li>"
            "<li><strong>Reporting & Retest:</strong> prioritized remediation with validation commands and retest criteria.</li>"
            "</ol>"
            "<p><strong>Reference frameworks:</strong> PTES (execution flow), OWASP Testing principles (verification mindset), and cloud security best practices for AWS.</p>"
            "</div>"
        )

    def _remediation_timeline_html(self, findings: List[Dict[str, Any]]) -> str:
        critical = [f for f in findings if f.get("severity") == "Critical"]
        high = [f for f in findings if f.get("severity") == "High"]
        medium = [f for f in findings if f.get("severity") == "Medium"]

        def _items(rows: List[Dict[str, Any]], limit: int) -> str:
            if not rows:
                return "<li>No items</li>"
            items = []
            for row in rows[:limit]:
                normalized = self._normalize_finding_language(row)
                items.append(
                    f"<li>[{html.escape(str(normalized.get('id', 'N/A')))}] {html.escape(str(normalized.get('title', 'Untitled')))}</li>"
                )
            return "".join(items)

        return (
            "<h3>Immediate (0-7 days) - Critical Priority</h3>"
            f"<ul>{_items(critical, 5)}</ul>"
            "<h3>Short-term (8-30 days) - High Priority</h3>"
            f"<ul>{_items(high, 5)}</ul>"
            "<h3>Medium-term (31-90 days) - Medium Priority</h3>"
            f"<ul>{_items(medium, 3)}</ul>"
        )

    def _references_html(self) -> str:
        refs = [
            "CIS AWS Foundations Benchmark v1.5.0",
            "AWS Security Best Practices",
        ]
        if getattr(self.config, "report_type", "general") == "pci-dss":
            refs.append("PCI DSS v4.0 Requirements")
        return "".join(f"<li>{html.escape(ref)}</li>" for ref in refs)

    def _footer_notes_html(self) -> str:
        return (
            "<ul>"
            "<li>This report contains sensitive security information. Handle with care.</li>"
            "<li>Recommendations are based on AWS security best practices.</li>"
            "<li>For questions or clarifications, contact your security team.</li>"
            "</ul>"
        )
