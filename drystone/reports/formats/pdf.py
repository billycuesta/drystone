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
from drystone.reports.pentest_inventory_summary import build_environment_narrative
from drystone.reports.validation_commands import suggest_aws_cli_commands


class PDFFormatter(BaseFormatter):
    # Skill execution order (pentest phases)
    PHASE_ORDER = {
        "recon": 0,
        "iam": 1,
        "exposure": 2,
        "network": 3,
        "vulns": 4,
        "alerting": 5,
        "hardening": 6,
        "secretsmanager": 7,
        "waf": 8,
        "ecr": 9,
        "cicd": 10,
        "kms": 11,
        "messaging": 12,
        "compute": 13,
    }

    def _finding_sort_key(self, finding: Dict[str, Any]) -> tuple:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        return (
            sev_order.get(str(finding.get("severity", "Low")), 4),
            -float(finding.get("risk_score", 0.0)),
            str(finding.get("id", "")),
        )

    def _finding_phase_sort_key(self, finding: Dict[str, Any]) -> tuple:
        """Sort key for findings ordered by pentest phase, then severity."""
        fid = str(finding.get("id", "")).lower()
        # Infer phase from finding ID prefix (e.g., "recon-003" → "recon")
        prefix = fid.split("-")[0] if "-" in fid else "zzz"
        phase_idx = self.PHASE_ORDER.get(prefix, 99)

        # Sort by: phase → severity → risk score → ID
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sev_idx = sev_order.get(str(finding.get("severity", "Low")), 4)
        risk = -float(finding.get("risk_score", 0.0))

        return (phase_idx, sev_idx, risk, str(finding.get("id", "")))

    @property
    def file_extension(self) -> str:
        return "pdf"

    def generate(self) -> Path:
        html_content = self._build_html_from_xml_template()
        skill_name = self._report_skill_slug()
        report_path = self.reports_path / f"audit-report-{skill_name}.{self.file_extension}"

        try:
            from weasyprint import HTML  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "PDF generation requires 'weasyprint'. Install it with: pip install weasyprint"
            ) from e

        HTML(string=html_content).write_pdf(str(report_path))
        return report_path

    def _get_client_context(self):
        """Safely get client context, returning None if not available or mock."""
        try:
            ctx = getattr(self.config, "_client_context", None)
            # Guard against Mock objects in tests — check for a real attribute
            if (
                ctx is not None
                and hasattr(ctx, "organization")
                and isinstance(getattr(ctx, "organization", None), str)
            ):
                return ctx
        except Exception:
            pass
        return None

    def _build_html_from_xml_template(self) -> str:
        template_path = Path(__file__).parent.parent / "templates" / "pdf_report.xml"
        root = ET.parse(template_path).getroot()
        html_block = root.findtext("html", default="")
        if not html_block.strip():
            raise ValueError(f"Invalid XML PDF template: {template_path}")

        return self._replace_placeholders(html_block, self._build_placeholders())

    @staticmethod
    def _md_bold_to_html(text: str) -> str:
        """Convert **bold** markdown syntax to HTML <strong> tags.

        Must be called AFTER html.escape() since asterisks are not escaped by html.escape.
        """
        return re.sub(r"\*\*([^*\n]+)\*\*", r"<strong>\1</strong>", text)

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
        is_pentest = str(getattr(self.config, "report_type", "general")) == "pentest"
        findings_html = (
            self._findings_by_phase_html(findings)
            if is_pentest
            else self._findings_by_severity_html(findings)
        )

        pagebreak_arch_corr = (
            "<div class='page-break'></div>" if (architecture_html or correlation_html) else ""
        )
        has_findings = bool(findings) and "No findings detected" not in findings_html
        pagebreak_findings = "<div class='page-break'></div>" if has_findings else ""

        return {
            "DRYSTONE_BANNER_HTML": self._drystone_ascii_banner_gradient_html(),
            "ANALYSIS_TITLE": html.escape(self._analysis_title()),
            "INDEX_SECTION": self._index_section_html(findings),
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
            "INVENTORY_SECTION": self._inventory_section_html(),
            "INVENTORY_ENV_SECTION": self._inventory_environment_section_html(),
            "DOCUMENT_CONTROL": self._document_control_html(),
            "EXECUTIVE_NARRATIVE": self._executive_narrative_html(summary),
            "CONDITIONS_SECTION": self._conditions_section_html(),
            "METHODOLOGY_SECTION": self._methodology_section_html(),
            "SEVERITY_CHART": self._severity_distribution_chart_html(summary),
            "PHASE_FINDINGS_TABLE": self._phase_findings_table_html(findings) if is_pentest else "",
            "ATTACK_PATH_CANDIDATES_TABLE": (
                self._attack_path_candidates_table_html() if is_pentest else ""
            ),
            "TOP_RESOURCES": self._top_resources_html(findings),
            "TOP_FINDINGS_ROWS": self._top_findings_rows_html(findings),
            "ARCHITECTURE_SECTION": architecture_html,
            "CORRELATION_SECTION": correlation_html,
            "PAGEBREAK_ARCH_CORR": pagebreak_arch_corr,
            "FINDINGS_BY_SEVERITY": findings_html,
            "PAGEBREAK_FINDINGS": pagebreak_findings,
            "REMEDIATION_TIMELINE": self._remediation_timeline_html(findings),
            "REFERENCES": self._references_html(),
            "FOOTER_NOTES": self._footer_notes_html(),
            "PCI_DSS_ANNEX": self._pci_dss_annex_html(),
        }

    def _index_section_html(self, findings: List[Dict[str, Any]]) -> str:
        is_pentest = str(getattr(self.config, "report_type", "general")) == "pentest"
        finding_items = []
        if is_pentest:
            grouped = self._group_reportable_pentest_findings(findings)
            for section in self._PENTEST_PHASE_SECTIONS:
                items = grouped.get(section["skill"], [])
                if not items:
                    continue
                per_phase_items = []
                for finding in sorted(
                    items, key=lambda f: float(f.get("risk_score", 0.0)), reverse=True
                ):
                    fid = html.escape(str(finding.get("id", "N/A")))
                    title = html.escape(str(finding.get("title", "Untitled")))
                    per_phase_items.append(
                        f"<li><span class='index-code'>{fid}</span> {title}</li>"
                    )
                finding_items.append(
                    "<li>"
                    f"<strong>{section['phase']}</strong>"
                    "<ol class='index-sublist'>" + "".join(per_phase_items) + "</ol>"
                    "</li>"
                )
        else:
            ordered = sorted(findings, key=self._finding_sort_key)
            for finding in ordered:
                fid = html.escape(str(finding.get("id", "N/A")))
                title = html.escape(str(finding.get("title", "Untitled")))
                finding_items.append(f"<li><span class='index-code'>{fid}</span> {title}</li>")

        nested_findings = (
            "<ol class='index-sublist'>" + "".join(finding_items) + "</ol>"
            if finding_items
            else "<ol class='index-sublist'><li>No findings</li></ol>"
        )

        findings_label = (
            "Detailed Findings by Phase" if is_pentest else "Detailed Findings by Severity"
        )

        # Build correlations index (attack chains)
        corr_index = ""
        if is_pentest:
            corr_file = self.session.base_path / "findings" / "correlated.json"
            if corr_file.exists():
                try:
                    with open(corr_file, "r") as f:
                        corr_data = json.load(f)
                    correlations = corr_data.get("correlations", []) or []
                    if correlations:
                        corr_items = []
                        for c in sorted(
                            correlations,
                            key=lambda x: x.get("compound_risk_score", 0),
                            reverse=True,
                        ):
                            cid = html.escape(str(c.get("id", "N/A")))
                            ctitle = html.escape(str(c.get("title", "Untitled")))
                            corr_items.append(
                                f"<li><span class='index-code'>{cid}</span> {ctitle}</li>"
                            )
                        corr_index = (
                            "<li>Attack Chains"
                            "<ol class='index-sublist'>" + "".join(corr_items) + "</ol></li>"
                        )
                except (OSError, json.JSONDecodeError):
                    pass

        return (
            "<ol class='index-list'>"
            "<li>Scope Definition</li>"
            "<li>Inventory</li>"
            "<li>Executive Summary</li>"
            "<li>Risk Analysis</li>"
            "<li>Architecture Overview (if available)</li>"
            "<li>Cross-Skill Correlations (if available)</li>"
            f"<li>{findings_label}"
            + nested_findings
            + "</li>"
            + corr_index
            + "<li>Remediation Timeline</li>"
            "<li>References</li>"
            "<li>Notes</li>"
            "</ol>"
        )

    def _display_skill(self) -> str:
        report_meta = self.findings.get("report_metadata", {})
        skill = report_meta.get("report_skill") or self.findings.get("skill", "unknown")
        return self._get_skill_display_name(str(skill).lower())

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

        # Normalize left padding so all lines start from the same column in PDF.
        leading_spaces = [len(line) - len(line.lstrip(" ")) for line in banner if line.strip()]
        trim = min(leading_spaces) if leading_spaces else 0
        banner = [line[trim:] if len(line) >= trim else line for line in banner]

        normalized_banner = "\n".join(banner)
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

        # Keep normalized banner text in comments for regression checks.
        return f"<!-- {normalized_banner} -->" + "".join(html_lines)

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

    _SKILL_DISPLAY_NAMES: Dict[str, str] = {
        "sistemas_explotables_red": "Network-Exploitable Systems Detection",
        "iam": "IAM",
        "exposure": "Exposure",
        "network": "Network",
        "vulns": "Vulnerabilities",
        "hardening": "Hardening",
        "secretsmanager": "Secrets Manager",
        "waf": "WAF",
        "ecr": "ECR",
        "alerting": "Alerting",
        "recon": "Recon",
        "webpen": "Web Pentest",
        "kms": "KMS",
        "cicd": "CI/CD",
        "compute": "Compute",
    }

    def _get_skill_display_name(self, skill: str) -> str:
        """Return a human-friendly display name for a skill."""
        return self._SKILL_DISPLAY_NAMES.get(skill.lower(), skill.upper())

    _SKILL_SCOPE_DESCRIPTIONS: Dict[str, str] = {
        "iam": "Identity and Access Management (IAM) controls, evaluating user privileges, password policies, MFA enforcement, access key rotation, root account usage, and IAM role trust relationships.",
        "exposure": "public internet exposure across S3 buckets, API Gateway endpoints, Lambda function URLs, EC2 security groups, and CloudFront distributions.",
        "network": "network segmentation controls including VPC configurations, Security Groups, Network ACLs, VPN endpoints, and inter-VPC connectivity.",
        "vulns": "vulnerability landscape reported by AWS Inspector v2, covering CVEs affecting EC2 instances, container images, and Lambda functions.",
        "hardening": "account-level hardening controls via AWS Config and Security Hub, evaluating CIS AWS Foundations Benchmark and PCI DSS compliance standards.",
        "alerting": "security alerting and monitoring pipelines via CloudTrail, CloudWatch alarms, EventBridge rules, and SNS notification flows.",
        "secretsmanager": "secrets lifecycle management including rotation policies, KMS encryption, access controls, and secret staleness.",
        "waf": "Web Application Firewall coverage across ALBs, CloudFront distributions, API Gateway endpoints, and AppSync APIs.",
        "ecr": "container registry security including image scanning configuration, lifecycle policies, and repository access controls.",
        "webpen": "web application security through active HTTP probing, TLS configuration analysis, security headers, CORS policies, and sensitive path discovery.",
        "kms": "KMS key management controls including rotation policies, key usage policies, and encryption coverage across AWS services.",
        "cicd": "CI/CD pipeline security covering CodePipeline, CodeBuild configurations, and artifact security controls.",
        "compute": "compute resource security including EC2 instance configurations, Launch Templates, and Auto Scaling group settings.",
        "sistemas_explotables_red": "network-exploitable systems detection: correlation of internet reachability, active Inspector vulnerability findings, and IAM blast-radius signals across EC2, ECS, Lambda, and RDS resources.",
    }

    def _compute_assessment_rating_pdf(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int,
        risk_score: float,
        total: int,
    ) -> tuple:
        """Compute qualitative assessment rating for PDF reports.

        Returns:
            (css_class, label, description) tuple
        """
        if total == 0:
            return (
                "rating-excellent",
                "Excellent",
                "No security findings were identified. The assessed controls demonstrate a strong security posture with no remediation required at this time.",
            )
        if critical == 0 and high == 0 and risk_score < 3.5:
            return (
                "rating-very-good",
                "Very Good",
                "The environment demonstrates a solid security posture. Only minor findings were identified, none of which represent immediate risk. Remediation can be planned as part of the regular improvement cycle.",
            )
        if critical == 0 and high <= 1 and risk_score < 5.5:
            return (
                "rating-good",
                "Good",
                "The environment shows a generally sound security posture with some areas requiring attention. High-severity findings should be scheduled for remediation within 30 days.",
            )
        if critical <= 1 and risk_score < 7.5:
            return (
                "rating-improvable",
                "Needs Improvement",
                "Significant security gaps have been identified. One or more critical or multiple high-severity findings require prompt remediation to reduce exposure and meet compliance requirements.",
            )
        return (
            "rating-critical",
            "Immediate Attention Required",
            "Critical security deficiencies have been detected that represent substantial risk to the environment. Immediate remediation is strongly recommended before the next assessment cycle.",
        )

    def _executive_narrative_html(self, summary: Dict[str, Any]) -> str:
        """Generate enriched narrative executive summary section for PDF reports."""
        skill = str(self.findings.get("skill", "unknown")).lower()
        client = html.escape(str(self.session.client_name or "the assessed environment"))

        total = int(summary.get("total_findings", 0))
        critical = int(summary.get("critical", 0))
        high = int(summary.get("high", 0))
        medium = int(summary.get("medium", 0))
        low = int(summary.get("low", 0))
        risk_score = float(summary.get("overall_risk_score", 0.0))

        scope = html.escape(
            self._SKILL_SCOPE_DESCRIPTIONS.get(
                skill, f"{self._get_skill_display_name(skill)} security controls and configurations"
            ).rstrip(".")
        )

        # Business context from client context file (if available)
        business_intro = ""
        client_context = self._get_client_context()
        if client_context:
            biz_text = str(getattr(client_context, "business_context", "") or "").strip()
            if biz_text:
                biz = html.escape(biz_text.split("\n")[0])
                business_intro = f"<p>{biz}</p>"

        # Assessment dates from client context or session
        dates_html = ""
        if client_context:
            ad = getattr(client_context, "assessment_dates", None)
            if isinstance(ad, dict):
                start = ad.get("start", "")
                end = ad.get("end", "")
            if start and end:
                dates_html = f"<p style='font-size:10px;color:#6b7280'>Assessment period: {html.escape(start)} to {html.escape(end)}</p>"

        if total == 0:
            findings_text = (
                "No security findings were identified during this assessment. "
                "The evaluated controls appear to be properly configured."
            )
        elif critical > 0 and high > 0:
            findings_text = (
                f"The assessment identified <strong>{total} finding(s)</strong>: "
                f"<strong>{critical} critical</strong> and <strong>{high} high</strong> severity issue(s) "
                f"alongside {medium} medium and {low} low severity item(s). "
                f"Immediate action is required on the critical findings."
            )
        elif critical > 0:
            findings_text = (
                f"The assessment identified <strong>{total} finding(s)</strong>, including "
                f"<strong>{critical} critical</strong> severity issue(s) requiring immediate remediation."
            )
        elif high > 0:
            findings_text = (
                f"The assessment identified <strong>{total} finding(s)</strong>, including "
                f"<strong>{high} high</strong> severity issue(s) that should be addressed promptly."
            )
        elif medium > 0:
            findings_text = (
                f"The assessment identified <strong>{total} finding(s)</strong> of medium or low severity, "
                f"representing opportunities for security improvement."
            )
        else:
            findings_text = (
                f"The assessment identified <strong>{total}</strong> low severity finding(s) "
                f"representing minor improvement opportunities."
            )

        rating_class, rating_label, rating_desc = self._compute_assessment_rating_pdf(
            critical, high, medium, low, risk_score, total
        )

        # Mini risk bar for executive summary
        colors = ["#16a34a", "#22c55e", "#eab308", "#f97316", "#dc2626"]
        segments = "".join(f"<div style='flex:1;background:{c};height:12px'></div>" for c in colors)
        indicator_pct = min(max(risk_score / 10.0 * 100, 0), 100)
        risk_bar = (
            f"<div style='position:relative;margin:8px 0'>"
            f"<div style='display:flex;border-radius:8px;overflow:hidden'>{segments}</div>"
            f"<div style='position:absolute;top:-2px;left:{indicator_pct:.0f}%;width:3px;height:16px;"
            f"background:#111827;border-radius:2px'></div>"
            f"</div>"
        )

        # Top recommendations from critical/high findings
        top_recs_html = ""
        findings_list = self.findings.get("findings", [])
        top_findings = sorted(
            [f for f in findings_list if f.get("severity") in ("Critical", "High")],
            key=lambda f: -float(f.get("risk_score", 0.0)),
        )[:5]
        if top_findings:
            rec_items = []
            for f in top_findings:
                f = self._normalize_finding_language(f)
                fid = html.escape(str(f.get("id", "")))
                title = html.escape(str(f.get("title", "")))
                sev = str(f.get("severity", "")).lower()
                rec_items.append(
                    f"<li><span class='severity-pill severity-{sev}'>"
                    f"{html.escape(str(f.get('severity', '')))}</span> "
                    f"<strong>{fid}</strong> — {title}</li>"
                )
            top_recs_html = (
                "<h3 style='margin-top:14px'>Top Recommendations</h3>"
                f"<ol style='margin:0;padding-left:18px'>{''.join(rec_items)}</ol>"
            )

        return (
            business_intro
            + dates_html
            + f"<p>This security assessment evaluated the {scope} for <strong>{client}</strong>. "
            + f"{findings_text}</p>"
            + risk_bar
            + f"<div class='assessment-rating {rating_class}'>"
            + f"<span class='rating-label'>Overall Assessment:</span> "
            + f"<span class='rating-value'>{html.escape(rating_label)}</span>"
            + f"<p class='rating-desc'>{html.escape(rating_desc)}</p>"
            + f"</div>"
            + top_recs_html
        )

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

        # Enrich from client context
        client_context = self._get_client_context()
        if client_context:
            if getattr(client_context, "project", ""):
                fields.insert(2, ("Project", client_context.project))
            ad = getattr(client_context, "assessment_dates", None)
            if isinstance(ad, dict):
                start = ad.get("start", "")
                end = ad.get("end", "")
                if start and end:
                    fields.append(("Assessment Period", f"{start} to {end}"))

        return "".join(item(label, value) for label, value in fields)

    # Mapping of evidence filenames → human-readable labels (mirrors MarkdownFormatter)
    _EVIDENCE_FILE_LABELS: Dict[str, str] = {
        # IAM
        "users.json": "IAM Users",
        "roles.json": "IAM Roles",
        "policies.json": "IAM Policies",
        "groups.json": "IAM Groups",
        "account-summary.json": "Account Summary",
        "mfa-devices.json": "MFA Devices",
        "access-keys.json": "Access Keys",
        # Alerting / Monitoring
        "cloudtrail-trails.json": "CloudTrail Trails",
        "cloudwatch-alarms.json": "CloudWatch Alarms",
        "cloudwatch-log-groups.json": "CloudWatch Log Groups",
        "cloudwatch-metric-filters.json": "CloudWatch Metric Filters",
        "eventbridge-rules.json": "EventBridge Rules",
        "sns-topics.json": "SNS Topics",
        "sns-subscriptions.json": "SNS Subscriptions",
        "vpc-flow-logs.json": "VPC Flow Logs",
        # Network
        "vpcs.json": "VPCs",
        "security-groups.json": "Security Groups",
        "nacls.json": "Network ACLs",
        "subnets.json": "Subnets",
        "route-tables.json": "Route Tables",
        "internet-gateways.json": "Internet Gateways",
        "nat-gateways.json": "NAT Gateways",
        "vpc-endpoints.json": "VPC Endpoints",
        "transit-gateways.json": "Transit Gateways",
        # Load Balancing / Compute
        "load-balancers.json": "Load Balancers",
        "ec2-instances.json": "EC2 Instances",
        "lambda-functions.json": "Lambda Functions",
        "auto-scaling-groups.json": "Auto Scaling Groups",
        # Exposure / Storage / API
        "s3-buckets.json": "S3 Buckets",
        "rds-instances.json": "RDS Instances",
        "api-gateways.json": "API Gateways",
        "cloudfront-distributions.json": "CloudFront Distributions",
        "elasticache-clusters.json": "ElastiCache Clusters",
        "opensearch-domains.json": "OpenSearch Domains",
        # Vulns
        "inspector-findings.json": "Inspector Findings",
        # Hardening
        "config-rules.json": "AWS Config Rules",
        "security-hub-findings.json": "Security Hub Findings",
        "security-hub-standards.json": "Security Hub Standards",
        "guardduty-detectors.json": "GuardDuty Detectors",
        "guardduty-findings.json": "GuardDuty Findings",
        # Secrets Manager
        "secrets.json": "Secrets",
        # WAF
        "web-acls.json": "Web ACLs",
        "waf-rules.json": "WAF Rules",
        "ip-sets.json": "IP Sets",
        # ECR
        "repositories.json": "ECR Repositories",
        "scanning-config.json": "ECR Scanning Config",
        "lifecycle-policies.json": "ECR Lifecycle Policies",
        # KMS
        "kms-keys.json": "KMS Keys",
    }

    def _skill_resources_audited_html(self) -> str:
        """Build an HTML table of audited resources from skill evidence files.

        Used for non-pentest report types where pentest inventory-summary.json
        is not available. Reads evidence/<skill>/ directory directly.
        """
        skill = self.findings.get("skill", "")
        if not skill:
            return "<p>No evidence directory available.</p>"

        evidence_dir = self.session.base_path / "evidence" / skill
        if not evidence_dir.exists() or not evidence_dir.is_dir():
            return "<p>No evidence directory available.</p>"

        rows = []
        for json_file in sorted(evidence_dir.glob("*.json")):
            if json_file.stem.startswith("_"):
                continue
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            # Count items: handle raw list evidence and dict evidence with 'items' key
            # (network/waf/ecr skills store evidence as {"_meta": ..., "items": [...], "by_id": {...}})
            if isinstance(data, list):
                count = len(data)
            elif isinstance(data, dict) and isinstance(data.get("items"), list):
                count = len(data["items"])
            else:
                # Skip scalar dicts (password-policy) or unrecognized structures
                continue
            label = self._EVIDENCE_FILE_LABELS.get(
                json_file.name,
                json_file.stem.replace("-", " ").replace("_", " ").title(),
            )
            rows.append((label, count))

        if not rows:
            return "<p>No countable evidence items found.</p>"

        out = [
            "<table style='width:100%;border-collapse:collapse;margin-top:8px'>",
            "<thead><tr>",
            "<th style='text-align:left;padding:6px 12px;border-bottom:2px solid #ccc'>Resource Type</th>",
            "<th style='text-align:right;padding:6px 12px;border-bottom:2px solid #ccc'>Count</th>",
            "</tr></thead><tbody>",
        ]
        for i, (label, count) in enumerate(rows):
            bg = " style='background:#f9f9f9'" if i % 2 == 1 else ""
            out.append(
                f"<tr{bg}>"
                f"<td style='padding:5px 12px'>{html.escape(label)}</td>"
                f"<td style='padding:5px 12px;text-align:right'>{count}</td>"
                "</tr>"
            )
        out.append("</tbody></table>")
        return "".join(out)

    def _inventory_section_html(self) -> str:
        if str(getattr(self.config, "report_type", "general")).lower() != "pentest":
            return self._skill_resources_audited_html()

        inventory = self._load_pentest_inventory()
        if not inventory:
            return "<p>No inventory data available.</p>"

        region = str(inventory.get("region") or getattr(self.config, "aws_region", "unknown"))
        regional = inventory.get("regional_resources") or {}
        global_res = inventory.get("global_resources") or {}
        errors = inventory.get("errors") or {}

        regional_services = [
            ("EC2 instances", int(regional.get("ec2_instances", 0))),
            ("RDS instances", int(regional.get("rds_instances", 0))),
            ("Load balancers", int(regional.get("load_balancers", 0))),
            ("Lambda functions", int(regional.get("lambda_functions", 0))),
            ("VPCs", int(regional.get("vpcs", 0))),
            ("DynamoDB tables", int(regional.get("dynamodb_tables", 0))),
            ("ECS clusters", int(regional.get("ecs_clusters", 0))),
            ("EKS clusters", int(regional.get("eks_clusters", 0))),
            ("DocumentDB clusters", int(regional.get("documentdb_clusters", 0))),
        ]

        global_services = [
            ("S3 buckets", int(global_res.get("s3_buckets", 0))),
            ("IAM users", int(global_res.get("iam_users", 0))),
            ("IAM roles", int(global_res.get("iam_roles", 0))),
            ("IAM customer policies", int(global_res.get("iam_policies", 0))),
            ("Route53 hosted zones", int(global_res.get("route53_hosted_zones", 0))),
            ("CloudFront distributions", int(global_res.get("cloudfront_distributions", 0))),
        ]

        def li(text: str) -> str:
            return f"<li>{html.escape(text)}</li>"

        out = [
            f"<p><strong>Audit region:</strong> {html.escape(region)}</p>",
            "<h3>Regional Resources</h3>",
            "<ul>",
        ]
        out.extend(li(f"{name}: {count}") for name, count in regional_services)
        out.append("</ul>")
        out.append("<h3>Global Resources</h3>")
        out.append("<ul>")
        out.extend(li(f"{name}: {count}") for name, count in global_services)
        out.append("</ul>")

        if isinstance(errors, dict) and errors:
            out.append("<h3>Collection Warnings</h3>")
            out.append("<ul>")
            out.extend(li(f"{k}: {v}") for k, v in sorted(errors.items()))
            out.append("</ul>")

        return "".join(out)

    def _inventory_environment_section_html(self) -> str:
        if str(getattr(self.config, "report_type", "general")).lower() != "pentest":
            return ""

        inventory = self._load_pentest_inventory()
        if not inventory:
            return ""

        narrative = build_environment_narrative(self.session.base_path, inventory)
        if not narrative:
            return ""

        return (
            "<div class='card'>"
            "<h3>Environment Description (Inferred)</h3>"
            f"<p>{html.escape(narrative)}</p>"
            "</div>"
        )

    def _load_pentest_inventory(self) -> Dict[str, Any]:
        inventory_path = self.session.base_path / "evidence" / "pentest" / "inventory-summary.json"
        if not inventory_path.exists():
            return {}
        try:
            with open(inventory_path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

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
        import os

        access_key = getattr(self.config, "aws_access_key_id", None)
        if isinstance(access_key, str) and access_key:
            return f"{access_key[:4]}...{access_key[-4:]}"
        if getattr(self.config, "aws_profile", None):
            return f"Profile: {self.config.aws_profile}"
        if getattr(self.config, "aws_credentials_file", None):
            # Load the real key from the file and show it masked (AKID****XXXX)
            try:
                key_id, _, _ = self.config.get_aws_credentials()
                if isinstance(key_id, str) and key_id:
                    return f"{key_id[:4]}...{key_id[-4:]}"
            except Exception:
                pass
            return f"File: {self.config.aws_credentials_file}"

        env_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        if isinstance(env_access_key, str) and env_access_key:
            return f"{env_access_key[:4]}...{env_access_key[-4:]}"

        return "Environment variables"

    def _severity_distribution_chart_html(self, summary: Dict[str, Any]) -> str:
        total = max(1, int(summary.get("total_findings", 0)))
        rows = []
        for sev in ["Critical", "High", "Medium", "Low"]:
            count = int(summary.get(sev.lower(), 0))
            pct = int((count / total) * 100)
            rows.append(
                "<tr>"
                f"<td><span class='severity-pill severity-{sev.lower()}'>{sev}</span></td>"
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

        # For pentest reports, sort by phase (execution order); otherwise by severity
        is_pentest = str(getattr(self.config, "report_type", "general")) == "pentest"
        sort_key = self._finding_phase_sort_key if is_pentest else self._finding_sort_key
        ordered = sorted(findings, key=sort_key)

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
                f"<td><span class='severity-pill severity-{severity.lower()}'>{severity}</span></td>"
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

        sorted_corrs = sorted(
            correlations, key=lambda x: x.get("compound_risk_score", 0), reverse=True
        )
        blocks = []
        for corr in sorted_corrs[:10]:
            blocks.append(self._correlation_card_html(corr))

        intro_html = (
            "<p class='phase-description'><strong>Focus areas:</strong> multi-step compromise logic | "
            "cross-skill chaining | compound business impact | remediation sequencing</p>"
            "<div class='finding-description'>"
            "<p><strong>What this section is:</strong> each attack chain links independent findings into a "
            "single adversarial storyline, from initial foothold to privilege expansion, lateral movement, "
            "and potential business impact.</p>"
            "<p><strong>Why it matters:</strong> isolated findings can appear manageable, but chained "
            "weaknesses show how a realistic attacker combines them to reach high-impact outcomes.</p>"
            "<p><strong>How to use it:</strong> prioritize remediation by chain and break any critical step "
            "to collapse the full path, starting with internet-exposed entry points and privilege-escalation "
            "pivots.</p>"
            "</div>"
        )

        return f"<h2>Attack Chains ({len(correlations)})</h2>" + intro_html + "".join(blocks)

    def _correlation_card_html(self, corr: Dict[str, Any]) -> str:
        """Render a correlation as a full finding card (same depth as technical findings)."""
        corr_id = html.escape(str(corr.get("id", "CORR")))
        title = html.escape(str(corr.get("title", "Attack chain")))
        severity = html.escape(str(corr.get("severity", "High")))
        risk = float(corr.get("compound_risk_score", 0.0))
        desc = self._md_bold_to_html(
            html.escape(str(corr.get("description", ""))).replace("\n\n", "</p><p>")
        )
        pattern_id = html.escape(str(corr.get("pattern_id", "N/A")))

        # CVSS
        cvss = corr.get("cvss") or {}
        cvss_score = float(cvss.get("base_score", risk))
        cvss_vector = html.escape(str(cvss.get("vector_string", "N/A")))

        # MITRE ATT&CK
        threat = corr.get("threat_context") or {}
        tactics = ", ".join(threat.get("mitre_attack_tactics", [])) or "N/A"
        techniques = ", ".join(threat.get("mitre_attack_techniques", [])) or "N/A"

        # Attack path
        attack_path = corr.get("attack_path") or []
        if attack_path:
            path_items = "".join(f"<li>{html.escape(str(step))}</li>" for step in attack_path)
            path_html = f"<ol class='attack-path-list'>{path_items}</ol>"
        else:
            path_html = "<p>N/A</p>"

        # Source findings
        source_findings = corr.get("source_findings") or []
        source_items = []
        for sf in source_findings:
            if isinstance(sf, dict):
                sf_id = html.escape(str(sf.get("id", "?")))
                sf_title = html.escape(str(sf.get("title", "Unknown")))
                sf_sev = html.escape(str(sf.get("severity", "?")))
                sf_score = float(sf.get("risk_score", 0))
                source_items.append(
                    f"<li><code>{sf_id}</code> ({sf_sev}, {sf_score:.1f}): {sf_title}</li>"
                )
            else:
                source_items.append(f"<li>{html.escape(str(sf))}</li>")
        # Fallback to source_finding_ids
        if not source_items:
            for sid in corr.get("source_finding_ids") or []:
                source_items.append(f"<li><code>{html.escape(str(sid))}</code></li>")
        source_html = (
            "<ul>" + "".join(source_items) + "</ul>"
            if source_items
            else "<p>Evidence-based pattern (no individual source findings)</p>"
        )

        # Exploitation details
        exploit = corr.get("exploitability") or {}
        exploit_steps = exploit.get("exploitation_steps") or attack_path or []
        if exploit_steps:
            steps_items = "".join(f"<li>{html.escape(str(step))}</li>" for step in exploit_steps)
            steps_html = f"<ol>{steps_items}</ol>"
        else:
            steps_html = "<p>See attack path above</p>"

        complexity = html.escape(str(exploit.get("exploitation_complexity", "N/A")))
        est_time = html.escape(str(exploit.get("estimated_time_to_compromise", "N/A")))
        tools = ", ".join(exploit.get("tools_required", [])) or "N/A"

        # Technical impact / blast radius
        impact = corr.get("technical_impact") or {}
        blast = impact.get("blast_radius") or {}
        if blast:
            blast_parts = []
            for k, v in blast.items():
                blast_parts.append(f"{html.escape(str(k))}: {html.escape(str(v))}")
            blast_line = "; ".join(blast_parts) if blast_parts else "N/A"
        else:
            blast_line = "N/A"

        # Affected resources
        affected = corr.get("affected_resources") or []
        res_items = "".join(
            f"<li><code>{html.escape(str(res))}</code></li>" for res in affected[:8]
        )

        # Remediation
        remediation_steps = corr.get("remediation_steps") or []
        if remediation_steps:
            rem_items = "".join(f"<li>{html.escape(str(step))}</li>" for step in remediation_steps)
            remediation_html = f"<ol>{rem_items}</ol>"
        else:
            remediation_html = "<p>N/A</p>"

        priority = html.escape(str(corr.get("remediation_priority", "N/A")))

        # Conditionally render affected resources
        affected_block = ""
        if res_items:
            affected_block = (
                f"<div class='finding-resources finding-affected'><h4>Affected Resources</h4>"
                f"<ul class='resource-list'>{res_items}</ul></div>"
            )

        # Conditionally render blast radius
        impact_block = ""
        if blast_line and blast_line != "N/A":
            impact_block = (
                f"<div class='finding-impact'><h4>Technical Impact</h4>"
                f"<p><strong>Blast radius:</strong> {blast_line}</p></div>"
            )

        # Conditionally render priority
        priority_line = ""
        if priority and priority not in ("N/A", "None", ""):
            priority_line = f"<p><strong>Priority:</strong> {priority}</p>"

        return (
            "<div class='individual-finding'>"
            f"<h3>[{corr_id}] {title}</h3>"
            f"<p><strong>Severity:</strong> "
            f"<span class='severity-pill severity-{severity.lower()}'>{severity}</span> | "
            f"<strong>Compound Risk:</strong> {risk:.1f}/10 | "
            f"<strong>CVSS 3.1:</strong> {cvss_score:.1f} ({cvss_vector})</p>"
            f"<p><strong>Pattern:</strong> <code>{pattern_id}</code></p>"
            f"<div class='finding-description'><h4>Description</h4><p>{desc}</p></div>"
            f"<div class='finding-mitre'><h4>MITRE ATT&amp;CK</h4>"
            f"<p><strong>Tactics:</strong> {html.escape(tactics)}<br>"
            f"<strong>Techniques:</strong> {html.escape(techniques)}</p></div>"
            f"<div class='finding-attack-path'><h4>Attack Path</h4>{path_html}</div>"
            f"<div class='finding-sources'><h4>Source Findings</h4>{source_html}</div>"
            f"<div class='finding-exploitation'><h4>Exploitation Details</h4>"
            f"{steps_html}"
            f"<p><strong>Complexity:</strong> {complexity} | "
            f"<strong>Estimated time:</strong> {est_time} | "
            f"<strong>Tools:</strong> {html.escape(tools)}</p></div>"
            + impact_block
            + affected_block
            + f"<div class='finding-remediation'><h4>Remediation</h4>{remediation_html}</div>"
            + priority_line
            + "</div>"
        )

    # Phase sections mirroring PentestFormatter._PHASE_SECTIONS (markdown)
    _PENTEST_PHASE_SECTIONS = [
        {
            "phase": "Phase 1 — Reconnaissance",
            "skill": "recon",
            "prefixes": ("RECON-",),
            "description": "External attack surface mapping across public entry points, DNS, and API exposure.",
            "focus_text": "Map all externally reachable assets and public attack surfaces, including DNS records, exposed endpoints, and API stages, to establish realistic entry vectors and unauthenticated discovery opportunities.",
            "objective": "Establish a realistic initial-access baseline by identifying externally discoverable services and unmanaged exposure points.",
            "what_was_evaluated": "Public endpoints, DNS intelligence, API stage exposure, and externally reachable service metadata.",
            "why_this_matters": "Reconnaissance findings define the attacker starting point and prioritize the controls that reduce first-contact compromise risk.",
        },
        {
            "phase": "Phase 2 — Identity &amp; Access Management",
            "skill": "iam",
            "prefixes": ("IAM-",),
            "description": "Privilege escalation paths, cross-account trust, credential hygiene.",
            "focus_text": "Assess identity trust boundaries by analyzing overprivileged principals, role assumption chains, cross-account trust policies, root-account safeguards, and credential lifecycle controls (key age, MFA, rotation, and policy scoping).",
            "objective": "Validate whether identity controls enforce least privilege and resist abuse of trust relationships.",
            "what_was_evaluated": "Role trust policies, privileged policy grants, root-account controls, MFA posture, and credential hygiene indicators.",
            "why_this_matters": "Identity misconfigurations are high-leverage pivots that can transform limited access into broad account compromise.",
        },
        {
            "phase": "Phase 2 — External Exposure",
            "skill": "exposure",
            "prefixes": ("EXP-",),
            "description": "Public-facing resources, open S3 buckets, public snapshots.",
            "focus_text": "Identify unintended internet exposure across data and service planes, including public storage artifacts, exposed management interfaces, and weak resource policies that can enable anonymous access or unauthorized external interaction.",
            "objective": "Confirm that internet-facing resources and data planes are intentionally exposed and appropriately protected.",
            "what_was_evaluated": "Public buckets/snapshots, externally accessible interfaces, and resource policies that permit anonymous or cross-account interaction.",
            "why_this_matters": "Unintended exposure creates immediate attack paths and direct data-loss scenarios without requiring deep internal footholds.",
        },
        {
            "phase": "Phase 2 — Network Security",
            "skill": "network",
            "prefixes": ("NET-",),
            "description": "Lateral movement paths, missing firewalls, unrestricted egress.",
            "focus_text": "Evaluate segmentation and containment posture by tracing possible lateral movement routes, permissive ingress/egress rules, missing inspection layers, and trust-path combinations that could expand compromise across VPC boundaries.",
            "objective": "Measure how effectively network controls contain compromise and block unauthorized east-west movement.",
            "what_was_evaluated": "Segmentation boundaries, permissive Security Group/NACL patterns, egress controls, and inspection coverage gaps.",
            "why_this_matters": "Weak containment allows a single exposed workload to become a pivot into broader infrastructure compromise.",
        },
        {
            "phase": "Phase 2 — Vulnerabilities",
            "skill": "vulns",
            "prefixes": ("VULN-",),
            "description": "CVEs, missing patches, insecure runtime configurations.",
            "focus_text": "Prioritize exploitable technical weaknesses using Inspector-derived vulnerability intelligence, patching status, exploitability context, and runtime hardening signals to estimate likelihood and operational impact.",
            "objective": "Prioritize vulnerabilities by exploitability and business impact instead of raw volume.",
            "what_was_evaluated": "Inspector v2 findings, patch/remediation status, exploitability indicators, and runtime hardening posture.",
            "why_this_matters": "Risk-ranked vulnerability context enables faster remediation of issues most likely to produce practical compromise.",
        },
        {
            "phase": "Phase 2 — Secrets Management",
            "skill": "secretsmanager",
            "prefixes": ("SM-",),
            "description": "Secrets rotation, access policies, monitoring gaps.",
            "focus_text": "Review secret governance controls, including rotation enforcement, least-privilege access policies, stale credential exposure risk, and monitoring coverage for high-impact retrieval or misuse events.",
            "objective": "Verify that secret lifecycle and access controls prevent credential misuse and long-lived exposure.",
            "what_was_evaluated": "Rotation enforcement, policy scope, stale secret risk, and monitoring for high-risk secret retrieval patterns.",
            "why_this_matters": "Secret-management failures can provide durable access that bypasses perimeter and workload hardening controls.",
        },
    ]

    def _phase_description_html(self, section: Dict[str, Any]) -> str:
        """Render editorial phase context below each phase title."""
        objective = str(section.get("objective", "")).strip()
        evaluated = str(section.get("what_was_evaluated", "")).strip()
        why = str(section.get("why_this_matters", "")).strip()
        if objective or evaluated or why:
            details: List[str] = []
            if objective:
                details.append(f"<p><strong>Objective:</strong> {html.escape(objective)}</p>")
            if evaluated:
                details.append(
                    f"<p><strong>What was evaluated:</strong> {html.escape(evaluated)}</p>"
                )
            if why:
                details.append(f"<p><strong>Why this matters:</strong> {html.escape(why)}</p>")
            return "<div class='phase-description'>" + "".join(details) + "</div>"

        focus_text = str(section.get("focus_text", "")).strip()
        if focus_text:
            return f"<p class='phase-description'><strong>Focus areas:</strong> {html.escape(focus_text)}</p>"

        focus_areas = section.get("focus_areas")
        if isinstance(focus_areas, list) and focus_areas:
            clean_areas = [str(item).strip() for item in focus_areas if str(item).strip()]
            if clean_areas:
                focus = " | ".join(html.escape(item) for item in clean_areas)
                return f"<p class='phase-description'><strong>Focus areas:</strong> {focus}</p>"

        description = str(section.get("description", "")).strip()
        if not description:
            return ""
        return (
            "<p class='phase-description'>"
            "<strong>Focus areas:</strong> "
            f"{html.escape(description)}"
            "</p>"
        )

    def _skill_for_finding_pdf(self, finding: Dict[str, Any]) -> str:
        fid = str(finding.get("id", ""))
        for section in self._PENTEST_PHASE_SECTIONS:
            if any(fid.startswith(p) for p in section["prefixes"]):
                return section["skill"]
        return "other"

    def _findings_by_phase_html(self, findings: List[Dict[str, Any]]) -> str:
        """Pentest-only: render findings grouped by methodology phase/skill."""
        if not findings:
            return "<p>No findings detected.</p>"

        grouped = self._group_reportable_pentest_findings(findings)
        other: List[Dict[str, Any]] = []
        for f in findings:
            sk = self._skill_for_finding_pdf(f)
            if sk == "other":
                other.append(f)

        sections_html = []

        for section in self._PENTEST_PHASE_SECTIONS:
            items = grouped.get(section["skill"], [])
            if not items:
                continue
            items_sorted = sorted(
                items, key=lambda f: float(f.get("risk_score", 0.0)), reverse=True
            )
            phase_header = f"<h2>{section['phase']}</h2>{self._phase_description_html(section)}"
            section_block = ["<div class='phase-section'>", phase_header]
            for finding in items_sorted:
                section_block.append(self._finding_card_html(finding))
            section_block.append("</div>")
            sections_html.append("".join(section_block))

        if other:
            section_block = ["<div class='phase-section'>", "<h2>Other Findings</h2>"]
            for finding in other:
                section_block.append(self._finding_card_html(finding))
            section_block.append("</div>")
            sections_html.append("".join(section_block))

        return "".join(sections_html)

    def _phase_findings_table_html(self, findings: List[Dict[str, Any]]) -> str:
        """Pentest-only: compact phase/skill counts table for Risk Analysis."""
        if not findings:
            return ""

        grouped = self._group_reportable_pentest_findings(findings)

        table_rows = []
        total_c = total_h = total_m = total_l = 0
        for section in self._PENTEST_PHASE_SECTIONS:
            items = grouped.get(section["skill"], [])
            if not items:
                continue
            c = sum(1 for f in items if f.get("severity") == "Critical")
            h = sum(1 for f in items if f.get("severity") == "High")
            m = sum(1 for f in items if f.get("severity") == "Medium")
            lo = sum(1 for f in items if f.get("severity") == "Low")
            total_c += c
            total_h += h
            total_m += m
            total_l += lo
            phase_label = section["phase"]
            phase_class = "phase-pill-2"
            if phase_label.startswith("Phase 1"):
                phase_class = "phase-pill-1"
            table_rows.append(
                f"<tr><td><span class='phase-pill {phase_class}'>{phase_label}</span></td><td>{len(items)}</td>"
                f"<td>{c}</td><td>{h}</td><td>{m}</td><td>{lo}</td></tr>"
            )

        if not table_rows:
            return ""

        return (
            "<h3>Findings by Phase</h3>"
            "<table class='findings-summary-table phase-summary-table'>"
            "<thead><tr><th>Phase</th><th>Total</th>"
            "<th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>"
            "<tbody>"
            + "".join(table_rows)
            + f"<tr class='totals-row'><td><strong>TOTAL</strong></td>"
            f"<td><strong>{total_c + total_h + total_m + total_l}</strong></td>"
            f"<td><strong>{total_c}</strong></td><td><strong>{total_h}</strong></td>"
            f"<td><strong>{total_m}</strong></td><td><strong>{total_l}</strong></td></tr>"
            "</tbody></table>"
        )

    def _attack_path_candidates_table_html(self) -> str:
        """Pentest-only: render attack path candidates from evidence if present."""
        docs = self._load_attack_path_candidate_docs()
        if not docs:
            return ""

        rows: List[Dict[str, Any]] = []
        for skill_name, payload in docs:
            paths = payload.get("paths") if isinstance(payload, dict) else None
            if not isinstance(paths, list):
                continue
            for p in paths:
                if not isinstance(p, dict):
                    continue
                row = dict(p)
                row["_skill"] = skill_name
                rows.append(row)

        if not rows:
            return ""

        rows = sorted(rows, key=lambda p: float(p.get("overall_score") or 0.0), reverse=True)[:10]
        out = [
            "<h3>Attack Path Candidates</h3>",
            "<table class='findings-summary-table'>",
            "<thead><tr><th>ID</th><th>Skill</th><th>Entry</th><th>Target</th><th>Overall</th></tr></thead>",
            "<tbody>",
        ]
        for row in rows:
            pid = html.escape(str(row.get("id") or "N/A"))
            skill = html.escape(str(row.get("_skill") or "unknown"))
            entry = html.escape(str(row.get("entry_point") or "internet"))
            target = html.escape(str(row.get("target_resource") or "N/A"))
            if len(target) > 90:
                target = target[:45] + "..." + target[-42:]
            overall = float(row.get("overall_score") or 0.0)
            out.append(
                f"<tr><td>{pid}</td><td>{skill}</td><td>{entry}</td><td><code>{target}</code></td><td><strong>{overall:.2f}</strong></td></tr>"
            )
        out.append("</tbody></table>")
        return "".join(out)

    def _load_attack_path_candidate_docs(self) -> List[tuple[str, Dict[str, Any]]]:
        evidence_root = self.session.base_path / "evidence"
        if not evidence_root.exists():
            return []

        docs: List[tuple[str, Dict[str, Any]]] = []
        skill = str(self.findings.get("skill") or "")
        if skill and skill != "aggregated":
            p = evidence_root / skill / "attack-path-candidates.json"
            if p.exists():
                try:
                    with open(p) as f:
                        payload = json.load(f)
                    if isinstance(payload, dict):
                        docs.append((skill, payload))
                except Exception:
                    pass
            return docs

        for skill_dir in evidence_root.iterdir():
            if not skill_dir.is_dir():
                continue
            p = skill_dir / "attack-path-candidates.json"
            if not p.exists():
                continue
            try:
                with open(p) as f:
                    payload = json.load(f)
                if isinstance(payload, dict):
                    docs.append((skill_dir.name, payload))
            except Exception:
                continue

        return docs

    def _group_reportable_pentest_findings(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group pentest findings by phase skill excluding informational-only observations."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for finding in findings:
            if self._is_non_applicable_pentest_finding(finding):
                continue
            sk = self._skill_for_finding_pdf(finding)
            if sk != "other":
                grouped.setdefault(sk, []).append(finding)
        return grouped

    def _is_non_applicable_pentest_finding(self, finding: Dict[str, Any]) -> bool:
        desc = str(finding.get("description", "")).lower()
        rem = str(finding.get("remediation", "")).lower()
        if any(k in desc for k in ["does not apply", "no action required", "no aplica"]):
            return True
        if any(k in rem for k in ["no action required", "no se requiere acción"]):
            return True
        return (
            isinstance(finding.get("affected_resources"), list)
            and len(finding.get("affected_resources", [])) == 0
            and not finding.get("evidence_snippet")
        )

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
        description = self._md_bold_to_html(
            html.escape(str(finding.get("description", ""))).replace("\n\n", "</p><p>")
        )
        remediation = self._md_bold_to_html(
            html.escape(str(finding.get("remediation", ""))).replace("\n\n", "</p><p>")
        )
        cis_ref = html.escape(str(finding.get("cis_reference", "N/A")))

        raw_impact = finding.get("impact")
        impact_html = ""
        if raw_impact:
            impact_text = self._md_bold_to_html(
                html.escape(str(raw_impact)).replace("\n\n", "</p><p>")
            )
            impact_html = f"<div class='finding-impact'><h4>Impact</h4><p>{impact_text}</p></div>"

        evidence_snippet = finding.get("evidence_snippet")
        skill = str(self.findings.get("skill", "")).lower()
        is_ser = skill == "sistemas_explotables_red"
        has_cve_intel = isinstance(evidence_snippet, dict) and (
            "cve_details" in evidence_snippet or "attack_paths" in evidence_snippet
        )
        snippet_for_json = evidence_snippet
        if is_ser and isinstance(evidence_snippet, dict):
            snippet_for_json = {
                k: v
                for k, v in evidence_snippet.items()
                if k not in ("cve_details", "attack_paths")
            }

        resources = finding.get("affected_resources", [])[:8]

        commands, commands_suggested = self._collect_validation_commands(finding)
        is_pentest_report = str(getattr(self.config, "report_type", "general")) == "pentest"
        exploitation_block = (
            self._exploitation_block_html(finding, commands) if is_pentest_report else ""
        )

        exploit_status = finding.get("exploitability_status")
        _exploit_styles = {
            "validated": "background:#fee2e2;color:#991b1b;border:1px solid #fca5a5",
            "probable": "background:#fef9c3;color:#854d0e;border:1px solid #fde047",
            "theoretical": "background:#f3f4f6;color:#374151;border:1px solid #d1d5db",
        }
        _default_style = _exploit_styles["theoretical"]
        if exploit_status:
            _style = _exploit_styles.get(exploit_status, _default_style)
            exploit_badge_html = (
                "<span style='padding:2px 8px;border-radius:12px;font-size:0.8em;font-weight:700;"
                + _style
                + "'>"
                + exploit_status.title()
                + "</span>"
            )
        else:
            exploit_badge_html = ""

        exploit_suffix = (
            f" | <strong>Exploitability:</strong> {exploit_badge_html}"
            if exploit_badge_html
            else ""
        )
        severity_line = (
            f"<p><strong>Risk Score:</strong> {risk:.1f}/10 | <strong>Severity:</strong> "
            f"<span class='severity-pill severity-{severity.lower()}'>{severity}</span>"
            f"{exploit_suffix}</p>"
        )

        analogy = finding.get("security_analogy")

        attack_vector_block = ""
        if is_ser and has_cve_intel:
            attack_vector_block = self._ser_attack_vector_html(finding)

        cis_line = ""
        if cis_ref and cis_ref not in ("N/A", "None", "", "n/a"):
            cis_line = f"<p><strong>CIS Reference:</strong> {cis_ref}</p>"

        # Build description with analogy as final paragraph (no standalone callout box)
        description_html = f"<p>{description}</p>"
        if analogy:
            analogy_html = self._md_bold_to_html(html.escape(str(analogy)))
            description_html += f"<p><em><strong>Analogy:</strong> {analogy_html}</em></p>"

        if resources:
            affected_text = "\n".join(str(res) for res in resources)
            description_html += (
                "<div class='finding-inline-section finding-affected'><h4>Affected Resources</h4>"
                f"<pre class='code-block'>{html.escape(affected_text)}</pre></div>"
            )

        if commands:
            heading = (
                "Validation Commands (AWS CLI Suggested)"
                if commands_suggested
                else "Validation Commands"
            )
            commands_text = "\n".join(commands)
            description_html += (
                "<div class='finding-inline-section finding-validation'><h4>"
                f"{html.escape(heading)}"
                "</h4>"
                f"<pre class='code-block'>{html.escape(commands_text)}</pre></div>"
            )

        if snippet_for_json:
            dumped = json.dumps(snippet_for_json, indent=2, ensure_ascii=False)
            description_html += (
                "<div class='finding-inline-section finding-evidence'><h4>Evidence</h4>"
                f"<pre class='code-block'>{html.escape(dumped)}</pre></div>"
            )

        return (
            "<div class='individual-finding'>"
            + f"<h3>[{finding_id}] {title}</h3>"
            + severity_line
            + f"<div class='finding-description'><h4>Description</h4>{description_html}</div>"
            + attack_vector_block
            + exploitation_block
            + impact_html
            + f"<div class='finding-remediation'><h4>Remediation</h4><p>{remediation}</p></div>"
            + cis_line
            + "</div>"
        )

    def _ser_attack_vector_html(self, finding: Dict[str, Any]) -> str:
        snippet = finding.get("evidence_snippet") or {}
        if not isinstance(snippet, dict):
            return ""

        attack_paths = snippet.get("attack_paths", {})
        if not isinstance(attack_paths, dict) or not attack_paths:
            return ""

        cve_details = snippet.get("cve_details", [])
        network_cve_ids: List[str] = []
        if isinstance(cve_details, list):
            for cve in cve_details:
                if not isinstance(cve, dict):
                    continue
                if str(cve.get("attack_vector", "")).upper() != "NETWORK":
                    continue
                cve_id = str(cve.get("id", "")).strip()
                if cve_id:
                    network_cve_ids.append(cve_id)

        blocks: List[str] = ["<div class='finding-exploitation'><h4>Attack Vector Playbook</h4>"]
        for iid, path_data in list(attack_paths.items())[:3]:
            if not isinstance(path_data, dict):
                continue
            narrative = str(path_data.get("narrative", "")).strip()
            steps = path_data.get("steps", []) if isinstance(path_data.get("steps"), list) else []

            lead = f"For instance {iid}, the exploitation flow starts from internet reachability and progresses into cloud credential abuse."
            if narrative:
                lead = f"For instance {iid}, {narrative}"
            blocks.append(f"<p>{html.escape(lead)}</p>")
            blocks.append(
                "<p>The attacker validates exposed services, gains execution via a remotely reachable weakness, "
                "queries IMDS for temporary role credentials, and reuses those credentials for lateral movement "
                "or data access in AWS.</p>"
            )
            if steps:
                step_items = []
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    action = str(step.get("action", "")).strip()
                    if not action:
                        continue
                    technique = str(step.get("technique", "")).strip()
                    suffix = f" ({technique})" if technique else ""
                    step_items.append(f"<li>{html.escape(action + suffix)}</li>")
                if step_items:
                    blocks.append("<ol>" + "".join(step_items) + "</ol>")

            blocks.append(
                "<p><strong>Concepts:</strong> IMDS can expose temporary IAM credentials from inside the instance; "
                "lateral movement means reusing those credentials to reach other AWS resources; blast radius is "
                "the scope of impact enabled by those permissions.</p>"
            )

            research_text = (
                "For internet research, validate each advisory with NVD/CVE entries, vendor bulletins, and CISA "
                "KEV when applicable; confirm exploit preconditions and affected versions; then map those "
                "requirements against observed ports, security groups, and package versions in evidence."
            )
            if network_cve_ids:
                research_text += " Prioritize: " + ", ".join(network_cve_ids[:6]) + "."
            blocks.append(
                f"<p><strong>Research workflow:</strong> {html.escape(research_text)}</p>"
            )

        blocks.append("</div>")
        return "".join(blocks)

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
                affected_resources=[str(r) for r in (finding.get("affected_resources", []) or [])],
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
            f"<div class='finding-resources finding-validation'><h4>{heading}</h4>"
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
            exploit_text = "\n".join(exploit_commands[:5])
            cmd_html = (
                "<h4>Exploitation Commands</h4>"
                f"<pre class='code-block'>{html.escape(exploit_text)}</pre>"
            )

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
            "<p>This engagement follows a PTES-oriented methodology (Penetration Testing Execution Standard), adapted for AWS control-plane assessments. The workflow is evidence-driven and non-intrusive: Drystone collects AWS-native telemetry/configuration data, validates deterministic security conditions, and models realistic attacker paths without deploying active exploitation payloads into production systems.</p>"
            "<h3>Test Scope and Procedures Executed</h3>"
            "<ul>"
            "<li><strong>IAM assessment:</strong> users, roles, policies, trust relationships, root posture, MFA coverage, and privilege-escalation opportunities.</li>"
            "<li><strong>Exposure assessment:</strong> internet-reachable services, public buckets/snapshots, exposed entry points, and externally accessible management surfaces.</li>"
            "<li><strong>Network assessment:</strong> segmentation controls (Security Groups/NACLs), lateral movement paths, permissive ingress/egress rules, and trust-boundary weaknesses.</li>"
            "<li><strong>Vulnerability assessment:</strong> AWS Inspector v2 outputs, exploitable CVEs, remediation coverage, and runtime hardening gaps.</li>"
            "<li><strong>Secrets assessment:</strong> Secrets Manager rotation status, policy scope, and monitoring coverage for high-impact secret access patterns.</li>"
            "</ul>"
            "<h3>Evidence and Validation Model</h3>"
            "<ul>"
            "<li><strong>Source of evidence:</strong> direct AWS API responses captured as raw JSON per skill and retained for traceability.</li>"
            "<li><strong>Deterministic pre-checks:</strong> reproducible rule checks validate objective controls before AI interpretation.</li>"
            "<li><strong>Analyst/AI interpretation:</strong> findings are enriched with risk context, exploitability stance, and remediation guidance.</li>"
            "<li><strong>Cross-skill correlation:</strong> findings are linked into attack chains that represent realistic end-to-end compromise scenarios.</li>"
            "</ul>"
            "<h3>Reporting Phases Used in This Report</h3>"
            "<ol>"
            "<li><strong>Phase 1 - Reconnaissance:</strong> external attack surface mapping (DNS, public endpoints, APIs).</li>"
            "<li><strong>Phase 2 - Analysis:</strong> findings grouped by skill domain (IAM, Exposure, Network, Vulnerabilities, and Secrets).</li>"
            "<li><strong>Phase 3 - Correlation + Reporting:</strong> attack-chain correlation, risk synthesis, and remediation plan.</li>"
            "</ol>"
            "<h3>PTES Mapping (Execution Backbone)</h3>"
            "<ul>"
            "<li><strong>Pre-Engagement + Intelligence Gathering</strong> -> <strong>Report Phase 1</strong></li>"
            "<li><strong>Threat Modeling + Vulnerability Analysis + Theoretical Exploitation + Post-Exploitation</strong> -> <strong>Report Phase 2</strong></li>"
            "<li><strong>Reporting</strong> -> <strong>Report Phase 3</strong></li>"
            "</ul>"
            "<p><strong>Compliance-ready method evidence:</strong> this workflow is structured to satisfy methodology expectations commonly required by PCI DSS, ISO 27001, and SOC 2 by producing scoped procedures, repeatable control validation, traceable evidence references, and risk-prioritized remediation outputs.</p>"
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

    def _risk_scale_html(self, summary: Dict[str, Any]) -> str:
        """Generate risk scale section with visual bar and definitions table."""
        risk_score = float(summary.get("overall_risk_score", 0.0))
        lang = str(getattr(self.config, "report_language", "en") or "en").lower()

        if lang == "es":
            levels = [
                ("Apropiado", "#16a34a", "0 hallazgos", "Sin acción requerida", "rs-appropriate"),
                (
                    "Bajo",
                    "#22c55e",
                    "0.0 – 2.9",
                    "Mejoras menores, planificación regular",
                    "rs-low",
                ),
                ("Medio", "#eab308", "3.0 – 5.9", "Remediación en 30 días", "rs-medium"),
                ("Alto", "#f97316", "6.0 – 8.4", "Remediación urgente (7 días)", "rs-high"),
                (
                    "Crítico",
                    "#dc2626",
                    "8.5 – 10.0",
                    "Riesgo de explotación inmediata",
                    "rs-critical",
                ),
            ]
            header = "Escala de Riesgo"
            col_headers = ("Nivel", "Rango", "Acción Requerida")
        else:
            levels = [
                ("Appropriate", "#16a34a", "0 findings", "No action required", "rs-appropriate"),
                ("Low", "#22c55e", "0.0 – 2.9", "Minor improvements, regular cycle", "rs-low"),
                ("Medium", "#eab308", "3.0 – 5.9", "Remediation within 30 days", "rs-medium"),
                ("High", "#f97316", "6.0 – 8.4", "Urgent remediation (7 days)", "rs-high"),
                ("Critical", "#dc2626", "8.5 – 10.0", "Immediate exploitation risk", "rs-critical"),
            ]
            header = "Risk Scale"
            col_headers = ("Level", "Range", "Required Action")

        # Calculate indicator position (0-100%)
        indicator_pct = min(max(risk_score / 10.0 * 100, 0), 100)
        # Map to the correct segment (5 segments, each 20%)
        segment_idx = 0
        if risk_score > 0:
            if risk_score < 3.0:
                segment_idx = 1
            elif risk_score < 6.0:
                segment_idx = 2
            elif risk_score < 8.5:
                segment_idx = 3
            else:
                segment_idx = 4

        # Build bar segments with indicator
        bar_segments = []
        for i, (_, color, _, _, css_class) in enumerate(levels):
            indicator = ""
            if i == segment_idx:
                # Position within segment (each segment is 20% width)
                if i == 0:
                    inner_pct = 50  # center for "appropriate"
                else:
                    seg_ranges = [(0, 0), (0, 2.9), (3.0, 5.9), (6.0, 8.4), (8.5, 10.0)]
                    lo, hi = seg_ranges[i]
                    span = max(hi - lo, 0.1)
                    inner_pct = min(((risk_score - lo) / span) * 100, 100)
                indicator = (
                    f"<div class='risk-scale-indicator' style='left:{inner_pct:.0f}%'></div>"
                )
            bar_segments.append(
                f"<div class='rs-segment {css_class}' style='position:relative'>{indicator}</div>"
            )

        bar_html = "<div class='risk-scale-bar'>" + "".join(bar_segments) + "</div>"

        # Build definitions table
        rows = []
        for label, color, range_str, action, _ in levels:
            dot = f"<span class='rs-dot' style='background:{color}'></span>"
            rows.append(
                f"<tr><td>{dot}{html.escape(label)}</td>"
                f"<td>{html.escape(range_str)}</td>"
                f"<td>{html.escape(action)}</td></tr>"
            )

        table = (
            f"<table class='risk-scale-table'>"
            f"<thead><tr><th>{col_headers[0]}</th><th>{col_headers[1]}</th><th>{col_headers[2]}</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

        return (
            f"<h2>{header}</h2>"
            f"<div class='card'>"
            f"<p style='font-size:10px;color:#6b7280;margin-bottom:4px'>"
            f"Current risk score: <strong>{risk_score:.1f}/10.0</strong></p>"
            f"{bar_html}{table}</div>"
        )

    def _document_control_html(self) -> str:
        """Generate document control section with metadata."""
        client = str(self.session.client_name or "Unknown")
        report_date = self.findings.get("analyzed_at", datetime.utcnow().isoformat())
        report_date_clean = report_date.replace("T", " ").split(".")[0]
        date_short = report_date_clean.split(" ")[0]  # YYYY-MM-DD

        # Auto-generate document code
        client_slug = re.sub(r"[^a-zA-Z0-9]", "", client).upper()[:12]
        report_type = str(getattr(self.config, "report_type", "general")).upper()
        type_map = {"GENERAL": "SEC", "PCI-DSS": "PCI", "PENTEST": "IPT"}
        type_code = type_map.get(report_type, "SEC")
        doc_code = f"{client_slug}-{type_code}-{date_short}-v1.0"

        # Client context overrides if available
        client_context = self._get_client_context()
        if client_context:
            code_val = str(getattr(client_context, "code", "") or "")
            if code_val:
                doc_code = code_val
            project_val = str(getattr(client_context, "project", "") or "")
            project_name = project_val if project_val else f"AWS Security Assessment — {client}"
            version_val = str(getattr(client_context, "version", "") or "")
            version = version_val if version_val else "1.0"
            report_date_val = str(getattr(client_context, "report_date", "") or "")
            if report_date_val:
                report_date_clean = report_date_val
        else:
            project_name = f"AWS Security Assessment — {client}"
            version = "1.0"

        def row(label: str, value: str) -> str:
            return (
                "<div class='scope-row'>"
                f"<span class='scope-label'>{html.escape(label)}</span>"
                f"<span class='scope-value'>{html.escape(value)}</span>"
                "</div>"
            )

        fields = [
            ("Document Code", doc_code),
            ("Project", project_name),
            ("Client", client),
            ("Date", report_date_clean),
            ("Version", version),
            ("Classification", "CONFIDENTIAL"),
        ]

        return (
            "<h2>Document Control</h2>"
            "<div class='document-control'>"
            + "".join(row(label, value) for label, value in fields)
            + "</div>"
        )

    def _conditions_section_html(self) -> str:
        """Generate conditions and exclusions section."""
        lang = str(getattr(self.config, "report_language", "en") or "en").lower()

        # Auto-detected conditions
        region = str(getattr(self.config, "aws_region", "unknown"))
        access_key = self._masked_access_key()
        skills_raw = getattr(self.config, "skills", None)
        skills = list(skills_raw) if isinstance(skills_raw, (list, tuple)) else []
        skills_str = ", ".join(str(s).upper() for s in skills) if skills else "N/A"
        scan_depth_raw = getattr(self.config, "scan_depth", "normal")
        scan_depth = (
            str(scan_depth_raw).capitalize() if isinstance(scan_depth_raw, str) else "Normal"
        )

        if lang == "es":
            header = "Condiciones y Exclusiones"
            scope_header = "Alcance de la Evaluación"
            exclusions_header = "Exclusiones"
            default_exclusions = [
                "Pruebas de Denegación de Servicio (DoS/DDoS)",
                "Ingeniería social",
                "Seguridad física",
                "Evaluación limitada al plano de control (control-plane only)",
            ]
        else:
            header = "Conditions &amp; Exclusions"
            scope_header = "Assessment Scope"
            exclusions_header = "Exclusions"
            default_exclusions = [
                "Denial of Service (DoS/DDoS) testing",
                "Social engineering",
                "Physical security assessment",
                "Control-plane only assessment",
            ]

        # Build scope conditions
        scope_items = [
            f"AWS Region: {region}",
            f"Access Key: {access_key}",
            f"Skills evaluated: {skills_str}",
            f"Scan depth: {scan_depth}",
        ]

        # Client context overrides
        client_context = self._get_client_context()
        if client_context:
            extra_conditions = getattr(client_context, "conditions", None)
            if isinstance(extra_conditions, list):
                scope_items.extend(str(c) for c in extra_conditions)
            extra_exclusions = getattr(client_context, "exclusions", None)
            if isinstance(extra_exclusions, list) and extra_exclusions:
                default_exclusions = [str(e) for e in extra_exclusions] + default_exclusions

        scope_list = "".join(f"<li>{html.escape(item)}</li>" for item in scope_items)
        exclusions_list = "".join(f"<li>{html.escape(item)}</li>" for item in default_exclusions)

        return (
            f"<h2>{header}</h2>"
            "<div class='card'>"
            f"<h3>{scope_header}</h3>"
            f"<ul class='conditions-list'>{scope_list}</ul>"
            f"<h3>{exclusions_header}</h3>"
            f"<ul class='conditions-list'>{exclusions_list}</ul>"
            "</div>"
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

    def _pci_dss_annex_html(self) -> str:
        """Generate PCI DSS Annex A HTML block.

        Returns empty string when report_type != 'pci-dss'.
        """
        if getattr(self.config, "report_type", "general") != "pci-dss":
            return ""

        from drystone.reports.formats.pci_dss import build_pci_controls_map, get_requirement_name

        findings = self.findings.get("findings", [])
        skills = list(getattr(self.config, "skills", [])) or [self.findings.get("skill", "unknown")]

        data = build_pci_controls_map(findings, skills)
        controls = data["controls"]
        summary = data["summary"]

        ko_controls = [c for c in controls if c["status"] == "ko"]
        if not ko_controls:
            return ""

        compliance_pct = (
            f"{summary['ok'] / summary['total'] * 100:.0f}%" if summary["total"] else "N/A"
        )

        rows_html = []
        current_req = None
        for ctrl in ko_controls:
            req_num = ctrl["requirement"]
            if req_num != current_req:
                current_req = req_num
                req_name = html.escape(get_requirement_name(req_num))
                rows_html.append(
                    f'<tr class="pci-req-header">'
                    f'<td colspan="3"><strong>Requirement {html.escape(req_num)} · {req_name}</strong></td>'
                    f"</tr>"
                )

            cid = html.escape(ctrl["control"])
            finding = ctrl["findings"][0]
            finding_reason = None
            for p in finding.get("pci_dss") or []:
                if p.get("control") == ctrl["control"]:
                    finding_reason = p.get("reason")
                    break
            reason = finding_reason or ctrl.get("reason", "")
            fid = html.escape(finding.get("id", ""))
            ftitle = html.escape(finding.get("title", ""))
            reason_escaped = html.escape(reason)
            just = f"<strong>{fid}</strong>: {ftitle}. {reason_escaped}" if fid else reason_escaped

            rows_html.append(
                f'<tr><td>{cid}</td><td class="pci-ko">❌ KO</td><td>{just}</td></tr>'
            )

        rows = "\n".join(rows_html)
        return f"""
<div class="page-break"></div>
<h2>Annex A: PCI DSS v4.0 Control Mapping</h2>
<div class="card pci-annex-card">
  <p><strong>Compliance Rate:</strong> {summary["ok"]}/{summary["total"]} controls ({compliance_pct})</p>
  <table class="findings-summary-table pci-annex-table">
    <thead>
      <tr>
        <th style="width:100px">Control</th>
        <th style="width:80px">Status</th>
        <th>Justification</th>
      </tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
  <p style="margin-top:12px;font-size:0.85em">
    ✅ OK — No violations found &nbsp;·&nbsp; ❌ KO — Violations detected (see findings above)
  </p>
</div>"""
