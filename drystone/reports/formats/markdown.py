"""Markdown report formatter."""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from drystone.reports.formats.base import BaseFormatter
from drystone.reports.safety import redact_secrets

logger = logging.getLogger(__name__)


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

        # Include skill name in filename to avoid overwriting when multiple skills
        skill_name = self._report_skill_slug()
        report_path = self.reports_path / f"audit-report-{skill_name}.{self.file_extension}"

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
            self._narrative_executive_summary(),
            self._executive_summary(),
            self._architecture_diagram(),
            self._resources_audited_section(),
            self._correlation_section(),
        ]

        parts.extend(
            [
                self._findings_by_severity(),
                self._observations(),
                self._remediation_timeline(),
                self._references(),
                self._footer(),
                self._pci_dss_annex_md(),
            ]
        )

        # Filter out empty sections
        parts = [p for p in parts if p]
        return "\n\n".join(parts)

    def _is_english_report(self) -> bool:
        return str(getattr(self.config, "report_language", "en")).lower() == "en"

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
            " publica",
            " politicas",
            " auditoria",
            " habilitado",
            " proteccion",
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
        if not self._is_english_report():
            return finding

        out = dict(finding)

        title = str(out.get("title", ""))
        if self._looks_spanish(title):
            out["title"] = self._translate_to_english(title)

        desc = str(out.get("description", ""))
        if self._looks_spanish(desc):
            out["description"] = self._translate_to_english(desc)

        remediation = str(out.get("remediation", ""))
        if self._looks_spanish(remediation):
            out["remediation"] = self._translate_to_english(remediation)

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
        "cloudtrail-s3-notifications.json": "CloudTrail S3 Notifications",
        "cloudtrail-log-subscriptions.json": "CloudTrail Log Subscriptions",
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
        "network-acls.json": "Network ACLs",  # actual network skill filename
        "subnets.json": "Subnets",
        "route-tables.json": "Route Tables",
        "internet-gateways.json": "Internet Gateways",
        "nat-gateways.json": "NAT Gateways",
        "nat-gateway-routes.json": "NAT Gateways",  # actual network skill filename
        "vpc-endpoints.json": "VPC Endpoints",
        "transit-gateways.json": "Transit Gateways",
        "vpn-connections.json": "VPN Connections",  # actual network skill filename
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
        # Sistemas Explotables por Red (SER)
        "compute-inventory.json": "Compute Inventory (EC2/ECS/Lambda/RDS)",
        "network-controls.json": "Network Controls (SGs/Route Tables/NACLs)",
        "front-doors.json": "Front Doors (LBs/Lambda URLs/API GW Routes)",
        "reachability-graph.json": "Reachability Graph",
        "attack-path-candidates.json": "Attack Path Candidates",
        "inspector-findings-normalized.json": "Inspector Findings (normalized)",
        "port-service-hypothesis.json": "Port/Service Hypothesis",
        "cve-intelligence.json": "CVE Intelligence",
    }

    # Primary item key per evidence file (for nested-dict evidence structures).
    # Used by _resources_audited_section() when evidence is neither a raw list
    # nor uses the standard {"items": [...]} envelope.
    _EVIDENCE_FILE_COUNT_KEYS: dict = {
        "attack-path-candidates.json": "paths",
        "inspector-findings-normalized.json": "findings",
        "reachability-graph.json": "edges",
    }

    def _compute_assessment_rating(
        self,
        critical: int,
        high: int,
        medium: int,
        low: int,
        risk_score: float,
        total: int,
    ) -> tuple:
        """Compute qualitative assessment rating.

        Returns:
            (icon, label, description) tuple
        """
        if total == 0:
            return (
                "🟢",
                "Excellent",
                "No security findings were identified. The assessed controls demonstrate a strong security posture with no remediation required at this time.",
            )
        if critical == 0 and high == 0 and risk_score < 3.5:
            return (
                "🟢",
                "Very Good",
                "The environment demonstrates a solid security posture. Only minor findings were identified, none of which represent immediate risk. Remediation can be planned as part of the regular improvement cycle.",
            )
        if critical == 0 and high <= 1 and risk_score < 5.5:
            return (
                "🟡",
                "Good",
                "The environment shows a generally sound security posture with some areas requiring attention. High-severity findings should be scheduled for remediation within 30 days.",
            )
        if critical <= 1 and risk_score < 7.5:
            return (
                "🟠",
                "Needs Improvement",
                "Significant security gaps have been identified. One or more critical or multiple high-severity findings require prompt remediation to reduce exposure and meet compliance requirements.",
            )
        return (
            "🔴",
            "Immediate Attention Required",
            "Critical security deficiencies have been detected that represent substantial risk to the environment. Immediate remediation is strongly recommended before the next assessment cycle.",
        )

    def _narrative_executive_summary(self) -> str:
        """Generate narrative executive summary with overall assessment rating."""
        summary = self.findings.get("summary", {})
        skill = self.findings.get("skill", "Unknown").lower()
        client = self.session.client_name or "the assessed environment"

        total = int(summary.get("total_findings", 0))
        critical = int(summary.get("critical", 0))
        high = int(summary.get("high", 0))
        medium = int(summary.get("medium", 0))
        low = int(summary.get("low", 0))
        risk_score = float(summary.get("overall_risk_score", 0.0))

        scope = self._SKILL_SCOPE_DESCRIPTIONS.get(
            skill,
            f"{skill.upper()} security controls and configurations",
        ).rstrip(".")

        if total == 0:
            findings_text = (
                "No security findings were identified during this assessment. "
                "The evaluated controls appear to be properly configured."
            )
        elif critical > 0 and high > 0:
            findings_text = (
                f"The assessment identified **{total} finding(s)**: "
                f"**{critical} critical** and **{high} high** severity issue(s) "
                f"alongside {medium} medium and {low} low severity item(s). "
                f"Immediate action is required on the critical findings."
            )
        elif critical > 0:
            findings_text = (
                f"The assessment identified **{total} finding(s)**, including "
                f"**{critical} critical** severity issue(s) requiring immediate remediation."
            )
        elif high > 0:
            findings_text = (
                f"The assessment identified **{total} finding(s)**, including "
                f"**{high} high** severity issue(s) that should be addressed promptly."
            )
        elif medium > 0:
            findings_text = (
                f"The assessment identified **{total} finding(s)** of medium or low severity, "
                f"representing opportunities for security improvement."
            )
        else:
            findings_text = (
                f"The assessment identified **{total}** low severity finding(s) "
                f"representing minor improvement opportunities."
            )

        rating_icon, rating_label, rating_desc = self._compute_assessment_rating(
            critical, high, medium, low, risk_score, total
        )

        return f"""## 🔍 Narrative Assessment

This security assessment evaluated the {scope} for **{client}**. {findings_text}

**Overall Assessment:** {rating_icon} **{rating_label}**

> {rating_desc}
"""

    def _header(self) -> str:
        """Generate report header."""
        skill = self.findings.get("skill", "Unknown")
        timestamp = self.findings.get("analyzed_at", datetime.utcnow().isoformat())
        account_id = self.session.account_id
        client_name = self.session.client_name
        min_sev = getattr(self.config, "min_severity", "low")
        report_meta = self.findings.get("report_metadata", {})
        raw_total = report_meta.get("raw_total_findings")
        filtered_out = report_meta.get("filtered_out_findings")

        filter_note = ""
        if isinstance(filtered_out, int) and filtered_out > 0 and isinstance(raw_total, int):
            filter_note = (
                f"\n**Raw Findings (pre-filter):** {raw_total}"
                f"\n**Filtered Out by Min Severity:** {filtered_out}"
            )

        banner = """ ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝"""

        return f"""{banner}

# AWS Security Audit Report

**Client:** {client_name}
**Skill:** {self._get_skill_display_name(skill)}
 **AWS Account:** {account_id}
 **Generated:** {timestamp}
 **Version:** {self.findings.get("checklist_version", "1.0")}
 **Report Min Severity:** {str(min_sev).upper()}
{filter_note}

 ---

## 📋 Quick Summary

This report presents security findings from the {self._get_skill_display_name(skill)} security assessment.
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
        risk_overview += (
            f"│ Overall Risk Score: {risk_score:.1f} / 10.0 ({risk_label.strip()})".ljust(45)
            + "│\n"
        )
        risk_overview += f"│ Total Findings: {total}".ljust(45) + "│\n"
        risk_overview += (
            f"│ Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}".ljust(45)
            + "│\n"
        )
        risk_overview += "└─────────────────────────────────────────────┘"

        severity_dist = self._severity_distribution_chart()
        top_resources = self._top_affected_resources()
        findings_summary = self._findings_summary_table()

        return f"""## 📊 Executive Summary

{risk_overview}

{severity_dist}

{top_resources}

{findings_summary}
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

    def _resources_audited_section(self) -> str:
        """Generate resources audited section from skill evidence files.

        Reads evidence/<skill>/ directory, counts items per evidence JSON file,
        and renders a table of audited resource types. Works generically for
        all skills (alerting, iam, network, waf, ecr, etc.).

        Returns:
            Markdown section string, or empty string if no countable evidence.
        """
        skill = self.findings.get("skill", "")
        if not skill:
            return ""

        evidence_dir = self.session.base_path / "evidence" / skill
        if not evidence_dir.exists() or not evidence_dir.is_dir():
            return ""

        rows = []
        for json_file in sorted(evidence_dir.glob("*.json")):
            # Skip internal / metadata files
            if json_file.stem.startswith("_"):
                continue

            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            # Count items: handle raw list, standard {"items": [...]} envelope,
            # known single-key dicts (SER skill), and multi-list dicts (compute-inventory).
            if isinstance(data, list):
                count = len(data)
            elif isinstance(data, dict) and isinstance(data.get("items"), list):
                count = len(data["items"])
            elif isinstance(data, dict):
                # Try known single primary-key shortcut first
                item_key = self._EVIDENCE_FILE_COUNT_KEYS.get(json_file.name)
                if item_key and isinstance(data.get(item_key), list):
                    count = len(data[item_key])
                else:
                    # Fallback: sum items across all collection values
                    # (handles compute-inventory, front-doors, cve-intelligence, etc.)
                    count = sum(
                        len(v)
                        for k, v in data.items()
                        if not k.startswith("_")
                        and k not in ("summary", "errors", "enrichment_errors")
                        and isinstance(v, (list, dict))
                    )
                if count == 0:
                    continue
            else:
                # Skip scalar dicts (password-policy) or unrecognized structures
                continue

            label = self._EVIDENCE_FILE_LABELS.get(
                json_file.name,
                json_file.stem.replace("-", " ").replace("_", " ").title(),
            )
            rows.append((label, count))

        if not rows:
            return ""

        section = "## 🗂️ Resources Audited\n\n"

        # For CloudTrail Events skill, prepend scan scope metadata from _summary.json
        if skill == "cloudtrail_events":
            summary_path = evidence_dir / "_summary.json"
            if summary_path.exists():
                try:
                    with open(summary_path) as f:
                        ct_summary = json.load(f)
                    region = ct_summary.get("region", "—")
                    days_back = ct_summary.get("days_back", "—")
                    scan_depth = ct_summary.get("scan_depth", "—")
                    start_time = ct_summary.get("start_time", "")
                    end_time = ct_summary.get("end_time", "")
                    account_id = ct_summary.get("account_id", "—")
                    # Format period as readable dates
                    try:
                        from datetime import datetime as _dt
                        start_fmt = _dt.fromisoformat(start_time).strftime("%Y-%m-%d") if start_time else "—"
                        end_fmt = _dt.fromisoformat(end_time).strftime("%Y-%m-%d") if end_time else "—"
                    except Exception:
                        start_fmt, end_fmt = start_time[:10] if start_time else "—", end_time[:10] if end_time else "—"
                    section += "### Scan Scope\n\n"
                    section += "| Parameter | Value |\n"
                    section += "|-----------|-------|\n"
                    section += f"| Account ID | `{account_id}` |\n"
                    section += f"| Region | {region} |\n"
                    section += f"| Period | {start_fmt} → {end_fmt} ({days_back} days) |\n"
                    section += f"| Scan Depth | {scan_depth} |\n"
                    total_events = sum(ct_summary.get("categories_collected", {}).values())
                    section += f"| Total Events Processed | {total_events:,} |\n"
                    section += "\n"
                except Exception:
                    pass

        section += "### Event Categories\n\n" if skill == "cloudtrail_events" else ""
        section += "| Resource Type | Count |\n"
        section += "|---------------|-------|\n"
        for label, count in rows:
            section += f"| {label} | {count} |\n"

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
            f = self._normalize_finding_language(f)
            timeline += f"- [ ] {f.get('id')}: {f.get('title')}\n"

        timeline += "\n### Short-term (8-30 days) - High Priority\n"
        for f in short_term[:5]:
            f = self._normalize_finding_language(f)
            timeline += f"- [ ] {f.get('id')}: {f.get('title')}\n"

        timeline += "\n### Medium-term (31-90 days) - Medium Priority\n"
        for f in medium_term[:3]:
            f = self._normalize_finding_language(f)
            timeline += f"- [ ] {f.get('id')}: {f.get('title')}\n"

        return timeline

    def _correlation_section(self) -> str:
        """Generate cross-skill correlation section.

        Displays attack chains from correlated findings if available.

        Returns:
            Markdown section or empty string if no correlations.
        """
        # Check if correlated.json exists
        corr_file = self.session.base_path / "findings" / "correlated.json"

        if not corr_file.exists():
            logger.debug("No correlated.json found, skipping correlation section")
            return ""

        # Load correlation data
        try:
            with open(corr_file, "r") as f:
                corr_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to parse correlated.json: {e}")
            return ""

        correlations = corr_data.get("correlations", [])

        if not correlations:
            return """## 🔗 Cross-Skill Correlations

✅ No cross-skill attack patterns detected. Individual findings analyzed separately.
"""

        # Sort by compound risk (highest first)
        correlations = sorted(
            correlations, key=lambda c: c.get("compound_risk_score", 0), reverse=True
        )

        # Limit to top 10
        max_displayed = 10
        displayed = correlations[:max_displayed]
        hidden_count = len(correlations) - max_displayed

        # Build section header
        total = len(correlations)
        skills = corr_data.get("metadata", {}).get("skills_analyzed", [])

        section = f"""## 🔗 Cross-Skill Correlations ({total})

**Attack Chains Detected:** {total} compound risks identified across {", ".join(skills).upper()}

These correlations represent multi-stage attack scenarios where findings from different skills combine to create elevated risk.

"""

        # Render each correlation
        for i, corr in enumerate(displayed, 1):
            section += self._format_correlation(corr, i)
            section += "\n\n---\n\n"

        # Add "more" indicator if truncated
        if hidden_count > 0:
            section += (
                f"*... and {hidden_count} more correlations (see findings/correlated.json)*\n\n"
            )

        return section

    def _format_correlation(self, corr: Dict[str, Any], index: int) -> str:
        """Format a single correlation finding.

        Args:
            corr: Correlation dict from correlated.json
            index: Display index (1, 2, 3...)

        Returns:
            Markdown for single correlation
        """
        corr_id = corr.get("id", "CORR-???")
        title = corr.get("title", "Unknown Attack Chain")
        severity = corr.get("severity", "High")
        risk_score = corr.get("compound_risk_score", 0.0)
        description = corr.get("description", "")
        attack_path = corr.get("attack_path", [])
        source_findings = corr.get("source_findings", [])
        affected_resources = corr.get("affected_resources", [])
        remediation_priority = corr.get("remediation_priority", "N/A")
        remediation_steps = corr.get("remediation_steps", [])

        # Get severity emoji and risk label
        emoji = self._get_severity_emoji(severity)
        risk_label = self._format_risk_score(risk_score)

        # Build output
        output = f"""### {index}. {emoji} [{corr_id}] {title}

**Severity:** {severity} | **Compound Risk:** {risk_label} | **Priority:** {remediation_priority}

**Description:**
{description}

"""

        # Attack Path (numbered with arrows)
        if attack_path:
            output += "**Attack Path:**\n"
            for step_idx, step in enumerate(attack_path, 1):
                arrow = "➜ " if step_idx > 1 else ""
                output += f"{step_idx}. {arrow}{step}\n"
            output += "\n"

        # Source Findings Table
        if source_findings:
            output += "**Source Findings:**\n\n"
            output += "| Skill | Finding ID | Title | Severity | Risk |\n"
            output += "|-------|------------|-------|----------|------|\n"

            for src in source_findings:
                skill = src.get("skill", "unknown").upper()
                finding_id = src.get("id", "N/A")
                src_title = src.get("title", "Unknown")[:50]  # Truncate
                sev = src.get("severity", "N/A")
                risk = src.get("risk_score", 0.0)

                # Add skill emoji
                skill_emoji = self._get_skill_emoji(skill)

                output += (
                    f"| {skill_emoji} {skill} | {finding_id} | {src_title} | {sev} | {risk:.1f} |\n"
                )

            output += "\n"

        # Affected Resources (compact list)
        if affected_resources:
            output += f"**Affected Resources:** {len(affected_resources)} total\n"
            for arn in affected_resources[:3]:
                output += f"- `{arn}`\n"
            if len(affected_resources) > 3:
                output += f"- *... and {len(affected_resources) - 3} more*\n"
            output += "\n"

        # Remediation Steps
        if remediation_steps:
            output += "**Remediation Steps:**\n"
            for step in remediation_steps:
                output += f"{step}\n"
            output += "\n"

        return output

    def _get_skill_emoji(self, skill: str) -> str:
        """Get emoji for skill name."""
        skill_emojis = {
            "IAM": "🔐",
            "NETWORK": "🌐",
            "EXPOSURE": "🚪",
            "VULNS": "🐛",
            "HARDENING": "🛡️",
            "ALERTING": "🚨",
            "ECR": "📦",
            "SECRETSMANAGER": "🔑",
            "WAF": "🛡️",
        }
        return skill_emojis.get(skill.upper(), "🔹")

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

    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
        return emoji_map.get(severity, "⚪")

    def _findings_summary_table(self) -> str:
        """Generate top 10 findings summary table for executive summary."""
        findings = self.findings.get("findings", [])

        if not findings:
            return ""

        # Sort by severity (Critical > High > Medium > Low), then by risk_score desc
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.get("severity", "Low"), 4),
                -f.get("risk_score", 0.0),
            ),
        )

        # Take top 10
        top_findings = sorted_findings[:10]

        # Build table
        output = "### 📋 Top 10 Findings Summary\n\n"
        output += "| ID | Title | Severity | Risk | Resources |\n"
        output += "|----|-------|----------|------|-----------|\n"

        for finding in top_findings:
            finding = self._normalize_finding_language(finding)
            finding_id = finding.get("id", "N/A")
            title = finding.get("title", "Unknown")[:50]  # Truncate to 50 chars
            severity = finding.get("severity", "Unknown")
            risk_score = finding.get("risk_score", 0.0)
            affected = finding.get("affected_resources", [])

            # Get severity emoji
            sev_emoji = self._get_severity_emoji(severity)

            # Format severity column
            sev_col = f"{sev_emoji} {severity}"

            # Format risk score
            risk_col = f"{risk_score:.1f}/10"

            # Format resources
            if len(affected) == 0:
                resources_col = "-"
            elif len(affected) == 1:
                # Single resource - show truncated ARN
                arn = affected[0]
                if len(arn) > 40:
                    resources_col = arn[:20] + "..." + arn[-17:]
                else:
                    resources_col = arn
            else:
                # Multiple resources - show count
                resources_col = f"{len(affected)} resources"

            output += f"| {finding_id} | {title} | {sev_col} | {risk_col} | {resources_col} |\n"

        return output + "\n"

    def _findings_by_severity(self) -> str:
        """Generate findings grouped by severity."""
        findings = self.findings.get("findings", [])

        if not findings:
            return "## 🔍 Findings\n\nNo findings detected."

        # Group by severity
        severity_order = ["Critical", "High", "Medium", "Low"]
        grouped = {sev: [] for sev in severity_order}

        for finding in findings:
            finding = self._normalize_finding_language(finding)
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

    def _threat_intel_block(self, threat_intel: Dict[str, Any]) -> str:
        """Render compact TrailDiscover threat intelligence block.

        Format (2 lines):
            🎯 **Threat Intel:** MITRE: TA0005 · T1562.001
            **Used in real attacks:** ✅ LUCR-3, SCARLETEEL 2.0
        """
        tactics = threat_intel.get("mitre_tactics") or []
        techniques = threat_intel.get("mitre_techniques") or []
        used_in_wild = threat_intel.get("used_in_wild", False)
        incidents = threat_intel.get("real_incidents") or []

        if not tactics and not used_in_wild:
            return ""

        block = "\n"

        # Line 1: MITRE tactics + techniques (compact)
        mitre_parts = []
        # Show tactics (abbreviated: "TA0005 - Defense Evasion" → "TA0005")
        tactic_ids = [t.split(" - ")[0] if " - " in t else t for t in tactics[:3]]
        if tactic_ids:
            mitre_parts.append(", ".join(tactic_ids))
        # Show first 2 technique IDs
        tech_ids = [t.split(" - ")[0] if " - " in t else t for t in techniques[:2]]
        if tech_ids:
            mitre_parts.append(" · ".join(tech_ids))
        mitre_str = " · ".join(mitre_parts) if mitre_parts else "—"
        block += f"🎯 **Threat Intel:** MITRE: {mitre_str}\n"

        # Line 2: usedInWild + incident names
        if used_in_wild:
            if incidents:
                # Truncate long incident names and limit to 3
                incident_names = []
                for name in incidents[:3]:
                    # Keep only the part before the first colon or URL-like segment
                    short = name.split(":")[0].strip() if ":" in name else name
                    incident_names.append(short[:60])
                block += f"**Used in real attacks:** ✅ {', '.join(incident_names)}\n"
            else:
                block += "**Used in real attacks:** ✅ Yes\n"
        else:
            block += "**Used in real attacks:** No documented incidents\n"

        return block

    def _ser_exploitability_section(self, finding: Dict[str, Any]) -> str:
        """Render Exploitability Analysis section for SER findings with CVE intelligence."""
        snippet = finding.get("evidence_snippet") or {}
        cve_details = snippet.get("cve_details", [])

        if not cve_details:
            return ""

        section = "\n#### Exploitability Analysis\n\n"

        if cve_details:
            # Group CVEs by resource (instance) so ALL instances are represented.
            # An uncapped flat [:15] slice would only show the first instance's CVEs
            # when multiple instances are present (e.g. 15 CVEs × 2 instances = 30 total).
            from collections import OrderedDict

            by_resource: OrderedDict = OrderedDict()
            for cve in cve_details:
                resource = cve.get("resource") or "unknown"
                by_resource.setdefault(resource, []).append(cve)

            # Per-instance cap: show top 10 CVEs per instance (sorted by CVSS desc)
            _MAX_PER_INSTANCE = 10
            cves_to_render: list = []
            for resource, cves in by_resource.items():
                sorted_cves = sorted(
                    cves,
                    key=lambda c: float(c.get("cvss_score") or 0.0),
                    reverse=True,
                )
                cves_to_render.append((resource, sorted_cves[:_MAX_PER_INSTANCE]))

            section += "| CVE / Advisory | Package | Installed | Fixed | CVSS | Impact | AV | Exploit | KEV |\n"
            section += "|----------------|---------|-----------|-------|------|--------|----|---------|-----|\n"
            for resource, cves in cves_to_render:
                if len(cves_to_render) > 1:
                    # Add a separator row labeling the instance when multiple instances
                    short_id = resource.split("/")[-1] if "/" in resource else resource
                    section += f"| **`{short_id}`** | | | | | | | | |\n"
                for cve in cves:
                    cve_id = cve.get("id", "—")
                    package = cve.get("package", "—") or "—"
                    installed = cve.get("installed_version", "") or "—"
                    fixed = cve.get("fixed_version", "") or "—"
                    cvss = cve.get("cvss_score")
                    sev = cve.get("inspector_severity", "")
                    cvss_str = f"{cvss:.1f} ({sev})" if cvss is not None else "—"
                    impact = cve.get("impact_type", "") or "—"
                    av = cve.get("attack_vector", "—")
                    ports = cve.get("relevant_open_ports", [])
                    ports_str = ", ".join(str(p) for p in ports[:3]) if ports else "—"
                    av_str = f"{av} ({ports_str})" if ports else av
                    ei = cve.get("exploit_intel") or {}
                    has_exploit = ei.get("has_public_exploit", False)
                    exploit_str = "✅ Yes" if has_exploit else "No"
                    kev = ei.get("cisa_kev") or {}
                    kev_str = "⚠️ **KEV**" if kev.get("listed") else "No"
                    section += (
                        f"| {cve_id} | {package} | {installed} | {fixed} | {cvss_str} | {impact} | {av_str} | {exploit_str} | {kev_str} |\n"
                    )
            section += "\n"

            # CVE descriptions — show top CVSS CVEs across all instances (up to 15 unique)
            desc_lines = []
            seen_ids: set = set()
            all_sorted = sorted(
                cve_details,
                key=lambda c: float(c.get("cvss_score") or 0.0),
                reverse=True,
            )
            for cve in all_sorted:
                cve_id = cve.get("id", "")
                if cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)
                desc = (cve.get("description") or "").strip()
                if not desc:
                    continue
                impact = cve.get("impact_type", "")
                impact_badge = f" `{impact}`" if impact and impact != "Unknown" else ""
                desc_lines.append(f"- **`{cve_id}`**{impact_badge}: {desc[:300]}")
                if len(desc_lines) >= 15:
                    break
            if desc_lines:
                section += "**CVE Descriptions:**\n\n"
                section += "\n".join(desc_lines) + "\n\n"

            # Surface PoC URLs and exploit references
            poc_lines = []
            for cve in cve_details[:15]:
                ei = cve.get("exploit_intel") or {}
                poc_urls = ei.get("poc_urls") or []
                edb = ei.get("exploit_db") or {}
                kev = ei.get("cisa_kev") or {}
                cve_id = cve.get("id", "")
                notes = []
                if kev.get("listed"):
                    date = kev.get("date_added", "")
                    rw = kev.get("ransomware_use", "")
                    notes.append(f"CISA KEV (added {date}" + (f", ransomware: {rw}" if rw and rw != "Unknown" else "") + ")")
                if edb.get("id"):
                    notes.append(f"[Exploit-DB #{edb['id']}](https://www.exploit-db.com/exploits/{edb['id']}) — {edb.get('type','?')} / {edb.get('platform','?')}")
                for url in poc_urls[:3]:
                    notes.append(f"[PoC]({url})")
                if notes:
                    poc_lines.append(f"- **`{cve_id}`**: " + " · ".join(notes))
            if poc_lines:
                section += "**Public exploit references:**\n\n"
                section += "\n".join(poc_lines) + "\n\n"

        return section

    def _ser_attack_vector_section(self, finding: Dict[str, Any]) -> str:
        """Render a pentester-style attack vector playbook for SER findings."""
        snippet = finding.get("evidence_snippet") or {}
        attack_paths = snippet.get("attack_paths", {})
        if not isinstance(attack_paths, dict) or not attack_paths:
            return ""

        cve_details = snippet.get("cve_details", [])
        sg_rules_context = snippet.get("sg_rules_context", {})
        iam_roles = snippet.get("iam_roles", {})

        # Group CVE details by instance for quick lookup
        cves_by_instance: Dict[str, List[Dict[str, Any]]] = {}
        if isinstance(cve_details, list):
            for c in cve_details:
                if not isinstance(c, dict):
                    continue
                res = str(c.get("resource", ""))
                cves_by_instance.setdefault(res, []).append(c)

        section = "\n**Attack Vector Playbook:**\n\n"

        for iid, path_data in list(attack_paths.items())[:3]:
            if not isinstance(path_data, dict):
                continue

            steps = path_data.get("steps", []) if isinstance(path_data.get("steps"), list) else []
            if not steps and not cves_by_instance.get(iid):
                continue

            iam_role = str(iam_roles.get(iid, "") or "")
            sg_rules = sg_rules_context.get(iid, []) if isinstance(sg_rules_context, dict) else []

            section += f"#### Instance `{iid}`\n\n"
            section += "As a pentester, here is how I would attack this instance step by step.\n\n"

            # Step 1: Network reconnaissance — show SG rules table
            section += "**Step 1 — Reconnaissance: What ports can I reach?**\n\n"
            if isinstance(sg_rules, list) and sg_rules:
                world_open = [
                    r
                    for r in sg_rules
                    if isinstance(r, dict) and r.get("source") in ("0.0.0.0/0", "::/0")
                ]
                restricted = [
                    r
                    for r in sg_rules
                    if isinstance(r, dict) and r.get("source") not in ("0.0.0.0/0", "::/0", "")
                ]
                if world_open:
                    section += "The following ports are **open to the internet** (`0.0.0.0/0`):\n\n"
                    section += "| Port/Range | Protocol | Source | SG |\n"
                    section += "|------------|----------|--------|---------|\n"
                    for r in world_open[:10]:
                        section += (
                            f"| {r.get('port', '?')} "
                            f"| {r.get('protocol', '?')} "
                            f"| {r.get('source', '?')} "
                            f"| `{r.get('sg_name', r.get('sg_id', ''))}` |\n"
                        )
                    section += "\n"
                    section += (
                        "> **Pentester note:** World-open ports are directly reachable from my attack machine "
                        "without any prior network access. These are my entry points.\n\n"
                    )
                if restricted:
                    section += "Additional restricted rules (not world-open):\n\n"
                    section += "| Port/Range | Protocol | Source | SG |\n"
                    section += "|------------|----------|--------|---------|\n"
                    for r in restricted[:8]:
                        section += (
                            f"| {r.get('port', '?')} "
                            f"| {r.get('protocol', '?')} "
                            f"| {r.get('source', '?')} "
                            f"| `{r.get('sg_name', r.get('sg_id', ''))}` |\n"
                        )
                    section += "\n"
            else:
                # Fall back to steps-based open ports description
                narrative = str(path_data.get("narrative", "")).strip()
                if narrative:
                    section += narrative + "\n\n"

            # Step 2+: Per-CVE exploitation steps
            inst_cves = cves_by_instance.get(iid, [])
            network_cves = [
                c
                for c in inst_cves
                if isinstance(c, dict)
                and (
                    str(c.get("attack_vector", "")).upper() == "NETWORK"
                    or c.get("exploitable_from_internet")
                )
            ]

            if network_cves:
                section += "**Step 2 — Exploitation: Which vulnerabilities can I weaponize?**\n\n"
                for idx, cve in enumerate(network_cves[:5], start=1):
                    cve_id = str(cve.get("id", "")).strip()
                    package = str(cve.get("package", "") or "").strip()
                    severity = str(cve.get("inspector_severity", "") or "").strip()
                    cvss = cve.get("cvss_score")
                    description = str(cve.get("description", "") or "").strip()
                    open_ports = cve.get("relevant_open_ports", [])

                    is_network_reachability = "reachable from an internet gateway" in cve_id.lower()

                    section += f"**{idx}. `{cve_id}`"
                    if package:
                        section += f" ({package})"
                    section += f"** — Inspector severity: {severity}"
                    if cvss is not None:
                        section += f", CVSS: {cvss}"
                    section += "\n\n"

                    if is_network_reachability:
                        # Network reachability finding — explain what it means
                        port_hint = ""
                        if "port 22" in cve_id.lower():
                            port_hint = "port 22 (SSH)"
                        elif "port 3389" in cve_id.lower():
                            port_hint = "port 3389 (RDP)"
                        elif "port 80" in cve_id.lower():
                            port_hint = "port 80 (HTTP)"
                        elif "port 443" in cve_id.lower():
                            port_hint = "port 443 (HTTPS)"
                        else:
                            port_hint = "a network port"
                        section += (
                            f"> AWS Inspector confirmed that {port_hint} on this instance is directly "
                            "reachable from an Internet Gateway. This is not a CVE — it is a network "
                            "reachability confirmation. This means I can reach the service on that port "
                            "from the public internet without VPN or any prior access.\n\n"
                        )
                        section += (
                            "**What this means in practice:** Any vulnerability running on this service "
                            "(SSH brute force, CVE in the SSH daemon, weak credentials) is now remotely "
                            "exploitable. I would start here as my entry point.\n\n"
                        )
                    else:
                        if description:
                            section += f"> **Vulnerability:** {description}\n\n"
                        if open_ports:
                            section += (
                                f"> **Attack surface:** This vulnerability is exploitable via the network "
                                f"(AV:N). The instance has port(s) `{', '.join(str(p) for p in open_ports)}` "
                                "open to the internet — traffic to the affected service can reach me from "
                                "the public internet.\n\n"
                            )
                        section += (
                            "**What this means in practice:** I would look up a public exploit or PoC for "
                            f"`{cve_id}`, confirm the affected package version is installed on the target, "
                            "and deliver the payload via the exposed network port. Remote code execution "
                            "would give me a shell in the instance context.\n\n"
                        )

            # IMDS credential harvesting step
            step_num = 3 if network_cves else 2
            section += (
                f"**Step {step_num} — Credential Theft: Stealing IAM credentials via IMDS**\n\n"
            )
            section += (
                "Once I have code execution on the instance (via SSH, RCE, or SSRF), I query the "
                "EC2 Instance Metadata Service (IMDS) to steal the IAM role's temporary credentials:\n\n"
            )
            if iam_role:
                section += (
                    "```bash\n"
                    "# 1. Check which IAM role is attached\n"
                    f"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
                    f"# Returns: {iam_role}\n\n"
                    "# 2. Steal the credentials\n"
                    f"curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{iam_role}\n"
                    "# Returns: AccessKeyId, SecretAccessKey, Token (valid ~1-6 hours)\n"
                    "```\n\n"
                )
            else:
                section += (
                    "```bash\n"
                    "# 1. Check which IAM role is attached\n"
                    "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n"
                    "# 2. Steal the credentials (replace ROLE-NAME with the output above)\n"
                    "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME\n"
                    "# Returns: AccessKeyId, SecretAccessKey, Token (valid ~1-6 hours)\n"
                    "```\n\n"
                )
            section += (
                "> **Why this matters:** IMDS credentials are temporary but fully valid AWS credentials. "
                "They carry the exact permissions of the attached IAM role. If the role has broad "
                "permissions (S3 read, Secrets Manager access, IAM actions), the blast radius extends "
                "far beyond this single instance.\n\n"
            )

            # Lateral movement step
            step_num += 1
            section += (
                f"**Step {step_num} — Lateral Movement: What can I do with these credentials?**\n\n"
            )
            section += (
                "```bash\n"
                "# Export stolen credentials\n"
                "export AWS_ACCESS_KEY_ID=<AccessKeyId>\n"
                "export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>\n"
                "export AWS_SESSION_TOKEN=<Token>\n\n"
                "# Verify identity\n"
                "aws sts get-caller-identity\n\n"
                "# Enumerate accessible data\n"
                "aws s3 ls                                          # S3 buckets\n"
                "aws secretsmanager list-secrets --region us-east-1 # Secrets\n"
                "aws ssm describe-parameters --region us-east-1     # SSM parameters\n"
                "aws iam list-attached-role-policies --role-name "
            )
            if iam_role:
                section += iam_role
            else:
                section += "ROLE-NAME"
            section += "  # Role policies\n```\n\n"

        return section

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

        # Append analogy as final paragraph of description (if present)
        analogy = finding.get("security_analogy")
        if analogy:
            description = f"{description}\n\n*Analogy: {analogy}*"

        detail = f"""### [{finding_id}] {title}

**Risk Score:** {self._format_risk_score(risk_score)}

**Description:**
{description}
"""

        # SER findings: render structured Exploitability Analysis section
        skill = str(self.findings.get("skill", "")).lower()
        is_ser = skill == "sistemas_explotables_red"
        has_cve_intel = isinstance(evidence_snippet, dict) and (
            "cve_details" in evidence_snippet or "attack_paths" in evidence_snippet
        )

        attack_vector_block = ""
        if is_ser and has_cve_intel:
            detail += self._ser_exploitability_section(finding)
            attack_vector_block = self._ser_attack_vector_section(finding)
            # Strip cve_details / attack_paths from the JSON blob shown below
            snippet_for_json = {
                k: v
                for k, v in (evidence_snippet or {}).items()
                if k not in ("cve_details", "attack_paths")
            }
        else:
            snippet_for_json = evidence_snippet

        # Render evidence snippet if present
        if snippet_for_json or evidence_refs:
            detail += "\n**Evidence:**\n"

            if snippet_for_json:
                detail += "```json\n"
                redacted, _ = redact_secrets(json.dumps(snippet_for_json, indent=2, ensure_ascii=False))
                detail += redacted
                detail += "\n```\n"

            if evidence_refs:
                detail += "\n*References:*\n"
                for ref in evidence_refs[:5]:
                    detail += f"- `{ref}`\n"
                if len(evidence_refs) > 5:
                    detail += f"- ... and {len(evidence_refs) - 5} more\n"

        if attack_vector_block:
            detail += "\n" + attack_vector_block

        if affected:
            detail += "\n**Affected Resources:**\n"
            for resource in affected[:5]:  # Limit to 5
                detail += f"- `{resource}`\n"
            if len(affected) > 5:
                detail += f"- ... and {len(affected) - 5} more\n"

        # TrailDiscover threat intelligence block (CTEF findings only)
        threat_intel = finding.get("threat_intel")
        if threat_intel and isinstance(threat_intel, dict):
            detail += self._threat_intel_block(threat_intel)

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
                f = self._normalize_finding_language(f)
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
                f = self._normalize_finding_language(f)
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
        findings = self.findings.get("findings", [])
        summary = self.findings.get("summary", {})
        total = int(
            summary.get("total_findings", len(findings) if isinstance(findings, list) else 0)
        )
        critical = int(summary.get("critical", 0))
        high = int(summary.get("high", 0))

        positives = []
        concerns = []
        recommendations = []

        if total == 0:
            positives.append("No findings at the selected severity threshold.")
        else:
            if critical == 0:
                positives.append("No critical findings identified in this scan.")
            if high <= 1:
                positives.append("High-severity exposure appears limited in this run.")

        if high + critical > 0:
            concerns.append(
                f"{critical + high} high-impact findings require prioritized remediation."
            )
        if total >= 3:
            concerns.append("Repeated control gaps indicate policy enforcement drift.")

        if high + critical > 0:
            recommendations.append("Remediate high-impact findings in the next 7-30 days.")
        recommendations.append("Re-run the scan after fixes to confirm closure and risk reduction.")

        if not positives:
            positives.append("Baseline security controls are present but can be strengthened.")
        if not concerns:
            concerns.append("No systemic weakness pattern detected in this run.")

        return (
            "## 📝 Observations\n\n"
            f"- **Positive:** {positives[0]}\n"
            f"- **Concerns:** {concerns[0]}\n"
            f"- **Recommendations:** {recommendations[0]}\n"
        )

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
        # Align with FindingsNormalizer.SEVERITY_RANGES:
        # Critical: 8.5-10.0, High: 6.0-8.4, Medium: 3.0-5.9, Low: 1.0-2.9
        if score >= 8.5:
            return "🔴 **CRITICAL**"
        elif score >= 6.0:
            return "🟠 **HIGH**"
        elif score >= 3.0:
            return "🟡 **MEDIUM**"
        else:
            return "🟢 **LOW**"

    def _natural_sort_key(self, s: str) -> List:
        """Natural sort key for control IDs (7.2.1 < 8.4.1)."""
        return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", s)]

    def _get_all_checklist_controls(self) -> List[str]:
        """Extract all unique PCI DSS controls from checklist.json."""
        try:
            # Get skill name from findings (NO default)
            skill = self.findings.get("skill")
            if not skill:
                raise ValueError("Skill name missing in findings")
            # Build path to checklist
            checklist_path = (
                Path(__file__).parent.parent.parent / "skills" / skill / "checklist.json"
            )

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

    def _pci_dss_annex_md(self) -> str:
        """Generate PCI DSS Annex A at the end of the report.

        Only emits content when report_type == 'pci-dss'. Returns empty string otherwise.
        """
        if getattr(self.config, "report_type", "general") != "pci-dss":
            return ""

        from drystone.reports.formats.pci_dss import build_pci_controls_map, get_requirement_name

        findings = self.findings.get("findings", [])
        skills = list(getattr(self.config, "skills", [])) or [self.findings.get("skill", "unknown")]

        data = build_pci_controls_map(findings, skills)
        controls = data["controls"]

        if not controls:
            return ""

        is_en = self._is_english_report()
        annex_title = (
            "Annex A: PCI DSS v4.0 Control Mapping"
            if is_en
            else "Anexo A: Mapeo de Controles PCI DSS v4.0"
        )
        ko_label = "KO"
        header_control = "Control" if is_en else "Control"
        header_status = "Status" if is_en else "Estado"
        header_just = "Justification" if is_en else "Justificación"

        ko_controls = [c for c in controls if c["status"] == "ko"]
        if not ko_controls:
            return ""

        lines = [
            "---",
            "",
            f"## {annex_title}",
            "",
        ]

        if is_en:
            lines += [
                "**Mapping methodology used in Drystone**",
                "",
                "1. Drystone loads each executed skill checklist (`drystone/skills/<skill>/checklist.json`) and reads the `pci_dss` array for every control check.",
                "2. Every checklist check is linked to one or more PCI DSS controls (`control`) and a technical rationale (`reason`) that explains why the check supports that control.",
                "3. During analysis, findings inherit those mappings; if one finding is tied to a control, that control is marked as `KO` in this annex and includes finding evidence context.",
                "4. Controls with mapped checks but without linked findings remain `OK`, meaning no violation was detected for the evaluated evidence in this specific audit scope.",
                "5. This annex is evidence-driven and scope-bounded: it reflects only executed skills, collected evidence, and controls explicitly mapped in the checklists used for this run.",
                "",
            ]
        else:
            lines += [
                "**Metodologia de mapeo aplicada por Drystone**",
                "",
                "1. Drystone carga los checklists de cada skill ejecutada (`drystone/skills/<skill>/checklist.json`) y lee el array `pci_dss` de cada check de control.",
                "2. Cada check del checklist se vincula a uno o mas controles PCI DSS (`control`) y a una justificacion tecnica (`reason`) que explica por que ese check soporta dicho control.",
                "3. Durante el analisis, los findings heredan ese mapeo; si un finding queda asociado a un control, ese control se marca como `KO` en este anexo e incluye contexto de evidencia.",
                "4. Los controles con checks mapeados pero sin findings asociados permanecen en `OK`, lo que indica que no se detecto incumplimiento para la evidencia evaluada en este alcance.",
                "5. Este anexo es evidence-driven y acotado por alcance: refleja solo skills ejecutadas, evidencia recolectada y controles mapeados explicitamente en los checklists usados en esta corrida.",
                "",
            ]

        current_req = None
        for ctrl in ko_controls:
            req_num = ctrl["requirement"]
            if req_num != current_req:
                if current_req is not None:
                    lines.append("")
                current_req = req_num
                req_name = get_requirement_name(req_num)
                lines.append(f"### Requirement {req_num} · {req_name}")
                lines.append("")
                lines.append(f"| {header_control} | {header_status} | {header_just} |")
                lines.append("|---------|--------|---------------|")

            cid = ctrl["control"]
            findings_for_ctrl = ctrl["findings"]
            # Extract reason from the first finding that has a per-control reason
            finding_reason = None
            for f in findings_for_ctrl:
                for p in f.get("pci_dss") or []:
                    if p.get("control") == cid and p.get("reason"):
                        finding_reason = p["reason"]
                        break
                if finding_reason:
                    break
            reason = finding_reason or ctrl.get("reason", "")
            # List all finding IDs contributing to this KO
            fids = [f.get("id", "") for f in findings_for_ctrl if f.get("id")]
            fids_str = ", ".join(fids)
            just = f"**{fids_str}**: {reason}" if fids_str else reason

            # Escape pipe chars in justification to avoid breaking Markdown table
            just = just.replace("|", "\\|")
            lines.append(f"| {cid} | ❌ {ko_label} | {just} |")

        lines += ["", ""]

        return "\n".join(lines)

    def _pci_dss_compliance_summary(self) -> str:
        """Generate PCI DSS compliance summary section."""
        findings = self.findings.get("findings", [])
        skill_name = self._get_skill_display_name(self.findings.get("skill", "unknown").lower())

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
