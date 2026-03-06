"""Markdown report formatter."""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from drystone.reports.formats.base import BaseFormatter

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
        skill_name = self.findings.get("skill", "audit").lower()
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

        # Only include PCI DSS summary for PCI compliance reports
        if self.config.report_type == "pci-dss":
            parts.append(self._pci_dss_compliance_summary())

        parts.extend(
            [
                self._findings_by_severity(),
                self._observations(),
                self._remediation_timeline(),
                self._references(),
                self._footer(),
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
**Skill:** {skill.upper()}
 **AWS Account:** {account_id}
 **Generated:** {timestamp}
 **Version:** {self.findings.get("checklist_version", "1.0")}
 **Report Min Severity:** {str(min_sev).upper()}
{filter_note}

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
            return ""

        section = "## 🗂️ Resources Audited\n\n"
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
            detail += "\n**Affected Resources:**\n"
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
