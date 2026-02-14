"""JSON report formatter."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from drystone.reports.formats.base import BaseFormatter


class JSONFormatter(BaseFormatter):
    """Formats findings as structured JSON export."""

    @property
    def file_extension(self) -> str:
        """File extension for JSON."""
        return "json"

    def generate(self) -> Path:
        """Generate JSON export.

        Returns:
            Path to generated JSON file
        """
        json_content = self._build_json()

        # Include skill name in filename to avoid overwriting when multiple skills
        skill_name = self.findings.get("skill", "audit").lower()
        report_path = self.reports_path / f"findings-export-{skill_name}.{self.file_extension}"

        with open(report_path, "w") as f:
            json.dump(json_content, f, indent=2, default=str)

        return report_path

    def _build_json(self) -> Dict[str, Any]:
        """Build structured JSON export."""
        return {
            "metadata": self._metadata(),
            "findings": self.findings.get("findings", []),
            "summary": self.findings.get("summary", {}),
            "statistics": self._calculate_statistics(),
            "export_timestamp": datetime.utcnow().isoformat(),
        }

    def _metadata(self) -> Dict[str, Any]:
        """Generate metadata section."""
        return {
            "client": self.session.client_name,
            "aws_account": self.session.account_id,
            "skill": self.findings.get("skill", "unknown"),
            "analyzed_at": self.findings.get("analyzed_at", datetime.utcnow().isoformat()),
            "checklist_version": self.findings.get("checklist_version", "1.0"),
            "evidence_count": self.findings.get("evidence_count", 0),
        }

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate additional statistics for export."""
        findings = self.findings.get("findings", [])
        summary = self.findings.get("summary", {})

        # Risk distribution
        risk_distribution = {
            "0.0-2.0": 0,
            "2.1-4.0": 0,
            "4.1-6.0": 0,
            "6.1-8.0": 0,
            "8.1-10.0": 0,
        }

        for finding in findings:
            score = finding.get("risk_score", 0)
            if score <= 2.0:
                risk_distribution["0.0-2.0"] += 1
            elif score <= 4.0:
                risk_distribution["2.1-4.0"] += 1
            elif score <= 6.0:
                risk_distribution["4.1-6.0"] += 1
            elif score <= 8.0:
                risk_distribution["6.1-8.0"] += 1
            else:
                risk_distribution["8.1-10.0"] += 1

        # Top affected resources
        resource_counts: Dict[str, int] = {}
        for finding in findings:
            for resource in finding.get("affected_resources", []):
                resource_counts[resource] = resource_counts.get(resource, 0) + 1

        top_resources = sorted(
            resource_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return {
            "risk_distribution": risk_distribution,
            "top_affected_resources": [
                {"resource": r[0], "finding_count": r[1]} for r in top_resources
            ],
            "average_risk_score": summary.get("overall_risk_score", 0),
            "remediation_count": len([f for f in findings if f.get("remediation")]),
            "cis_referenced": len(
                [f for f in findings if f.get("cis_reference")]
            ),
        }
