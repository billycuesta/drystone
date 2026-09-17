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
        payload: Dict[str, Any] = {
            "metadata": self._metadata(),
            "findings": self.findings.get("findings", []),
            "summary": self.findings.get("summary", {}),
            "statistics": self._calculate_statistics(),
            "export_timestamp": datetime.utcnow().isoformat(),
        }
        attack_paths = self._collect_attack_paths()
        if attack_paths:
            payload["attack_path_candidates"] = attack_paths
        correlation_summary = self._correlation_summary()
        if correlation_summary:
            payload["correlation_summary"] = correlation_summary
        trend = self._trend_summary()
        if trend:
            payload["trend"] = trend
        return payload

    def _trend_summary(self) -> Dict[str, Any]:
        """Load findings/trend.json (P2 #3), if this client has a prior audit."""
        trend_path = self.session.base_path / "findings" / "trend.json"
        if not trend_path.exists():
            return {}
        try:
            with open(trend_path) as f:
                data = json.load(f) or {}
        except Exception:
            return {}
        if not isinstance(data, dict) or not data.get("previous_session"):
            return {}
        return data

    def _correlation_summary(self) -> Dict[str, Any]:
        """Load report-visible correlation truncation metadata without embedding all chains."""
        corr_path = self.session.base_path / "findings" / "correlated.json"
        if not corr_path.exists():
            return {}
        try:
            with open(corr_path) as f:
                data = json.load(f) or {}
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}
        summary = {
            "total_correlations": data.get("total_correlations", 0),
            "truncated": bool(data.get("truncated", False)),
            "warnings": data.get("warnings") or [],
            "truncation": data.get("truncation"),
        }
        if not summary["total_correlations"] and not summary["truncated"] and not summary["warnings"]:
            return {}
        return summary

    def _collect_attack_paths(self) -> list:
        """Collect attack-path-candidates.json from evidence directories.

        For single-skill exports: reads evidence/<skill>/attack-path-candidates.json.
        For aggregated exports: reads all evidence/*/attack-path-candidates.json and
        merges them sorted by overall_score descending.
        """
        skill = self.findings.get("skill", "")
        evidence_base = self.session.base_path / "evidence"
        if not evidence_base.exists():
            return []

        all_paths: list = []
        if skill and skill != "aggregated":
            # Single skill — look directly under evidence/<skill>/
            candidate_file = evidence_base / skill / "attack-path-candidates.json"
            if candidate_file.exists():
                try:
                    with open(candidate_file) as f:
                        data = json.load(f)
                    for path in data.get("paths", []):
                        path["skill"] = skill
                        all_paths.append(path)
                except Exception:
                    pass
        else:
            # Aggregated — scan all skill subdirectories
            for skill_dir in sorted(evidence_base.iterdir()):
                if not skill_dir.is_dir():
                    continue
                candidate_file = skill_dir / "attack-path-candidates.json"
                if not candidate_file.exists():
                    continue
                try:
                    with open(candidate_file) as f:
                        data = json.load(f)
                    for path in data.get("paths", []):
                        path["skill"] = skill_dir.name
                        all_paths.append(path)
                except Exception:
                    pass

        # Sort by overall_score descending
        all_paths.sort(key=lambda x: x.get("overall_score", 0), reverse=True)
        return all_paths

    def _metadata(self) -> Dict[str, Any]:
        """Generate metadata section."""
        report_meta = self.findings.get("report_metadata", {}) or {}
        metadata: Dict[str, Any] = {
            "client": self.session.client_name,
            "aws_account": self.session.account_id,
            "skill": self.findings.get("skill", "unknown"),
            "analyzed_at": self.findings.get("analyzed_at", datetime.utcnow().isoformat()),
            "checklist_version": self.findings.get("checklist_version", "1.0"),
            "report_format_version": self.REPORT_FORMAT_VERSION,
            "evidence_count": self.findings.get("evidence_count", 0),
        }
        integrity_hash = report_meta.get("integrity_manifest_sha256")
        if integrity_hash:
            metadata["integrity_manifest_sha256"] = integrity_hash
            metadata["integrity_manifest_file"] = report_meta.get("integrity_manifest_file")
        return metadata

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

        top_resources = sorted(resource_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "risk_distribution": risk_distribution,
            "top_affected_resources": [
                {"resource": r[0], "finding_count": r[1]} for r in top_resources
            ],
            "average_risk_score": summary.get("overall_risk_score", 0),
            "remediation_count": len([f for f in findings if f.get("remediation")]),
            "cis_referenced": len([f for f in findings if f.get("cis_reference")]),
        }
