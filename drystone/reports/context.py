"""Canonical report context shared by all formatters.

The context object centralizes report-visible metadata and safe/redacted payloads
so Markdown/PDF/JSON/Pentest outputs can migrate away from independently reading
sidecar files and applying inconsistent redaction rules.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

from drystone.reports.safety import redact_secrets_in_obj
from drystone.storage.session import AuditSession


@dataclass(frozen=True)
class ReportContext:
    """Canonical, report-safe view over findings and session sidecars."""

    metadata: Dict[str, Any]
    findings: Dict[str, Any]
    redacted_findings: Dict[str, Any]
    redaction_count: int = 0
    trend: Dict[str, Any] = field(default_factory=dict)
    correlation_summary: Dict[str, Any] = field(default_factory=dict)
    attack_path_candidates: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_findings(
        cls,
        findings: Dict[str, Any],
        session: AuditSession,
        *,
        report_format_version: str,
    ) -> "ReportContext":
        """Build canonical report context from formatter inputs.

        Args:
            findings: Parsed findings payload already selected for this report.
            session: Audit session that owns sidecar paths.
            report_format_version: Formatter output schema version.
        """

        source_findings = copy.deepcopy(findings or {})
        redacted_findings, redaction_count = redact_secrets_in_obj(source_findings)
        metadata = _metadata(source_findings, session, report_format_version, redaction_count)
        return cls(
            metadata=metadata,
            findings=source_findings,
            redacted_findings=redacted_findings,
            redaction_count=redaction_count,
            trend=_trend_summary(session),
            correlation_summary=_correlation_summary(session),
            attack_path_candidates=_collect_attack_paths(source_findings, session),
        )


def _metadata(
    findings: Dict[str, Any],
    session: AuditSession,
    report_format_version: str,
    redaction_count: int,
) -> Dict[str, Any]:
    report_meta = findings.get("report_metadata", {}) or {}
    metadata: Dict[str, Any] = {
        "client": session.client_name,
        "aws_account": session.account_id,
        "skill": findings.get("skill", "unknown"),
        "analyzed_at": findings.get("analyzed_at", datetime.utcnow().isoformat()),
        "checklist_version": findings.get("checklist_version", "1.0"),
        "report_format_version": report_format_version,
        "evidence_count": findings.get("evidence_count", 0),
    }
    integrity_hash = report_meta.get("integrity_manifest_sha256")
    if integrity_hash:
        metadata["integrity_manifest_sha256"] = integrity_hash
        metadata["integrity_manifest_file"] = report_meta.get("integrity_manifest_file")
    if redaction_count:
        metadata["redactions_applied"] = redaction_count
    return metadata


def _trend_summary(session: AuditSession) -> Dict[str, Any]:
    """Load findings/trend.json, if this client has a prior audit."""
    trend_path = session.base_path / "findings" / "trend.json"
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


def _correlation_summary(session: AuditSession) -> Dict[str, Any]:
    """Load report-visible correlation truncation metadata without all chains."""
    corr_path = session.base_path / "findings" / "correlated.json"
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


def _collect_attack_paths(findings: Dict[str, Any], session: AuditSession) -> List[Dict[str, Any]]:
    """Collect attack path candidate sidecars for single-skill or aggregated reports."""
    skill = findings.get("skill", "")
    evidence_base = session.base_path / "evidence"
    if not evidence_base.exists():
        return []

    all_paths: List[Dict[str, Any]] = []
    if skill and skill != "aggregated":
        candidate_file = evidence_base / skill / "attack-path-candidates.json"
        if candidate_file.exists():
            _append_attack_paths(all_paths, candidate_file, str(skill))
    else:
        for skill_dir in sorted(evidence_base.iterdir()):
            if not skill_dir.is_dir():
                continue
            candidate_file = skill_dir / "attack-path-candidates.json"
            if candidate_file.exists():
                _append_attack_paths(all_paths, candidate_file, skill_dir.name)

    all_paths.sort(key=lambda item: item.get("overall_score", 0), reverse=True)
    return all_paths


def _append_attack_paths(paths: List[Dict[str, Any]], candidate_file, skill: str) -> None:
    try:
        with open(candidate_file) as f:
            data = json.load(f)
    except Exception:
        return
    if not isinstance(data, dict):
        return
    for path in data.get("paths", []) or []:
        if isinstance(path, dict):
            path = dict(path)
            path["skill"] = skill
            paths.append(path)
