"""Canonical report context shared by all formatters.

The context object centralizes report-visible metadata and safe/redacted payloads
so Markdown/PDF/JSON/Pentest outputs can migrate away from independently reading
sidecar files and applying inconsistent redaction rules.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from drystone.reports.safety import redact_secrets_in_obj
from drystone.storage.session import AuditSession


def _utc_now_iso() -> str:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


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
    coverage_gaps: List[Dict[str, Any]] = field(default_factory=list)

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
        coverage_gaps = _collect_coverage_gaps(source_findings, redacted_findings, session)
        metadata = _metadata(source_findings, session, report_format_version, redaction_count)
        if coverage_gaps:
            metadata["coverage_gap_count"] = len(coverage_gaps)
        return cls(
            metadata=metadata,
            findings=source_findings,
            redacted_findings=redacted_findings,
            redaction_count=redaction_count,
            trend=_trend_summary(session),
            correlation_summary=_correlation_summary(session),
            attack_path_candidates=_collect_attack_paths(source_findings, session),
            coverage_gaps=coverage_gaps,
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
        "analyzed_at": findings.get("analyzed_at") or _utc_now_iso(),
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


_COVERAGE_GAP_REASONS: Dict[str, str] = {
    "collection_failed": "Required evidence collection failed before this control could be evaluated.",
    "partial_collection": "Only partial evidence was collected, so this control could not be evaluated deterministically.",
    "missing_evidence": "Required evidence was not present in the collected dataset.",
    "evidence_parse_failed": "Collected evidence could not be parsed reliably for this control.",
    "precheck_error": "The deterministic pre-check errored before reaching a reliable result.",
    "not_supported_by_collector": "The current collector does not yet support the evidence needed for this deterministic control.",
}


def _collect_coverage_gaps(
    findings: Dict[str, Any], redacted_findings: Dict[str, Any], session: AuditSession
) -> List[Dict[str, Any]]:
    """Build redacted client-visible coverage gaps from persisted WARN metadata."""
    skill = str(findings.get("skill") or "unknown")
    if skill == "aggregated":
        return _collect_aggregate_coverage_gaps(session)
    return _coverage_gaps_from_payload(skill, redacted_findings)


def _collect_aggregate_coverage_gaps(session: AuditSession) -> List[Dict[str, Any]]:
    findings_dir = session.base_path / "findings"
    if not findings_dir.exists():
        return []

    gaps: List[Dict[str, Any]] = []
    for finding_file in sorted(findings_dir.glob("*.json")):
        if finding_file.name in {"correlated.json", "trend.json"}:
            continue
        try:
            with open(finding_file) as f:
                payload = json.load(f) or {}
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        redacted_payload, _ = redact_secrets_in_obj(payload)
        skill = str(payload.get("skill") or finding_file.stem)
        if skill == "aggregated":
            continue
        gaps.extend(_coverage_gaps_from_payload(skill, redacted_payload))
    gaps.sort(key=lambda gap: (str(gap.get("skill", "")), str(gap.get("check_id", ""))))
    return gaps


def _coverage_gaps_from_payload(skill: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    analysis_meta = payload.get("analysis_metadata") or {}
    if not isinstance(analysis_meta, dict):
        return []

    warn_ids = [str(cid) for cid in analysis_meta.get("pre_check_warn_ids") or [] if cid]
    reasons = analysis_meta.get("pre_check_warn_reasons") or []
    reasons_by_id: Dict[str, Dict[str, Any]] = {}
    if isinstance(reasons, list):
        for item in reasons:
            if isinstance(item, dict) and item.get("check_id"):
                reasons_by_id[str(item["check_id"])] = item

    resolved_check_ids = _finding_check_ids(payload)
    check_ids = sorted((set(warn_ids) | set(reasons_by_id)) - resolved_check_ids)
    if not check_ids:
        return []

    titles = _check_titles(skill)
    gaps: List[Dict[str, Any]] = []
    for check_id in check_ids:
        reason_payload = reasons_by_id.get(check_id, {})
        reason_code = str(reason_payload.get("reason_code") or "unknown")
        gap = {
            "check_id": check_id,
            "title": titles.get(check_id, "Unknown control"),
            "skill": skill,
            "reason_code": reason_code,
            "reason": _COVERAGE_GAP_REASONS.get(
                reason_code,
                "Required evidence was not sufficient for deterministic evaluation of this control.",
            ),
        }
        evidence_summary = reason_payload.get("evidence_summary")
        if evidence_summary:
            gap["evidence_summary"] = str(evidence_summary)
        gaps.append(gap)
    return gaps


def _finding_check_ids(payload: Dict[str, Any]) -> set[str]:
    findings = payload.get("findings") or []
    if not isinstance(findings, list):
        return set()
    check_ids: set[str] = set()
    for finding in findings:
        if isinstance(finding, dict) and finding.get("id"):
            check_ids.add(str(finding["id"]))
    return check_ids


def _check_titles(skill: str) -> Dict[str, str]:
    checklist_path = Path(__file__).parents[1] / "skills" / skill / "checklist.json"
    if not checklist_path.exists():
        return {}
    try:
        with open(checklist_path) as f:
            checklist = json.load(f) or {}
    except Exception:
        return {}
    titles: Dict[str, str] = {}
    for item in checklist.get("items", []) or []:
        if isinstance(item, dict) and item.get("id"):
            titles[str(item["id"])] = str(item.get("title") or "Unknown control")
    return titles
