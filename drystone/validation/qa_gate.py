"""Post-scan QA gate checks for report robustness."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List

PLACEHOLDER_PATTERNS = [
    "will be listed here",
    "to be completed",
    "tbd",
]


@dataclass
class QAGateResult:
    passed: bool
    issues: List[str] = field(default_factory=list)
    critical_coverage_pct: float = 100.0


def _load_json(path: Path) -> dict:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


IAM_TEXT_GUARDS: Dict[str, Dict[str, List[str]]] = {
    "IAM-007": {
        "required_any": ["inline polic"],
        "forbidden": ["password reuse", "password policy", "password expiration"],
    },
    "IAM-026": {
        "required_any": ["permission boundar"],
        "forbidden": ["can grant themselves", "delegated administration"],
    },
    "IAM-041": {
        "required_any": ["administratoraccess", "poweruseraccess"],
        "forbidden": ["wildcard action", "wildcard resource"],
    },
}

NETWORK_TEXT_GUARDS: Dict[str, Dict[str, List[str]]] = {
    "NET-007": {
        "required_any": ["network firewall", "internet gateway", "stateful inspection"],
        "forbidden": ["sensitive ports", "ssh", "rdp"],
    },
    "NET-008": {
        "required_any": ["critical workload", "public subnet"],
        "forbidden": ["overlapping", "redundant security group"],
    },
    "NET-009": {
        "required_any": ["security group", "broad cidr", "non-web"],
        "forbidden": ["vpc peering", "peered vpc"],
    },
    "NET-010": {
        "required_any": ["network acl", "nacl", "allow-all"],
        "forbidden": ["transit gateway"],
    },
    "NET-011": {
        "required_any": ["security group", "description"],
        "forbidden": ["vpc endpoint", "privatelink"],
    },
    "NET-016": {
        "required_any": ["subnet", "default", "nacl"],
        "forbidden": ["security group-to-security group", "trust entire security"],
    },
    "NET-025": {
        "required_any": ["subnet", "classification", "tag"],
        "forbidden": ["ssh", "rdp", "administrative ports"],
    },
    "NET-027": {
        "required_any": ["security group", "tag"],
        "forbidden": ["vpc endpoint", "privatelink", "aws api calls"],
    },
}


def _iter_findings(payload: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    findings = payload.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                yield finding


def _collect_evidence_arns(obj: Any) -> set[str]:
    arns: set[str] = set()
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key.lower() in {"arn", "policyarn", "rolearn", "userarn"} and isinstance(val, str):
                if val.startswith("arn:"):
                    arns.add(val)
            arns.update(_collect_evidence_arns(val))
    elif isinstance(obj, list):
        for item in obj:
            arns.update(_collect_evidence_arns(item))
    return arns


def _resource_name(resource: str) -> str:
    if "/" in resource:
        return resource.rsplit("/", 1)[-1]
    return resource.rsplit(":", 1)[-1]


def _metrics_quality_issues(base_path: Path, skills: List[str]) -> List[str]:
    metrics_path = base_path / "metrics.json"
    if not metrics_path.exists():
        return []

    metrics = _load_json(metrics_path)
    if not isinstance(metrics, dict):
        return []

    issues: List[str] = []
    validation_failures = int(metrics.get("validation_failures") or 0)
    if validation_failures > 0:
        issues.append(f"Metrics report {validation_failures} validation failure(s)")

    metrics_skills = metrics.get("skills")
    if not isinstance(metrics_skills, dict):
        return issues

    requested = {str(skill).lower() for skill in skills}
    for skill, payload in sorted(metrics_skills.items()):
        if requested and str(skill).lower() not in requested:
            continue
        if not isinstance(payload, dict):
            continue

        status = str(payload.get("status") or "").lower()
        confidence = str(payload.get("confidence_level") or "").lower()
        partial = (
            status == "partial"
            or bool(payload.get("partial_results"))
            or bool(payload.get("llm_fallback_used"))
            or payload.get("validation_passed") is False
        )
        if partial:
            reason_parts = []
            if status:
                reason_parts.append(f"status={status}")
            if confidence:
                reason_parts.append(f"confidence={confidence}")
            if payload.get("llm_fallback_used"):
                reason_parts.append("llm_fallback_used=true")
            if payload.get("validation_passed") is False:
                reason_parts.append("validation_passed=false")
            issues.append(f"Skill {skill} execution incomplete ({', '.join(reason_parts)})")

    return issues


def run_qa_gate(base_path: Path, skills: List[str]) -> QAGateResult:
    """Run QA checks over a completed audit session."""
    issues: List[str] = []

    audit_log = base_path / "audit.log"
    log_text = audit_log.read_text() if audit_log.exists() else ""

    issues.extend(_metrics_quality_issues(base_path, skills))

    missing_critical = re.findall(r"Missing Critical check:\s*([A-Z0-9-]+)", log_text)
    if missing_critical:
        uniq = sorted(set(missing_critical))
        issues.append(f"Missing critical checks detected: {', '.join(uniq)}")

    # Critical coverage based on checklist critical IDs minus explicitly missing IDs from log.
    critical_ids: List[str] = []
    for skill in skills:
        checklist_path = Path(__file__).parents[1] / "skills" / skill / "checklist.json"
        checklist = _load_json(checklist_path)
        for item in checklist.get("items", []) or []:
            if str(item.get("severity", "")).lower() == "critical":
                cid = str(item.get("id", "")).strip()
                if cid:
                    critical_ids.append(cid)

    critical_set = set(critical_ids)
    missing_set = set(missing_critical)
    if critical_set:
        covered = max(0, len(critical_set - missing_set))
        coverage_pct = (covered / len(critical_set)) * 100.0
    else:
        coverage_pct = 100.0

    if coverage_pct < 100.0:
        issues.append(f"Critical checklist coverage below 100% ({coverage_pct:.1f}%)")

    reports_dir = base_path / "reports"
    if reports_dir.exists():
        for md in reports_dir.glob("*.md"):
            text = md.read_text().lower()
            for pat in PLACEHOLDER_PATTERNS:
                if pat in text:
                    issues.append(f"Placeholder text found in report {md.name}: '{pat}'")
                    break

    evidence_arns: set[str] = set()
    evidence_root = base_path / "evidence"
    if evidence_root.exists():
        for ev in evidence_root.glob("**/*.json"):
            evidence_arns.update(_collect_evidence_arns(_load_json(ev)))

    findings_dir = base_path / "findings"
    if findings_dir.exists():
        for finding_file in findings_dir.glob("*.json"):
            if finding_file.name == "correlated.json":
                continue
            for finding in _iter_findings(_load_json(finding_file)):
                fid = str(finding.get("id") or "")
                text = " ".join(
                    str(finding.get(field) or "").lower()
                    for field in ("title", "description", "remediation")
                )
                guard = IAM_TEXT_GUARDS.get(fid) or NETWORK_TEXT_GUARDS.get(fid)
                if guard:
                    if not any(req in text for req in guard.get("required_any", [])):
                        issues.append(f"{finding_file.name}:{fid} text does not match expected topic")
                    for forbidden in guard.get("forbidden", []):
                        if forbidden in text:
                            issues.append(
                                f"{finding_file.name}:{fid} contains mismatched text: '{forbidden}'"
                            )
                            break

                affected = [str(r) for r in (finding.get("affected_resources") or [])]
                refs = [str(r) for r in (finding.get("evidence_refs") or [])]
                severity = str(finding.get("severity") or "").lower()
                impact = finding.get("impact")

                high_or_critical = severity in {"critical", "high"}
                if high_or_critical and not str(impact or "").strip():
                    issues.append(
                        f"{finding_file.name}:{fid} {severity} finding has empty impact"
                    )

                for resource in affected:
                    if "arn:aws:iam::*" not in resource:
                        continue
                    name = _resource_name(resource)
                    if any(_resource_name(arn) == name and "arn:aws:iam::*" not in arn for arn in evidence_arns):
                        issues.append(
                            f"{finding_file.name}:{fid} uses wildcard account ARN despite real ARN evidence: {resource}"
                        )
                        break

                if affected and (finding.get("exploitability_status") == "validated" or high_or_critical):
                    if not refs:
                        issues.append(f"{finding_file.name}:{fid} validated finding has no evidence_refs")
                    elif len(refs) < len(affected):
                        issues.append(
                            f"{finding_file.name}:{fid} evidence_refs do not cover all affected resources"
                        )

    return QAGateResult(passed=len(issues) == 0, issues=issues, critical_coverage_pct=coverage_pct)
