"""Post-scan QA gate checks for report robustness."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

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


def run_qa_gate(base_path: Path, skills: List[str]) -> QAGateResult:
    """Run QA checks over a completed audit session."""
    issues: List[str] = []

    audit_log = base_path / "audit.log"
    log_text = audit_log.read_text() if audit_log.exists() else ""

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

    return QAGateResult(passed=len(issues) == 0, issues=issues, critical_coverage_pct=coverage_pct)
