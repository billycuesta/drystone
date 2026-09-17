"""Multi-run trend analysis (P2 #3).

Diffs the current audit's findings against the most recent prior session for
the same client, surfacing which findings are new, which were fixed since
last time, and which are still open.

Deliberately no separate persisted "history index": `audit-logs/{client}_
{timestamp}/` directory names are already timestamp-sortable (see
`AuditSession`), so "the most recent prior session for this client" is a
glob + sort, not state that has to be created and kept in sync on every run.
Just as lightweight as a real index, with one less thing that can drift.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})$")


def _session_name_parts(session_dir: Path) -> Optional[Tuple[str, str]]:
    """Return (client_name, timestamp) parsed from an AuditSession directory."""
    match = _TIMESTAMP_RE.search(session_dir.name)
    if not match:
        return None
    timestamp = match.group(1)
    suffix = f"_{timestamp}"
    if not session_dir.name.endswith(suffix):
        return None
    return session_dir.name[: -len(suffix)], timestamp


def _session_timestamp(session_dir: Path) -> Optional[str]:
    """Extract the trailing timestamp from an `AuditSession` directory name."""
    parts = _session_name_parts(session_dir)
    return parts[1] if parts else None


def find_previous_session(
    client_name: str, audit_logs_dir: Path, exclude: Path
) -> Optional[Path]:
    """Return the most recent prior session directory for this client.

    "Most recent prior" means the highest timestamp strictly earlier than
    `exclude`'s own timestamp -- not merely "any directory that isn't
    exclude" -- so this is safe to call against a directory that already
    contains later runs too.
    """
    if not audit_logs_dir.exists():
        return None

    exclude_resolved = exclude.resolve()
    exclude_ts = _session_timestamp(exclude)

    candidates: List[Tuple[str, Path]] = []
    for entry in audit_logs_dir.iterdir():
        if not entry.is_dir() or entry.resolve() == exclude_resolved:
            continue
        parts = _session_name_parts(entry)
        if parts is None:
            continue
        entry_client_name, ts = parts
        if entry_client_name != client_name:
            continue
        if exclude_ts is not None and ts >= exclude_ts:
            continue
        candidates.append((ts, entry))

    if not candidates:
        return None
    candidates.sort(key=lambda pair: pair[0])
    return candidates[-1][1]


def _finding_identity(finding: Dict[str, Any]) -> Tuple[str, Tuple[str, ...]]:
    """Identity used to match "the same finding" across two sessions.

    Keyed on (id, affected_resources) rather than id alone: a check ID with
    a different resource set (e.g. a different security group) is a
    different instance of the finding, not a persisting one.
    """
    resources = finding.get("affected_resources") or []
    return (str(finding.get("id", "")), tuple(sorted(str(r) for r in resources)))


@dataclass
class SkillTrend:
    skill: str
    new: List[Dict[str, Any]] = field(default_factory=list)
    fixed: List[Dict[str, Any]] = field(default_factory=list)
    persisting_count: int = 0


@dataclass
class TrendResult:
    previous_session: Optional[str] = None  # session directory name, or None

    skills: List[SkillTrend] = field(default_factory=list)

    @property
    def has_baseline(self) -> bool:
        return self.previous_session is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "previous_session": self.previous_session,
            "skills": [
                {
                    "skill": s.skill,
                    "new": s.new,
                    "fixed": s.fixed,
                    "persisting_count": s.persisting_count,
                }
                for s in self.skills
            ],
        }


def compute_trend(
    current_findings: Dict[str, Dict[str, Any]], previous_session_dir: Optional[Path]
) -> TrendResult:
    """Diff `current_findings` (skill_name -> findings_data, as produced by
    `audit_runner.run_audit`) against the prior session's `findings/{skill}.json`.

    Only skills present in *both* runs are compared: a skill audited only
    this time has no baseline to diff against (its findings just aren't
    "new since last audit", they're this run's first findings), and a skill
    audited only last time but not this time is out of scope now, not
    "fixed" -- reporting it as fixed would be actively misleading.
    """
    if previous_session_dir is None:
        return TrendResult(previous_session=None)

    result = TrendResult(previous_session=previous_session_dir.name)
    findings_dir = previous_session_dir / "findings"

    for skill_name, findings_data in current_findings.items():
        prev_path = findings_dir / f"{skill_name}.json"
        if not prev_path.exists():
            continue
        try:
            prev_data = json.loads(prev_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue

        current_list = findings_data.get("findings") or []
        prev_list = prev_data.get("findings") or []

        current_by_identity = {_finding_identity(f): f for f in current_list}
        prev_by_identity = {_finding_identity(f): f for f in prev_list}

        new = [f for key, f in current_by_identity.items() if key not in prev_by_identity]
        fixed = [f for key, f in prev_by_identity.items() if key not in current_by_identity]
        persisting_count = sum(1 for key in current_by_identity if key in prev_by_identity)

        if new or fixed or persisting_count:
            result.skills.append(
                SkillTrend(skill=skill_name, new=new, fixed=fixed, persisting_count=persisting_count)
            )

    return result
