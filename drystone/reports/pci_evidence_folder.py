"""PCI DSS evidence folder generator.

Writes one self-contained Markdown file per (PCI DSS control, checklist item)
pair into ``<session>/pci-evidence/`` for ``report_type == "pci-dss"`` audits,
so a QSA gets attachable, per-control supporting evidence alongside the
summarised PCI DSS report.

Each file follows the same structure: the query that produced the evidence ->
the raw result (fenced code block) -> an assessment. The assessment is reused
verbatim from text authored during the scan (the finding narrative, or the
pre-check evidence summary plus the checklist's PCI DSS reason) -- this module
makes no LLM calls.

Status is resolved per checklist item from the recomputed pre-check results
and the skill's findings directly, never from ``build_pci_controls_map``'s
collapsed ok/ko status (which cannot distinguish SKIP from PASS):

- FAIL: a finding exists for the item (LLM-originated or pre-check-injected),
  or the deterministic pre-check failed.
- PASS: the deterministic pre-check passed and no finding exists.
- INCONCLUSIVE: the pre-check was skipped or warned, or no pre-check exists
  and the AI analysis raised no finding -- never silently treated as compliant.
"""

from __future__ import annotations

import json
import logging
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple, cast

from drystone.reports.pci_cli_queries import resolve_query
from drystone.reports.pci_text_table import apply_output_spec
from drystone.validation.pre_checks import PRE_CHECK_REGISTRY, PreCheckResult

if TYPE_CHECKING:
    from drystone.models import WizardConfig
    from drystone.storage.session import AuditSession

logger = logging.getLogger(__name__)

_SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
_QSA_DEPTH_ORDER = {"obvious": 0, "standard": 1, "deep": 2}
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"

_PASS_CLOSING = "Control requirement met based on automated evidence collected during this audit."
_INCONCLUSIVE_CLOSING = (
    "Evidence collected during this audit was insufficient to make an automated "
    "determination for this control. Manual QSA review recommended."
)


@dataclass
class _EvidenceEntry:
    """Everything needed to render one evidence file."""

    skill_name: str
    item: Dict[str, Any]
    control: str
    reason: str
    status: str
    pre_check: Optional[PreCheckResult]
    finding: Optional[Dict[str, Any]]
    consulted_stems: Tuple[str, ...]
    evidence: Dict[str, Any]
    region: str
    captured_at: str


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def generate_pci_evidence_folder(
    config: "WizardConfig",
    session: "AuditSession",
    all_findings: Dict[str, Any],
    skills: List[str],
) -> Path:
    """Write one Markdown evidence file per (control, checklist-item) pair
    into ``session.get_pci_evidence_path()``. Returns that path.

    Args:
        config: Audit configuration (``qsa_depth`` filters the checklist
            exactly as ``BaseSkill.analyze()`` did).
        session: Current audit session (evidence is read from disk).
        all_findings: ``{skill_name: findings_dict}`` as produced by analysis.
        skills: Skills to cover (those analysed in this audit).
    """
    out_dir = cast(Path, session.get_pci_evidence_path())
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    used_names: set = set()

    for entry in _iter_evidence_entries(config, session, all_findings, skills):
        filename = _filename(getattr(config, "project_id", None) or session.client_name, entry, used_names)
        content = _render_markdown(entry, generated_at)
        (out_dir / filename).write_text(content, encoding="utf-8")

    return out_dir


# ---------------------------------------------------------------------------
# Data assembly
# ---------------------------------------------------------------------------


def _load_checklist(skill_name: str, qsa_depth: str) -> Optional[Dict[str, Any]]:
    """Load a skill's checklist filtered by QSA depth, mirroring BaseSkill.analyze()."""
    checklist_path = _SKILLS_DIR / skill_name / "checklist.json"
    if not checklist_path.exists():
        return None
    with open(checklist_path) as f:
        checklist: Dict[str, Any] = json.load(f)

    max_depth = _QSA_DEPTH_ORDER.get(qsa_depth, 1)
    checklist["items"] = [
        item
        for item in checklist.get("items", [])
        if isinstance(item, dict)
        and _QSA_DEPTH_ORDER.get(item.get("qsa_visibility", "standard"), 1) <= max_depth
    ]
    return checklist


class _AccessRecordingEvidence(dict):
    """Dict wrapper recording top-level evidence stems consulted by a pre-check."""

    def __init__(self, evidence: Dict[str, Any]):
        super().__init__(evidence)
        self.consulted_stems: List[str] = []

    def _record(self, key: Any) -> None:
        stem = str(key)
        if stem not in self.consulted_stems:
            self.consulted_stems.append(stem)

    def get(self, key: Any, default: Any = None) -> Any:  # noqa: D401 - mirrors dict.get
        self._record(key)
        return super().get(key, default)

    def __getitem__(self, key: Any) -> Any:
        self._record(key)
        return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        self._record(key)
        return super().__contains__(key)


def _load_skill_evidence(session: "AuditSession", skill_name: str) -> Dict[str, Any]:
    evidence_path = session.get_evidence_path(skill_name)
    evidence: Dict[str, Any] = {}
    for json_file in sorted(evidence_path.glob("*.json")):
        try:
            with open(json_file) as f:
                evidence[json_file.stem] = json.load(f)
        except Exception as exc:
            logger.warning("PCI evidence: could not load %s: %s", json_file, exc)

    try:
        from drystone.skills.registry import discover_skills

        manifest = discover_skills().get(skill_name)
        if manifest is not None:
            manifest.skill_class()._load_extra_evidence(evidence, evidence_path)
    except Exception as exc:
        logger.warning("PCI evidence: extra evidence hook failed for %s: %s", skill_name, exc)

    return evidence


def _recompute_pre_checks(
    session: "AuditSession",
    skill_name: str,
) -> Tuple[List[PreCheckResult], Dict[str, Tuple[str, ...]], Dict[str, Any]]:
    """Re-run Tier 1 pre-checks and record evidence stems each function consults."""
    evidence = _load_skill_evidence(session, skill_name)
    results: List[PreCheckResult] = []
    consulted_by_id: Dict[str, Tuple[str, ...]] = {}

    for check_fn in PRE_CHECK_REGISTRY.get(skill_name.lower(), []):
        recorder = _AccessRecordingEvidence(evidence)
        try:
            result = check_fn(recorder)
            results.append(result)
            consulted_by_id[result.check_id] = tuple(recorder.consulted_stems)
        except Exception as exc:
            logger.warning("Pre-check %s failed: %s", check_fn.__name__, exc, exc_info=True)

    return results, consulted_by_id, evidence


def _iter_checklist_items(
    checklist: Dict[str, Any],
) -> Iterator[Tuple[Dict[str, Any], List[Dict[str, str]]]]:
    """Yield (item, pci_dss_entries) for every item with at least one control.

    A control repeated within the same item is emitted once.
    """
    for item in checklist.get("items", []):
        if not item.get("id"):
            continue
        entries: List[Dict[str, str]] = []
        seen: set = set()
        for pci in item.get("pci_dss") or []:
            control = str((pci or {}).get("control") or "").strip()
            if not control or control in seen:
                continue
            seen.add(control)
            entries.append({"control": control, "reason": str(pci.get("reason") or "")})
        if entries:
            yield item, entries


def _resolve_status(pre_check: Optional[PreCheckResult], finding: Optional[Dict[str, Any]]) -> str:
    if finding is not None:
        return STATUS_FAIL
    if pre_check is None:
        return STATUS_INCONCLUSIVE
    if pre_check.status == "PASS":
        return STATUS_PASS
    if pre_check.status == "FAIL":
        return STATUS_FAIL
    return STATUS_INCONCLUSIVE


def _finding_reason(finding: Optional[Dict[str, Any]], control: str) -> Optional[str]:
    """Return the finding's own PCI DSS reason for this specific control, if any."""
    for pci in (finding or {}).get("pci_dss") or []:
        if isinstance(pci, dict) and pci.get("control") == control and pci.get("reason"):
            return str(pci["reason"])
    return None


def _iter_evidence_entries(
    config: "WizardConfig",
    session: "AuditSession",
    all_findings: Dict[str, Any],
    skills: List[str],
) -> Iterator[_EvidenceEntry]:
    qsa_depth = getattr(config, "qsa_depth", "standard") or "standard"
    for skill_name in skills:
        checklist = _load_checklist(skill_name, qsa_depth)
        if checklist is None:
            continue

        pre_check_results, consulted_by_id, evidence = _recompute_pre_checks(session, skill_name)
        pre_checks = {r.check_id: r for r in pre_check_results}
        skill_findings = (all_findings.get(skill_name) or {}).get("findings") or []
        region = _evidence_region(evidence, getattr(config, "aws_region", ""))
        captured_at = _evidence_captured_at(evidence, getattr(session, "timestamp", ""))
        findings_by_id: Dict[str, Dict[str, Any]] = {}
        for f in skill_findings:
            if isinstance(f, dict) and f.get("id"):
                findings_by_id.setdefault(str(f["id"]), f)

        for item, pci_entries in _iter_checklist_items(checklist):
            item_id = str(item["id"])
            pre_check = pre_checks.get(item_id)
            finding = findings_by_id.get(item_id)
            status = _resolve_status(pre_check, finding)
            consulted_stems = _consulted_stems_for_item(item, pre_check, finding, consulted_by_id)
            for pci in pci_entries:
                reason = pci["reason"]
                if status == STATUS_FAIL:
                    reason = _finding_reason(finding, pci["control"]) or reason
                yield _EvidenceEntry(
                    skill_name=skill_name,
                    item=item,
                    control=pci["control"],
                    reason=reason,
                    status=status,
                    pre_check=pre_check,
                    finding=finding,
                    consulted_stems=consulted_stems,
                    evidence=evidence,
                    region=region,
                    captured_at=captured_at,
                )


def _evidence_metadata(evidence: Dict[str, Any]) -> Dict[str, Any]:
    metadata = evidence.get("_audit_metadata")
    return metadata if isinstance(metadata, dict) else {}


def _evidence_region(evidence: Dict[str, Any], fallback: str) -> str:
    region = _evidence_metadata(evidence).get("_region")
    return str(region or fallback or "")


def _evidence_captured_at(evidence: Dict[str, Any], fallback: str) -> str:
    metadata = _evidence_metadata(evidence)
    captured = metadata.get("_collected_at") or metadata.get("_timestamp")
    if captured:
        return str(captured).split("T", 1)[0]
    return str(fallback or "")


# ---------------------------------------------------------------------------
# Filenames
# ---------------------------------------------------------------------------


def _safe_filename_component(text: str, fallback: str) -> str:
    """Normalize a filename component while preserving QSA-readable spaces."""
    normalized = unicodedata.normalize("NFKD", str(text).replace("_", " "))
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii")
    safe = re.sub(r"[^A-Za-z0-9 ._-]+", "", ascii_text)
    safe = re.sub(r"\s+", " ", safe)
    while ".." in safe:
        safe = safe.replace("..", ".")
    safe = safe.strip(" .")
    return safe or fallback


def _truncate_evidence_name(evidence_name: str, max_length: int = 80) -> str:
    if len(evidence_name) <= max_length:
        return evidence_name

    truncated = evidence_name[:max_length].rstrip()
    word_boundary = truncated.rfind(" ")
    if word_boundary > 0:
        truncated = truncated[:word_boundary].rstrip()
    return truncated or evidence_name[:max_length].rstrip()


def _filename(client_name: str, entry: _EvidenceEntry, used_names: set) -> str:
    query = resolve_query(entry.skill_name, str(entry.item.get("id", "")), entry.consulted_stems, entry.item)
    client = _safe_filename_component(client_name, "client")
    control = _safe_filename_component(entry.control, "control")
    evidence_name = _truncate_evidence_name(_safe_filename_component(query.evidence_name, "evidence"))
    stem = f"{client}_{control}_{evidence_name}"
    name = f"{stem}.md"
    suffix = 2
    while name in used_names:
        name = f"{stem} ({suffix}).md"
        suffix += 1
    used_names.add(name)
    return name


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _consulted_stems_for_item(
    item: Dict[str, Any],
    pre_check: Optional[PreCheckResult],
    finding: Optional[Dict[str, Any]],
    consulted_by_id: Dict[str, Tuple[str, ...]],
) -> Tuple[str, ...]:
    """Return evidence stems for query resolution, falling back to checklist files."""
    item_id = str(item.get("id") or "")
    stems: List[str] = list(consulted_by_id.get(item_id, ()))

    if finding is not None:
        for ref in finding.get("evidence_refs") or []:
            stem = Path(str(ref).split("#", 1)[0]).stem
            if stem and stem not in stems:
                stems.append(stem)

    if pre_check is None and not stems:
        for evidence_file in item.get("evidence_files") or []:
            stem = Path(str(evidence_file)).stem
            if stem and stem not in stems:
                stems.append(stem)

    return tuple(stems)


def _fence(body: str, lang: str = "") -> str:
    """Fence a code block with a backtick run longer than any inside the body."""
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{body.rstrip()}\n{ticks}"


def _render_commands(commands: Tuple[str, ...]) -> str:
    return "\nor\n".join(commands)


def _render_output(entry: _EvidenceEntry, outputs: Tuple[Any, ...]) -> str:
    rendered = [table for spec in outputs if (table := apply_output_spec(spec, entry.evidence))]
    if rendered:
        return "\n\n".join(rendered)

    if entry.pre_check is not None:
        lines = [entry.pre_check.evidence_summary or "(empty evidence summary)"]
        if entry.pre_check.affected_resources:
            lines.append("Affected resources:")
            lines.extend(f"- {resource}" for resource in entry.pre_check.affected_resources)
        return "\n".join(lines)

    finding = entry.finding or {}
    snippet = finding.get("evidence_snippet")
    if snippet:
        return json.dumps(snippet, indent=2, sort_keys=True, default=str)

    return "(no tabular output available from collected evidence)"


def _warn_gap_note(pre_check: Optional[PreCheckResult]) -> Optional[str]:
    if pre_check is None or pre_check.status != "WARN":
        return None
    reason_code = str(pre_check.metadata.get("reason_code") or "unspecified")
    return (
        "Automated pre-check reported a collection gap "
        f"({reason_code}); do not treat this control as compliant without manual review."
    )


def _short_description(entry: _EvidenceEntry, generated_at: str, derived_note: Optional[str]) -> str:
    item_id = entry.item.get("id", "")
    title = entry.item.get("title", item_id)
    pieces = [
        f"PCI DSS {entry.control} evidence for {item_id} ({title}) is {entry.status.lower()} based on {entry.skill_name} evidence captured at {entry.captured_at or generated_at} in {entry.region or 'the configured AWS region'}."
    ]
    if derived_note:
        pieces.append(derived_note)
    warn_gap_note = _warn_gap_note(entry.pre_check)
    if warn_gap_note:
        pieces.append(warn_gap_note)
    if entry.reason:
        pieces.append(entry.reason.strip())
    if entry.status == STATUS_PASS:
        pieces.append(_PASS_CLOSING)
    elif entry.status == STATUS_INCONCLUSIVE:
        pieces.append(_INCONCLUSIVE_CLOSING)
    return " ".join(piece for piece in pieces if piece).strip()


def _render_markdown(entry: _EvidenceEntry, generated_at: str) -> str:
    query = resolve_query(entry.skill_name, str(entry.item.get("id", "")), entry.consulted_stems, entry.item)
    sections = [
        f"Query:\n{_fence(_render_commands(query.commands), 'bash')}",
        f"Output:\n{_fence(_render_output(entry, query.outputs))}",
        f"Evidence description:\n{_fence(_short_description(entry, generated_at, query.derived_note))}",
    ]
    return "\n\n".join(sections) + "\n"
