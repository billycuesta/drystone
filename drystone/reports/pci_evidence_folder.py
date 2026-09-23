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
- INCONCLUSIVE: the pre-check was skipped, or no pre-check exists and the AI
  analysis raised no finding -- never silently treated as compliant.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple

from drystone.reports.formats.pci_dss import get_requirement_name
from drystone.validation.pre_checks import PRE_CHECK_REGISTRY, PreCheckResult, run_pre_checks

if TYPE_CHECKING:
    from drystone.models import WizardConfig
    from drystone.storage.session import AuditSession

logger = logging.getLogger(__name__)

_SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
_QSA_DEPTH_ORDER = {"obvious": 0, "standard": 1, "deep": 2}
_MAX_SLUG_LEN = 60

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
    out_dir = session.get_pci_evidence_path()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    used_names: set = set()

    for entry in _iter_evidence_entries(config, session, all_findings, skills):
        filename = _filename(session.client_name, entry, used_names)
        content = _render_markdown(entry, session.client_name, generated_at)
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


def _recompute_pre_checks(
    config: "WizardConfig",
    session: "AuditSession",
    skill_name: str,
    checklist: Dict[str, Any],
) -> List[PreCheckResult]:
    """Re-run the (pure, side-effect-free) Tier 1 pre-checks for a skill.

    Mirrors the evidence loading in ``BaseSkill.analyze()``, including the
    skill's ``_load_extra_evidence`` hook (e.g. IAM's credential-report.csv),
    so results match what the analysis phase computed.
    """
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

    return run_pre_checks(skill_name, evidence, checklist)


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

        pre_checks = {
            r.check_id: r for r in _recompute_pre_checks(config, session, skill_name, checklist)
        }
        skill_findings = (all_findings.get(skill_name) or {}).get("findings") or []
        findings_by_id: Dict[str, Dict[str, Any]] = {}
        for f in skill_findings:
            if isinstance(f, dict) and f.get("id"):
                findings_by_id.setdefault(str(f["id"]), f)

        for item, pci_entries in _iter_checklist_items(checklist):
            item_id = str(item["id"])
            pre_check = pre_checks.get(item_id)
            finding = findings_by_id.get(item_id)
            status = _resolve_status(pre_check, finding)
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
                )


# ---------------------------------------------------------------------------
# Filenames
# ---------------------------------------------------------------------------


def _slugify(text: str, max_len: int = _MAX_SLUG_LEN) -> str:
    """Lowercase kebab-case slug restricted to [a-z0-9-]."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    if len(slug) > max_len:
        slug = slug[:max_len].rsplit("-", 1)[0] or slug[:max_len]
    return slug.strip("-")


def _safe_component(text: str, fallback: str) -> str:
    """Allowlist a filename component to [A-Za-z0-9.-] (no path separators, no '..')."""
    safe = re.sub(r"[^A-Za-z0-9.\-]+", "-", str(text)).strip("-.")
    safe = re.sub(r"\.{2,}", ".", safe)
    return safe or fallback


def _filename(client_name: str, entry: _EvidenceEntry, used_names: set) -> str:
    client = _safe_component(client_name, "client")
    control = _safe_component(entry.control, "control")
    evidence_name = (
        "-".join(
            p
            for p in (
                _slugify(str(entry.item.get("id", "")), 40),
                _slugify(entry.item.get("title", "")),
            )
            if p
        )
        or "evidence"
    )
    stem = f"{client}_{control}_{evidence_name}"
    name = f"{stem}.md"
    suffix = 2
    while name in used_names:
        name = f"{stem}-{suffix}.md"
        suffix += 1
    used_names.add(name)
    return name


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _pre_check_fn_index(skill_name: str) -> Dict[str, Any]:
    """Map check IDs to their registered pre-check function (by naming convention)."""
    index: Dict[str, Any] = {}
    for fn in PRE_CHECK_REGISTRY.get(skill_name.lower(), []):
        check_id = fn.__name__.removeprefix("check_").upper().replace("_", "-")
        index.setdefault(check_id, fn)
    return index


def _fence(body: str, lang: str = "") -> str:
    """Fence a code block with a backtick run longer than any inside the body."""
    longest = max((len(m) for m in re.findall(r"`+", body)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{body.rstrip()}\n{ticks}"


def _evidence_files_text(item: Dict[str, Any]) -> str:
    files = [str(f) for f in item.get("evidence_files") or [] if f]
    return ", ".join(f"`{f}`" for f in files) if files else "the evidence collected for this skill"


def _render_query(entry: _EvidenceEntry) -> str:
    item = entry.item
    finding = entry.finding

    if finding is not None:
        refs = [str(r) for r in finding.get("evidence_refs") or [] if r]
        if refs:
            lines = [f"Finding `{finding.get('id')}` is traced to the following evidence:", ""]
            lines += [f"- `{r}`" for r in refs]
            return "\n".join(lines)
        return (
            f"Finding `{finding.get('id')}` raised during AI analysis of "
            f"{_evidence_files_text(item)}. No evidence reference was recorded."
        )

    fn = _pre_check_fn_index(entry.skill_name).get(str(item.get("id")))
    if entry.pre_check is not None:
        fn_name = fn.__name__ if fn is not None else f"pre-check for {item.get('id')}"
        doc = (
            (inspect.getdoc(fn) or "").strip().splitlines()[0]
            if fn is not None and fn.__doc__
            else ""
        )
        doc_part = f' ("{doc}")' if doc else ""
        text = (
            f"Deterministic check `{fn_name}`{doc_part} -- inspects {_evidence_files_text(item)}."
        )
        if entry.status == STATUS_INCONCLUSIVE:
            text += " The check ran but no verdict was reached (SKIP)."
        return text

    return (
        f"No deterministic pre-check exists for `{item.get('id')}`. The item was evaluated "
        f"by the AI analysis of {_evidence_files_text(item)}, which raised no finding; "
        "no verdict was recorded."
    )


def _render_result(entry: _EvidenceEntry) -> str:
    finding = entry.finding
    if finding is not None:
        snippet = finding.get("evidence_snippet")
        if snippet:
            return _fence(json.dumps(snippet, indent=2, sort_keys=True, default=str), "json")
        fallback_lines = []
        if entry.pre_check is not None and entry.pre_check.evidence_summary:
            fallback_lines.append(entry.pre_check.evidence_summary)
        resources = [str(r) for r in finding.get("affected_resources") or []]
        if resources:
            fallback_lines.append("Affected resources:")
            fallback_lines += [f"- {r}" for r in resources]
        label = (
            "No raw evidence snippet captured -- theoretical finding."
            if finding.get("exploitability_status") == "theoretical"
            else "No raw evidence snippet captured."
        )
        body = "\n".join(fallback_lines) or "(no evidence summary available)"
        return f"_{label}_\n\n{_fence(body)}"

    if entry.pre_check is not None:
        pc = entry.pre_check
        lines = [pc.evidence_summary or "(empty evidence summary)"]
        if pc.affected_resources:
            lines.append("Affected resources:")
            lines += [f"- {r}" for r in pc.affected_resources]
        return _fence("\n".join(lines))

    return _fence("(no deterministic result -- no finding raised by AI analysis)")


def _render_assessment(entry: _EvidenceEntry) -> str:
    parts: List[str] = []
    finding = entry.finding

    if entry.status == STATUS_FAIL and finding is not None:
        for key in ("description", "impact"):
            if finding.get(key):
                parts.append(str(finding[key]).strip())
        if finding.get("security_analogy"):
            parts.append(f"_Analogy:_ {str(finding['security_analogy']).strip()}")
        if entry.reason:
            parts.append(f"**PCI DSS {entry.control}:** {entry.reason.strip()}")
        if finding.get("remediation"):
            parts.append(f"**Remediation:** {str(finding['remediation']).strip()}")
        severity = finding.get("severity")
        sev = f" (severity: {severity})" if severity else ""
        parts.append(
            f"**Status: Control requirement not met**{sev} -- see finding `{finding.get('id')}`."
        )
        return "\n\n".join(parts)

    if entry.status == STATUS_FAIL:
        # Pre-check FAIL with no matching finding in the findings file.
        summary = entry.pre_check.evidence_summary if entry.pre_check else ""
        desc = str(entry.item.get("description") or "").strip()
        parts.append(
            f"The deterministic check for `{entry.item.get('id')}` failed ({summary}). {desc}".strip()
        )
        if entry.reason:
            parts.append(f"**PCI DSS {entry.control}:** {entry.reason.strip()}")
        if entry.item.get("remediation"):
            parts.append(f"**Remediation:** {str(entry.item['remediation']).strip()}")
        parts.append("**Status: Control requirement not met.**")
        return "\n\n".join(parts)

    if entry.status == STATUS_PASS and entry.pre_check is not None:
        summary = (entry.pre_check.evidence_summary or "").strip()
        parts.append(
            f"Automated evidence collected during this audit confirms that the requirement "
            f'"{entry.item.get("title", entry.item.get("id"))}" is satisfied ({summary}).'
        )
        if entry.reason:
            parts.append(f"**PCI DSS {entry.control}:** {entry.reason.strip()}")
        parts.append(f"**Status: {_PASS_CLOSING}**")
        return "\n\n".join(parts)

    parts.append(_INCONCLUSIVE_CLOSING)
    if entry.pre_check is not None and entry.pre_check.evidence_summary:
        parts.append(f"Pre-check outcome: {entry.pre_check.evidence_summary.strip()}")
    if entry.reason:
        parts.append(f"**PCI DSS {entry.control}:** {entry.reason.strip()}")
    parts.append("**Status: Inconclusive -- manual QSA review recommended.**")
    return "\n\n".join(parts)


def _render_markdown(entry: _EvidenceEntry, client_name: str, generated_at: str) -> str:
    item = entry.item
    item_id = item.get("id", "")
    title = item.get("title", item_id)
    requirement = get_requirement_name(entry.control.split(".")[0])

    header = [
        f"# PCI DSS Control {entry.control} -- Evidence: {title}",
        "",
        f"**Client:** {client_name}  ",
        f"**Control:** {entry.control} -- {requirement}  ",
        f"**Checklist item:** {item_id} -- {title}  ",
        f"**Skill:** {entry.skill_name}  ",
        f"**Status:** {entry.status}  ",
        f"**Generated:** {generated_at} (automated, during audit scan)",
    ]
    sections = [
        "\n".join(header),
        f"## Query\n\n{_render_query(entry)}",
        f"## Raw result\n\n{_render_result(entry)}",
        f"## Assessment\n\n{_render_assessment(entry)}",
    ]
    return "\n\n".join(sections) + "\n"
