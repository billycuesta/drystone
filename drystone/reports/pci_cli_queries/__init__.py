"""AWS CLI query recipes for PCI DSS evidence files.

The catalog is intentionally split in two layers:

* Layer 2 recipes are keyed by checklist id and provide check-specific commands.
* Layer 1 recipes are keyed by evidence source stem and are used as fallback.

Per-skill modules may extend the registries at import time. This P1 scaffold keeps
unmapped checks honest by returning a D5 placeholder query instead of omitting the
file.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, Literal, Optional, Tuple


@dataclass(frozen=True)
class OutputSpec:
    """Describe how stored evidence should be rendered as command-like output."""

    source: str
    rows: str = ""
    columns: Tuple[Tuple[str, str], ...] = ()
    style: Literal["table", "kv"] = "table"


@dataclass(frozen=True)
class CliQuery:
    """A reproducible CLI query recipe.

    ``commands`` contains the canonical command first and any alternatives after
    it. Rendering joins alternatives with a standalone ``or`` line.
    """

    commands: Tuple[str, ...]
    output: Optional[OutputSpec] = None
    evidence_name: Optional[str] = None
    derived_note: Optional[str] = None


@dataclass(frozen=True)
class ResolvedQuery:
    """The effective query recipe for one checklist item."""

    commands: Tuple[str, ...]
    outputs: Tuple[OutputSpec, ...]
    evidence_name: str
    derived_note: Optional[str] = None
    layer: Literal["check", "source", "placeholder"] = "placeholder"
    consulted_stems: Tuple[str, ...] = ()


SOURCE_QUERIES: Dict[str, Dict[str, CliQuery]] = {}
CHECK_QUERIES: Dict[str, CliQuery] = {}
COMPLETE_SKILLS: FrozenSet[str] = frozenset()


def _dedupe_in_order(values: Iterable[str]) -> Tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def _fallback_evidence_name(check_id: str, item: Any) -> str:
    if isinstance(item, dict):
        title = str(item.get("title") or "").strip()
        if title:
            return title
    return check_id


def _outputs_from_query(query: CliQuery) -> Tuple[OutputSpec, ...]:
    return (query.output,) if query.output is not None else ()


def _placeholder_command(check_id: str, consulted_stems: Tuple[str, ...]) -> str:
    files = ", ".join(consulted_stems) if consulted_stems else "none"
    return f"# No AWS CLI equivalent catalogued yet for {check_id} (evidence consulted: {files})"


def resolve_query(
    skill: str,
    check_id: str,
    consulted_stems: Iterable[str],
    item: Any,
) -> ResolvedQuery:
    """Resolve the best available CLI recipe for a checklist item.

    Resolution order follows the plan:
    1. Layer 2 check-specific recipe wins.
    2. Layer 1 evidence-source recipes for consulted stems, de-duplicated in
       first-consulted order.
    3. D5 placeholder when no catalogued recipe exists.
    """

    stems = _dedupe_in_order(str(stem) for stem in consulted_stems if str(stem).strip())
    evidence_name = _fallback_evidence_name(check_id, item)

    if check_id in CHECK_QUERIES:
        query = CHECK_QUERIES[check_id]
        return ResolvedQuery(
            commands=query.commands,
            outputs=_outputs_from_query(query),
            evidence_name=query.evidence_name or evidence_name,
            derived_note=query.derived_note,
            layer="check",
            consulted_stems=stems,
        )

    source_catalog = SOURCE_QUERIES.get(skill, {})
    commands: list[str] = []
    outputs: list[OutputSpec] = []
    derived_notes: list[str] = []
    seen_outputs: set[OutputSpec] = set()

    for stem in stems:
        source_query = source_catalog.get(stem)
        if source_query is None:
            continue
        commands.extend(source_query.commands)
        for output in _outputs_from_query(source_query):
            if output not in seen_outputs:
                seen_outputs.add(output)
                outputs.append(output)
        if source_query.derived_note and source_query.derived_note not in derived_notes:
            derived_notes.append(source_query.derived_note)

    deduped_commands = _dedupe_in_order(commands)
    if deduped_commands:
        return ResolvedQuery(
            commands=deduped_commands,
            outputs=tuple(outputs),
            evidence_name=evidence_name,
            derived_note="; ".join(derived_notes) if derived_notes else None,
            layer="source",
            consulted_stems=stems,
        )

    return ResolvedQuery(
        commands=(_placeholder_command(check_id, stems),),
        outputs=(),
        evidence_name=evidence_name,
        layer="placeholder",
        consulted_stems=stems,
    )


def _import_skill_module(name: str) -> None:
    """Import an optional per-skill catalog module and merge its registries."""

    global COMPLETE_SKILLS
    try:
        module = importlib.import_module(f"{__name__}.{name}")
    except ModuleNotFoundError as exc:
        if exc.name == f"{__name__}.{name}":
            return
        raise

    for skill, recipes in getattr(module, "SOURCE_QUERIES", {}).items():
        SOURCE_QUERIES.setdefault(skill, {}).update(recipes)
    CHECK_QUERIES.update(getattr(module, "CHECK_QUERIES", {}))
    COMPLETE_SKILLS = frozenset((*COMPLETE_SKILLS, *getattr(module, "COMPLETE_SKILLS", frozenset())))


_import_skill_module("iam")
_import_skill_module("network")
_import_skill_module("exposure")
_import_skill_module("waf")
_import_skill_module("hardening")

__all__ = [
    "CHECK_QUERIES",
    "COMPLETE_SKILLS",
    "SOURCE_QUERIES",
    "CliQuery",
    "OutputSpec",
    "ResolvedQuery",
    "resolve_query",
]
