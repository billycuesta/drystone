"""Skill auto-discovery registry.

Scans ``drystone/skills/*/`` for packages that declare the skill manifest
constants (``SKILL_NAME``, ``SKILL_DISPLAY_NAME``, ``SKILL_CLASS``, ...) in
their ``__init__.py`` and builds the lookup tables that used to be
hand-copied into ``cli/main.py``, ``cli/ui/wizard.py``, ``models/config.py``,
and ``scripts/e2e_test_runner.py``.

Adding a new skill now only requires creating its package and declaring
these constants — nothing outside that folder needs to change.
"""

from __future__ import annotations

import importlib
import json
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import drystone.skills as _skills_pkg


@dataclass(frozen=True)
class SkillManifest:
    name: str
    display_name: str
    skill_class: type
    module_path: str
    class_name: str
    wizard_selectable: bool = True
    wizard_label: Optional[str] = None
    wizard_order: Optional[int] = None


_registry_cache: Optional[Dict[str, SkillManifest]] = None
_id_prefix_cache: Optional[Dict[str, str]] = None


def discover_skills(force_refresh: bool = False) -> Dict[str, SkillManifest]:
    """Scan ``drystone/skills/*/`` and return ``{skill_name: SkillManifest}``.

    Cached after the first call within a process — skills don't change
    mid-run. Pass ``force_refresh=True`` to re-scan (mainly useful for
    tests that monkeypatch the scan root).
    """
    global _registry_cache
    if _registry_cache is not None and not force_refresh:
        return _registry_cache

    manifests: Dict[str, SkillManifest] = {}
    for _finder, module_name, is_pkg in pkgutil.iter_modules(_skills_pkg.__path__):
        if not is_pkg:
            continue
        full_module_path = f"{_skills_pkg.__name__}.{module_name}"
        module = importlib.import_module(full_module_path)

        skill_name = getattr(module, "SKILL_NAME", None)
        skill_class = getattr(module, "SKILL_CLASS", None)
        if not skill_name or skill_class is None:
            continue  # not a skill package (e.g. a helper subpackage)

        manifests[skill_name] = SkillManifest(
            name=skill_name,
            display_name=getattr(module, "SKILL_DISPLAY_NAME", skill_name.capitalize()),
            skill_class=skill_class,
            module_path=full_module_path,
            class_name=skill_class.__name__,
            wizard_selectable=getattr(module, "SKILL_WIZARD_SELECTABLE", True),
            wizard_label=getattr(module, "SKILL_WIZARD_LABEL", None),
            wizard_order=getattr(module, "SKILL_WIZARD_ORDER", None),
        )

    _registry_cache = manifests
    return manifests


def skill_names() -> List[str]:
    """All registered skill names — for CLI ``--skills`` choices and config validation.

    Does NOT include "pentest", which is a preset/meta-skill, not a
    discoverable package under drystone/skills/.
    """
    return sorted(discover_skills().keys())


def skill_import_map() -> Dict[str, Tuple[str, str]]:
    """``{name: (module_path, class_name)}`` — drop-in for the old ``skills_map``."""
    return {m.name: (m.module_path, m.class_name) for m in discover_skills().values()}


def skill_display_names() -> Dict[str, str]:
    """``{name: display_name}`` — drop-in for the old ``skill_display_names`` dict."""
    return {m.name: m.display_name for m in discover_skills().values()}


def wizard_choices() -> List[SkillManifest]:
    """Wizard-selectable skills, in their curated display order."""
    selectable = [m for m in discover_skills().values() if m.wizard_selectable]
    return sorted(
        selectable, key=lambda m: (m.wizard_order if m.wizard_order is not None else 999)
    )


def skill_name_by_id_prefix(force_refresh: bool = False) -> Dict[str, str]:
    """``{id_prefix_lower: skill_name}`` derived from each skill's checklist.json.

    The single source of truth for going from a finding ID's prefix (e.g.
    "CTEF" from "CTEF-001") back to the real skill name, instead of assuming
    skill_name == id_prefix.lower() -- that assumption is wrong for skills
    whose checklist prefix doesn't match their name (sistemas_explotables_red
    -> "SER", cloudtrail_events -> "CTEF", messaging -> "MSG", etc.).

    Built from the same checklist.json data agent/client.py's
    _get_skill_code() uses in the other direction (skill_name -> prefix).
    Cached after the first call; pass force_refresh=True to re-scan.
    """
    global _id_prefix_cache
    if _id_prefix_cache is not None and not force_refresh:
        return _id_prefix_cache

    mapping: Dict[str, str] = {}
    skills_dir = Path(__file__).parent
    for skill_name in discover_skills(force_refresh=force_refresh):
        checklist_path = skills_dir / skill_name / "checklist.json"
        try:
            checklist = json.loads(checklist_path.read_text())
        except Exception:
            continue
        items = checklist.get("items") or []
        if not items:
            continue
        first_id = str(items[0].get("id", ""))
        if "-" not in first_id:
            continue
        mapping[first_id.split("-", 1)[0].lower()] = skill_name

    _id_prefix_cache = mapping
    return mapping
