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
import pkgutil
from dataclasses import dataclass
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
