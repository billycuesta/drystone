"""Lazy skill-specific hooks for findings normalization.

The central normalizer owns the generic pipeline. Optional skill modules can
provide narrowly-scoped behavior without importing the skill registry or eager
loading skill packages during validation startup.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, Tuple

from drystone.models.findings import Finding

logger = logging.getLogger(__name__)

SeverityAdjustment = Tuple[str, float]


@dataclass
class NormalizerContext:
    """Runtime state shared with skill normalizer hooks."""

    skill_name: str
    checklist_map: Dict[str, Dict[str, Any]]
    evidence: Optional[Dict[str, Any]] = None


class NormalizerHook(Protocol):
    """Optional skill hook surface.

    Hooks return the input/default result unless the skill owns a narrower
    behavior. ``validate_against_evidence`` returns ``None`` when the hook does
    not decide so the central normalizer can use its generic fail-open fallback.
    """

    def remap_id(self, finding_id: str, finding: Finding) -> str: ...

    def normalize_evidence_refs(self, refs: List[str]) -> List[str]: ...

    def ensure_impact(self, finding: Finding) -> bool: ...

    def adjust_severity(
        self, finding_id: str, finding: Finding, severity: str, risk_score: float
    ) -> Optional[SeverityAdjustment]: ...

    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]: ...


class DefaultNormalizerHook:
    """No-op fallback used for skills without a normalizer module."""

    def __init__(self, context: NormalizerContext):
        self.context = context

    @property
    def evidence(self) -> Optional[Dict[str, Any]]:
        return self.context.evidence

    @property
    def skill_name(self) -> str:
        return self.context.skill_name

    def remap_id(self, finding_id: str, finding: Finding) -> str:
        return finding_id

    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        return refs

    def ensure_impact(self, finding: Finding) -> bool:
        return False

    def adjust_severity(
        self, finding_id: str, finding: Finding, severity: str, risk_score: float
    ) -> Optional[SeverityAdjustment]:
        return None

    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        return None


def get_normalizer_hook(skill_name: str, context: NormalizerContext) -> NormalizerHook:
    """Return the lazy-loaded hook for ``skill_name`` or the no-op fallback.

    The only dynamic import attempted is ``drystone.skills.<skill>.normalizer``;
    this intentionally avoids the skill registry and any central skill discovery.
    """

    module_name = f"drystone.skills.{skill_name.lower()}.normalizer"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            return DefaultNormalizerHook(context)
        logger.debug("Skill normalizer import failed for %s", module_name, exc_info=True)
        return DefaultNormalizerHook(context)
    except Exception:
        logger.debug("Skill normalizer import failed for %s", module_name, exc_info=True)
        return DefaultNormalizerHook(context)

    factory = getattr(module, "get_normalizer_hook", None)
    if callable(factory):
        hook = factory(context)
        return hook if hook is not None else DefaultNormalizerHook(context)

    hook_cls = getattr(module, "SkillNormalizerHook", None)
    if callable(hook_cls):
        return hook_cls(context)

    return DefaultNormalizerHook(context)
