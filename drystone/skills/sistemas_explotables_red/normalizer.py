"""Sistemas Explotables Red-specific findings normalization hooks.

This skill currently uses the default normalizer behavior. The explicit hook
keeps that contract visible and gives the skill a stable extension point.
"""

from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext


class SkillNormalizerHook(DefaultNormalizerHook):
    """Sistemas Explotables Red currently relies on default normalization semantics."""



def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
