"""Validation module for post-analysis quality checks.

Live validation pipeline (integrated into audit execution):
- Tier 1: Deterministic pre-checks (drystone/validation/pre_checks/)
- Tier 2: AI-powered findings analysis via agent (drystone/skills/base.py)
- Tier 3: Findings reconciliation and normalization (findings_normalizer.py)

This module also exports optional validation helpers (FindingsReviewer, report_validator,
queue_validator) that are not currently wired into the live audit pipeline and are
reserved for future development. The live pipeline integration happens through the
skill base class and the findings normalizer, not through the exports below.

Public API for checklist coverage validation:
- validate_checklist_coverage(): Check which skill requirements were evaluated
- get_unevaluated_checks(): Get list of unevaluated checks by requirement
"""

from .checklist_coverage import get_unevaluated_checks, validate_checklist_coverage
from .queue_validator import QueueValidator, ValidationResult
from .report_validator import (
    suggest_report_fixes,
    validate_report_completeness,
    validate_report_format,
)

__all__ = [
    "validate_checklist_coverage",
    "get_unevaluated_checks",
    "FindingsReviewer",
    "validate_report_completeness",
    "validate_report_format",
    "suggest_report_fixes",
    "QueueValidator",
    "ValidationResult",
]


def __getattr__(name):
    """Lazily load optional validation helpers."""
    if name == "FindingsReviewer":
        from .reviewer import FindingsReviewer

        return FindingsReviewer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
