"""Core deterministic pre-check types, registry, and runners."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

PRE_CHECK_STATUS_PASS = "PASS"
PRE_CHECK_STATUS_FAIL = "FAIL"
PRE_CHECK_STATUS_SKIP = "SKIP"
PRE_CHECK_STATUS_WARN = "WARN"


@dataclass
class PreCheckResult:
    """Result of a single deterministic pre-check."""

    check_id: str  # e.g. "IAM-001"
    status: str  # "PASS" | "FAIL" | "SKIP" | "WARN"
    evidence_summary: str  # e.g. "AccountMFAEnabled=0"
    affected_resources: List[str] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )  # structured extras (cve_details, attack_path, etc.)
    risk_score_override: Optional[float] = None  # overrides checklist severity-based score


# Type alias for check functions
PreCheckFn = Callable[[Dict[str, Any]], PreCheckResult]


# ---------------------------------------------------------------------------
# Registry: maps skill name → list of (check_id, check_function) pairs
# ---------------------------------------------------------------------------
PRE_CHECK_REGISTRY: Dict[str, List[PreCheckFn]] = {}


_CHECK_ID_PREFIX_RE = re.compile(r"^\s*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3})\s*:")


def resolve_pre_check_id(check_fn: PreCheckFn) -> str:
    """Resolve the checklist ID associated with a registered pre-check function."""
    doc = getattr(check_fn, "__doc__", None) or ""
    first_line = doc.strip().splitlines()[0] if doc.strip() else ""
    if match := _CHECK_ID_PREFIX_RE.match(first_line):
        return match.group(1)

    name = getattr(check_fn, "__name__", "unknown_pre_check")
    if name.startswith("check_"):
        return name[len("check_") :].upper().replace("_", "-")
    return name.upper().replace("_", "-")


def _register(skill: str):
    """Decorator to register a pre-check function for a skill."""

    def decorator(fn: PreCheckFn) -> PreCheckFn:
        PRE_CHECK_REGISTRY.setdefault(skill, []).append(fn)
        return fn

    return decorator


def run_pre_checks(
    skill_name: str, evidence: Dict[str, Any], checklist: Dict[str, Any]
) -> List[PreCheckResult]:
    """Run all registered pre-checks for a skill.

    Args:
        skill_name: Skill identifier (e.g. 'iam', 'hardening')
        evidence: Evidence dict (file stems → parsed JSON)
        checklist: Checklist dict with 'items' array

    Returns:
        List of PreCheckResult for each check. Checks that raise are recorded
        as WARN so deterministic coverage gaps remain visible to the LLM and
        downstream reports.
    """
    checks = PRE_CHECK_REGISTRY.get(skill_name.lower(), [])
    if not checks:
        return []

    results = []
    for check_fn in checks:
        try:
            result = check_fn(evidence)
            results.append(result)
        except Exception as e:
            logger.warning("Pre-check %s failed: %s", check_fn.__name__, e, exc_info=True)
            results.append(
                PreCheckResult(
                    resolve_pre_check_id(check_fn),
                    PRE_CHECK_STATUS_WARN,
                    f"Pre-check raised {type(e).__name__}: {e}",
                    metadata={
                        "reason_code": "precheck_error",
                        "exception_type": type(e).__name__,
                        "check_fn": getattr(check_fn, "__name__", "unknown_pre_check"),
                    },
                    confidence=0.0,
                )
            )
    return results


def format_pre_checks_for_prompt(
    pre_checks: List[PreCheckResult], checklist: Optional[Dict[str, Any]] = None
) -> str:
    """Format pre-check results as XML for prompt injection.

    Args:
        pre_checks: List of pre-check results
        checklist: Optional checklist to look up severities

    Returns:
        XML string for SKILL_ADDENDUM injection
    """
    if not pre_checks:
        return ""

    # Build severity lookup from checklist
    severity_map: Dict[str, str] = {}
    if checklist and "items" in checklist:
        for item in checklist["items"]:
            if isinstance(item, dict) and "id" in item:
                severity_map[item["id"]] = item.get("severity", "Medium")

    lines = [
        "<pre_computed_facts>",
        "  <instructions>",
        "    These facts were verified deterministically against collected evidence.",
        "    They are AUTHORITATIVE — do not contradict them.",
        "    - For PASS items: DO NOT generate a finding (the check passed).",
        "    - For FAIL items: Generate a finding with professional description and remediation.",
        "    - For SKIP items: DO NOT generate a finding (the check is not applicable to this environment).",
        "    - For WARN items: Treat as a coverage gap; deterministic evaluation could not complete.",
        "      Analyze from available evidence if possible; never treat as compliant.",
        "    - For items NOT listed: Analyze evidence yourself.",
        "  </instructions>",
        "",
    ]

    for r in pre_checks:
        sev = severity_map.get(r.check_id, "")
        sev_attr = f' severity="{sev}"' if sev else ""
        resources = ""
        if r.affected_resources:
            resources = (
                f"\n    <affected_resources>{', '.join(r.affected_resources)}</affected_resources>"
            )
        lines.append(
            f'  <fact id="{r.check_id}" status="{r.status}"{sev_attr}>'
            f"\n    <evidence>{r.evidence_summary}</evidence>"
            f"{resources}"
            f"\n  </fact>"
        )

    lines.append("</pre_computed_facts>")
    return "\n".join(lines)

__all__ = [
    "PreCheckResult",
    "PreCheckFn",
    "PRE_CHECK_STATUS_PASS",
    "PRE_CHECK_STATUS_FAIL",
    "PRE_CHECK_STATUS_SKIP",
    "PRE_CHECK_STATUS_WARN",
    "PRE_CHECK_REGISTRY",
    "_register",
    "resolve_pre_check_id",
    "run_pre_checks",
    "format_pre_checks_for_prompt",
]
