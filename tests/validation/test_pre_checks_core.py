import json
import logging
from pathlib import Path

from drystone.validation.pre_checks.core import (
    PRE_CHECK_REGISTRY,
    PRE_CHECK_STATUS_WARN,
    PRE_CHECK_REGISTRY,
    PreCheckResult,
    format_pre_checks_for_prompt,
    resolve_pre_check_id,
    run_pre_checks,
)


def test_run_pre_checks_logs_warning_with_traceback(caplog):
    def broken_check(evidence):
        """IAM-001: synthetic broken pre-check."""
        raise RuntimeError("boom")

    skill = "__test_debug_exception__"
    PRE_CHECK_REGISTRY[skill] = [broken_check]
    try:
        with caplog.at_level(logging.WARNING, logger="drystone.validation.pre_checks.core"):
            results = run_pre_checks(skill, {}, {"items": []})
    finally:
        PRE_CHECK_REGISTRY.pop(skill, None)

    assert len(results) == 1
    result = results[0]
    assert result.check_id == "IAM-001"
    assert result.status == PRE_CHECK_STATUS_WARN
    assert result.metadata["reason_code"] == "precheck_error"
    assert result.metadata["exception_type"] == "RuntimeError"
    assert result.metadata["check_fn"] == "broken_check"
    assert "Pre-check broken_check failed: boom" in caplog.text
    assert "Traceback" in caplog.text


def test_resolve_pre_check_id_uses_docstring_then_function_name_fallback():
    def documented_check(evidence):
        """IAM-009: synthetic documented pre-check."""
        return None

    def check_iam_010(evidence):
        return None

    assert resolve_pre_check_id(documented_check) == "IAM-009"
    assert resolve_pre_check_id(check_iam_010) == "IAM-010"


def test_all_registered_pre_checks_resolve_to_skill_checklist_ids():
    skills_dir = Path("drystone/skills")
    misses = []
    for skill_name, checks in sorted(PRE_CHECK_REGISTRY.items()):
        checklist_path = skills_dir / skill_name / "checklist.json"
        assert checklist_path.exists(), f"Missing checklist for {skill_name}"
        checklist = json.loads(checklist_path.read_text())
        checklist_ids = {str(item.get("id")) for item in checklist.get("items", []) if item.get("id")}
        for check_fn in checks:
            resolved = resolve_pre_check_id(check_fn)
            if resolved not in checklist_ids:
                misses.append(f"{skill_name}:{check_fn.__name__}->{resolved}")

    assert misses == []


def test_format_pre_checks_documents_warn_without_treating_it_as_compliant():
    xml = format_pre_checks_for_prompt(
        [
            PreCheckResult(
                "IAM-999",
                PRE_CHECK_STATUS_WARN,
                "could not evaluate",
                metadata={"reason_code": "missing_evidence"},
            )
        ]
    )

    assert 'status="WARN"' in xml
    assert "coverage gap" in xml
    assert "never treat as compliant" in xml
    assert "For SKIP items: DO NOT generate a finding (the check is not applicable" in xml
