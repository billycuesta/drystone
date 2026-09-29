import logging

from drystone.validation.pre_checks.core import (
    PRE_CHECK_REGISTRY,
    PRE_CHECK_STATUS_WARN,
    PreCheckResult,
    format_pre_checks_for_prompt,
    run_pre_checks,
)


def test_run_pre_checks_logs_warning_with_traceback(caplog):
    def broken_check(evidence):
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
    assert result.check_id == "broken_check"
    assert result.status == PRE_CHECK_STATUS_WARN
    assert result.metadata["reason_code"] == "collection_failed"
    assert result.metadata["exception_type"] == "RuntimeError"
    assert "Pre-check broken_check failed: boom" in caplog.text
    assert "Traceback" in caplog.text


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
