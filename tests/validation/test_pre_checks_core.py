import logging

from drystone.validation.pre_checks.core import PRE_CHECK_REGISTRY, run_pre_checks


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

    assert results == []
    assert "Pre-check broken_check failed: boom" in caplog.text
    assert "Traceback" in caplog.text
