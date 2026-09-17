"""Tests for the CLI-agnostic audit orchestration core."""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from drystone.core.audit_runner import AuditRunResult, run_audit
from drystone.models import WizardConfig
from drystone.validation.qa_gate import QAGateResult

_FAKE_SKILL_MODULE_NAME = "tests.core._fake_iam_skill_module"


def _install_fake_skill_module(session_base_path: Path) -> None:
    """Register a throwaway module with a minimal skill class in sys.modules.

    run_audit() dynamically imports skills via `__import__(module_name, ...)`,
    so the fake skill needs to be a real importable module rather than a mock.
    """
    module = types.ModuleType(_FAKE_SKILL_MODULE_NAME)

    class FakeIamSkill:
        def collect(self, aws_client, session):
            pass

        def analyze(self, session, agent):
            findings_path = session_base_path / "iam_findings.json"
            findings_path.write_text(
                json.dumps(
                    {
                        "summary": {
                            "total_findings": 2,
                            "critical": 1,
                            "high": 1,
                            "overall_risk_score": 7.5,
                        }
                    }
                )
            )
            return str(findings_path)

    module.FakeIamSkill = FakeIamSkill
    sys.modules[_FAKE_SKILL_MODULE_NAME] = module


@pytest.fixture
def config():
    return WizardConfig(
        client_name="ACME Corp",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="us-east-1",
        skills=["iam"],
        output_formats=["markdown"],
        report_type="general",
        ai_provider="claude-cli",
    )


@pytest.fixture
def mock_aws_client():
    client = MagicMock()
    client.session = MagicMock()
    return client


@pytest.fixture
def mock_session(tmp_path):
    session = MagicMock()
    session.base_path = tmp_path
    session.get_findings_path.return_value = tmp_path / "findings"
    return session


@pytest.fixture
def report_file(tmp_path):
    path = tmp_path / "iam_report.md"
    path.write_text("# IAM Report\n")
    return path


def _patched(mock_session, qa_result, report_file, mock_aws_client):
    """Patch every collaborator run_audit() touches, at their lazy-import origin."""
    _install_fake_skill_module(mock_session.base_path)

    generator = MagicMock()
    generator.generate_reports.return_value = {"markdown": report_file}

    return (
        patch("drystone.cloud.aws.client.AWSClient", return_value=mock_aws_client),
        patch("drystone.storage.session.AuditSession", return_value=mock_session),
        patch("drystone.logging.MetricsTracker"),
        patch("drystone.agent.client.AgentClient"),
        patch(
            "drystone.skills.registry.skill_import_map",
            return_value={"iam": (_FAKE_SKILL_MODULE_NAME, "FakeIamSkill")},
        ),
        patch(
            "drystone.skills.registry.skill_display_names",
            return_value={"iam": "IAM"},
        ),
        patch(
            "drystone.verification.runner.run_active_verification",
            return_value={
                "attempted": 0,
                "succeeded": 0,
                "denied": 0,
                "errored": 0,
                "log_path": "/tmp/verify.log",
            },
        ),
        patch(
            "drystone.storage.manifest.write_manifest",
            return_value=(Path("/tmp/manifest.json"), "deadbeef"),
        ),
        patch("drystone.agent.optimizer.optimize_budgets_from_metrics", return_value={"updated": 0}),
        patch("drystone.validation.qa_gate.run_qa_gate", return_value=qa_result),
        patch("drystone.reports.ReportGenerator", return_value=generator),
    )


def _apply(patches):
    return [p.start() for p in patches]


def _stop(patches):
    for p in patches:
        p.stop()


class TestRunAuditHappyPath:
    def test_returns_result_with_qa_passed_true(self, config, mock_aws_client, mock_session, report_file):
        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        try:
            result = run_audit(config, "123456789012")
        finally:
            _stop(patches)

        assert isinstance(result, AuditRunResult)
        assert result.qa_passed is True
        assert "iam" in result.all_findings
        assert result.all_findings["iam"]["summary"]["total_findings"] == 2
        assert result.session is mock_session

    def test_on_message_none_does_not_raise(self, config, mock_aws_client, mock_session, report_file):
        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        try:
            result = run_audit(config, "123456789012", on_message=None)
        finally:
            _stop(patches)

        assert result.qa_passed is True

    def test_messages_reach_custom_callback(self, config, mock_aws_client, mock_session, report_file):
        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        messages = []
        try:
            run_audit(config, "123456789012", on_message=messages.append)
        finally:
            _stop(patches)

        joined = "\n".join(messages)
        assert "Creating audit session" in joined
        assert "Executing IAM Security Audit" in joined
        assert "QA Gate: PASS" in joined
        assert "Audit Complete" in joined


class TestRunAuditQaFailure:
    def test_qa_failure_surfaces_qa_passed_false(self, config, mock_aws_client, mock_session, report_file):
        qa_result = QAGateResult(passed=False, issues=["Missing critical checks"])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        messages = []
        try:
            result = run_audit(config, "123456789012", on_message=messages.append)
        finally:
            _stop(patches)

        assert result.qa_passed is False
        assert any("QA Gate: FAIL" in m for m in messages)
        assert any("Missing critical checks" in m for m in messages)


class TestRunAuditNoClick:
    def test_module_does_not_import_click(self):
        import drystone.core.audit_runner as module

        assert not hasattr(module, "click")
