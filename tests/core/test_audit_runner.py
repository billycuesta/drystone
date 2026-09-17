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

    class _BaseFakeSkill:
        skill_name = "iam"

        def collect(self, aws_client, session):
            pass

        def analyze(self, session, agent):
            findings_path = session_base_path / f"{self.skill_name}_findings.json"
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

    class FakeIamSkill(_BaseFakeSkill):
        skill_name = "iam"

    class FakeNetworkSkill(_BaseFakeSkill):
        skill_name = "network"

    module.FakeIamSkill = FakeIamSkill
    module.FakeNetworkSkill = FakeNetworkSkill
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
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(exist_ok=True)
    session.get_findings_path.return_value = findings_dir
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


class TestRunAuditTrendAnalysis:
    """P2 #3: multi-run trend analysis is wired into the pipeline."""

    def test_no_baseline_writes_empty_trend_json(
        self, config, mock_aws_client, mock_session, report_file
    ):
        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        try:
            with patch(
                "drystone.core.trend_analysis.find_previous_session", return_value=None
            ):
                run_audit(config, "123456789012")
        finally:
            _stop(patches)

        trend_path = mock_session.get_findings_path() / "trend.json"
        assert trend_path.exists()
        data = json.loads(trend_path.read_text())
        assert data == {"previous_session": None, "skills": []}

    def test_baseline_found_reports_new_and_fixed_counts(
        self, config, mock_aws_client, mock_session, report_file
    ):
        from drystone.core.trend_analysis import SkillTrend, TrendResult

        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        messages = []
        canned_result = TrendResult(
            previous_session="ACME Corp_2026-09-01T10-00-00",
            skills=[
                SkillTrend(
                    skill="iam",
                    new=[{"id": "IAM-002"}],
                    fixed=[{"id": "IAM-099"}],
                    persisting_count=1,
                )
            ],
        )
        try:
            with (
                patch(
                    "drystone.core.trend_analysis.find_previous_session",
                    return_value=Path("/fake/ACME Corp_2026-09-01T10-00-00"),
                ),
                patch(
                    "drystone.core.trend_analysis.compute_trend", return_value=canned_result
                ),
            ):
                run_audit(config, "123456789012", on_message=messages.append)
        finally:
            _stop(patches)

        joined = "\n".join(messages)
        assert "Trend vs. ACME Corp_2026-09-01T10-00-00" in joined
        assert "1 new" in joined
        assert "1 fixed" in joined

        trend_path = mock_session.get_findings_path() / "trend.json"
        data = json.loads(trend_path.read_text())
        assert data["previous_session"] == "ACME Corp_2026-09-01T10-00-00"
        assert data["skills"][0]["new"] == [{"id": "IAM-002"}]
        assert data["skills"][0]["fixed"] == [{"id": "IAM-099"}]

    def test_trend_failure_does_not_abort_audit(
        self, config, mock_aws_client, mock_session, report_file
    ):
        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        try:
            with patch(
                "drystone.core.trend_analysis.find_previous_session",
                side_effect=RuntimeError("boom"),
            ):
                result = run_audit(config, "123456789012")
        finally:
            _stop(patches)

        assert result.qa_passed is True


class TestRunAuditFailureHandling:
    def test_empty_skill_instances_do_not_crash_analysis_phase(
        self, config, mock_aws_client, mock_session, report_file
    ):
        config.skills = ["missing_skill"]
        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        messages = []
        try:
            result = run_audit(config, "123456789012", on_message=messages.append)
        finally:
            _stop(patches)

        assert result.qa_passed is True
        assert result.all_findings == {}
        joined = "\n".join(messages)
        assert "Unknown skill: missing_skill" in joined
        assert "No valid skills collected; skipping AI analysis" in joined

    def test_correlation_failure_surfaces_warning(
        self, config, mock_aws_client, mock_session, report_file
    ):
        config.skills = ["iam", "network"]
        qa_result = QAGateResult(passed=True, issues=[])
        patches = _patched(mock_session, qa_result, report_file, mock_aws_client)
        _apply(patches)
        messages = []
        try:
            with (
                patch(
                    "drystone.skills.registry.skill_import_map",
                    return_value={
                        "iam": (_FAKE_SKILL_MODULE_NAME, "FakeIamSkill"),
                        "network": (_FAKE_SKILL_MODULE_NAME, "FakeNetworkSkill"),
                    },
                ),
                patch(
                    "drystone.skills.registry.skill_display_names",
                    return_value={"iam": "IAM", "network": "Network"},
                ),
                patch("drystone.correlation.engine.CorrelationEngine") as mock_engine,
            ):
                mock_engine.return_value.run.side_effect = RuntimeError("correlation boom")
                result = run_audit(config, "123456789012", on_message=messages.append)
        finally:
            _stop(patches)

        assert result.qa_passed is True
        assert "iam" in result.all_findings
        assert "network" in result.all_findings
        assert any("Correlation failed" in m and "correlation boom" in m for m in messages)


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
