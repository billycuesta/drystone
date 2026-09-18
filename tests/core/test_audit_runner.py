"""Tests for the CLI-agnostic audit orchestration core."""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from drystone.core.audit_runner import (
    AuditRunResult,
    _analyze_evidence,
    _collect_pentest_inventory_if_needed,
    _optimize_budgets,
    _run_correlation,
    _run_qa_gate,
    _write_integrity_manifest,
    run_audit,
)
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
        patch("drystone.audit_logging.MetricsTracker"),
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


# =============================================================================
# rec P: isolated tests for individual pipeline phases, not just the full
# run_audit() pipeline. These exercise each phase function directly, without
# needing to stand up the whole (skills + agent + reports + QA gate) chain.
# =============================================================================


class TestCollectPentestInventoryIfNeededPhase:
    def test_skipped_for_non_pentest_report_type(self, config, mock_aws_client, mock_session):
        config.report_type = "general"
        with patch("drystone.pentest.inventory.collect_pentest_inventory") as mock_collect:
            _collect_pentest_inventory_if_needed(config, mock_aws_client, mock_session, lambda m: None)
        mock_collect.assert_not_called()

    def test_runs_and_reports_success_for_pentest_report_type(
        self, config, mock_aws_client, mock_session, tmp_path
    ):
        config.skills = ["iam", "exposure", "network", "vulns", "recon", "secretsmanager", "sistemas_explotables_red"]
        config.report_type = "pentest"
        inventory_path = tmp_path / "inventory-summary.json"
        inventory_path.write_text("{}")
        messages = []
        with patch(
            "drystone.pentest.inventory.collect_pentest_inventory", return_value=inventory_path
        ):
            _collect_pentest_inventory_if_needed(config, mock_aws_client, mock_session, messages.append)
        assert any("Inventory saved" in m for m in messages)

    def test_failure_is_non_blocking(self, config, mock_aws_client, mock_session):
        config.report_type = "pentest"
        messages = []
        with patch(
            "drystone.pentest.inventory.collect_pentest_inventory",
            side_effect=RuntimeError("boom"),
        ):
            _collect_pentest_inventory_if_needed(config, mock_aws_client, mock_session, messages.append)
        assert any("Could not collect pentest inventory" in m and "boom" in m for m in messages)


class TestRunCorrelationPhase:
    def test_skipped_with_one_or_zero_skills(self, mock_session):
        with patch("drystone.correlation.engine.CorrelationEngine") as mock_engine:
            _run_correlation(mock_session, {"iam": {}}, lambda m: None)
        mock_engine.assert_not_called()

    def test_runs_and_reports_chain_count_with_multiple_skills(self, mock_session):
        messages = []
        with patch("drystone.correlation.engine.CorrelationEngine") as mock_engine:
            mock_engine.return_value.run.return_value = {"total_correlations": 3}
            _run_correlation(mock_session, {"iam": {}, "network": {}}, messages.append)
        assert any("3 attack chain(s) correlated" in m for m in messages)

    def test_failure_is_non_blocking(self, mock_session):
        messages = []
        with patch("drystone.correlation.engine.CorrelationEngine") as mock_engine:
            mock_engine.return_value.run.side_effect = RuntimeError("boom")
            _run_correlation(mock_session, {"iam": {}, "network": {}}, messages.append)
        assert any("Correlation failed" in m and "boom" in m for m in messages)


class TestWriteIntegrityManifestPhase:
    def test_writes_manifest_and_sets_session_hash(self, mock_session):
        messages = []
        with patch(
            "drystone.storage.manifest.write_manifest",
            return_value=(Path("/tmp/manifest.json"), "deadbeef"),
        ):
            _write_integrity_manifest(mock_session, messages.append)

        assert mock_session.integrity_manifest_sha256 == "deadbeef"
        assert any("manifest.json" in m for m in messages)

    def test_failure_is_non_blocking(self, mock_session):
        messages = []
        with patch(
            "drystone.storage.manifest.write_manifest", side_effect=RuntimeError("boom")
        ):
            _write_integrity_manifest(mock_session, messages.append)
        assert any("Could not write integrity manifest" in m and "boom" in m for m in messages)


class TestOptimizeBudgetsPhase:
    def test_reports_when_budgets_updated(self, tmp_path):
        messages = []
        with patch(
            "drystone.agent.optimizer.optimize_budgets_from_metrics",
            return_value={"updated": 2},
        ):
            _optimize_budgets(tmp_path / "metrics.json", messages.append)
        assert any("updated 2 budget override(s)" in m for m in messages)

    def test_silent_when_nothing_updated(self, tmp_path):
        messages = []
        with patch(
            "drystone.agent.optimizer.optimize_budgets_from_metrics",
            return_value={"updated": 0},
        ):
            _optimize_budgets(tmp_path / "metrics.json", messages.append)
        assert messages == []

    def test_failure_is_silently_swallowed(self, tmp_path):
        messages = []
        with patch(
            "drystone.agent.optimizer.optimize_budgets_from_metrics",
            side_effect=RuntimeError("boom"),
        ):
            _optimize_budgets(tmp_path / "metrics.json", messages.append)
        assert messages == []


class TestRunQaGatePhase:
    def test_pass_returns_false_and_reports_pass(self, mock_session, config):
        messages = []
        with patch(
            "drystone.validation.qa_gate.run_qa_gate",
            return_value=QAGateResult(passed=True, issues=[]),
        ):
            qa_failed = _run_qa_gate(mock_session, config, messages.append)
        assert qa_failed is False
        assert any("QA Gate: PASS" in m for m in messages)

    def test_fail_returns_true_and_lists_issues(self, mock_session, config):
        messages = []
        with patch(
            "drystone.validation.qa_gate.run_qa_gate",
            return_value=QAGateResult(passed=False, issues=["Missing critical checks"]),
        ):
            qa_failed = _run_qa_gate(mock_session, config, messages.append)
        assert qa_failed is True
        assert any("Missing critical checks" in m for m in messages)

    def test_execution_error_returns_false_not_true(self, mock_session, config):
        """An error running the gate itself is not the same as the gate failing."""
        messages = []
        with patch(
            "drystone.validation.qa_gate.run_qa_gate", side_effect=RuntimeError("boom")
        ):
            qa_failed = _run_qa_gate(mock_session, config, messages.append)
        assert qa_failed is False
        assert any("QA Gate execution error" in m and "boom" in m for m in messages)


class TestAnalyzeEvidenceMetricsIntegration:
    """rec AT: integration test exercising a REAL (unmocked) MetricsTracker
    through _analyze_evidence()'s actual ThreadPoolExecutor concurrency, to
    cover the read-modify-write-under-threads path unit tests can't reach.
    Only AgentClient itself is mocked (no real Claude call); the metrics file
    on disk and its RLock-guarded read-modify-write cycle are the real thing.
    """

    def test_concurrent_skills_all_record_metrics_without_lost_updates(
        self, config, tmp_path
    ):
        from drystone.audit_logging import MetricsTracker

        config.ai_provider = "claude-api"  # parallel mode: max_workers = len(skills)
        skill_names = ["iam", "network", "exposure", "vulns"]
        config.skills = skill_names

        metrics_tracker = MetricsTracker(tmp_path / "metrics.json")
        session = MagicMock()
        session.base_path = tmp_path

        class _FakeSkill:
            def __init__(self, name: str):
                self.name = name

            def analyze(self, session, agent):
                findings_path = tmp_path / f"{self.name}_findings.json"
                findings_path.write_text(
                    json.dumps(
                        {
                            "summary": {
                                "total_findings": 1,
                                "critical": 0,
                                "high": 1,
                                "overall_risk_score": 5.0,
                            }
                        }
                    )
                )
                return str(findings_path)

        skill_instances = {name: _FakeSkill(name) for name in skill_names}
        skill_display_names = {name: name.capitalize() for name in skill_names}

        with patch("drystone.agent.client.AgentClient") as mock_agent_cls:
            mock_agent_cls.return_value = MagicMock()
            all_findings = _analyze_evidence(
                config,
                session,
                skill_instances,
                skill_display_names,
                metrics_tracker,
                lambda m: None,
            )

        assert set(all_findings.keys()) == set(skill_names)

        final_metrics = metrics_tracker.get_metrics()
        for skill_name in skill_names:
            skill_metrics = final_metrics["skills"].get(skill_name)
            assert skill_metrics is not None, f"{skill_name} metrics missing -- lost update?"
            assert skill_metrics["findings"] == 1
            assert skill_metrics["provider"] == "claude-api"
            assert skill_metrics["status"] == "complete"

        # Recomputed as a running sum on every record_skill_findings() call --
        # a lost update under concurrent writers would show up here as < 4.
        assert final_metrics["total_findings"] == len(skill_names)
