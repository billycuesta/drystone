"""Targeted tests for orchestrator methods not covered by test_orchestrator_parallel.py.

Covers:
- _generate_report (pure markdown builder)
- _determine_validation_status (pure logic)
- run_skill_audit (end-to-end with mocked collaborators)
- run_full_audit metrics_file path
- run_correlation (QueueValidator + CorrelationEngine)
- save_results (file I/O + correlation integration)
"""

import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from drystone.cloud.orchestrator import AuditOrchestrator
from drystone.models.config import WizardConfig

# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_config():
    config = Mock(spec=WizardConfig)
    config.aws_credentials = {}
    config.anthropic_client = Mock()
    config.skills = ["iam", "exposure"]
    return config


@pytest.fixture
def orchestrator(mock_config):
    return AuditOrchestrator(mock_config)


CHECKLIST = {
    "items": [
        {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
        {"id": "IAM-002", "title": "Password policy", "severity": "High"},
    ]
}

FINDINGS = [
    {
        "id": "IAM-001",
        "title": "Root account has no MFA",
        "severity": "Critical",
        "risk_score": 9.5,
        "description": "Root MFA is disabled.",
        "remediation": "Enable MFA on root.",
    }
]


def _mock_result(skill_name="iam", status="PASS"):
    return {
        "skill": skill_name,
        "evidence": {},
        "findings": FINDINGS[:],
        "report": f"# {skill_name.upper()} Report",
        "validation": {
            "coverage": {"coverage_valid": True, "coverage_percentage": 100.0},
            "quality": {"validation_status": status, "confidence_score": 0.9},
            "report": {"report_valid": True},
            "status": status,
        },
        "timestamp": datetime.now().isoformat(),
    }


# ── _generate_report ──────────────────────────────────────────────────────────


class TestGenerateReport:
    def test_contains_skill_name_heading(self, orchestrator):
        report = orchestrator._generate_report("iam", FINDINGS, CHECKLIST)
        assert "IAM" in report

    def test_contains_findings_count(self, orchestrator):
        report = orchestrator._generate_report("iam", FINDINGS, CHECKLIST)
        assert "1" in report  # "Found 1 security findings."

    def test_contains_check_count(self, orchestrator):
        report = orchestrator._generate_report("iam", FINDINGS, CHECKLIST)
        assert "2" in report  # "evaluated 2 security checks."

    def test_contains_finding_id(self, orchestrator):
        report = orchestrator._generate_report("iam", FINDINGS, CHECKLIST)
        assert "IAM-001" in report

    def test_contains_finding_severity(self, orchestrator):
        report = orchestrator._generate_report("iam", FINDINGS, CHECKLIST)
        assert "Critical" in report

    def test_contains_remediation_section(self, orchestrator):
        report = orchestrator._generate_report("iam", FINDINGS, CHECKLIST)
        assert "Remediation" in report

    def test_no_findings_shows_clean_message(self, orchestrator):
        report = orchestrator._generate_report("iam", [], CHECKLIST)
        assert "No findings detected" in report

    def test_remediation_text_in_report(self, orchestrator):
        report = orchestrator._generate_report("iam", FINDINGS, CHECKLIST)
        assert "Enable MFA on root" in report

    def test_multiple_findings_all_present(self, orchestrator):
        findings = [
            {**FINDINGS[0], "id": "IAM-001", "title": "Root MFA"},
            {
                "id": "IAM-002",
                "title": "Weak password",
                "severity": "High",
                "risk_score": 7.0,
                "description": "...",
                "remediation": "Fix policy.",
            },
        ]
        report = orchestrator._generate_report("iam", findings, CHECKLIST)
        assert "IAM-001" in report
        assert "IAM-002" in report


# ── _determine_validation_status ─────────────────────────────────────────────


class TestDetermineValidationStatus:
    def _make(self, coverage_valid=True, quality_status="PASS", report_valid=True):
        return (
            {"coverage_valid": coverage_valid, "missing_checks": []},
            {"validation_status": quality_status, "confidence_score": 0.9},
            {"report_valid": report_valid},
        )

    def test_all_pass_returns_pass(self, orchestrator):
        cov, qual, rep = self._make()
        assert orchestrator._determine_validation_status(cov, qual, rep) == "PASS"

    def test_coverage_invalid_returns_fail(self, orchestrator):
        cov, qual, rep = self._make(coverage_valid=False)
        assert orchestrator._determine_validation_status(cov, qual, rep) == "FAIL"

    def test_quality_fail_returns_fail(self, orchestrator):
        cov, qual, rep = self._make(quality_status="FAIL")
        assert orchestrator._determine_validation_status(cov, qual, rep) == "FAIL"

    def test_report_invalid_returns_fail(self, orchestrator):
        cov, qual, rep = self._make(report_valid=False)
        assert orchestrator._determine_validation_status(cov, qual, rep) == "FAIL"

    def test_quality_needs_review_returns_needs_review(self, orchestrator):
        cov, qual, rep = self._make(quality_status="NEEDS_REVIEW")
        assert orchestrator._determine_validation_status(cov, qual, rep) == "NEEDS_REVIEW"

    def test_fail_takes_priority_over_needs_review(self, orchestrator):
        cov, qual, rep = self._make(coverage_valid=False, quality_status="NEEDS_REVIEW")
        assert orchestrator._determine_validation_status(cov, qual, rep) == "FAIL"


# ── run_skill_audit ───────────────────────────────────────────────────────────


class TestRunSkillAudit:
    """Smoke + branch tests for run_skill_audit with fully mocked collaborators."""

    def _setup_mocks(self, tmp_path, quality_status="PASS"):
        checklist_path = tmp_path / "checklist.json"
        checklist_path.write_text(json.dumps(CHECKLIST))

        collector_class = Mock()
        collector_instance = Mock()
        collector_instance.collect.return_value = Mock(data={"users": []})
        collector_class.return_value = collector_instance

        analyzer_class = Mock()
        analyzer_instance = Mock()
        analyzer_instance.analyze.return_value = FINDINGS[:]
        analyzer_class.return_value = analyzer_instance

        coverage_result = {
            "coverage_valid": True,
            "coverage_percentage": 100.0,
            "evaluated_checks": 2,
            "total_checks": 2,
            "missing_checks": [],
        }
        quality_result = {
            "validation_status": quality_status,
            "confidence_score": 0.9,
        }
        report_result = {"report_valid": True}

        return (
            checklist_path,
            collector_class,
            analyzer_class,
            coverage_result,
            quality_result,
            report_result,
        )

    def test_successful_audit_returns_result_dict(self, orchestrator, tmp_path):
        (
            checklist_path,
            collector_class,
            analyzer_class,
            coverage_result,
            quality_result,
            report_result,
        ) = self._setup_mocks(tmp_path)

        with (
            patch(
                "drystone.cloud.orchestrator.validate_checklist_coverage",
                return_value=coverage_result,
            ),
            patch("drystone.cloud.orchestrator.FindingsReviewer") as mock_reviewer,
            patch(
                "drystone.cloud.orchestrator.validate_report_completeness",
                return_value=report_result,
            ),
        ):
            mock_reviewer.return_value.validate.return_value = quality_result
            result = orchestrator.run_skill_audit(
                skill_name="iam",
                collector_class=collector_class,
                analyzer_class=analyzer_class,
                checklist_path=checklist_path,
            )

        assert result["skill"] == "iam"
        assert "findings" in result
        assert "report" in result
        assert result["validation"]["status"] == "PASS"

    def test_result_stored_in_results(self, orchestrator, tmp_path):
        (
            checklist_path,
            collector_class,
            analyzer_class,
            coverage_result,
            quality_result,
            report_result,
        ) = self._setup_mocks(tmp_path)

        with (
            patch(
                "drystone.cloud.orchestrator.validate_checklist_coverage",
                return_value=coverage_result,
            ),
            patch("drystone.cloud.orchestrator.FindingsReviewer") as mock_reviewer,
            patch(
                "drystone.cloud.orchestrator.validate_report_completeness",
                return_value=report_result,
            ),
        ):
            mock_reviewer.return_value.validate.return_value = quality_result
            orchestrator.run_skill_audit(
                skill_name="iam",
                collector_class=collector_class,
                analyzer_class=analyzer_class,
                checklist_path=checklist_path,
            )

        assert "iam" in orchestrator.results

    def test_quality_fail_triggers_reanalysis(self, orchestrator, tmp_path):
        (
            checklist_path,
            collector_class,
            analyzer_class,
            coverage_result,
            quality_result,
            report_result,
        ) = self._setup_mocks(tmp_path, quality_status="FAIL")
        # Coverage has missing checks to trigger re-analysis
        coverage_result["missing_checks"] = ["IAM-002"]
        coverage_result["coverage_valid"] = False

        with (
            patch(
                "drystone.cloud.orchestrator.validate_checklist_coverage",
                return_value=coverage_result,
            ),
            patch("drystone.cloud.orchestrator.FindingsReviewer") as mock_reviewer,
            patch(
                "drystone.cloud.orchestrator.validate_report_completeness",
                return_value=report_result,
            ),
            patch(
                "drystone.validation.checklist_coverage.get_unevaluated_checks",
                return_value=[],
                create=True,
            ),
        ):
            mock_reviewer.return_value.validate.return_value = quality_result
            # Second analyze call returns extra findings
            analyzer_instance = analyzer_class.return_value
            analyzer_instance.analyze.side_effect = [FINDINGS[:], []]

            orchestrator.run_skill_audit(
                skill_name="iam",
                collector_class=collector_class,
                analyzer_class=analyzer_class,
                checklist_path=checklist_path,
            )
        # Should have attempted re-analysis (analyze called twice)
        assert analyzer_instance.analyze.call_count == 2

    def test_exception_propagates(self, orchestrator, tmp_path):
        checklist_path = tmp_path / "checklist.json"
        checklist_path.write_text(json.dumps(CHECKLIST))

        collector_class = Mock()
        collector_class.return_value.collect.side_effect = RuntimeError("AWS timeout")

        with pytest.raises(RuntimeError, match="AWS timeout"):
            orchestrator.run_skill_audit(
                skill_name="iam",
                collector_class=collector_class,
                analyzer_class=Mock(),
                checklist_path=checklist_path,
            )


# ── run_full_audit with metrics_file ─────────────────────────────────────────


class TestRunFullAuditMetrics:
    def test_metrics_tracker_used_when_file_provided(self, orchestrator, tmp_path, mock_config):
        skills = [
            {
                "name": "iam",
                "collector": Mock(),
                "analyzer": Mock(),
                "checklist_path": tmp_path / "c.json",
            }
        ]
        metrics_file = tmp_path / "metrics.json"

        with (
            patch.object(orchestrator, "run_skill_audit", return_value=_mock_result("iam")),
            patch("drystone.cloud.orchestrator.MetricsTracker") as mock_metrics,
        ):
            mock_tracker = mock_metrics.return_value
            mock_tracker.get_summary.return_value = {
                "completion_rate": "1/1",
                "total_findings": 1,
                "validation_failures": 0,
                "elapsed_time": "0.1s",
            }
            mock_tracker.get_metrics.return_value = {}

            orchestrator.run_full_audit(skills, metrics_file=metrics_file)

        mock_metrics.assert_called_once_with(metrics_file)
        mock_tracker.record_skill_start.assert_called_once_with("iam")
        mock_tracker.record_skill_complete.assert_called_once()


# ── run_correlation ───────────────────────────────────────────────────────────


class TestRunCorrelation:
    def _valid_validation(self):
        v = SimpleNamespace(valid=True, should_correlate=True, error=None)
        return v

    def test_correlation_runs_when_skills_ready(self, orchestrator, tmp_path):
        engine_result = {
            "total_correlations": 2,
            "correlations": [],
            "patterns_applied": ["IAM+Exposure"],
            "execution_time_seconds": 0.5,
        }
        with (
            patch("drystone.cloud.orchestrator.QueueValidator") as mock_qv,
            patch("drystone.correlation.engine.CorrelationEngine") as mock_engine,
        ):
            mock_qv.return_value.validate_skill_output.return_value = self._valid_validation()
            mock_engine.return_value.run.return_value = engine_result

            result = orchestrator.run_correlation(tmp_path)

        assert result["total_correlations"] == 2

    def test_no_skills_ready_returns_empty(self, orchestrator, tmp_path):
        with patch("drystone.cloud.orchestrator.QueueValidator") as mock_qv:
            invalid = SimpleNamespace(valid=False, should_correlate=False, error="no output")
            mock_qv.return_value.validate_skill_output.return_value = invalid

            result = orchestrator.run_correlation(tmp_path)

        assert result["total_correlations"] == 0
        assert result["errors"]

    def test_correlation_engine_exception_returns_graceful_result(self, orchestrator, tmp_path):
        with (
            patch("drystone.cloud.orchestrator.QueueValidator") as mock_qv,
            patch("drystone.correlation.engine.CorrelationEngine") as mock_engine,
        ):
            mock_qv.return_value.validate_skill_output.return_value = self._valid_validation()
            mock_engine.return_value.run.side_effect = RuntimeError("engine error")

            result = orchestrator.run_correlation(tmp_path)

        assert result["total_correlations"] == 0
        assert "engine error" in result["errors"][0]

    def test_skills_from_config_used(self, orchestrator, tmp_path):
        orchestrator.config.skills = ["iam", "exposure"]
        with (
            patch("drystone.cloud.orchestrator.QueueValidator") as mock_qv,
            patch("drystone.correlation.engine.CorrelationEngine") as mock_engine,
        ):
            mock_qv.return_value.validate_skill_output.return_value = self._valid_validation()
            mock_engine.return_value.run.return_value = {
                "total_correlations": 0,
                "correlations": [],
                "patterns_applied": [],
                "execution_time_seconds": 0.0,
            }
            orchestrator.run_correlation(tmp_path)

        # Validate called once per skill
        assert mock_qv.return_value.validate_skill_output.call_count == 2


# ── save_results ──────────────────────────────────────────────────────────────


class TestSaveResults:
    def _populate_results(self, orchestrator, skills=("iam",)):
        for skill in skills:
            orchestrator.results[skill] = {
                "evidence": {"users": []},
                "findings": FINDINGS[:],
                "validation": {"status": "PASS"},
                "report": f"# {skill.upper()} Report",
            }

    def test_creates_output_directory_structure(self, orchestrator, tmp_path):
        self._populate_results(orchestrator)
        with patch.object(orchestrator, "run_correlation", return_value={"total_correlations": 0}):
            orchestrator.save_results(tmp_path)

        audit_dir = tmp_path / orchestrator.audit_id
        assert (audit_dir / "iam" / "evidence" / "raw.json").exists()
        assert (audit_dir / "iam" / "findings" / "findings.json").exists()
        assert (audit_dir / "iam" / "findings" / "validation.json").exists()
        assert (audit_dir / "iam" / "reports" / "iam_report.md").exists()

    def test_evidence_json_content(self, orchestrator, tmp_path):
        self._populate_results(orchestrator)
        with patch.object(orchestrator, "run_correlation", return_value={"total_correlations": 0}):
            orchestrator.save_results(tmp_path)

        raw = json.loads(
            (tmp_path / orchestrator.audit_id / "iam" / "evidence" / "raw.json").read_text()
        )
        assert raw == {"users": []}

    def test_correlation_run_for_two_or_more_skills(self, orchestrator, tmp_path):
        self._populate_results(orchestrator, skills=["iam", "exposure"])
        with patch.object(orchestrator, "run_correlation") as mock_corr:
            mock_corr.return_value = {"total_correlations": 1, "correlations": []}
            orchestrator.save_results(tmp_path)

        mock_corr.assert_called_once()

    def test_correlation_skipped_for_single_skill(self, orchestrator, tmp_path):
        self._populate_results(orchestrator, skills=["iam"])
        with patch.object(orchestrator, "run_correlation") as mock_corr:
            orchestrator.save_results(tmp_path)

        mock_corr.assert_not_called()

    def test_correlated_json_saved_when_correlations_found(self, orchestrator, tmp_path):
        self._populate_results(orchestrator, skills=["iam", "exposure"])
        corr_result = {
            "total_correlations": 2,
            "correlations": [{"id": "C-001"}],
        }
        with patch.object(orchestrator, "run_correlation", return_value=corr_result):
            orchestrator.save_results(tmp_path)

        corr_path = tmp_path / orchestrator.audit_id / "findings" / "correlated.json"
        assert corr_path.exists()
        data = json.loads(corr_path.read_text())
        assert data["total_correlations"] == 2

    def test_report_md_content(self, orchestrator, tmp_path):
        self._populate_results(orchestrator)
        with patch.object(orchestrator, "run_correlation", return_value={"total_correlations": 0}):
            orchestrator.save_results(tmp_path)

        md = (tmp_path / orchestrator.audit_id / "iam" / "reports" / "iam_report.md").read_text()
        assert "IAM Report" in md
