"""Tests for thread-safe metrics tracker with atomic updates."""

import tempfile
import threading
import time
from pathlib import Path

from drystone.logging import MetricsTracker


class TestMetricsTracker:
    """Test thread-safe metrics tracker."""

    def test_init_creates_metrics_file(self):
        """Test that tracker creates metrics file on init."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            MetricsTracker(metrics_file)

            assert metrics_file.exists(), "Metrics file should be created"

    def test_initial_metrics_structure(self):
        """Test that initial metrics have correct structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            metrics = tracker.get_metrics()

            assert "start_time" in metrics
            assert "skills" in metrics
            assert "total_findings" in metrics
            assert "total_risk_score" in metrics
            assert "validation_failures" in metrics
            assert "retry_attempts" in metrics

    def test_record_skill_start(self):
        """Test recording skill start."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("iam")

            metrics = tracker.get_metrics()
            assert "iam" in metrics["skills"]
            assert metrics["skills"]["iam"]["status"] == "in_progress"
            assert metrics["skills"]["iam"]["findings"] == 0

    def test_record_skill_findings(self):
        """Test recording skill findings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("network")
            tracker.record_skill_findings("network", findings_count=5, risk_score=6.5)

            metrics = tracker.get_metrics()
            assert metrics["skills"]["network"]["findings"] == 5
            assert metrics["skills"]["network"]["risk_score"] == 6.5
            assert metrics["total_findings"] == 5

    def test_record_skill_complete_pass(self):
        """Test recording skill completion (PASS)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("iam")
            tracker.record_skill_complete("iam", validation_passed=True)

            metrics = tracker.get_metrics()
            assert metrics["skills"]["iam"]["status"] == "complete"
            assert metrics["skills"]["iam"]["validation_passed"] is True

    def test_record_skill_complete_fail(self):
        """Test recording skill completion (FAIL)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("exposure")
            tracker.record_skill_complete("exposure", validation_passed=False)

            metrics = tracker.get_metrics()
            assert metrics["skills"]["exposure"]["status"] == "failed"
            assert metrics["validation_failures"] == 1

    def test_record_retry_attempt(self):
        """Test recording retry attempt."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("vulns")
            tracker.record_retry_attempt("vulns", attempt_number=1, reason="validation_failed")

            metrics = tracker.get_metrics()
            assert metrics["retry_attempts"] == 1
            assert len(metrics["skills"]["vulns"]["retries"]) == 1
            assert metrics["skills"]["vulns"]["retries"][0]["reason"] == "validation_failed"

    def test_get_skill_metrics(self):
        """Test retrieving metrics for specific skill."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("hardening")
            tracker.record_skill_findings("hardening", findings_count=3, risk_score=4.0)

            skill_metrics = tracker.get_skill_metrics("hardening")
            assert skill_metrics is not None
            assert skill_metrics["findings"] == 3
            assert skill_metrics["risk_score"] == 4.0

    def test_get_skill_metrics_not_found(self):
        """Test retrieving metrics for non-existent skill."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            skill_metrics = tracker.get_skill_metrics("nonexistent")
            assert skill_metrics is None

    def test_get_summary(self):
        """Test getting summary metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("iam")
            tracker.record_skill_findings("iam", 5, 7.0)
            tracker.record_skill_complete("iam", True)

            tracker.record_skill_start("network")
            tracker.record_skill_findings("network", 3, 5.0)
            tracker.record_skill_complete("network", True)

            summary = tracker.get_summary()
            assert "completion_rate" in summary
            assert summary["total_findings"] == 8
            assert summary["total_risk_score"] == 12.0
            assert summary["validation_failures"] == 0

    def test_total_risk_score_aggregation(self):
        """Test that total risk score aggregates from all skills."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("iam")
            tracker.record_skill_findings("iam", 2, 5.0)

            tracker.record_skill_start("network")
            tracker.record_skill_findings("network", 1, 3.5)

            metrics = tracker.get_metrics()
            assert metrics["total_risk_score"] == 8.5

    def test_multiple_skills_independent(self):
        """Test that multiple skills are tracked independently."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            for skill in ["iam", "exposure", "network"]:
                tracker.record_skill_start(skill)
                tracker.record_skill_findings(skill, findings_count=1, risk_score=1.0)

            metrics = tracker.get_metrics()
            assert len(metrics["skills"]) == 3
            assert metrics["total_findings"] == 3
            assert metrics["total_risk_score"] == 3.0

    def test_concurrent_skill_updates(self):
        """Test thread-safe concurrent updates to metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            def update_skill(skill_name: str):
                tracker.record_skill_start(skill_name)
                time.sleep(0.01)  # Simulate work
                tracker.record_skill_findings(skill_name, findings_count=1, risk_score=1.0)
                tracker.record_skill_complete(skill_name, validation_passed=True)

            # Create threads for concurrent updates
            threads = [
                threading.Thread(target=update_skill, args=(f"skill_{i}",)) for i in range(5)
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

            # Verify all skills were recorded
            metrics = tracker.get_metrics()
            assert len(metrics["skills"]) == 5
            assert metrics["total_findings"] == 5
            assert metrics["total_risk_score"] == 5.0

    def test_elapsed_time_calculation(self):
        """Test that elapsed time is calculated correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            time.sleep(0.1)  # Wait a bit
            summary = tracker.get_summary()

            assert "elapsed_time" in summary
            assert summary["elapsed_time"] is not None
            # Should be at least "0m 0s"
            assert "m" in summary["elapsed_time"]
            assert "s" in summary["elapsed_time"]

    def test_completion_rate_calculation(self):
        """Test completion rate calculation in summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            # Start 3 skills
            for skill in ["iam", "network", "exposure"]:
                tracker.record_skill_start(skill)

            # Complete 2 skills
            tracker.record_skill_complete("iam", True)
            tracker.record_skill_complete("network", True)

            summary = tracker.get_summary()
            assert "2/3" in summary["completion_rate"]

    def test_validation_failures_counter(self):
        """Test that validation failures are counted correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            for i in range(3):
                tracker.record_skill_start(f"skill_{i}")
                tracker.record_skill_complete(f"skill_{i}", validation_passed=False)

            metrics = tracker.get_metrics()
            assert metrics["validation_failures"] == 3

    def test_retry_attempts_counter(self):
        """Test that retry attempts are counted correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            tracker.record_skill_start("iam")
            tracker.record_retry_attempt("iam", 1, "validation_failed")
            tracker.record_retry_attempt("iam", 2, "timeout")

            tracker.record_skill_start("network")
            tracker.record_retry_attempt("network", 1, "validation_failed")

            metrics = tracker.get_metrics()
            assert metrics["retry_attempts"] == 3

    def test_atomicity_with_reentrancy(self):
        """Test that RLock provides atomic updates with reentrancy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"
            tracker = MetricsTracker(metrics_file)

            # Record multiple updates in quick succession
            tracker.record_skill_start("test")
            tracker.record_skill_findings("test", 5, 5.0)
            tracker.record_skill_complete("test", True)
            tracker.record_retry_attempt("test", 1, "reason")

            # Verify all updates were atomic (no partial updates)
            metrics = tracker.get_metrics()
            assert metrics["skills"]["test"]["findings"] == 5
            assert metrics["retry_attempts"] == 1
            assert metrics["validation_failures"] == 0  # Should be complete, not failed

    def test_metrics_persistence(self):
        """Test that metrics persist across tracker instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "metrics.json"

            # First tracker
            tracker1 = MetricsTracker(metrics_file)
            tracker1.record_skill_start("iam")
            tracker1.record_skill_findings("iam", 3, 6.0)

            # Second tracker (reading same file)
            tracker2 = MetricsTracker(metrics_file)
            metrics = tracker2.get_metrics()

            assert metrics["skills"]["iam"]["findings"] == 3
            assert metrics["total_findings"] == 3

    def test_nonexistent_directory_created(self):
        """Test that tracker creates parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics_file = Path(tmpdir) / "deep" / "nested" / "path" / "metrics.json"
            MetricsTracker(metrics_file)

            assert metrics_file.parent.exists()
            assert metrics_file.exists()


# ── Additional branch coverage ────────────────────────────────────────────────


class TestBranchCoverage:
    """Target the specific uncovered branches reported by coverage."""

    def test_read_metrics_recovers_after_file_deleted(self, tmp_path):
        """_read_metrics: FileNotFoundError branch re-creates the file."""
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        path.unlink()
        result = tracker._read_metrics()
        assert isinstance(result, dict)

    def test_read_metrics_returns_empty_dict_on_corrupt_json(self, tmp_path):
        """_read_metrics: general Exception path returns {}."""
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        path.write_text("NOT JSON{{")
        result = tracker._read_metrics()
        assert result == {}

    def test_record_skill_start_creates_skills_key_if_absent(self, tmp_path):
        """record_skill_start: 'if skills not in metrics' branch."""
        path = tmp_path / "m.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"start_time": "2026-01-01T00:00:00"}')
        tracker = MetricsTracker(path)
        tracker.record_skill_start("iam")
        import json as _json

        data = _json.loads(path.read_text())
        assert "iam" in data["skills"]

    def test_record_token_usage_creates_skill_entry_if_missing(self, tmp_path):
        """record_token_usage: 'if skill_name not in' branch."""
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_token_usage("network", 300, 150)
        import json as _json

        data = _json.loads(path.read_text())
        assert data["skills"]["network"]["prompt_tokens_est"] == 300

    def test_record_skill_provider_stores_provider(self, tmp_path):
        """record_skill_provider (entire function was uncovered)."""
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_skill_start("iam")
        tracker.record_skill_provider("iam", "claude-api")
        import json as _json

        data = _json.loads(path.read_text())
        assert data["skills"]["iam"]["provider"] == "claude-api"

    def test_record_skill_provider_creates_entry_if_missing(self, tmp_path):
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_skill_provider("vulns", "claude-cli")
        import json as _json

        data = _json.loads(path.read_text())
        assert "vulns" in data["skills"]

    def test_record_skill_quality_stores_metrics(self, tmp_path):
        """record_skill_quality (entire function was uncovered)."""
        import json as _json

        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_skill_start("iam")
        tracker.record_skill_quality("iam", 0.9, "CONFIDENT", llm_skipped=False)
        data = _json.loads(path.read_text())
        assert abs(data["skills"]["iam"]["confidence_score"] - 0.9) < 1e-6
        assert data["skills"]["iam"]["llm_skipped"] is False

    def test_record_skill_quality_creates_entry_if_missing(self, tmp_path):
        import json as _json

        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_skill_quality("exposure", 0.7, "UNCERTAIN", llm_skipped=True)
        data = _json.loads(path.read_text())
        assert data["skills"]["exposure"]["llm_skipped"] is True

    def test_record_llm_budget_stores_metrics(self, tmp_path):
        """record_llm_budget (entire function was uncovered)."""
        import json as _json

        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_skill_start("iam")
        tracker.record_llm_budget(
            "iam", llm_checks=5, deterministic_checks=10, distilled_files=2, items_removed=40
        )
        data = _json.loads(path.read_text())
        assert data["skills"]["iam"]["llm_checks"] == 5
        assert data["skills"]["iam"]["evidence_items_removed"] == 40

    def test_record_llm_budget_creates_entry_if_missing(self, tmp_path):
        import json as _json

        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_llm_budget(
            "waf", llm_checks=3, deterministic_checks=7, distilled_files=0, items_removed=0
        )
        data = _json.loads(path.read_text())
        assert "waf" in data["skills"]

    def test_record_skill_findings_creates_entry_if_missing(self, tmp_path):
        """record_skill_findings: 'if skill_name not in' branch."""
        import json as _json

        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_skill_findings("network", 2, 6.0)
        data = _json.loads(path.read_text())
        assert "network" in data["skills"]

    def test_record_skill_complete_creates_entry_if_missing(self, tmp_path):
        """record_skill_complete: 'if skill_name not in' branch."""
        import json as _json

        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_skill_complete("vulns", True)
        data = _json.loads(path.read_text())
        assert "vulns" in data["skills"]

    def test_record_retry_attempt_creates_entry_if_missing(self, tmp_path):
        """record_retry_attempt: 'if skill_name not in' branch."""
        import json as _json

        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        tracker.record_retry_attempt("waf", 1, "rate_limit")
        data = _json.loads(path.read_text())
        assert "waf" in data["skills"]

    def test_calculate_elapsed_time_returns_none_when_no_start_time(self, tmp_path):
        """_calculate_elapsed_time: start_time missing or not string."""
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        assert tracker._calculate_elapsed_time({}) is None
        assert tracker._calculate_elapsed_time({"start_time": None}) is None
        assert tracker._calculate_elapsed_time({"start_time": 12345}) is None

    def test_calculate_elapsed_time_returns_none_on_invalid_date(self, tmp_path):
        """_calculate_elapsed_time: Exception branch."""
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        result = tracker._calculate_elapsed_time({"start_time": "NOT-A-DATE"})
        assert result is None

    def test_get_skill_metrics_returns_none_for_unknown(self, tmp_path):
        path = tmp_path / "m.json"
        tracker = MetricsTracker(path)
        assert tracker.get_skill_metrics("unknown") is None
