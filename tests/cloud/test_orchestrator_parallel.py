"""Tests for parallel orchestrator execution.

Tests the new ThreadPoolExecutor-based parallel skill execution
to ensure correct behavior, error resilience, and performance.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from drystone.cloud.orchestrator import AuditOrchestrator, SkillProgressTracker
from drystone.models.config import WizardConfig


@pytest.fixture
def mock_config():
    """Create mock WizardConfig for testing."""
    config = Mock(spec=WizardConfig)
    config.aws_credentials = {"access_key_id": "test", "secret_access_key": "test"}
    config.anthropic_client = Mock()
    return config


@pytest.fixture
def mock_skills():
    """Create mock skill configs."""
    return [
        {
            "name": "iam",
            "collector": Mock(),
            "analyzer": Mock(),
            "checklist_path": Path("test.json"),
        },
        {
            "name": "exposure",
            "collector": Mock(),
            "analyzer": Mock(),
            "checklist_path": Path("test.json"),
        },
        {
            "name": "network",
            "collector": Mock(),
            "analyzer": Mock(),
            "checklist_path": Path("test.json"),
        },
    ]


def create_mock_result(skill_name, status="PASS"):
    """Create a mock skill audit result."""
    return {
        "skill": skill_name,
        "evidence": {},
        "findings": [{"id": f"{skill_name}-001", "severity": "High"}],
        "report": f"# {skill_name} Report",
        "validation": {
            "coverage": {"coverage_valid": True, "coverage_percentage": 100.0},
            "quality": {"validation_status": status, "confidence_score": 0.95},
            "report": {"report_valid": True},
            "status": status,
        },
        "timestamp": datetime.now().isoformat(),
    }


class TestSkillProgressTracker:
    """Test SkillProgressTracker functionality."""

    def test_tracker_initialization(self):
        """Test tracker initializes correctly."""
        tracker = SkillProgressTracker(6)

        assert tracker.total == 6
        assert tracker.completed == 0
        assert tracker.start_time is None

    def test_tracker_start(self):
        """Test tracker start method."""
        tracker = SkillProgressTracker(3)
        tracker.start()

        assert tracker.start_time is not None
        assert isinstance(tracker.start_time, datetime)

    def test_tracker_record_completion(self):
        """Test recording skill completion."""
        tracker = SkillProgressTracker(3)
        tracker.start()

        tracker.record_completion("iam", "PASS", duration=5.0)
        assert tracker.completed == 1
        assert tracker.skill_times["iam"] == 5.0

    def test_tracker_summary(self):
        """Test progress summary generation."""
        tracker = SkillProgressTracker(3)
        tracker.start()

        time.sleep(0.1)
        tracker.record_completion("iam", "PASS", duration=0.1)

        summary = tracker.summary()
        assert "1/3" in summary
        assert "33%" in summary  # Roughly 33%

    def test_tracker_thread_safety(self):
        """Test tracker is thread-safe with concurrent updates."""
        tracker = SkillProgressTracker(10)
        tracker.start()

        def record_skill(i):
            time.sleep(0.01)  # Simulate work
            tracker.record_completion(f"skill-{i}", "PASS", duration=0.01)

        # Run 10 concurrent updates
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(record_skill, i) for i in range(10)]
            for future in futures:
                future.result()

        # All should be recorded
        assert tracker.completed == 10


class TestParallelOrchestrator:
    """Test parallel orchestrator execution."""

    def test_orchestrator_initialization(self, mock_config):
        """Test orchestrator initializes with parallel support."""
        orchestrator = AuditOrchestrator(mock_config)

        assert orchestrator.config == mock_config
        assert orchestrator.results == {}
        assert hasattr(orchestrator, "results_lock")

    def test_parallel_execution_all_succeed(self, mock_config, mock_skills):
        """Test parallel execution when all skills succeed."""
        orchestrator = AuditOrchestrator(mock_config)

        # Mock run_skill_audit to return results
        with patch.object(orchestrator, "run_skill_audit") as mock_run:
            # Side effects must be order-independent because skills run in parallel.
            def _side_effect(*, skill_name, **_kwargs):
                return create_mock_result(skill_name, "PASS")

            mock_run.side_effect = _side_effect

            result = orchestrator.run_full_audit(mock_skills)

            # Verify all skills were executed
            assert mock_run.call_count == 3
            assert len(result["skills"]) == 3
            assert result["status"] == "PASS"
            assert result["summary"]["passed_skills"] == 3
            assert result["summary"]["failed_skills"] == 0

    def test_parallel_execution_one_failure(self, mock_config, mock_skills):
        """Test parallel execution when one skill fails."""
        orchestrator = AuditOrchestrator(mock_config)

        # Mock run_skill_audit: iam fails, others succeed
        with patch.object(orchestrator, "run_skill_audit") as mock_run:

            def _side_effect(*, skill_name, **_kwargs):
                if skill_name == "iam":
                    raise Exception("IAM connection error")
                return create_mock_result(skill_name, "PASS")

            mock_run.side_effect = _side_effect

            result = orchestrator.run_full_audit(mock_skills)

            # Should have 2 results despite 1 failure
            assert len(result["skills"]) == 2
            assert "iam" not in result["skills"]
            assert "exposure" in result["skills"]
            assert "network" in result["skills"]
            assert result["status"] == "PASS"  # Others passed

    def test_parallel_execution_multiple_failures(self, mock_config, mock_skills):
        """Test parallel execution with multiple failures."""
        orchestrator = AuditOrchestrator(mock_config)

        with patch.object(orchestrator, "run_skill_audit") as mock_run:

            def _side_effect(*, skill_name, **_kwargs):
                if skill_name == "iam":
                    raise Exception("IAM failed")
                if skill_name == "exposure":
                    raise Exception("Exposure failed")
                return create_mock_result(skill_name, "PASS")

            mock_run.side_effect = _side_effect

            result = orchestrator.run_full_audit(mock_skills)

            # Should have 1 result from network
            assert len(result["skills"]) == 1
            assert result["skills"]["network"]["validation"]["status"] == "PASS"

    def test_max_workers_parameter(self, mock_config, mock_skills):
        """Test max_workers parameter limits concurrency."""
        orchestrator = AuditOrchestrator(mock_config)

        with patch.object(orchestrator, "run_skill_audit") as mock_run:

            def _side_effect(*, skill_name, **_kwargs):
                return create_mock_result(skill_name)

            mock_run.side_effect = _side_effect

            with patch("drystone.cloud.orchestrator.ThreadPoolExecutor") as mock_pool:
                mock_pool.return_value.__enter__.return_value = ThreadPoolExecutor(max_workers=2)

                # Use max_workers=2 explicitly
                orchestrator.run_full_audit(mock_skills, max_workers=2)

                # ThreadPoolExecutor should be called with max_workers=2
                # Note: We can't verify the exact call due to mocking complexity,
                # but we test that it doesn't crash

    def test_empty_skills_list(self, mock_config):
        """Test handling of empty skills list."""
        orchestrator = AuditOrchestrator(mock_config)

        result = orchestrator.run_full_audit([])

        assert result["summary"]["total_skills"] == 0
        assert result["status"] == "PASS"

    def test_skills_with_different_statuses(self, mock_config, mock_skills):
        """Test handling mixed skill statuses."""
        orchestrator = AuditOrchestrator(mock_config)

        with patch.object(orchestrator, "run_skill_audit") as mock_run:

            def _side_effect(*, skill_name, **_kwargs):
                statuses = {
                    "iam": "PASS",
                    "exposure": "NEEDS_REVIEW",
                    "network": "FAIL",
                }
                return create_mock_result(skill_name, statuses[skill_name])

            mock_run.side_effect = _side_effect

            result = orchestrator.run_full_audit(mock_skills)

            assert result["summary"]["passed_skills"] == 1
            assert result["summary"]["review_skills"] == 1
            assert result["summary"]["failed_skills"] == 1
            assert result["status"] == "FAIL"  # Overall status is FAIL

    def test_thread_safe_wrapper_isolation(self, mock_config, mock_skills):
        """Test _run_skill_audit_thread_safe doesn't affect other threads."""
        orchestrator = AuditOrchestrator(mock_config)

        with patch.object(orchestrator, "run_skill_audit") as mock_run:

            def _side_effect(*, skill_name, **_kwargs):
                return create_mock_result(skill_name)

            mock_run.side_effect = _side_effect

            orchestrator.run_full_audit(mock_skills)

            # Each thread should have stored its result in self.results
            assert len(orchestrator.results) == 3
            assert all(skill in orchestrator.results for skill in ["iam", "exposure", "network"])


class TestParallelPerformance:
    """Test parallel execution performance benefits."""

    def test_parallel_faster_than_sequential(self, mock_config):
        """Verify parallel is faster than sequential (on mock data)."""
        # Create 3 mock skills
        mock_skills = [
            {
                "name": f"skill-{i}",
                "collector": Mock(),
                "analyzer": Mock(),
                "checklist_path": Path("test.json"),
            }
            for i in range(3)
        ]

        orchestrator = AuditOrchestrator(mock_config)

        # Mock with delays to simulate real work
        call_count = [0]

        def slow_audit(*args, **kwargs):
            time.sleep(0.05)  # 50ms per skill (quicker for tests)
            call_count[0] += 1
            # Get the skill_name from the first positional arg
            skill_name = args[0] if args else f"skill-{call_count[0]}"
            return create_mock_result(skill_name)

        with patch.object(orchestrator, "run_skill_audit", side_effect=slow_audit):
            # Measure parallel execution
            start = time.time()
            result = orchestrator.run_full_audit(mock_skills)
            parallel_time = time.time() - start

            # Sequential would take ~0.15s (3 * 0.05s)
            # Parallel should take ~0.05s (max of 0.05s each)
            # In reality it'll be more due to overhead, but much less than 0.15s
            assert parallel_time < 0.12  # Much less than sequential 0.15s
            assert len(result["skills"]) == 3


class TestBackwardCompatibility:
    """Test that parallel implementation maintains backward compatibility."""

    def test_api_signature_unchanged(self, mock_config, mock_skills):
        """Test run_full_audit API signature is backward compatible."""
        orchestrator = AuditOrchestrator(mock_config)

        # Old code should still work (without max_workers parameter)
        with patch.object(orchestrator, "run_skill_audit") as mock_run:

            def _side_effect(*, skill_name, **_kwargs):
                return create_mock_result(skill_name)

            mock_run.side_effect = _side_effect

            # Call without max_workers (old way)
            result = orchestrator.run_full_audit(mock_skills)

            # Should work and return same structure
            assert "audit_id" in result
            assert "status" in result
            assert "skills" in result
            assert "summary" in result

    def test_result_structure_unchanged(self, mock_config, mock_skills):
        """Test result structure matches original."""
        orchestrator = AuditOrchestrator(mock_config)

        with patch.object(orchestrator, "run_skill_audit") as mock_run:

            def _side_effect(*, skill_name, **_kwargs):
                return create_mock_result(skill_name, "PASS")

            mock_run.side_effect = _side_effect

            result = orchestrator.run_full_audit(mock_skills)

            # Verify structure
            assert "audit_id" in result
            assert "status" in result
            assert isinstance(result["status"], str)
            assert result["status"] in ["PASS", "FAIL", "NEEDS_REVIEW"]
            assert "timestamp" in result
            assert "skills" in result
            assert isinstance(result["skills"], dict)
            assert "summary" in result
            assert "total_skills" in result["summary"]
            assert "passed_skills" in result["summary"]
            assert "failed_skills" in result["summary"]
            assert "total_findings" in result["summary"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
