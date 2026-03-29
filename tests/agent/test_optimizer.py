"""Tests for agent/optimizer.py."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from drystone.agent.optimizer import optimize_budgets_from_metrics


@pytest.fixture
def metrics_file(tmp_path):
    path = tmp_path / "metrics.json"
    return path


def _write_metrics(path: Path, skills: dict):
    data = {"skills": skills}
    path.write_text(json.dumps(data))
    return path


# ── Guard clauses ─────────────────────────────────────────────────────────────


class TestGuardClauses:
    def test_returns_zero_when_file_missing(self, metrics_file):
        result = optimize_budgets_from_metrics(metrics_file)
        assert result == {"updated": 0}

    def test_returns_zero_on_corrupt_json(self, metrics_file):
        metrics_file.write_text("NOT JSON{{")
        result = optimize_budgets_from_metrics(metrics_file)
        assert result == {"updated": 0}

    def test_returns_zero_when_skills_not_a_dict(self, metrics_file):
        metrics_file.write_text(json.dumps({"skills": ["list", "not", "dict"]}))
        result = optimize_budgets_from_metrics(metrics_file)
        assert result == {"updated": 0}

    def test_skips_non_dict_skill_entries(self, metrics_file, tmp_path):
        _write_metrics(metrics_file, {"iam": "not-a-dict"})
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = optimize_budgets_from_metrics(metrics_file)
        assert result["updated"] == 0


# ── Overrides file ────────────────────────────────────────────────────────────


class TestOverridesFile:
    def test_creates_overrides_file(self, metrics_file, tmp_path):
        _write_metrics(metrics_file, {"iam": {"status": "complete", "provider": "claude-cli"}})
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = optimize_budgets_from_metrics(metrics_file)
        overrides = tmp_path / ".drystone" / "budget-overrides.json"
        assert overrides.exists()
        assert "overrides_file" in result

    def test_reads_existing_overrides(self, metrics_file, tmp_path):
        _write_metrics(metrics_file, {"iam": {"status": "complete", "provider": "claude-api"}})
        overrides_path = tmp_path / ".drystone" / "budget-overrides.json"
        overrides_path.parent.mkdir(parents=True)
        existing = {
            "skills": {
                "claude-api:iam": {
                    "max_chunks": 10,
                    "distill_max_list_items": 25,
                    "max_tokens_per_chunk": 30000,
                }
            }
        }
        overrides_path.write_text(json.dumps(existing))
        with patch("pathlib.Path.home", return_value=tmp_path):
            optimize_budgets_from_metrics(metrics_file)
        data = json.loads(overrides_path.read_text())
        assert "claude-api:iam" in data["skills"]

    def test_recovers_when_overrides_corrupt(self, metrics_file, tmp_path):
        _write_metrics(metrics_file, {"iam": {"status": "complete", "provider": "claude-cli"}})
        overrides_path = tmp_path / ".drystone" / "budget-overrides.json"
        overrides_path.parent.mkdir(parents=True)
        overrides_path.write_text("INVALID{{")
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = optimize_budgets_from_metrics(metrics_file)
        # Should not raise; creates fresh overrides
        assert "updated" in result


# ── Reduction heuristics ──────────────────────────────────────────────────────


class TestHeuristics:
    def test_failed_skill_reduces_chunks(self, metrics_file, tmp_path):
        _write_metrics(
            metrics_file,
            {"iam": {"status": "failed", "provider": "claude-cli", "retries": []}},
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = optimize_budgets_from_metrics(metrics_file)
        assert result["updated"] == 1
        data = json.loads((tmp_path / ".drystone" / "budget-overrides.json").read_text())
        entry = data["skills"]["claude-cli:iam"]
        assert entry["max_chunks"] < 8  # reduced from default 8

    def test_quota_retry_reduces_chunks(self, metrics_file, tmp_path):
        _write_metrics(
            metrics_file,
            {
                "network": {
                    "status": "complete",
                    "provider": "claude-cli",
                    "retries": [{"reason": "quota_exceeded"}],
                }
            },
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = optimize_budgets_from_metrics(metrics_file)
        assert result["updated"] == 1

    def test_llm_skipped_reduces_chunks_by_one(self, metrics_file, tmp_path):
        _write_metrics(
            metrics_file,
            {
                "iam": {
                    "status": "complete",
                    "provider": "claude-cli",
                    "llm_skipped": True,
                    "retries": [],
                }
            },
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = optimize_budgets_from_metrics(metrics_file)
        assert result["updated"] == 1
        data = json.loads((tmp_path / ".drystone" / "budget-overrides.json").read_text())
        entry = data["skills"]["claude-cli:iam"]
        assert entry["max_chunks"] == 7  # reduced by 1 from default 8

    def test_clean_run_no_update(self, metrics_file, tmp_path):
        """Successful skill with no retries and llm_skipped=False → no override update."""
        _write_metrics(
            metrics_file,
            {
                "iam": {
                    "status": "complete",
                    "provider": "claude-cli",
                    "llm_skipped": False,
                    "retries": [],
                }
            },
        )
        # Pre-seed overrides with the default values so next_cfg == current
        overrides_path = tmp_path / ".drystone" / "budget-overrides.json"
        overrides_path.parent.mkdir(parents=True)
        overrides_path.write_text(
            json.dumps(
                {
                    "skills": {
                        "claude-cli:iam": {
                            "max_tokens_per_chunk": 14000,
                            "max_chunks": 8,
                            "distill_max_list_items": 20,
                        }
                    }
                }
            )
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = optimize_budgets_from_metrics(metrics_file)
        assert result["updated"] == 0

    def test_api_provider_has_higher_defaults(self, metrics_file, tmp_path):
        _write_metrics(
            metrics_file,
            {"iam": {"status": "failed", "provider": "claude-api", "retries": []}},
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            optimize_budgets_from_metrics(metrics_file)
        data = json.loads((tmp_path / ".drystone" / "budget-overrides.json").read_text())
        entry = data["skills"]["claude-api:iam"]
        assert entry["max_chunks"] <= 10  # reduced from api default 12

    def test_max_chunks_floor_at_four(self, metrics_file, tmp_path):
        """max_chunks should never go below 4."""
        overrides_path = tmp_path / ".drystone" / "budget-overrides.json"
        overrides_path.parent.mkdir(parents=True)
        # Start with already-reduced value
        overrides_path.write_text(
            json.dumps(
                {
                    "skills": {
                        "claude-cli:iam": {
                            "max_chunks": 4,
                            "distill_max_list_items": 12,
                            "max_tokens_per_chunk": 14000,
                        }
                    }
                }
            )
        )
        _write_metrics(
            metrics_file,
            {"iam": {"status": "failed", "provider": "claude-cli", "retries": []}},
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            optimize_budgets_from_metrics(metrics_file)
        data = json.loads(overrides_path.read_text())
        assert data["skills"]["claude-cli:iam"]["max_chunks"] >= 4

    def test_records_last_optimized_from(self, metrics_file, tmp_path):
        _write_metrics(
            metrics_file,
            {"iam": {"status": "failed", "provider": "claude-cli", "retries": []}},
        )
        with patch("pathlib.Path.home", return_value=tmp_path):
            optimize_budgets_from_metrics(metrics_file)
        data = json.loads((tmp_path / ".drystone" / "budget-overrides.json").read_text())
        assert "last_optimized_from" in data
