import json
from pathlib import Path

from drystone.agent.optimizer import optimize_budgets_from_metrics


def test_optimizer_creates_overrides_for_failed_skill(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)

    metrics_file = tmp_path / "metrics.json"
    metrics_file.write_text(
        json.dumps(
            {
                "skills": {
                    "iam": {
                        "provider": "claude-api",
                        "status": "failed",
                        "retries": [{"reason": "provider quota/rate limit"}],
                    }
                }
            }
        )
    )

    out = optimize_budgets_from_metrics(metrics_file)
    assert out["updated"] >= 1

    overrides = home / ".drystone" / "budget-overrides.json"
    assert overrides.exists()
    data = json.loads(overrides.read_text())
    assert "claude-api:iam" in data["skills"]
