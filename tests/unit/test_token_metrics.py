import json
from pathlib import Path

from drystone.logging.metrics_tracker import MetricsTracker


def test_record_token_usage_aggregates_per_skill_and_total(tmp_path: Path):
    metrics_file = tmp_path / "metrics.json"
    tracker = MetricsTracker(metrics_file)

    tracker.record_skill_start("iam")
    tracker.record_token_usage("iam", prompt_tokens=100, response_tokens=40)
    tracker.record_token_usage("iam", prompt_tokens=20, response_tokens=10)

    data = json.loads(metrics_file.read_text())
    assert data["skills"]["iam"]["prompt_tokens_est"] == 120
    assert data["skills"]["iam"]["response_tokens_est"] == 50
    assert data["skills"]["iam"]["total_tokens_est"] == 170
    assert data["total_prompt_tokens_est"] == 120
    assert data["total_response_tokens_est"] == 50
    assert data["total_tokens_est"] == 170
