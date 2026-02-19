import json
from pathlib import Path

from drystone.agent.budget import get_budget_policy


def test_budget_policy_reads_overrides(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    cfg = home / ".drystone"
    cfg.mkdir(parents=True)
    monkeypatch.setattr("pathlib.Path.home", lambda: home)

    overrides = {
        "skills": {
            "openai-api:iam": {
                "max_tokens_per_chunk": 12345,
                "max_chunks": 7,
                "distill_max_list_items": 19,
            }
        }
    }
    (cfg / "budget-overrides.json").write_text(json.dumps(overrides))

    policy = get_budget_policy("openai-api", "iam")
    assert policy.max_tokens_per_chunk == 12345
    assert policy.max_chunks == 7
    assert policy.distill_max_list_items == 19
