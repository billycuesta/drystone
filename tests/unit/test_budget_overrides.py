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
            "claude-api:iam": {
                "max_tokens_per_chunk": 12345,
                "max_chunks": 7,
                "distill_max_list_items": 19,
            }
        }
    }
    (cfg / "budget-overrides.json").write_text(json.dumps(overrides))

    policy = get_budget_policy("claude-api", "iam")
    assert policy.max_tokens_per_chunk == 12345
    assert policy.max_chunks == 7
    assert policy.distill_max_list_items == 19


def test_budget_policy_scopes_client_overrides_and_falls_back_to_global(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    cfg = home / ".drystone"
    cfg.mkdir(parents=True)
    monkeypatch.setattr("pathlib.Path.home", lambda: home)

    overrides = {
        "skills": {
            "claude-cli:iam": {"max_chunks": 8},
        },
        "clients": {
            "client-a": {
                "skills": {
                    "claude-cli:iam": {"max_chunks": 3},
                }
            }
        },
    }
    (cfg / "budget-overrides.json").write_text(json.dumps(overrides))

    client_a = get_budget_policy("claude-cli", "iam", client_name="client-a")
    client_b = get_budget_policy("claude-cli", "iam", client_name="client-b")
    unscoped = get_budget_policy("claude-cli", "iam")

    assert client_a.max_chunks == 3
    assert client_b.max_chunks == 8
    assert unscoped.max_chunks == 8
