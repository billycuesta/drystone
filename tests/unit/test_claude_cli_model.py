from unittest.mock import Mock

from drystone.agent.client import AgentClient


def test_claude_cli_defaults_to_haiku(monkeypatch):
    monkeypatch.setattr(AgentClient, "_get_claude_cli_path", lambda self: "/usr/local/bin/claude")
    agent = AgentClient(provider_config={"type": "claude-cli"})
    assert agent.model == "haiku"
    assert agent.get_display_name() == "Claude CLI (Haiku)"


def test_claude_cli_uses_selected_model_flag(monkeypatch):
    monkeypatch.setattr(AgentClient, "_get_claude_cli_path", lambda self: "/usr/local/bin/claude")

    captured = {}

    def fake_run(args, input, capture_output, text, timeout, **kwargs):
        captured["args"] = args
        result = Mock()
        result.returncode = 0
        result.stdout = "{}"
        result.stderr = ""
        return result

    monkeypatch.setattr("subprocess.run", fake_run)

    agent = AgentClient(provider_config={"type": "claude-cli", "model": "opus"})
    agent._call_claude_cli_direct("ping")
    assert captured["args"][:4] == ["/usr/local/bin/claude", "--model", "opus", "-p"]
