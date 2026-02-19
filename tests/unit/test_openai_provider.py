from drystone.agent.client import AgentClient
from drystone.models.config import WizardConfig


def test_wizard_config_accepts_openai_provider_with_key():
    cfg = WizardConfig(
        client_name="test",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="us-east-1",
        skills=["iam"],
        output_formats=["markdown"],
        ai_provider="openai-api",
        ai_api_key="sk-test",
    )
    assert cfg.ai_provider == "openai-api"


def test_agent_display_name_openai(monkeypatch):
    class FakeOpenAI:
        def __init__(self, api_key):
            self.api_key = api_key

        class _Models:
            @staticmethod
            def list():
                class _Resp:
                    data = []

                return _Resp()

        models = _Models()

    monkeypatch.setattr("drystone.agent.client.OpenAI", FakeOpenAI)

    agent = AgentClient(provider_config={"type": "openai-api", "api_key": "sk-test"})
    assert agent.get_display_name() == "OpenAI API (gpt-5.3-codex)"


def test_openai_api_key_sanitization(monkeypatch):
    class FakeOpenAI:
        def __init__(self, api_key):
            self.api_key = api_key

        class _Models:
            @staticmethod
            def list():
                class _Resp:
                    data = []

                return _Resp()

        models = _Models()

    monkeypatch.setattr("drystone.agent.client.OpenAI", FakeOpenAI)

    agent = AgentClient(provider_config={"type": "openai-api", "api_key": " - sk-test  "})
    assert agent.api_key == "sk-test"


def test_openai_model_fallback(monkeypatch):
    class FakeOpenAI:
        def __init__(self, api_key):
            self.api_key = api_key

        class _Model:
            def __init__(self, model_id):
                self.id = model_id

        class _Models:
            @staticmethod
            def list():
                class _Resp:
                    data = [FakeOpenAI._Model("gpt-5-mini")]

                return _Resp()

        models = _Models()

    monkeypatch.setattr("drystone.agent.client.OpenAI", FakeOpenAI)

    agent = AgentClient(provider_config={"type": "openai-api", "api_key": "sk-test"})
    assert agent.model == "gpt-5-mini"
