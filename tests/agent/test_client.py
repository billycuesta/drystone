"""Tests for AgentClient — constructor, pure helpers, JSON parsing, analyze_evidence."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from drystone.agent.client import AgentClient, AgentError

# ── Constructor helpers ───────────────────────────────────────────────────────


def _make_api_client(**kwargs) -> AgentClient:
    """Create a claude-api client without a real Anthropic connection."""
    config = {"type": "claude-api", "api_key": "sk-ant-test", **kwargs}
    with patch("anthropic.Anthropic"):
        return AgentClient(provider_config=config)


def _make_cli_client(**kwargs) -> AgentClient:
    """Create a claude-cli client with a fake binary path."""
    config = {"type": "claude-cli", **kwargs}
    with (
        patch("shutil.which", return_value="/usr/bin/claude"),
        patch.object(Path, "is_file", return_value=True),
    ):
        return AgentClient(provider_config=config)


# ── AgentClient.__init__ ──────────────────────────────────────────────────────


class TestAgentClientInit:
    def test_invalid_provider_raises(self):
        with pytest.raises(AgentError, match="not supported"):
            AgentClient(provider_config={"type": "openai"})

    def test_claude_api_no_key_raises(self):
        with pytest.raises(AgentError, match="API key required"):
            AgentClient(provider_config={"type": "claude-api"})

    def test_claude_api_empty_key_raises(self):
        with pytest.raises(AgentError, match="API key required"):
            AgentClient(provider_config={"type": "claude-api", "api_key": ""})

    def test_claude_api_initializes(self):
        client = _make_api_client()
        assert client.provider_type == "claude-api"
        assert client.use_cli is False

    def test_claude_cli_not_found_raises(self):
        with patch("shutil.which", return_value=None):
            with pytest.raises(AgentError, match="not found in PATH"):
                AgentClient(provider_config={"type": "claude-cli"})

    def test_claude_cli_not_a_file_raises(self):
        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch.object(Path, "is_file", return_value=False),
        ):
            with pytest.raises(AgentError, match="not a file"):
                AgentClient(provider_config={"type": "claude-cli"})

    def test_claude_cli_initializes(self):
        client = _make_cli_client()
        assert client.provider_type == "claude-cli"
        assert client.use_cli is True

    def test_default_provider_is_cli(self):
        with (
            patch("shutil.which", return_value="/usr/bin/claude"),
            patch.object(Path, "is_file", return_value=True),
        ):
            client = AgentClient()
        assert client.provider_type == "claude-cli"

    def test_crash_safe_logger_stored(self):
        mock_logger = MagicMock()
        client = _make_api_client()
        client.crash_safe_logger = mock_logger
        assert client.crash_safe_logger is mock_logger

    def test_findings_cache_created(self):
        client = _make_api_client()
        assert client.findings_cache is not None

    def test_api_key_sanitized_on_init(self):
        """Leading '- ' should be stripped from API key."""
        with patch("anthropic.Anthropic"):
            client = AgentClient(provider_config={"type": "claude-api", "api_key": "- sk-ant-test"})
        assert client.api_key == "sk-ant-test"


# ── _sanitize_api_key ─────────────────────────────────────────────────────────


class TestSanitizeApiKey:
    def setup_method(self):
        self.client = _make_api_client()

    def test_strips_leading_whitespace(self):
        assert self.client._sanitize_api_key("  sk-ant-key  ") == "sk-ant-key"

    def test_strips_dash_space_prefix(self):
        assert self.client._sanitize_api_key("- sk-ant-key") == "sk-ant-key"

    def test_plain_key_unchanged(self):
        assert self.client._sanitize_api_key("sk-ant-abc123") == "sk-ant-abc123"

    def test_none_returns_none(self):
        assert self.client._sanitize_api_key(None) is None

    def test_non_string_returned_as_is(self):
        assert self.client._sanitize_api_key(42) == 42  # type: ignore[arg-type]

    def test_strips_both_dash_and_whitespace(self):
        assert self.client._sanitize_api_key("  - sk-ant-key  ") == "sk-ant-key"


# ── get_display_name ──────────────────────────────────────────────────────────


class TestGetDisplayName:
    def test_api_opus_name(self):
        client = _make_api_client()
        assert "Opus" in client.get_display_name()

    def test_api_sonnet_name(self):
        client = _make_api_client()
        client.model = "claude-sonnet-4-5"
        assert "Sonnet" in client.get_display_name()

    def test_api_fallback_name(self):
        client = _make_api_client()
        client.model = "claude-haiku-4"
        assert client.get_display_name() == "Claude API"

    def test_cli_name_includes_model(self):
        client = _make_cli_client()
        name = client.get_display_name()
        assert "Claude CLI" in name

    def test_cli_name_capitalizes_model(self):
        client = _make_cli_client()
        client.model = "haiku"
        assert "Haiku" in client.get_display_name()

    def test_unknown_provider_fallback(self):
        client = _make_api_client()
        client.provider_type = "other"
        assert client.get_display_name() == "AI Provider"


# ── _estimate_tokens_text ─────────────────────────────────────────────────────


class TestEstimateTokensText:
    def setup_method(self):
        self.client = _make_api_client()

    def test_empty_string_returns_zero(self):
        assert self.client._estimate_tokens_text("") == 0

    def test_none_returns_zero(self):
        assert self.client._estimate_tokens_text(None) == 0  # type: ignore[arg-type]

    def test_short_text_returns_at_least_one(self):
        assert self.client._estimate_tokens_text("hi") == 1

    def test_longer_text(self):
        # 300 chars → 100 tokens
        text = "a" * 300
        assert self.client._estimate_tokens_text(text) == 100

    def test_non_string_returns_zero(self):
        assert self.client._estimate_tokens_text(42) == 0  # type: ignore[arg-type]


# ── _extract_json_from_text ───────────────────────────────────────────────────


class TestExtractJsonFromText:
    def setup_method(self):
        self.client = _make_api_client()

    def test_extracts_object_from_prose(self):
        text = 'Here is the result: {"key": "value"} and some trailing text.'
        result = self.client._extract_json_from_text(text)
        assert result == '{"key": "value"}'

    def test_extracts_array_from_prose(self):
        text = "Results: [1, 2, 3] done."
        result = self.client._extract_json_from_text(text)
        assert result == "[1, 2, 3]"

    def test_nested_object(self):
        text = '{"a": {"b": 1}}'
        result = self.client._extract_json_from_text(text)
        assert result == '{"a": {"b": 1}}'

    def test_no_json_returns_none(self):
        result = self.client._extract_json_from_text("no json here at all")
        assert result is None

    def test_object_wins_over_array_when_first(self):
        text = '{"key": 1} [1, 2]'
        result = self.client._extract_json_from_text(text)
        assert result == '{"key": 1}'

    def test_array_wins_when_first(self):
        text = '[1, 2] {"key": 1}'
        result = self.client._extract_json_from_text(text)
        assert result == "[1, 2]"

    def test_empty_object(self):
        result = self.client._extract_json_from_text("{}")
        assert result == "{}"

    def test_empty_string_returns_none(self):
        result = self.client._extract_json_from_text("")
        assert result is None

    def test_unclosed_brace_returns_none(self):
        result = self.client._extract_json_from_text('{"key": "never closed"')
        assert result is None


# ── _parse_json_response ──────────────────────────────────────────────────────


class TestParseJsonResponse:
    def setup_method(self):
        self.client = _make_api_client()

    def test_plain_json(self):
        data = self.client._parse_json_response('{"key": "value"}')
        assert data == {"key": "value"}

    def test_json_in_code_block(self):
        text = '```json\n{"key": "value"}\n```'
        data = self.client._parse_json_response(text)
        assert data == {"key": "value"}

    def test_json_in_plain_code_block(self):
        text = '```\n{"key": "value"}\n```'
        data = self.client._parse_json_response(text)
        assert data == {"key": "value"}

    def test_json_embedded_in_prose(self):
        text = 'Here is the analysis:\n{"findings": [], "summary": {"total_findings": 0}}'
        data = self.client._parse_json_response(text)
        assert "findings" in data

    def test_truncated_response_raises(self):
        text = '{"findings": ["unclosed'
        with pytest.raises(AgentError):
            self.client._parse_json_response(text)

    def test_pure_prose_raises(self):
        # Prose ending in "." → code takes the truncated path, raises AgentError
        with pytest.raises(AgentError):
            self.client._parse_json_response("This is just prose with no JSON at all.")

    def test_pure_prose_ending_in_brace_raises_invalid_json(self):
        # Prose that ends with } but is not valid JSON → "Invalid JSON" message
        with pytest.raises(AgentError, match="Invalid JSON"):
            self.client._parse_json_response("This is prose that ends with a brace}")

    def test_trailing_text_after_json_salvaged(self):
        """Trailing text after closing brace should be stripped."""
        valid_json = '{"key": "value"}'
        text = valid_json + "\n\nSome explanation here."
        data = self.client._parse_json_response(text)
        assert data == {"key": "value"}

    def test_leading_whitespace_stripped(self):
        data = self.client._parse_json_response('  {"x": 1}  ')
        assert data == {"x": 1}

    def test_array_response(self):
        data = self.client._parse_json_response("[1, 2, 3]")
        assert data == [1, 2, 3]


# ── analyze_evidence (API path) ───────────────────────────────────────────────


MINIMAL_FINDINGS_JSON = json.dumps(
    {
        "skill": "iam",
        "findings": [],
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 0.0,
        },
        "analyzed_at": "2025-01-01T00:00:00",
        "evidence_count": 1,
        "checklist_version": "1.0",
    }
)

MINIMAL_CHECKLIST = {
    "skill": "iam",
    "items": [{"id": "IAM-001", "title": "Root MFA", "severity": "Critical"}],
}


class TestAnalyzeEvidence:
    def test_returns_skill_findings(self):
        client = _make_api_client()
        with patch.object(client, "_call_claude_api", return_value=MINIMAL_FINDINGS_JSON):
            result = client.analyze_evidence("iam", {"users": []}, MINIMAL_CHECKLIST)
        assert result.skill == "iam"
        assert result.summary.total_findings == 0

    def test_cli_path_used_when_use_cli(self):
        client = _make_cli_client()
        with patch.object(
            client, "_call_claude_cli", return_value=MINIMAL_FINDINGS_JSON
        ) as mock_cli:
            result = client.analyze_evidence("iam", {"users": []}, MINIMAL_CHECKLIST)
        mock_cli.assert_called_once()
        assert result.skill == "iam"

    def test_invalid_json_raises_agent_error(self):
        client = _make_api_client()
        with patch.object(client, "_call_claude_api", return_value="not json at all"):
            with pytest.raises(AgentError):
                client.analyze_evidence("iam", {"users": []}, MINIMAL_CHECKLIST)

    def test_interactive_response_raises_with_message(self):
        client = _make_api_client()
        interactive = "I'm ready to help you with your request!"
        with patch.object(client, "_call_claude_api", return_value=interactive):
            with pytest.raises(AgentError, match="interactive session"):
                client.analyze_evidence("iam", {"users": []}, MINIMAL_CHECKLIST)

    def test_crash_safe_logger_called_on_start(self):
        client = _make_api_client()
        mock_logger = MagicMock()
        client.crash_safe_logger = mock_logger
        with patch.object(client, "_call_claude_api", return_value=MINIMAL_FINDINGS_JSON):
            client.analyze_evidence("iam", {"users": []}, MINIMAL_CHECKLIST)
        mock_logger.log_skill_start.assert_called_once()

    def test_crash_safe_logger_called_on_complete(self):
        client = _make_api_client()
        mock_logger = MagicMock()
        client.crash_safe_logger = mock_logger
        with patch.object(client, "_call_claude_api", return_value=MINIMAL_FINDINGS_JSON):
            client.analyze_evidence("iam", {"users": []}, MINIMAL_CHECKLIST)
        mock_logger.log_skill_complete.assert_called_once()

    def test_metrics_tracker_called_when_present(self):
        client = _make_api_client()
        mock_metrics = MagicMock()
        client.metrics_tracker = mock_metrics
        with patch.object(client, "_call_claude_api", return_value=MINIMAL_FINDINGS_JSON):
            client.analyze_evidence("iam", {"users": []}, MINIMAL_CHECKLIST)
        mock_metrics.record_token_usage.assert_called_once()

    def test_evidence_with_list_counts_correctly(self):
        """evidence_count is computed from evidence dict values."""
        client = _make_api_client()
        evidence = {"users": [1, 2, 3], "roles": [4, 5]}
        response_json = MINIMAL_FINDINGS_JSON.replace('"evidence_count": 1', '"evidence_count": 5')
        with patch.object(client, "_call_claude_api", return_value=response_json):
            result = client.analyze_evidence("iam", evidence, MINIMAL_CHECKLIST)
        assert result.evidence_count == 5
