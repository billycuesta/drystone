"""Tests for agent/retry.py — error classification, delay calculation, retry logic."""

from unittest.mock import MagicMock, patch

import pytest

from drystone.agent.retry import (
    analyze_with_retry,
    get_retry_delay,
    is_retryable_error,
)

# ── is_retryable_error ────────────────────────────────────────────────────────


class TestIsRetryableError:
    def test_network_error_retryable(self):
        assert is_retryable_error(Exception("network failure")) is True

    def test_timeout_retryable(self):
        assert is_retryable_error(Exception("connection timeout")) is True

    def test_rate_limit_retryable(self):
        assert is_retryable_error(Exception("rate limit exceeded")) is True

    def test_429_retryable(self):
        assert is_retryable_error(Exception("status 429 too many requests")) is True

    def test_server_error_500_retryable(self):
        assert is_retryable_error(Exception("500 internal server error")) is True

    def test_service_unavailable_retryable(self):
        assert is_retryable_error(Exception("service unavailable")) is True

    def test_truncated_retryable(self):
        assert is_retryable_error(Exception("response truncated")) is True

    def test_validation_failed_retryable(self):
        assert is_retryable_error(Exception("output validation failed for iam")) is True

    def test_credit_balance_retryable(self):
        assert is_retryable_error(Exception("insufficient credits")) is True

    def test_authentication_not_retryable(self):
        assert is_retryable_error(Exception("authentication failed")) is False

    def test_invalid_api_key_not_retryable(self):
        assert is_retryable_error(Exception("invalid api key")) is False

    def test_401_not_retryable(self):
        assert is_retryable_error(Exception("401 unauthorized")) is False

    def test_forbidden_not_retryable(self):
        assert is_retryable_error(Exception("403 forbidden")) is False

    def test_not_found_not_retryable(self):
        assert is_retryable_error(Exception("file not found")) is False

    def test_malformed_not_retryable(self):
        assert is_retryable_error(Exception("malformed request body")) is False

    def test_unknown_error_not_retryable(self):
        """Conservative default: unknown errors do NOT retry."""
        assert is_retryable_error(Exception("some weird unknown error xyz")) is False

    def test_non_retryable_checked_before_retryable(self):
        """'not found' (non-retryable) wins over 'network' (retryable) in same message."""
        assert is_retryable_error(Exception("not found at network location")) is False

    def test_case_insensitive(self):
        assert is_retryable_error(Exception("RATE LIMIT exceeded")) is True

    def test_empty_message(self):
        assert is_retryable_error(Exception("")) is False


# ── get_retry_delay ────────────────────────────────────────────────────────────


class TestGetRetryDelay:
    def test_rate_limit_base_delay(self):
        delay = get_retry_delay(Exception("rate limit exceeded"), attempt=1)
        assert delay == 40  # 30 + 1*10

    def test_rate_limit_delay_grows_with_attempt(self):
        d1 = get_retry_delay(Exception("rate limit"), attempt=1)
        d2 = get_retry_delay(Exception("rate limit"), attempt=2)
        assert d2 > d1

    def test_rate_limit_delay_capped_at_120(self):
        delay = get_retry_delay(Exception("rate limit"), attempt=100)
        assert delay == 120

    def test_exponential_backoff_attempt_1(self):
        delay = get_retry_delay(Exception("timeout"), attempt=1)
        # base_delay=2, jitter=0.2, total=2.2
        assert 2.0 <= delay <= 3.0

    def test_exponential_backoff_attempt_2(self):
        delay = get_retry_delay(Exception("timeout"), attempt=2)
        # base_delay=4, jitter=0.4, total=4.4
        assert 4.0 <= delay <= 5.0

    def test_exponential_backoff_capped_at_30(self):
        delay = get_retry_delay(Exception("network error"), attempt=10)
        assert delay == 30.0

    def test_429_uses_rate_limit_delay(self):
        delay = get_retry_delay(Exception("429 error"), attempt=1)
        assert delay == 40  # rate limit path


# ── analyze_with_retry ────────────────────────────────────────────────────────


class TestAnalyzeWithRetry:
    def _make_valid_findings(self, skill="iam"):
        from drystone.models.findings import FindingsSummary, SkillFindings

        return SkillFindings(
            skill=skill,
            findings=[],
            summary=FindingsSummary(
                total_findings=0,
                overall_risk_score=0.0,
            ),
            evidence_count=0,
        )

    def test_succeeds_on_first_call(self):
        findings = self._make_valid_findings()
        func = MagicMock(return_value=findings)

        result = analyze_with_retry(func, skill_name="iam", max_retries=3)

        assert result is findings
        func.assert_called_once()

    def test_retries_on_retryable_error(self):
        findings = self._make_valid_findings()
        call_count = 0

        def func(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("timeout")
            return findings

        with patch("drystone.agent.retry.time.sleep"):
            result = analyze_with_retry(func, skill_name="iam", max_retries=3)

        assert result is findings
        assert call_count == 2

    def test_non_retryable_error_propagates(self):
        def func(**kwargs):
            raise Exception("authentication failed")

        with pytest.raises(Exception, match="authentication"):
            analyze_with_retry(func, skill_name="iam", max_retries=3)

    def test_kwargs_passed_to_func(self):
        findings = self._make_valid_findings()
        func = MagicMock(return_value=findings)

        analyze_with_retry(func, skill_name="iam", max_retries=1, key="value")

        func.assert_called_once_with(key="value")
