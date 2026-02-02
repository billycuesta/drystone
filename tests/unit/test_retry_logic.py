"""Unit tests for retry logic and output validation."""

import pytest
from unittest.mock import Mock, patch
from drystone.agent.retry import (
    is_retryable_error,
    get_retry_delay,
    analyze_with_retry
)
from drystone.models.findings import Findings, FindingSummary, Finding


class TestErrorClassification:
    """Test error classification logic."""

    def test_retryable_rate_limit_error(self):
        """Rate limit errors should be retryable."""
        error = Exception("Rate limit exceeded: 429 Too Many Requests")
        assert is_retryable_error(error) is True

    def test_retryable_timeout_error(self):
        """Timeout errors should be retryable."""
        error = Exception("Connection timeout after 30s")
        assert is_retryable_error(error) is True

    def test_retryable_server_error(self):
        """5xx server errors should be retryable."""
        error = Exception("HTTP 503: Service Unavailable")
        assert is_retryable_error(error) is True

    def test_retryable_network_error(self):
        """Network errors should be retryable."""
        error = Exception("Network connection reset")
        assert is_retryable_error(error) is True

    def test_non_retryable_auth_error(self):
        """Authentication errors should NOT be retryable."""
        error = Exception("Authentication failed: invalid API key")
        assert is_retryable_error(error) is False

    def test_non_retryable_permission_error(self):
        """Permission errors should NOT be retryable."""
        error = Exception("Permission denied: forbidden")
        assert is_retryable_error(error) is False

    def test_non_retryable_malformed_error(self):
        """Malformed request errors should NOT be retryable."""
        error = Exception("Invalid request: malformed JSON")
        assert is_retryable_error(error) is False

    def test_unknown_error_conservative_default(self):
        """Unknown errors should NOT retry (conservative)."""
        error = Exception("Some random unknown error")
        assert is_retryable_error(error) is False


class TestRetryDelay:
    """Test retry delay calculation."""

    def test_rate_limit_delay_longer(self):
        """Rate limit errors should get longer delays."""
        error = Exception("Rate limit: 429")
        delay_1 = get_retry_delay(error, attempt=1)
        delay_2 = get_retry_delay(error, attempt=2)
        assert delay_1 == 30  # Base 30s
        assert delay_2 == 40  # +10s per attempt

    def test_rate_limit_delay_capped(self):
        """Rate limit delays should be capped at 120s."""
        error = Exception("Rate limit: 429")
        delay_10 = get_retry_delay(error, attempt=10)
        assert delay_10 == 120  # Max 2min

    def test_exponential_backoff_delay(self):
        """Other retryable errors should use exponential backoff."""
        error = Exception("Connection timeout")
        delay_1 = get_retry_delay(error, attempt=1)  # 2^1 = 2s
        delay_2 = get_retry_delay(error, attempt=2)  # 2^2 = 4s
        delay_3 = get_retry_delay(error, attempt=3)  # 2^3 = 8s

        # Allow 10% jitter
        assert 1.8 <= delay_1 <= 2.2
        assert 3.6 <= delay_2 <= 4.4
        assert 7.2 <= delay_3 <= 8.8

    def test_exponential_backoff_capped(self):
        """Exponential backoff should be capped at 30s."""
        error = Exception("Connection timeout")
        delay_10 = get_retry_delay(error, attempt=10)
        assert delay_10 <= 30  # Max 30s


class TestOutputValidation:
    """Test output validation."""

    def test_valid_iam_findings(self):
        """Valid IAM findings should pass validation."""
        from drystone.validation.output_validators import validate_iam_findings

        summary = FindingSummary(
            total_findings=1,
            critical=1,
            high=0,
            medium=0,
            low=0
        )
        finding = Finding(
            id="IAM-001",
            severity="critical",
            title="Test",
            description="Test finding",
            cis_id="1.5"
        )
        findings = Findings(findings=[finding], summary=summary)

        assert validate_iam_findings(findings) is True

    def test_invalid_findings_missing_summary(self):
        """Findings with missing summary should fail validation."""
        from drystone.validation.output_validators import validate_iam_findings

        findings = Findings(findings=[], summary=None)
        assert validate_iam_findings(findings) is False

    def test_invalid_findings_count_mismatch(self):
        """Findings with count mismatch should fail validation."""
        from drystone.validation.output_validators import validate_iam_findings

        summary = FindingSummary(
            total_findings=5,  # Mismatch!
            critical=1,
            high=0,
            medium=0,
            low=0
        )
        finding = Finding(
            id="IAM-001",
            severity="critical",
            title="Test",
            description="Test finding",
            cis_id="1.5"
        )
        findings = Findings(findings=[finding], summary=summary)

        assert validate_iam_findings(findings) is False

    def test_invalid_findings_missing_cis_id(self):
        """Findings with missing CIS ID should fail validation."""
        from drystone.validation.output_validators import validate_iam_findings

        summary = FindingSummary(
            total_findings=1,
            critical=1,
            high=0,
            medium=0,
            low=0
        )
        finding = Finding(
            id="IAM-001",
            severity="critical",
            title="Test",
            description="Test finding",
            cis_id=None  # Missing CIS ID
        )
        findings = Findings(findings=[finding], summary=summary)

        assert validate_iam_findings(findings) is False

    def test_invalid_findings_invalid_severity(self):
        """Findings with invalid severity should fail validation."""
        from drystone.validation.output_validators import validate_iam_findings

        summary = FindingSummary(
            total_findings=1,
            critical=0,
            high=0,
            medium=0,
            low=0
        )
        finding = Finding(
            id="IAM-001",
            severity="INVALID",  # Invalid severity
            title="Test",
            description="Test finding",
            cis_id="1.5"
        )
        findings = Findings(findings=[finding], summary=summary)

        assert validate_iam_findings(findings) is False


class TestRetryWithBackoff:
    """Test retry_with_backoff decorator."""

    def test_success_on_first_attempt(self):
        """Should return immediately on success."""
        from drystone.agent.retry import retry_with_backoff

        @retry_with_backoff(max_retries=3, skill_name="test")
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"

    def test_retry_on_transient_error(self):
        """Should retry on transient errors."""
        from drystone.agent.retry import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_retries=3, skill_name="test")
        def test_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Connection timeout")
            return "success"

        with patch('time.sleep'):  # Mock sleep to avoid delays
            result = test_func()

        assert result == "success"
        assert call_count == 2

    def test_fail_on_permanent_error(self):
        """Should fail immediately on permanent errors."""
        from drystone.agent.retry import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_retries=3, skill_name="test")
        def test_func():
            nonlocal call_count
            call_count += 1
            raise Exception("Authentication failed: invalid API key")

        with pytest.raises(Exception):
            test_func()

        # Should only try once (no retry for permanent error)
        assert call_count == 1

    def test_max_retries_exhausted(self):
        """Should fail after max retries exhausted."""
        from drystone.agent.retry import retry_with_backoff

        call_count = 0

        @retry_with_backoff(max_retries=2, skill_name="test")
        def test_func():
            nonlocal call_count
            call_count += 1
            raise Exception("Connection timeout")

        with patch('time.sleep'):  # Mock sleep to avoid delays
            with pytest.raises(Exception):
                test_func()

        # Should try max_retries times
        assert call_count == 2
