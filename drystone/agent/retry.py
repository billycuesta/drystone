"""
Retry logic for agent analysis with exponential backoff.

Pattern from Shannon:
- Classify errors as retryable vs. permanent
- Rate limits get longer delays (30s base)
- Other retryable errors get exponential backoff (2s, 4s, 8s)
- Unknown errors do NOT retry (conservative fail-safe)

Inspiration: src/error-handling.ts (lines 132-198)
"""

import logging
import time
from functools import wraps
from typing import Callable, Optional, TypeVar

from drystone.models.findings import SkillFindings
from drystone.validation.output_validators import validate_findings

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Patterns that indicate RETRYABLE errors (transient/temporary)
RETRYABLE_ERROR_PATTERNS = [
    # Network and connection errors
    "network",
    "connection",
    "timeout",
    "connection reset",
    "connection refused",
    "connection timeout",
    # Rate limiting
    "rate limit",
    "429",
    "too many requests",
    "rate_limit_error",
    # Server errors (5xx)
    "server error",
    "5xx",
    "500",
    "502",
    "503",
    "504",
    "internal server error",
    "service unavailable",
    "bad gateway",
    "temporarily unavailable",
    "overloaded",
    # Gemini API specific
    "mcp server",
    "model unavailable",
    "api error",
    "service temporarily unavailable",
    "terminated",
    # Billing (retryable - wait for credits)
    "billing_error",
    "credit balance",
    "insufficient credits",
    "usage limit reached",
    "quota exceeded",
    # Output validation (retryable - agent can fix)
    "output validation failed",
    "validation failed",
    # Truncation / partial output (common with CLI / long responses)
    "truncated",
    "doesn't end with",
    "unterminated string",
]

# Patterns that indicate NON-RETRYABLE errors (permanent)
NON_RETRYABLE_ERROR_PATTERNS = [
    # Authentication (bad API key won't fix itself)
    "authentication",
    "invalid api key",
    "invalid_api_key",
    "401",
    "authentication_error",
    "unauthorized",
    # Permission (access won't be granted)
    "permission denied",
    "forbidden",
    "403",
    "permission_error",
    # Bad request (malformed won't fix itself)
    "invalid request",
    "malformed",
    "invalid_request",
    "400",
    # Invalid target URL
    "invalid url",
    "invalid target",
    "malformed url",
    # Execution limits
    "max turns",
    "maximum turns",
    "execution limit",
    # Configuration (missing files need manual fix)
    "enoent",
    "no such file",
    "cli not installed",
    "not found",
]


def is_retryable_error(error: Exception) -> bool:
    """
    Classify error as retryable or permanent.

    Conservative approach: Unknown errors do NOT retry.
    Non-retryable patterns are checked FIRST to avoid false positives.

    Args:
        error: Exception to classify

    Returns:
        bool: True if retryable, False if permanent
    """
    message = str(error).lower()

    # Check for explicit non-retryable patterns FIRST
    for pattern in NON_RETRYABLE_ERROR_PATTERNS:
        if pattern in message:
            logger.debug(f"Non-retryable error detected: pattern '{pattern}' in '{message}'")
            return False

    # Check for retryable patterns
    for pattern in RETRYABLE_ERROR_PATTERNS:
        if pattern in message:
            logger.debug(f"Retryable error detected: pattern '{pattern}' in '{message}'")
            return True

    # Unknown errors: conservative default = do NOT retry
    logger.debug(f"Unknown error: conservative default = non-retryable. Error: '{message}'")
    return False


def get_retry_delay(error: Exception, attempt: int) -> float:
    """
    Calculate retry delay based on error type and attempt number.

    Rate limits get longer delays (30s base) to avoid overwhelming API.
    Other retryable errors use exponential backoff: 2s, 4s, 8s, etc.
    Jitter prevents thundering herd when many clients retry simultaneously.

    Args:
        error: Exception being retried
        attempt: Current attempt number (1-indexed)

    Returns:
        float: Delay in seconds
    """
    message = str(error).lower()

    # Rate limiting gets longer base delay
    if "rate limit" in message or "429" in message:
        delay = min(30 + attempt * 10, 120)  # 30s, 40s, 50s, max 2min
        logger.info(f"Rate limit detected: retrying in {delay}s")
        return delay

    # Exponential backoff with jitter for other retryable errors
    base_delay = 2**attempt  # 2s, 4s, 8s, 16s...
    jitter = base_delay * 0.1  # 10% jitter
    delay = min(base_delay + jitter, 30)  # Max 30s

    logger.info(f"Exponential backoff: retrying in {delay:.1f}s (attempt {attempt})")
    return delay


def retry_with_backoff(
    max_retries: int = 3,
    skill_name: str = "unknown",
    validator: Optional[Callable[[T], bool]] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for retry with exponential backoff.

    Retries agent analysis on transient errors or validation failures.
    Non-retryable errors fail immediately.

    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        skill_name: Name of skill being analyzed (for logging)
        validator: Optional validation function (called after agent returns)

    Returns:
        Callable: Decorated function with retry logic
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            for attempt in range(1, max_retries + 1):
                try:
                    # Execute agent
                    result = func(*args, **kwargs)

                    # Validate output (if validator provided)
                    if validator and result:
                        if not validator(result):
                            if attempt < max_retries:
                                logger.warning(
                                    f"[{skill_name}] Validation failed, "
                                    f"retry {attempt}/{max_retries}"
                                )
                                continue
                            else:
                                raise ValueError(f"Validation failed after {max_retries} attempts")

                    # SUCCESS: Return result
                    logger.info(f"[{skill_name}] Analysis succeeded on attempt {attempt}")
                    return result

                except Exception as e:
                    # Classify error
                    if not is_retryable_error(e):
                        logger.error(f"[{skill_name}] Non-retryable error: {e}")
                        raise

                    # Check if max retries exhausted
                    if attempt >= max_retries:
                        logger.error(
                            f"[{skill_name}] Failed after {max_retries} attempts. Last error: {e}"
                        )
                        raise

                    # Calculate delay and retry
                    delay = get_retry_delay(e, attempt)
                    logger.warning(
                        f"[{skill_name}] Retrying in {delay:.1f}s "
                        f"(attempt {attempt}/{max_retries}). "
                        f"Error: {e}"
                    )
                    time.sleep(delay)

            # Unreachable (loop exhausted)
            raise Exception(f"[{skill_name}] Unreachable state after {max_retries} attempts")

        return wrapper

    return decorator


# Alternative: Non-decorator retry function (for when decorator not suitable)
def analyze_with_retry(
    analyze_func: Callable[..., SkillFindings], skill_name: str, max_retries: int = 3, **kwargs
) -> SkillFindings:
    """
    Execute analyze function with retry logic.

    Args:
        analyze_func: Function to call (should return SkillFindings)
        skill_name: Name of skill being analyzed
        max_retries: Maximum retry attempts
        **kwargs: Arguments to pass to analyze_func

    Returns:
        SkillFindings: Analysis results

    Raises:
        Exception: If fails after max_retries attempts
    """
    validator = validate_findings

    for attempt in range(1, max_retries + 1):
        try:
            findings = analyze_func(**kwargs)

            # Validate findings
            if not validator(skill_name, findings):
                if attempt < max_retries:
                    logger.warning(
                        f"[{skill_name}] Validation failed, retry {attempt}/{max_retries}"
                    )
                    continue
                else:
                    raise ValueError(f"Validation failed after {max_retries} attempts")

            logger.info(f"[{skill_name}] Analysis succeeded on attempt {attempt}")
            return findings

        except Exception as e:
            if not is_retryable_error(e):
                logger.error(f"[{skill_name}] Non-retryable error: {e}")
                raise

            if attempt >= max_retries:
                logger.error(f"[{skill_name}] Failed after {max_retries} attempts. Last error: {e}")
                raise

            delay = get_retry_delay(e, attempt)
            logger.warning(
                f"[{skill_name}] Retrying in {delay:.1f}s "
                f"(attempt {attempt}/{max_retries}). "
                f"Error: {e}"
            )
            time.sleep(delay)

    raise Exception(f"[{skill_name}] Unreachable state")
