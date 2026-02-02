# Plan de Implementación: Mejoras de Shannon para Drystone

**Fecha:** 2026-02-02
**Versión:** 1.0
**Estado:** 📋 LISTO PARA IMPLEMENTACIÓN

---

## Resumen Ejecutivo

Plan de 15 horas para adoptar estrategias de confiabilidad de Shannon (pentesting autónomo) a Drystone (AWS security audit) SIN requerir Temporal.

**Resultado esperado:**
- ✅ Resilencia a rate limits/network errors (+90%)
- ✅ Detección automática de output inválido (+100%)
- ✅ Prompts estructurados (menos variabilidad)
- ✅ Logs crash-safe (reproducibilidad)

**Commits esperados:** 5-7 commits principales

---

## Phase 1: Output Validation + Error Classification + Retry (5 horas)

**Prioridad:** 🔴 CRÍTICO
**Timeline:** Semana 1 (lunes-martes)

### 1.1: Create Validation System (2 horas)

**Archivo:** `drystone/validation/output_validators.py` (NEW)

```python
"""
Output validators for each skill.

Each validator is a deterministic function that checks if agent output is valid.
Validators are called AFTER agent analysis to detect:
- Missing required fields
- Invalid JSON structure
- Semantic errors (e.g., total_findings != len(findings))
- Domain-specific errors (e.g., missing CIS control ID)

Pattern from Shannon: Agent-specific validators in constants.ts
"""

from typing import Protocol, Callable
from dataclasses import dataclass
from drystone.models.findings import Findings
import logging

logger = logging.getLogger(__name__)


class SkillValidator(Protocol):
    """Protocol for skill-specific validators."""
    def __call__(self, findings: Findings) -> bool:
        """
        Validate findings structure and content.

        Returns:
            bool: True if valid, False otherwise (triggers retry)
        """
        ...


def validate_iam_findings(findings: Findings) -> bool:
    """Validate IAM findings structure and content."""
    try:
        # Check summary exists
        if not findings.summary:
            logger.error("IAM validation failed: missing summary")
            return False

        # Check count consistency
        if findings.summary.total_findings != len(findings.findings):
            logger.error(
                f"IAM validation failed: summary.total_findings ({findings.summary.total_findings}) "
                f"!= len(findings) ({len(findings.findings)})"
            )
            return False

        # Check all findings have required fields
        for finding in findings.findings:
            if not all([finding.id, finding.severity, finding.title, finding.description]):
                logger.error(f"IAM finding {finding.id} missing required fields")
                return False

            # Check severity is valid
            if finding.severity not in ['critical', 'high', 'medium', 'low']:
                logger.error(f"IAM finding {finding.id} has invalid severity: {finding.severity}")
                return False

            # Check CIS reference exists
            if not finding.cis_id:
                logger.error(f"IAM finding {finding.id} missing cis_id")
                return False

        logger.info(f"IAM validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"IAM validation error: {e}", exc_info=True)
        return False


def validate_hardening_findings(findings: Findings) -> bool:
    """Validate hardening findings structure."""
    try:
        if not findings.summary:
            logger.error("Hardening validation failed: missing summary")
            return False

        if findings.summary.total_findings != len(findings.findings):
            logger.error("Hardening validation failed: count mismatch")
            return False

        # Hardening should have security-specific checks
        # At minimum, check for Security Hub enabled checks
        required_check_patterns = ['HRD-001', 'HRD-002', 'HRD-003']
        found_ids = {f.id for f in findings.findings}
        has_required_checks = any(pattern in found_ids for pattern in required_check_patterns)

        if not has_required_checks:
            logger.warning(
                f"Hardening validation: missing core checks. Found: {found_ids}"
            )

        logger.info(f"Hardening validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Hardening validation error: {e}", exc_info=True)
        return False


def validate_vulns_findings(findings: Findings) -> bool:
    """Validate vulns (Inspector v2) findings."""
    try:
        if not findings.summary:
            logger.error("Vulns validation failed: missing summary")
            return False

        if findings.summary.total_findings != len(findings.findings):
            logger.error("Vulns validation failed: count mismatch")
            return False

        # Vulns should have severity breakdown
        if (findings.summary.critical + findings.summary.high +
            findings.summary.medium + findings.summary.low) != findings.summary.total_findings:
            logger.error("Vulns validation failed: severity counts don't sum to total")
            return False

        logger.info(f"Vulns validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Vulns validation error: {e}", exc_info=True)
        return False


def validate_exposure_findings(findings: Findings) -> bool:
    """Validate exposure findings."""
    try:
        if not findings.summary:
            logger.error("Exposure validation failed: missing summary")
            return False

        if findings.summary.total_findings != len(findings.findings):
            logger.error("Exposure validation failed: count mismatch")
            return False

        logger.info(f"Exposure validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Exposure validation error: {e}", exc_info=True)
        return False


def validate_network_findings(findings: Findings) -> bool:
    """Validate network findings."""
    try:
        if not findings.summary:
            logger.error("Network validation failed: missing summary")
            return False

        if findings.summary.total_findings != len(findings.findings):
            logger.error("Network validation failed: count mismatch")
            return False

        logger.info(f"Network validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Network validation error: {e}", exc_info=True)
        return False


def validate_alerting_findings(findings: Findings) -> bool:
    """Validate alerting findings."""
    try:
        if not findings.summary:
            logger.error("Alerting validation failed: missing summary")
            return False

        if findings.summary.total_findings != len(findings.findings):
            logger.error("Alerting validation failed: count mismatch")
            return False

        logger.info(f"Alerting validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Alerting validation error: {e}", exc_info=True)
        return False


# Registry of validators by skill
SKILL_VALIDATORS: dict[str, SkillValidator] = {
    'iam': validate_iam_findings,
    'hardening': validate_hardening_findings,
    'vulns': validate_vulns_findings,
    'exposure': validate_exposure_findings,
    'network': validate_network_findings,
    'alerting': validate_alerting_findings,
}


def validate_findings(skill_name: str, findings: Findings) -> bool:
    """
    Validate findings for a given skill.

    Args:
        skill_name: Name of the skill (e.g., 'iam', 'hardening')
        findings: Findings object to validate

    Returns:
        bool: True if valid, False otherwise
    """
    validator = SKILL_VALIDATORS.get(skill_name)
    if not validator:
        logger.warning(f"No validator found for skill: {skill_name}")
        return True  # Default to true if no validator (fail-open)

    return validator(findings)
```

### 1.2: Create Retry System (2 horas)

**Archivo:** `drystone/agent/retry.py` (NEW)

```python
"""
Retry logic for agent analysis with exponential backoff.

Pattern from Shannon:
- Classify errors as retryable vs. permanent
- Rate limits get longer delays (30s base)
- Other retryable errors get exponential backoff (2s, 4s, 8s)
- Unknown errors do NOT retry (conservative fail-safe)

Inspiration: src/error-handling.ts (lines 132-198)
"""

import time
import logging
from typing import Callable, TypeVar, Optional
from functools import wraps
from drystone.validation.output_validators import validate_findings
from drystone.models.findings import Findings

logger = logging.getLogger(__name__)

T = TypeVar('T')

# Patterns that indicate RETRYABLE errors (transient/temporary)
RETRYABLE_ERROR_PATTERNS = [
    # Network and connection errors
    'network', 'connection', 'timeout', 'connection reset',
    'connection refused', 'connection timeout',
    # Rate limiting
    'rate limit', '429', 'too many requests', 'rate_limit_error',
    # Server errors (5xx)
    'server error', '5xx', '500', '502', '503', '504',
    'internal server error', 'service unavailable', 'bad gateway',
    'temporarily unavailable', 'overloaded',
    # Claude API specific
    'mcp server', 'model unavailable', 'api error',
    'service temporarily unavailable', 'terminated',
    # Billing (retryable - wait for credits)
    'billing_error', 'credit balance', 'insufficient credits',
    'usage limit reached', 'quota exceeded',
    # Output validation (retryable - agent can fix)
    'output validation failed', 'validation failed',
]

# Patterns that indicate NON-RETRYABLE errors (permanent)
NON_RETRYABLE_ERROR_PATTERNS = [
    # Authentication (bad API key won't fix itself)
    'authentication', 'invalid api key', 'invalid_api_key', '401',
    'authentication_error', 'unauthorized',
    # Permission (access won't be granted)
    'permission denied', 'forbidden', '403', 'permission_error',
    # Bad request (malformed won't fix itself)
    'invalid request', 'malformed', 'invalid_request', '400',
    # Invalid target URL
    'invalid url', 'invalid target', 'malformed url',
    # Execution limits
    'max turns', 'maximum turns', 'execution limit',
    # Configuration (missing files need manual fix)
    'enoent', 'no such file', 'cli not installed', 'not found',
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
    if 'rate limit' in message or '429' in message:
        delay = min(30 + attempt * 10, 120)  # 30s, 40s, 50s, max 2min
        logger.info(f"Rate limit detected: retrying in {delay}s")
        return delay

    # Exponential backoff with jitter for other retryable errors
    base_delay = 2 ** attempt  # 2s, 4s, 8s, 16s...
    jitter = base_delay * 0.1  # 10% jitter
    delay = min(base_delay + jitter, 30)  # Max 30s

    logger.info(f"Exponential backoff: retrying in {delay:.1f}s (attempt {attempt})")
    return delay


def retry_with_backoff(
    max_retries: int = 3,
    skill_name: str = "unknown",
    validator: Optional[Callable[[Findings], bool]] = None
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
                                raise ValueError(
                                    f"Validation failed after {max_retries} attempts"
                                )

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
                            f"[{skill_name}] Failed after {max_retries} attempts. "
                            f"Last error: {e}"
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
    analyze_func: Callable[..., Findings],
    skill_name: str,
    max_retries: int = 3,
    **kwargs
) -> Findings:
    """
    Execute analyze function with retry logic.

    Args:
        analyze_func: Function to call (should return Findings)
        skill_name: Name of skill being analyzed
        max_retries: Maximum retry attempts
        **kwargs: Arguments to pass to analyze_func

    Returns:
        Findings: Analysis results

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
                        f"[{skill_name}] Validation failed, "
                        f"retry {attempt}/{max_retries}"
                    )
                    continue
                else:
                    raise ValueError(
                        f"Validation failed after {max_retries} attempts"
                    )

            logger.info(f"[{skill_name}] Analysis succeeded on attempt {attempt}")
            return findings

        except Exception as e:
            if not is_retryable_error(e):
                logger.error(f"[{skill_name}] Non-retryable error: {e}")
                raise

            if attempt >= max_retries:
                logger.error(
                    f"[{skill_name}] Failed after {max_retries} attempts. "
                    f"Last error: {e}"
                )
                raise

            delay = get_retry_delay(e, attempt)
            logger.warning(
                f"[{skill_name}] Retrying in {delay:.1f}s "
                f"(attempt {attempt}/{max_retries}). "
                f"Error: {e}"
            )
            time.sleep(delay)

    raise Exception(f"[{skill_name}] Unreachable state")
```

### 1.3: Integrate with Agent Client (1 hora)

**Archivo:** `drystone/agent/client.py` (MODIFY)

Buscar la función `analyze_evidence_chunked` y modificar:

```python
# At top of file, add imports:
from drystone.validation.output_validators import validate_findings
from drystone.agent.retry import analyze_with_retry, is_retryable_error, get_retry_delay

# Modify analyze_evidence_chunked method:
def analyze_evidence_chunked(
    self,
    skill_name: str,
    evidence: dict,
    checklist: dict
) -> Findings:
    """Analyze evidence with validation and retry logic."""

    # ... existing code (build prompt, call Claude) ...

    findings = self._normalize_findings(findings, checklist)

    # NEW: Validate output
    if not validate_findings(skill_name, findings):
        raise ValueError(f"Output validation failed for {skill_name}")

    return findings
```

Luego, en `drystone/cloud/orchestrator.py` (o donde se llama a analyze_evidence_chunked):

```python
# Use retry wrapper:
from drystone.agent.retry import analyze_with_retry

findings = analyze_with_retry(
    analyze_func=agent_client.analyze_evidence_chunked,
    skill_name=skill_name,
    max_retries=3,
    evidence=evidence,
    checklist=checklist
)
```

---

### 1.4: Test Implementation (30 min)

**Archivo:** `tests/unit/test_retry_logic.py` (NEW)

```python
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

    def test_non_retryable_auth_error(self):
        """Authentication errors should NOT be retryable."""
        error = Exception("Authentication failed: invalid API key")
        assert is_retryable_error(error) is False

    def test_non_retryable_permission_error(self):
        """Permission errors should NOT be retryable."""
        error = Exception("Permission denied: forbidden")
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

    def test_exponential_backoff_delay(self):
        """Other retryable errors should use exponential backoff."""
        error = Exception("Connection timeout")
        delay_1 = get_retry_delay(error, attempt=1)  # 2^1 = 2s
        delay_2 = get_retry_delay(error, attempt=2)  # 2^2 = 4s
        assert 2 <= delay_1 <= 3  # 2s ± jitter
        assert 4 <= delay_2 <= 5  # 4s ± jitter


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
```

**Ejecutar tests:**
```bash
cd /Users/gcuesta/Projects/drystone
pytest tests/unit/test_retry_logic.py -v
```

---

### 1.5: Commit Phase 1

```bash
git add -A
git commit -m "feat: add output validation + error classification + retry logic

- Add drystone/validation/output_validators.py with skill-specific validators
- Add drystone/agent/retry.py with error classification and retry with backoff
- Integrate retry logic into agent client (analyze_evidence_chunked)
- Add unit tests for retry logic and validation
- Pattern from Shannon: deterministic post-agent validation + multi-level retry
- Expected impact: +90% resilience to rate limits and network errors

Inspired by: Shannon src/constants.ts, src/error-handling.ts, src/queue-validation.ts"