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
from drystone.models.findings import SkillFindings
import logging

logger = logging.getLogger(__name__)


class SkillValidator(Protocol):
    """Protocol for skill-specific validators."""
    def __call__(self, findings: SkillFindings) -> bool:
        """
        Validate findings structure and content.

        Returns:
            bool: True if valid, False otherwise (triggers retry)
        """
        ...


def validate_iam_findings(findings: SkillFindings) -> bool:
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

        # Check severity breakdown consistency
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }

        # Check all findings have required fields
        for finding in findings.findings:
            if not all([finding.id, finding.severity, finding.title, finding.description]):
                logger.error(f"IAM finding {finding.id} missing required fields")
                return False

            # Check severity is valid (capitalized: Critical, High, Medium, Low)
            if finding.severity not in ['Critical', 'High', 'Medium', 'Low']:
                logger.error(f"IAM finding {finding.id} has invalid severity: {finding.severity}")
                return False

            # Check risk_score is valid
            if not (0.0 <= finding.risk_score <= 10.0):
                logger.error(f"IAM finding {finding.id} has invalid risk_score: {finding.risk_score}")
                return False

            # Check CIS reference exists
            if not finding.cis_reference:
                logger.error(f"IAM finding {finding.id} missing cis_reference")
                return False

            # Count severity
            severity_counts[finding.severity] += 1

        # Verify severity breakdown matches summary
        if (severity_counts['Critical'] != findings.summary.critical or
            severity_counts['High'] != findings.summary.high or
            severity_counts['Medium'] != findings.summary.medium or
            severity_counts['Low'] != findings.summary.low):
            logger.error(
                f"IAM validation failed: severity counts mismatch. "
                f"Found: {severity_counts}, Summary: "
                f"critical={findings.summary.critical}, high={findings.summary.high}, "
                f"medium={findings.summary.medium}, low={findings.summary.low}"
            )
            return False

        logger.info(f"IAM validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"IAM validation error: {e}", exc_info=True)
        return False


def validate_hardening_findings(findings: SkillFindings) -> bool:
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


def validate_vulns_findings(findings: SkillFindings) -> bool:
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


def validate_exposure_findings(findings: SkillFindings) -> bool:
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


def validate_network_findings(findings: SkillFindings) -> bool:
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


def validate_alerting_findings(findings: SkillFindings) -> bool:
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


def validate_findings(skill_name: str, findings: SkillFindings) -> bool:
    """
    Validate findings for a given skill.

    Args:
        skill_name: Name of the skill (e.g., 'iam', 'hardening')
        findings: SkillFindings object to validate

    Returns:
        bool: True if valid, False otherwise
    """
    validator = SKILL_VALIDATORS.get(skill_name)
    if not validator:
        logger.warning(f"No validator found for skill: {skill_name}")
        return True  # Default to true if no validator (fail-open)

    return validator(findings)
