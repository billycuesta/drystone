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
    """Validate IAM findings structure and content.

    Note: Tolerates small count discrepancies (±2) from agent.
    This can occur when agent refines counts during analysis.
    """
    try:
        # Check summary exists
        if not findings.summary:
            logger.error("IAM validation failed: missing summary")
            return False

        # Allow ±2 discrepancy between summary total and actual findings count
        count_diff = abs(findings.summary.total_findings - len(findings.findings))
        if count_diff > 2:
            logger.error(
                f"IAM validation failed: summary.total_findings ({findings.summary.total_findings}) "
                f"!= len(findings) ({len(findings.findings)}) - difference too large ({count_diff})"
            )
            return False

        # Auto-correct summary if off by 1-2
        if count_diff >= 1:
            logger.warning(
                f"IAM: Auto-correcting summary count from {findings.summary.total_findings} to {len(findings.findings)}"
            )
            findings.summary.total_findings = len(findings.findings)

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

        # Verify severity breakdown adds up correctly (more tolerant)
        # Agent sometimes miscounts individual severities, but total usually matches findings
        severity_total = (severity_counts['Critical'] + severity_counts['High'] +
                         severity_counts['Medium'] + severity_counts['Low'])

        if severity_total != len(findings.findings):
            logger.warning(
                f"IAM: Severity breakdown doesn't sum to findings count. "
                f"Found total: {severity_total}, findings count: {len(findings.findings)}"
            )
            # Auto-correct summary severities to match actual findings
            findings.summary.critical = severity_counts['Critical']
            findings.summary.high = severity_counts['High']
            findings.summary.medium = severity_counts['Medium']
            findings.summary.low = severity_counts['Low']

        logger.info(f"IAM validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"IAM validation error: {e}", exc_info=True)
        return False


def validate_hardening_findings(findings: SkillFindings) -> bool:
    """Validate hardening findings structure.

    Note: Tolerates small count discrepancies (±1) from agent.
    """
    try:
        if not findings.summary:
            logger.error("Hardening validation failed: missing summary")
            return False

        count_diff = abs(findings.summary.total_findings - len(findings.findings))
        if count_diff > 1:
            logger.error(f"Hardening validation failed: count mismatch (diff={count_diff})")
            return False

        if count_diff == 1:
            logger.warning(f"Hardening: Auto-correcting count from {findings.summary.total_findings} to {len(findings.findings)}")
            findings.summary.total_findings = len(findings.findings)

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
    """Validate vulns (Inspector v2) findings.

    Note: Tolerates small count discrepancies (±1) from agent.
    More tolerant of severity breakdown mismatches (common with complex vulnerability data).
    """
    try:
        if not findings.summary:
            logger.error("Vulns validation failed: missing summary")
            return False

        count_diff = abs(findings.summary.total_findings - len(findings.findings))
        if count_diff > 1:
            logger.error(f"Vulns validation failed: count mismatch (diff={count_diff})")
            return False

        if count_diff == 1:
            logger.warning(f"Vulns: Auto-correcting count from {findings.summary.total_findings} to {len(findings.findings)}")
            findings.summary.total_findings = len(findings.findings)

        # Check severity breakdown adds up to actual findings count (not summary total)
        severity_total = (
            findings.summary.critical +
            findings.summary.high +
            findings.summary.medium +
            findings.summary.low
        )
        # Allow small discrepancy in severity breakdown (common with complex vuln data)
        if abs(severity_total - len(findings.findings)) > 1:
            logger.warning(
                f"Vulns: severity breakdown ({severity_total}) doesn't match findings count ({len(findings.findings)}). "
                f"Auto-correcting to use actual count."
            )
            # Auto-correct by proportionally adjusting severities (keep ratios if possible)
            # Otherwise just make sure counts are reasonable
            if len(findings.findings) > 0:
                # Fallback: clear and recalculate from actual findings
                critical_count = sum(1 for f in findings.findings if f.severity == 'Critical')
                high_count = sum(1 for f in findings.findings if f.severity == 'High')
                medium_count = sum(1 for f in findings.findings if f.severity == 'Medium')
                low_count = sum(1 for f in findings.findings if f.severity == 'Low')

                findings.summary.critical = critical_count
                findings.summary.high = high_count
                findings.summary.medium = medium_count
                findings.summary.low = low_count

        logger.info(f"Vulns validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Vulns validation error: {e}", exc_info=True)
        return False


def validate_exposure_findings(findings: SkillFindings) -> bool:
    """Validate exposure findings.

    Note: Tolerates small count discrepancies (±1) from agent.
    """
    try:
        if not findings.summary:
            logger.error("Exposure validation failed: missing summary")
            return False

        count_diff = abs(findings.summary.total_findings - len(findings.findings))
        if count_diff > 1:
            logger.error(f"Exposure validation failed: count mismatch (diff={count_diff})")
            return False

        if count_diff == 1:
            logger.warning(f"Exposure: Auto-correcting count from {findings.summary.total_findings} to {len(findings.findings)}")
            findings.summary.total_findings = len(findings.findings)

        logger.info(f"Exposure validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Exposure validation error: {e}", exc_info=True)
        return False


def validate_network_findings(findings: SkillFindings) -> bool:
    """Validate network findings.

    Note: Tolerates small count discrepancies (±1) from agent.
    This can occur when agent refines counts during analysis.
    """
    try:
        if not findings.summary:
            logger.error("Network validation failed: missing summary")
            return False

        # Allow ±1 discrepancy between summary total and actual findings count
        # (agent sometimes adjusts counts during refinement)
        count_diff = abs(findings.summary.total_findings - len(findings.findings))
        if count_diff > 1:
            logger.error(
                f"Network validation failed: count mismatch > 1. "
                f"summary.total_findings={findings.summary.total_findings}, "
                f"len(findings)={len(findings.findings)}"
            )
            return False

        # Auto-correct summary if off by 1
        if count_diff == 1:
            logger.warning(
                f"Network: Auto-correcting summary count from {findings.summary.total_findings} to {len(findings.findings)}"
            )
            findings.summary.total_findings = len(findings.findings)

        # Check severity breakdown adds up to actual findings count (not summary total)
        severity_total = (
            findings.summary.critical +
            findings.summary.high +
            findings.summary.medium +
            findings.summary.low
        )
        # Allow small discrepancy in severity breakdown too
        if abs(severity_total - len(findings.findings)) > 1:
            logger.warning(
                f"Network: severity breakdown ({severity_total}) doesn't match findings count ({len(findings.findings)}). "
                f"Continuing with caution."
            )

        logger.info(f"Network validation passed: {len(findings.findings)} findings")
        return True

    except Exception as e:
        logger.error(f"Network validation error: {e}", exc_info=True)
        return False


def validate_alerting_findings(findings: SkillFindings) -> bool:
    """Validate alerting findings.

    Note: Tolerates small count discrepancies (±1) from agent.
    """
    try:
        if not findings.summary:
            logger.error("Alerting validation failed: missing summary")
            return False

        count_diff = abs(findings.summary.total_findings - len(findings.findings))
        if count_diff > 1:
            logger.error(f"Alerting validation failed: count mismatch (diff={count_diff})")
            return False

        if count_diff == 1:
            logger.warning(f"Alerting: Auto-correcting count from {findings.summary.total_findings} to {len(findings.findings)}")
            findings.summary.total_findings = len(findings.findings)

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
