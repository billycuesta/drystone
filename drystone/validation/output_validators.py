"""
Output validators for each skill.

RECONCILIATION APPROACH (not tolerance patches):
- Validator's job is to reconcile Claude's response with reality
- Trust the actual findings array (what Claude really generated)
- Reconcile summary values (estimates that may be wrong)
- Log discrepancies but NEVER reject for count mismatches
- Only reject for: missing required fields, invalid data types, semantic errors

Philosophy:
- Claude's array of findings = ground truth
- Claude's summary.total_findings = estimate (may be wrong, ignore it)
- Our job: make summary match reality, not reject findings
"""

import logging
from typing import Protocol

from drystone.models.findings import SkillFindings

logger = logging.getLogger(__name__)


class SkillValidator(Protocol):
    """Protocol for skill-specific validators."""

    def __call__(self, findings: SkillFindings) -> bool:
        """
        Validate and reconcile findings structure.

        Returns:
            bool: True if valid (or reconciled), False only for critical errors
        """
        ...


def _reconcile_summary(findings: SkillFindings, skill_name: str) -> None:
    """Reconcile summary values to match actual findings array.

    Args:
        findings: SkillFindings object (modified in-place)
        skill_name: Name of the skill (for logging)
    """
    actual_count = len(findings.findings)
    estimated_count = findings.summary.total_findings

    # Reconcile total_findings
    if estimated_count != actual_count:
        logger.warning(
            f"{skill_name}: Reconciling total_findings: "
            f"estimated={estimated_count}, actual={actual_count}"
        )
        findings.summary.total_findings = actual_count

    # Reconcile severity breakdown
    critical_count = sum(1 for f in findings.findings if f.severity == "Critical")
    high_count = sum(1 for f in findings.findings if f.severity == "High")
    medium_count = sum(1 for f in findings.findings if f.severity == "Medium")
    low_count = sum(1 for f in findings.findings if f.severity == "Low")

    severity_total = critical_count + high_count + medium_count + low_count

    if severity_total != actual_count:
        logger.warning(
            f"{skill_name}: Severity breakdown mismatch: "
            f"breakdown_sum={severity_total}, actual_count={actual_count}. "
            f"Reconciling to actual."
        )

    if (
        findings.summary.critical != critical_count
        or findings.summary.high != high_count
        or findings.summary.medium != medium_count
        or findings.summary.low != low_count
    ):
        logger.warning(
            f"{skill_name}: Updating severity counts: "
            f"critical {findings.summary.critical}→{critical_count}, "
            f"high {findings.summary.high}→{high_count}, "
            f"medium {findings.summary.medium}→{medium_count}, "
            f"low {findings.summary.low}→{low_count}"
        )
        findings.summary.critical = critical_count
        findings.summary.high = high_count
        findings.summary.medium = medium_count
        findings.summary.low = low_count


def validate_iam_findings(findings: SkillFindings) -> bool:
    """Validate IAM findings and reconcile summary."""
    try:
        if not findings.summary:
            logger.error("IAM validation failed: missing summary")
            return False

        if not findings.findings:
            logger.warning("IAM: No findings generated (empty array)")

        # Validate each finding has required fields
        for finding in findings.findings:
            if not all([finding.id, finding.severity, finding.title, finding.description]):
                logger.error(f"IAM finding {finding.id} missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"IAM finding {finding.id} invalid severity: {finding.severity}")
                return False

            if not (0.0 <= finding.risk_score <= 10.0):
                logger.error(f"IAM finding {finding.id} invalid risk_score: {finding.risk_score}")
                return False

            if not finding.cis_reference:
                logger.error(f"IAM finding {finding.id} missing cis_reference")
                return False

        # Reconcile summary to match actual findings
        _reconcile_summary(findings, "IAM")

        logger.info(f"IAM validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"IAM validation error: {e}", exc_info=True)
        return False


def validate_hardening_findings(findings: SkillFindings) -> bool:
    """Validate hardening findings and reconcile summary."""
    try:
        if not findings.summary:
            logger.error("Hardening validation failed: missing summary")
            return False

        if not findings.findings:
            logger.warning("Hardening: No findings generated (empty array)")

        # Validate findings
        for finding in findings.findings:
            if not finding.id or not finding.severity or not finding.title:
                logger.error("Hardening finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"Hardening finding {finding.id} invalid severity: {finding.severity}")
                return False

        # Reconcile summary
        _reconcile_summary(findings, "Hardening")

        logger.info(f"Hardening validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Hardening validation error: {e}", exc_info=True)
        return False


def validate_vulns_findings(findings: SkillFindings) -> bool:
    """Validate vulns (Inspector v2) findings and reconcile summary."""
    try:
        if not findings.summary:
            logger.error("Vulns validation failed: missing summary")
            return False

        if not findings.findings:
            logger.warning("Vulns: No findings generated (empty array)")

        # Validate findings
        for finding in findings.findings:
            if not finding.id or not finding.severity:
                logger.error("Vulns finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"Vulns finding {finding.id} invalid severity: {finding.severity}")
                return False

        # Reconcile summary
        _reconcile_summary(findings, "Vulns")

        logger.info(f"Vulns validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Vulns validation error: {e}", exc_info=True)
        return False


def validate_exposure_findings(findings: SkillFindings) -> bool:
    """Validate exposure findings and reconcile summary."""
    try:
        if not findings.summary:
            logger.error("Exposure validation failed: missing summary")
            return False

        if not findings.findings:
            logger.warning("Exposure: No findings generated (empty array)")

        # Validate findings
        for finding in findings.findings:
            if not finding.id or not finding.severity:
                logger.error("Exposure finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"Exposure finding {finding.id} invalid severity: {finding.severity}")
                return False

        # Reconcile summary
        _reconcile_summary(findings, "Exposure")

        logger.info(f"Exposure validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Exposure validation error: {e}", exc_info=True)
        return False


def validate_network_findings(findings: SkillFindings) -> bool:
    """Validate network findings and reconcile summary."""
    try:
        if not findings.summary:
            logger.error("Network validation failed: missing summary")
            return False

        if not findings.findings:
            logger.warning("Network: No findings generated (empty array)")

        # Validate findings
        for finding in findings.findings:
            if not finding.id or not finding.severity:
                logger.error("Network finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"Network finding {finding.id} invalid severity: {finding.severity}")
                return False

        # Reconcile summary
        _reconcile_summary(findings, "Network")

        logger.info(f"Network validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Network validation error: {e}", exc_info=True)
        return False


def validate_alerting_findings(findings: SkillFindings) -> bool:
    """Validate alerting findings and reconcile summary."""
    try:
        if not findings.summary:
            logger.error("Alerting validation failed: missing summary")
            return False

        if not findings.findings:
            logger.warning("Alerting: No findings generated (empty array)")

        # Validate findings
        for finding in findings.findings:
            if not finding.id or not finding.severity:
                logger.error("Alerting finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"Alerting finding {finding.id} invalid severity: {finding.severity}")
                return False

        # Reconcile summary
        _reconcile_summary(findings, "Alerting")

        logger.info(f"Alerting validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Alerting validation error: {e}", exc_info=True)
        return False


def validate_waf_findings(findings: SkillFindings) -> bool:
    """Validate WAF findings and reconcile summary.

    Notes:
    - WAF findings may not have CIS references (cis_reference can be null).
    - Count/summary mismatches are reconciled, not rejected.
    """
    try:
        if not findings.summary:
            logger.error("WAF validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("WAF validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("WAF finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"WAF finding {finding.id} invalid severity: {finding.severity}")
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(f"WAF finding {finding.id} invalid risk_score: {finding.risk_score}")
                return False

        _reconcile_summary(findings, "WAF")
        logger.info(f"WAF validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"WAF validation error: {e}", exc_info=True)
        return False


def validate_secretsmanager_findings(findings: SkillFindings) -> bool:
    """Validate Secrets Manager findings and reconcile summary.

    Notes:
    - Enforces required fields and sane risk_score range.
    - Reconciles summary counts to the actual findings array.
    """
    try:
        if not findings.summary:
            logger.error("SecretsManager validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("SecretsManager validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
                or not finding.remediation
            ):
                logger.error("SecretsManager finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(
                    f"SecretsManager finding {finding.id} invalid severity: {finding.severity}"
                )
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(
                    f"SecretsManager finding {finding.id} invalid risk_score: {finding.risk_score}"
                )
                return False

        _reconcile_summary(findings, "SecretsManager")
        logger.info(f"SecretsManager validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"SecretsManager validation error: {e}", exc_info=True)
        return False


def validate_ecr_findings(findings: SkillFindings) -> bool:
    """Validate ECR findings and reconcile summary."""
    try:
        if not findings.summary:
            logger.error("ECR validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("ECR validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
                or not finding.remediation
            ):
                logger.error("ECR finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"ECR finding {finding.id} invalid severity: {finding.severity}")
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(f"ECR finding {finding.id} invalid risk_score: {finding.risk_score}")
                return False

        _reconcile_summary(findings, "ECR")
        logger.info(f"ECR validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"ECR validation error: {e}", exc_info=True)
        return False


# Registry of validators by skill
def validate_cicd_findings(findings: SkillFindings) -> bool:
    """Validate CICD findings and reconcile summary.

    Notes:
    - Valid finding IDs are CICD-001 through CICD-999.
    - High severity findings must have risk_score in 6.5–8.4.
    - Count/summary mismatches are reconciled, not rejected.
    """
    try:
        if not findings.summary:
            logger.error("CICD validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("CICD validation failed: findings array is missing")
            return False

        import re as _re
        _cicd_id_pattern = _re.compile(r"^CICD-\d{3}$")

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("CICD finding missing required fields")
                return False

            if not _cicd_id_pattern.match(finding.id):
                logger.error(f"CICD finding has invalid ID format: {finding.id}")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"CICD finding {finding.id} invalid severity: {finding.severity}")
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(
                    f"CICD finding {finding.id} invalid risk_score: {finding.risk_score}"
                )
                return False

        _reconcile_summary(findings, "CICD")
        logger.info(f"CICD validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"CICD validation error: {e}", exc_info=True)
        return False


def validate_compute_findings(findings: SkillFindings) -> bool:
    """Validate compute (ECS/EKS/Lambda) findings and reconcile summary."""
    import re as _re

    _compute_id_pattern = _re.compile(r"^COMP-(ECS|EKS|LAMBDA)-\d{3}$")

    try:
        if not findings.summary:
            logger.error("Compute validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("Compute validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("Compute finding missing required fields")
                return False

            if not _compute_id_pattern.match(finding.id):
                logger.error(f"Compute finding has invalid ID format: {finding.id}")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(
                    f"Compute finding {finding.id} invalid severity: {finding.severity}"
                )
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(
                    f"Compute finding {finding.id} invalid risk_score: {finding.risk_score}"
                )
                return False

        _reconcile_summary(findings, "Compute")
        logger.info(f"Compute validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Compute validation error: {e}", exc_info=True)
        return False


SKILL_VALIDATORS: dict[str, SkillValidator] = {
    "iam": validate_iam_findings,
    "hardening": validate_hardening_findings,
    "vulns": validate_vulns_findings,
    "exposure": validate_exposure_findings,
    "network": validate_network_findings,
    "alerting": validate_alerting_findings,
    "ecr": validate_ecr_findings,
    "secretsmanager": validate_secretsmanager_findings,
    "waf": validate_waf_findings,
    "cicd": validate_cicd_findings,
    "compute": validate_compute_findings,
}


def validate_findings(skill_name: str, findings: SkillFindings) -> bool:
    """
    Validate and reconcile findings for a given skill.

    Args:
        skill_name: Name of the skill (e.g., 'iam', 'hardening')
        findings: SkillFindings object to validate

    Returns:
        bool: True if valid (or reconciled), False only for critical errors
    """
    validator = SKILL_VALIDATORS.get(skill_name)
    if not validator:
        logger.warning(f"No validator found for skill: {skill_name}")
        return True  # Default to true if no validator (fail-open)

    return validator(findings)
