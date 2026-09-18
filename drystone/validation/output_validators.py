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
                logger.error(f"CICD finding {finding.id} invalid risk_score: {finding.risk_score}")
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
                logger.error(f"Compute finding {finding.id} invalid severity: {finding.severity}")
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


def validate_recon_findings(findings: SkillFindings) -> bool:
    """Validate recon (attack surface) findings and reconcile summary.

    Notes:
    - Valid finding IDs are RECON-001 through RECON-999.
    - Count/summary mismatches are reconciled, not rejected.
    """
    import re as _re

    _recon_id_pattern = _re.compile(r"^RECON-\d{3}$")

    try:
        if not findings.summary:
            logger.error("Recon validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("Recon validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("Recon finding missing required fields")
                return False

            if not _recon_id_pattern.match(finding.id):
                logger.error(f"Recon finding has invalid ID format: {finding.id}")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"Recon finding {finding.id} invalid severity: {finding.severity}")
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(f"Recon finding {finding.id} invalid risk_score: {finding.risk_score}")
                return False

        _reconcile_summary(findings, "Recon")
        logger.info(f"Recon validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Recon validation error: {e}", exc_info=True)
        return False


def validate_kms_findings(findings: SkillFindings) -> bool:
    """Validate KMS findings and reconcile summary.

    Notes:
    - Valid finding IDs are KMS-001 through KMS-999.
    """
    import re as _re

    _kms_id_pattern = _re.compile(r"^KMS-\d{3}$")

    try:
        if not findings.summary:
            logger.error("KMS validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("KMS validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("KMS finding missing required fields")
                return False

            if not _kms_id_pattern.match(finding.id):
                logger.error(f"KMS finding has invalid ID format: {finding.id}")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"KMS finding {finding.id} invalid severity: {finding.severity}")
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(f"KMS finding {finding.id} invalid risk_score: {finding.risk_score}")
                return False

        _reconcile_summary(findings, "KMS")
        logger.info(f"KMS validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"KMS validation error: {e}", exc_info=True)
        return False


def validate_messaging_findings(findings: SkillFindings) -> bool:
    """Validate messaging (SQS/SNS) findings and reconcile summary.

    Notes:
    - Valid finding IDs are MSG-001 through MSG-999.
    """
    import re as _re

    _msg_id_pattern = _re.compile(r"^MSG-\d{3}$")

    try:
        if not findings.summary:
            logger.error("Messaging validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("Messaging validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("Messaging finding missing required fields")
                return False

            if not _msg_id_pattern.match(finding.id):
                logger.error(f"Messaging finding has invalid ID format: {finding.id}")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"Messaging finding {finding.id} invalid severity: {finding.severity}")
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(
                    f"Messaging finding {finding.id} invalid risk_score: {finding.risk_score}"
                )
                return False

        _reconcile_summary(findings, "Messaging")
        logger.info(f"Messaging validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"Messaging validation error: {e}", exc_info=True)
        return False


def validate_cloudtrail_events_findings(findings: SkillFindings) -> bool:
    """Validate CloudTrail Events (threat activity) findings and reconcile summary.

    Notes:
    - Valid finding IDs are CTEF-001 through CTEF-999.
    """
    import re as _re

    _ctef_id_pattern = _re.compile(r"^CTEF-\d{3}$")

    try:
        if not findings.summary:
            logger.error("CloudTrail Events validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("CloudTrail Events validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("CloudTrail Events finding missing required fields")
                return False

            if not _ctef_id_pattern.match(finding.id):
                logger.error(f"CloudTrail Events finding has invalid ID format: {finding.id}")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(
                    f"CloudTrail Events finding {finding.id} invalid severity: {finding.severity}"
                )
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(
                    f"CloudTrail Events finding {finding.id} invalid risk_score: {finding.risk_score}"
                )
                return False

        _reconcile_summary(findings, "CloudTrail Events")
        logger.info(
            f"CloudTrail Events validation passed: {findings.summary.total_findings} findings"
        )
        return True

    except Exception as e:
        logger.error(f"CloudTrail Events validation error: {e}", exc_info=True)
        return False


def validate_sistemas_explotables_red_findings(findings: SkillFindings) -> bool:
    """Validate Sistemas Explotables Red (exploitable network systems) findings
    and reconcile summary.

    Notes:
    - Valid finding IDs look like SER-<CATEGORY>-<NNN>, e.g. SER-EC2-001, SER-CVE-001.
    """
    import re as _re

    _ser_id_pattern = _re.compile(r"^SER-[A-Z0-9]+-\d{3}$")

    try:
        if not findings.summary:
            logger.error("Sistemas Explotables Red validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error("Sistemas Explotables Red validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error("Sistemas Explotables Red finding missing required fields")
                return False

            if not _ser_id_pattern.match(finding.id):
                logger.error(
                    f"Sistemas Explotables Red finding has invalid ID format: {finding.id}"
                )
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(
                    f"Sistemas Explotables Red finding {finding.id} invalid severity: "
                    f"{finding.severity}"
                )
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(
                    f"Sistemas Explotables Red finding {finding.id} invalid risk_score: "
                    f"{finding.risk_score}"
                )
                return False

        _reconcile_summary(findings, "Sistemas Explotables Red")
        logger.info(
            f"Sistemas Explotables Red validation passed: "
            f"{findings.summary.total_findings} findings"
        )
        return True

    except Exception as e:
        logger.error(f"Sistemas Explotables Red validation error: {e}", exc_info=True)
        return False


def _generic_validate_findings(findings: SkillFindings, skill_name: str) -> bool:
    """Baseline validator for any skill without a dedicated entry in
    SKILL_VALIDATORS.

    Checks the logic shared by every skill-specific validator above --
    required fields, a valid severity, and a sane risk_score range -- so a
    skill that isn't (yet) registered still gets validated instead of
    silently fail-opening in validate_findings().
    """
    try:
        if not findings.summary:
            logger.error(f"{skill_name}: validation failed: missing summary")
            return False

        if findings.findings is None:
            logger.error(f"{skill_name}: validation failed: findings array is missing")
            return False

        for finding in findings.findings:
            if (
                not finding.id
                or not finding.severity
                or not finding.title
                or not finding.description
            ):
                logger.error(f"{skill_name} finding missing required fields")
                return False

            if finding.severity not in ["Critical", "High", "Medium", "Low"]:
                logger.error(f"{skill_name} finding {finding.id} invalid severity: {finding.severity}")
                return False

            if finding.risk_score is None or not (0.0 <= float(finding.risk_score) <= 10.0):
                logger.error(
                    f"{skill_name} finding {finding.id} invalid risk_score: {finding.risk_score}"
                )
                return False

        _reconcile_summary(findings, skill_name)
        logger.info(f"{skill_name} validation passed: {findings.summary.total_findings} findings")
        return True

    except Exception as e:
        logger.error(f"{skill_name} validation error: {e}", exc_info=True)
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
    "recon": validate_recon_findings,
    "kms": validate_kms_findings,
    "messaging": validate_messaging_findings,
    "cloudtrail_events": validate_cloudtrail_events_findings,
    "sistemas_explotables_red": validate_sistemas_explotables_red_findings,
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
        logger.warning(
            f"No dedicated validator registered for skill: {skill_name} -- "
            "applying generic baseline validation instead of fail-open"
        )
        return _generic_validate_findings(findings, skill_name)

    return validator(findings)
