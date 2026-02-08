"""Post-processing normalizer for AI-generated findings.

Reduces variance between different AI models by:
1. Normalizing finding IDs (IAM-008-001 → IAM-008)
2. Calibrating severities against checklist constraints
3. Filtering false positives and duplicates
4. Validating findings against evidence (evidence-based filtering)
5. Resolving mutually exclusive findings (anti-duplicates)
6. Recalculating risk scores with consistent formula

SKILL-AGNOSTIC: Works with any skill (IAM, Exposure, Network, Vulns).
"""

import re
import logging
from typing import List, Dict, Any, Tuple, Optional, Literal, cast

from drystone.models.findings import Finding, FindingsSummary

logger = logging.getLogger(__name__)


Severity = Literal["Critical", "High", "Medium", "Low"]


class FindingsNormalizer:
    """Normalizes findings from different AI models to ensure consistency.

    Reduces variance by enforcing:
    - Simple ID format: SKILL-XXX (no sub-IDs like IAM-008-001)
    - Severity ranges: Critical 8.5-10, High 6.0-8.4, Medium 3.0-5.9, Low 1.0-2.9
    - Checklist constraints: Only valid IDs, no false positives, max 1 per item
    - Risk score calibration: Aligned with severity ranges

    Works for any skill by using skill name + checklist ID mapping.

    Example:
        >>> normalizer = FindingsNormalizer(
        ...     checklist={"items": [{"id": "IAM-001", "severity": "Critical"}]},
        ...     skill_name="iam"
        ... )
        >>> normalized = normalizer.normalize(raw_findings)
        >>> summary = normalizer.recalculate_summary(normalized)
    """

    # Severity ranges (risk_score bounds)
    SEVERITY_RANGES = {
        "Critical": (8.5, 10.0),
        "High": (6.0, 8.4),
        "Medium": (3.0, 5.9),
        "Low": (1.0, 2.9),
    }

    # Mutually exclusive findings pairs: (ID1, ID2) → resolution strategy
    # Strategy: "keep_specific" (keep more specific/detailed finding)
    #           "keep_higher" (keep higher severity finding)
    MUTUAL_EXCLUSIONS = {
        # Hardening: Config state
        ("HRD-001", "HRD-006"): "keep_specific",  # Config: disabled vs partial
        # Hardening: Security Hub state
        ("HRD-002", "HRD-003"): "keep_specific",  # Hub: disabled vs no standards
        # Hardening: Compliance score ranges (overlapping ranges)
        ("HRD-004", "HRD-008"): "keep_higher",  # Compliance: <50% vs 50-70%
        ("HRD-008", "HRD-011"): "keep_higher",  # Compliance: 50-70% vs 70-85%
        # IAM: User state
        ("IAM-003", "IAM-004"): "keep_specific",  # Inactive user vs no MFA
        ("IAM-005", "IAM-007"): "keep_specific",  # No rotation vs old keys
        ("IAM-008", "IAM-009"): "keep_specific",  # Weak policy vs no policy
        # IAM: Root account
        ("IAM-001", "IAM-002"): "keep_higher",  # No MFA vs partial MFA
        # Alerting: CloudTrail state
        ("ALR-001", "ALR-003"): "keep_specific",  # Disabled vs no logs
        ("ALR-003", "ALR-005"): "keep_specific",  # No logs vs no alarms
    }

    def __init__(self, checklist: Dict[str, Any], skill_name: str):
        """Initialize normalizer with checklist reference.

        Args:
            checklist: Security checklist for this skill (from checklist.json)
                      Must have 'items' array with id/severity fields
            skill_name: Skill identifier (e.g., 'iam', 'exposure', 'network', 'vulns')

        Raises:
            ValueError: If checklist format invalid or skill_name not provided
        """
        if not checklist or "items" not in checklist:
            raise ValueError("Checklist must have 'items' array")

        self.checklist = checklist
        self.skill_name = skill_name.upper()  # IAM, EXPOSURE, NETWORK, VULNS
        self.evidence: Optional[Dict[str, Any]] = None  # Optional evidence for validation

        # Build mapping: {ID → checklist item}
        # Example: {"IAM-001": {...}, "IAM-007": {...}, ...}
        self.checklist_map = {item["id"]: item for item in checklist["items"] if "id" in item}

    def normalize(self, findings: List[Finding]) -> List[Finding]:
        """Normalize all findings to reduce variance.

        Steps:
        1. Normalize each finding ID (remove sub-IDs)
        2. Skip duplicates (keep first occurrence of normalized ID)
        3. Skip false positives (e.g., "DISREGARD THIS FINDING")
        4. Skip findings that contradict evidence (if evidence provided)
        5. Calibrate severity against checklist constraints
        6. Return normalized list

        Args:
            findings: Raw findings from AI model

        Returns:
            Normalized findings list with:
            - Simple IDs (SKILL-XXX format)
            - Valid severities from checklist
            - Risk scores in correct ranges
            - No false positives or duplicates

        Example:
            >>> findings = [Finding(id="IAM-008-001", severity="High", ...)]
            >>> normalized = normalizer.normalize(findings)
            >>> normalized[0].id  # Returns "IAM-008"
        """
        logger.debug(f"Normalizing {len(findings)} findings...")
        normalized = []
        seen_ids = set()

        for finding in findings:
            # 1. Normalize ID (remove sub-IDs)
            normalized_id = self._normalize_id(finding.id)

            # 2. Skip duplicates
            if normalized_id in seen_ids:
                logger.debug(f"  ⏭️  Skipped duplicate: {finding.id} → {normalized_id}")
                continue
            seen_ids.add(normalized_id)

            # 3. Skip false positives
            if self._is_false_positive(finding):
                logger.debug(
                    f"  ❌ Rejected false positive: {finding.id} (severity: {finding.severity})"
                )
                continue

            # 4. Validate against evidence (if available)
            if self.evidence and not self._validate_against_evidence(normalized_id, finding):
                logger.warning(
                    f"  ❌ Rejected {normalized_id} - contradicts evidence (severity: {finding.severity})"
                )
                continue

            # 5. Calibrate severity
            severity, risk_score = self._calibrate_severity(
                normalized_id, finding.severity, finding.risk_score
            )

            # Update finding in-place
            finding.id = normalized_id
            finding.severity = severity
            finding.risk_score = risk_score

            logger.debug(f"  ✅ Accepted: {normalized_id} | {severity} | risk={risk_score:.1f}")
            normalized.append(finding)

        return normalized

    def _normalize_id(self, finding_id: str) -> str:
        """Normalize finding ID to simple format (SKILL-XXX).

        Removes sub-IDs and standardizes format.

        Args:
            finding_id: Original ID from AI model (may include sub-IDs)

        Returns:
            Normalized ID in format SKILL-XXX

        Examples:
            "IAM-008-001" → "IAM-008"
            "EXP-005-002" → "EXP-005"
            "NET-012" → "NET-012" (unchanged)
            "VULN-003-sub" → "VULN-003"
        """
        # Pattern: SKILL-XXX (skill prefix + 3 digits)
        # Matches: IAM-001, EXP-005, NET-012, VULN-003, etc
        match = re.match(r"([A-Z]+-\d{3})", finding_id)
        if match:
            return match.group(1)

        # Fallback: return as-is (will be caught as invalid later)
        return finding_id

    def _is_false_positive(self, finding: Finding) -> bool:
        """Detect false positive findings that should be filtered.

        Checks for:
        1. "DISREGARD" markers in title or description
        2. Invalid IDs (not in checklist)

        Args:
            finding: Finding to check

        Returns:
            True if false positive (should be filtered), False otherwise

        Examples:
            >>> Finding(title="DISREGARD THIS FINDING - ERROR") → True
            >>> Finding(id="IAM-999") → True (not in checklist)
            >>> Finding(id="IAM-001", title="Root account without MFA") → False
        """
        # Check for "DISREGARD" markers
        if "DISREGARD" in finding.title.upper() or "DISREGARD" in finding.description.upper():
            return True

        # Check for invalid IDs (not in checklist)
        normalized_id = self._normalize_id(finding.id)
        if normalized_id not in self.checklist_map:
            return True

        return False

    def _calibrate_severity(
        self, finding_id: str, current_severity: str, current_risk_score: float
    ) -> Tuple[Severity, float]:
        """Calibrate severity against checklist constraints.

        Uses checklist as source of truth for severity mapping.
        If AI model assigned wrong severity, corrects it to match checklist.
        Ensures risk_score is within valid range for severity level.

        Args:
            finding_id: Normalized finding ID (SKILL-XXX)
            current_severity: Severity from AI model (Critical/High/Medium/Low)
            current_risk_score: Risk score from AI model (0.0-10.0)

        Returns:
            Tuple of (calibrated_severity, calibrated_risk_score)

        Logic:
        1. If ID not in checklist: return current values (will be filtered by _is_false_positive)
        2. If severity doesn't match checklist: use checklist severity + middle of range
        3. If severity matches: clamp risk_score to severity range
        4. Use middle of range as default when recalibrating

        Examples:
            >>> calibrate("IAM-007", "High", 7.5)  # Checklist says Medium
            → ("Medium", 4.45)  # Middle of 3.0-5.9 range

            >>> calibrate("IAM-001", "Critical", 9.2)  # Matches checklist
            → ("Critical", 9.2)  # Within 8.5-10.0, unchanged
        """
        # Get expected severity from checklist
        if finding_id not in self.checklist_map:
            # Invalid ID: return current values (will be filtered)
            return cast(Severity, current_severity), current_risk_score

        expected_severity = cast(Severity, self.checklist_map[finding_id]["severity"])

        # If AI model used wrong severity, correct it
        if current_severity != expected_severity:
            # Recalculate risk_score to match expected severity
            min_score, max_score = self.SEVERITY_RANGES[expected_severity]

            # Use middle of range as default
            calibrated_score = (min_score + max_score) / 2

            return expected_severity, calibrated_score

        # Severity matches checklist, but ensure risk_score is in valid range
        min_score, max_score = self.SEVERITY_RANGES[expected_severity]

        if current_risk_score < min_score:
            return expected_severity, min_score
        elif current_risk_score > max_score:
            return expected_severity, max_score

        return expected_severity, current_risk_score

    def _validate_against_evidence(self, finding_id: str, finding: Finding) -> bool:
        """Validate finding against actual evidence to detect false positives.

        Checks if finding contradicts explicit evidence about service state.
        Returns False (reject) if evidence clearly shows finding is incorrect.

        Args:
            finding_id: Normalized finding ID (e.g., "HRD-002")
            finding: Finding object to validate

        Returns:
            True if finding is valid, False if contradicts evidence (should be filtered)

        Examples:
            - HRD-002 "Security Hub disabled" is FALSE if HubArn exists in evidence → return False
            - HRD-001 "Config disabled" is FALSE if ConfigurationRecorders > 0 → return False
            - HRD-003 "No standards enabled" is FALSE if Security Hub not enabled → return False
        """
        if not self.evidence:
            return True  # No evidence to validate against

        # WAF: Applicability gating (avoid false positives when there is no in-scope surface)
        # Evidence keys come from BaseSkill.analyze(), using json_file.stem.
        if finding_id in {
            "WAF-001",
            "WAF-002",
            "WAF-003",
            "WAF-004",
            "WAF-005",
            "WAF-006",
            "WAF-007",
            "WAF-008",
            "WAF-009",
            "WAF-010",
            "WAF-011",
            "WAF-012",
            "WAF-013",
            "WAF-014",
            "WAF-015",
            "WAF-016",
        }:
            albs = self.evidence.get("alb-waf-associations", None)
            dists = self.evidence.get("cloudfront-distributions", None)
            web_acls = self.evidence.get("wafv2-web-acls", None)
            ip_sets = self.evidence.get("wafv2-ip-sets", None)
            api_entrypoints = self.evidence.get("api-entrypoints-waf-associations", None)
            coll_status = self.evidence.get("waf-collection-status", None)

            # If collection status indicates failures, treat coverage/config findings as unverifiable.
            # Allow ONLY WAF-013 to surface the evidence-quality gap.
            if isinstance(coll_status, dict):
                has_failure = False
                try:
                    if (coll_status.get("cloudfront") or {}).get("ok") is False:
                        has_failure = True
                    if ((coll_status.get("wafv2") or {}).get("CLOUDFRONT") or {}).get(
                        "ok"
                    ) is False:
                        has_failure = True
                    for _, r in (
                        ((coll_status.get("wafv2") or {}).get("REGIONAL") or {})
                        .get("regions", {})
                        .items()
                    ):
                        if isinstance(r, dict) and r.get("ok") is False:
                            has_failure = True
                            break
                    for _, r in (coll_status.get("alb") or {}).get("regions", {}).items():
                        if isinstance(r, dict) and r.get("ok") is False:
                            has_failure = True
                            break
                    for _, r in (coll_status.get("api_entrypoints") or {}).items():
                        if isinstance(r, dict) and r.get("ok") is False:
                            has_failure = True
                            break
                    if (coll_status.get("waf_classic") or {}).get("ok") is False:
                        has_failure = True
                except Exception:
                    # If status parsing fails, don't hard-reject.
                    has_failure = False

                if has_failure and finding_id != "WAF-013":
                    logger.warning(
                        f"Rejected {finding_id} - WAF collection status indicates failures; only WAF-013 is valid."
                    )
                    return False

                if (not has_failure) and finding_id == "WAF-013":
                    logger.warning(
                        f"Rejected {finding_id} - No collection failures detected in waf-collection-status."
                    )
                    return False

            # WAF-001 only makes sense if we detected at least one internet-facing ALB in-scope.
            if finding_id == "WAF-001" and isinstance(albs, list) and len(albs) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No internet-facing ALBs detected (alb-waf-associations is empty)."
                )
                return False

            # WAF-002 only makes sense if we detected at least one CloudFront distribution in-scope.
            if finding_id == "WAF-002" and isinstance(dists, list) and len(dists) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No CloudFront distributions detected (cloudfront-distributions is empty)."
                )
                return False

            # WAF-003..WAF-008 relate to Web ACL configuration; if we have no Web ACLs,
            # these checks are N/A (coverage should be reported via WAF-001/WAF-002 only).
            if finding_id in {"WAF-003", "WAF-004", "WAF-005", "WAF-006", "WAF-007", "WAF-008"}:
                if isinstance(web_acls, list) and len(web_acls) == 0:
                    logger.warning(
                        f"Rejected {finding_id} - No WAFv2 Web ACLs detected (wafv2-web-acls is empty)."
                    )
                    return False

            # WAF-009 only makes sense if IP sets exist.
            if finding_id == "WAF-009" and isinstance(ip_sets, list) and len(ip_sets) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No WAFv2 IP sets detected (wafv2-ip-sets is empty)."
                )
                return False

            # WAF-014..WAF-016 only make sense if we detected any WAF-supported API entry points.
            if finding_id in {"WAF-014", "WAF-015", "WAF-016"}:
                if isinstance(api_entrypoints, list) and len(api_entrypoints) == 0:
                    logger.warning(
                        f"Rejected {finding_id} - No API entry points detected (api-entrypoints-waf-associations is empty)."
                    )
                    return False

        # Security Hub false positive detection
        if finding_id == "HRD-002":
            hub_status = self.evidence.get("security-hub-status", {})
            # If HubArn exists and is not empty, Security Hub IS enabled
            if hub_status.get("HubArn"):
                logger.warning(
                    f"Rejected {finding_id} - Security Hub IS enabled (HubArn present). "
                    f"Evidence: HubArn={hub_status.get('HubArn')}"
                )
                return False  # False positive: Hub is actually enabled

        # Security Hub standards check (HRD-003, HRD-007) - only valid if Hub is enabled
        if finding_id in ["HRD-003", "HRD-007"]:
            hub_status = self.evidence.get("security-hub-status", {})
            # These findings only make sense if Security Hub is enabled
            if not hub_status.get("HubArn"):
                logger.warning(
                    f"Rejected {finding_id} - Security Hub is NOT enabled. "
                    f"Cannot evaluate Hub-specific findings without enabled Hub."
                )
                return False  # Can't evaluate if Hub is disabled

        # AWS Config false positive detection
        if finding_id == "HRD-001":
            config_recorders = self.evidence.get("config-recorders", {})
            recorders = config_recorders.get("ConfigurationRecorders", [])
            # If recorders array has items, Config IS enabled (at least partially)
            if len(recorders) > 0:
                logger.warning(
                    f"Rejected {finding_id} - Config IS enabled ({len(recorders)} recorders). "
                    f"Should be HRD-006 instead."
                )
                return False  # False positive: Config is actually enabled

        # AWS Config enabled check (HRD-006) - only valid if Config is partially enabled
        if finding_id == "HRD-006":
            config_recorders = self.evidence.get("config-recorders", {})
            recorders = config_recorders.get("ConfigurationRecorders", [])
            # This finding only makes sense if Config is enabled but incomplete
            if len(recorders) == 0:
                logger.warning(
                    f"Rejected {finding_id} - Config is NOT enabled (no recorders). "
                    f"Should be HRD-001 instead."
                )
                return False  # False positive: Config is disabled, not partial

        # GuardDuty validation (HRD-009, HRD-014)
        if finding_id in ["HRD-009", "HRD-014"]:
            gd_detectors = self.evidence.get("guardduty-detectors", [])
            # These findings only make sense if GuardDuty is enabled
            if not gd_detectors or len(gd_detectors) == 0:
                logger.warning(
                    f"Rejected {finding_id} - GuardDuty is NOT enabled. "
                    f"Cannot evaluate GuardDuty-specific findings."
                )
                return False

        # IAM: Root account MFA
        if finding_id == "IAM-001":
            account_summary = self.evidence.get("account-summary", {})
            if account_summary.get("AccountMFAEnabled"):
                logger.warning(
                    f"Rejected {finding_id} - Root account MFA IS enabled. "
                    f"Evidence: AccountMFAEnabled={account_summary.get('AccountMFAEnabled')}"
                )
                return False  # Root MFA IS enabled

        # IAM: Inactive users
        if finding_id == "IAM-003":
            users = self.evidence.get("users", [])
            inactive = [
                u for u in users if not u.get("PasswordLastUsed") and not u.get("AccessKeys")
            ]
            if len(inactive) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No inactive users found. "
                    f"Evidence: {len(users)} users, all have activity."
                )
                return False  # No inactive users found

        # IAM: Old access keys (> 90 days)
        if finding_id == "IAM-007":
            from datetime import datetime, timedelta

            users = self.evidence.get("users", [])
            old_keys = []
            for user in users:
                for key in user.get("AccessKeys", []):
                    create_date = key.get("CreateDate")
                    if isinstance(create_date, str):
                        try:
                            create_date = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                        except (ValueError, TypeError):
                            continue
                    if create_date and isinstance(create_date, datetime):
                        age_days = (datetime.now(create_date.tzinfo) - create_date).days
                        if age_days > 90:
                            old_keys.append(key)
            if len(old_keys) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No old access keys found (>90 days). "
                    f"All keys are recent or missing CreateDate."
                )
                return False  # No old keys found

        # Alerting: CloudTrail disabled
        if finding_id == "ALR-001":
            trails = self.evidence.get("cloudtrail-trails", [])
            if len(trails) > 0:
                logger.warning(
                    f"Rejected {finding_id} - CloudTrail IS enabled ({len(trails)} trails). "
                    f"Should be ALR-003 (no logs) or ALR-005+ (other issues)."
                )
                return False  # CloudTrail IS enabled (should be ALR-003 or ALR-005+)

        # Alerting: CloudTrail logs disabled (ALR-003 only valid if Trail exists)
        if finding_id == "ALR-003":
            trails = self.evidence.get("cloudtrail-trails", [])
            if len(trails) == 0:
                logger.warning(
                    f"Rejected {finding_id} - CloudTrail is NOT enabled (no trails). "
                    f"Should be ALR-001 instead."
                )
                return False  # Can't have "no logs" if trail doesn't exist

        return True  # Finding is valid against evidence

    def _resolve_mutual_exclusions(self, findings: List[Finding]) -> List[Finding]:
        """Resolve mutually exclusive findings.

        If both findings in an exclusion pair are present, keep only one
        according to the resolution strategy (keep_specific or keep_higher).

        Args:
            findings: List of findings that may contain exclusive pairs

        Returns:
            Findings list with exclusions resolved (no conflicting pairs)

        Example:
            If both HRD-001 (disabled) and HRD-006 (partial) present:
            Keep HRD-006 (more specific)
        """
        findings_dict = {f.id: f for f in findings}
        to_remove = set()

        for (id1, id2), strategy in self.MUTUAL_EXCLUSIONS.items():
            if id1 in findings_dict and id2 in findings_dict:
                # Both present - resolve conflict
                f1, f2 = findings_dict[id1], findings_dict[id2]

                if strategy == "keep_specific":
                    # Keep the more specific finding (higher ID number = more detailed)
                    id1_num = int(id1.split("-")[1])
                    id2_num = int(id2.split("-")[1])
                    to_remove_id = id1 if id1_num < id2_num else id2
                    kept_id = id2 if to_remove_id == id1 else id1
                    logger.info(
                        f"Mutual exclusion resolved: {id1} vs {id2} → kept {kept_id} (more specific)"
                    )
                    to_remove.add(to_remove_id)

                elif strategy == "keep_higher":
                    # Keep higher severity
                    to_remove_id = id1 if f1.risk_score < f2.risk_score else id2
                    kept_id = id2 if to_remove_id == id1 else id1
                    logger.info(
                        f"Mutual exclusion resolved: {id1} vs {id2} → kept {kept_id} (higher severity: {max(f1.risk_score, f2.risk_score)})"
                    )
                    to_remove.add(to_remove_id)

        return [f for f in findings if f.id not in to_remove]

    def recalculate_summary(self, findings: List[Finding]) -> FindingsSummary:
        """Recalculate summary statistics after normalization.

        Counts findings by severity and calculates overall_risk_score
        using weighted average formula (same as original scoring).

        Args:
            findings: Normalized findings list

        Returns:
            FindingsSummary with updated totals and overall_risk_score

        Formula for overall_risk_score:
            weighted_sum = Σ(risk_score × weight)
            total_weight = Σ(weight)
            overall = weighted_sum / total_weight

        where weights are:
            - Critical: 3.0
            - High: 2.0
            - Medium: 1.0
            - Low: 0.5

        Example:
            >>> findings = [Critical(9.5), High(7.0), Medium(4.0)]
            >>> summary = normalizer.recalculate_summary(findings)
            >>> summary.overall_risk_score  # ≈ 7.0
        """
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "Critical")
        high = sum(1 for f in findings if f.severity == "High")
        medium = sum(1 for f in findings if f.severity == "Medium")
        low = sum(1 for f in findings if f.severity == "Low")

        # Overall risk score = weighted average
        # Critical: 3x weight, High: 2x, Medium: 1x, Low: 0.5x
        if total == 0:
            overall_risk = 0.0
        else:
            weights = {
                "Critical": 3.0,
                "High": 2.0,
                "Medium": 1.0,
                "Low": 0.5,
            }

            weighted_sum = sum(f.risk_score * weights[f.severity] for f in findings)
            total_weight = sum(weights[f.severity] for f in findings)

            # Round to 1 decimal place
            overall_risk = round(weighted_sum / total_weight, 1)

        return FindingsSummary(
            total_findings=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            overall_risk_score=overall_risk,
        )


__all__ = ["FindingsNormalizer", "logger"]
