"""Post-processing normalizer for AI-generated findings.

Reduces variance between different AI models by:
1. Normalizing finding IDs (IAM-008-001 → IAM-008)
2. Calibrating severities against checklist constraints
3. Filtering false positives and duplicates
4. Recalculating risk scores with consistent formula

SKILL-AGNOSTIC: Works with any skill (IAM, Exposure, Network, Vulns).
"""

import re
from typing import List, Dict, Any, Tuple

from drystone.models.findings import Finding, FindingsSummary


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
        'Critical': (8.5, 10.0),
        'High': (6.0, 8.4),
        'Medium': (3.0, 5.9),
        'Low': (1.0, 2.9),
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
        if not checklist or 'items' not in checklist:
            raise ValueError("Checklist must have 'items' array")

        self.checklist = checklist
        self.skill_name = skill_name.upper()  # IAM, EXPOSURE, NETWORK, VULNS

        # Build mapping: {ID → checklist item}
        # Example: {"IAM-001": {...}, "IAM-007": {...}, ...}
        self.checklist_map = {
            item['id']: item
            for item in checklist['items']
            if 'id' in item
        }

    def normalize(self, findings: List[Finding]) -> List[Finding]:
        """Normalize all findings to reduce variance.

        Steps:
        1. Normalize each finding ID (remove sub-IDs)
        2. Skip duplicates (keep first occurrence of normalized ID)
        3. Skip false positives (e.g., "DISREGARD THIS FINDING")
        4. Calibrate severity against checklist constraints
        5. Return normalized list

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
        normalized = []
        seen_ids = set()

        for finding in findings:
            # 1. Normalize ID (remove sub-IDs)
            normalized_id = self._normalize_id(finding.id)

            # 2. Skip duplicates
            if normalized_id in seen_ids:
                continue
            seen_ids.add(normalized_id)

            # 3. Skip false positives
            if self._is_false_positive(finding):
                continue

            # 4. Calibrate severity
            severity, risk_score = self._calibrate_severity(
                normalized_id,
                finding.severity,
                finding.risk_score
            )

            # Update finding in-place
            finding.id = normalized_id
            finding.severity = severity
            finding.risk_score = risk_score

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
        match = re.match(r'([A-Z]+-\d{3})', finding_id)
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
        if "DISREGARD" in finding.title.upper() or \
           "DISREGARD" in finding.description.upper():
            return True

        # Check for invalid IDs (not in checklist)
        normalized_id = self._normalize_id(finding.id)
        if normalized_id not in self.checklist_map:
            return True

        return False

    def _calibrate_severity(
        self,
        finding_id: str,
        current_severity: str,
        current_risk_score: float
    ) -> Tuple[str, float]:
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
            return current_severity, current_risk_score

        expected_severity = self.checklist_map[finding_id]['severity']

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
        critical = sum(1 for f in findings if f.severity == 'Critical')
        high = sum(1 for f in findings if f.severity == 'High')
        medium = sum(1 for f in findings if f.severity == 'Medium')
        low = sum(1 for f in findings if f.severity == 'Low')

        # Overall risk score = weighted average
        # Critical: 3x weight, High: 2x, Medium: 1x, Low: 0.5x
        if total == 0:
            overall_risk = 0.0
        else:
            weights = {
                'Critical': 3.0,
                'High': 2.0,
                'Medium': 1.0,
                'Low': 0.5,
            }

            weighted_sum = sum(
                f.risk_score * weights[f.severity]
                for f in findings
            )
            total_weight = sum(weights[f.severity] for f in findings)

            # Round to 1 decimal place
            overall_risk = round(weighted_sum / total_weight, 1)

        return FindingsSummary(
            total_findings=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            overall_risk_score=overall_risk
        )


__all__ = ["FindingsNormalizer"]
