"""Tests for severity/risk_score alignment and impact fallback (Fix 8, Fix 9)."""

from drystone.validation.findings_normalizer import FindingsNormalizer
from drystone.models.findings import Finding


def _make_normalizer(checklist_items=None):
    checklist = {"items": checklist_items or []}
    return FindingsNormalizer(checklist=checklist, skill_name="iam")


class TestFix9SeverityAlignment:
    """Fix 9: Severity label must match risk_score range for non-checklist findings."""

    def test_low_score_with_medium_label_corrected(self):
        """risk_score=2.5 with severity=Medium → should be corrected to Low."""
        norm = _make_normalizer()
        sev, score = norm._align_severity_to_score("Medium", 2.5)
        assert sev == "Low"
        assert score == 2.5

    def test_high_score_with_low_label_corrected(self):
        """risk_score=7.0 with severity=Low → should be corrected to High."""
        norm = _make_normalizer()
        sev, score = norm._align_severity_to_score("Low", 7.0)
        assert sev == "High"
        assert score == 7.0

    def test_matching_score_unchanged(self):
        """risk_score=9.0 with severity=Critical → no change."""
        norm = _make_normalizer()
        sev, score = norm._align_severity_to_score("Critical", 9.0)
        assert sev == "Critical"
        assert score == 9.0

    def test_calibrate_non_checklist_finding_uses_alignment(self):
        """Finding not in checklist → _calibrate_severity uses _align_severity_to_score."""
        norm = _make_normalizer()
        sev, score = norm._calibrate_severity("UNKNOWN-001", "Medium", 2.0)
        assert sev == "Low"
        assert score == 2.0


class TestFix8ImpactFallback:
    """Fix 8: Null impact gets populated by severity-based template."""

    def test_null_impact_gets_populated(self):
        """Finding with no impact receives template-based impact."""
        norm = _make_normalizer()
        finding = Finding(
            id="IAM-999",
            severity="High",
            risk_score=7.0,
            title="Test Finding",
            description="Some description",
            remediation="Fix it",
        )
        assert finding.impact is None
        norm._ensure_impact(finding)
        assert finding.impact is not None
        assert "test finding" in finding.impact.lower()

    def test_existing_impact_preserved(self):
        """Finding with existing impact is not overwritten."""
        norm = _make_normalizer()
        finding = Finding(
            id="IAM-999",
            severity="High",
            risk_score=7.0,
            title="Test Finding",
            description="Some description",
            remediation="Fix it",
            impact="Custom impact text",
        )
        norm._ensure_impact(finding)
        assert finding.impact == "Custom impact text"

    def test_critical_impact_template(self):
        """Critical findings get critical-level impact language."""
        norm = _make_normalizer()
        finding = Finding(
            id="IAM-001",
            severity="Critical",
            risk_score=9.5,
            title="Root Account Compromise",
            description="Root has no MFA",
            remediation="Enable MFA",
        )
        norm._ensure_impact(finding)
        assert "full compromise" in finding.impact.lower()

    def test_low_impact_template(self):
        """Low findings get low-level impact language."""
        norm = _make_normalizer()
        finding = Finding(
            id="IAM-050",
            severity="Low",
            risk_score=1.5,
            title="Minor Config Gap",
            description="Minor issue",
            remediation="Fix minor gap",
        )
        norm._ensure_impact(finding)
        assert "minor" in finding.impact.lower() or "limited" in finding.impact.lower()
