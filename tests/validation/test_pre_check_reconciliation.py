"""Tests for Tier 3 reconciliation: pre-checks vs AI findings.

Verifies that:
1. AI findings contradicting PASS pre-checks are rejected
2. FAIL pre-checks with no AI finding trigger deterministic injection
3. Non-pre-checked findings pass through unchanged
"""

import pytest
from unittest.mock import MagicMock

from drystone.models.findings import Finding, SkillFindings, FindingsSummary
from drystone.skills.base import BaseSkill, _severity_to_risk
from drystone.validation.pre_checks import PreCheckResult


def _make_finding(fid: str, severity: str = "Critical") -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        risk_score=7.0,
        title=f"Test {fid}",
        description="Test description",
        remediation="Fix it",
        evidence_refs=[],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def _make_skill_findings(findings_list) -> SkillFindings:
    return SkillFindings(
        skill="test",
        findings=findings_list,
        evidence_count=1,
        summary=FindingsSummary(
            total_findings=len(findings_list),
            critical=sum(1 for f in findings_list if f.severity == "Critical"),
            high=sum(1 for f in findings_list if f.severity == "High"),
            medium=sum(1 for f in findings_list if f.severity == "Medium"),
            low=sum(1 for f in findings_list if f.severity == "Low"),
            overall_risk_score=5.0,
        ),
    )


class ConcreteSkill(BaseSkill):
    """Concrete implementation of BaseSkill for testing."""

    @property
    def name(self) -> str:
        return "test"

    def collect(self, aws_client, session):
        pass


CHECKLIST = {
    "items": [
        {"id": "IAM-001", "severity": "Critical", "title": "Root MFA", "remediation": "Enable MFA"},
        {"id": "IAM-009", "severity": "Critical", "title": "Root keys", "remediation": "Remove keys"},
        {"id": "IAM-008", "severity": "Critical", "title": "Admin policies", "remediation": "Restrict"},
        {
            "id": "IAM-020",
            "severity": "Medium",
            "title": "Groups",
            "description": "IAM users should belong to at least one group for access management.",
            "remediation": "Add groups",
        },
    ],
}


class TestRejectFindingsContradicatingPass:
    """Rule 1: If pre-check says PASS, AI finding for that ID should be rejected."""

    def test_reject_finding_for_pass_check(self):
        skill = ConcreteSkill()
        findings = _make_skill_findings([
            _make_finding("IAM-001"),  # AI says this is a problem
            _make_finding("IAM-008"),  # This one is fine
        ])
        pre_checks = [
            PreCheckResult("IAM-001", "PASS", "MFA enabled"),  # Pre-check says PASS
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        ids = [f.id for f in result.findings]
        assert "IAM-001" not in ids  # Rejected (contradicts PASS)
        assert "IAM-008" in ids  # Preserved (no pre-check)

    def test_multiple_pass_rejections(self):
        skill = ConcreteSkill()
        findings = _make_skill_findings([
            _make_finding("IAM-001"),
            _make_finding("IAM-009"),
            _make_finding("IAM-008"),
        ])
        pre_checks = [
            PreCheckResult("IAM-001", "PASS", "MFA enabled"),
            PreCheckResult("IAM-009", "PASS", "No root keys"),
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        ids = [f.id for f in result.findings]
        assert "IAM-001" not in ids
        assert "IAM-009" not in ids
        assert "IAM-008" in ids


class TestInjectFindingsForMissedFails:
    """Rule 2: If pre-check says FAIL but AI didn't generate finding, inject one."""

    def test_inject_finding_for_missed_fail(self):
        skill = ConcreteSkill()
        findings = _make_skill_findings([
            _make_finding("IAM-008"),  # AI found this
        ])
        pre_checks = [
            PreCheckResult("IAM-020", "FAIL", "3 users without groups",
                           ["arn:aws:iam::*:user/alice", "arn:aws:iam::*:user/bob"]),
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        ids = [f.id for f in result.findings]
        assert "IAM-020" in ids  # Injected
        assert "IAM-008" in ids  # Preserved

        injected = next(f for f in result.findings if f.id == "IAM-020")
        assert injected.severity == "Medium"
        # Description now combines checklist context + specific evidence detected
        assert "IAM users should belong to at least one group" in injected.description
        assert "3 users without groups" in injected.description
        assert "**Detected:**" in injected.description
        assert len(injected.affected_resources) == 2

    def test_no_injection_when_ai_already_found(self):
        skill = ConcreteSkill()
        findings = _make_skill_findings([
            _make_finding("IAM-020", "Medium"),
        ])
        pre_checks = [
            PreCheckResult("IAM-020", "FAIL", "3 users without groups"),
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        # Should only have one IAM-020 (from AI), not duplicated
        iam020 = [f for f in result.findings if f.id == "IAM-020"]
        assert len(iam020) == 1
        assert "Pre-check determined" not in iam020[0].description


class TestSkipPreChecksNoEffect:
    """SKIP pre-checks should not affect AI findings."""

    def test_skip_no_impact(self):
        skill = ConcreteSkill()
        findings = _make_skill_findings([
            _make_finding("IAM-008"),
        ])
        pre_checks = [
            PreCheckResult("IAM-008", "SKIP", "no policies evidence"),
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        ids = [f.id for f in result.findings]
        assert "IAM-008" in ids  # Preserved (SKIP doesn't reject)


class TestNonPreCheckedFindingsPreserved:
    """AI findings for checks without pre-checks should pass through unchanged."""

    def test_ai_findings_preserved(self):
        skill = ConcreteSkill()
        findings = _make_skill_findings([
            _make_finding("IAM-003"),
            _make_finding("IAM-007"),
        ])
        pre_checks = [
            PreCheckResult("IAM-001", "PASS", "MFA enabled"),
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        ids = [f.id for f in result.findings]
        assert "IAM-003" in ids
        assert "IAM-007" in ids


class TestPreCheckImpactInjection:
    """G3: Pre-check FAIL findings get impact narrative from PRE_CHECK_IMPACTS."""

    def test_injected_finding_has_impact_when_defined(self):
        """IAM-001 FAIL → injected finding should have impact text."""
        skill = ConcreteSkill()
        findings = _make_skill_findings([])
        pre_checks = [
            PreCheckResult("IAM-001", "FAIL", "AccountMFAEnabled=0"),
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        injected = next((f for f in result.findings if f.id == "IAM-001"), None)
        assert injected is not None
        assert injected.impact is not None
        assert "root account" in injected.impact.lower()
        assert injected.exploitability_status == "validated"

    def test_injected_finding_no_impact_when_not_defined(self):
        """IAM-020 has no entry in PRE_CHECK_IMPACTS → impact is None."""
        skill = ConcreteSkill()
        findings = _make_skill_findings([])
        pre_checks = [
            PreCheckResult("IAM-020", "FAIL", "3 users without groups",
                           ["arn:aws:iam::*:user/alice"]),
        ]

        result = skill._reconcile_with_pre_checks(findings, pre_checks, CHECKLIST)

        injected = next((f for f in result.findings if f.id == "IAM-020"), None)
        assert injected is not None
        # No entry in PRE_CHECK_IMPACTS for IAM-020, so impact should be None
        assert injected.impact is None
        assert injected.exploitability_status == "validated"


class TestSeverityToRisk:
    def test_critical(self):
        assert _severity_to_risk("Critical") == 9.0

    def test_high(self):
        assert _severity_to_risk("High") == 7.0

    def test_medium(self):
        assert _severity_to_risk("Medium") == 4.5

    def test_low(self):
        assert _severity_to_risk("Low") == 2.0

    def test_unknown(self):
        assert _severity_to_risk("Unknown") == 5.0
