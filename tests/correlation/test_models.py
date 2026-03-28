"""Tests for correlation Pydantic models — boundary and constraint validation."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from drystone.correlation.models import (
    CorrelatedFinding,
    CorrelationPattern,
    CVSSScore,
    SourceFindingRef,
    ThreatContext,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def make_cvss(**kwargs) -> CVSSScore:
    defaults = dict(
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        base_score=9.8,
        attack_vector="Network",
        attack_complexity="Low",
        privileges_required="None",
        user_interaction="None",
        scope="Changed",
        confidentiality_impact="High",
        integrity_impact="High",
        availability_impact="High",
    )
    defaults.update(kwargs)
    return CVSSScore(**defaults)


def make_source_ref(**kwargs) -> SourceFindingRef:
    defaults = dict(
        id="IAM-001",
        skill="iam",
        title="Root MFA not enabled",
        severity="Critical",
        risk_score=9.5,
        contribution_weight=1.0,
    )
    defaults.update(kwargs)
    return SourceFindingRef(**defaults)


def make_correlated_finding(**kwargs) -> CorrelatedFinding:
    defaults = dict(
        id="CORR-001",
        pattern_id="PAT-001",
        severity="Critical",
        compound_risk_score=9.5,
        title="Compound risk",
        description="Attack chain description",
        source_finding_ids=["IAM-001", "NET-001"],
        source_findings=[make_source_ref()],
        remediation_priority="Immediate",
    )
    defaults.update(kwargs)
    return CorrelatedFinding(**defaults)


# ── CVSSScore: base_score bounds ──────────────────────────────────────────────


class TestCVSSScoreBounds:
    def test_valid_minimum_base_score(self):
        cvss = make_cvss(base_score=0.0)
        assert cvss.base_score == 0.0

    def test_valid_maximum_base_score(self):
        cvss = make_cvss(base_score=10.0)
        assert cvss.base_score == 10.0

    def test_base_score_above_10_rejected(self):
        with pytest.raises(ValidationError):
            make_cvss(base_score=10.1)

    def test_base_score_negative_rejected(self):
        with pytest.raises(ValidationError):
            make_cvss(base_score=-0.1)

    def test_valid_temporal_score_bounds(self):
        cvss = make_cvss(temporal_score=0.0)
        assert cvss.temporal_score == 0.0
        cvss = make_cvss(temporal_score=10.0)
        assert cvss.temporal_score == 10.0

    def test_temporal_score_above_10_rejected(self):
        with pytest.raises(ValidationError):
            make_cvss(temporal_score=10.1)

    def test_environmental_score_above_10_rejected(self):
        with pytest.raises(ValidationError):
            make_cvss(environmental_score=10.5)

    def test_optional_scores_default_to_none(self):
        cvss = make_cvss()
        assert cvss.temporal_score is None
        assert cvss.environmental_score is None

    def test_optional_temporal_fields_default_to_none(self):
        cvss = make_cvss()
        assert cvss.exploit_code_maturity is None
        assert cvss.remediation_level is None
        assert cvss.report_confidence is None


# ── SourceFindingRef: bounds ───────────────────────────────────────────────────


class TestSourceFindingRefBounds:
    def test_valid_min_risk_score(self):
        ref = make_source_ref(risk_score=0.0)
        assert ref.risk_score == 0.0

    def test_valid_max_risk_score(self):
        ref = make_source_ref(risk_score=10.0)
        assert ref.risk_score == 10.0

    def test_risk_score_above_10_rejected(self):
        with pytest.raises(ValidationError):
            make_source_ref(risk_score=10.1)

    def test_risk_score_negative_rejected(self):
        with pytest.raises(ValidationError):
            make_source_ref(risk_score=-1.0)

    def test_valid_contribution_weight_boundaries(self):
        ref = make_source_ref(contribution_weight=0.0)
        assert ref.contribution_weight == 0.0
        ref = make_source_ref(contribution_weight=1.0)
        assert ref.contribution_weight == 1.0

    def test_contribution_weight_above_1_rejected(self):
        with pytest.raises(ValidationError):
            make_source_ref(contribution_weight=1.1)

    def test_contribution_weight_negative_rejected(self):
        with pytest.raises(ValidationError):
            make_source_ref(contribution_weight=-0.1)

    def test_contribution_weight_defaults_to_1(self):
        ref = SourceFindingRef(
            id="IAM-001", skill="iam", title="X", severity="High", risk_score=7.0
        )
        assert ref.contribution_weight == 1.0

    def test_required_fields_missing_raises(self):
        with pytest.raises(ValidationError):
            SourceFindingRef(id="IAM-001")


# ── CorrelatedFinding: bounds ─────────────────────────────────────────────────


class TestCorrelatedFindingBounds:
    def test_valid_min_compound_risk_score(self):
        finding = make_correlated_finding(compound_risk_score=0.0)
        assert finding.compound_risk_score == 0.0

    def test_valid_max_compound_risk_score(self):
        finding = make_correlated_finding(compound_risk_score=10.0)
        assert finding.compound_risk_score == 10.0

    def test_compound_risk_score_above_10_rejected(self):
        with pytest.raises(ValidationError):
            make_correlated_finding(compound_risk_score=10.1)

    def test_compound_risk_score_negative_rejected(self):
        with pytest.raises(ValidationError):
            make_correlated_finding(compound_risk_score=-0.1)

    def test_defaults_for_optional_list_fields(self):
        finding = make_correlated_finding()
        assert finding.attack_path == []
        assert finding.affected_resources == []
        assert finding.remediation_steps == []
        assert finding.cis_reference is None
        assert finding.pci_dss is None

    def test_created_at_auto_populated(self):
        finding = make_correlated_finding()
        assert isinstance(finding.created_at, datetime)

    def test_required_fields_missing_raises(self):
        with pytest.raises(ValidationError):
            CorrelatedFinding(id="CORR-001")


# ── CorrelationPattern: amplification_factor bounds ───────────────────────────


class TestCorrelationPatternBounds:
    def _make_pattern(self, amplification_factor: float) -> CorrelationPattern:
        return CorrelationPattern(
            id="PAT-001",
            name="Test Pattern",
            severity="Critical",
            skills_required=["iam", "network"],
            amplification_factor=amplification_factor,
            title_template="Title {resource}",
            description_template="Description",
            attack_path_steps=["Step 1", "Step 2"],
            remediation_template="Fix it",
        )

    def test_valid_min_amplification_factor(self):
        pattern = self._make_pattern(1.0)
        assert pattern.amplification_factor == 1.0

    def test_valid_max_amplification_factor(self):
        pattern = self._make_pattern(2.0)
        assert pattern.amplification_factor == 2.0

    def test_amplification_below_1_rejected(self):
        with pytest.raises(ValidationError):
            self._make_pattern(0.9)

    def test_amplification_above_2_rejected(self):
        with pytest.raises(ValidationError):
            self._make_pattern(2.1)


# ── ThreatContext: defaults ────────────────────────────────────────────────────


class TestThreatContextDefaults:
    def test_empty_lists_by_default(self):
        ctx = ThreatContext()
        assert ctx.mitre_attack_tactics == []
        assert ctx.mitre_attack_techniques == []
        assert ctx.threat_actors == []

    def test_observed_in_wild_false_by_default(self):
        ctx = ThreatContext()
        assert ctx.observed_in_wild is False

    def test_exploit_maturity_default(self):
        ctx = ThreatContext()
        assert ctx.exploit_maturity == "Not Defined"

    def test_populated_threat_context(self):
        ctx = ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0003"],
            mitre_attack_techniques=["T1078"],
            threat_actors=["APT29"],
            observed_in_wild=True,
            exploit_maturity="High",
        )
        assert len(ctx.mitre_attack_tactics) == 2
        assert ctx.observed_in_wild is True
        assert ctx.exploit_maturity == "High"
