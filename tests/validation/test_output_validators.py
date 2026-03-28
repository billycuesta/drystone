"""Tests for output_validators — per-skill validation and summary reconciliation."""

import pytest

from drystone.models.findings import Finding, FindingsSummary, SkillFindings
from drystone.validation.output_validators import (
    SKILL_VALIDATORS,
    validate_alerting_findings,
    validate_cicd_findings,
    validate_compute_findings,
    validate_ecr_findings,
    validate_exposure_findings,
    validate_findings,
    validate_hardening_findings,
    validate_iam_findings,
    validate_network_findings,
    validate_recon_findings,
    validate_secretsmanager_findings,
    validate_vulns_findings,
    validate_waf_findings,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def make_summary(total=1, critical=0, high=0, medium=0, low=0, risk=5.0) -> FindingsSummary:
    return FindingsSummary(
        total_findings=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        overall_risk_score=risk,
    )


def make_finding(
    id="IAM-001",
    severity="High",
    risk_score=7.0,
    title="Test finding",
    description="Test description",
    remediation="Fix it",
    cis_reference="1.5",
) -> Finding:
    return Finding(
        id=id,
        severity=severity,
        risk_score=risk_score,
        title=title,
        description=description,
        remediation=remediation,
        cis_reference=cis_reference,
    )


def make_skill_findings(
    skill="iam",
    findings=None,
    summary=None,
) -> SkillFindings:
    if findings is None:
        findings = [make_finding()]
    if summary is None:
        summary = make_summary(total=len(findings))
    return SkillFindings(
        skill=skill,
        findings=findings,
        summary=summary,
        evidence_count=1,
    )


# ── _reconcile_summary (tested via validators) ────────────────────────────────


class TestReconcileSummary:
    def test_summary_count_reconciled_when_mismatched(self):
        """If Claude reports total=5 but there are 2 findings, reconcile to 2."""
        findings = make_skill_findings(
            findings=[make_finding(id="IAM-001"), make_finding(id="IAM-002")],
            summary=make_summary(total=5, high=2),
        )
        result = validate_iam_findings(findings)
        assert result is True
        assert findings.summary.total_findings == 2

    def test_severity_counts_reconciled(self):
        f1 = make_finding(id="IAM-001", severity="Critical", cis_reference="1.1")
        f2 = make_finding(id="IAM-002", severity="High", cis_reference="1.2")
        sf = make_skill_findings(
            findings=[f1, f2],
            summary=make_summary(total=2, critical=5, high=5),  # wrong counts
        )
        validate_iam_findings(sf)
        assert sf.summary.critical == 1
        assert sf.summary.high == 1

    def test_exact_summary_unchanged(self):
        f1 = make_finding(id="IAM-001", severity="Critical", cis_reference="1.1")
        sf = make_skill_findings(
            findings=[f1],
            summary=make_summary(total=1, critical=1),
        )
        validate_iam_findings(sf)
        assert sf.summary.critical == 1
        assert sf.summary.total_findings == 1


# ── validate_iam_findings ─────────────────────────────────────────────────────


class TestValidateIAMFindings:
    def test_valid_findings_returns_true(self):
        assert validate_iam_findings(make_skill_findings()) is True

    def test_empty_findings_returns_true(self):
        sf = make_skill_findings(findings=[], summary=make_summary(total=0))
        assert validate_iam_findings(sf) is True

    def test_missing_cis_reference_returns_false(self):
        f = make_finding(cis_reference=None)
        sf = make_skill_findings(findings=[f])
        assert validate_iam_findings(sf) is False

    def test_invalid_severity_returns_false(self):
        f = Finding(
            id="IAM-001",
            severity="Critical",
            risk_score=9.0,
            title="T",
            description="D",
            remediation="R",
            cis_reference="1.1",
        )
        # Bypass Pydantic literal by patching after creation
        object.__setattr__(f, "severity", "Unknown")
        sf = make_skill_findings(findings=[f])
        assert validate_iam_findings(sf) is False

    def test_risk_score_out_of_range_returns_false(self):
        # Pydantic enforces 0-10 on creation; patch after
        f = make_finding(cis_reference="1.1")
        object.__setattr__(f, "risk_score", 11.0)
        sf = make_skill_findings(findings=[f])
        assert validate_iam_findings(sf) is False

    def test_missing_title_returns_false(self):
        f = make_finding(cis_reference="1.1")
        object.__setattr__(f, "title", "")
        sf = make_skill_findings(findings=[f])
        assert validate_iam_findings(sf) is False

    def test_exception_returns_false(self):
        # Pass a non-SkillFindings object to trigger AttributeError
        assert validate_iam_findings(None) is False  # type: ignore[arg-type]


# ── validate_hardening_findings ───────────────────────────────────────────────


class TestValidateHardeningFindings:
    def test_valid_returns_true(self):
        sf = make_skill_findings(skill="hardening")
        assert validate_hardening_findings(sf) is True

    def test_missing_id_returns_false(self):
        f = make_finding()
        object.__setattr__(f, "id", "")
        sf = make_skill_findings(skill="hardening", findings=[f])
        assert validate_hardening_findings(sf) is False

    def test_invalid_severity_returns_false(self):
        f = make_finding()
        object.__setattr__(f, "severity", "INVALID")
        sf = make_skill_findings(skill="hardening", findings=[f])
        assert validate_hardening_findings(sf) is False

    def test_empty_findings_returns_true(self):
        sf = make_skill_findings(skill="hardening", findings=[], summary=make_summary(total=0))
        assert validate_hardening_findings(sf) is True


# ── validate_vulns_findings ────────────────────────────────────────────────────


class TestValidateVulnsFindings:
    def test_valid_returns_true(self):
        sf = make_skill_findings(skill="vulns")
        assert validate_vulns_findings(sf) is True

    def test_invalid_severity_returns_false(self):
        f = make_finding()
        object.__setattr__(f, "severity", "NOPE")
        sf = make_skill_findings(skill="vulns", findings=[f])
        assert validate_vulns_findings(sf) is False


# ── validate_exposure_findings ────────────────────────────────────────────────


class TestValidateExposureFindings:
    def test_valid_returns_true(self):
        sf = make_skill_findings(skill="exposure")
        assert validate_exposure_findings(sf) is True

    def test_missing_id_returns_false(self):
        f = make_finding()
        object.__setattr__(f, "id", "")
        sf = make_skill_findings(skill="exposure", findings=[f])
        assert validate_exposure_findings(sf) is False


# ── validate_network_findings ─────────────────────────────────────────────────


class TestValidateNetworkFindings:
    def test_valid_returns_true(self):
        sf = make_skill_findings(skill="network")
        assert validate_network_findings(sf) is True

    def test_invalid_severity_returns_false(self):
        f = make_finding()
        object.__setattr__(f, "severity", "Extreme")
        sf = make_skill_findings(skill="network", findings=[f])
        assert validate_network_findings(sf) is False


# ── validate_alerting_findings ────────────────────────────────────────────────


class TestValidateAlertingFindings:
    def test_valid_returns_true(self):
        sf = make_skill_findings(skill="alerting")
        assert validate_alerting_findings(sf) is True

    def test_missing_id_returns_false(self):
        f = make_finding()
        object.__setattr__(f, "id", "")
        sf = make_skill_findings(skill="alerting", findings=[f])
        assert validate_alerting_findings(sf) is False


# ── validate_waf_findings ─────────────────────────────────────────────────────


class TestValidateWAFFindings:
    def _make_waf_finding(self, **kwargs) -> Finding:
        defaults = dict(
            id="WAF-001",
            severity="High",
            risk_score=7.5,
            title="WAF rule missing",
            description="No WAF rule",
            remediation="Add WAF rule",
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_valid_returns_true(self):
        f = self._make_waf_finding()
        sf = SkillFindings(
            skill="waf",
            findings=[f],
            summary=make_summary(total=1, high=1),
            evidence_count=1,
        )
        assert validate_waf_findings(sf) is True

    def test_missing_description_returns_false(self):
        f = self._make_waf_finding()
        object.__setattr__(f, "description", "")
        sf = SkillFindings(
            skill="waf",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_waf_findings(sf) is False

    def test_invalid_risk_score_returns_false(self):
        f = self._make_waf_finding()
        object.__setattr__(f, "risk_score", 11.0)
        sf = SkillFindings(
            skill="waf",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_waf_findings(sf) is False

    def test_empty_findings_returns_true(self):
        sf = SkillFindings(
            skill="waf",
            findings=[],
            summary=make_summary(total=0),
            evidence_count=1,
        )
        assert validate_waf_findings(sf) is True


# ── validate_secretsmanager_findings ─────────────────────────────────────────


class TestValidateSecretsManagerFindings:
    def _make_sm_finding(self) -> Finding:
        return Finding(
            id="SM-001",
            severity="Critical",
            risk_score=9.0,
            title="Secret rotated never",
            description="Secret has never been rotated",
            remediation="Enable automatic rotation",
        )

    def test_valid_returns_true(self):
        f = self._make_sm_finding()
        sf = SkillFindings(
            skill="secretsmanager",
            findings=[f],
            summary=make_summary(total=1, critical=1),
            evidence_count=1,
        )
        assert validate_secretsmanager_findings(sf) is True

    def test_missing_remediation_returns_false(self):
        f = self._make_sm_finding()
        object.__setattr__(f, "remediation", "")
        sf = SkillFindings(
            skill="secretsmanager",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_secretsmanager_findings(sf) is False

    def test_invalid_risk_score_returns_false(self):
        f = self._make_sm_finding()
        object.__setattr__(f, "risk_score", -1.0)
        sf = SkillFindings(
            skill="secretsmanager",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_secretsmanager_findings(sf) is False


# ── validate_ecr_findings ─────────────────────────────────────────────────────


class TestValidateECRFindings:
    def _make_ecr_finding(self) -> Finding:
        return Finding(
            id="ECR-001",
            severity="High",
            risk_score=7.0,
            title="Image scan disabled",
            description="ECR image scanning is disabled",
            remediation="Enable scan on push",
        )

    def test_valid_returns_true(self):
        f = self._make_ecr_finding()
        sf = SkillFindings(
            skill="ecr",
            findings=[f],
            summary=make_summary(total=1, high=1),
            evidence_count=1,
        )
        assert validate_ecr_findings(sf) is True

    def test_missing_title_returns_false(self):
        f = self._make_ecr_finding()
        object.__setattr__(f, "title", "")
        sf = SkillFindings(
            skill="ecr",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_ecr_findings(sf) is False


# ── validate_cicd_findings ────────────────────────────────────────────────────


class TestValidateCICDFindings:
    def _make_cicd_finding(self, id="CICD-001") -> Finding:
        return Finding(
            id=id,
            severity="High",
            risk_score=7.0,
            title="No branch protection",
            description="Branch protection rules not configured",
            remediation="Enable branch protection",
        )

    def test_valid_returns_true(self):
        f = self._make_cicd_finding()
        sf = SkillFindings(
            skill="cicd",
            findings=[f],
            summary=make_summary(total=1, high=1),
            evidence_count=1,
        )
        assert validate_cicd_findings(sf) is True

    def test_invalid_id_format_returns_false(self):
        f = self._make_cicd_finding(id="CICD001")  # no dash
        sf = SkillFindings(
            skill="cicd",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_cicd_findings(sf) is False

    def test_id_pattern_cicd_dash_3digits(self):
        for valid_id in ["CICD-001", "CICD-123", "CICD-999"]:
            f = self._make_cicd_finding(id=valid_id)
            sf = SkillFindings(
                skill="cicd",
                findings=[f],
                summary=make_summary(total=1),
                evidence_count=1,
            )
            assert validate_cicd_findings(sf) is True, f"Expected valid for id={valid_id}"

    def test_empty_findings_returns_true(self):
        sf = SkillFindings(
            skill="cicd",
            findings=[],
            summary=make_summary(total=0),
            evidence_count=1,
        )
        assert validate_cicd_findings(sf) is True


# ── validate_compute_findings ─────────────────────────────────────────────────


class TestValidateComputeFindings:
    @pytest.mark.parametrize("comp_id", ["COMP-ECS-001", "COMP-EKS-042", "COMP-LAMBDA-100"])
    def test_valid_id_formats(self, comp_id):
        f = Finding(
            id=comp_id,
            severity="High",
            risk_score=7.0,
            title="Compute issue",
            description="Desc",
            remediation="Fix",
        )
        sf = SkillFindings(
            skill="compute",
            findings=[f],
            summary=make_summary(total=1, high=1),
            evidence_count=1,
        )
        assert validate_compute_findings(sf) is True

    def test_invalid_id_format_returns_false(self):
        f = Finding(
            id="COMP-EC2-001",  # EC2 not in allowed set
            severity="High",
            risk_score=7.0,
            title="T",
            description="D",
            remediation="R",
        )
        sf = SkillFindings(
            skill="compute",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_compute_findings(sf) is False


# ── validate_recon_findings ───────────────────────────────────────────────────


class TestValidateReconFindings:
    def _make_recon_finding(self, id="RECON-001") -> Finding:
        return Finding(
            id=id,
            severity="Medium",
            risk_score=5.0,
            title="Exposed metadata",
            description="Instance metadata accessible",
            remediation="Restrict metadata service",
        )

    def test_valid_returns_true(self):
        f = self._make_recon_finding()
        sf = SkillFindings(
            skill="recon",
            findings=[f],
            summary=make_summary(total=1, medium=1),
            evidence_count=1,
        )
        assert validate_recon_findings(sf) is True

    def test_invalid_id_format_returns_false(self):
        f = self._make_recon_finding(id="REC-001")
        sf = SkillFindings(
            skill="recon",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_recon_findings(sf) is False

    @pytest.mark.parametrize("id", ["RECON-001", "RECON-500", "RECON-999"])
    def test_valid_id_patterns(self, id):
        f = self._make_recon_finding(id=id)
        sf = SkillFindings(
            skill="recon",
            findings=[f],
            summary=make_summary(total=1),
            evidence_count=1,
        )
        assert validate_recon_findings(sf) is True


# ── validate_findings (dispatch) ──────────────────────────────────────────────


class TestValidateFindings:
    def test_known_skill_dispatched(self):
        sf = make_skill_findings(skill="iam")
        assert validate_findings("iam", sf) is True

    def test_unknown_skill_returns_true(self):
        sf = make_skill_findings(skill="unknown")
        assert validate_findings("unknown_skill_xyz", sf) is True

    def test_all_registered_skills_present(self):
        expected = {
            "iam",
            "hardening",
            "vulns",
            "exposure",
            "network",
            "alerting",
            "ecr",
            "secretsmanager",
            "waf",
            "cicd",
            "compute",
            "recon",
        }
        assert expected.issubset(set(SKILL_VALIDATORS.keys()))

    def test_dispatch_calls_correct_validator(self):
        """validate_findings('hardening', ...) should call validate_hardening_findings."""
        f = make_finding()
        object.__setattr__(f, "id", "")  # Force hardening validator to return False
        sf = make_skill_findings(skill="hardening", findings=[f])
        # If dispatched to hardening validator, missing id → False
        assert validate_findings("hardening", sf) is False
