"""Tests for FindingsNormalizer pure-logic methods and module-level helpers."""

import pytest

from drystone.models.findings import Finding, FindingsSummary
from drystone.validation.findings_normalizer import (
    FindingsNormalizer,
    _kms_grant_has_context_constraints,
    _kms_grant_is_sensitive,
    _kms_grant_is_service_managed,
    _principal_has_wildcard,
)

# ── helpers ───────────────────────────────────────────────────────────────────

CHECKLIST = {
    "items": [
        {"id": "IAM-001", "severity": "Critical"},
        {"id": "IAM-002", "severity": "High"},
        {"id": "IAM-003", "severity": "Medium"},
        {"id": "IAM-004", "severity": "Low"},
        {"id": "HRD-001", "severity": "Critical"},
        {"id": "HRD-006", "severity": "High"},
        {"id": "HRD-004", "severity": "Critical"},
        {"id": "HRD-008", "severity": "High"},
    ]
}


def _make_normalizer(skill="iam", checklist=None):
    return FindingsNormalizer(checklist=checklist or CHECKLIST, skill_name=skill)


def _finding(
    id="IAM-001",
    severity="Critical",
    risk_score=9.0,
    title="Root MFA missing",
    description="Root account has no MFA",
    remediation="Enable MFA",
    affected_resources=None,
    evidence_refs=None,
    evidence_snippet=None,
    impact=None,
) -> Finding:
    return Finding(
        id=id,
        severity=severity,
        risk_score=risk_score,
        title=title,
        description=description,
        remediation=remediation,
        affected_resources=(
            ["arn:aws:iam::123:root"] if affected_resources is None else affected_resources
        ),
        evidence_refs=["evidence/iam/users.json"] if evidence_refs is None else evidence_refs,
        evidence_snippet=evidence_snippet,
        impact=impact,
    )


# ── Module-level helpers ──────────────────────────────────────────────────────


class TestKmsGrantIsSensitive:
    def test_decrypt_is_sensitive(self):
        assert _kms_grant_is_sensitive({"Operations": ["Decrypt"]}) is True

    def test_generate_data_key_is_sensitive(self):
        assert _kms_grant_is_sensitive({"Operations": ["GenerateDataKey"]}) is True

    def test_generate_data_key_without_plaintext_is_sensitive(self):
        assert _kms_grant_is_sensitive({"Operations": ["GenerateDataKeyWithoutPlaintext"]}) is True

    def test_describe_key_not_sensitive(self):
        assert _kms_grant_is_sensitive({"Operations": ["DescribeKey"]}) is False

    def test_empty_operations_not_sensitive(self):
        assert _kms_grant_is_sensitive({"Operations": []}) is False

    def test_missing_operations_not_sensitive(self):
        assert _kms_grant_is_sensitive({}) is False

    def test_non_list_operations_not_sensitive(self):
        assert _kms_grant_is_sensitive({"Operations": "Decrypt"}) is False

    def test_mixed_ops_with_decrypt_is_sensitive(self):
        assert _kms_grant_is_sensitive({"Operations": ["DescribeKey", "Decrypt"]}) is True


class TestKmsGrantHasContextConstraints:
    def test_equals_constraint(self):
        grant = {"Constraints": {"EncryptionContextEquals": {"key": "val"}}}
        assert _kms_grant_has_context_constraints(grant) is True

    def test_subset_constraint(self):
        grant = {"Constraints": {"EncryptionContextSubset": {"env": "prod"}}}
        assert _kms_grant_has_context_constraints(grant) is True

    def test_empty_constraints(self):
        assert _kms_grant_has_context_constraints({"Constraints": {}}) is False

    def test_missing_constraints(self):
        assert _kms_grant_has_context_constraints({}) is False

    def test_non_dict_constraints(self):
        assert _kms_grant_has_context_constraints({"Constraints": "none"}) is False


class TestKmsGrantIsServiceManaged:
    def test_amazonaws_grantee(self):
        assert _kms_grant_is_service_managed({"GranteePrincipal": "lambda.amazonaws.com"}) is True

    def test_assumed_role_arn(self):
        grant = {"GranteePrincipal": "arn:aws:sts::123:assumed-role/MyRole/session"}
        assert _kms_grant_is_service_managed(grant) is True

    def test_issuing_account_amazonaws(self):
        assert _kms_grant_is_service_managed({"IssuingAccount": "s3.amazonaws.com"}) is True

    def test_regular_user_not_service(self):
        assert (
            _kms_grant_is_service_managed({"GranteePrincipal": "arn:aws:iam::123:user/alice"})
            is False
        )

    def test_empty_grant_not_service(self):
        assert _kms_grant_is_service_managed({}) is False


class TestPrincipalHasWildcard:
    def test_string_wildcard(self):
        assert _principal_has_wildcard("*") is True

    def test_dict_aws_wildcard(self):
        assert _principal_has_wildcard({"AWS": "*"}) is True

    def test_dict_aws_list_with_wildcard(self):
        assert _principal_has_wildcard({"AWS": ["arn:aws:iam::123:root", "*"]}) is True

    def test_dict_aws_list_no_wildcard(self):
        assert _principal_has_wildcard({"AWS": ["arn:aws:iam::123:root"]}) is False

    def test_specific_arn_not_wildcard(self):
        assert _principal_has_wildcard("arn:aws:iam::123:root") is False

    def test_none_not_wildcard(self):
        assert _principal_has_wildcard(None) is False

    def test_empty_dict_not_wildcard(self):
        assert _principal_has_wildcard({}) is False


# ── FindingsNormalizer.__init__ ───────────────────────────────────────────────


class TestFindingsNormalizerInit:
    def test_valid_init(self):
        n = _make_normalizer()
        assert n.skill_name == "IAM"  # uppercased

    def test_checklist_map_built(self):
        n = _make_normalizer()
        assert "IAM-001" in n.checklist_map
        assert "IAM-002" in n.checklist_map

    def test_missing_items_raises(self):
        with pytest.raises(ValueError, match="items"):
            FindingsNormalizer(checklist={}, skill_name="iam")

    def test_empty_checklist_raises(self):
        with pytest.raises(ValueError):
            FindingsNormalizer(checklist=None, skill_name="iam")  # type: ignore[arg-type]

    def test_skill_name_uppercased(self):
        n = _make_normalizer(skill="network")
        assert n.skill_name == "NETWORK"

    def test_pre_checked_ids_empty_by_default(self):
        n = _make_normalizer()
        assert n._pre_checked_ids == set()

    def test_evidence_none_by_default(self):
        n = _make_normalizer()
        assert n.evidence is None


# ── _normalize_id ──────────────────────────────────────────────────────────────


class TestNormalizeId:
    def test_sub_id_stripped(self):
        n = _make_normalizer()
        assert n._normalize_id("IAM-008-001") == "IAM-008"

    def test_already_normalized(self):
        n = _make_normalizer()
        assert n._normalize_id("IAM-008") == "IAM-008"

    def test_two_digit_sub_id_stripped(self):
        n = _make_normalizer()
        assert n._normalize_id("EXP-005-002") == "EXP-005"

    def test_alphabetic_sub_id_stripped(self):
        n = _make_normalizer()
        assert n._normalize_id("VULN-003-sub") == "VULN-003"

    def test_non_matching_format_returned_as_is(self):
        n = _make_normalizer()
        result = n._normalize_id("INVALID")
        assert result == "INVALID"

    def test_network_id(self):
        n = _make_normalizer()
        assert n._normalize_id("NET-012-A") == "NET-012"


# ── _is_false_positive ─────────────────────────────────────────────────────────


class TestIsFalsePositive:
    def test_valid_finding_not_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001")
        assert n._is_false_positive(f) is False

    def test_disregard_in_title_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", title="DISREGARD THIS FINDING")
        assert n._is_false_positive(f) is True

    def test_disregard_in_description_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", description="DISREGARD - not applicable")
        assert n._is_false_positive(f) is True

    def test_disregard_in_remediation_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", remediation="DISREGARD this item")
        assert n._is_false_positive(f) is True

    def test_no_finding_placeholder_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", title="NO FINDING - everything ok")
        assert n._is_false_positive(f) is True

    def test_no_action_needed_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", title="No action needed")
        assert n._is_false_positive(f) is True

    def test_correctly_configured_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", description="Service is correctly configured")
        assert n._is_false_positive(f) is True

    def test_invalid_id_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-999")  # not in checklist
        assert n._is_false_positive(f) is True

    def test_no_resources_no_refs_no_snippet_is_fp(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", affected_resources=[], evidence_refs=[], evidence_snippet=None)
        assert n._is_false_positive(f) is True

    def test_snippet_alone_avoids_fp(self):
        """A finding with only evidence_snippet (no resources/refs) should not be FP."""
        n = _make_normalizer()
        f = _finding(
            id="IAM-001",
            affected_resources=[],
            evidence_refs=[],
            evidence_snippet={"key": "value"},
        )
        assert n._is_false_positive(f) is False

    def test_case_insensitive_disregard(self):
        n = _make_normalizer()
        f = _finding(id="IAM-001", title="Disregard this finding")
        assert n._is_false_positive(f) is True


# ── _ensure_impact ─────────────────────────────────────────────────────────────


class TestEnsureImpact:
    def test_existing_impact_not_overwritten(self):
        n = _make_normalizer()
        f = _finding(impact="My custom impact text")
        n._ensure_impact(f)
        assert f.impact == "My custom impact text"

    def test_missing_impact_filled_for_critical(self):
        n = _make_normalizer()
        f = _finding(severity="Critical", impact=None)
        n._ensure_impact(f)
        assert f.impact is not None
        assert len(f.impact) > 20

    def test_missing_impact_filled_for_high(self):
        n = _make_normalizer()
        f = _finding(severity="High", impact=None)
        n._ensure_impact(f)
        assert f.impact is not None

    def test_impact_contains_finding_title(self):
        n = _make_normalizer()
        f = _finding(title="Root MFA missing", severity="Critical", impact=None)
        n._ensure_impact(f)
        assert "root mfa missing" in f.impact.lower()

    def test_low_severity_template_used(self):
        n = _make_normalizer()
        f = _finding(severity="Low", impact=None)
        n._ensure_impact(f)
        assert (
            "minor" in f.impact.lower()
            or "low" in f.impact.lower()
            or "improvement" in f.impact.lower()
        )


# ── _align_severity_to_score ───────────────────────────────────────────────────


class TestAlignSeverityToScore:
    def test_critical_score_returns_critical(self):
        n = _make_normalizer()
        sev, score = n._align_severity_to_score("High", 9.0)
        assert sev == "Critical"

    def test_high_score_returns_high(self):
        n = _make_normalizer()
        sev, score = n._align_severity_to_score("Critical", 7.0)
        assert sev == "High"

    def test_medium_score_returns_medium(self):
        n = _make_normalizer()
        sev, score = n._align_severity_to_score("High", 4.5)
        assert sev == "Medium"

    def test_low_score_returns_low(self):
        n = _make_normalizer()
        sev, score = n._align_severity_to_score("Critical", 2.0)
        assert sev == "Low"

    def test_score_unchanged(self):
        n = _make_normalizer()
        _, score = n._align_severity_to_score("Critical", 9.0)
        assert score == 9.0

    def test_out_of_range_score_fallback(self):
        """Score 0.0 is out of all ranges → fallback to input severity."""
        n = _make_normalizer()
        sev, score = n._align_severity_to_score("Low", 0.0)
        assert sev == "Low"
        assert score == 0.0


# ── _calibrate_severity ────────────────────────────────────────────────────────


class TestCalibrateSeverity:
    def test_correct_severity_score_in_range_unchanged(self):
        n = _make_normalizer()
        sev, score = n._calibrate_severity("IAM-001", "Critical", 9.2)
        assert sev == "Critical"
        assert score == 9.2

    def test_wrong_severity_corrected_to_checklist(self):
        n = _make_normalizer()
        # IAM-003 is Medium in checklist; AI said High
        sev, score = n._calibrate_severity("IAM-003", "High", 7.0)
        assert sev == "Medium"

    def test_wrong_severity_score_is_midpoint(self):
        n = _make_normalizer()
        # IAM-004 is Low; AI said Critical
        sev, score = n._calibrate_severity("IAM-004", "Critical", 9.5)
        assert sev == "Low"
        min_s, max_s = FindingsNormalizer.SEVERITY_RANGES["Low"]
        assert score == (min_s + max_s) / 2

    def test_score_clamped_to_min(self):
        n = _make_normalizer()
        # IAM-001 is Critical (8.5-10.0); score too low
        sev, score = n._calibrate_severity("IAM-001", "Critical", 1.0)
        assert sev == "Critical"
        assert score == 8.5

    def test_score_clamped_to_max(self):
        n = _make_normalizer()
        # IAM-004 is Low (1.0-2.9); score too high
        sev, score = n._calibrate_severity("IAM-004", "Low", 5.0)
        assert sev == "Low"
        assert score == 2.9

    def test_unknown_id_aligns_to_score_range(self):
        """IDs not in checklist use _align_severity_to_score."""
        n = _make_normalizer()
        sev, score = n._calibrate_severity("IAM-999", "High", 9.0)
        # Score 9.0 is Critical range
        assert sev == "Critical"


# ── recalculate_summary ────────────────────────────────────────────────────────


class TestRecalculateSummary:
    def test_empty_findings(self):
        n = _make_normalizer()
        summary = n.recalculate_summary([])
        assert summary.total_findings == 0
        assert summary.overall_risk_score == 0.0

    def test_single_critical_finding(self):
        n = _make_normalizer()
        f = _finding(severity="Critical", risk_score=9.5)
        summary = n.recalculate_summary([f])
        assert summary.total_findings == 1
        assert summary.critical == 1
        assert summary.high == 0
        assert summary.overall_risk_score == 9.5

    def test_counts_by_severity(self):
        n = _make_normalizer()
        findings = [
            _finding(id="IAM-001", severity="Critical", risk_score=9.0),
            _finding(id="IAM-002", severity="High", risk_score=7.0),
            _finding(id="IAM-002", severity="High", risk_score=7.0),
            _finding(id="IAM-003", severity="Medium", risk_score=4.0),
        ]
        summary = n.recalculate_summary(findings)
        assert summary.critical == 1
        assert summary.high == 2
        assert summary.medium == 1
        assert summary.low == 0
        assert summary.total_findings == 4

    def test_weighted_risk_score(self):
        """Critical:3, High:2, Medium:1, Low:0.5 weights."""
        n = _make_normalizer()
        # Only 1 critical at 9.0 → weighted_sum=27.0, total_weight=3.0 → 9.0
        f = _finding(severity="Critical", risk_score=9.0)
        summary = n.recalculate_summary([f])
        assert summary.overall_risk_score == 9.0

    def test_risk_score_rounded_to_one_decimal(self):
        n = _make_normalizer()
        findings = [
            _finding(id="IAM-001", severity="Critical", risk_score=9.3),
            _finding(id="IAM-002", severity="High", risk_score=7.1),
        ]
        # weighted_sum = 9.3*3 + 7.1*2 = 27.9 + 14.2 = 42.1
        # total_weight = 3 + 2 = 5
        # overall = 42.1 / 5 = 8.42 → 8.4
        summary = n.recalculate_summary(findings)
        assert isinstance(summary.overall_risk_score, float)
        # Check it's rounded to 1 decimal
        assert summary.overall_risk_score == round(summary.overall_risk_score, 1)

    def test_returns_findings_summary_type(self):
        n = _make_normalizer()
        summary = n.recalculate_summary([])
        assert isinstance(summary, FindingsSummary)


# ── _resolve_mutual_exclusions ─────────────────────────────────────────────────


class TestResolveMutualExclusions:
    def test_no_conflict_unchanged(self):
        # IAM-001 and IAM-003 are NOT in MUTUAL_EXCLUSIONS together
        n = _make_normalizer()
        findings = [_finding(id="IAM-001"), _finding(id="IAM-003")]
        result = n._resolve_mutual_exclusions(findings)
        assert len(result) == 2

    def test_keep_specific_keeps_higher_number(self):
        """HRD-001 vs HRD-006 → keep_specific → keep HRD-006 (higher number)."""
        n = _make_normalizer(skill="hardening", checklist=CHECKLIST)
        f1 = _finding(id="HRD-001", severity="Critical", risk_score=9.0)
        f2 = _finding(id="HRD-006", severity="High", risk_score=7.0)
        result = n._resolve_mutual_exclusions([f1, f2])
        ids = {f.id for f in result}
        assert "HRD-006" in ids
        assert "HRD-001" not in ids

    def test_keep_higher_keeps_higher_risk_score(self):
        """HRD-004 vs HRD-008 → keep_higher → keep higher risk_score."""
        n = _make_normalizer(skill="hardening", checklist=CHECKLIST)
        f1 = _finding(id="HRD-004", severity="Critical", risk_score=9.5)
        f2 = _finding(id="HRD-008", severity="High", risk_score=7.0)
        result = n._resolve_mutual_exclusions([f1, f2])
        ids = {f.id for f in result}
        assert "HRD-004" in ids
        assert "HRD-008" not in ids

    def test_only_one_of_pair_unchanged(self):
        n = _make_normalizer(skill="hardening", checklist=CHECKLIST)
        f1 = _finding(id="HRD-001")
        result = n._resolve_mutual_exclusions([f1])
        assert len(result) == 1

    def test_empty_findings_unchanged(self):
        n = _make_normalizer()
        assert n._resolve_mutual_exclusions([]) == []

    def test_non_conflicting_findings_all_kept(self):
        n = _make_normalizer()
        findings = [
            _finding(id="IAM-001", severity="Critical", risk_score=9.0),
            _finding(id="IAM-003", severity="Medium", risk_score=4.0),
        ]
        result = n._resolve_mutual_exclusions(findings)
        assert len(result) == 2
