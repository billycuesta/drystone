"""Tests for checklist coverage validation."""

import pytest

from drystone.validation.checklist_coverage import (
    get_unevaluated_checks,
    validate_checklist_coverage,
)


def _make_checklist(items):
    """Helper to create checklist dict."""
    return {"items": items}


def _make_finding(finding_id, title="Finding"):
    """Helper to create finding dict."""
    return {"id": finding_id, "title": title, "severity": "High"}


class TestValidateChecklistCoverage:
    """Tests for validate_checklist_coverage()."""

    def test_full_coverage(self):
        """All checklist items evaluated → 100% coverage."""
        checklist = _make_checklist([
            {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
            {"id": "IAM-002", "title": "Access keys", "severity": "High"},
        ])
        findings = [
            _make_finding("IAM-001"),
            _make_finding("IAM-002"),
        ]
        result = validate_checklist_coverage(checklist, findings)

        assert result["coverage_valid"] is True
        assert result["total_checks"] == 2
        assert result["evaluated_checks"] == 2
        assert result["coverage_percentage"] == 100.0
        assert result["missing_checks"] == []

    def test_partial_coverage(self):
        """Only some checklist items evaluated."""
        checklist = _make_checklist([
            {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
            {"id": "IAM-002", "title": "Access keys", "severity": "High"},
            {"id": "IAM-003", "title": "Password policy", "severity": "Medium"},
        ])
        findings = [_make_finding("IAM-001")]
        result = validate_checklist_coverage(checklist, findings)

        assert result["coverage_valid"] is False
        assert result["evaluated_checks"] == 1
        assert result["total_checks"] == 3
        assert abs(result["coverage_percentage"] - 33.33) < 1.0
        assert "IAM-002" in result["missing_checks"]
        assert "IAM-003" in result["missing_checks"]

    def test_zero_findings(self):
        """No findings at all → 0% coverage."""
        checklist = _make_checklist([
            {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
        ])
        result = validate_checklist_coverage(checklist, [])

        assert result["coverage_valid"] is False
        assert result["evaluated_checks"] == 0
        assert result["coverage_percentage"] == 0.0
        assert result["missing_checks"] == ["IAM-001"]

    def test_empty_checklist(self):
        """Empty checklist → 100% coverage (vacuously true)."""
        checklist = _make_checklist([])
        result = validate_checklist_coverage(checklist, [_make_finding("X-001")])

        assert result["coverage_valid"] is True
        assert result["coverage_percentage"] == 100.0

    def test_finding_ids_match_checklist_ids(self):
        """Finding IDs directly match checklist item IDs (the fixed behavior)."""
        checklist = _make_checklist([
            {"id": "NET-001", "title": "SG rules", "severity": "High"},
            {"id": "NET-002", "title": "NACL rules", "severity": "Medium"},
        ])
        # Findings use the same ID format as checklist items
        findings = [
            {"id": "NET-001", "title": "Open SG", "severity": "High"},
            {"id": "NET-002", "title": "Default NACL", "severity": "Medium"},
        ]
        result = validate_checklist_coverage(checklist, findings)

        assert result["coverage_valid"] is True
        assert result["evaluated_checks"] == 2

    def test_details_contain_severity(self):
        """Details include check_severity for missing critical detection."""
        checklist = _make_checklist([
            {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
            {"id": "IAM-002", "title": "Access keys", "severity": "Low"},
        ])
        findings = [_make_finding("IAM-002")]
        result = validate_checklist_coverage(checklist, findings)

        # Find the missing critical
        missing_criticals = [
            d for d in result["details"]
            if not d["evaluated"] and d["check_severity"] == "Critical"
        ]
        assert len(missing_criticals) == 1
        assert missing_criticals[0]["check_id"] == "IAM-001"

    def test_extra_findings_ignored(self):
        """Findings with IDs not in checklist are ignored (no errors)."""
        checklist = _make_checklist([
            {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
        ])
        findings = [
            _make_finding("IAM-001"),
            _make_finding("IAM-999"),  # Not in checklist
        ]
        result = validate_checklist_coverage(checklist, findings)

        assert result["coverage_valid"] is True
        assert result["evaluated_checks"] == 1


class TestGetUnevaluatedChecks:
    """Tests for get_unevaluated_checks()."""

    def test_returns_unevaluated_items(self):
        """Returns checklist items that were not covered by findings."""
        checklist = _make_checklist([
            {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
            {"id": "IAM-002", "title": "Access keys", "severity": "High"},
        ])
        findings = [_make_finding("IAM-001")]
        unevaluated = get_unevaluated_checks(checklist, findings)

        assert len(unevaluated) == 1
        assert unevaluated[0]["id"] == "IAM-002"

    def test_all_evaluated_returns_empty(self):
        """Returns empty list when all items covered."""
        checklist = _make_checklist([
            {"id": "IAM-001", "title": "Root MFA", "severity": "Critical"},
        ])
        findings = [_make_finding("IAM-001")]
        unevaluated = get_unevaluated_checks(checklist, findings)

        assert unevaluated == []
