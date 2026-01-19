"""Unit tests for validation modules.

Tests for:
- Checklist coverage validation
- Report validation
- Findings reviewer (mock)
"""

import pytest
from drystone.validation import (
    validate_checklist_coverage,
    validate_report_completeness,
    validate_report_format,
    get_unevaluated_checks,
)


class TestChecklistCoverage:
    """Tests for checklist coverage validation."""

    @pytest.fixture
    def sample_checklist(self):
        return {
            "skill": "iam",
            "items": [
                {"id": "IAM-001", "title": "Root account", "severity": "Critical"},
                {"id": "IAM-002", "title": "Access keys", "severity": "High"},
                {"id": "IAM-003", "title": "MFA", "severity": "High"},
            ]
        }

    @pytest.fixture
    def sample_findings(self):
        return [
            {
                "id": "f1",
                "checklist_ref": "IAM-001",
                "title": "Root account active",
                "severity": "Critical"
            },
            {
                "id": "f2",
                "checklist_ref": "IAM-002",
                "title": "Access keys exposed",
                "severity": "High"
            }
        ]

    def test_full_coverage(self, sample_checklist):
        """Test when all checks are evaluated."""
        findings = [
            {"id": "f1", "checklist_ref": "IAM-001"},
            {"id": "f2", "checklist_ref": "IAM-002"},
            {"id": "f3", "checklist_ref": "IAM-003"},
        ]

        result = validate_checklist_coverage(sample_checklist, findings)

        assert result["coverage_valid"] is True
        assert result["total_checks"] == 3
        assert result["evaluated_checks"] == 3
        assert result["coverage_percentage"] == 100.0
        assert result["missing_checks"] == []

    def test_partial_coverage(self, sample_checklist, sample_findings):
        """Test when some checks are missing."""
        result = validate_checklist_coverage(sample_checklist, sample_findings)

        assert result["coverage_valid"] is False
        assert result["total_checks"] == 3
        assert result["evaluated_checks"] == 2
        assert result["coverage_percentage"] == pytest.approx(66.67, 0.01)
        assert result["missing_checks"] == ["IAM-003"]

    def test_no_findings(self, sample_checklist):
        """Test with no findings (clean audit)."""
        result = validate_checklist_coverage(sample_checklist, [])

        assert result["coverage_valid"] is False
        assert result["total_checks"] == 3
        assert result["evaluated_checks"] == 0
        assert result["coverage_percentage"] == 0.0
        assert len(result["missing_checks"]) == 3

    def test_empty_checklist(self):
        """Test with empty checklist."""
        result = validate_checklist_coverage({"items": []}, [])

        assert result["coverage_valid"] is True
        assert result["total_checks"] == 0
        assert result["coverage_percentage"] == 100.0

    def test_detailed_output(self, sample_checklist, sample_findings):
        """Test that details are properly formatted."""
        result = validate_checklist_coverage(sample_checklist, sample_findings)

        assert len(result["details"]) == 3

        # Check first item (evaluated)
        detail_iam001 = next(d for d in result["details"] if d["check_id"] == "IAM-001")
        assert detail_iam001["evaluated"] is True
        assert detail_iam001["finding_id"] == "f1"
        assert detail_iam001["check_title"] == "Root account"

        # Check third item (not evaluated)
        detail_iam003 = next(d for d in result["details"] if d["check_id"] == "IAM-003")
        assert detail_iam003["evaluated"] is False
        assert detail_iam003["finding_id"] is None


class TestReportValidation:
    """Tests for report validation."""

    @pytest.fixture
    def sample_findings(self):
        return [
            {"id": "IAM-001", "title": "Root account"},
            {"id": "IAM-002", "title": "Access keys"},
        ]

    @pytest.fixture
    def complete_report(self):
        return """# AWS Security Audit Report

## Executive Summary
This audit identified 2 findings.

## Findings
### IAM-001: Root account in use
Evidence shows root account used for daily operations.

### IAM-002: Access keys exposed
Evidence shows access keys in GitHub.

## Remediation
- Delete root access keys
- Create IAM users instead
"""

    def test_complete_report(self, sample_findings, complete_report):
        """Test validation of complete report."""
        result = validate_report_completeness(
            complete_report,
            sample_findings,
            format_type="markdown"
        )

        assert result["report_valid"] is True
        assert result["total_findings"] == 2
        assert result["referenced_findings"] == 2
        assert result["findings_coverage_percentage"] == 100.0
        assert result["missing_sections"] == []
        assert result["unreferenced_findings"] == []
        assert len(result["gaps"]) == 0

    def test_missing_section(self, sample_findings):
        """Test report missing a required section."""
        incomplete_report = "# Report\n## Findings\n- IAM-001\n"

        result = validate_report_completeness(
            incomplete_report,
            sample_findings,
            format_type="markdown"
        )

        assert result["report_valid"] is False
        assert "executive summary" in result["missing_sections"]
        assert len(result["gaps"]) > 0

    def test_unreferenced_finding(self, sample_findings, complete_report):
        """Test when a finding is not mentioned in report."""
        incomplete_findings = [
            {"id": "IAM-001", "title": "Root account"},
            {"id": "IAM-002", "title": "Access keys"},
            {"id": "IAM-003", "title": "New finding not in report"},
        ]

        result = validate_report_completeness(
            complete_report,
            incomplete_findings,
            format_type="markdown"
        )

        assert result["report_valid"] is False
        assert "IAM-003" in result["unreferenced_findings"]

    def test_empty_report(self, sample_findings):
        """Test validation of empty report."""
        result = validate_report_completeness("", sample_findings)

        assert result["report_valid"] is False
        assert len(result["gaps"]) > 0

    def test_html_format(self, sample_findings):
        """Test HTML format validation."""
        html_report = """<html>
<h2>Executive Summary</h2>
<h2>Findings</h2>
<p>IAM-001: Root account</p>
<p>IAM-002: Access keys</p>
<h2>Remediation</h2>
</html>"""

        result = validate_report_completeness(
            html_report,
            sample_findings,
            format_type="html"
        )

        assert result["report_valid"] is True
        assert result["format"] == "html"


class TestReportFormat:
    """Tests for report format validation."""

    def test_valid_markdown_format(self):
        """Test valid markdown structure."""
        markdown = """# Title
## Section 1
- Item 1
- Item 2

```python
code block
```

## Section 2
"""

        result = validate_report_format(markdown, format_type="markdown")
        assert result["format_valid"] is True
        assert len(result["issues"]) == 0

    def test_unbalanced_code_blocks(self):
        """Test markdown with unbalanced code blocks."""
        markdown = """# Title
```python
code block without close
"""

        result = validate_report_format(markdown, format_type="markdown")
        assert result["format_valid"] is False
        assert any("unbalanced" in issue.lower() for issue in result["issues"])

    def test_no_headers(self):
        """Test markdown with no headers."""
        markdown = "Just some text without any headers"

        result = validate_report_format(markdown, format_type="markdown")
        assert result["format_valid"] is False

    def test_valid_html_format(self):
        """Test valid HTML structure."""
        html = """<div>
<p>Paragraph 1</p>
<p>Paragraph 2</p>
</div>"""

        result = validate_report_format(html, format_type="html")
        assert result["format_valid"] is True

    def test_unknown_format(self):
        """Test unknown format type."""
        result = validate_report_format("text", format_type="unknown")
        assert result["format_valid"] is False
        assert any("unknown" in issue.lower() for issue in result["issues"])


class TestGetUnevaluatedChecks:
    """Tests for getting unevaluated checks."""

    def test_get_unevaluated_checks(self):
        """Test extraction of unevaluated checks."""
        checklist = {
            "items": [
                {"id": "IAM-001", "title": "Root"},
                {"id": "IAM-002", "title": "Keys"},
                {"id": "IAM-003", "title": "MFA"},
            ]
        }
        findings = [
            {"id": "f1", "checklist_ref": "IAM-001"}
        ]

        unevaluated = get_unevaluated_checks(checklist, findings)

        assert len(unevaluated) == 2
        assert all(item["id"] in ["IAM-002", "IAM-003"] for item in unevaluated)

    def test_all_evaluated(self):
        """Test when all checks are evaluated."""
        checklist = {
            "items": [
                {"id": "IAM-001", "title": "Root"},
            ]
        }
        findings = [
            {"id": "f1", "checklist_ref": "IAM-001"}
        ]

        unevaluated = get_unevaluated_checks(checklist, findings)

        assert len(unevaluated) == 0


class TestReportSuggestions:
    """Tests for report fix suggestions."""

    def test_suggestions_for_missing_sections(self):
        """Test that suggestions are generated for missing sections."""
        from drystone.validation.report_validator import suggest_report_fixes

        validation = {
            "report_valid": False,
            "missing_sections": ["executive summary", "remediation"],
            "unreferenced_findings": [],
        }

        suggestions = suggest_report_fixes(validation)

        assert any("executive summary" in s.lower() for s in suggestions)
        assert any("remediation" in s.lower() for s in suggestions)

    def test_suggestions_for_unreferenced_findings(self):
        """Test suggestions for unreferenced findings."""
        from drystone.validation.report_validator import suggest_report_fixes

        validation = {
            "report_valid": False,
            "missing_sections": [],
            "unreferenced_findings": ["IAM-001", "IAM-002"],
        }

        suggestions = suggest_report_fixes(validation)

        assert any("IAM-001" in s for s in suggestions)
        assert any("IAM-002" in s for s in suggestions)
