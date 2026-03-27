"""Tests for report structure and completeness validation."""

import pytest

from drystone.validation.report_validator import (
    suggest_report_fixes,
    validate_report_completeness,
    validate_report_format,
)

# ── fixtures ──────────────────────────────────────────────────────────────────

VALID_MARKDOWN = """# Audit Report

## Executive Summary
This report covers the IAM security audit.

## Findings
- IAM-001: Root account has active access keys
- IAM-002: MFA not enabled for all users

## Remediation
Apply MFA to all accounts and rotate access keys.
"""

VALID_HTML = """<h1>Audit Report</h1>
<h2>Executive Summary</h2>
<p>This report covers the IAM security audit.</p>
<h2>Findings</h2>
<p>IAM-001: Root account has active access keys</p>
<p>IAM-002: MFA not enabled for all users</p>
<h2>Remediation</h2>
<p>Apply MFA to all accounts and rotate access keys.</p>
"""

FINDINGS = [
    {"id": "IAM-001", "title": "Root account has active access keys"},
    {"id": "IAM-002", "title": "MFA not enabled for all users"},
]


# ── validate_report_completeness: happy path ──────────────────────────────────


class TestValidateReportCompletenessValid:
    def test_valid_markdown_report_passes(self):
        result = validate_report_completeness(VALID_MARKDOWN, FINDINGS, "markdown")
        assert result["report_valid"] is True
        assert result["missing_sections"] == []
        assert result["unreferenced_findings"] == []
        assert result["gaps"] == []

    def test_valid_html_report_passes(self):
        result = validate_report_completeness(VALID_HTML, FINDINGS, "html")
        assert result["report_valid"] is True
        assert result["missing_sections"] == []

    def test_all_findings_referenced(self):
        result = validate_report_completeness(VALID_MARKDOWN, FINDINGS)
        assert result["referenced_findings"] == 2
        assert result["total_findings"] == 2
        assert result["findings_coverage_percentage"] == 100.0

    def test_no_findings_gives_full_coverage(self):
        result = validate_report_completeness(VALID_MARKDOWN, [])
        assert result["findings_coverage_percentage"] == 100.0
        assert result["total_findings"] == 0

    def test_summary_contains_ok_indicator(self):
        result = validate_report_completeness(VALID_MARKDOWN, FINDINGS)
        assert "✅" in result["summary"]

    def test_format_field_matches_input(self):
        result = validate_report_completeness(VALID_MARKDOWN, FINDINGS, "markdown")
        assert result["format"] == "markdown"

        result = validate_report_completeness(VALID_HTML, FINDINGS, "html")
        assert result["format"] == "html"


# ── validate_report_completeness: missing sections ────────────────────────────


class TestValidateReportCompletenessMissingSections:
    def test_missing_executive_summary_detected(self):
        report = "## Findings\n- IAM-001\n\n## Remediation\nFix it."
        result = validate_report_completeness(report, [], "markdown")
        assert "executive summary" in result["missing_sections"]
        assert any("executive summary" in g for g in result["gaps"])

    def test_missing_findings_section_detected(self):
        report = "## Executive Summary\nSummary.\n\n## Remediation\nFix it."
        result = validate_report_completeness(report, [], "markdown")
        assert "findings" in result["missing_sections"]

    def test_missing_remediation_section_detected(self):
        report = "## Executive Summary\nSummary.\n\n## Findings\n- IAM-001"
        result = validate_report_completeness(report, [], "markdown")
        assert "remediation" in result["missing_sections"]

    def test_all_sections_missing_marks_invalid(self):
        report = "Some random text without proper sections and it is long enough."
        result = validate_report_completeness(report, [], "markdown")
        assert result["report_valid"] is False
        assert len(result["missing_sections"]) == 3

    def test_section_check_is_case_insensitive(self):
        report = "## EXECUTIVE SUMMARY\nX\n## FINDINGS\nY\n## REMEDIATION\nZ"
        result = validate_report_completeness(report, [], "markdown")
        assert result["missing_sections"] == []

    def test_html_sections_detected_correctly(self):
        report = "<h2>Executive Summary</h2><p>x</p><h2>Findings</h2><p>y</p><h2>Remediation</h2><p>z</p>"
        result = validate_report_completeness(report, [], "html")
        assert result["missing_sections"] == []


# ── validate_report_completeness: unreferenced findings ───────────────────────


class TestValidateReportCompletenessUnreferencedFindings:
    def test_unreferenced_finding_detected(self):
        report = VALID_MARKDOWN.replace("IAM-002", "REDACTED")
        result = validate_report_completeness(report, FINDINGS)
        assert "IAM-002" in result["unreferenced_findings"]
        assert result["referenced_findings"] == 1

    def test_all_unreferenced_marks_invalid(self):
        report = "## Executive Summary\nx\n## Findings\nnone\n## Remediation\nfix"
        result = validate_report_completeness(report, FINDINGS)
        assert result["report_valid"] is False
        assert len(result["unreferenced_findings"]) == 2

    def test_findings_without_id_are_skipped(self):
        findings = [{"title": "No ID finding"}]
        result = validate_report_completeness(VALID_MARKDOWN, findings)
        assert result["unreferenced_findings"] == []

    def test_coverage_percentage_partial(self):
        report = VALID_MARKDOWN.replace("IAM-002", "REDACTED")
        result = validate_report_completeness(report, FINDINGS)
        assert result["findings_coverage_percentage"] == pytest.approx(50.0)


# ── validate_report_completeness: empty/short report ─────────────────────────


class TestValidateReportCompletenessEmptyReport:
    def test_empty_report_marked_invalid(self):
        result = validate_report_completeness("", [], "markdown")
        assert result["report_valid"] is False
        assert any("empty" in g.lower() for g in result["gaps"])

    def test_short_report_marked_invalid(self):
        result = validate_report_completeness("Too short.", [], "markdown")
        assert result["report_valid"] is False

    def test_summary_contains_issue_count_when_invalid(self):
        result = validate_report_completeness("", [], "markdown")
        assert "issue" in result["summary"]
        assert "⚠️" in result["summary"]


# ── validate_report_format: markdown ─────────────────────────────────────────


class TestValidateReportFormatMarkdown:
    def test_valid_markdown_passes(self):
        result = validate_report_format(VALID_MARKDOWN, "markdown")
        assert result["format_valid"] is True
        assert result["issues"] == []

    def test_unbalanced_code_blocks_detected(self):
        report = "# Title\n```python\ncode here\n# missing closing fence"
        result = validate_report_format(report, "markdown")
        assert result["format_valid"] is False
        assert any("code block" in i.lower() for i in result["issues"])

    def test_balanced_code_blocks_pass(self):
        report = "# Title\n```python\ncode\n```\n## Section\ntext"
        result = validate_report_format(report, "markdown")
        assert result["format_valid"] is True

    def test_no_headers_detected(self):
        report = "Just plain text without any headers present in the document."
        result = validate_report_format(report, "markdown")
        assert result["format_valid"] is False
        assert any("header" in i.lower() for i in result["issues"])

    def test_format_type_in_result(self):
        result = validate_report_format(VALID_MARKDOWN, "markdown")
        assert result["format_type"] == "markdown"


# ── validate_report_format: html ─────────────────────────────────────────────


class TestValidateReportFormatHTML:
    def test_valid_html_passes(self):
        result = validate_report_format(VALID_HTML, "html")
        assert result["format_valid"] is True
        assert result["issues"] == []

    def test_unbalanced_div_tags_detected(self):
        report = "<div><p>content</p><div>nested"  # missing closing divs
        result = validate_report_format(report, "html")
        assert result["format_valid"] is False
        assert any("div" in i for i in result["issues"])

    def test_balanced_div_tags_pass(self):
        report = "<div><p>content</p></div>"
        result = validate_report_format(report, "html")
        assert result["format_valid"] is True

    def test_unknown_format_type_flagged(self):
        result = validate_report_format("content", "pdf")
        assert result["format_valid"] is False
        assert any("unknown" in i.lower() for i in result["issues"])


# ── suggest_report_fixes ──────────────────────────────────────────────────────


class TestSuggestReportFixes:
    def test_no_suggestions_when_valid(self):
        result = validate_report_completeness(VALID_MARKDOWN, FINDINGS)
        suggestions = suggest_report_fixes(result)
        assert suggestions == []

    def test_suggests_adding_missing_section(self):
        report = "## Findings\n- IAM-001\n\n## Remediation\nFix it."
        result = validate_report_completeness(report, [], "markdown")
        suggestions = suggest_report_fixes(result)
        assert any("executive summary" in s.lower() for s in suggestions)

    def test_suggests_adding_unreferenced_finding(self):
        report = VALID_MARKDOWN.replace("IAM-002", "REDACTED")
        result = validate_report_completeness(report, FINDINGS)
        suggestions = suggest_report_fixes(result)
        assert any("IAM-002" in s for s in suggestions)

    def test_suggests_rerun_when_invalid(self):
        result = validate_report_completeness("", FINDINGS)
        suggestions = suggest_report_fixes(result)
        assert any("validation" in s.lower() for s in suggestions)

    def test_multiple_issues_produce_multiple_suggestions(self):
        report = "## Findings\n- IAM-001\n\n## Remediation\nFix it."
        result = validate_report_completeness(report, FINDINGS)
        suggestions = suggest_report_fixes(result)
        # Missing executive summary + unreferenced IAM-002 + rerun = at least 3
        assert len(suggestions) >= 2
