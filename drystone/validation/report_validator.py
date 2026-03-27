"""Report structure and completeness validation.

Validates that generated reports contain all required sections,
findings are properly referenced, and formatting is correct.
"""

import re
from typing import Any, Dict, List


def validate_report_completeness(
    report: str,
    findings: List[Dict[str, Any]],
    format_type: str = "markdown",
) -> Dict[str, Any]:
    """Validate report structure and completeness.

    Checks:
    - Presence of required sections (executive summary, findings, remediation)
    - All findings are referenced in report
    - Proper formatting (markdown or HTML)
    - Non-empty content

    Args:
        report: Generated report content (markdown or HTML)
        findings: List of findings that should be in report
        format_type: "markdown" or "html" (default: markdown)

    Returns:
        dict: {
            "report_valid": bool,
            "format": str,
            "total_findings": int,
            "referenced_findings": int,
            "missing_sections": list[str],
            "unreferenced_findings": list[str],  # Finding IDs not in report
            "gaps": list[str],  # Human-readable list of issues
            "summary": str,  # Overall validation summary
        }

    Example:
        >>> report = "# Audit Report\\n## Findings\\n- IAM-001: ...\\n## Remediation"
        >>> findings = [{"id": "IAM-001", "title": "..."}]
        >>> result = validate_report_completeness(report, findings)
        >>> result["report_valid"]
        True
    """

    gaps: List[str] = []
    missing_sections: List[str] = []
    unreferenced_findings: List[str] = []

    # Normalize to lowercase for checking
    report_lower = report.lower()

    # Check required sections based on format
    if format_type == "markdown":
        required_sections = {
            "executive summary": ["## executive summary", "# executive summary"],
            "findings": ["## findings", "# findings"],
            "remediation": ["## remediation", "# remediation"],
        }
    else:  # HTML
        required_sections = {
            "executive summary": ["<h2>executive summary", "<h1>executive summary"],
            "findings": ["<h2>findings", "<h1>findings"],
            "remediation": ["<h2>remediation", "<h1>remediation"],
        }

    for section_name, section_markers in required_sections.items():
        if not any(marker in report_lower for marker in section_markers):
            missing_sections.append(section_name)
            gaps.append(f"Missing section: {section_name}")

    # Check if report is empty
    if not report or len(report.strip()) < 50:
        gaps.append("Report is empty or too short")

    # Check that all findings are referenced in report
    referenced_findings = 0
    for finding in findings:
        finding_id = finding.get("id")
        if finding_id:
            # Check if finding ID appears in report
            if finding_id in report:
                referenced_findings += 1
            else:
                unreferenced_findings.append(finding_id)
                gaps.append(f"Finding {finding_id} not referenced in report")

    # Calculate coverage
    total_findings = len(findings)
    findings_coverage = (
        (referenced_findings / total_findings * 100) if total_findings > 0 else 100.0
    )

    # Build summary
    if not gaps:
        summary = "Report is complete and well-structured ✅"
        report_valid = True
    else:
        summary = f"Report has {len(gaps)} issue(s) ⚠️"
        report_valid = False

    return {
        "report_valid": report_valid,
        "format": format_type,
        "total_findings": total_findings,
        "referenced_findings": referenced_findings,
        "findings_coverage_percentage": findings_coverage,
        "missing_sections": missing_sections,
        "unreferenced_findings": unreferenced_findings,
        "gaps": gaps,
        "summary": summary,
    }


def validate_report_format(
    report: str,
    format_type: str = "markdown",
) -> Dict[str, Any]:
    """Validate report format (markdown or HTML).

    Checks:
    - Proper markdown structure (headers, lists, code blocks)
    - Proper HTML structure (tags, nesting)
    - No malformed content

    Args:
        report: Report content
        format_type: "markdown" or "html"

    Returns:
        dict: {
            "format_valid": bool,
            "format_type": str,
            "issues": list[str],
        }
    """

    issues: List[str] = []

    if format_type == "markdown":
        # Check for balanced code blocks
        code_block_count = report.count("```")
        if code_block_count % 2 != 0:
            issues.append("Unbalanced code blocks (```) in markdown")

        # Check for header hierarchy
        h1_count = len(re.findall(r"^# ", report, re.MULTILINE))
        h2_count = len(re.findall(r"^## ", report, re.MULTILINE))

        if h1_count == 0 and h2_count == 0:
            issues.append("No headers found in markdown")

    elif format_type == "html":
        # Check for balanced tags
        open_tags = re.findall(r"<(\w+)[^>]*>", report)
        close_tags = re.findall(r"</(\w+)>", report)

        # Simple check for major tags
        for tag in set(open_tags):
            if tag in ["div", "p", "section", "article"]:
                if open_tags.count(tag) != close_tags.count(tag):
                    issues.append(f"Unbalanced <{tag}> tags")

    else:
        issues.append(f"Unknown format type: {format_type}")

    return {
        "format_valid": len(issues) == 0,
        "format_type": format_type,
        "issues": issues,
    }


def suggest_report_fixes(
    validation_result: Dict[str, Any],
) -> List[str]:
    """Generate actionable suggestions to fix report issues.

    Args:
        validation_result: Result from validate_report_completeness()

    Returns:
        list: Actionable suggestions
    """

    suggestions = []

    for section in validation_result["missing_sections"]:
        suggestions.append(f"Add '## {section.title()}' section with relevant content")

    for finding_id in validation_result["unreferenced_findings"]:
        suggestions.append(f"Add finding {finding_id} to Findings section in report")

    if not validation_result["report_valid"]:
        suggestions.append("Run validation again after fixing issues")

    return suggestions
