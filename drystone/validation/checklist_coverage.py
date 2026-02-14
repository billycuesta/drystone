"""Programmatic checklist coverage validation.

Ensures 100% of checklist items are evaluated, regardless of findings.
This validation is deterministic, cost-free, and guaranteed to be accurate.
"""

from typing import Any, Dict, List, Set


def validate_checklist_coverage(
    checklist: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Verify all checklist items were evaluated in the analysis.

    Compares checklist item IDs against findings to identify gaps.
    This is a deterministic check with no false positives.

    Args:
        checklist: Checklist dict with 'items' list containing 'id' fields
        findings: List of findings dicts, each with 'checklist_ref' field

    Returns:
        dict: {
            "coverage_valid": bool,
            "total_checks": int,
            "evaluated_checks": int,
            "coverage_percentage": float,
            "missing_checks": list[str],  # IDs of unevaluated items
            "details": [
                {
                    "check_id": "IAM-001",
                    "check_title": "...",
                    "evaluated": bool,
                    "finding_id": "finding-123" if evaluated else None
                }
            ]
        }

    Example:
        >>> checklist = {
        ...     "items": [
        ...         {"id": "IAM-001", "title": "Root account"},
        ...         {"id": "IAM-002", "title": "Access keys"},
        ...     ]
        ... }
        >>> findings = [
        ...     {"id": "f1", "checklist_ref": "IAM-001", "title": "..."}
        ... ]
        >>> result = validate_checklist_coverage(checklist, findings)
        >>> result["coverage_percentage"]
        50.0
        >>> result["missing_checks"]
        ["IAM-002"]
    """

    # Extract check IDs and their metadata
    checklist_items = {
        item["id"]: item for item in checklist.get("items", [])
    }
    total_checks = len(checklist_items)

    # Extract evaluated check IDs from findings
    evaluated_checks: Set[str] = set()
    finding_mapping: Dict[str, str] = {}

    for finding in findings:
        checklist_ref = finding.get("checklist_ref")
        if checklist_ref and checklist_ref in checklist_items:
            evaluated_checks.add(checklist_ref)
            finding_mapping[checklist_ref] = finding.get("id", "unknown")

    # Calculate coverage
    num_evaluated = len(evaluated_checks)
    coverage_percentage = (
        (num_evaluated / total_checks * 100) if total_checks > 0 else 100.0
    )

    # Identify missing checks
    missing_checks = sorted(list(checklist_items.keys() - evaluated_checks))

    # Build detailed report
    details = []
    for check_id in sorted(checklist_items.keys()):
        is_evaluated = check_id in evaluated_checks
        details.append({
            "check_id": check_id,
            "check_title": checklist_items[check_id].get("title", ""),
            "check_severity": checklist_items[check_id].get("severity", "Unknown"),
            "evaluated": is_evaluated,
            "finding_id": finding_mapping.get(check_id) if is_evaluated else None,
        })

    return {
        "coverage_valid": len(missing_checks) == 0,
        "total_checks": total_checks,
        "evaluated_checks": num_evaluated,
        "coverage_percentage": coverage_percentage,
        "missing_checks": missing_checks,
        "details": details,
    }


def get_unevaluated_checks(
    checklist: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Get list of unevaluated checklist items for re-analysis.

    Useful for focused re-analysis of missing checks.

    Args:
        checklist: Full checklist
        findings: Current findings

    Returns:
        list: Checklist items that were not evaluated
    """
    coverage = validate_checklist_coverage(checklist, findings)
    missing_ids = set(coverage["missing_checks"])

    unevaluated = [
        item for item in checklist.get("items", [])
        if item["id"] in missing_ids
    ]

    return unevaluated
