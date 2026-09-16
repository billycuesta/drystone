"""Vulns (VULN-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id not in {
        "VULN-002",
        "VULN-004",
        "VULN-008",
        "VULN-010",
        "VULN-011",
        "VULN-009",
        "VULN-023",
        "VULN-024",
    }:
        return None

    resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
    if not resource_details:
        return None

    evidence_files = {
        "VULN-002": "inspector-findings.json",
        "VULN-004": "inspector-findings.json",
        "VULN-008": "inspector-findings.json",
        "VULN-010": "inspector-findings.json",
        "VULN-011": "ecr-image-scans.json",
        "VULN-009": "inspector-findings.json",
        "VULN-023": "ec2-user-data.json",
        "VULN-024": "lambda-environment-variables.json",
    }
    summaries = {
        "VULN-002": f"{len(resource_details)} CRITICAL active Inspector finding(s)",
        "VULN-004": f"{len(resource_details)} ACTIVE Inspector finding(s) with exploitAvailable=YES",
        "VULN-008": f"{len(resource_details)} ACTIVE HIGH Inspector finding(s) requiring remediation tracking",
        "VULN-010": f"{len(resource_details)} ACTIVE HIGH/CRITICAL Inspector finding(s) on EC2 service instances",
        "VULN-011": f"{len(resource_details)} ECR scan configuration item(s) explicitly disabled",
        "VULN-009": f"{len(resource_details)} resource(s) with 3+ active CVEs",
        "VULN-023": f"{len(resource_details)} instance(s) with secret-like user-data",
        "VULN-024": f"{len(resource_details)} Lambda function(s) with sensitive env keys",
    }
    detail_refs: List[str] = []
    for detail in resource_details:
        if not isinstance(detail, dict):
            continue
        if detail.get("evidence_ref"):
            detail_refs.append(str(detail.get("evidence_ref")))
        for ref in detail.get("evidence_refs") or []:
            detail_refs.append(str(ref))
    return (
        dedupe_refs(detail_refs or [evidence_files[check_id]])[:50],
        {
            "evidence_summary": summaries[check_id],
            "affected_resources": resource_details,
        },
    )
