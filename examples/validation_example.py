#!/usr/bin/env python
"""Example: Using the Drystone Validation Module

Demonstrates all three levels of validation:
1. Checklist coverage (programmatic, free)
2. Findings quality review (agent, $0.02)
3. Report validation (static checks)
"""

import json
from pathlib import Path
from drystone.validation import (
    validate_checklist_coverage,
    get_unevaluated_checks,
    FindingsReviewer,
    validate_report_completeness,
    validate_report_format,
    suggest_report_fixes,
)

# Sample data
SAMPLE_CHECKLIST = {
    "skill": "iam",
    "items": [
        {
            "id": "IAM-001",
            "title": "Avoid root account usage",
            "severity": "Critical",
            "framework": "CIS AWS Foundations 1.1"
        },
        {
            "id": "IAM-002",
            "title": "Enable MFA for all users",
            "severity": "High",
            "framework": "CIS AWS Foundations 1.2"
        },
        {
            "id": "IAM-003",
            "title": "Rotate access keys regularly",
            "severity": "High",
            "framework": "CIS AWS Foundations 1.3"
        },
    ]
}

SAMPLE_FINDINGS = [
    {
        "id": "IAM-001",
        "checklist_ref": "IAM-001",
        "title": "Root account has active access keys",
        "severity": "Critical",
        "risk_score": 9.5,
        "description": "Root account was found to have active access keys.",
        "remediation": "Delete root access keys. Use IAM users instead.",
        "evidence_refs": ["users.root.access_keys[0]"]
    },
    {
        "id": "IAM-002",
        "checklist_ref": "IAM-002",
        "title": "MFA not enabled on root account",
        "severity": "Critical",
        "risk_score": 9.0,
        "description": "MFA is not enabled on the root account.",
        "remediation": "Enable MFA on root account using AWS console.",
        "evidence_refs": ["users.root.mfa_devices"]
    }
]

SAMPLE_REPORT = """# AWS IAM Security Audit Report

## Executive Summary

This audit evaluated 3 critical IAM security checks and identified 2 significant findings.
Immediate action is required to remediate critical vulnerabilities.

## Findings

### IAM-001: Root account has active access keys

**Severity:** Critical (9.5/10)

Root account was found to have active access keys. This is a critical security issue
as it provides direct access to all AWS resources without audit trail restrictions.

**Evidence:**
- Root access keys are present and active
- No rotation policy detected

### IAM-002: MFA not enabled on root account

**Severity:** Critical (9.0/10)

MFA is not enabled on the root account. This significantly increases risk of account
compromise through credential theft or brute force attacks.

**Evidence:**
- Root account has no MFA devices configured
- All users should have MFA enabled

## Remediation

### Immediate Actions

1. **Delete root access keys** (for IAM-001)
   - Sign into AWS console as root account
   - Navigate to Security Credentials
   - Delete all access keys
   - Create IAM users for day-to-day operations

2. **Enable MFA on root account** (for IAM-002)
   - Use AWS Authenticator app or hardware token
   - Complete MFA setup in Security Credentials
   - Test MFA authentication

### Long-term Actions

- Implement password rotation policy
- Enable CloudTrail for root account activity
- Set up SNS alerts for root account API usage
- Use AWS Organizations for multi-account management
"""


def example_1_checklist_coverage():
    """Example 1: Validate checklist coverage."""
    print("=" * 70)
    print("EXAMPLE 1: Checklist Coverage Validation (FREE)")
    print("=" * 70)

    result = validate_checklist_coverage(SAMPLE_CHECKLIST, SAMPLE_FINDINGS)

    print(f"✅ Coverage Valid: {result['coverage_valid']}")
    print(f"📊 Coverage: {result['coverage_percentage']:.1f}% "
          f"({result['evaluated_checks']}/{result['total_checks']} checks)")

    if result["missing_checks"]:
        print(f"\n⚠️  Missing checks: {result['missing_checks']}")

        # Get unevaluated checks for re-analysis
        unevaluated = get_unevaluated_checks(SAMPLE_CHECKLIST, SAMPLE_FINDINGS)
        print(f"\nUnevaluated items (for re-analysis):")
        for item in unevaluated:
            print(f"  - {item['id']}: {item['title']}")
    else:
        print("\n✅ All checklist items evaluated!")

    print()


def example_2_quality_review():
    """Example 2: Quality review (requires Anthropic API key)."""
    print("=" * 70)
    print("EXAMPLE 2: Findings Quality Review (AGENT, $0.02)")
    print("=" * 70)

    # This example shows the structure but requires ANTHROPIC_API_KEY
    print("\n⚠️  SKIPPED: Requires ANTHROPIC_API_KEY environment variable")
    print("\nTo use quality review in production:")
    print("""
from anthropic import Anthropic

client = Anthropic()
reviewer = FindingsReviewer(client)

result = reviewer.validate(
    skill="iam",
    evidence=evidence_dict,
    checklist=checklist,
    findings=findings,
)

print(f"Status: {result['validation_status']}")
print(f"Confidence: {result['confidence_score']:.2f}")

if result['severity_mismatches']:
    print("\\nSeverity mismatches found:")
    for mismatch in result['severity_mismatches']:
        print(f"  - {mismatch['finding_id']}: "
              f"{mismatch['agent_severity']} → {mismatch['recommended_severity']}")
""")
    print()


def example_3_report_validation():
    """Example 3: Report validation."""
    print("=" * 70)
    print("EXAMPLE 3: Report Validation (FREE)")
    print("=" * 70)

    # Validate completeness
    completeness = validate_report_completeness(SAMPLE_REPORT, SAMPLE_FINDINGS)

    print(f"✅ Report Valid: {completeness['report_valid']}")
    print(f"📄 Format: {completeness['format']}")
    print(f"📊 Findings Coverage: "
          f"{completeness['findings_coverage_percentage']:.1f}% "
          f"({completeness['referenced_findings']}/{completeness['total_findings']})")

    if completeness["missing_sections"]:
        print(f"\n⚠️  Missing sections: {completeness['missing_sections']}")
    else:
        print("\n✅ All required sections present!")

    # Validate format
    format_check = validate_report_format(SAMPLE_REPORT, format_type="markdown")
    print(f"\n📋 Format Valid: {format_check['format_valid']}")

    if not format_check["format_valid"]:
        print(f"Format issues: {format_check['issues']}")

    # Get suggestions if there are issues
    if not completeness["report_valid"]:
        suggestions = suggest_report_fixes(completeness)
        print("\n💡 Suggestions to fix report:")
        for suggestion in suggestions:
            print(f"  - {suggestion}")

    print()


def example_4_full_workflow():
    """Example 4: Full validation workflow."""
    print("=" * 70)
    print("EXAMPLE 4: Full Validation Workflow")
    print("=" * 70)

    # Step 1: Check checklist coverage
    print("\n1️⃣  Checking checklist coverage...")
    coverage = validate_checklist_coverage(SAMPLE_CHECKLIST, SAMPLE_FINDINGS)
    coverage_status = "✅ PASS" if coverage["coverage_valid"] else "❌ FAIL"
    print(f"   {coverage_status} - {coverage['coverage_percentage']:.1f}% coverage")

    # Step 2: Check report validity
    print("\n2️⃣  Validating report...")
    report = validate_report_completeness(SAMPLE_REPORT, SAMPLE_FINDINGS)
    report_status = "✅ PASS" if report["report_valid"] else "❌ FAIL"
    print(f"   {report_status} - {report['findings_coverage_percentage']:.1f}% findings referenced")

    # Step 3: Determine overall status
    print("\n3️⃣  Overall Validation Status:")
    if not coverage["coverage_valid"] or not report["report_valid"]:
        status = "❌ FAIL"
    else:
        status = "✅ PASS"

    print(f"   {status}")

    print()


if __name__ == "__main__":
    print("\n")
    print("🔍 Drystone Validation Module Examples")
    print("=" * 70)
    print()

    example_1_checklist_coverage()
    example_2_quality_review()
    example_3_report_validation()
    example_4_full_workflow()

    print("=" * 70)
    print("✅ Examples complete!")
    print()
    print("For more details, see VALIDATION.md")
