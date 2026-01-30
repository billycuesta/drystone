"""Tests for evidence snippet functionality in findings and reports."""
import json
from datetime import datetime

import pytest


@pytest.fixture
def findings_with_snippets():
    """Create findings with evidence snippets."""
    return {
        "skill": "iam",
        "findings": [
            {
                "id": "IAM-001",
                "severity": "Critical",
                "risk_score": 9.5,
                "title": "Weak password policy",
                "description": "Password policy does not meet minimum requirements",
                "evidence_refs": ["password-policy.json"],
                "evidence_snippet": {
                    "PasswordPolicy": {
                        "MinimumPasswordLength": 2,
                        "RequireSymbols": False,
                        "RequireNumbers": False
                    }
                },
                "affected_resources": ["arn:aws:iam::123:account-policy"],
                "remediation": "Update password policy to require 14+ chars",
                "cis_reference": "1.9",
                "pci_dss": [
                    {
                        "control": "8.2.3",
                        "reason": "Password policy controls are required"
                    }
                ]
            },
            {
                "id": "IAM-002",
                "severity": "High",
                "risk_score": 8.0,
                "title": "MFA not enabled on root",
                "description": "Root account has no MFA",
                "evidence_refs": ["users.json#root"],
                "evidence_snippet": {
                    "User": "root",
                    "MFADevices": []
                },
                "affected_resources": ["arn:aws:iam::123:root"],
                "remediation": "Enable MFA on root account",
                "cis_reference": "1.5",
                "pci_dss": [
                    {
                        "control": "8.4.1",
                        "reason": "MFA required for admin access"
                    }
                ]
            },
            {
                "id": "IAM-003",
                "severity": "Medium",
                "risk_score": 5.0,
                "title": "Finding without snippet",
                "description": "Test finding without snippet",
                "evidence_refs": ["test.json"],
                "evidence_snippet": None,
                "affected_resources": [],
                "remediation": "Test remediation",
            }
        ],
        "summary": {
            "total_findings": 3,
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 0,
            "overall_risk_score": 7.5
        },
        "analyzed_at": datetime.utcnow().isoformat(),
        "evidence_count": 3,
        "checklist_version": "2.0"
    }


def test_finding_has_evidence_snippet_field(findings_with_snippets):
    """Test that findings have evidence_snippet field."""
    finding = findings_with_snippets["findings"][0]
    assert "evidence_snippet" in finding
    assert finding["evidence_snippet"] is not None


def test_finding_evidence_snippet_is_dict(findings_with_snippets):
    """Test that evidence_snippet is a valid dict."""
    finding = findings_with_snippets["findings"][0]
    assert isinstance(finding["evidence_snippet"], dict)
    assert "PasswordPolicy" in finding["evidence_snippet"]


def test_evidence_snippet_json_valid(findings_with_snippets):
    """Test that evidence snippets are valid JSON."""
    for finding in findings_with_snippets["findings"]:
        if finding.get("evidence_snippet"):
            # Should be serializable to JSON
            json_str = json.dumps(finding["evidence_snippet"])
            assert json_str is not None
            # And deserializable back
            parsed = json.loads(json_str)
            assert parsed is not None
            assert isinstance(parsed, dict)


def test_evidence_snippet_not_too_large(findings_with_snippets):
    """Test that evidence snippets are not excessively large."""
    for finding in findings_with_snippets["findings"]:
        if finding.get("evidence_snippet"):
            json_str = json.dumps(finding["evidence_snippet"], indent=2)
            lines = json_str.split("\n")
            # Recommend max ~20 lines, allow up to 50 for test
            assert len(lines) < 50, f"Evidence snippet too large: {len(lines)} lines"


def test_finding_without_snippet_allowed(findings_with_snippets):
    """Test that findings can have null snippet (backward compatible)."""
    finding = findings_with_snippets["findings"][2]
    assert finding["evidence_snippet"] is None
    # Should still have other required fields
    assert "id" in finding
    assert "remediation" in finding


def test_finding_has_evidence_refs(findings_with_snippets):
    """Test that findings have evidence_refs field (not just snippet)."""
    finding = findings_with_snippets["findings"][0]
    assert "evidence_refs" in finding
    assert len(finding["evidence_refs"]) > 0
    assert "password-policy.json" in finding["evidence_refs"]


def test_evidence_snippet_contains_config_issue(findings_with_snippets):
    """Test that snippets contain the problematic config (not the whole file)."""
    finding = findings_with_snippets["findings"][0]
    snippet = finding["evidence_snippet"]

    # Should contain the specific problem: MinimumPasswordLength is 2
    assert snippet["PasswordPolicy"]["MinimumPasswordLength"] == 2
    # And the failing requirements
    assert snippet["PasswordPolicy"]["RequireSymbols"] is False


def test_mfa_snippet_shows_empty_devices(findings_with_snippets):
    """Test that MFA snippet shows empty device list."""
    finding = findings_with_snippets["findings"][1]
    snippet = finding["evidence_snippet"]

    # Should clearly show MFA is disabled
    assert snippet["User"] == "root"
    assert snippet["MFADevices"] == []


def test_critical_findings_included(findings_with_snippets):
    """Test that critical findings are present with snippets."""
    critical = [f for f in findings_with_snippets["findings"] if f["severity"] == "Critical"]
    assert len(critical) == 1
    assert critical[0]["id"] == "IAM-001"
    assert critical[0]["evidence_snippet"] is not None


def test_summary_counts_match_findings(findings_with_snippets):
    """Test that summary counts match the findings list."""
    findings = findings_with_snippets["findings"]
    summary = findings_with_snippets["summary"]

    critical_count = len([f for f in findings if f["severity"] == "Critical"])
    high_count = len([f for f in findings if f["severity"] == "High"])
    medium_count = len([f for f in findings if f["severity"] == "Medium"])

    assert summary["critical"] == critical_count
    assert summary["high"] == high_count
    assert summary["medium"] == medium_count
    assert summary["total_findings"] == len(findings)
