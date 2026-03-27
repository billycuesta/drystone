"""Tests for Finding model with security_analogy field."""

import json

from drystone.models.findings import Finding, PCIDSSControl


def test_finding_with_security_analogy():
    """Test that security_analogy field is optional and can be set."""
    finding = Finding(
        id="IAM-001",
        severity="Critical",
        risk_score=9.5,
        title="Root account without MFA",
        description="Root account lacks MFA protection.",
        impact="Attackers could access root account.",
        evidence_refs=["evidence/iam/users.json#root"],
        evidence_snippet={"User": "root", "MFADevices": []},
        affected_resources=["arn:aws:iam::123456789012:root"],
        remediation="Enable MFA on root account.",
        security_analogy="Like leaving the master key in the front door of a bank vault.",
    )

    assert (
        finding.security_analogy == "Like leaving the master key in the front door of a bank vault."
    )
    assert finding.id == "IAM-001"


def test_finding_without_security_analogy():
    """Test that security_analogy field is optional (backward compatibility)."""
    finding = Finding(
        id="IAM-002",
        severity="High",
        risk_score=7.5,
        title="Unused access key",
        description="Access key not used for 90 days.",
        impact="Unused keys should be rotated.",
        evidence_refs=["evidence/iam/users.json#alice"],
        evidence_snippet={"User": "alice", "AccessKeyLastUsedDate": None},
        affected_resources=["arn:aws:iam::123456789012:user/alice"],
        remediation="Rotate the access key.",
    )

    assert finding.security_analogy is None
    assert finding.id == "IAM-002"


def test_finding_serialization_with_analogy():
    """Test that security_analogy is included in JSON serialization."""
    finding = Finding(
        id="EXP-001",
        severity="Critical",
        risk_score=9.0,
        title="S3 bucket publicly accessible",
        description="S3 bucket allows public GetObject.",
        impact="Public data exposure.",
        evidence_refs=["evidence/s3-buckets.json#bucket1"],
        evidence_snippet={
            "BucketName": "test-bucket",
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": False},
        },
        affected_resources=["arn:aws:s3:::test-bucket"],
        remediation="Enable BlockPublicAcls.",
        security_analogy="Like leaving sensitive documents on a public park bench.",
    )

    finding_dict = json.loads(finding.model_dump_json())
    assert "security_analogy" in finding_dict
    assert (
        finding_dict["security_analogy"]
        == "Like leaving sensitive documents on a public park bench."
    )


def test_finding_with_pci_dss_and_analogy():
    """Test that security_analogy works alongside other optional fields."""
    finding = Finding(
        id="IAM-003",
        severity="High",
        risk_score=8.0,
        title="No MFA on privileged user",
        description="User with admin role has no MFA.",
        impact="Admin compromise without MFA protection.",
        evidence_refs=["evidence/iam/users.json#admin"],
        evidence_snippet={"User": "admin", "MFADevices": []},
        affected_resources=["arn:aws:iam::123456789012:user/admin"],
        remediation="Enable MFA.",
        cis_reference="1.5",
        pci_dss=[PCIDSSControl(control="8.4.1", reason="MFA required for admin access")],
        security_analogy="Like requiring a PIN at an ATM alongside your debit card.",
    )

    assert finding.security_analogy is not None
    assert len(finding.pci_dss) > 0
    assert finding.cis_reference == "1.5"


if __name__ == "__main__":
    test_finding_with_security_analogy()
    test_finding_without_security_analogy()
    test_finding_serialization_with_analogy()
    test_finding_with_pci_dss_and_analogy()
    print("✓ All tests passed")
