"""Tests for evidence snippet functionality in findings."""
import pytest
from drystone.models.findings import Finding


def test_finding_with_evidence_snippet():
    """Test that findings can include evidence snippets."""
    finding = Finding(
        id="IAM-001",
        severity="Critical",
        risk_score=9.5,
        title="Weak password policy",
        description="Password policy insufficient",
        evidence_snippet={
            "PasswordPolicy": {
                "MinimumPasswordLength": 2,
                "RequireSymbols": False
            }
        },
        affected_resources=["arn:aws:iam::123:account-policy"],
        remediation="Update password policy",
    )

    assert finding.evidence_snippet is not None
    assert finding.evidence_snippet["PasswordPolicy"]["MinimumPasswordLength"] == 2
    assert finding.evidence_snippet["PasswordPolicy"]["RequireSymbols"] is False


def test_finding_without_evidence_snippet():
    """Test backward compatibility - snippets are optional."""
    finding = Finding(
        id="IAM-002",
        severity="High",
        risk_score=7.5,
        title="MFA not enabled",
        description="Root has no MFA",
        affected_resources=["arn:aws:iam::123:root"],
        remediation="Enable MFA",
    )

    assert finding.evidence_snippet is None


def test_evidence_snippet_serialization():
    """Test that evidence snippets are properly serialized to JSON."""
    finding = Finding(
        id="IAM-003",
        severity="High",
        risk_score=7.0,
        title="Security Group too permissive",
        description="Security group allows all inbound traffic",
        evidence_snippet={
            "GroupId": "sg-12345",
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        },
        affected_resources=["sg-12345"],
        remediation="Restrict inbound traffic",
    )

    # Serialize to JSON
    json_str = finding.model_dump_json()
    assert '"evidence_snippet"' in json_str
    assert '"GroupId"' in json_str
    assert '"0.0.0.0/0"' in json_str


def test_evidence_snippet_with_refs():
    """Test that snippet and refs can coexist."""
    finding = Finding(
        id="ALERT-001",
        severity="Critical",
        risk_score=9.0,
        title="CloudWatch alarm missing",
        description="No alarm for root user login",
        evidence_snippet={
            "MonitoredMetrics": ["UnauthorizedAPICallsEventCount"],
            "MissingAlarms": ["Root account usage"]
        },
        evidence_refs=[
            "cloudwatch-alarms.json",
            "cloudtrail-logs.json"
        ],
        affected_resources=["CloudWatch"],
        remediation="Create CloudWatch alarm",
    )

    assert finding.evidence_snippet is not None
    assert len(finding.evidence_refs) == 2
    assert "cloudwatch-alarms.json" in finding.evidence_refs


def test_evidence_snippet_with_complex_data():
    """Test that snippets can contain nested complex structures."""
    finding = Finding(
        id="NET-001",
        severity="High",
        risk_score=7.5,
        title="VPC Flow Logs disabled",
        description="VPC missing flow logs configuration",
        evidence_snippet={
            "VPCs": [
                {
                    "VpcId": "vpc-12345",
                    "FlowLogsStatus": "DISABLED",
                    "Subnets": [
                        {
                            "SubnetId": "subnet-11111",
                            "HasFlowLogs": False
                        }
                    ]
                }
            ]
        },
        affected_resources=["vpc-12345"],
        remediation="Enable VPC Flow Logs",
    )

    assert finding.evidence_snippet["VPCs"][0]["VpcId"] == "vpc-12345"
    assert finding.evidence_snippet["VPCs"][0]["FlowLogsStatus"] == "DISABLED"
