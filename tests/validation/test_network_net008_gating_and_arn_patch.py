"""Tests for NET-008 subnet gating and account-id patching in ARNs."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

CHECKLIST = {
    "skill": "network",
    "items": [
        {"id": "NET-008", "severity": "Critical", "title": "NET-008 title"},
    ],
}


def _finding() -> Finding:
    return Finding(
        id="NET-008",
        severity="Critical",
        risk_score=9.5,
        title="wrong title",
        description="...",
        remediation="...",
        evidence_refs=[],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_net_008_rejected_when_referenced_subnet_not_public():
    n = FindingsNormalizer(CHECKLIST, "network")
    n.evidence = {
        "_audit_metadata": {"_account_id": "111111111111"},
        "route-tables": {
            "items": [
                {
                    "RouteTableId": "rtb-1",
                    "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
                    "Associations": [{"SubnetId": "subnet-public"}],
                }
            ]
        },
        "network-interfaces": {"items": []},
    }

    f = _finding()
    f.affected_resources = [
        "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-private",
    ]
    out = n.normalize([f])
    assert out == []


def test_arn_account_id_patched_from_audit_metadata():
    n = FindingsNormalizer(CHECKLIST, "network")
    n.evidence = {
        "_audit_metadata": {"_account_id": "111111111111"},
        "route-tables": {"items": []},
        "network-interfaces": {"items": []},
    }

    f = _finding()
    f.affected_resources = [
        "arn:aws:lambda:us-east-1:123456789012:function:ids_lambda",
    ]
    # NET-008 will be rejected due to missing public subnets; ensure patch happens on accepted findings.
    # Add a fake public subnet association and a referenced subnet in affected resources.
    n.evidence["route-tables"] = {
        "items": [
            {
                "RouteTableId": "rtb-1",
                "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
                "Associations": [{"SubnetId": "subnet-1"}],
            }
        ]
    }
    f.affected_resources.append("arn:aws:ec2:us-east-1:111111111111:subnet/subnet-1")

    out = n.normalize([f])
    assert len(out) == 1
    assert "arn:aws:lambda:us-east-1:111111111111:function:ids_lambda" in out[0].affected_resources
    assert out[0].title == "NET-008 title"


def test_malformed_ec2_subnet_arn_is_rewritten():
    n = FindingsNormalizer(CHECKLIST, "network")
    n.evidence = {
        "_audit_metadata": {"_account_id": "111111111111", "_region": "us-east-1"},
        "route-tables": {
            "items": [
                {
                    "RouteTableId": "rtb-1",
                    "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
                    "Associations": [{"SubnetId": "subnet-1"}],
                }
            ]
        },
        "network-interfaces": {"items": []},
    }

    f = _finding()
    f.affected_resources = [
        "arn:aws:ec2:us-east-1:vpc/subnet-subnet-1",
        "arn:aws:ec2:us-east-1:vpc/subnet-1",
        "arn:aws:ec2:us-east-1:vpc/rtb-1",
    ]
    f.affected_resources.append("arn:aws:ec2:us-east-1:111111111111:subnet/subnet-1")
    out = n.normalize([f])
    assert len(out) == 1
    assert "arn:aws:ec2:us-east-1:111111111111:subnet/subnet-1" in out[0].affected_resources
    assert "arn:aws:ec2:us-east-1:111111111111:route-table/rtb-1" in out[0].affected_resources
