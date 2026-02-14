"""Tests for Network remapping and NET-011 evidence validation."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

CHECKLIST = {
    "skill": "network",
    "items": [
        {"id": "NET-004", "severity": "Critical"},
        {"id": "NET-022", "severity": "Medium"},
        {"id": "NET-011", "severity": "High"},
    ],
}


def _finding(fid: str, sev: str, rs: float) -> Finding:
    return Finding(
        id=fid,
        severity=sev,
        risk_score=rs,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=[],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_net_004_remaps_to_net_022_when_no_sensitive_indicators_in_public_subnets():
    n = FindingsNormalizer(CHECKLIST, "network")
    n.evidence = {
        "route-tables": {
            "items": [
                {
                    "RouteTableId": "rtb-1",
                    "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
                    "Associations": [{"SubnetId": "subnet-1"}],
                }
            ]
        },
        "network-interfaces": {
            "items": [{"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "Description": "app"}]
        },
        "security-groups": {"items": [], "by_id": {}},
    }

    f = _finding("NET-004", "Critical", 9.2)
    f.affected_resources = ["subnet-1", "igw-1"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "NET-022"
    assert out[0].severity == "Medium"


def test_net_004_kept_when_sensitive_indicator_found_in_public_subnet():
    n = FindingsNormalizer(CHECKLIST, "network")
    n.evidence = {
        "route-tables": {
            "items": [
                {
                    "RouteTableId": "rtb-1",
                    "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
                    "Associations": [{"SubnetId": "subnet-1"}],
                }
            ]
        },
        "network-interfaces": {
            "items": [
                {
                    "NetworkInterfaceId": "eni-1",
                    "SubnetId": "subnet-1",
                    "Description": "RDSNetworkInterface",
                }
            ]
        },
        "security-groups": {"items": [], "by_id": {}},
    }

    f = _finding("NET-004", "Critical", 9.2)
    f.affected_resources = ["subnet-1", "igw-1"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "NET-004"


def test_net_011_rejected_when_no_missing_descriptions_on_critical_rules():
    n = FindingsNormalizer(CHECKLIST, "network")
    n.evidence = {
        "security-groups": {
            "items": [],
            "by_id": {
                "sg-1": {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/24", "Description": "SSH"}],
                        }
                    ],
                    "EgressRules": [],
                }
            },
        }
    }

    f = _finding("NET-011", "High", 7.0)
    f.affected_resources = ["arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"]
    out = n.normalize([f])
    assert out == []


def test_net_011_accepted_when_missing_descriptions_on_critical_rules():
    n = FindingsNormalizer(CHECKLIST, "network")
    n.evidence = {
        "security-groups": {
            "items": [],
            "by_id": {
                "sg-1": {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "10.0.0.0/24"}],
                        }
                    ],
                    "EgressRules": [],
                }
            },
        }
    }

    f = _finding("NET-011", "High", 7.0)
    f.affected_resources = ["arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "NET-011"
