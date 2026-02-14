"""Tests for Network evidence-based validation and ref normalization."""

from typing import Literal

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

NETWORK_CHECKLIST = {
    "skill": "network",
    "items": [
        {"id": "NET-001", "severity": "Critical"},
        {"id": "NET-018", "severity": "High"},
    ],
}


def _finding(
    fid: str, severity: Literal["Critical", "High", "Medium", "Low"], risk: float
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        risk_score=risk,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=[],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_net_001_rejected_when_no_world_ingress_for_sensitive_ports():
    n = FindingsNormalizer(NETWORK_CHECKLIST, "network")
    n.evidence = {
        "security-groups": {
            "items": [
                {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "3.3.3.3/32"}],
                        }
                    ],
                }
            ],
            "by_id": {
                "sg-1": {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "3.3.3.3/32"}],
                        }
                    ],
                }
            },
        }
    }

    f = _finding("NET-001", "Critical", 9.2)
    f.affected_resources = ["arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"]
    out = n.normalize([f])
    assert out == []


def test_net_001_accepted_when_world_ingress_present():
    n = FindingsNormalizer(NETWORK_CHECKLIST, "network")
    n.evidence = {
        "security-groups": {
            "items": [
                {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ],
            "by_id": {
                "sg-1": {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            },
        }
    }

    f = _finding("NET-001", "Critical", 9.2)
    f.affected_resources = ["arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "NET-001"


def test_net_018_rejected_when_flow_logs_active():
    n = FindingsNormalizer(NETWORK_CHECKLIST, "network")
    n.evidence = {
        "vpcs": {
            "items": [
                {
                    "VpcId": "vpc-1",
                    "FlowLogs": [{"FlowLogStatus": "ACTIVE"}],
                }
            ],
            "by_id": {
                "vpc-1": {
                    "VpcId": "vpc-1",
                    "FlowLogs": [{"FlowLogStatus": "ACTIVE"}],
                }
            },
        }
    }

    f = _finding("NET-018", "High", 7.8)
    # Model sometimes emits plain vpc- ids
    f.affected_resources = ["vpc-1"]
    f.evidence_snippet = {"vpc_id": "vpc-1"}
    out = n.normalize([f])
    assert out == []


def test_disregarded_variant_is_filtered():
    n = FindingsNormalizer(NETWORK_CHECKLIST, "network")
    f = _finding("NET-001", "Critical", 9.2)
    f.remediation = "This finding should be DISREGARDED - no remediation needed."
    out = n.normalize([f])
    assert out == []


def test_network_evidence_refs_normalize_sg_by_id():
    n = FindingsNormalizer(NETWORK_CHECKLIST, "network")
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
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            },
        }
    }

    f = _finding("NET-001", "Critical", 9.2)
    f.evidence_refs = ["security-groups.json#sg-1"]
    # Ensure it survives heuristics
    f.affected_resources = ["arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"]

    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].evidence_refs[0] == "security-groups.json#by_id.sg-1"
