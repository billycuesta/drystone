import json
from unittest.mock import Mock

from drystone.skills.network.post_processor import NetworkPostProcessor
from drystone.storage.session import AuditSession


def test_network_post_processor_adds_architecture_diagram(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True)
    # session.get_evidence_path("network") should return evidence_dir
    session = Mock(spec=AuditSession)
    session.get_evidence_path.return_value = evidence_dir

    (evidence_dir / "_audit_metadata.json").write_text(
        json.dumps({"_region": "us-east-1", "_account_id": "111111111111"})
    )
    (evidence_dir / "vpcs.json").write_text(
        json.dumps(
            {"items": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16", "FlowLogs": []}], "by_id": {}}
        )
    )
    (evidence_dir / "subnets.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "SubnetId": "subnet-1",
                        "VpcId": "vpc-1",
                        "CidrBlock": "10.0.1.0/24",
                        "AvailabilityZone": "us-east-1a",
                        "MapPublicIpOnLaunch": True,
                        "Tags": [],
                    }
                ],
                "by_id": {},
            }
        )
    )
    (evidence_dir / "route-tables.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "RouteTableId": "rtb-1",
                        "VpcId": "vpc-1",
                        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}],
                        "Associations": [{"SubnetId": "subnet-1"}],
                    }
                ],
                "by_id": {},
            }
        )
    )
    (evidence_dir / "internet-gateways.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "InternetGatewayId": "igw-1",
                        "Attachments": [{"VpcId": "vpc-1", "State": "available"}],
                    }
                ],
                "by_id": {},
            }
        )
    )
    (evidence_dir / "network-interfaces.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "NetworkInterfaceId": "eni-1",
                        "VpcId": "vpc-1",
                        "SubnetId": "subnet-1",
                        "PublicIp": "1.2.3.4",
                        "Description": "instance eni",
                        "Attachment": {"InstanceId": "i-123"},
                        "Groups": [],
                    }
                ],
                "by_id": {},
            }
        )
    )
    (evidence_dir / "vpc-endpoints.json").write_text(json.dumps({"items": [], "by_id": {}}))

    (evidence_dir / "ec2-instances.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "InstanceId": "i-123",
                        "SubnetId": "subnet-1",
                        "Tags": [{"Key": "Name", "Value": "web-1"}],
                    }
                ],
                "by_id": {},
            }
        )
    )
    (evidence_dir / "rds-instances.json").write_text(
        json.dumps(
            {
                "items": [{"DBInstanceIdentifier": "cardsdb", "SubnetIds": ["subnet-1"]}],
                "by_id": {},
            }
        )
    )
    (evidence_dir / "lambda-functions.json").write_text(
        json.dumps({"items": [{"FunctionName": "fn1", "SubnetIds": ["subnet-1"]}]})
    )

    findings = {"findings": []}
    out = NetworkPostProcessor(session).process(findings)
    assert "architecture" in out
    assert "flow_diagram" in out["architecture"]
    diagram = out["architecture"]["flow_diagram"]
    assert "vpc-1" in diagram
    assert "10.0.0.0/16" in diagram
    assert "EC2: web-1" in diagram
    assert "Lambda: fn1" in diagram
    assert "RDS: cardsdb" in diagram
    # new-mmap tree connectors present
    assert "├──" in diagram or "└──" in diagram
