"""Tests for NetworkSkill.collect() with mocked boto3.

Strategy (mirrors tests/skills/test_alerting_collect.py):
- Patch boto3.client with a factory dispatch function keyed by service name
- Use _make_paginator() helper to avoid unconfigured-MagicMock infinite-loop pitfalls
- Test: happy path (all evidence files written with expected structure/content,
  via the inherited self._wrap_indexed()/self._save_json() helpers)
- Test: each service's own try/except swallows its exception and collection
  continues for the other services
- Test: session_token branch adds aws_session_token to boto3 client kwargs

Notable asymmetry worth knowing for future work on this gap: the Transit
Gateway topology section's per-TGW route-table lookup catches ONLY
`botocore.exceptions.ClientError` (`except ClientError: continue`), while
every other section in this skill (including the OUTER try around the whole
TGW block) catches generic `Exception`. A non-ClientError failure in that
inner call is NOT skipped per-TGW — it propagates to the section's outer
`except Exception`, aborting the whole transit-gateway-topology.json write
instead of degrading gracefully. Both behaviors are covered below.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from drystone.skills.network import NetworkSkill

# ── Low-level helpers ──────────────────────────────────────────────────────────


def _make_paginator(*pages):
    """Return a mock paginator whose .paginate() returns the given pages."""
    pag = MagicMock()
    pag.paginate.return_value = iter(pages)
    return pag


def _make_aws_client(access_key="AKID", secret="SECRET", region="us-east-1", token=None):
    client = MagicMock()
    client.access_key_id = access_key
    client.secret_access_key = secret
    client.region_name = region
    client.session_token = token

    def _client_kwargs(region_name=None):
        kwargs = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret,
            "region_name": region_name or region,
        }
        if token:
            kwargs["aws_session_token"] = token
        return kwargs

    client.client_kwargs.side_effect = _client_kwargs
    return client


def _make_session(tmp_path, skill_name="network", account_id="123456789012"):
    session = MagicMock()
    evidence_path = tmp_path / "evidence" / skill_name
    evidence_path.mkdir(parents=True)
    session.get_evidence_path.return_value = evidence_path
    session.account_id = account_id
    return session, evidence_path


# ── Per-service mock factories ────────────────────────────────────────────────


def _make_ec2_client():
    """EC2 mock covering VPCs, security groups, NACLs, route tables, subnets,
    instances, endpoints, VPN, IGWs, Transit Gateway, and NAT gateways."""
    c = MagicMock()

    c.describe_vpcs.return_value = {
        "Vpcs": [
            {
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.0.0/16",
                "State": "available",
                "IsDefault": False,
                "Tags": [],
            }
        ]
    }
    c.describe_flow_logs.return_value = {"FlowLogs": [{"FlowLogId": "fl-1"}]}

    c.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-1",
                "GroupName": "default",
                "VpcId": "vpc-1",
                "Description": "default group",
                "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp"}],
                "IpPermissionsEgress": [],
                "Tags": [],
            }
        ]
    }

    c.describe_network_acls.return_value = {
        "NetworkAcls": [
            {
                "NetworkAclId": "acl-1",
                "VpcId": "vpc-1",
                "IsDefault": True,
                "Entries": [],
                "Associations": [],
                "Tags": [],
            }
        ]
    }

    c.describe_route_tables.return_value = {
        "RouteTables": [
            {
                "RouteTableId": "rtb-1",
                "VpcId": "vpc-1",
                "Routes": [{"NatGatewayId": "nat-1"}],
                "Associations": [],
                "Tags": [],
            }
        ]
    }

    c.describe_subnets.return_value = {
        "Subnets": [
            {
                "SubnetId": "subnet-1",
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.1.0/24",
                "AvailabilityZone": "us-east-1a",
                "MapPublicIpOnLaunch": False,
                "DefaultForAz": False,
                "State": "available",
                "Tags": [],
            }
        ]
    }

    instances_page = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-1",
                        "SubnetId": "subnet-1",
                        "VpcId": "vpc-1",
                        "PrivateIpAddress": "10.0.1.5",
                        "PublicIpAddress": "1.2.3.4",
                        "State": {"Name": "running"},
                        "Tags": [],
                        "SecurityGroups": [],
                    }
                ]
            }
        ]
    }
    network_interfaces_page = {
        "NetworkInterfaces": [
            {
                "NetworkInterfaceId": "eni-1",
                "SubnetId": "subnet-1",
                "VpcId": "vpc-1",
                "PrivateIpAddress": "10.0.1.5",
                "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.5", "Primary": True}],
                "Association": {"PublicIp": "1.2.3.4"},
                "Status": "in-use",
                "Description": "primary eni",
                "InterfaceType": "interface",
                "Attachment": {"InstanceId": "i-1", "DeviceIndex": 0},
                "Groups": [{"GroupId": "sg-1", "GroupName": "default"}],
                "SourceDestCheck": True,
                "TagSet": [],
            }
        ]
    }

    def _paginator(name):
        if name == "describe_instances":
            return _make_paginator(instances_page)
        if name == "describe_network_interfaces":
            return _make_paginator(network_interfaces_page)
        return _make_paginator({})

    c.get_paginator.side_effect = _paginator

    c.describe_vpc_endpoints.return_value = {
        "VpcEndpoints": [
            {
                "VpcEndpointId": "vpce-1",
                "VpcId": "vpc-1",
                "VpcEndpointType": "Gateway",
                "ServiceName": "com.amazonaws.us-east-1.s3",
                "State": "available",
                "RouteTableIds": ["rtb-1"],
                "SubnetIds": [],
                "Groups": [],
                "PolicyDocument": None,
                "Tags": [],
            }
        ]
    }

    c.describe_vpn_connections.return_value = {
        "VpnConnections": [
            {
                "VpnConnectionId": "vpn-1",
                "State": "available",
                "Type": "ipsec.1",
                "CustomerGatewayId": "cgw-1",
                "VpnGatewayId": "vgw-1",
                "Routes": [],
                "VgwTelemetry": [],
                "Tags": [],
            }
        ]
    }

    c.describe_internet_gateways.return_value = {
        "InternetGateways": [{"InternetGatewayId": "igw-1", "Attachments": [], "Tags": []}]
    }

    c.describe_transit_gateways.return_value = {
        "TransitGateways": [{"TransitGatewayId": "tgw-1"}]
    }
    c.describe_transit_gateway_attachments.return_value = {"TransitGatewayAttachments": []}
    c.describe_transit_gateway_route_tables.return_value = {
        "TransitGatewayRouteTables": [{"TransitGatewayRouteTableId": "tgw-rtb-1"}]
    }

    c.describe_nat_gateways.return_value = {
        "NatGateways": [
            {
                "NatGatewayId": "nat-1",
                "SubnetId": "subnet-1",
                "VpcId": "vpc-1",
                "State": "available",
                "NatGatewayAddresses": [{"PublicIp": "5.6.7.8"}],
            }
        ]
    }

    return c


def _make_rds_client():
    c = MagicMock()
    page = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "db-1",
                "Engine": "postgres",
                "DBInstanceClass": "db.t3.micro",
                "PubliclyAccessible": False,
                "DBSubnetGroup": {
                    "VpcId": "vpc-1",
                    "Subnets": [{"SubnetIdentifier": "subnet-1"}],
                },
                "VpcSecurityGroups": [],
            }
        ]
    }
    c.get_paginator.return_value = _make_paginator(page)
    return c


def _make_lambda_client():
    c = MagicMock()
    page = {
        "Functions": [
            {
                "FunctionName": "fn-1",
                "Runtime": "python3.12",
                "VpcConfig": {"SubnetIds": ["subnet-1"], "SecurityGroupIds": ["sg-1"]},
            }
        ]
    }
    c.get_paginator.return_value = _make_paginator(page)
    return c


def _boto3_factory(**overrides):
    """Dispatch factory: returns the appropriate mock client by service name."""
    clients = {
        "ec2": _make_ec2_client(),
        "rds": _make_rds_client(),
        "lambda": _make_lambda_client(),
    }
    clients.update(overrides)

    def _factory(service, **kwargs):
        return clients[service]

    return _factory


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def skill():
    return NetworkSkill()


@pytest.fixture
def aws_client():
    return _make_aws_client()


# ── Happy path ────────────────────────────────────────────────────────────────


class TestCollectHappyPath:
    def test_all_evidence_files_created(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        expected = [
            "vpcs.json",
            "security-groups.json",
            "network-acls.json",
            "route-tables.json",
            "subnets.json",
            "ec2-instances.json",
            "network-interfaces.json",
            "rds-instances.json",
            "lambda-functions.json",
            "vpc-endpoints.json",
            "vpn-connections.json",
            "internet-gateways.json",
            "transit-gateway-topology.json",
            "nat-gateway-routes.json",
            "_audit_metadata.json",
        ]
        for fname in expected:
            assert (evidence_path / fname).exists(), f"Missing: {fname}"

    def test_vpcs_content_with_flow_logs(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "vpcs.json").read_text())
        assert len(data["items"]) == 1
        assert data["items"][0]["VpcId"] == "vpc-1"
        assert data["items"][0]["FlowLogs"] == [{"FlowLogId": "fl-1"}]
        assert data["by_id"]["vpc-1"]["VpcId"] == "vpc-1"
        assert data["_meta"]["_region"] == "us-east-1"

    def test_security_groups_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "security-groups.json").read_text())
        assert len(data["items"]) == 1
        sg = data["items"][0]
        assert sg["GroupId"] == "sg-1"
        assert sg["IngressRules"] == [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp"}]
        assert sg["EgressRules"] == []

    def test_ec2_instances_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "ec2-instances.json").read_text())
        assert len(data["items"]) == 1
        inst = data["items"][0]
        assert inst["InstanceId"] == "i-1"
        assert inst["PublicIpAddress"] == "1.2.3.4"
        assert inst["State"] == "running"

    def test_network_interfaces_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "network-interfaces.json").read_text())
        assert len(data["items"]) == 1
        eni = data["items"][0]
        assert eni["NetworkInterfaceId"] == "eni-1"
        assert eni["AttachedInstanceId"] == "i-1"
        assert eni["Association"] == {"PublicIp": "1.2.3.4"}
        assert data["by_id"]["eni-1"]["SubnetId"] == "subnet-1"

    def test_rds_instances_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "rds-instances.json").read_text())
        assert len(data["items"]) == 1
        db = data["items"][0]
        assert db["DBInstanceIdentifier"] == "db-1"
        assert db["VpcId"] == "vpc-1"
        assert db["SubnetIds"] == ["subnet-1"]

    def test_lambda_functions_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "lambda-functions.json").read_text())
        # Lambda functions are saved as a plain {_meta, items} dict, NOT via
        # _wrap_indexed (no "by_id" key).
        assert "by_id" not in data
        assert data["_meta"]["_region"] == "us-east-1"
        assert len(data["items"]) == 1
        assert data["items"][0]["FunctionName"] == "fn-1"
        assert data["items"][0]["SecurityGroupIds"] == ["sg-1"]

    def test_transit_gateway_topology_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "transit-gateway-topology.json").read_text())
        assert len(data["transit_gateways"]) == 1
        assert len(data["route_tables"]) == 1
        assert data["route_tables"][0]["TransitGatewayRouteTableId"] == "tgw-rtb-1"

    def test_nat_gateway_routes_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "nat-gateway-routes.json").read_text())
        assert len(data["items"]) == 1
        nat = data["items"][0]
        assert nat["NatGatewayId"] == "nat-1"
        assert nat["PublicIp"] == "5.6.7.8"
        assert nat["AssociatedRouteTables"] == ["rtb-1"]

    def test_audit_metadata_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "_audit_metadata.json").read_text())
        assert data["_region"] == "us-east-1"
        assert data["_scope"] == "single-region"
        assert data["_skill"] == "network"
        assert data["_account_id"] == "123456789012"
        # _audit_metadata.json records itself only in evidence_files AFTER it
        # is written, so its own filename is not present inside the file.
        assert "_audit_metadata.json" not in data["evidence_files"]
        assert "vpcs.json" in data["evidence_files"]
        assert "network-interfaces.json" in data["evidence_files"]
        assert "nat-gateway-routes.json" in data["evidence_files"]
        assert len(data["evidence_files"]) == 14


# ── Session token branch ──────────────────────────────────────────────────────


class TestSessionToken:
    def test_collect_uses_managed_client_kwargs_with_token(self, skill, tmp_path):
        aws_client = _make_aws_client(token="STS-TOKEN-123")
        session, _ = _make_session(tmp_path)

        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        aws_client.client_kwargs.assert_called()

    def test_collect_uses_managed_client_kwargs_without_token(self, skill, tmp_path):
        aws_client = _make_aws_client(token=None)
        session, _ = _make_session(tmp_path)

        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        aws_client.client_kwargs.assert_called()


# ── Error resilience: each service's own try/except swallows its exception ───


class TestErrorResilience:
    def _collect_with_broken_ec2_call(self, skill, tmp_path, broken_method):
        """Break a single ec2_client method while keeping the rest working."""
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ec2 = _make_ec2_client()
        getattr(ec2, broken_method).side_effect = Exception(f"{broken_method} failed")

        with patch("boto3.client", side_effect=_boto3_factory(ec2=ec2)):
            skill.collect(aws_client, session)  # Must not raise

        return evidence_path

    def test_ec2_client_creation_failure_aborts_collection(self, skill, tmp_path):
        """boto3.client('ec2', ...) itself is created with no surrounding
        try/except in collect() — a failure there is not resilient and
        propagates, unlike every individual data-collection section below."""
        aws_client = _make_aws_client()
        session, _ = _make_session(tmp_path)

        def _factory(service, **kwargs):
            if service == "ec2":
                raise Exception("ec2 unavailable")
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            with pytest.raises(Exception, match="ec2 unavailable"):
                skill.collect(aws_client, session)

    def test_describe_vpcs_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken_ec2_call(skill, tmp_path, "describe_vpcs")
        assert not (evidence_path / "vpcs.json").exists()
        # Other sections still collected
        assert (evidence_path / "security-groups.json").exists()
        assert (evidence_path / "_audit_metadata.json").exists()

    def test_describe_security_groups_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken_ec2_call(
            skill, tmp_path, "describe_security_groups"
        )
        assert not (evidence_path / "security-groups.json").exists()
        assert (evidence_path / "vpcs.json").exists()
        assert (evidence_path / "route-tables.json").exists()

    def test_describe_route_tables_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken_ec2_call(
            skill, tmp_path, "describe_route_tables"
        )
        assert not (evidence_path / "route-tables.json").exists()
        # NAT gateway routing also calls describe_route_tables() again and
        # its own outer try/except swallows the same failure independently.
        assert not (evidence_path / "nat-gateway-routes.json").exists()
        assert (evidence_path / "vpcs.json").exists()

    def test_rds_client_creation_failure_swallowed(self, skill, tmp_path):
        """boto3.client('rds', ...) is created INSIDE the RDS section's own
        try/except Exception, so a failure there is fully resilient (unlike
        the primary ec2 client above)."""
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        def _factory(service, **kwargs):
            if service == "rds":
                raise Exception("rds unavailable")
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            skill.collect(aws_client, session)  # Must not raise

        assert not (evidence_path / "rds-instances.json").exists()
        assert (evidence_path / "vpcs.json").exists()
        assert (evidence_path / "lambda-functions.json").exists()

    def test_lambda_client_creation_failure_swallowed(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        def _factory(service, **kwargs):
            if service == "lambda":
                raise Exception("lambda unavailable")
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            skill.collect(aws_client, session)  # Must not raise

        assert not (evidence_path / "lambda-functions.json").exists()
        assert (evidence_path / "rds-instances.json").exists()


class TestSubCallResilience:
    def test_flow_logs_failure_still_saves_vpc(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        ec2 = _make_ec2_client()
        ec2.describe_flow_logs.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(ec2=ec2)):
            skill.collect(aws_client, session)  # Must not raise

        data = json.loads((evidence_path / "vpcs.json").read_text())
        assert len(data["items"]) == 1
        assert data["items"][0]["FlowLogs"] == []

    def test_tgw_route_tables_client_error_skips_only_that_tgw(self, skill, aws_client, tmp_path):
        """The inner per-TGW call catches ONLY ClientError, so a ClientError
        here is skipped gracefully and the section still saves."""
        session, evidence_path = _make_session(tmp_path)
        ec2 = _make_ec2_client()
        ec2.describe_transit_gateway_route_tables.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "DescribeTransitGatewayRouteTables",
        )

        with patch("boto3.client", side_effect=_boto3_factory(ec2=ec2)):
            skill.collect(aws_client, session)  # Must not raise

        data = json.loads((evidence_path / "transit-gateway-topology.json").read_text())
        assert len(data["transit_gateways"]) == 1
        assert data["route_tables"] == []

    def test_tgw_route_tables_generic_exception_aborts_whole_section(
        self, skill, aws_client, tmp_path
    ):
        """Surprising asymmetry: a non-ClientError exception in the same call
        is NOT caught by the inner `except ClientError: continue` — it
        propagates to the section's outer `except Exception`, so the whole
        transit-gateway-topology.json file is never written (instead of just
        skipping that one TGW's route tables)."""
        session, evidence_path = _make_session(tmp_path)
        ec2 = _make_ec2_client()
        ec2.describe_transit_gateway_route_tables.side_effect = Exception("boom")

        with patch("boto3.client", side_effect=_boto3_factory(ec2=ec2)):
            skill.collect(aws_client, session)  # Must not raise (outer catch)

        assert not (evidence_path / "transit-gateway-topology.json").exists()
        # Collection continues past this section regardless
        assert (evidence_path / "nat-gateway-routes.json").exists()
        assert (evidence_path / "_audit_metadata.json").exists()


def test_skill_name():
    assert NetworkSkill().name == "network"
