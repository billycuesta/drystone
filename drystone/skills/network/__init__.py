"""Network security skill for AWS audit."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

import boto3

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient


class NetworkSkill(BaseSkill):
    """Network security audit skill - analyzes VPCs, security groups, and network policies."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "network"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect network configuration data from AWS account.

        Collects:
            - VPCs (configurations, flow logs, peering)
            - Security groups (detailed rules)
            - Network ACLs (ingress/egress rules)
            - Route tables (routes and associations)
            - Network interfaces (ENIs and IPs)
            - VPN connections and gateways
            - VPC endpoints (gateway and interface)
            - Transit Gateway attachments

        Args:
            aws_client: Authenticated AWS client
            session: Audit session for evidence storage
        """
        client_kwargs = {
            'aws_access_key_id': aws_client.access_key_id,
            'aws_secret_access_key': aws_client.secret_access_key,
            'region_name': aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs['aws_session_token'] = aws_client.session_token

        ec2_client = boto3.client("ec2", **client_kwargs)
        evidence_path = session.get_evidence_path(self.name)

        # === VPCs ===
        print("  Collecting VPC configurations...")
        try:
            vpcs = ec2_client.describe_vpcs()
            vpcs_list = []

            for vpc in vpcs.get("Vpcs", []):
                vpc_id = vpc.get("VpcId")
                vpc_detail = {
                    "VpcId": vpc_id,
                    "CidrBlock": vpc.get("CidrBlock"),
                    "State": vpc.get("State"),
                    "IsDefault": vpc.get("IsDefault"),
                    "Tags": vpc.get("Tags", []),
                }

                try:
                    flow_logs = ec2_client.describe_flow_logs(
                        Filter=[{"Name": "resource-id", "Values": [vpc_id]}]
                    )
                    vpc_detail["FlowLogs"] = flow_logs.get("FlowLogs", [])
                except Exception:
                    vpc_detail["FlowLogs"] = []

                vpcs_list.append(vpc_detail)

            self._save_json(evidence_path / "vpcs.json", vpcs_list)
        except Exception as e:
            print(f"    Warning: Could not collect VPC data: {e}")

        # === SECURITY GROUPS (detailed) ===
        print("  Collecting security group rules...")
        try:
            sgs = ec2_client.describe_security_groups()
            sgs_list = []

            for sg in sgs.get("SecurityGroups", []):
                sg_detail = {
                    "GroupId": sg.get("GroupId"),
                    "GroupName": sg.get("GroupName"),
                    "VpcId": sg.get("VpcId"),
                    "Description": sg.get("Description"),
                    "IngressRules": sg.get("IpPermissions", []),
                    "EgressRules": sg.get("IpPermissionsEgress", []),
                    "Tags": sg.get("Tags", []),
                }
                sgs_list.append(sg_detail)

            self._save_json(evidence_path / "security-groups.json", sgs_list)
        except Exception as e:
            print(f"    Warning: Could not collect security group data: {e}")

        # === NETWORK ACLs ===
        print("  Collecting Network ACL rules...")
        try:
            nacls = ec2_client.describe_network_acls()
            nacls_list = []

            for nacl in nacls.get("NetworkAcls", []):
                nacl_detail = {
                    "NetworkAclId": nacl.get("NetworkAclId"),
                    "VpcId": nacl.get("VpcId"),
                    "IsDefault": nacl.get("IsDefault"),
                    "Entries": nacl.get("Entries", []),
                    "Associations": nacl.get("Associations", []),
                    "Tags": nacl.get("Tags", []),
                }
                nacls_list.append(nacl_detail)

            self._save_json(evidence_path / "network-acls.json", nacls_list)
        except Exception as e:
            print(f"    Warning: Could not collect NACL data: {e}")

        # === ROUTE TABLES ===
        print("  Collecting route tables...")
        try:
            route_tables = ec2_client.describe_route_tables()
            rts_list = []

            for rt in route_tables.get("RouteTables", []):
                rt_detail = {
                    "RouteTableId": rt.get("RouteTableId"),
                    "VpcId": rt.get("VpcId"),
                    "Routes": rt.get("Routes", []),
                    "Associations": rt.get("Associations", []),
                    "Tags": rt.get("Tags", []),
                }
                rts_list.append(rt_detail)

            self._save_json(evidence_path / "route-tables.json", rts_list)
        except Exception as e:
            print(f"    Warning: Could not collect route table data: {e}")

        # === NETWORK INTERFACES ===
        print("  Collecting network interfaces...")
        try:
            enis = ec2_client.describe_network_interfaces()
            enis_list = []

            for eni in enis.get("NetworkInterfaces", []):
                eni_detail = {
                    "NetworkInterfaceId": eni.get("NetworkInterfaceId"),
                    "VpcId": eni.get("VpcId"),
                    "SubnetId": eni.get("SubnetId"),
                    "Groups": eni.get("Groups", []),
                    "PrivateIpAddresses": eni.get("PrivateIpAddresses", []),
                    "PublicIp": eni.get("Association", {}).get("PublicIp"),
                    "Description": eni.get("Description"),
                    "Tags": eni.get("Tags", []),
                }
                enis_list.append(eni_detail)

            self._save_json(evidence_path / "network-interfaces.json", enis_list)
        except Exception as e:
            print(f"    Warning: Could not collect ENI data: {e}")

        # === VPC ENDPOINTS ===
        print("  Collecting VPC endpoints...")
        try:
            endpoints = ec2_client.describe_vpc_endpoints()
            endpoints_list = []

            for endpoint in endpoints.get("VpcEndpoints", []):
                endpoint_detail = {
                    "VpcEndpointId": endpoint.get("VpcEndpointId"),
                    "VpcId": endpoint.get("VpcId"),
                    "VpcEndpointType": endpoint.get("VpcEndpointType"),
                    "ServiceName": endpoint.get("ServiceName"),
                    "State": endpoint.get("State"),
                    "RouteTableIds": endpoint.get("RouteTableIds", []),
                    "SubnetIds": endpoint.get("SubnetIds", []),
                    "Groups": endpoint.get("Groups", []),
                    "PolicyDocument": endpoint.get("PolicyDocument"),
                    "Tags": endpoint.get("Tags", []),
                }
                endpoints_list.append(endpoint_detail)

            self._save_json(evidence_path / "vpc-endpoints.json", endpoints_list)
        except Exception as e:
            print(f"    Warning: Could not collect VPC endpoint data: {e}")

        # === VPN CONNECTIONS ===
        print("  Collecting VPN connections...")
        try:
            vpn_conns = ec2_client.describe_vpn_connections()
            vpn_list = []

            for vpn in vpn_conns.get("VpnConnections", []):
                vpn_detail = {
                    "VpnConnectionId": vpn.get("VpnConnectionId"),
                    "State": vpn.get("State"),
                    "Type": vpn.get("Type"),
                    "CustomerGatewayId": vpn.get("CustomerGatewayId"),
                    "VpnGatewayId": vpn.get("VpnGatewayId"),
                    "Routes": vpn.get("Routes", []),
                    "VgwTelemetry": vpn.get("VgwTelemetry", []),
                    "Tags": vpn.get("Tags", []),
                }
                vpn_list.append(vpn_detail)

            self._save_json(evidence_path / "vpn-connections.json", vpn_list)
        except Exception as e:
            print(f"    Warning: Could not collect VPN data: {e}")

        # === INTERNET GATEWAYS ===
        print("  Collecting internet gateways...")
        try:
            igws = ec2_client.describe_internet_gateways()
            igws_list = []

            for igw in igws.get("InternetGateways", []):
                igw_detail = {
                    "InternetGatewayId": igw.get("InternetGatewayId"),
                    "Attachments": igw.get("Attachments", []),
                    "Tags": igw.get("Tags", []),
                }
                igws_list.append(igw_detail)

            self._save_json(evidence_path / "internet-gateways.json", igws_list)
        except Exception as e:
            print(f"    Warning: Could not collect IGW data: {e}")

        print(f"\n✅ Network collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["NetworkSkill"]
