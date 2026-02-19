"""Network security skill for AWS audit."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List

import boto3
from botocore.exceptions import ClientError

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
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        ec2_client = boto3.client("ec2", **client_kwargs)
        evidence_path = session.get_evidence_path(self.name)
        region = aws_client.region_name

        # === AUDIT METADATA ===
        audit_metadata: Dict[str, Any] = {
            "_region": region,
            "_timestamp": datetime.now(timezone.utc).isoformat(),
            "_scope": "single-region",
            "_skill": self.name,
            "_account_id": session.account_id,
            "evidence_files": [],
        }

        def _save(filepath: Path, data: Any) -> None:
            self._save_json(filepath, data)
            audit_metadata["evidence_files"].append(filepath.name)

        def _wrap_indexed(items: List[Dict[str, Any]], *, by_key: str) -> Dict[str, Any]:
            by_id: Dict[str, Any] = {}
            for it in items:
                if not isinstance(it, dict):
                    continue
                k = it.get(by_key)
                if isinstance(k, str) and k:
                    by_id[k] = it
            return {
                "_meta": {"_region": region},
                "items": items,
                "by_id": by_id,
            }

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

            _save(evidence_path / "vpcs.json", _wrap_indexed(vpcs_list, by_key="VpcId"))
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

            _save(
                evidence_path / "security-groups.json",
                _wrap_indexed(sgs_list, by_key="GroupId"),
            )
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

            _save(
                evidence_path / "network-acls.json",
                _wrap_indexed(nacls_list, by_key="NetworkAclId"),
            )
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

            _save(
                evidence_path / "route-tables.json",
                _wrap_indexed(rts_list, by_key="RouteTableId"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect route table data: {e}")

        # === SUBNETS ===
        print("  Collecting subnets...")
        try:
            subnets = ec2_client.describe_subnets()
            subnets_list: List[Dict[str, Any]] = []
            for sn in subnets.get("Subnets", []) or []:
                subnets_list.append(
                    {
                        "SubnetId": sn.get("SubnetId"),
                        "VpcId": sn.get("VpcId"),
                        "CidrBlock": sn.get("CidrBlock"),
                        "AvailabilityZone": sn.get("AvailabilityZone"),
                        "MapPublicIpOnLaunch": sn.get("MapPublicIpOnLaunch"),
                        "DefaultForAz": sn.get("DefaultForAz"),
                        "State": sn.get("State"),
                        "Tags": sn.get("Tags", []),
                    }
                )

            _save(
                evidence_path / "subnets.json",
                _wrap_indexed(subnets_list, by_key="SubnetId"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect subnet data: {e}")

        # === EC2 INSTANCES (for topology labels) ===
        print("  Collecting EC2 instances (labels)...")
        try:
            instances_list: List[Dict[str, Any]] = []
            paginator = ec2_client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for r in page.get("Reservations", []) or []:
                    for inst in r.get("Instances", []) or []:
                        if not isinstance(inst, dict):
                            continue
                        instances_list.append(
                            {
                                "InstanceId": inst.get("InstanceId"),
                                "SubnetId": inst.get("SubnetId"),
                                "VpcId": inst.get("VpcId"),
                                "PrivateIpAddress": inst.get("PrivateIpAddress"),
                                "PublicIpAddress": (
                                    inst.get("PublicIpAddress")
                                    or (
                                        inst.get("PublicIp")
                                        if isinstance(inst.get("PublicIp"), str)
                                        else None
                                    )
                                ),
                                "State": (inst.get("State") or {}).get("Name")
                                if isinstance(inst.get("State"), dict)
                                else None,
                                "Tags": inst.get("Tags", []),
                                "SecurityGroups": inst.get("SecurityGroups", []),
                            }
                        )

            _save(
                evidence_path / "ec2-instances.json",
                _wrap_indexed(instances_list, by_key="InstanceId"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect EC2 instances: {e}")

        # === RDS INSTANCES (for topology labels) ===
        print("  Collecting RDS instances (labels)...")
        try:
            rds = boto3.client("rds", **client_kwargs)
            rds_list: List[Dict[str, Any]] = []
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []) or []:
                    if not isinstance(db, dict):
                        continue
                    subnet_ids: List[str] = []
                    sg = db.get("DBSubnetGroup")
                    if isinstance(sg, dict):
                        for sn in sg.get("Subnets", []) or []:
                            if isinstance(sn, dict):
                                sid = sn.get("SubnetIdentifier")
                                if isinstance(sid, str):
                                    subnet_ids.append(sid)
                    rds_list.append(
                        {
                            "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                            "Engine": db.get("Engine"),
                            "DBInstanceClass": db.get("DBInstanceClass"),
                            "PubliclyAccessible": db.get("PubliclyAccessible"),
                            "VpcId": db.get("DBSubnetGroup", {}).get("VpcId")
                            if isinstance(db.get("DBSubnetGroup"), dict)
                            else None,
                            "SubnetIds": subnet_ids,
                            "VpcSecurityGroups": db.get("VpcSecurityGroups", []),
                        }
                    )

            _save(
                evidence_path / "rds-instances.json",
                _wrap_indexed(rds_list, by_key="DBInstanceIdentifier"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect RDS instances: {e}")

        # === LAMBDA FUNCTIONS (for topology labels) ===
        print("  Collecting Lambda functions (labels)...")
        try:
            lam = boto3.client("lambda", **client_kwargs)
            functions_list: List[Dict[str, Any]] = []
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []) or []:
                    if not isinstance(fn, dict):
                        continue
                    vpc_cfg = fn.get("VpcConfig") if isinstance(fn.get("VpcConfig"), dict) else {}
                    functions_list.append(
                        {
                            "FunctionName": fn.get("FunctionName"),
                            "Runtime": fn.get("Runtime"),
                            "VpcConfig": vpc_cfg,
                            "SubnetIds": (vpc_cfg.get("SubnetIds") or [])
                            if isinstance(vpc_cfg, dict)
                            else [],
                            "SecurityGroupIds": (vpc_cfg.get("SecurityGroupIds") or [])
                            if isinstance(vpc_cfg, dict)
                            else [],
                        }
                    )

            _save(
                evidence_path / "lambda-functions.json",
                {
                    "_meta": {"_region": region},
                    "items": functions_list,
                },
            )
        except Exception as e:
            print(f"    Warning: Could not collect Lambda functions: {e}")

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

            _save(
                evidence_path / "vpc-endpoints.json",
                _wrap_indexed(endpoints_list, by_key="VpcEndpointId"),
            )
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

            _save(
                evidence_path / "vpn-connections.json",
                _wrap_indexed(vpn_list, by_key="VpnConnectionId"),
            )
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

            _save(
                evidence_path / "internet-gateways.json",
                _wrap_indexed(igws_list, by_key="InternetGatewayId"),
            )
        except Exception as e:
            print(f"    Warning: Could not collect IGW data: {e}")

        # === TRANSIT GATEWAY TOPOLOGY ===
        print("  Collecting Transit Gateway topology...")
        try:
            tgw_topology = {"transit_gateways": [], "attachments": [], "route_tables": []}
            tgws = ec2_client.describe_transit_gateways().get("TransitGateways", [])
            tgw_topology["transit_gateways"] = tgws
            attachments = ec2_client.describe_transit_gateway_attachments().get(
                "TransitGatewayAttachments", []
            )
            tgw_topology["attachments"] = attachments

            for tgw in tgws:
                tgw_id = tgw.get("TransitGatewayId")
                if not tgw_id:
                    continue
                try:
                    route_tables = ec2_client.describe_transit_gateway_route_tables(
                        Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
                    ).get("TransitGatewayRouteTables", [])
                    tgw_topology["route_tables"].extend(route_tables)
                except ClientError:
                    continue

            _save(evidence_path / "transit-gateway-topology.json", tgw_topology)
        except Exception as e:
            print(f"    Warning: Could not collect Transit Gateway topology: {e}")

        # === NAT GATEWAY ROUTING ===
        print("  Collecting NAT Gateway routes...")
        try:
            nat_gateways = ec2_client.describe_nat_gateways().get("NatGateways", [])
            route_tables = ec2_client.describe_route_tables().get("RouteTables", [])
            nat_routes: List[Dict[str, Any]] = []

            for nat in nat_gateways:
                nat_id = nat.get("NatGatewayId")
                associated_rts: List[str] = []
                if nat_id:
                    for rt in route_tables:
                        routes = rt.get("Routes", []) if isinstance(rt, dict) else []
                        if any(
                            isinstance(r, dict) and r.get("NatGatewayId") == nat_id for r in routes
                        ):
                            rtid = rt.get("RouteTableId")
                            if isinstance(rtid, str):
                                associated_rts.append(str(rtid))

                nat_routes.append(
                    {
                        "NatGatewayId": nat_id,
                        "SubnetId": nat.get("SubnetId"),
                        "VpcId": nat.get("VpcId"),
                        "State": nat.get("State"),
                        "PublicIp": (
                            (nat.get("NatGatewayAddresses") or [{}])[0].get("PublicIp")
                            if isinstance(nat.get("NatGatewayAddresses"), list)
                            else None
                        ),
                        "AssociatedRouteTables": sorted(set(associated_rts)),
                    }
                )

            _save(evidence_path / "nat-gateway-routes.json", {"items": nat_routes})
        except Exception as e:
            print(f"    Warning: Could not collect NAT Gateway routes: {e}")

        # Persist audit metadata last so it includes all files.
        _save(evidence_path / "_audit_metadata.json", audit_metadata)

        print("\n✅ Network collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def analyze(self, session: AuditSession, agent_client: "AgentClient") -> Path:
        """Analyze collected network evidence using Gemini API.

        1. Read all evidence files
        2. Read security checklist
        3. Send to AI provider for analysis
        4. Save findings to findings/network.json
        5. Print summary

        Args:
            session: Audit session with collected evidence
            agent_client: Gemini AI client for analysis

        Returns:
            Path to saved findings JSON file

        Raises:
            Exception: If evidence cannot be read or analysis fails
        """
        print("  Reading evidence files...")

        # 1. Read all evidence files
        evidence_path = session.get_evidence_path(self.name)
        evidence = {}

        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence directory not found: {evidence_path}")

        for json_file in evidence_path.glob("*.json"):
            try:
                with open(json_file) as f:
                    evidence[json_file.stem] = json.load(f)
            except Exception as e:
                print(f"    Warning: Could not read {json_file.name}: {e}")

        print(f"    Loaded {len(evidence)} evidence files")

        # 2. Read checklist
        checklist_path = Path(__file__).parent / "checklist.json"
        if not checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {checklist_path}")

        with open(checklist_path) as f:
            checklist = json.load(f)

        print(f"    Loaded {len(checklist['items'])} security checks")

        # 3. Call agent for analysis (chunked for large evidence)
        provider_name = agent_client.get_display_name()
        print(f"  Analyzing with {provider_name}...")
        findings = agent_client.analyze_evidence_chunked(
            skill_name=self.name, evidence=evidence, checklist=checklist
        )

        # 3a. Normalize findings (reduce variance between models)
        print("  Normalizing findings...")
        findings = self._normalize_findings(findings, checklist, evidence=evidence)

        # Enforce server-side metadata for report generation and QA consistency.
        findings.skill = self.name
        findings.evidence_count = len(evidence)
        findings.checklist_version = str(checklist.get("version") or "1.0")
        findings.analyzed_at = datetime.now(timezone.utc)

        # 4. Save findings
        findings_dir = session.get_findings_path()
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / f"{self.name}.json"

        with open(findings_path, "w") as f:
            json.dump(findings.model_dump(mode="json"), f, indent=2, default=str)

        # 5. Print summary
        print("\n✅ Analysis complete:")
        print(f"   Total findings: {findings.summary.total_findings}")
        print(f"   Critical: {findings.summary.critical}")
        print(f"   High: {findings.summary.high}")
        print(f"   Medium: {findings.summary.medium}")
        print(f"   Low: {findings.summary.low}")
        print(f"   Overall Risk: {findings.summary.overall_risk_score:.1f}/10")

        return findings_path


__all__ = ["NetworkSkill"]
