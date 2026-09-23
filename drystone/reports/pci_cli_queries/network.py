"""Network AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"network"})

_WRAPPED_ITEM_COLUMNS = (
    ("Resource", "GroupId"),
    ("Name", "GroupName"),
    ("VpcId", "VpcId"),
)

_SECURITY_GROUPS_OUTPUT = OutputSpec(
    source="security-groups",
    rows="items",
    columns=(
        ("GroupId", "GroupId"),
        ("GroupName", "GroupName"),
        ("VpcId", "VpcId"),
        ("IngressRules", "IngressRules"),
        ("EgressRules", "EgressRules"),
        ("Tags", "Tags"),
    ),
)

_NETWORK_ACLS_OUTPUT = OutputSpec(
    source="network-acls",
    rows="items",
    columns=(
        ("NetworkAclId", "NetworkAclId"),
        ("VpcId", "VpcId"),
        ("IsDefault", "IsDefault"),
        ("Entries", "Entries"),
        ("Associations", "Associations"),
    ),
)

_ROUTE_TABLES_OUTPUT = OutputSpec(
    source="route-tables",
    rows="items",
    columns=(
        ("RouteTableId", "RouteTableId"),
        ("VpcId", "VpcId"),
        ("Routes", "Routes"),
        ("Associations", "Associations"),
        ("Tags", "Tags"),
    ),
)

_SUBNETS_OUTPUT = OutputSpec(
    source="subnets",
    rows="items",
    columns=(
        ("SubnetId", "SubnetId"),
        ("VpcId", "VpcId"),
        ("CidrBlock", "CidrBlock"),
        ("MapPublicIpOnLaunch", "MapPublicIpOnLaunch"),
        ("Tags", "Tags"),
    ),
)

_VPCS_OUTPUT = OutputSpec(
    source="vpcs",
    rows="items",
    columns=(
        ("VpcId", "VpcId"),
        ("CidrBlock", "CidrBlock"),
        ("IsDefault", "IsDefault"),
        ("FlowLogs", "FlowLogs"),
        ("Tags", "Tags"),
    ),
)

SOURCE_QUERIES = {
    "network": {
        "security-groups": CliQuery(
            commands=("aws ec2 describe-security-groups",),
            output=_SECURITY_GROUPS_OUTPUT,
        ),
        "network-acls": CliQuery(
            commands=("aws ec2 describe-network-acls",),
            output=_NETWORK_ACLS_OUTPUT,
        ),
        "route-tables": CliQuery(
            commands=("aws ec2 describe-route-tables",),
            output=_ROUTE_TABLES_OUTPUT,
        ),
        "subnets": CliQuery(
            commands=("aws ec2 describe-subnets",),
            output=_SUBNETS_OUTPUT,
        ),
        "vpcs": CliQuery(
            commands=(
                'for vpc in $(aws ec2 describe-vpcs --query "Vpcs[].VpcId" --output text); do\n'
                '  aws ec2 describe-vpcs --vpc-ids "$vpc"\n'
                '  aws ec2 describe-flow-logs --filter Name=resource-id,Values="$vpc"\n'
                "done",
            ),
            output=_VPCS_OUTPUT,
        ),
        "ec2-instances": CliQuery(
            commands=("aws ec2 describe-instances",),
            output=OutputSpec(
                source="ec2-instances",
                rows="items",
                columns=(
                    ("InstanceId", "InstanceId"),
                    ("SubnetId", "SubnetId"),
                    ("VpcId", "VpcId"),
                    ("PublicIpAddress", "PublicIpAddress"),
                    ("SecurityGroups", "SecurityGroups"),
                ),
            ),
        ),
        "network-interfaces": CliQuery(
            commands=("aws ec2 describe-network-interfaces",),
            output=OutputSpec(
                source="network-interfaces",
                rows="items",
                columns=(
                    ("NetworkInterfaceId", "NetworkInterfaceId"),
                    ("VpcId", "VpcId"),
                    ("SubnetId", "SubnetId"),
                    ("Groups", "Groups"),
                    ("AttachedInstanceId", "AttachedInstanceId"),
                ),
            ),
        ),
        "rds-instances": CliQuery(
            commands=("aws rds describe-db-instances",),
            output=OutputSpec(
                source="rds-instances",
                rows="items",
                columns=(
                    ("DBInstanceIdentifier", "DBInstanceIdentifier"),
                    ("Engine", "Engine"),
                    ("PubliclyAccessible", "PubliclyAccessible"),
                    ("SubnetIds", "SubnetIds"),
                    ("VpcSecurityGroups", "VpcSecurityGroups"),
                ),
            ),
        ),
        "lambda-functions": CliQuery(
            commands=("aws lambda list-functions",),
            output=OutputSpec(
                source="lambda-functions",
                rows="items",
                columns=(("FunctionName", "FunctionName"), ("SubnetIds", "SubnetIds"), ("SecurityGroupIds", "SecurityGroupIds")),
            ),
        ),
        "vpc-endpoints": CliQuery(
            commands=("aws ec2 describe-vpc-endpoints",),
            output=OutputSpec(
                source="vpc-endpoints",
                rows="items",
                columns=(("VpcEndpointId", "VpcEndpointId"), ("VpcId", "VpcId"), ("ServiceName", "ServiceName"), ("State", "State")),
            ),
        ),
        "internet-gateways": CliQuery(
            commands=("aws ec2 describe-internet-gateways",),
            output=OutputSpec(
                source="internet-gateways",
                rows="items",
                columns=(("InternetGatewayId", "InternetGatewayId"), ("Attachments", "Attachments"), ("Tags", "Tags")),
            ),
        ),
        "vpn-connections": CliQuery(
            commands=("aws ec2 describe-vpn-connections",),
            output=OutputSpec(source="vpn-connections", rows="items", columns=(("VpnConnectionId", "VpnConnectionId"), ("State", "State"), ("Routes", "Routes"))),
        ),
        "transit-gateway-topology": CliQuery(
            commands=(
                "aws ec2 describe-transit-gateways\n"
                "aws ec2 describe-transit-gateway-attachments\n"
                "aws ec2 describe-transit-gateway-route-tables",
            ),
            output=OutputSpec(
                source="transit-gateway-topology",
                rows="attachments",
                columns=(("TransitGatewayId", "TransitGatewayId"), ("ResourceType", "ResourceType"), ("ResourceId", "ResourceId"), ("State", "State")),
            ),
            derived_note="Drystone combines Transit Gateway inventory, attachments, and route tables to evaluate inspection paths.",
        ),
        "nat-gateway-routes": CliQuery(
            commands=("aws ec2 describe-nat-gateways\naws ec2 describe-route-tables",),
            output=OutputSpec(
                source="nat-gateway-routes",
                rows="items",
                columns=(("NatGatewayId", "NatGatewayId"), ("VpcId", "VpcId"), ("SubnetId", "SubnetId"), ("AssociatedRouteTables", "AssociatedRouteTables")),
            ),
            derived_note="Drystone derives NAT route relationships by matching NAT Gateway IDs in route-table routes.",
        ),
    }
}

_CHECK_STEMS = {
    "NET-001": "security-groups",
    "NET-002": "security-groups",
    "NET-003": "network-acls",
    "NET-004": "route-tables",
    "NET-005": "route-tables",
    "NET-006": "security-groups",
    "NET-007": "vpc-endpoints",
    "NET-008": "subnets",
    "NET-009": "security-groups",
    "NET-010": "network-acls",
    "NET-011": "security-groups",
    "NET-012": "transit-gateway-topology",
    "NET-013": "nat-gateway-routes",
    "NET-014": "route-tables",
    "NET-015": "security-groups",
    "NET-016": "network-acls",
    "NET-017": "route-tables",
    "NET-018": "vpcs",
    "NET-019": "security-groups",
    "NET-020": "network-acls",
    "NET-021": "security-groups",
    "NET-022": "route-tables",
    "NET-023": "route-tables",
    "NET-024": "vpcs",
    "NET-025": "subnets",
    "NET-026": "security-groups",
    "NET-027": "security-groups",
    "NET-028": "network-acls",
    "NET-029": "vpcs",
    "NET-030": "route-tables",
    "NET-031": "vpcs",
    "NET-032": "route-tables",
}

_CHECK_NAMES = {
    "NET-001": "Sensitive ports open to world",
    "NET-002": "Security groups allow all traffic",
    "NET-003": "NACL allow all rules",
    "NET-004": "Sensitive subnet IGW routes",
    "NET-005": "Broad VPC peering routes",
    "NET-006": "Cross-account security group references",
    "NET-007": "Network Firewall coverage",
    "NET-008": "Critical workloads in public subnets",
    "NET-009": "Broad CIDRs to non-web ports",
    "NET-010": "Default NACL permissiveness",
    "NET-011": "Security group rule descriptions",
    "NET-012": "Transit Gateway firewall inspection",
    "NET-013": "Private subnet AWS service egress",
    "NET-014": "Blackhole routes",
    "NET-015": "Redundant security group rules",
    "NET-016": "Subnets using default NACLs",
    "NET-017": "Private subnet IGW routes",
    "NET-018": "VPC Flow Logs",
    "NET-019": "Security group rule count",
    "NET-020": "NACL rule numbering",
    "NET-021": "Orphaned security groups",
    "NET-022": "Public subnet workload validation",
    "NET-023": "VPC peering ownership tags",
    "NET-024": "Network naming conventions",
    "NET-025": "Subnet classification tags",
    "NET-026": "Restrictive egress update paths",
    "NET-027": "Security group tags",
    "NET-028": "NACL stale rules",
    "NET-029": "Overlapping VPC CIDRs",
    "NET-030": "Static route propagation",
    "NET-031": "VPC DNS settings",
    "NET-032": "Multiple default routes",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["network"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=_CHECK_NAMES[_check_id],
        derived_note=_source_query.derived_note,
    )
