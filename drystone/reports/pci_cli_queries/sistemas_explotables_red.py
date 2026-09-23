"""Sistemas Explotables Red AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"sistemas_explotables_red"})

SOURCE_QUERIES = {
    "sistemas_explotables_red": {
        "compute-inventory": CliQuery(
            commands=(
                "aws ec2 describe-instances\n"
                "aws ecs list-services --cluster <cluster-name>\n"
                "aws lambda list-functions\n"
                "aws rds describe-db-instances",
            ),
            output=OutputSpec(
                source="compute-inventory",
                style="kv",
            ),
            derived_note="Drystone normalizes EC2, ECS, Lambda, and RDS inventory into one compute-inventory object.",
        ),
        "network-controls": CliQuery(
            commands=(
                "aws ec2 describe-security-groups\n"
                "aws ec2 describe-route-tables\n"
                "aws ec2 describe-network-acls",
            ),
            output=OutputSpec(source="network-controls", style="kv"),
        ),
        "front-doors": CliQuery(
            commands=(
                "aws elbv2 describe-load-balancers\n"
                "aws elbv2 describe-listeners --load-balancer-arn <load-balancer-arn>\n"
                "aws elbv2 describe-target-groups\n"
                "aws lambda list-function-url-configs --function-name <function-name>\n"
                "aws apigatewayv2 get-apis",
            ),
            output=OutputSpec(source="front-doors", style="kv"),
            derived_note="Drystone combines load balancers, listener paths, targets, Lambda URLs, and API Gateway routes as public front doors.",
        ),
        "inspector-findings-normalized": CliQuery(
            commands=("aws inspector2 list-findings",),
            output=OutputSpec(
                source="inspector-findings-normalized",
                rows="findings",
                columns=(
                    ("resourceId", "resourceId"),
                    ("severity", "severity"),
                    ("status", "status"),
                    ("title", "title"),
                    ("cve", "cve"),
                ),
            ),
            derived_note="Drystone normalizes Inspector findings into compact vulnerability rows.",
        ),
        "reachability-graph": CliQuery(
            commands=(
                "aws ec2 describe-instances\n"
                "aws ec2 describe-security-groups\n"
                "aws ec2 describe-route-tables\n"
                "aws elbv2 describe-load-balancers",
            ),
            output=OutputSpec(
                source="reachability-graph",
                rows="edges",
                columns=(("source", "source"), ("target", "target"), ("type", "type"), ("reason", "reason")),
            ),
            derived_note="Drystone derives reachability edges by correlating public entry points, routes, security groups, and compute targets.",
        ),
        "port-service-hypothesis": CliQuery(
            commands=("aws ec2 describe-security-groups",),
            output=OutputSpec(
                source="port-service-hypothesis",
                rows="items",
                columns=(("resource", "resource"), ("port", "port"), ("service", "service"), ("confidence", "confidence")),
            ),
            derived_note="Drystone derives likely exposed services from ingress ports and protocol conventions without active scanning.",
        ),
        "attack-path-candidates": CliQuery(
            commands=(
                "aws ec2 describe-instances\n"
                "aws ec2 describe-security-groups\n"
                "aws inspector2 list-findings",
            ),
            output=OutputSpec(
                source="attack-path-candidates",
                rows="paths",
                columns=(("asset", "asset"), ("path", "path"), ("severity", "severity"), ("signals", "signals")),
            ),
            derived_note="Drystone derives attack-path candidates by correlating reachability, vulnerability, and blast-radius signals.",
        ),
        "cve-intelligence": CliQuery(
            commands=("aws inspector2 list-findings",),
            output=OutputSpec(
                source="cve-intelligence",
                style="kv",
            ),
            derived_note="Drystone enriches Inspector CVEs with local CVE intelligence such as CISA KEV and public-exploit signals.",
        ),
    }
}

_CHECK_STEMS = {
    "SER-EC2-001": "reachability-graph",
    "SER-EC2-002": "attack-path-candidates",
    "SER-ECS-001": "reachability-graph",
    "SER-LMB-001": "front-doors",
    "SER-LMB-002": "front-doors",
    "SER-RDS-001": "reachability-graph",
    "SER-COR-003": "attack-path-candidates",
    "SER-CVE-001": "cve-intelligence",
}

_DERIVED_NOTES = {
    "SER-EC2-001": "Drystone derives internet-reachable administrative exposure from compute inventory, route tables, and security-group ingress.",
    "SER-EC2-002": "Drystone correlates reachability graph edges with active Inspector findings to prioritize exposed vulnerable EC2 instances.",
    "SER-ECS-001": "Drystone derives ECS reachability by correlating internet-facing ALBs, target groups, and ECS service targets.",
    "SER-LMB-001": "Drystone derives unauthenticated Lambda URL exposure from front-door inventory and AuthType values.",
    "SER-LMB-002": "Drystone derives unauthenticated API Gateway to Lambda exposure from route authorization and integration metadata.",
    "SER-RDS-001": "Drystone derives public RDS exposure by correlating public DB settings, security groups, and internet routes.",
    "SER-COR-003": "Drystone derives correlated exploitation risk from network exposure, vulnerable software, and blast-radius context.",
    "SER-CVE-001": "Drystone derives known-exploited vulnerability exposure by correlating CVE intelligence with internet-reachable assets.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["sistemas_explotables_red"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
