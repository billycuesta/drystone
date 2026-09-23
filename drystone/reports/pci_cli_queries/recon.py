"""Recon AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"recon"})

SOURCE_QUERIES = {
    "recon": {
        "route53-zones": CliQuery(
            commands=(
                'for zone in $(aws route53 list-hosted-zones --query "HostedZones[].Id" --output text); do\n'
                '  aws route53 list-resource-record-sets --hosted-zone-id "$zone"\n'
                "done",
            ),
            output=OutputSpec(
                source="route53-zones",
                rows="zones",
                columns=(
                    ("Id", "Id"),
                    ("Name", "Name"),
                    ("IsPrivate", "IsPrivate"),
                    ("RecordCount", "RecordCount"),
                    ("Records", "Records"),
                    ("SensitivityAnalysis", "SensitivityAnalysis"),
                ),
            ),
        ),
        "api-gateway-stages": CliQuery(
            commands=(
                "aws apigateway get-rest-apis\n"
                "aws apigatewayv2 get-apis\n"
                'for api in $(aws apigateway get-rest-apis --query "items[].id" --output text); do\n'
                '  aws apigateway get-stages --rest-api-id "$api"\n'
                "done",
            ),
            output=OutputSpec(
                source="api-gateway-stages",
                rows="apis",
                columns=(
                    ("Id", "Id"),
                    ("Name", "Name"),
                    ("Type", "Type"),
                    ("Stages", "Stages"),
                    ("UnauthenticatedRouteCount", "UnauthenticatedRouteCount"),
                ),
            ),
        ),
        "lambda-urls": CliQuery(
            commands=(
                'for function in $(aws lambda list-functions --query "Functions[].FunctionName" --output text); do\n'
                '  aws lambda list-function-url-configs --function-name "$function"\n'
                "done",
            ),
            output=OutputSpec(
                source="lambda-urls",
                rows="urls",
                columns=(
                    ("FunctionName", "FunctionName"),
                    ("FunctionArn", "FunctionArn"),
                    ("FunctionUrl", "FunctionUrl"),
                    ("AuthType", "AuthType"),
                    ("IsPublic", "IsPublic"),
                    ("Cors", "Cors"),
                ),
            ),
        ),
        "load-balancer-dns": CliQuery(
            commands=(
                'for lb in $(aws elbv2 describe-load-balancers --query "LoadBalancers[].LoadBalancerArn" '
                "--output text); do\n"
                '  aws elbv2 describe-load-balancers --load-balancer-arns "$lb"\n'
                '  aws elbv2 describe-listeners --load-balancer-arn "$lb"\n'
                "done",
            ),
            output=OutputSpec(
                source="load-balancer-dns",
                rows="load_balancers",
                columns=(
                    ("Name", "Name"),
                    ("DNSName", "DNSName"),
                    ("Scheme", "Scheme"),
                    ("Type", "Type"),
                    ("IsPublic", "IsPublic"),
                    ("Listeners", "Listeners"),
                    ("WafWebAclArn", "WafWebAclArn"),
                ),
            ),
        ),
        "public-endpoints": CliQuery(
            commands=(
                "aws ec2 describe-addresses\n"
                "aws ec2 describe-instances\n"
                "aws ec2 describe-nat-gateways",
            ),
            output=OutputSpec(
                source="public-endpoints",
                rows="elastic_ips",
                columns=(
                    ("PublicIp", "PublicIp"),
                    ("AssociatedWithInstance", "AssociatedWithInstance"),
                    ("InstanceId", "InstanceId"),
                    ("PermissiveSGRules", "PermissiveSGRules"),
                ),
            ),
            derived_note=(
                "NAT gateway IPs are also normalized in stored evidence, but this table uses the Elastic IP row set."
            ),
        ),
        "cloudfront-origins": CliQuery(
            commands=("aws cloudfront list-distributions",),
            output=OutputSpec(
                source="cloudfront-origins",
                rows="distributions",
                columns=(
                    ("Id", "Id"),
                    ("DomainName", "DomainName"),
                    ("Aliases", "Aliases"),
                    ("Enabled", "Enabled"),
                    ("Origins", "Origins"),
                    ("LoggingEnabled", "LoggingEnabled"),
                    ("WebAclId", "WebAclId"),
                ),
            ),
        ),
        "attack-surface-score": CliQuery(
            commands=(
                "aws route53 list-hosted-zones\n"
                "aws elbv2 describe-load-balancers\n"
                "aws cloudfront list-distributions\n"
                "aws ec2 describe-addresses",
            ),
            output=OutputSpec(source="attack-surface-score", style="kv"),
            derived_note="Drystone calculates attack-surface score from public DNS, CDN, load balancer, and IP endpoint counts.",
        ),
    }
}

_CHECK_STEMS = {
    "RECON-001": "route53-zones",
    "RECON-002": "api-gateway-stages",
    "RECON-003": "public-endpoints",
    "RECON-004": "route53-zones",
    "RECON-005": "lambda-urls",
    "RECON-006": "cloudfront-origins",
    "RECON-007": "load-balancer-dns",
    "RECON-008": "attack-surface-score",
    "RECON-009": "api-gateway-stages",
    "RECON-010": "public-endpoints",
    "RECON-011": "load-balancer-dns",
    "RECON-012": "cloudfront-origins",
    "RECON-013": "route53-zones",
    "RECON-014": "api-gateway-stages",
    "RECON-015": "attack-surface-score",
    "RECON-016": "public-endpoints",
    "RECON-017": "load-balancer-dns",
    "RECON-018": "lambda-urls",
    "RECON-019": "cloudfront-origins",
}

_DERIVED_NOTES = {
    "RECON-003": "Drystone correlates public endpoints with attached security groups to assess exposure restrictions.",
    "RECON-008": SOURCE_QUERIES["recon"]["attack-surface-score"].derived_note,
    "RECON-010": "Drystone treats NAT Gateway public IPs as a composite public endpoint inventory input.",
    "RECON-015": SOURCE_QUERIES["recon"]["attack-surface-score"].derived_note,
    "RECON-016": "Drystone derives unassociated Elastic IP status from the normalized public endpoint inventory.",
    "RECON-019": "Drystone groups CloudFront distributions by origin domain to identify shared origins.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["recon"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
