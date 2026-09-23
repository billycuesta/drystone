"""WAF AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"waf"})

_WEB_ACLS_OUTPUT = OutputSpec(
    source="wafv2-web-acls",
    rows="",
    columns=(
        ("Name", "Name"),
        ("ARN", "ARN"),
        ("Scope", "Scope"),
        ("Region", "Region"),
        ("Logging", "Logging"),
        ("AssociatedResourceArns", "AssociatedResourceArns"),
        ("Rules", "WebACL.Rules"),
    ),
)

SOURCE_QUERIES = {
    "waf": {
        "cloudfront-distributions": CliQuery(
            commands=("aws cloudfront list-distributions",),
            output=OutputSpec(source="cloudfront-distributions", rows="", columns=(("Id", "Id"), ("DomainName", "DomainName"), ("WebACLId", "WebACLId"), ("Enabled", "Enabled"))),
        ),
        "cloudfront-wafv2-associations": CliQuery(
            commands=("aws cloudfront list-distributions",),
            output=OutputSpec(source="cloudfront-wafv2-associations", style="kv"),
            derived_note="Drystone derives CloudFront WAFv2 associations from each distribution WebACLId field.",
        ),
        "cloudfront-classic-associations": CliQuery(
            commands=("aws cloudfront list-distributions",),
            output=OutputSpec(source="cloudfront-classic-associations", style="kv"),
            derived_note="Drystone derives CloudFront WAF Classic associations from legacy distribution WebACLId values.",
        ),
        "wafv2-web-acls": CliQuery(
            commands=(
                'for scope in REGIONAL CLOUDFRONT; do\n'
                '  aws wafv2 list-web-acls --scope "$scope"\n'
                "done",
            ),
            output=_WEB_ACLS_OUTPUT,
        ),
        "wafv2-ip-sets": CliQuery(
            commands=(
                'for scope in REGIONAL CLOUDFRONT; do\n'
                '  aws wafv2 list-ip-sets --scope "$scope"\n'
                "done",
            ),
            output=OutputSpec(source="wafv2-ip-sets", rows="", columns=(("Name", "Name"), ("ARN", "ARN"), ("Scope", "Scope"), ("Addresses", "IPSet.Addresses"))),
        ),
        "wafv2-rule-groups": CliQuery(
            commands=(
                'for scope in REGIONAL CLOUDFRONT; do\n'
                '  aws wafv2 list-rule-groups --scope "$scope"\n'
                "done",
            ),
            output=OutputSpec(source="wafv2-rule-groups", rows="", columns=(("Name", "Name"), ("ARN", "ARN"), ("Scope", "Scope"), ("Rules", "RuleGroup.Rules"))),
        ),
        "wafv2-managed-rule-groups": CliQuery(
            commands=(
                'for scope in REGIONAL CLOUDFRONT; do\n'
                '  aws wafv2 list-available-managed-rule-groups --scope "$scope"\n'
                "done",
            ),
            output=OutputSpec(source="wafv2-managed-rule-groups", style="kv"),
        ),
        "alb-waf-associations": CliQuery(
            commands=(
                'for lb in $(aws elbv2 describe-load-balancers --query "LoadBalancers[?Scheme==\'internet-facing\'].LoadBalancerArn" --output text); do\n'
                '  aws wafv2 get-web-acl-for-resource --resource-arn "$lb"\n'
                "done",
            ),
            output=OutputSpec(source="alb-waf-associations", rows="", columns=(("LoadBalancerArn", "LoadBalancerArn"), ("DNSName", "DNSName"), ("Region", "Region"), ("WAFv2WebACL", "WAFv2WebACL"))),
        ),
        "api-entrypoints-waf-associations": CliQuery(
            commands=(
                "aws apigateway get-rest-apis\n"
                "aws apigatewayv2 get-apis\n"
                "aws appsync list-graphql-apis\n"
                "aws cognito-idp list-user-pools",
            ),
            output=OutputSpec(source="api-entrypoints-waf-associations", rows="", columns=(("Service", "Service"), ("ResourceArn", "ResourceArn"), ("Name", "Name"), ("WAFv2WebACL", "WAFv2WebACL"))),
        ),
        "waf-classic": CliQuery(
            commands=("aws waf list-web-acls\naws waf-regional list-web-acls",),
            output=OutputSpec(source="waf-classic", style="kv"),
        ),
        "waf-collection-status": CliQuery(
            commands=(
                "aws cloudfront list-distributions\n"
                "aws wafv2 list-web-acls --scope REGIONAL\n"
                "aws wafv2 list-web-acls --scope CLOUDFRONT\n"
                "aws elbv2 describe-load-balancers",
            ),
            output=OutputSpec(source="waf-collection-status", style="kv"),
            derived_note="Drystone records per-service collection success and failures while gathering WAF posture evidence.",
        ),
    }
}

_CHECK_STEMS = {
    "WAF-001": "alb-waf-associations",
    "WAF-002": "cloudfront-distributions",
    "WAF-003": "wafv2-web-acls",
    "WAF-004": "wafv2-web-acls",
    "WAF-005": "wafv2-web-acls",
    "WAF-006": "wafv2-web-acls",
    "WAF-007": "wafv2-web-acls",
    "WAF-008": "wafv2-web-acls",
    "WAF-009": "wafv2-ip-sets",
    "WAF-010": "waf-classic",
    "WAF-011": "wafv2-web-acls",
    "WAF-012": "wafv2-rule-groups",
    "WAF-013": "waf-collection-status",
    "WAF-014": "api-entrypoints-waf-associations",
    "WAF-015": "api-entrypoints-waf-associations",
    "WAF-016": "api-entrypoints-waf-associations",
}

_CHECK_NAMES = {
    "WAF-001": "ALB WAF protection",
    "WAF-002": "CloudFront WAF protection",
    "WAF-003": "WAF logging",
    "WAF-004": "WAF log redaction",
    "WAF-005": "WAF visibility metrics",
    "WAF-006": "WAF managed rules",
    "WAF-007": "WAF count-only rules",
    "WAF-008": "WAF rate based rules",
    "WAF-009": "WAF IP set ranges",
    "WAF-010": "WAF Classic migration",
    "WAF-011": "Unassociated Web ACLs",
    "WAF-012": "WAF reusable rule groups",
    "WAF-013": "WAF collection status",
    "WAF-014": "API Gateway WAF protection",
    "WAF-015": "AppSync WAF protection",
    "WAF-016": "Cognito WAF protection",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["waf"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=_CHECK_NAMES[_check_id],
        derived_note=_source_query.derived_note,
    )
