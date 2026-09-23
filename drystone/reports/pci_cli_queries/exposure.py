"""Exposure AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"exposure"})

_S3_OUTPUT = OutputSpec(
    source="s3-buckets",
    rows="items",
    columns=(
        ("Name", "Name"),
        ("PublicAccessBlock", "PublicAccessBlock"),
        ("ACL", "ACL"),
        ("BucketPolicy", "BucketPolicy"),
        ("Versioning", "Versioning"),
        ("EncryptionAlgorithm", "EncryptionAlgorithm"),
        ("KMSMasterKeyID", "KMSMasterKeyID"),
    ),
)

_SECURITY_GROUPS_OUTPUT = OutputSpec(
    source="security-groups",
    rows="items",
    columns=(("GroupId", "GroupId"), ("GroupName", "GroupName"), ("VpcId", "VpcId"), ("IngressRules", "IngressRules")),
)

SOURCE_QUERIES = {
    "exposure": {
        "s3-buckets": CliQuery(
            commands=(
                'for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do\n'
                '  aws s3api get-public-access-block --bucket "$bucket"\n'
                '  aws s3api get-bucket-acl --bucket "$bucket"\n'
                '  aws s3api get-bucket-policy --bucket "$bucket"\n'
                '  aws s3api get-bucket-versioning --bucket "$bucket"\n'
                '  aws s3api get-bucket-encryption --bucket "$bucket"\n'
                "done",
            ),
            output=_S3_OUTPUT,
        ),
        "rds-instances": CliQuery(
            commands=("aws rds describe-db-instances",),
            output=OutputSpec(source="rds-instances", rows="items", columns=(("DBInstanceIdentifier", "DBInstanceIdentifier"), ("Engine", "Engine"), ("PubliclyAccessible", "PubliclyAccessible"), ("VpcSecurityGroups", "VpcSecurityGroups"))),
        ),
        "security-groups": CliQuery(commands=("aws ec2 describe-security-groups",), output=_SECURITY_GROUPS_OUTPUT),
        "ami-images": CliQuery(
            commands=(
                'for image in $(aws ec2 describe-images --owners self --query "Images[].ImageId" --output text); do\n'
                '  aws ec2 describe-images --image-ids "$image"\n'
                '  aws ec2 describe-image-attribute --image-id "$image" --attribute launchPermission\n'
                "done",
            ),
            output=OutputSpec(source="ami-images", rows="items", columns=(("ImageId", "ImageId"), ("Name", "Name"), ("Public", "Public"), ("LaunchPermissions", "LaunchPermissions"))),
        ),
        "cloudfront-distributions": CliQuery(
            commands=("aws cloudfront list-distributions",),
            output=OutputSpec(source="cloudfront-distributions", rows="items", columns=(("Id", "Id"), ("DomainName", "DomainName"), ("Enabled", "Enabled"), ("Origins", "Origins"), ("DefaultCacheBehavior", "DefaultCacheBehavior"))),
        ),
        "load-balancers": CliQuery(
            commands=("aws elbv2 describe-load-balancers",),
            output=OutputSpec(source="load-balancers", rows="items", columns=(("LoadBalancerArn", "LoadBalancerArn"), ("LoadBalancerName", "LoadBalancerName"), ("Scheme", "Scheme"), ("Type", "Type"), ("SecurityGroups", "SecurityGroups"))),
        ),
        "load-balancer-listeners": CliQuery(
            commands=(
                'for lb in $(aws elbv2 describe-load-balancers --query "LoadBalancers[].LoadBalancerArn" --output text); do\n'
                '  aws elbv2 describe-listeners --load-balancer-arn "$lb"\n'
                "done",
            ),
            output=OutputSpec(source="load-balancer-listeners", rows="items", columns=(("LoadBalancerArn", "LoadBalancerArn"), ("Protocol", "Protocol"), ("Port", "Port"), ("SslPolicy", "SslPolicy"))),
        ),
        "wafv2-web-acls": CliQuery(
            commands=("aws wafv2 list-web-acls --scope REGIONAL",),
            output=OutputSpec(source="wafv2-web-acls", rows="items", columns=(("Name", "Name"), ("ARN", "ARN"), ("Scope", "Scope"))),
        ),
        "wafv2-web-acl-alb-associations": CliQuery(
            commands=(
                'for acl in $(aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[].ARN" --output text); do\n'
                '  aws wafv2 list-resources-for-web-acl --web-acl-arn "$acl" --resource-type APPLICATION_LOAD_BALANCER\n'
                "done",
            ),
            output=OutputSpec(source="wafv2-web-acl-alb-associations", rows="by_alb_arn", columns=(("LoadBalancerArn", ""), ("WebACLArns", ""))),
            derived_note="Drystone derives the ALB association map by inverting WAFv2 list-resources-for-web-acl results.",
        ),
        "lambda-function-urls": CliQuery(
            commands=(
                'for fn in $(aws lambda list-functions --query "Functions[].FunctionName" --output text); do\n'
                '  aws lambda get-function-url-config --function-name "$fn"\n'
                "done",
            ),
            output=OutputSpec(source="lambda-function-urls", rows="items", columns=(("FunctionName", "FunctionName"), ("FunctionUrl", "FunctionUrl"), ("AuthType", "AuthType"), ("IsPublic", "IsPublic"))),
        ),
        "api-gateway-stages": CliQuery(
            commands=(
                'for api in $(aws apigateway get-rest-apis --query "items[].id" --output text); do\n'
                '  aws apigateway get-stages --rest-api-id "$api"\n'
                "done\n"
                'for api in $(aws apigatewayv2 get-apis --query "Items[].ApiId" --output text); do\n'
                '  aws apigatewayv2 get-stages --api-id "$api"\n'
                "done",
            ),
            output=OutputSpec(source="api-gateway-stages", rows="items", columns=(("ApiType", "ApiType"), ("ApiId", "ApiId"), ("StageName", "StageName"), ("InvokeUrl", "InvokeUrl"), ("HasWAF", "HasWAF"))),
        ),
        "api-gateway-routes": CliQuery(
            commands=(
                'for api in $(aws apigateway get-rest-apis --query "items[].id" --output text); do\n'
                '  aws apigateway get-resources --rest-api-id "$api"\n'
                "done\n"
                'for api in $(aws apigatewayv2 get-apis --query "Items[].ApiId" --output text); do\n'
                '  aws apigatewayv2 get-routes --api-id "$api"\n'
                "done",
            ),
            output=OutputSpec(source="api-gateway-routes", rows="items", columns=(("ApiType", "ApiType"), ("ApiId", "ApiId"), ("Path", "Path"), ("Method", "Method"), ("AuthorizationType", "AuthorizationType"), ("ApiKeyRequired", "ApiKeyRequired"))),
        ),
        "ecs-eks-ingress": CliQuery(
            commands=("aws ecs list-clusters\naws eks list-clusters",),
            output=OutputSpec(source="ecs-eks-ingress", rows="items", columns=(("Type", "Type"), ("ServiceName", "ServiceName"), ("ClusterName", "ClusterName"), ("EndpointPublicAccess", "EndpointPublicAccess"), ("LoadBalancers", "LoadBalancers"))),
        ),
        "elasticsearch-domains": CliQuery(
            commands=("aws opensearch list-domain-names\naws es list-domain-names",),
            output=OutputSpec(source="elasticsearch-domains", rows="items", columns=(("Service", "Service"), ("DomainName", "DomainName"), ("Endpoint", "Endpoint"), ("AccessPolicies", "AccessPolicies"), ("VPCOptions", "VPCOptions"))),
        ),
        "resource-based-policies": CliQuery(
            commands=("aws sqs list-queues\naws sns list-topics\naws ecr describe-repositories\naws secretsmanager list-secrets\naws opensearch list-domain-names",),
            output=OutputSpec(source="resource-based-policies", rows="items", columns=(("Service", "Service"), ("ResourceArn", "ResourceArn"), ("Policy", "Policy"), ("Issue", "Issue"))),
            derived_note="Drystone normalises resource policies from multiple AWS services and evaluates wildcard principals with weak conditions.",
        ),
    }
}

_CHECK_STEMS = {
    "EXP-001": "s3-buckets",
    "EXP-002": "rds-instances",
    "EXP-003": "security-groups",
    "EXP-004": "security-groups",
    "EXP-005": "lambda-function-urls",
    "EXP-006": "api-gateway-routes",
    "EXP-007": "wafv2-web-acl-alb-associations",
    "EXP-009": "cloudfront-distributions",
    "EXP-010": "load-balancer-listeners",
    "EXP-011": "s3-buckets",
    "EXP-012": "security-groups",
    "EXP-013": "s3-buckets",
    "EXP-014": "s3-buckets",
    "EXP-015": "s3-buckets",
    "EXP-016": "lambda-function-urls",
    "EXP-017": "api-gateway-stages",
    "EXP-018": "ecs-eks-ingress",
    "EXP-019": "elasticsearch-domains",
    "EXP-020": "cloudfront-distributions",
    "EXP-021": "api-gateway-routes",
    "EXP-022": "api-gateway-routes",
    "EXP-023": "resource-based-policies",
    "EXP-024": "s3-buckets",
}

_CHECK_NAMES = {
    "EXP-001": "Public S3 buckets",
    "EXP-002": "Public RDS databases",
    "EXP-003": "SSH RDP open to world",
    "EXP-004": "EC2 management ports exposed",
    "EXP-005": "Public Lambda URLs",
    "EXP-006": "API Gateway auth and rate limits",
    "EXP-007": "Internet ALB WAF coverage",
    "EXP-009": "CloudFront Shield posture",
    "EXP-010": "ALB TLS policy",
    "EXP-011": "S3 public listing",
    "EXP-012": "EC2 IMDSv2 enforcement",
    "EXP-013": "S3 TLS enforcement",
    "EXP-014": "S3 audit bucket versioning",
    "EXP-015": "S3 policy principal conditions",
    "EXP-016": "Lambda URL authentication",
    "EXP-017": "API Gateway WAF coverage",
    "EXP-018": "Container ingress exposure",
    "EXP-019": "OpenSearch exposure",
    "EXP-020": "CloudFront S3 origin access",
    "EXP-021": "API mutation authentication",
    "EXP-022": "API wildcard route authentication",
    "EXP-023": "Resource policy wildcard principals",
    "EXP-024": "S3 audit bucket KMS encryption",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["exposure"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=_CHECK_NAMES[_check_id],
        derived_note=_source_query.derived_note,
    )
