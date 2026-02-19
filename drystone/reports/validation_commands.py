"""Helpers to derive reproducible AWS CLI validation commands per finding."""

from __future__ import annotations

from typing import Dict, List


def suggest_aws_cli_commands(
    skill: str,
    evidence_refs: List[str],
    region: str = "us-east-1",
    account_id: str = "<account-id>",
    finding_id: str = "",
) -> List[str]:
    """Suggest AWS CLI commands from evidence references.

    Commands are intentionally deterministic and runnable against AWS,
    not local evidence files.
    """
    skill_file_maps: Dict[str, Dict[str, str]] = {
        "iam": {
            "account-summary.json": "aws iam get-account-summary",
            "password-policy.json": "aws iam get-account-password-policy",
            "instance-profiles.json": "aws iam list-instance-profiles",
            "resource-based-policies.json": "aws sns list-topics",
            "assumeRole-chains.json": "aws iam list-roles",
            "groups.json": "aws iam list-groups",
            "roles.json": "aws iam list-roles",
            "users.json": "aws iam list-users",
            "policies.json": "aws iam list-policies --scope Local",
            "credential-report.csv": "aws iam get-credential-report",
            "credential-report": "aws iam get-credential-report",
        },
        "network": {
            "security-groups.json": f"aws ec2 describe-security-groups --region {region}",
            "route-tables.json": f"aws ec2 describe-route-tables --region {region}",
            "network-acls.json": f"aws ec2 describe-network-acls --region {region}",
            "subnets.json": f"aws ec2 describe-subnets --region {region}",
            "vpc-endpoints.json": f"aws ec2 describe-vpc-endpoints --region {region}",
            "internet-gateways.json": f"aws ec2 describe-internet-gateways --region {region}",
            "vpcs.json": f"aws ec2 describe-vpcs --region {region}",
            "network-interfaces.json": f"aws ec2 describe-network-interfaces --region {region}",
            "transit-gateway-topology.json": f"aws ec2 describe-transit-gateways --region {region}",
            "vpn-connections.json": f"aws ec2 describe-vpn-connections --region {region}",
            "nat-gateway-routes.json": f"aws ec2 describe-nat-gateways --region {region}",
            "privatelink-endpoints.json": f"aws ec2 describe-vpc-endpoints --region {region}",
        },
        "exposure": {
            "s3-buckets.json": "aws s3api list-buckets && aws s3api get-bucket-policy --bucket <bucket-name>",
            "load-balancers.json": f"aws elbv2 describe-load-balancers --region {region}",
            "load-balancer-listeners.json": f"aws elbv2 describe-listeners --load-balancer-arn <alb-arn> --region {region}",
            "rds-instances.json": f"aws rds describe-db-instances --region {region}",
            "rds-snapshots.json": f"aws rds describe-db-snapshots --region {region}",
            "cloudfront-distributions.json": "aws cloudfront list-distributions",
            "api-gateway-stages.json": f"aws apigateway get-rest-apis --region {region}",
            "lambda-function-urls.json": f"aws lambda list-functions --region {region}",
            "elasticsearch-domains.json": f"aws es list-domain-names --region {region}",
            "ecs-eks-ingress.json": f"aws ecs list-clusters --region {region} && aws eks list-clusters --region {region}",
        },
        "waf": {
            "wafv2-web-acls.json": (
                f"aws wafv2 list-web-acls --scope REGIONAL --region {region} && "
                "aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1"
            ),
            "wafv2-rule-groups.json": f"aws wafv2 list-rule-groups --scope REGIONAL --region {region}",
            "wafv2-managed-rule-groups.json": f"aws wafv2 list-available-managed-rule-groups --scope REGIONAL --region {region}",
            "wafv2-ip-sets.json": f"aws wafv2 list-ip-sets --scope REGIONAL --region {region}",
            "wafv2-regex-pattern-sets.json": f"aws wafv2 list-regex-pattern-sets --scope REGIONAL --region {region}",
            "waf-classic.json": f"aws waf-regional list-web-acls --region {region}",
            "cloudfront-wafv2-associations.json": "aws cloudfront list-distributions",
            "alb-waf-associations.json": f"aws elbv2 describe-load-balancers --region {region}",
        },
        "secretsmanager": {
            "secrets.json": f"aws secretsmanager list-secrets --region {region}",
            "resource-policy.json": f"aws secretsmanager list-secrets --region {region}",
            "rotation-status.json": f"aws secretsmanager list-secrets --region {region}",
        },
        "ecr": {
            "registry.json": f"aws ecr describe-registry --region {region}",
            "repositories.json": f"aws ecr describe-repositories --region {region}",
            "images.json": f"aws ecr describe-images --repository-name <repo> --region {region}",
        },
        "kms": {
            "keys.json": f"aws kms list-keys --region {region}",
            "aliases.json": f"aws kms list-aliases --region {region}",
            "key-policies.json": f"aws kms list-keys --region {region}",
            "kms-keys.json": f"aws kms list-keys --region {region}",
            "kms-key-policies.json": f"aws kms get-key-policy --key-id <key-id> --policy-name default --region {region}",
            "kms-grants.json": f"aws kms list-grants --key-id <key-id> --region {region}",
            "kms-aliases.json": f"aws kms list-aliases --region {region}",
            "kms-custom-key-stores.json": f"aws kms describe-custom-key-stores --region {region}",
        },
        "messaging": {
            "sqs-queues.json": f"aws sqs list-queues --region {region}",
            "sns-topics.json": f"aws sns list-topics --region {region}",
            "sns-subscriptions.json": f"aws sns list-subscriptions --region {region}",
        },
        "cicd": {
            "codebuild-projects.json": f"aws codebuild list-projects --region {region}",
            "codebuild-builds.json": f"aws codebuild list-builds --region {region}",
        },
        "compute": {
            "ecs-clusters.json": f"aws ecs list-clusters --region {region}",
            "ecs-services.json": f"aws ecs list-services --cluster <cluster> --region {region}",
            "eks-clusters.json": f"aws eks list-clusters --region {region}",
            "eks-nodegroups.json": f"aws eks list-nodegroups --cluster-name <cluster> --region {region}",
            "ec2-instances.json": f"aws ec2 describe-instances --region {region}",
        },
        "alerting": {
            "cloudtrail-trails.json": f"aws cloudtrail describe-trails --region {region}",
            "cloudwatch-alarms.json": f"aws cloudwatch describe-alarms --region {region}",
            "eventbridge-rules.json": f"aws events list-rules --region {region}",
            "sns-topics.json": f"aws sns list-topics --region {region}",
        },
        "hardening": {
            "securityhub-standards.json": f"aws securityhub get-enabled-standards --region {region}",
            "config-rules.json": f"aws configservice describe-config-rules --region {region}",
            "config-compliance.json": f"aws configservice describe-compliance-by-config-rule --region {region}",
        },
        "vulns": {
            "inspector-findings.json": f"aws inspector2 list-findings --region {region}",
            "inspector-coverage.json": f"aws inspector2 list-coverage --region {region}",
        },
    }

    # Smart per-file commands for IAM special cases.
    def _iam_specific(file_name: str, token: str) -> str:
        if file_name == "users.json" and token:
            return f"aws iam get-user --user-name {token}"
        if file_name == "roles.json" and token:
            return f"aws iam get-role --role-name {token}"
        if file_name == "groups.json" and token:
            return f"aws iam get-group --group-name {token}"
        if file_name == "resource-based-policies.json":
            return f"aws sns get-topic-attributes --topic-arn arn:aws:sns:{region}:{account_id}:OpsGenie"
        return ""

    # Smart per-finding commands for Secrets Manager checks.
    def _secretsmanager_specific(fid: str) -> List[str]:
        fid = fid.strip().upper()
        if not fid:
            return []

        if fid == "SM-001":
            return [
                f"aws secretsmanager list-secrets --region {region}",
                f"aws secretsmanager get-resource-policy --secret-id <secret-id-or-arn> --region {region}",
            ]
        if fid == "SM-002":
            return [
                f"aws secretsmanager list-secrets --region {region}",
                f"aws secretsmanager describe-secret --secret-id <secret-id-or-arn> --region {region}",
            ]
        if fid == "SM-003":
            return [
                f"aws secretsmanager describe-secret --secret-id <secret-id-or-arn> --region {region}",
                f"aws secretsmanager list-secret-version-ids --secret-id <secret-id-or-arn> --region {region}",
            ]
        if fid == "SM-004":
            return [
                f"aws secretsmanager describe-secret --secret-id <secret-id-or-arn> --region {region}",
                f"aws kms describe-key --key-id <kms-key-id-or-arn> --region {region}",
            ]
        if fid == "SM-012":
            return [
                f"aws cloudwatch describe-alarms --region {region}",
                f"aws events list-rules --region {region}",
                f"aws events list-targets-by-rule --rule <rule-name> --region {region}",
            ]
        if fid == "SM-013":
            return [
                f"aws secretsmanager get-resource-policy --secret-id <secret-id-or-arn> --region {region}",
            ]
        if fid == "SM-014":
            return [
                f"aws secretsmanager describe-secret --secret-id <secret-id-or-arn> --region {region}",
            ]
        if fid == "SM-015":
            return [
                f"aws secretsmanager describe-secret --secret-id <secret-id-or-arn> --region {region}",
                f"aws kms describe-key --key-id <kms-key-id-or-arn> --region {region}",
            ]
        if fid == "SM-017":
            return [
                f"aws secretsmanager describe-secret --secret-id <secret-id-or-arn> --region {region}",
                f"aws secretsmanager get-resource-policy --secret-id <secret-id-or-arn> --region {region}",
            ]

        return []

    generic = {
        "ec2-instances.json": f"aws ec2 describe-instances --region {region}",
        "rds-instances.json": f"aws rds describe-db-instances --region {region}",
        "lambda-functions.json": f"aws lambda list-functions --region {region}",
        "security-groups.json": f"aws ec2 describe-security-groups --region {region}",
        "subnets.json": f"aws ec2 describe-subnets --region {region}",
        "vpcs.json": f"aws ec2 describe-vpcs --region {region}",
        "policies.json": "aws iam list-policies --scope Local",
        "users.json": "aws iam list-users",
        "roles.json": "aws iam list-roles",
    }

    commands: List[str] = []
    seen = set()
    smap = skill_file_maps.get(skill, {})

    if skill == "secretsmanager":
        for cmd in _secretsmanager_specific(finding_id):
            if cmd not in seen:
                commands.append(cmd)
                seen.add(cmd)

    for ref in evidence_refs:
        ref_s = str(ref)
        file_name, anchor = (ref_s.split("#", 1) + [""])[:2] if "#" in ref_s else (ref_s, "")
        token = anchor.split(".")[-1].strip() if anchor else ""

        cmd = ""
        if skill == "iam":
            cmd = _iam_specific(file_name, token)
        if not cmd:
            cmd = smap.get(file_name, "")
        if not cmd:
            cmd = generic.get(file_name, "")

        if cmd and cmd not in seen:
            commands.append(cmd)
            seen.add(cmd)

    return commands[:8]
