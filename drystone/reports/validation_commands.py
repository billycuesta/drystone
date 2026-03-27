"""Helpers to derive reproducible AWS CLI validation commands per finding."""

from __future__ import annotations

from typing import Dict, List, Optional


def extract_resource_name(arn: str) -> Dict[str, str]:
    """Extract resource type and name from an ARN for use in CLI commands.

    Returns a dict with keys: service, type, name.
    Returns empty dict if ARN is not parseable.

    Examples:
        arn:aws:iam::123:role/admin-role  -> {service: iam, type: role, name: admin-role}
        arn:aws:s3:::my-bucket            -> {service: s3, type: my-bucket, name: my-bucket}
        arn:aws:ec2:us-east-1:123:instance/i-abc -> {service: ec2, type: instance, name: i-abc}
    """
    parts = arn.split(":")
    if len(parts) < 6:
        return {}
    service = parts[2]
    resource = parts[5] if len(parts) > 5 else ""
    if not resource:
        return {}
    resource_parts = resource.split("/", 1)
    resource_type = resource_parts[0]
    resource_name = resource_parts[1] if len(resource_parts) > 1 else resource
    return {"service": service, "type": resource_type, "name": resource_name}


def _arn_specific_commands(affected_resources: List[str], region: str, skill: str) -> List[str]:
    """Generate specific AWS CLI commands from affected_resources ARNs."""
    commands: List[str] = []
    seen: set = set()

    for arn in affected_resources[:5]:
        info = extract_resource_name(str(arn))
        if not info:
            continue
        service = info["service"]
        rtype = info["type"]
        name = info["name"]
        cmd: Optional[str] = None

        if service == "iam":
            if rtype == "role":
                cmd = f"aws iam get-role --role-name {name}"
            elif rtype == "user":
                cmd = f"aws iam get-user --user-name {name}"
            elif rtype == "policy":
                cmd = f"aws iam get-policy --policy-arn {arn}"
            elif rtype == "group":
                cmd = f"aws iam get-group --group-name {name}"
        elif service == "s3":
            # arn:aws:s3:::bucket-name has type=bucket-name, name=bucket-name
            bucket = rtype if not name or name == rtype else name
            cmd = f"aws s3api get-bucket-policy --bucket {bucket}"
        elif service == "ec2":
            if rtype == "instance":
                cmd = f"aws ec2 describe-instances --instance-ids {name} --region {region}"
            elif rtype == "security-group":
                cmd = f"aws ec2 describe-security-groups --group-ids {name} --region {region}"
        elif service == "rds":
            if rtype == "db":
                cmd = f"aws rds describe-db-instances --db-instance-identifier {name} --region {region}"
        elif service == "lambda":
            if rtype == "function":
                cmd = f"aws lambda get-function --function-name {name} --region {region}"
        elif service == "secretsmanager":
            if rtype == "secret":
                cmd = f"aws secretsmanager describe-secret --secret-id {arn} --region {region}"

        if cmd and cmd not in seen:
            commands.append(cmd)
            seen.add(cmd)

    return commands


def suggest_aws_cli_commands(
    skill: str,
    evidence_refs: List[str],
    region: str = "us-east-1",
    account_id: str = "<account-id>",
    finding_id: str = "",
    affected_resources: Optional[List[str]] = None,
) -> List[str]:
    """Suggest AWS CLI commands from evidence references and affected resource ARNs.

    Commands are intentionally deterministic and runnable against AWS,
    not local evidence files. When affected_resources contains parseable ARNs,
    resource-specific commands are generated (e.g. --role-name actual-name).
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
            "transit-gateway-topology.json": f"aws ec2 describe-transit-gateways --region {region}",
            "vpn-connections.json": f"aws ec2 describe-vpn-connections --region {region}",
            "nat-gateway-routes.json": f"aws ec2 describe-nat-gateways --region {region}",
        },
        "exposure": {
            "s3-buckets.json": "aws s3api list-buckets && aws s3api get-bucket-policy --bucket <bucket-name>",
            "load-balancers.json": f"aws elbv2 describe-load-balancers --region {region}",
            "load-balancer-listeners.json": f"aws elbv2 describe-listeners --load-balancer-arn <alb-arn> --region {region}",
            "rds-instances.json": f"aws rds describe-db-instances --region {region}",
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
        # Skip anchor tokens that are bare numeric indices (e.g. from "roles.json#/5").
        # These are JSON-pointer array offsets, not resource names — using them directly
        # would produce invalid CLI commands like `--role-name 5`.
        is_array_index = token.lstrip("/").isdigit()
        if file_name == "users.json" and token and not is_array_index:
            return f"aws iam get-user --user-name {token}"
        if file_name == "roles.json" and token and not is_array_index:
            return f"aws iam get-role --role-name {token}"
        if file_name == "groups.json" and token and not is_array_index:
            return f"aws iam get-group --group-name {token}"
        if file_name == "resource-based-policies.json":
            return f"aws sns get-topic-attributes --topic-arn arn:aws:sns:{region}:{account_id}:OpsGenie"
        return ""

    def _first_resource_name(arns: List[str], service: str, rtype: str = "") -> str:
        """Extract resource name from first matching ARN."""
        for arn in arns:
            info = extract_resource_name(str(arn))
            if not info or info.get("service") != service:
                continue
            if rtype and info.get("type") != rtype:
                continue
            return info.get("name", "")
        return ""

    def _iam_finding_specific(fid: str, res: List[str]) -> List[str]:
        """Per-finding-id commands for IAM checks."""
        fid = fid.strip().upper()
        role_name = _first_resource_name(res, "iam", "role") or "<role-name>"
        user_name = _first_resource_name(res, "iam", "user") or "<user-name>"

        if fid == "IAM-001":
            return [
                "aws iam get-account-summary",
                "aws iam list-mfa-devices --user-name root",
            ]
        if fid in ("IAM-002", "IAM-003"):
            return [
                "aws iam generate-credential-report",
                "aws iam get-credential-report",
                f"aws iam list-mfa-devices --user-name {user_name}",
            ]
        if fid == "IAM-004":
            return [
                f"aws iam list-access-keys --user-name {user_name}",
                "aws iam generate-credential-report && aws iam get-credential-report",
            ]
        if fid in ("IAM-030", "IAM-033"):
            return [
                f"aws iam get-role --role-name {role_name}",
                "aws iam list-roles | jq '.Roles[] | select(.AssumeRolePolicyDocument)'",
            ]
        if fid in ("IAM-041", "IAM-042"):
            return [
                f"aws iam list-attached-role-policies --role-name {role_name}",
                "aws iam list-roles | jq '.Roles[] | select(.RoleName)' | head -20",
            ]
        if fid == "IAM-043":
            return [
                f"aws iam get-role --role-name {role_name}",
                "aws iam list-roles | jq '.Roles[].AssumeRolePolicyDocument'",
            ]
        if fid == "IAM-040":
            return [
                "aws organizations list-policies --filter SERVICE_CONTROL_POLICY",
                "aws organizations describe-policy --policy-id <policy-id>",
            ]
        return []

    def _recon_finding_specific(fid: str, res: List[str]) -> List[str]:
        """Per-finding-id commands for RECON checks."""
        fid = fid.strip().upper()
        if fid == "RECON-002":
            api_id = _first_resource_name(res, "apigateway") or "<api-id>"
            return [
                f"aws apigateway get-rest-apis --region {region}",
                f"aws apigateway get-stages --rest-api-id {api_id} --region {region}",
            ]
        if fid == "RECON-003":
            return [
                f"aws ec2 describe-addresses --region {region}",
                f"aws ec2 describe-instances --filters Name=instance-state-name,Values=running --region {region}",
            ]
        if fid == "RECON-004":
            return [
                "aws route53 list-hosted-zones",
                "aws route53 list-resource-record-sets --hosted-zone-id <zone-id>",
            ]
        if fid == "RECON-005":
            func = _first_resource_name(res, "lambda", "function") or "<function-name>"
            return [
                f"aws lambda list-functions --region {region}",
                f"aws lambda get-function-url-config --function-name {func} --region {region}",
            ]
        if fid in ("RECON-006", "RECON-015"):
            return [
                "aws cloudfront list-distributions",
                "aws cloudfront get-distribution-config --id <dist-id>",
            ]
        if fid in ("RECON-007", "RECON-011"):
            return [
                f"aws elbv2 describe-load-balancers --region {region}",
                f"aws elbv2 describe-listeners --load-balancer-arn <alb-arn> --region {region}",
            ]
        return []

    def _exposure_finding_specific(fid: str, res: List[str]) -> List[str]:
        """Per-finding-id commands for EXPOSURE checks."""
        fid = fid.strip().upper()
        # Normalize S3 ARN: arn:aws:s3:::bucket-name
        bucket = ""
        for arn in res:
            info = extract_resource_name(str(arn))
            if info.get("service") == "s3":
                bucket = info.get("type") or info.get("name") or ""
                break
        bucket = bucket or "<bucket-name>"

        if fid in ("EXP-013", "EXP-014", "EXP-015"):
            return [
                f"aws s3api get-bucket-policy --bucket {bucket}",
                f"aws s3api get-bucket-acl --bucket {bucket}",
            ]
        if fid == "EXP-026":
            return [
                f"aws s3api get-bucket-public-access-block --bucket {bucket}",
                "aws s3api list-buckets",
            ]
        if fid in ("EXP-028", "EXP-029"):
            return [
                f"aws ec2 describe-snapshots --owner-ids self --region {region}",
                f"aws ec2 describe-snapshot-attribute --snapshot-id <snap-id> --attribute createVolumePermission --region {region}",
            ]
        if fid in ("EXP-021", "EXP-006", "EXP-022"):
            api_id = _first_resource_name(res, "apigateway") or "<api-id>"
            return [
                f"aws apigateway get-rest-apis --region {region}",
                f"aws apigateway get-resources --rest-api-id {api_id} --region {region}",
            ]
        if fid == "EXP-019":
            return [
                f"aws es list-domain-names --region {region}",
                f"aws es describe-elasticsearch-domain --domain-name <domain> --region {region}",
            ]
        if fid == "EXP-023":
            return [
                f"aws sns list-topics --region {region}",
                f"aws sqs list-queues --region {region}",
            ]
        return []

    def _network_finding_specific(fid: str, res: List[str]) -> List[str]:
        """Per-finding-id commands for NETWORK checks."""
        fid = fid.strip().upper()
        sg = _first_resource_name(res, "ec2", "security-group") or "<sg-id>"
        if fid in ("NET-011", "NET-009", "NET-015"):
            return [
                f"aws ec2 describe-security-groups --group-ids {sg} --region {region}",
                f"aws ec2 describe-security-groups --region {region}",
            ]
        if fid in ("NET-016", "NET-025"):
            return [
                f"aws ec2 describe-subnets --region {region}",
                f"aws ec2 describe-network-acls --region {region}",
            ]
        if fid in ("NET-007", "NET-EGR-001"):
            return [
                f"aws network-firewall list-firewalls --region {region}",
                f"aws ec2 describe-route-tables --region {region}",
            ]
        return []

    def _vuln_finding_specific(fid: str, res: List[str]) -> List[str]:
        """Per-finding-id commands for VULNS checks."""
        fid = fid.strip().upper()
        if fid == "VULN-026":
            bucket = ""
            for arn in res:
                info = extract_resource_name(str(arn))
                if info.get("service") == "s3":
                    bucket = info.get("type") or info.get("name") or ""
                    break
            bucket = bucket or "<bucket-name>"
            return [
                f"aws s3 ls s3://{bucket}/ --region {region}",
                f"aws s3api get-bucket-policy --bucket {bucket}",
            ]
        if fid in ("VULN-004", "VULN-008", "VULN-009"):
            return [
                f"aws inspector2 list-findings --region {region}",
                f"aws inspector2 get-findings-statistics --region {region}",
            ]
        if fid in ("VULN-006", "VULN-007"):
            return [
                f"aws inspector2 list-coverage --region {region}",
                f"aws ec2 describe-instances --region {region}",
            ]
        if fid in ("VULN-GD-001", "VULN-GD-002"):
            return [
                f"aws guardduty list-detectors --region {region}",
                f"aws guardduty get-detector --detector-id <detector-id> --region {region}",
            ]
        return []

    def _finding_specific_commands(fid: str, res: List[str]) -> List[str]:
        """Dispatcher: route to per-skill per-finding-id helpers."""
        if skill == "iam":
            return _iam_finding_specific(fid, res)
        if skill == "recon":
            return _recon_finding_specific(fid, res)
        if skill == "exposure":
            return _exposure_finding_specific(fid, res)
        if skill == "vulns":
            return _vuln_finding_specific(fid, res)
        if skill == "network":
            return _network_finding_specific(fid, res)
        return []

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

    # ARN-specific commands take priority: use real resource names when available.
    if affected_resources:
        for cmd in _arn_specific_commands(affected_resources, region, skill):
            if cmd not in seen:
                commands.append(cmd)
                seen.add(cmd)

    # Per-finding-id commands (IAM, RECON, EXPOSURE, VULNS, SECRETSMANAGER)
    if skill == "secretsmanager":
        for cmd in _secretsmanager_specific(finding_id):
            if cmd not in seen:
                commands.append(cmd)
                seen.add(cmd)
    elif finding_id:
        for cmd in _finding_specific_commands(finding_id, affected_resources or []):
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
