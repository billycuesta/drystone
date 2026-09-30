"""Vulnerability AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"vulns"})

SOURCE_QUERIES = {
    "vulns": {
        "inspector-org-config": CliQuery(
            commands=(
                "aws inspector2 get-configuration\n"
                "aws inspector2 list-account-permissions\n"
                "aws inspector2 list-coverage",
            ),
            output=OutputSpec(source="inspector-org-config", style="kv"),
        ),
        "inspector-findings": CliQuery(
            commands=("aws inspector2 list-findings",),
            output=OutputSpec(
                source="inspector-findings",
                rows="",
                columns=(
                    ("findingArn", "findingArn"),
                    ("severity", "severity"),
                    ("status", "status"),
                    ("type", "type"),
                    ("title", "title"),
                    ("resources", "resources"),
                    ("exploitAvailable", "exploitAvailable"),
                    ("fixAvailable", "fixAvailable"),
                ),
            ),
        ),
        "ec2-patch-status": CliQuery(
            commands=("aws ssm describe-instance-patch-states",),
            output=OutputSpec(
                source="ec2-patch-status",
                rows="",
                columns=(
                    ("InstanceId", "InstanceId"),
                    ("Platform", "Platform"),
                    ("State", "State"),
                    ("SSMStatus", "SSMStatus"),
                    ("PatchCompliance", "PatchCompliance"),
                ),
            ),
        ),
        "patch-baselines": CliQuery(
            commands=("aws ssm describe-patch-baselines",),
            output=OutputSpec(
                source="patch-baselines",
                rows="",
                columns=(
                    ("BaselineId", "BaselineId"),
                    ("BaselineName", "BaselineName"),
                    ("OperatingSystemFamily", "OperatingSystemFamily"),
                    ("DefaultBaseline", "DefaultBaseline"),
                    ("Details", "Details"),
                ),
            ),
        ),
        "rds-patch-info": CliQuery(
            commands=("aws rds describe-db-instances",),
            output=OutputSpec(
                source="rds-patch-info",
                rows="",
                columns=(
                    ("DBInstanceIdentifier", "DBInstanceIdentifier"),
                    ("Engine", "Engine"),
                    ("EngineVersion", "EngineVersion"),
                    ("UpgradeAvailable", "UpgradeAvailable"),
                    ("MinorUpgradeCount", "MinorUpgradeCount"),
                    ("MajorUpgradeCount", "MajorUpgradeCount"),
                ),
            ),
        ),
        "ecr-image-scans": CliQuery(
            commands=(
                'for repo in $(aws ecr describe-repositories --query "repositories[].repositoryName" --output text); do\n'
                '  aws ecr describe-image-scan-findings --repository-name "$repo"\n'
                "done",
            ),
            output=OutputSpec(
                source="ecr-image-scans",
                rows="",
                columns=(
                    ("RepositoryName", "RepositoryName"),
                    ("ImageId", "ImageId"),
                    ("ImageScanStatus", "ImageScanStatus"),
                    ("ImageScanFindingsSummary", "ImageScanFindingsSummary"),
                    ("ScanFindings", "ScanFindings"),
                ),
            ),
        ),
        "ec2-user-data": CliQuery(
            commands=(
                'for instance in $(aws ec2 describe-instances --query "Reservations[].Instances[].InstanceId" '
                "--output text); do\n"
                '  aws ec2 describe-instance-attribute --instance-id "$instance" --attribute userData\n'
                "done",
            ),
            output=OutputSpec(source="ec2-user-data", rows="items", columns=(("InstanceId", "InstanceId"), ("UserData", "UserData"))),
        ),
        "lambda-environment-variables": CliQuery(
            commands=(
                'for function in $(aws lambda list-functions --query "Functions[].FunctionName" --output text); do\n'
                '  aws lambda get-function-configuration --function-name "$function"\n'
                "done",
            ),
            output=OutputSpec(
                source="lambda-environment-variables",
                rows="items",
                columns=(("FunctionName", "FunctionName"), ("Environment", "Environment.Variables")),
            ),
        ),
        "imds-configuration": CliQuery(
            commands=("aws ec2 describe-instances",),
            output=OutputSpec(
                source="imds-configuration",
                rows="items",
                columns=(("InstanceId", "InstanceId"), ("HttpTokens", "MetadataOptions.HttpTokens")),
            ),
        ),
        "instance-profiles-permissions": CliQuery(
            commands=(
                'for profile in $(aws iam list-instance-profiles --query "InstanceProfiles[].InstanceProfileName" '
                "--output text); do\n"
                '  aws iam get-instance-profile --instance-profile-name "$profile"\n'
                "done",
            ),
            output=OutputSpec(
                source="instance-profiles-permissions",
                rows="items",
                columns=(("InstanceProfileName", "InstanceProfileName"), ("Roles", "Roles")),
            ),
            derived_note="Drystone evaluates attached instance-profile roles and their effective policies for broad privileges.",
        ),
        "ebs-snapshot-sharing": CliQuery(
            commands=(
                'for snapshot in $(aws ec2 describe-snapshots --owner-ids self --query "Snapshots[].SnapshotId" '
                "--output text); do\n"
                '  aws ec2 describe-snapshot-attribute --snapshot-id "$snapshot" --attribute createVolumePermission\n'
                "done",
            ),
            output=OutputSpec(
                source="ebs-snapshot-sharing",
                rows="items",
                columns=(("SnapshotId", "SnapshotId"), ("CreateVolumePermissions", "CreateVolumePermissions")),
            ),
        ),
        "guardduty-status": CliQuery(
            commands=("aws guardduty list-detectors",),
            output=OutputSpec(
                source="guardduty-status",
                rows="detectors",
                columns=(
                    ("DetectorId", "DetectorId"),
                    ("Status", "Status"),
                    ("S3LogsEnabled", "S3LogsEnabled"),
                    ("MalwareProtectionEnabled", "MalwareProtectionEnabled"),
                    ("KubernetesAuditLogsEnabled", "KubernetesAuditLogsEnabled"),
                    ("AutoArchiveRuleCount", "AutoArchiveRuleCount"),
                ),
            ),
        ),
        "ecs-task-env-secrets": CliQuery(
            commands=(
                'for taskdef in $(aws ecs list-task-definitions --query "taskDefinitionArns[]" --output text); do\n'
                '  aws ecs describe-task-definition --task-definition "$taskdef"\n'
                "done",
            ),
            output=OutputSpec(
                source="ecs-task-env-secrets",
                rows="items",
                columns=(("TaskDefinitionArn", "taskDefinitionArn"), ("ContainerDefinitions", "containerDefinitions")),
            ),
        ),
        "terraform-state-scan": CliQuery(
            commands=(
                "aws s3api list-buckets\n"
                'for bucket in $(aws s3api list-buckets --query "Buckets[].Name" --output text); do\n'
                '  aws s3api list-objects-v2 --bucket "$bucket" --query "Contents[?ends_with(Key, `.tfstate`)].Key"\n'
                "done",
            ),
            output=OutputSpec(
                source="terraform-state-scan",
                rows="items",
                columns=(("Bucket", "bucket"), ("Key", "key"), ("SensitiveMatches", "sensitive_matches")),
            ),
            derived_note="Drystone performs a bounded object-key scan for Terraform state files, then inspects matched state content for plaintext secrets.",
        ),
    }
}

_CHECK_STEMS = {
    "VULN-001": "inspector-org-config",
    "VULN-002": "inspector-findings",
    "VULN-003": "inspector-findings",
    "VULN-004": "inspector-findings",
    "VULN-005": "inspector-findings",
    "VULN-006": "inspector-org-config",
    "VULN-007": "inspector-org-config",
    "VULN-008": "inspector-findings",
    "VULN-009": "inspector-findings",
    "VULN-010": "inspector-findings",
    "VULN-011": "ecr-image-scans",
    "VULN-012": "inspector-org-config",
    "VULN-013": "inspector-findings",
    "VULN-014": "ec2-patch-status",
    "VULN-015": "inspector-findings",
    "VULN-016": "guardduty-status",
    "VULN-017": "guardduty-status",
    "VULN-018": "inspector-org-config",
    "VULN-019": "inspector-findings",
    "VULN-020": "inspector-findings",
    "VULN-021": "patch-baselines",
    "VULN-022": "imds-configuration",
    "VULN-023": "ec2-user-data",
    "VULN-024": "lambda-environment-variables",
    "VULN-025": "instance-profiles-permissions",
    "VULN-026": "terraform-state-scan",
    "VULN-028": "ebs-snapshot-sharing",
    "VULN-029": "ecs-task-env-secrets",
    "VULN-GD-001": "guardduty-status",
    "VULN-GD-002": "guardduty-status",
}

_DERIVED_NOTES = {
    "VULN-003": "Drystone correlates Inspector findings with public exposure evidence to identify internet-reachable vulnerable resources.",
    "VULN-005": "Drystone derives criticality context from resource names, tags, and service type before grouping vulnerable resources.",
    "VULN-009": "Drystone groups Inspector findings by resource to detect vulnerability accumulation on the same asset.",
    "VULN-010": "Drystone correlates Inspector resources with application-service context inferred from tags and names.",
    "VULN-020": "Drystone groups findings by vulnerability identifier across resources to detect repeated exposure.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["vulns"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
