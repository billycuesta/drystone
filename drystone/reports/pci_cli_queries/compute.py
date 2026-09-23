"""Compute AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"compute"})

SOURCE_QUERIES = {
    "compute": {
        "ecs-inventory": CliQuery(
            commands=(
                "aws ecs list-clusters\n"
                'for taskdef in $(aws ecs list-task-definitions --query "taskDefinitionArns[]" --output text); do\n'
                '  aws ecs describe-task-definition --task-definition "$taskdef"\n'
                "done",
            ),
            output=OutputSpec(
                source="ecs-inventory",
                rows="task_definitions",
                columns=(
                    ("taskDefinitionArn", "taskDefinitionArn"),
                    ("family", "family"),
                    ("taskRoleArn", "taskRoleArn"),
                    ("executionRoleArn", "executionRoleArn"),
                    ("containerDefinitions", "containerDefinitions"),
                ),
            ),
        ),
        "eventbridge-rules": CliQuery(
            commands=(
                'for rule in $(aws events list-rules --query "Rules[].Name" --output text); do\n'
                '  aws events describe-rule --name "$rule"\n'
                '  aws events list-targets-by-rule --rule "$rule"\n'
                "done",
            ),
            output=OutputSpec(
                source="eventbridge-rules",
                rows="rules",
                columns=(("Name", "Name"), ("ScheduleExpression", "ScheduleExpression"), ("State", "State"), ("Targets", "Targets")),
            ),
        ),
        "eks-inventory": CliQuery(
            commands=(
                'for cluster in $(aws eks list-clusters --query "clusters[]" --output text); do\n'
                '  aws eks describe-cluster --name "$cluster"\n'
                "done",
            ),
            output=OutputSpec(
                source="eks-inventory",
                rows="clusters",
                columns=(
                    ("name", "name"),
                    ("arn", "arn"),
                    ("resourcesVpcConfig", "resourcesVpcConfig"),
                    ("logging", "logging"),
                    ("status", "status"),
                ),
            ),
        ),
        "ec2-inventory": CliQuery(
            commands=(
                "aws ec2 describe-instances\n"
                'for instance in $(aws ec2 describe-instances --query "Reservations[].Instances[].InstanceId" '
                "--output text); do\n"
                '  aws ec2 describe-instance-attribute --instance-id "$instance" --attribute userData\n'
                "done",
            ),
            output=OutputSpec(
                source="ec2-inventory",
                rows="instances",
                columns=(
                    ("InstanceId", "InstanceId"),
                    ("IamInstanceProfile", "IamInstanceProfile"),
                    ("MetadataOptions", "MetadataOptions"),
                    ("UserData", "UserData"),
                    ("ContainsSecrets", "ContainsSecrets"),
                    ("HasRemoteBootstrap", "HasRemoteBootstrap"),
                ),
            ),
        ),
        "lambda-inventory": CliQuery(
            commands=(
                'for function in $(aws lambda list-functions --query "Functions[].FunctionName" --output text); do\n'
                '  aws lambda get-function-configuration --function-name "$function"\n'
                '  aws lambda list-function-url-configs --function-name "$function"\n'
                '  aws lambda get-policy --function-name "$function"\n'
                "done",
            ),
            output=OutputSpec(
                source="lambda-inventory",
                rows="functions",
                columns=(
                    ("FunctionName", "FunctionName"),
                    ("FunctionArn", "FunctionArn"),
                    ("Role", "Role"),
                    ("FunctionUrl", "FunctionUrl"),
                    ("AuthType", "AuthType"),
                    ("AttachedPolicies", "AttachedPolicies"),
                ),
            ),
        ),
    }
}

_CHECK_STEMS = {
    "COMP-ECS-001": "eventbridge-rules",
    "COMP-ECS-002": "ecs-inventory",
    "COMP-ECS-003": "ecs-inventory",
    "COMP-ECS-004": "ecs-inventory",
    "COMP-ECS-005": "ecs-inventory",
    "COMP-EKS-001": "eks-inventory",
    "COMP-EKS-002": "eks-inventory",
    "COMP-EC2-001": "ec2-inventory",
    "COMP-EC2-002": "ec2-inventory",
    "COMP-LMB-001": "lambda-inventory",
    "COMP-LMB-002": "lambda-inventory",
}

_DERIVED_NOTES = {
    "COMP-ECS-001": "Drystone correlates scheduled EventBridge targets with ECS task definitions.",
    "COMP-ECS-002": "Drystone derives task-definition drift by comparing container images and definitions over collected inventory.",
    "COMP-ECS-004": "Drystone evaluates ECS task and execution role policy context to identify broad permissions.",
    "COMP-ECS-005": "Drystone scans ECS container environment entries for plaintext credential patterns.",
    "COMP-EC2-002": "Drystone scans decoded EC2 user data for credential and remote bootstrap risk patterns.",
    "COMP-LMB-002": "Drystone evaluates Lambda execution role policy context to identify broad permissions.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["compute"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
