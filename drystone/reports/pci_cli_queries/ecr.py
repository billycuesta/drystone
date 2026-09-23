"""ECR AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"ecr"})

SOURCE_QUERIES = {
    "ecr": {
        "registry": CliQuery(
            commands=(
                "aws ecr describe-registry\n"
                "aws ecr get-registry-policy\n"
                "aws ecr get-registry-scanning-configuration",
            ),
            output=OutputSpec(
                source="registry",
                style="kv",
            ),
        ),
        "repositories": CliQuery(
            commands=(
                "aws ecr describe-repositories\n"
                'for repo in $(aws ecr describe-repositories --query "repositories[].repositoryName" --output text); do\n'
                '  aws ecr get-repository-policy --repository-name "$repo"\n'
                '  aws ecr get-lifecycle-policy --repository-name "$repo"\n'
                "done\n"
                'for arn in $(aws ecr describe-repositories --query "repositories[].repositoryArn" --output text); do\n'
                '  aws ecr list-tags-for-resource --resource-arn "$arn"\n'
                "done",
            ),
            output=OutputSpec(
                source="repositories",
                rows="repositories",
                columns=(
                    ("repositoryName", "repositoryName"),
                    ("repositoryArn", "repositoryArn"),
                    ("imageTagMutability", "imageTagMutability"),
                    ("imageScanningConfiguration", "imageScanningConfiguration"),
                    ("encryptionConfiguration", "encryptionConfiguration"),
                    ("Policy", "Policy"),
                    ("LifecyclePolicy", "LifecyclePolicy"),
                    ("Tags", "Tags"),
                ),
            ),
        ),
        "ecr-collection-status": CliQuery(
            commands=("# Drystone-generated ECR collection status; review registry and repository commands above for source API coverage.",),
            output=OutputSpec(source="ecr-collection-status", style="kv"),
            derived_note="Drystone records collection status from ECR API attempts and permission errors.",
        ),
    }
}

_CHECK_STEMS = {
    "ECR-001": "repositories",
    "ECR-002": "repositories",
    "ECR-003": "repositories",
    "ECR-004": "registry",
    "ECR-005": "repositories",
    "ECR-006": "repositories",
    "ECR-007": "repositories",
    "ECR-009": "repositories",
}

_DERIVED_NOTES = {
    "ECR-001": "Drystone interprets repository policy principals to identify public-style access.",
    "ECR-003": "Drystone evaluates both repository scan-on-push settings and registry scanning configuration for coverage.",
    "ECR-007": "Drystone interprets repository policy principals to identify external-account access.",
    "ECR-009": "Drystone interprets repository policy actions and principals to identify broad access patterns.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["ecr"][_stem]
    _commands = _source_query.commands
    if _check_id == "ECR-003":
        _commands = (*SOURCE_QUERIES["ecr"]["repositories"].commands, *SOURCE_QUERIES["ecr"]["registry"].commands)
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
