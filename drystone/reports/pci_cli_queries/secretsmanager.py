"""Secrets Manager AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"secretsmanager"})

SOURCE_QUERIES = {
    "secretsmanager": {
        "secrets": CliQuery(
            commands=(
                'for secret in $(aws secretsmanager list-secrets --query "SecretList[].ARN" --output text); do\n'
                '  aws secretsmanager describe-secret --secret-id "$secret"\n'
                '  aws secretsmanager get-resource-policy --secret-id "$secret"\n'
                '  aws secretsmanager list-secret-version-ids --secret-id "$secret"\n'
                "done",
            ),
            output=OutputSpec(
                source="secrets",
                rows="secrets",
                columns=(
                    ("Region", "Region"),
                    ("Name", "Name"),
                    ("ARN", "ARN"),
                    ("KmsKeyId", "KmsKeyId"),
                    ("RotationEnabled", "RotationEnabled"),
                    ("RotationRules", "RotationRules"),
                    ("LastRotatedDate", "LastRotatedDate"),
                    ("LastAccessedDate", "LastAccessedDate"),
                    ("Tags", "Tags"),
                    ("ResourcePolicy", "ResourcePolicy"),
                    ("ReplicationStatus", "ReplicationStatus"),
                    ("SecurityIssues", "SecurityIssues"),
                    ("RiskScore", "RiskScore"),
                ),
            ),
        ),
        "cloudwatch_alarms": CliQuery(
            commands=("aws cloudwatch describe-alarms",),
            output=OutputSpec(source="cloudwatch_alarms", style="kv"),
        ),
        "eventbridge_rules": CliQuery(
            commands=(
                'for rule in $(aws events list-rules --query "Rules[].Name" --output text); do\n'
                '  aws events describe-rule --name "$rule"\n'
                '  aws events list-targets-by-rule --rule "$rule"\n'
                "done",
            ),
            output=OutputSpec(source="eventbridge_rules", style="kv"),
        ),
    }
}

_CHECK_STEMS = {
    "SM-001": "secrets",
    "SM-002": "secrets",
    "SM-003": "secrets",
    "SM-004": "secrets",
    "SM-005": "secrets",
    "SM-006": "secrets",
    "SM-007": "secrets",
    "SM-008": "secrets",
    "SM-009": "secrets",
    "SM-010": "secrets",
    "SM-011": "secrets",
    "SM-012": "cloudwatch_alarms",
    "SM-013": "secrets",
    "SM-014": "secrets",
    "SM-015": "secrets",
    "SM-016": "secrets",
    "SM-017": "secrets",
}

_DERIVED_NOTES = {
    "SM-001": "Drystone interprets secret resource policy semantics to detect broad principals and public-style access.",
    "SM-003": "Drystone derives rotation interval age from secret metadata timestamps and rotation configuration.",
    "SM-005": "Drystone derives lifecycle age from last changed and last accessed secret metadata.",
    "SM-006": "Drystone evaluates governance tags on secret metadata.",
    "SM-007": "Drystone evaluates description quality as semantic governance metadata.",
    "SM-008": "Drystone derives disaster-recovery posture from secret replication metadata.",
    "SM-009": "Drystone correlates access frequency with rotation interval to flag high-use secrets.",
    "SM-010": "Drystone has weak direct CLI evidence for Lambda/VPC endpoint access paths and treats this as semantic context from secret use metadata.",
    "SM-011": "Drystone interprets resource policy conditions to determine whether MFA is required for secret access.",
    "SM-012": "Drystone correlates Secrets Manager rotation failures with CloudWatch alarms and EventBridge rule targets.",
    "SM-013": "Drystone interprets resource policy principals for external-account access.",
    "SM-014": "Drystone evaluates rotation Lambda configuration and permissions as a derived hijack-risk signal.",
    "SM-015": "Drystone interprets policy actions and KMS references to identify re-encryption risk.",
    "SM-016": "Drystone evaluates version stage lifecycle metadata for AWSCURRENT manipulation risk.",
    "SM-017": "Drystone evaluates replica metadata for cross-region promotion backdoor risk.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["secretsmanager"][_stem]
    _commands = _source_query.commands
    if _check_id == "SM-012":
        _commands = (
            *SOURCE_QUERIES["secretsmanager"]["secrets"].commands,
            *SOURCE_QUERIES["secretsmanager"]["cloudwatch_alarms"].commands,
            *SOURCE_QUERIES["secretsmanager"]["eventbridge_rules"].commands,
        )
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('_', ' ').replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
