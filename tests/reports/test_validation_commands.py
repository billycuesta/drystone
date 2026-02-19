"""Tests for AWS CLI validation command suggestions."""

from drystone.reports.validation_commands import suggest_aws_cli_commands


def test_secretsmanager_sm002_prefers_describe_secret_commands():
    commands = suggest_aws_cli_commands(
        skill="secretsmanager",
        evidence_refs=["secrets.json#/secrets/0"],
        region="us-east-1",
        finding_id="SM-002",
    )

    assert any("list-secrets" in c for c in commands)
    assert any("describe-secret" in c for c in commands)


def test_secretsmanager_sm012_suggests_alerting_commands():
    commands = suggest_aws_cli_commands(
        skill="secretsmanager",
        evidence_refs=[
            "cloudwatch_alarms.json#/regions/us-east-1",
            "eventbridge_rules.json#/regions/us-east-1",
        ],
        region="us-east-1",
        finding_id="SM-012",
    )

    assert any("cloudwatch describe-alarms" in c for c in commands)
    assert any("events list-rules" in c for c in commands)


def test_secretsmanager_without_finding_id_keeps_file_based_fallback():
    commands = suggest_aws_cli_commands(
        skill="secretsmanager",
        evidence_refs=["secrets.json#/secrets/0"],
        region="us-east-1",
    )

    assert commands
    assert commands[0] == "aws secretsmanager list-secrets --region us-east-1"
