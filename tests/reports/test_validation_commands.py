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


from drystone.reports.validation_commands import extract_resource_name


def test_extract_resource_name_iam_role():
    result = extract_resource_name("arn:aws:iam::123456789012:role/admin-role")
    assert result["service"] == "iam"
    assert result["type"] == "role"
    assert result["name"] == "admin-role"


def test_extract_resource_name_s3_bucket():
    result = extract_resource_name("arn:aws:s3:::my-bucket")
    assert result["service"] == "s3"
    assert result["name"] == "my-bucket"


def test_extract_resource_name_ec2_instance():
    result = extract_resource_name("arn:aws:ec2:us-east-1:123:instance/i-abcdef01")
    assert result["service"] == "ec2"
    assert result["type"] == "instance"
    assert result["name"] == "i-abcdef01"


def test_extract_resource_name_invalid_returns_empty():
    assert extract_resource_name("not-an-arn") == {}
    assert extract_resource_name("") == {}


def test_arn_specific_commands_iam_role():
    commands = suggest_aws_cli_commands(
        skill="iam",
        evidence_refs=[],
        region="us-east-1",
        affected_resources=["arn:aws:iam::123456789012:role/prod-role"],
    )
    assert any("get-role --role-name prod-role" in c for c in commands)


def test_arn_specific_commands_s3_bucket():
    commands = suggest_aws_cli_commands(
        skill="exposure",
        evidence_refs=[],
        region="us-east-1",
        affected_resources=["arn:aws:s3:::my-public-bucket"],
    )
    assert any("get-bucket-policy --bucket my-public-bucket" in c for c in commands)


def test_arn_specific_commands_take_priority_over_generic():
    """ARN-specific commands appear before file-based commands."""
    commands = suggest_aws_cli_commands(
        skill="iam",
        evidence_refs=["roles.json#prod-role"],
        region="us-east-1",
        affected_resources=["arn:aws:iam::123456789012:role/prod-role"],
    )
    # Should have ARN-specific command
    assert any("get-role --role-name prod-role" in c for c in commands)
    # ARN-specific command should appear first
    assert "get-role --role-name prod-role" in commands[0]
