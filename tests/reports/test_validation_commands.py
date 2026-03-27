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


# ── G2: Per-finding-id helpers ────────────────────────────────────────────────


def test_iam_iam001_suggests_root_mfa_commands():
    """IAM-001 → root MFA verification commands."""
    commands = suggest_aws_cli_commands(
        skill="iam",
        evidence_refs=[],
        region="us-east-1",
        finding_id="IAM-001",
    )
    assert any("get-account-summary" in c for c in commands)
    assert any("list-mfa-devices" in c and "root" in c for c in commands)


def test_iam_iam004_suggests_key_rotation_commands():
    """IAM-004 with user ARN → user-specific access key commands."""
    commands = suggest_aws_cli_commands(
        skill="iam",
        evidence_refs=[],
        region="us-east-1",
        finding_id="IAM-004",
        affected_resources=["arn:aws:iam::123456789012:user/alice"],
    )
    assert any("list-access-keys --user-name alice" in c for c in commands)


def test_iam_iam041_suggests_role_policy_commands():
    """IAM-041 with role ARN → attached policies commands."""
    commands = suggest_aws_cli_commands(
        skill="iam",
        evidence_refs=[],
        region="us-east-1",
        finding_id="IAM-041",
        affected_resources=["arn:aws:iam::123456789012:role/admin-role"],
    )
    assert any("list-attached-role-policies --role-name admin-role" in c for c in commands)


def test_recon_recon002_suggests_apigateway_commands():
    """RECON-002 → API Gateway listing commands."""
    commands = suggest_aws_cli_commands(
        skill="recon",
        evidence_refs=[],
        region="eu-west-1",
        finding_id="RECON-002",
    )
    assert any("get-rest-apis --region eu-west-1" in c for c in commands)


def test_recon_recon003_suggests_eip_commands():
    """RECON-003 → EIP / instance describe commands."""
    commands = suggest_aws_cli_commands(
        skill="recon",
        evidence_refs=[],
        region="us-east-1",
        finding_id="RECON-003",
    )
    assert any("describe-addresses" in c for c in commands)


def test_exposure_exp026_suggests_s3_public_access_commands():
    """EXP-026 with bucket ARN → public-access-block commands."""
    commands = suggest_aws_cli_commands(
        skill="exposure",
        evidence_refs=[],
        region="us-east-1",
        finding_id="EXP-026",
        affected_resources=["arn:aws:s3:::my-public-bucket"],
    )
    assert any("get-bucket-public-access-block --bucket my-public-bucket" in c for c in commands)


def test_vuln_vuln026_suggests_terraform_state_commands():
    """VULN-026 with bucket ARN → S3 ls + bucket policy commands."""
    commands = suggest_aws_cli_commands(
        skill="vulns",
        evidence_refs=[],
        region="us-east-1",
        finding_id="VULN-026",
        affected_resources=["arn:aws:s3:::tf-state-bucket"],
    )
    assert any("s3 ls s3://tf-state-bucket/" in c for c in commands)
    assert any("get-bucket-policy --bucket tf-state-bucket" in c for c in commands)


def test_vuln_vuln004_suggests_inspector_commands():
    """VULN-004 → Inspector findings commands."""
    commands = suggest_aws_cli_commands(
        skill="vulns",
        evidence_refs=[],
        region="us-east-1",
        finding_id="VULN-004",
    )
    assert any("inspector2 list-findings" in c for c in commands)


def test_unknown_skill_finding_id_returns_empty():
    """Skills without per-finding-id helpers fall through gracefully."""
    commands = suggest_aws_cli_commands(
        skill="alerting",
        evidence_refs=["cloudtrail-trails.json"],
        region="us-east-1",
        finding_id="ALRT-001",
    )
    # Should still get file-based commands, just not crash
    assert isinstance(commands, list)
