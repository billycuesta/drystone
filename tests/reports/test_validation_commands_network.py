"""Tests for network finding-id specific validation commands (G2b)."""

from drystone.reports.validation_commands import suggest_aws_cli_commands


def test_net011_returns_security_group_command():
    commands = suggest_aws_cli_commands(
        skill="network",
        evidence_refs=[],
        region="us-east-1",
        finding_id="NET-011",
    )
    assert any("describe-security-groups" in c for c in commands)


def test_net016_returns_subnet_or_nacl_command():
    commands = suggest_aws_cli_commands(
        skill="network",
        evidence_refs=[],
        region="us-east-1",
        finding_id="NET-016",
    )
    assert any("describe-subnets" in c or "describe-network-acls" in c for c in commands)


def test_net025_returns_nacl_command():
    commands = suggest_aws_cli_commands(
        skill="network",
        evidence_refs=[],
        region="us-east-1",
        finding_id="NET-025",
    )
    assert any("describe-network-acls" in c or "describe-subnets" in c for c in commands)


def test_exp021_returns_apigateway_command():
    commands = suggest_aws_cli_commands(
        skill="exposure",
        evidence_refs=[],
        region="us-east-1",
        finding_id="EXP-021",
    )
    assert any("apigateway" in c for c in commands)


def test_exp019_returns_elasticsearch_command():
    commands = suggest_aws_cli_commands(
        skill="exposure",
        evidence_refs=[],
        region="us-east-1",
        finding_id="EXP-019",
    )
    assert any("es" in c for c in commands)


def test_exp023_returns_sns_or_sqs_command():
    commands = suggest_aws_cli_commands(
        skill="exposure",
        evidence_refs=[],
        region="us-east-1",
        finding_id="EXP-023",
    )
    assert any("sns" in c or "sqs" in c for c in commands)


def test_network_unknown_finding_id_falls_back_to_file_map():
    commands = suggest_aws_cli_commands(
        skill="network",
        evidence_refs=["security-groups.json"],
        region="us-east-1",
        finding_id="NET-999",
    )
    # Should still produce at least file-map based command
    assert any("describe-security-groups" in c for c in commands)
