"""Tests for PCI DSS CLI query resolution and IAM P1 coverage."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from drystone.reports import pci_cli_queries
from drystone.reports.pci_cli_queries import CliQuery, OutputSpec, resolve_query

EXPECTED_LAYER_1_STEMS = {
    "iam": {
        "account-summary",
        "account-aliases",
        "password-policy",
        "credential-report",
        "users",
        "groups",
        "roles",
        "policies",
        "assumeRole-chains",
        "resource-based-policies",
        "instance-profiles",
        "effective-scps",
    },
    "network": {
        "security-groups",
        "network-acls",
        "route-tables",
        "subnets",
        "vpcs",
        "ec2-instances",
        "network-interfaces",
        "rds-instances",
        "lambda-functions",
        "vpc-endpoints",
        "internet-gateways",
        "vpn-connections",
        "transit-gateway-topology",
        "nat-gateway-routes",
    },
    "exposure": {
        "s3-buckets",
        "rds-instances",
        "security-groups",
        "ami-images",
        "cloudfront-distributions",
        "load-balancers",
        "load-balancer-listeners",
        "wafv2-web-acls",
        "wafv2-web-acl-alb-associations",
        "lambda-function-urls",
        "api-gateway-stages",
        "api-gateway-routes",
        "ecs-eks-ingress",
        "elasticsearch-domains",
        "resource-based-policies",
    },
    "waf": {
        "cloudfront-distributions",
        "cloudfront-wafv2-associations",
        "cloudfront-classic-associations",
        "wafv2-web-acls",
        "wafv2-ip-sets",
        "wafv2-rule-groups",
        "wafv2-managed-rule-groups",
        "alb-waf-associations",
        "api-entrypoints-waf-associations",
        "waf-classic",
        "waf-collection-status",
    },
    "hardening": {
        "security-hub-status",
        "security-hub-findings",
        "security-hub-findings-summary",
        "security-hub-enabled-standards",
        "config-recorders",
        "config-delivery-channels",
        "config-recorder-status",
        "config-compliance",
        "config-compliance-summary",
        "config-conformance-packs",
        "config-conformance-pack-compliance",
        "acm-certificates",
        "guardduty-detectors",
        "macie-session",
        "macie-findings",
        "backup-vaults",
        "backup-plans",
        "backup-plans-detailed",
        "account-summary",
        "account-aliases",
        "password-policy",
        "hardening-collection-status",
    },
}


def test_resolve_query_layer_2_wins_over_source_fallback(monkeypatch):
    source_output = OutputSpec(source="users", columns=(("User", "UserName"),))
    check_output = OutputSpec(source="credential-report", rows="rows", columns=(("user", "user"),))
    monkeypatch.setattr(pci_cli_queries, "SOURCE_QUERIES", {"iam": {"users": CliQuery(commands=("aws iam list-users",), output=source_output)}})
    monkeypatch.setattr(
        pci_cli_queries,
        "CHECK_QUERIES",
        {
            "IAM-002": CliQuery(
                commands=("aws iam get-credential-report",),
                output=check_output,
                evidence_name="IAM users MFA",
            )
        },
    )

    resolved = resolve_query("iam", "IAM-002", ["users"], {"title": "Checklist title"})

    assert resolved.layer == "check"
    assert resolved.commands == ("aws iam get-credential-report",)
    assert resolved.outputs == (check_output,)
    assert resolved.evidence_name == "IAM users MFA"


def test_resolve_query_layer_1_fallback_dedupes_in_consulted_order(monkeypatch):
    users_output = OutputSpec(source="users", columns=(("User", "UserName"),))
    monkeypatch.setattr(pci_cli_queries, "CHECK_QUERIES", {})
    monkeypatch.setattr(
        pci_cli_queries,
        "SOURCE_QUERIES",
        {
            "iam": {
                "users": CliQuery(commands=("aws iam list-users",), output=users_output),
                "credential-report": CliQuery(
                    commands=("aws iam list-users", "aws iam get-credential-report"),
                    output=OutputSpec(source="credential-report", rows="rows", columns=(("user", "user"),)),
                ),
            }
        },
    )

    resolved = resolve_query(
        "iam",
        "IAM-999",
        ["credential-report", "users", "credential-report"],
        {"title": "Fallback title"},
    )

    assert resolved.layer == "source"
    assert resolved.commands == ("aws iam list-users", "aws iam get-credential-report")
    assert [output.source for output in resolved.outputs] == ["credential-report", "users"]
    assert resolved.evidence_name == "Fallback title"


def test_resolve_query_returns_placeholder_when_no_recipe_exists(monkeypatch):
    monkeypatch.setattr(pci_cli_queries, "CHECK_QUERIES", {})
    monkeypatch.setattr(pci_cli_queries, "SOURCE_QUERIES", {"iam": {}})

    resolved = resolve_query("iam", "IAM-999", ["users", "unknown"], {"title": "Unknown"})

    assert resolved.layer == "placeholder"
    assert resolved.outputs == ()
    assert resolved.commands == (
        "# No AWS CLI equivalent catalogued yet for IAM-999 (evidence consulted: users, unknown)",
    )


def test_resolve_query_preserves_alternative_commands_as_data_structure(monkeypatch):
    monkeypatch.setattr(
        pci_cli_queries,
        "CHECK_QUERIES",
        {
            "IAM-002": CliQuery(
                commands=(
                    "aws iam get-credential-report --query Content",
                    "for user in $(aws iam list-users --query Users[].UserName --output text); do echo $user; done",
                ),
            )
        },
    )

    resolved = resolve_query("iam", "IAM-002", [], {"title": "MFA"})

    assert resolved.layer == "check"
    assert resolved.commands == (
        "aws iam get-credential-report --query Content",
        "for user in $(aws iam list-users --query Users[].UserName --output text); do echo $user; done",
    )


def test_complete_skills_contains_p1_and_p2_catalogs():
    assert pci_cli_queries.COMPLETE_SKILLS == frozenset({"iam", "network", "exposure", "waf", "hardening"})


@pytest.mark.parametrize("skill, expected_stems", EXPECTED_LAYER_1_STEMS.items())
def test_complete_skills_have_layer_1_recipes_for_expected_stems(skill: str, expected_stems: set[str]):
    assert set(pci_cli_queries.SOURCE_QUERIES[skill]) == expected_stems


def test_iam_keeps_p1_layer_1_recipes_for_plan_stems():
    assert set(pci_cli_queries.SOURCE_QUERIES["iam"]) == EXPECTED_LAYER_1_STEMS["iam"]


@pytest.mark.parametrize("skill", sorted(pci_cli_queries.COMPLETE_SKILLS))
def test_every_complete_skill_checklist_item_with_pci_dss_has_layer_2_recipe(skill: str):
    checklist = json_load(Path(f"drystone/skills/{skill}/checklist.json"))
    pci_check_ids = {item["id"] for item in checklist["items"] if item.get("pci_dss")}

    assert pci_check_ids <= set(pci_cli_queries.CHECK_QUERIES)


def test_catalogued_aws_cli_operations_exist_in_botocore_models():
    botocore = pytest.importorskip("botocore.session")
    botocore_package = pytest.importorskip("botocore")
    session = botocore.get_session()
    aliases = {"s3api": "s3", "configservice": "config"}

    for service, operation in aws_operations_from_catalog():
        model = session.get_service_model(aliases.get(service, service))
        cli_operations = {botocore_package.xform_name(name).replace("_", "-") for name in model.operation_names}
        assert operation in cli_operations, f"aws {service} {operation}"


def json_load(path: Path) -> dict[str, Any]:
    import json

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def aws_operations_from_catalog() -> set[tuple[str, str]]:
    operations: set[tuple[str, str]] = set()
    queries = [*pci_cli_queries.CHECK_QUERIES.values()]
    for source_queries in pci_cli_queries.SOURCE_QUERIES.values():
        queries.extend(source_queries.values())

    for query in queries:
        for command in query.commands:
            for raw_line in command.splitlines():
                line = raw_line.strip()
                if not line.startswith("aws "):
                    continue
                tokens = line.split()
                if len(tokens) >= 3:
                    operations.add((tokens[1], tokens[2]))
    return operations
