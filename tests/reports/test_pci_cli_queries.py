"""Tests for PCI DSS CLI query resolution and IAM P1 coverage."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from drystone.reports import pci_cli_queries
from drystone.reports.pci_cli_queries import CliQuery, OutputSpec, resolve_query

IAM_LAYER_1_STEMS = {
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


def test_p1_complete_skills_only_contains_iam():
    assert pci_cli_queries.COMPLETE_SKILLS == frozenset({"iam"})


def test_iam_has_layer_1_recipes_for_plan_stems():
    assert set(pci_cli_queries.SOURCE_QUERIES["iam"]) == IAM_LAYER_1_STEMS


def test_every_iam_checklist_item_with_pci_dss_has_layer_2_recipe():
    checklist = json_load(Path("drystone/skills/iam/checklist.json"))
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
