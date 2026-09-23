"""Tests for PCI DSS text output rendering."""

from drystone.reports.pci_cli_queries import OutputSpec
from drystone.reports.pci_text_table import apply_output_spec, render_kv, render_table


def test_render_table_left_aligns_columns():
    assert render_table(("User", "MFA"), (("alice", True), ("bo", False))) == (
        "User   MFA\n"
        "alice  true\n"
        "bo     false"
    )


def test_apply_output_spec_flattens_values():
    evidence = {
        "users": [
            {"name": "alice", "groups": ["admin", "dev"], "mfa": True, "note": "a\nb"},
            {"name": "bob", "groups": [], "mfa": None},
        ]
    }
    spec = OutputSpec(
        source="users",
        columns=(
            ("name", "name"),
            ("groups", "groups"),
            ("mfa", "mfa"),
            ("note", "note"),
        ),
    )

    assert apply_output_spec(spec, evidence) == (
        "name   groups     mfa   note\n"
        "alice  admin,dev  true  a\\nb\n"
        "bob               -     -"
    )


def test_apply_output_spec_caps_rows_at_200():
    evidence = {"rows": [{"id": index} for index in range(203)]}
    spec = OutputSpec(source="rows", columns=(("id", "id"),))

    output = apply_output_spec(spec, evidence)

    assert output is not None
    lines = output.splitlines()
    assert len(lines) == 202  # header + 200 rows + cap notice
    assert lines[-1] == "... (3 more rows)"


def test_render_kv_style():
    assert render_kv({"AccountMFAEnabled": 0, "Users": 2}) == (
        "Key                Value\n"
        "AccountMFAEnabled  0\n"
        "Users              2"
    )


def test_apply_output_spec_kv_style():
    evidence = {"account-summary": {"SummaryMap": {"AccountMFAEnabled": 0}}}
    spec = OutputSpec(source="account-summary", rows="SummaryMap", style="kv")

    assert apply_output_spec(spec, evidence) == "Key                Value\nAccountMFAEnabled  0"


def test_apply_output_spec_returns_none_when_unresolved():
    evidence = {"users": [{"name": "alice"}]}
    spec = OutputSpec(source="missing", columns=(("name", "name"),))

    assert apply_output_spec(spec, evidence) is None
