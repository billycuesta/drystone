"""Tests for audit prompt template loader."""

from unittest.mock import patch

import pytest

from drystone.prompts.template_loader import (
    get_audit_template,
    list_available_templates,
    load_template,
    render_template,
)

# ── helpers ───────────────────────────────────────────────────────────────────

BASE_TEMPLATE = """<audit_task>
  <role>AWS security auditor</role>
  <evidence>{EVIDENCE_JSON}</evidence>
  {SKILL_ADDENDUM}
</audit_task>"""

SKILL_TEMPLATE = """<?xml version="1.0"?>
<audit_task extends="base_audit.xml">
  <skill_section>IAM-specific checks</skill_section>
</audit_task>"""

SKILL_TEMPLATE_NO_EXTENDS = """<audit_task>
  <skill_section>Standalone skill template</skill_section>
</audit_task>"""


def write_templates(tmp_path, *, base=None, skill=None, skill_name="iam"):
    """Write template files to a temp directory and patch TEMPLATE_DIR."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    if base is not None:
        (tmp_path / "base_audit.xml").write_text(base)
    if skill is not None:
        (tmp_path / f"{skill_name}_audit.xml").write_text(skill)
    return tmp_path


# ── load_template ─────────────────────────────────────────────────────────────


class TestLoadTemplate:
    def test_loads_skill_specific_template(self, tmp_path):
        write_templates(tmp_path, skill=SKILL_TEMPLATE_NO_EXTENDS)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("iam")
        assert "Standalone skill template" in result

    def test_falls_back_to_base_when_no_skill_template(self, tmp_path):
        write_templates(tmp_path, base=BASE_TEMPLATE)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("network")
        assert "AWS security auditor" in result

    def test_raises_when_no_template_found(self, tmp_path):
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            with pytest.raises(FileNotFoundError, match="network"):
                load_template("network")

    def test_skill_name_is_lowercased(self, tmp_path):
        write_templates(tmp_path, skill=SKILL_TEMPLATE_NO_EXTENDS, skill_name="iam")
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("IAM")
        assert "Standalone skill template" in result

    def test_extends_mechanism_injects_skill_content_into_base(self, tmp_path):
        write_templates(tmp_path, base=BASE_TEMPLATE, skill=SKILL_TEMPLATE)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("iam")
        assert "IAM-specific checks" in result
        assert "AWS security auditor" in result

    def test_extends_removes_xml_prolog(self, tmp_path):
        write_templates(tmp_path, base=BASE_TEMPLATE, skill=SKILL_TEMPLATE)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("iam")
        assert "<?xml" not in result

    def test_extends_removes_outer_audit_task_wrapper(self, tmp_path):
        write_templates(tmp_path, base=BASE_TEMPLATE, skill=SKILL_TEMPLATE)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("iam")
        # The skill's outer <audit_task> tag should not appear twice
        assert result.count("<audit_task") == 1

    def test_extends_appends_to_base_when_no_skill_addendum_placeholder(self, tmp_path):
        base_without_placeholder = "<audit_task><role>auditor</role></audit_task>"
        write_templates(tmp_path, base=base_without_placeholder, skill=SKILL_TEMPLATE)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("iam")
        assert "IAM-specific checks" in result
        assert "auditor" in result

    def test_no_extends_returns_skill_template_as_is(self, tmp_path):
        write_templates(tmp_path, base=BASE_TEMPLATE, skill=SKILL_TEMPLATE_NO_EXTENDS)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = load_template("iam")
        assert "Standalone skill template" in result
        # Base template content should NOT be merged in
        assert "AWS security auditor" not in result


# ── render_template ───────────────────────────────────────────────────────────


class TestRenderTemplate:
    def test_substitutes_single_placeholder(self):
        template = "Hello {NAME}!"
        result = render_template(template, {"NAME": "Alice"})
        assert result == "Hello Alice!"

    def test_substitutes_multiple_placeholders(self):
        template = "{SKILL_NAME} audit for {CLIENT_NAME}"
        result = render_template(template, {"SKILL_NAME": "IAM", "CLIENT_NAME": "ACME"})
        assert result == "IAM audit for ACME"

    def test_unknown_placeholder_left_unchanged(self):
        template = "Value: {UNKNOWN}"
        result = render_template(template, {"OTHER": "x"})
        assert "{UNKNOWN}" in result

    def test_empty_context_returns_template_unchanged(self):
        template = "No placeholders here."
        result = render_template(template, {})
        assert result == template

    def test_non_string_values_are_coerced(self):
        template = "Count: {COUNT}, Score: {SCORE}"
        result = render_template(template, {"COUNT": 42, "SCORE": 7.5})
        assert result == "Count: 42, Score: 7.5"

    def test_placeholder_replaced_only_once_per_occurrence(self):
        template = "{KEY} and {KEY} again"
        result = render_template(template, {"KEY": "X"})
        assert result == "X and X again"


# ── get_audit_template ────────────────────────────────────────────────────────


class TestGetAuditTemplate:
    def test_loads_and_renders_in_one_call(self, tmp_path):
        template = "<audit>{EVIDENCE_JSON}</audit>"
        (tmp_path / "iam_audit.xml").write_text(template)
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = get_audit_template("iam", {"EVIDENCE_JSON": '{"users": []}'})
        assert '{"users": []}' in result

    def test_raises_when_template_missing(self, tmp_path):
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            with pytest.raises(FileNotFoundError):
                get_audit_template("nonexistent", {})


# ── list_available_templates ──────────────────────────────────────────────────


class TestListAvailableTemplates:
    def test_returns_empty_dict_when_no_templates(self, tmp_path):
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = list_available_templates()
        assert result == {}

    def test_detects_base_template(self, tmp_path):
        (tmp_path / "base_audit.xml").write_text("<base/>")
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = list_available_templates()
        assert "_base" in result

    def test_detects_skill_templates(self, tmp_path):
        (tmp_path / "iam_audit.xml").write_text("<iam/>")
        (tmp_path / "network_audit.xml").write_text("<network/>")
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = list_available_templates()
        assert "iam" in result
        assert "network" in result

    def test_base_template_excluded_from_skill_entries(self, tmp_path):
        (tmp_path / "base_audit.xml").write_text("<base/>")
        (tmp_path / "iam_audit.xml").write_text("<iam/>")
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = list_available_templates()
        assert "base" not in result
        assert "_base" in result
        assert "iam" in result

    def test_returns_string_paths(self, tmp_path):
        (tmp_path / "iam_audit.xml").write_text("<iam/>")
        with patch("drystone.prompts.template_loader.TEMPLATE_DIR", tmp_path):
            result = list_available_templates()
        assert isinstance(result["iam"], str)
        assert result["iam"].endswith("iam_audit.xml")
