"""Tests for ClientContext model and parser."""

import pytest

from drystone.models.client_context import ClientContext


class TestClientContextParsing:
    """Test YAML frontmatter + markdown body parsing."""

    def test_parse_full_context(self):
        content = """---
organization: TuLotero
industry: Fintech / Online Lottery
project: Internal Penetration Test 2026
code: A2SECURE-TuLotero-IPT-2026-v1.0
version: "1.0"
assessment_dates:
  start: "2026-03-02"
  end: "2026-03-09"
report_date: "2026-03-11"
conditions:
  - "Source IPs: 54.72.64.191"
  - "IPs whitelisted in WAF"
exclusions:
  - "Denial of Service (DoS) testing"
  - "Social engineering"
scope_notes: |
  Internal penetration test of AWS account.
---

## Business Context

TuLotero is an online lottery platform operating in Spain and LATAM.

## Compliance Requirements

PCI DSS v4.0, GDPR / LOPD-GDD.
"""
        ctx = ClientContext._parse(content)
        assert ctx.organization == "TuLotero"
        assert ctx.industry == "Fintech / Online Lottery"
        assert ctx.project == "Internal Penetration Test 2026"
        assert ctx.code == "A2SECURE-TuLotero-IPT-2026-v1.0"
        assert ctx.version == "1.0"
        assert ctx.assessment_dates == {"start": "2026-03-02", "end": "2026-03-09"}
        assert ctx.report_date == "2026-03-11"
        assert len(ctx.conditions) == 2
        assert "Source IPs: 54.72.64.191" in ctx.conditions
        assert len(ctx.exclusions) == 2
        assert "TuLotero" in ctx.business_context
        assert "PCI DSS" in ctx.compliance_reqs

    def test_parse_minimal_context(self):
        content = """---
organization: ACME
---

## Business Context

Simple test company.
"""
        ctx = ClientContext._parse(content)
        assert ctx.organization == "ACME"
        assert ctx.code == ""
        assert ctx.conditions == []
        assert ctx.exclusions == []
        assert "Simple test" in ctx.business_context

    def test_parse_no_frontmatter(self):
        content = """## Business Context

No frontmatter here.
"""
        ctx = ClientContext._parse(content)
        assert ctx.organization == ""
        assert "No frontmatter" in ctx.business_context

    def test_parse_empty_content(self):
        ctx = ClientContext._parse("")
        assert ctx.organization == ""
        assert ctx.business_context == ""

    def test_from_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            ClientContext.from_file(tmp_path / "nonexistent.md")

    def test_from_file_success(self, tmp_path):
        ctx_file = tmp_path / "client-context.md"
        ctx_file.write_text(
            "---\norganization: TestCorp\ncode: TC-001\n---\n\n## Business Context\n\nTest business.\n"
        )
        ctx = ClientContext.from_file(ctx_file)
        assert ctx.organization == "TestCorp"
        assert ctx.code == "TC-001"
        assert "Test business" in ctx.business_context
