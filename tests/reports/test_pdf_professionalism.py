"""Tests for PDF professionalism enhancements (GAPs 2-7)."""

from unittest.mock import MagicMock

import pytest

from drystone.models.client_context import ClientContext
from drystone.reports.formats.pdf import PDFFormatter


@pytest.fixture
def pdf_formatter(tmp_path):
    """Create a PDFFormatter with minimal mock data."""
    session = MagicMock()
    session.client_name = "ACME Corp"
    session.account_id = "123456789012"
    session.base_path = tmp_path

    # Create real WizardConfig-like object (not Mock) to avoid subscript issues
    config = MagicMock()
    config.report_type = "general"
    config.aws_region = "us-east-1"
    config.ai_provider = "claude-cli"
    config.ai_model = "auto"
    config.min_severity = "low"
    config.scan_depth = "normal"
    config.skills = ["iam"]
    config.report_language = "en"
    config._client_context = None  # No client context by default

    findings = {
        "skill": "iam",
        "analyzed_at": "2026-03-16T10:00:00",
        "summary": {
            "total_findings": 5,
            "critical": 1,
            "high": 2,
            "medium": 1,
            "low": 1,
            "overall_risk_score": 6.5,
        },
        "findings": [
            {
                "id": "IAM-001",
                "title": "Root account has active access keys",
                "severity": "Critical",
                "risk_score": 9.5,
                "description": "Root account has active access keys.",
                "remediation": "Delete root access keys.",
                "cis_reference": "1.5",
                "affected_resources": ["arn:aws:iam::123456789012:root"],
                "evidence_snippet": {"User": "root"},
            },
            {
                "id": "IAM-002",
                "title": "No MFA on root",
                "severity": "High",
                "risk_score": 8.0,
                "description": "MFA not enabled.",
                "remediation": "Enable MFA.",
                "cis_reference": None,
                "affected_resources": [],
            },
            {
                "id": "IAM-003",
                "title": "Unused access keys",
                "severity": "High",
                "risk_score": 7.0,
                "description": "Old keys.",
                "remediation": "Rotate keys.",
                "cis_reference": "N/A",
                "affected_resources": [],
                "evidence_snippet": None,
            },
            {
                "id": "IAM-004",
                "title": "Weak password policy",
                "severity": "Medium",
                "risk_score": 5.0,
                "description": "Short passwords.",
                "remediation": "Increase length.",
            },
            {
                "id": "IAM-005",
                "title": "CloudTrail not enabled",
                "severity": "Low",
                "risk_score": 2.0,
                "description": "No trail.",
                "remediation": "Enable CloudTrail.",
            },
        ],
    }

    formatter = PDFFormatter(findings, session, config)
    return formatter


class TestGAP5HideEmptyFields:
    """GAP 5: Empty fields should not render."""

    def test_no_evidence_placeholder(self, pdf_formatter):
        """Evidence block should be empty when no snippet."""
        finding = {
            "id": "TEST-001",
            "title": "Test",
            "severity": "Low",
            "risk_score": 1.0,
            "description": "Test finding.",
            "remediation": "Fix it.",
            "cis_reference": "N/A",
            "evidence_snippet": None,
        }
        card = pdf_formatter._finding_card_html(finding)
        assert "No raw evidence snippet" not in card
        assert "<h4>Evidence</h4>" not in card

    def test_no_affected_resources_placeholder(self, pdf_formatter):
        """No 'No affected resources listed' when empty."""
        finding = {
            "id": "TEST-002",
            "title": "Test",
            "severity": "Low",
            "risk_score": 1.0,
            "description": "Test.",
            "remediation": "Fix.",
            "affected_resources": [],
        }
        card = pdf_formatter._finding_card_html(finding)
        assert "No affected resources listed" not in card
        assert "finding-affected" not in card

    def test_cis_reference_hidden_when_na(self, pdf_formatter):
        """CIS Reference hidden when N/A or None."""
        finding = {
            "id": "TEST-003",
            "title": "Test",
            "severity": "Low",
            "risk_score": 1.0,
            "description": "Test.",
            "remediation": "Fix.",
            "cis_reference": "N/A",
        }
        card = pdf_formatter._finding_card_html(finding)
        assert "CIS Reference" not in card

    def test_cis_reference_shown_when_valid(self, pdf_formatter):
        """CIS Reference shown when valid."""
        finding = {
            "id": "TEST-004",
            "title": "Test",
            "severity": "Low",
            "risk_score": 1.0,
            "description": "Test.",
            "remediation": "Fix.",
            "cis_reference": "1.5",
        }
        card = pdf_formatter._finding_card_html(finding)
        assert "CIS Reference" in card
        assert "1.5" in card

    def test_evidence_shown_when_present(self, pdf_formatter):
        """Evidence block renders when snippet exists."""
        finding = {
            "id": "TEST-005",
            "title": "Test",
            "severity": "Low",
            "risk_score": 1.0,
            "description": "Test.",
            "remediation": "Fix.",
            "evidence_snippet": {"key": "value"},
        }
        card = pdf_formatter._finding_card_html(finding)
        assert "<h4>Evidence</h4>" in card
        assert "key" in card
        assert "value" in card


class TestGAP4RiskScale:
    """GAP 4: Risk scale section."""

    def test_risk_scale_renders(self, pdf_formatter):
        summary = {"overall_risk_score": 6.5}
        result = pdf_formatter._risk_scale_html(summary)
        assert "Risk Scale" in result
        assert "risk-scale-bar" in result
        assert "6.5/10.0" in result

    def test_risk_scale_spanish(self, pdf_formatter):
        pdf_formatter.config.report_language = "es"
        summary = {"overall_risk_score": 3.0}
        result = pdf_formatter._risk_scale_html(summary)
        assert "Escala de Riesgo" in result

    def test_risk_scale_levels_table(self, pdf_formatter):
        summary = {"overall_risk_score": 0.0}
        result = pdf_formatter._risk_scale_html(summary)
        assert "Appropriate" in result
        assert "Critical" in result
        assert "rs-appropriate" in result


class TestGAP2DocumentControl:
    """GAP 2: Document control section."""

    def test_document_control_auto_generated(self, pdf_formatter):
        result = pdf_formatter._document_control_html()
        assert "meta-table" in result  # heading lives in template section-divider
        assert "ACMECORP" in result  # Client slug
        assert "SEC" in result  # General report type code
        assert "CONFIDENTIAL" in result
        assert "v1.0" in result

    def test_document_control_with_client_context(self, pdf_formatter):
        ctx = ClientContext(
            organization="TestCorp",
            code="TC-SEC-2026-v2.0",
            project="Security Assessment 2026",
            version="2.0",
            report_date="2026-03-15",
        )
        pdf_formatter.config._client_context = ctx
        result = pdf_formatter._document_control_html()
        assert "TC-SEC-2026-v2.0" in result
        assert "Security Assessment 2026" in result
        assert "2.0" in result


class TestGAP6ExecutiveSummary:
    """GAP 6: Enriched executive summary."""

    def test_executive_summary_has_risk_bar(self, pdf_formatter):
        summary = pdf_formatter.findings["summary"]
        result = pdf_formatter._executive_narrative_html(summary)
        # Should have a mini risk bar
        assert "border-radius:8px" in result

    def test_executive_summary_has_top_recommendations(self, pdf_formatter):
        summary = pdf_formatter.findings["summary"]
        result = pdf_formatter._executive_narrative_html(summary)
        assert "Top Recommendations" in result
        assert "IAM-001" in result

    def test_executive_summary_with_business_context(self, pdf_formatter):
        ctx = ClientContext(
            organization="TestCorp",
            business_context="TestCorp operates a critical payment platform.",
            assessment_dates={"start": "2026-03-01", "end": "2026-03-05"},
        )
        pdf_formatter.config._client_context = ctx
        summary = pdf_formatter.findings["summary"]
        result = pdf_formatter._executive_narrative_html(summary)
        assert "critical payment platform" in result
        assert "2026-03-01" in result


class TestGAP3Conditions:
    """GAP 3: Conditions section."""

    def test_conditions_renders_defaults(self, pdf_formatter):
        result = pdf_formatter._conditions_section_html()
        assert "Conditions" in result
        assert "us-east-1" in result
        assert "IAM" in result
        assert "Denial of Service" in result

    def test_conditions_spanish(self, pdf_formatter):
        pdf_formatter.config.report_language = "es"
        result = pdf_formatter._conditions_section_html()
        assert "Condiciones y Exclusiones" in result
        assert "Denegación de Servicio" in result

    def test_conditions_with_client_context(self, pdf_formatter):
        ctx = ClientContext(
            conditions=["Source IPs: 1.2.3.4", "IPs whitelisted"],
            exclusions=["DoS testing", "Social engineering"],
        )
        pdf_formatter.config._client_context = ctx
        result = pdf_formatter._conditions_section_html()
        assert "1.2.3.4" in result
        assert "DoS testing" in result
