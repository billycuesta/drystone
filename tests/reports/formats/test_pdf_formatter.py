"""Tests for PDF formatter."""

import sys
import types
from unittest.mock import Mock

from drystone.reports.formats.pdf import PDFFormatter
from drystone.storage.session import AuditSession


def _mock_session(tmp_path):
    session = Mock(spec=AuditSession)
    session.base_path = tmp_path
    session.account_id = "123456789012"
    session.client_name = "Acme"
    session.get_reports_path.return_value = tmp_path / "reports"
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    return session


def _sample_findings():
    return {
        "skill": "iam",
        "analyzed_at": "2026-02-16T10:00:00",
        "summary": {
            "total_findings": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 9.0,
        },
        "findings": [
            {
                "id": "IAM-001",
                "severity": "Critical",
                "risk_score": 9.0,
                "title": "Root key active",
                "description": "Root account has active access keys.",
                "remediation": "Disable root access keys and enable MFA.",
                "affected_resources": ["arn:aws:iam::123456789012:root"],
            }
        ],
    }


def test_pdf_formatter_generates_pdf_with_weasyprint_stub(tmp_path, monkeypatch):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    captured = {}

    class FakeHTML:
        def __init__(self, string):
            captured["html"] = string

        def write_pdf(self, output_path):
            with open(output_path, "wb") as f:
                f.write(b"%PDF-1.4 test")

    fake_module = types.SimpleNamespace(HTML=FakeHTML)
    monkeypatch.setitem(sys.modules, "weasyprint", fake_module)

    formatter = PDFFormatter(_sample_findings(), session, config)
    report_path = formatter.generate()

    assert report_path.exists()
    assert report_path.suffix == ".pdf"
    assert "Security Audit Report: IAM Security Analysis" in captured["html"]
    assert "██████╗" in captured["html"]


def test_pdf_formatter_raises_when_weasyprint_missing(tmp_path, monkeypatch):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    monkeypatch.delitem(sys.modules, "weasyprint", raising=False)

    formatter = PDFFormatter(_sample_findings(), session, config)

    original_import = __import__

    def fail_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise ImportError("missing")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fail_import)

    try:
        formatter.generate()
        assert False, "Expected RuntimeError for missing weasyprint"
    except RuntimeError as exc:
        assert "weasyprint" in str(exc)
