"""Tests for PCI DSS report routing in ReportGenerator (rec RPT-A).

Before this fix, report_type="pci-dss" fell through to the generic
MarkdownFormatter (an annex showing only KO controls) instead of the
dedicated PCIDSSFormatter (a full compliance table including OK controls).
"""

import json
from unittest.mock import Mock

from drystone.reports.formats.pci_dss import PCIDSSFormatter
from drystone.reports.generator import ReportGenerator
from drystone.storage.session import AuditSession


def _session(tmp_path):
    session = Mock(spec=AuditSession)
    session.base_path = tmp_path
    session.account_id = "123456789012"
    session.client_name = "TestClient"
    session.get_findings_path.return_value = tmp_path / "findings"
    session.get_reports_path.return_value = tmp_path / "reports"
    (tmp_path / "findings").mkdir(parents=True, exist_ok=True)
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    return session


def test_generator_uses_pci_dss_formatter_for_markdown(tmp_path):
    session = _session(tmp_path)

    findings = {
        "skill": "iam",
        "findings": [
            {
                "id": "IAM-001",
                "severity": "Critical",
                "risk_score": 9.5,
                "title": "Root account without MFA",
                "description": "...",
                "remediation": "...",
                "affected_resources": [],
                "pci_dss": [{"control": "8.4.1", "reason": "MFA required"}],
            }
        ],
        "summary": {
            "total_findings": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 9.5,
        },
    }
    with open(tmp_path / "findings" / "iam.json", "w") as f:
        json.dump(findings, f)

    config = Mock()
    config.report_type = "pci-dss"
    config.min_severity = "low"
    config.skills = ["iam"]

    generator = ReportGenerator(session, config)
    out = generator.generate_reports("iam", ["markdown"])

    assert "markdown" in out
    assert out["markdown"].name == "pci-dss-compliance-report-iam.md"
    content = out["markdown"].read_text()
    # PCIDSSFormatter's real content markers, not MarkdownFormatter's.
    assert "PCI DSS v4.0 Compliance Report" in content
    assert "PCI DSS Control Compliance Table" in content


def test_generator_pci_dss_pdf_still_uses_generic_pdf_formatter(tmp_path):
    """No dedicated PCI-DSS PDF formatter exists yet -- pdf format must keep
    using the generic PDFFormatter rather than raising or misrouting."""
    session = _session(tmp_path)
    findings = {
        "skill": "iam",
        "findings": [],
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 0.0,
        },
    }
    with open(tmp_path / "findings" / "iam.json", "w") as f:
        json.dump(findings, f)

    config = Mock()
    config.report_type = "pci-dss"
    config.min_severity = "low"
    config.skills = ["iam"]
    config.report_language = "en"
    config.brand_accent_color = None
    config.client_logo_path = None
    config.firm_logo_path = None

    generator = ReportGenerator(session, config)
    assert generator.FORMATTERS["pdf"].__name__ == "PDFFormatter"


def test_pci_dss_formatter_reports_all_twelve_requirement_names():
    """rec RPT-D: the per-instance requirement-name lookup used to only cover
    6 of 12 PCI DSS requirements (missing 3,4,5,6,9,11), rendering "Unknown
    Requirement" for the rest. It must now match the module-level, complete map.
    """
    fmt = PCIDSSFormatter.__new__(PCIDSSFormatter)
    for req_num in [str(n) for n in range(1, 13)]:
        assert fmt._get_requirement_name(req_num) != "Unknown Requirement"
