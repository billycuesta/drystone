"""Tests for PDF formatter."""

import json
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


def test_pdf_formatter_includes_pentest_inventory_scope(tmp_path, monkeypatch):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "us-east-1"
    config.min_severity = "low"
    config.report_type = "pentest"

    inventory_dir = tmp_path / "evidence" / "pentest"
    inventory_dir.mkdir(parents=True, exist_ok=True)
    with open(inventory_dir / "inventory-summary.json", "w") as f:
        json.dump(
            {
                "region": "us-east-1",
                "regional_resources": {
                    "ec2_instances": 2,
                    "rds_instances": 1,
                    "lambda_functions": 3,
                    "vpcs": 1,
                },
                "global_resources": {
                    "s3_buckets": 5,
                    "iam_roles": 12,
                },
            },
            f,
        )

    network_dir = tmp_path / "evidence" / "network"
    network_dir.mkdir(parents=True, exist_ok=True)
    with open(network_dir / "subnets.json", "w") as f:
        json.dump({"Subnets": [{"SubnetId": "subnet-1"}]}, f)

    exposure_dir = tmp_path / "evidence" / "exposure"
    exposure_dir.mkdir(parents=True, exist_ok=True)
    with open(exposure_dir / "api-gateway-stages.json", "w") as f:
        json.dump({"items": [{"ApiId": "a1"}]}, f)

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
    formatter.generate()

    assert "<h2>Inventory</h2>" in captured["html"]
    assert "Regional Resources" in captured["html"]
    assert "EC2 instances: 2" in captured["html"]
    assert "Global Resources" in captured["html"]
    assert "Environment Description (Inferred)" in captured["html"]


# ---------------------------------------------------------------------------
# PDF Findings — Phase-based grouping for pentest reports
# ---------------------------------------------------------------------------


def _pentest_findings_multi_skill():
    """Aggregated pentest findings with RECON, IAM, EXP, NET, VULN findings."""
    return {
        "skill": "aggregated",
        "analyzed_at": "2026-03-01T00:00:00",
        "summary": {"total_findings": 5, "overall_risk_score": 8.0},
        "findings": [
            {
                "id": "RECON-002",
                "title": "API GW unauthenticated",
                "severity": "Critical",
                "risk_score": 9.0,
                "description": "Unauthenticated API stage.",
                "affected_resources": ["arn:aws:apigateway:us-east-1::/restapis/abc"],
                "remediation": "Enable auth.",
            },
            {
                "id": "IAM-004",
                "title": "Root no MFA",
                "severity": "Critical",
                "risk_score": 9.0,
                "description": "Root lacks MFA.",
                "affected_resources": ["arn:aws:iam::123456789012:root"],
                "remediation": "Enable MFA.",
            },
            {
                "id": "EXP-021",
                "title": "Public S3 bucket",
                "severity": "Critical",
                "risk_score": 9.0,
                "description": "Bucket is publicly readable.",
                "affected_resources": ["arn:aws:s3:::my-bucket"],
                "remediation": "Remove public ACL.",
            },
            {
                "id": "NET-007",
                "title": "No Network Firewall",
                "severity": "Critical",
                "risk_score": 9.0,
                "description": "VPC has no ANFW.",
                "affected_resources": ["arn:aws:ec2:us-east-1:123456789012:vpc/vpc-1"],
                "remediation": "Deploy ANFW.",
            },
            {
                "id": "VULN-005",
                "title": "Critical CVE unpatched",
                "severity": "Critical",
                "risk_score": 9.0,
                "description": "EC2 instance has exploitable CVE.",
                "affected_resources": ["arn:aws:ec2:us-east-1:123456789012:instance/i-1"],
                "remediation": "Apply patch.",
            },
        ],
    }


def test_pdf_pentest_uses_phase_grouping(tmp_path):
    """Pentest PDF uses phase-based grouping instead of severity grouping."""
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "pentest"
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    formatter = PDFFormatter(_pentest_findings_multi_skill(), session, config)
    html_content = formatter._findings_by_phase_html(_pentest_findings_multi_skill()["findings"])

    assert "Phase 1 — Reconnaissance" in html_content
    assert "Phase 2 — Identity" in html_content
    assert "Phase 2 — External Exposure" in html_content
    assert "Phase 2 — Network Security" in html_content
    assert "Phase 2 — Vulnerabilities" in html_content
    # Should NOT use severity headers
    assert "Critical Severity" not in html_content
    assert "High Severity" not in html_content


def test_pdf_pentest_summary_table_rendered(tmp_path):
    """Phase summary table is generated for Risk Analysis."""
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "pentest"
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    formatter = PDFFormatter(_pentest_findings_multi_skill(), session, config)
    html_content = formatter._phase_findings_table_html(_pentest_findings_multi_skill()["findings"])

    assert "findings-summary-table" in html_content
    assert "TOTAL" in html_content
    assert "<th>Critical</th>" in html_content


def test_pdf_non_pentest_still_uses_severity_grouping(tmp_path):
    """Non-pentest PDF still groups by severity."""
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "general"
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    formatter = PDFFormatter(_sample_findings(), session, config)
    html_content = formatter._findings_by_severity_html(_sample_findings()["findings"])

    assert "pill-critical" in html_content  # severity group header uses pill, not old text
    assert "Phase 1" not in html_content


def test_pdf_index_labels_by_phase_for_pentest(tmp_path):
    """Index section says 'by Phase' for pentest reports."""
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "pentest"
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    formatter = PDFFormatter(_pentest_findings_multi_skill(), session, config)
    index = formatter._index_section_html(_pentest_findings_multi_skill()["findings"])

    assert "Detailed Findings by Phase" in index
    assert "Detailed Findings by Severity" not in index


def test_pdf_index_labels_by_severity_for_general(tmp_path):
    """Index section says 'by Severity' for general reports."""
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "general"
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    formatter = PDFFormatter(_sample_findings(), session, config)
    index = formatter._index_section_html(_sample_findings()["findings"])

    assert "Detailed Findings by Severity" in index
    assert "Detailed Findings by Phase" not in index


def test_pdf_pentest_index_and_findings_follow_phase_order(tmp_path):
    """Pentest index and detailed findings follow the same phase order."""
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "pentest"
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    findings = _pentest_findings_multi_skill()["findings"]
    formatter = PDFFormatter(_pentest_findings_multi_skill(), session, config)

    index = formatter._index_section_html(findings)
    details = formatter._findings_by_phase_html(findings)

    index_phase1 = index.index("Phase 1 — Reconnaissance")
    index_iam = index.index("Phase 2 — Identity")
    index_exp = index.index("Phase 2 — External Exposure")
    index_net = index.index("Phase 2 — Network Security")
    index_vuln = index.index("Phase 2 — Vulnerabilities")
    assert index_phase1 < index_iam < index_exp < index_net < index_vuln

    details_phase1 = details.index("Phase 1 — Reconnaissance")
    details_iam = details.index("Phase 2 — Identity")
    details_exp = details.index("Phase 2 — External Exposure")
    details_net = details.index("Phase 2 — Network Security")
    details_vuln = details.index("Phase 2 — Vulnerabilities")
    assert details_phase1 < details_iam < details_exp < details_net < details_vuln
