"""Tests for PDF formatter."""

import json
import sys
import types
from pathlib import Path
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


def test_pdf_template_uses_physical_page_margins_for_safe_area():
    template_path = (
        Path(__file__).parents[3] / "drystone" / "reports" / "templates" / "pdf_report.xml"
    )
    template = template_path.read_text()

    assert "margin: 14mm 16mm 14mm 16mm;" in template
    assert "margin: 0 0 14mm 0;" not in template
    assert ".report-content {\n      width: 100%;" in template
    assert "padding: 0 0 10mm 0;" in template
    assert "margin-left: 16mm;" not in template
    assert "margin-right: 16mm;" not in template


def test_pdf_template_uses_compact_normal_text_size():
    template_path = (
        Path(__file__).parents[3] / "drystone" / "reports" / "templates" / "pdf_report.xml"
    )
    template = template_path.read_text()

    assert "body {\n      font-family: var(--font-sans);\n      font-size: 10px;" in template
    assert ".executive-narrative p {\n      font-size: 10px;" in template
    assert "font-size: 11px;" not in template


def test_pdf_formatter_renders_network_architecture_as_visual_diagram(tmp_path, monkeypatch):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "eu-west-1"
    config.min_severity = "low"

    findings = {
        "skill": "network",
        "analyzed_at": "2026-04-30T10:00:00",
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 0.0,
        },
        "findings": [],
        "architecture": {
            "flow_diagram": "AWS Network Topology\n├── legacy ascii",
            "components_detected": {
                "region": "eu-west-1",
                "account_id": "982725252505",
                "vpcs": [
                    {
                        "vpc_id": "vpc-1",
                        "vpc_name": "IntouchDev",
                        "cidr": "10.0.0.0/16",
                        "igw_ids": ["igw-1"],
                        "flow_logs_active": True,
                        "vpc_endpoints_total": 0,
                        "resources_total": 3,
                        "subnets_private": [
                            {
                                "subnet_id": "subnet-private",
                                "subnet_name": "IntouchDev Private",
                                "cidr": "10.0.1.0/24",
                                "az": "eu-west-1b",
                                "is_public": False,
                                "eni_total": 2,
                                "eni_types": {},
                                "resource_names": {
                                    "EC2": ["API - Robicheaux N1 - 2025"],
                                    "RDS": ["postclear"],
                                },
                            }
                        ],
                        "subnets_public": [
                            {
                                "subnet_id": "subnet-public",
                                "subnet_name": "IntouchDev Public",
                                "cidr": "10.0.0.0/24",
                                "az": "eu-west-1b",
                                "is_public": True,
                                "eni_total": 2,
                                "eni_public_ip_total": 1,
                                "eni_types": {"NATGW": 1},
                                "resource_names": {
                                    "EC2": ["BO - Billy Rocks N1 - 2025"],
                                    "RDS": ["postclear"],
                                },
                            }
                        ],
                    }
                ],
            },
        },
    }

    captured = {}

    class FakeHTML:
        def __init__(self, string):
            captured["html"] = string

        def write_pdf(self, output_path):
            with open(output_path, "wb") as f:
                f.write(b"%PDF-1.4 test")

    fake_module = types.SimpleNamespace(HTML=FakeHTML)
    monkeypatch.setitem(sys.modules, "weasyprint", fake_module)

    formatter = PDFFormatter(findings, session, config)
    formatter.generate()

    assert "network-diagram" in captured["html"]
    assert "network-subnet-card private" in captured["html"]
    assert "network-subnet-card public" in captured["html"]
    assert "Multi-Subnet Resources" in captured["html"]
    assert "postclear" in captured["html"]
    assert "AWS Network Topology" not in captured["html"]


def test_pdf_formatter_renders_alerting_architecture_as_visual_diagram(tmp_path, monkeypatch):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "eu-west-1"
    config.min_severity = "low"

    findings = {
        "skill": "alerting",
        "analyzed_at": "2026-05-01T13:00:00",
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 0.0,
        },
        "findings": [],
        "architecture": {
            "flow_diagram": "AWS SECURITY ALERTING FLOW ARCHITECTURE",
            "components_detected": {
                "region": "eu-west-1",
                "account_id": "982725252505",
                "cloudtrail_enabled": True,
                "cloudtrail_multi_region": True,
                "cloudwatch_integration": True,
                "eventbridge_rules_exist": False,
                "metric_filters_exist": True,
                "alarms_configured": True,
                "sns_topics_exist": True,
                "sns_has_subscribers": True,
                "subscriptions_confirmed": True,
                "cloudtrail_names": ["MainCloudTrail"],
                "cloudtrail_s3_buckets": ["maincloudtrailap7"],
                "cloudwatch_log_groups": ["aws-cloudtrail-logs-maincloudtrail"],
                "metric_filter_names": ["RootAccountUsage"],
                "alarm_names": ["RootAccountUsage"],
                "eventbridge_rule_names": [],
                "sns_topic_names": ["InfraAlerts"],
                "subscription_protocols": ["email"],
                "counts": {
                    "trails": 1,
                    "log_groups": 1,
                    "metric_filters": 12,
                    "alarms": 12,
                    "eventbridge_rules": 0,
                    "sns_topics": 6,
                    "subscriptions": 6,
                },
            },
        },
    }

    captured = {}

    class FakeHTML:
        def __init__(self, string):
            captured["html"] = string

        def write_pdf(self, output_path):
            with open(output_path, "wb") as f:
                f.write(b"%PDF-1.4 test")

    fake_module = types.SimpleNamespace(HTML=FakeHTML)
    monkeypatch.setitem(sys.modules, "weasyprint", fake_module)

    formatter = PDFFormatter(findings, session, config)
    formatter.generate()

    assert "alerting-diagram" in captured["html"]
    assert "Alerting Flow Diagram" in captured["html"]
    assert "CloudTrail" in captured["html"]
    assert "CloudWatch Alarms" in captured["html"]
    assert "SNS Topics" in captured["html"]
    assert "AWS SECURITY ALERTING FLOW ARCHITECTURE" not in captured["html"]


def test_pdf_formatter_renders_alerting_partial_delivery_status(tmp_path, monkeypatch):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "eu-west-1"
    config.min_severity = "low"

    findings = {
        "skill": "alerting",
        "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
        "architecture": {
            "components_detected": {
                "region": "eu-west-1",
                "account_id": "982725252505",
                "cloudtrail_enabled": True,
                "cloudtrail_multi_region": True,
                "cloudwatch_integration": True,
                "eventbridge_rules_exist": False,
                "metric_filters_exist": True,
                "alarms_configured": True,
                "sns_topics_exist": True,
                "sns_delivery_status": "warn",
                "subscriptions_confirmed": False,
                "alert_topic_names": ["InfraAlerts"],
                "alert_topics_without_confirmed_subscribers": ["InfraAlerts"],
                "subscription_protocols": [],
                "counts": {
                    "trails": 1,
                    "log_groups": 1,
                    "metric_filters": 15,
                    "alarms": 17,
                    "eventbridge_rules": 10,
                    "sns_topics": 6,
                    "subscriptions": 1,
                    "alert_topics": 1,
                    "alert_topics_without_confirmed_subscribers": 1,
                },
            }
        },
    }

    captured = {}

    class FakeHTML:
        def __init__(self, string):
            captured["html"] = string

        def write_pdf(self, output_path):
            with open(output_path, "wb") as f:
                f.write(b"%PDF-1.4 test")

    monkeypatch.setitem(sys.modules, "weasyprint", types.SimpleNamespace(HTML=FakeHTML))

    PDFFormatter(findings, session, config).generate()

    assert "alerting-card warn" in captured["html"]
    assert "Partial" in captured["html"]
    assert "1 alert topic(s) missing subscribers" in captured["html"]
    assert "InfraAlerts" in captured["html"]


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


def test_pdf_formatter_renders_single_exploitability_pill(tmp_path):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    formatter = PDFFormatter(_sample_findings(), session, config)
    finding = dict(_sample_findings()["findings"][0], exploitability_status="validated")

    card = formatter._finding_card_html(finding)

    assert "exploit-pill exploit-pill-validated" in card
    assert "style='padding:2px 8px" not in card
    assert card.count("Validated") == 1


def test_pdf_formatter_places_finding_id_after_title_content(tmp_path):
    session = _mock_session(tmp_path)
    config = Mock()
    config.aws_region = "us-east-1"
    config.min_severity = "low"

    formatter = PDFFormatter(_sample_findings(), session, config)
    card = formatter._finding_card_html(_sample_findings()["findings"][0])

    assert card.index("finding-title-wrap") < card.index("finding-id")


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


# ── _masked_access_key (rec AW: must recognize AssumeRole) ────────────────────


def _formatter_with_config(tmp_path, config) -> PDFFormatter:
    session = _mock_session(tmp_path)
    return PDFFormatter(_sample_findings(), session, config)


def test_masked_access_key_recognizes_assume_role(tmp_path):
    config = Mock()
    config.aws_role_arn = "arn:aws:iam::123456789012:role/AuditRole"
    config.aws_access_key_id = None
    config.aws_profile = None
    config.aws_credentials_file = None

    formatter = _formatter_with_config(tmp_path, config)
    assert formatter._masked_access_key() == "AssumeRole: arn:aws:iam::123456789012:role/AuditRole"


def test_masked_access_key_assume_role_takes_priority_over_direct_keys(tmp_path):
    """aws_role_arn changes the identity actually used regardless of the source
    credential method, so it must be checked before direct keys/profile/file."""
    config = Mock()
    config.aws_role_arn = "arn:aws:iam::123456789012:role/AuditRole"
    config.aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"

    formatter = _formatter_with_config(tmp_path, config)
    assert formatter._masked_access_key().startswith("AssumeRole:")


def test_masked_access_key_falls_back_to_direct_keys(tmp_path):
    config = Mock()
    config.aws_role_arn = None
    config.aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"

    formatter = _formatter_with_config(tmp_path, config)
    assert formatter._masked_access_key() == "AKIA...MPLE"


def test_masked_access_key_falls_back_to_profile(tmp_path):
    config = Mock()
    config.aws_role_arn = None
    config.aws_access_key_id = None
    config.aws_profile = "prod-audit"

    formatter = _formatter_with_config(tmp_path, config)
    assert formatter._masked_access_key() == "Profile: prod-audit"


def test_masked_access_key_role_arn_only_no_longer_mislabeled_as_env(tmp_path, monkeypatch):
    """Before rec AW, a role-only config (the intended way to use AssumeRole)
    fell through every branch and was wrongly labeled 'Environment variables'."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    config = Mock()
    config.aws_role_arn = "arn:aws:iam::123456789012:role/AuditRole"
    config.aws_access_key_id = None
    config.aws_profile = None
    config.aws_credentials_file = None

    formatter = _formatter_with_config(tmp_path, config)
    result = formatter._masked_access_key()
    assert result != "Environment variables"
    assert "AuditRole" in result


# ── active_verification + integrity manifest rendering (recs RPT-E, RPT-G) ────


def test_document_control_includes_integrity_manifest_hash_when_present(tmp_path):
    """rec RPT-G: the integrity manifest hash markdown.py already renders was
    missing from PDF/Pentest PDF's document control section."""
    session = _mock_session(tmp_path)
    findings = _sample_findings()
    findings["report_metadata"] = {"integrity_manifest_sha256": "deadbeef1234"}
    config = Mock()
    config.report_type = "general"

    formatter = PDFFormatter(findings, session, config)
    html_out = formatter._document_control_html()

    assert "deadbeef1234" in html_out
    assert "Evidence Integrity" in html_out


def test_document_control_omits_integrity_row_when_absent(tmp_path):
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "general"

    formatter = PDFFormatter(_sample_findings(), session, config)
    html_out = formatter._document_control_html()

    assert "Evidence Integrity" not in html_out


def test_finding_card_renders_successful_active_verification(tmp_path):
    """rec RPT-E: active_verification (attached by verification/runner.py) was
    rendered in pentest Markdown but silently dropped in PDF/Pentest PDF."""
    session = _mock_session(tmp_path)
    findings = _sample_findings()
    findings["findings"][0]["active_verification"] = {
        "method": "sts_assume_role",
        "result": "success",
        "detail": "AssumeRole succeeded; confirmed identity change",
    }
    config = Mock()
    config.report_type = "pentest"

    formatter = PDFFormatter(findings, session, config)
    card_html = formatter._finding_card_html(findings["findings"][0])

    assert "Active Verification" in card_html
    assert "sts_assume_role" in card_html
    assert "✅" in card_html


def test_finding_card_renders_denied_active_verification_without_downgrading(tmp_path):
    session = _mock_session(tmp_path)
    findings = _sample_findings()
    findings["findings"][0]["active_verification"] = {
        "method": "s3_unauthenticated_head_bucket",
        "result": "denied",
        "detail": "Unauthenticated HEAD failed: 403",
    }
    config = Mock()
    config.report_type = "general"

    formatter = PDFFormatter(findings, session, config)
    card_html = formatter._finding_card_html(findings["findings"][0])

    assert "Active Verification" in card_html
    assert "⚠️" in card_html


def test_finding_card_omits_active_verification_section_when_absent(tmp_path):
    session = _mock_session(tmp_path)
    findings = _sample_findings()
    config = Mock()
    config.report_type = "general"

    formatter = PDFFormatter(findings, session, config)
    card_html = formatter._finding_card_html(findings["findings"][0])

    assert "Active Verification" not in card_html


def test_executive_summary_includes_active_verification_line(tmp_path):
    """rec RPT-E: the executive-summary note pentest.py's markdown already
    has (_active_verification_summary_line) was missing from the PDF's
    narrative executive summary."""
    session = _mock_session(tmp_path)
    findings = _sample_findings()
    findings["findings"][0]["active_verification"] = {
        "method": "sts_assume_role",
        "result": "success",
        "detail": "AssumeRole succeeded",
    }
    config = Mock()
    config.report_type = "pentest"

    formatter = PDFFormatter(findings, session, config)
    narrative_html = formatter._executive_narrative_html(findings["summary"])

    assert "Active verification" in narrative_html
    assert "1 confirmed via live AWS API calls" in narrative_html


def test_executive_summary_omits_active_verification_line_when_none_ran(tmp_path):
    session = _mock_session(tmp_path)
    findings = _sample_findings()
    config = Mock()
    config.report_type = "general"

    formatter = PDFFormatter(findings, session, config)
    narrative_html = formatter._executive_narrative_html(findings["summary"])

    assert "Active verification" not in narrative_html


def test_correlation_card_renders_active_verification(tmp_path):
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "pentest"

    formatter = PDFFormatter(_sample_findings(), session, config)
    corr = {
        "id": "CORR-abc12345-001",
        "title": "AssumeRole privilege escalation",
        "pattern_id": "iam_assume_role_privilege_escalation",
        "active_verification": {
            "method": "sts_assume_role",
            "result": "success",
            "detail": "AssumeRole succeeded",
        },
    }
    card_html = formatter._correlation_card_html(corr)

    assert "Active Verification" in card_html
    assert "sts_assume_role" in card_html


# ── _pci_dss_annex_html (rec RPT-B: must not disappear for an all-OK audit) ───


def test_pci_dss_annex_html_all_ok_audit_still_renders_annex(tmp_path):
    session = _mock_session(tmp_path)
    findings = {
        "skill": "iam",
        "findings": [],  # no findings -> every mapped control is OK
        "summary": {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 0.0,
        },
    }
    config = Mock()
    config.report_type = "pci-dss"
    config.report_language = "en"
    config.skills = ["iam"]

    formatter = PDFFormatter(findings, session, config)
    annex = formatter._pci_dss_annex_html()

    assert annex != ""
    assert "Annex A: PCI DSS v4.0 Control Mapping" in annex
    assert "✅ OK" in annex
    assert "❌ KO" not in annex


def test_pci_dss_annex_html_mixed_ok_and_ko_controls(tmp_path):
    session = _mock_session(tmp_path)
    findings = {
        "skill": "iam",
        "findings": [
            {
                "id": "IAM-001",
                "title": "Root account without MFA",
                "severity": "Critical",
                "pci_dss": [{"control": "8.4.1", "reason": "MFA required"}],
            }
        ],
        "summary": {
            "total_findings": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 9.0,
        },
    }
    config = Mock()
    config.report_type = "pci-dss"
    config.report_language = "en"
    config.skills = ["iam"]

    formatter = PDFFormatter(findings, session, config)
    annex = formatter._pci_dss_annex_html()

    assert "❌ KO" in annex
    assert "✅ OK" in annex


def test_pci_dss_annex_html_non_pci_report_type_returns_empty(tmp_path):
    session = _mock_session(tmp_path)
    config = Mock()
    config.report_type = "general"
    config.skills = ["iam"]

    formatter = PDFFormatter(_sample_findings(), session, config)
    assert formatter._pci_dss_annex_html() == ""
