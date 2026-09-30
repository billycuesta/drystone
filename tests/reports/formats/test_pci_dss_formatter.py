"""Tests for PCI DSS formatter behavior."""

from unittest.mock import Mock

from drystone.reports.formats.pci_dss import PCIDSSFormatter
from drystone.storage.session import AuditSession


class TestPCIDSSFormatter:
    def test_header_uses_report_context_metadata_without_utcnow_warning(self, tmp_path):
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        findings = {
            "skill": "iam",
            "findings": [],
            "summary": {"total_findings": 0},
            "analyzed_at": "2026-09-28T00:00:00+00:00",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        header = formatter._header()

        assert "**AWS Account:** 123456789012" in header
        assert "**Skills Audited:** IAM" in header
        assert "**Date:** 2026-09-28T00:00:00+00:00" in header

    def test_generate_filename_uses_report_metadata_skill(self, tmp_path):
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        findings = {
            "skill": "aggregated",
            "report_metadata": {"report_skill": "iam"},
            "findings": [],
            "summary": {"total_findings": 0},
            "analyzed_at": "2026-09-28T00:00:00+00:00",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        path = formatter.generate()

        assert path.name == "pci-dss-compliance-report-iam.md"
        assert path.exists()

    def test_ok_rows_use_no_mapped_findings_language(self, tmp_path):
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        findings = {
            "skill": "iam",
            "findings": [],
            "summary": {"total_findings": 0},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        md = formatter._build_pci_report()

        assert "## 📋 PCI DSS Control Compliance Table" in md
        assert "No mapped findings for" in md

    def test_ok_rows_list_multiple_checks_for_same_control(self, tmp_path):
        """If multiple checklist items map to the same control, list all check IDs."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["exposure"]
        config.report_type = "pci-dss"

        findings = {
            "skill": "exposure",
            "findings": [],
            "summary": {"total_findings": 0},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        # Create a temp checklist with two checks mapping to same control.
        chk_path = tmp_path / "checklist.json"
        chk_path.write_text(
            """
{
  \"items\": [
    {\"id\": \"EXP-001\", \"title\": \"Public S3\", \"pci_dss\": [{\"control\": \"7.2.1\", \"reason\": \"r1\"}]},
    {\"id\": \"EXP-015\", \"title\": \"Cross-account S3\", \"pci_dss\": [{\"control\": \"7.2.1\", \"reason\": \"r2\"}]}
  ]
}
""".strip()
        )

        formatter = PCIDSSFormatter(findings, session, config)
        # Patch checklist path to use temp file.
        formatter._get_checklist_path = lambda skill: chk_path
        md = formatter._build_pci_report()

        assert "| 7.2.1 | ✅ OK" in md
        assert "EXP-001" in md
        assert "EXP-015" in md

    def test_ko_row_prefers_finding_reason_for_control(self, tmp_path):
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        findings = {
            "skill": "iam",
            "findings": [
                {
                    "id": "IAM-008",
                    "severity": "Critical",
                    "risk_score": 9.5,
                    "title": "Admin perms",
                    "description": "...",
                    "remediation": "...",
                    "pci_dss": [
                        {"control": "7.2.1", "reason": "FINDING_REASON_721"},
                        {"control": "7.3.3", "reason": "FINDING_REASON_733"},
                    ],
                }
            ],
            "summary": {"total_findings": 1},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        md = formatter._build_pci_report()

        assert "| 7.2.1 | ❌ KO" in md
        assert "FINDING_REASON_721" in md

    def test_critical_non_compliances_redacts_evidence_snippet(self, tmp_path):
        """rec RPT-H: PCIDSSFormatter used to read raw self.findings, so a
        credential-shaped string in evidence_snippet reached the report
        unredacted -- it must now come from the redacted report context, the
        same as JSONFormatter already does.
        """
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

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
                    "pci_dss": [{"control": "8.4.1", "reason": "MFA required"}],
                    "evidence_snippet": {"AccessKeyId": "AKIA1234567890ABCDE1"},
                }
            ],
            "summary": {"total_findings": 1},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        md = formatter._build_pci_report()

        assert "AKIA1234567890ABCDE1" not in md
        assert "AKIA****************" in md


    def test_pci_dss_formatter_renders_warn_rows_from_report_context(self, tmp_path):
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        findings = {
            "skill": "iam",
            "findings": [],
            "summary": {"total_findings": 0},
            "analysis_metadata": {
                "pre_check_warn_ids": ["IAM-001"],
                "pre_check_warn_reasons": [
                    {"check_id": "IAM-001", "reason_code": "missing_evidence", "evidence_summary": "missing evidence"}
                ],
            },
        }

        md = PCIDSSFormatter(findings, session, config)._build_pci_report()

        assert "Coverage Gaps / Controls Not Evaluated" in md
        assert "IAM-001" in md
        assert "⚠️ WARN" in md
        assert "Required evidence was not present in the collected dataset." in md
