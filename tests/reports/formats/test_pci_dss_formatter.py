"""Tests for PCI DSS formatter behavior."""

from unittest.mock import Mock

from drystone.reports.formats.pci_dss import PCIDSSFormatter
from drystone.storage.session import AuditSession


class TestPCIDSSFormatter:
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
