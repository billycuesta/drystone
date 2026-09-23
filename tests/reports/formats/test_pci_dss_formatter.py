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

    def test_compliance_statistics_groups_by_requirement(self, tmp_path):
        """_compliance_statistics() should build a table grouped by requirement."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        # Create checklist with controls in multiple requirements (7 and 8)
        chk_path = tmp_path / "checklist.json"
        chk_path.write_text(
            """
{
  "items": [
    {"id": "IAM-001", "title": "Check 1", "pci_dss": [{"control": "7.2.1", "reason": "r1"}]},
    {"id": "IAM-002", "title": "Check 2", "pci_dss": [{"control": "7.2.2", "reason": "r2"}]},
    {"id": "IAM-003", "title": "Check 3", "pci_dss": [{"control": "7.3.1", "reason": "r3"}]},
    {"id": "IAM-004", "title": "Check 4", "pci_dss": [{"control": "8.4.1", "reason": "r4"}]},
    {"id": "IAM-005", "title": "Check 5", "pci_dss": [{"control": "8.4.2", "reason": "r5"}]}
  ]
}
""".strip()
        )

        # Two findings: 7.2.1 (non-compliant) and 8.4.1 (non-compliant)
        findings = {
            "skill": "iam",
            "findings": [
                {
                    "id": "IAM-F1",
                    "severity": "High",
                    "risk_score": 8.0,
                    "title": "Finding 1",
                    "description": "...",
                    "remediation": "...",
                    "pci_dss": [{"control": "7.2.1", "reason": "Non-compliant"}],
                },
                {
                    "id": "IAM-F2",
                    "severity": "Critical",
                    "risk_score": 9.0,
                    "title": "Finding 2",
                    "description": "...",
                    "remediation": "...",
                    "pci_dss": [{"control": "8.4.1", "reason": "Non-compliant"}],
                },
            ],
            "summary": {"total_findings": 2},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        formatter._get_checklist_path = lambda skill: chk_path
        stats = formatter._compliance_statistics()

        # Should contain table with requirements 7 and 8
        assert "## 📊 Compliance Statistics" in stats
        assert "| Requirement | Controls | Compliant | Non-Compliant | Rate |" in stats
        assert "7. Access Control | 3 | 2 | 1 | 67%" in stats
        assert "8. Identification & Authentication | 2 | 1 | 1 | 50%" in stats
        # Should not contain "TBD"
        assert "TBD" not in stats

    def test_compliance_statistics_empty_when_no_controls(self, tmp_path):
        """_compliance_statistics() should return empty string if no controls."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["unknown_skill"]
        config.report_type = "pci-dss"

        findings = {
            "skill": "unknown_skill",
            "findings": [],
            "summary": {"total_findings": 0},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        stats = formatter._compliance_statistics()

        assert stats == ""

    def test_recommendations_sorted_by_risk_score(self, tmp_path):
        """_recommendations() should list findings sorted by risk_score descending."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        chk_path = tmp_path / "checklist.json"
        chk_path.write_text(
            """
{
  "items": [
    {"id": "IAM-001", "title": "Check 1", "pci_dss": [{"control": "7.2.1", "reason": "r1"}]},
    {"id": "IAM-002", "title": "Check 2", "pci_dss": [{"control": "8.4.1", "reason": "r2"}]},
    {"id": "IAM-003", "title": "Check 3", "pci_dss": [{"control": "10.2.1", "reason": "r3"}]}
  ]
}
""".strip()
        )

        findings = {
            "skill": "iam",
            "findings": [
                {
                    "id": "IAM-F1",
                    "severity": "High",
                    "risk_score": 6.5,
                    "title": "Lower Risk Finding",
                    "description": "...",
                    "remediation": "Fix this issue by doing X.",
                    "pci_dss": [{"control": "7.2.1", "reason": "Non-compliant"}],
                },
                {
                    "id": "IAM-F2",
                    "severity": "Critical",
                    "risk_score": 9.2,
                    "title": "Critical Finding",
                    "description": "...",
                    "remediation": "This is very critical. Please fix immediately.",
                    "pci_dss": [{"control": "8.4.1", "reason": "Non-compliant"}],
                },
                {
                    "id": "IAM-F3",
                    "severity": "Medium",
                    "risk_score": 5.0,
                    "title": "Medium Risk",
                    "description": "...",
                    "remediation": "Address this medium priority issue.",
                    "pci_dss": [{"control": "10.2.1", "reason": "Non-compliant"}],
                },
            ],
            "summary": {"total_findings": 3},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        formatter._get_checklist_path = lambda skill: chk_path
        recs = formatter._recommendations()

        # Should contain header
        assert "## 📝 Recommendations" in recs
        # Should not contain "TBD"
        assert "TBD" not in recs
        # Should be sorted by risk score descending: 9.2, 6.5, 5.0
        lines = recs.split("\n")
        critical_idx = next(i for i, line in enumerate(lines) if "Critical Finding" in line)
        lower_idx = next(i for i, line in enumerate(lines) if "Lower Risk Finding" in line)
        medium_idx = next(i for i, line in enumerate(lines) if "Medium Risk" in line)
        assert critical_idx < lower_idx < medium_idx

    def test_recommendations_empty_when_no_findings(self, tmp_path):
        """_recommendations() should return empty string if no non-compliant controls."""
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
        recs = formatter._recommendations()

        assert recs == ""

    def test_no_tbd_in_full_report(self, tmp_path):
        """Regression test: report should never contain literal 'TBD' strings."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.skills = ["iam"]
        config.report_type = "pci-dss"

        chk_path = tmp_path / "checklist.json"
        chk_path.write_text(
            """
{
  "items": [
    {"id": "IAM-001", "title": "Check 1", "pci_dss": [{"control": "7.2.1", "reason": "r1"}]},
    {"id": "IAM-002", "title": "Check 2", "pci_dss": [{"control": "8.4.1", "reason": "r2"}]}
  ]
}
""".strip()
        )

        findings = {
            "skill": "iam",
            "findings": [
                {
                    "id": "IAM-F1",
                    "severity": "Critical",
                    "risk_score": 9.0,
                    "title": "Test Finding",
                    "description": "...",
                    "remediation": "Do something.",
                    "pci_dss": [{"control": "7.2.1", "reason": "Non-compliant"}],
                }
            ],
            "summary": {"total_findings": 1},
            "analyzed_at": "2026-02-09T00:00:00Z",
        }

        formatter = PCIDSSFormatter(findings, session, config)
        formatter._get_checklist_path = lambda skill: chk_path
        md = formatter._build_pci_report()

        # The bug was that _compliance_statistics() and _recommendations() returned
        # literal "TBD" strings, so a complete report would contain them
        assert "TBD" not in md, "Report contains unfinished placeholder 'TBD' string"
