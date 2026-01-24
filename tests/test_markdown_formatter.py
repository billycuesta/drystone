"""Unit tests for Markdown formatter with PCI DSS compliance summary."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from drystone.reports.formats.markdown import MarkdownFormatter


class TestPCIDSSComplianceSummary:
    """Tests for PCI DSS compliance summary generation."""

    @pytest.fixture
    def mock_session(self, tmp_path):
        """Create mock session."""
        session = Mock()
        session.account_id = "123456789012"
        session.client_name = "Test Client"
        
        # Mock the get_reports_path method to return a temp path
        reports_path = tmp_path / "reports"
        reports_path.mkdir()
        session.get_reports_path.return_value = reports_path
        return session

    @pytest.fixture
    def findings_with_pci(self):
        """Create sample findings with PCI DSS controls."""
        return {
            "skill": "iam",
            "analyzed_at": "2026-01-22T10:00:00Z",
            "checklist_version": "2.0",
            "evidence_count": 5,
            "summary": {
                "total_findings": 5,
                "critical": 2,
                "high": 2,
                "medium": 1,
                "low": 0,
                "overall_risk_score": 7.5,
            },
            "findings": [
                {
                    "id": "IAM-001",
                    "severity": "Critical",
                    "risk_score": 9.5,
                    "title": "Root account without MFA",
                    "description": "Root account has no MFA",
                    "remediation": "Enable MFA",
                    "pci_dss": [
                        {"control": "8.4.1", "reason": "MFA required"},
                        {"control": "7.2.1", "reason": "Least privilege"},
                    ],
                },
                {
                    "id": "IAM-002",
                    "severity": "Critical",
                    "risk_score": 9.0,
                    "title": "Root access keys active",
                    "description": "Root account has active access keys",
                    "remediation": "Delete root access keys",
                    "pci_dss": [
                        {"control": "2.2.2", "reason": "Vendor defaults"},
                        {"control": "7.2.1", "reason": "Least privilege"},
                    ],
                },
                {
                    "id": "IAM-003",
                    "severity": "High",
                    "risk_score": 7.5,
                    "title": "Admin users without MFA",
                    "description": "Administrative users lack MFA",
                    "remediation": "Enable MFA for admins",
                    "pci_dss": [
                        {"control": "8.4.1", "reason": "MFA required"},
                    ],
                },
                {
                    "id": "IAM-004",
                    "severity": "High",
                    "risk_score": 7.0,
                    "title": "Weak password policy",
                    "description": "Password min length is less than 14",
                    "remediation": "Update password policy",
                    "pci_dss": [
                        {"control": "8.3.6", "reason": "Min length required"},
                    ],
                },
                {
                    "id": "IAM-005",
                    "severity": "Medium",
                    "risk_score": 5.0,
                    "title": "Unused access keys",
                    "description": "Some access keys not used in 90 days",
                    "remediation": "Remove or rotate unused keys",
                    "pci_dss": [
                        {"control": "8.2.6", "reason": "Inactive removal"},
                    ],
                },
            ],
        }

    @pytest.fixture
    def findings_no_pci(self):
        """Create findings without PCI mappings (no pci_dss field)."""
        return {
            "skill": "network",
            "analyzed_at": "2026-01-22T10:00:00Z",
            "checklist_version": "1.0",
            "evidence_count": 3,
            "summary": {
                "total_findings": 2,
                "critical": 0,
                "high": 2,
                "medium": 0,
                "low": 0,
                "overall_risk_score": 7.0,
            },
            "findings": [
                {
                    "id": "NET-001",
                    "severity": "High",
                    "risk_score": 7.0,
                    "title": "Open security group",
                    "description": "Security group allows 0.0.0.0/0",
                    "remediation": "Restrict ingress",
                },
            ],
        }

    def test_natural_sort_key(self, mock_session):
        """Test natural sort key for control IDs."""
        formatter = MarkdownFormatter({}, mock_session)

        # Test sorting
        assert formatter._natural_sort_key("7.2.1") < formatter._natural_sort_key("8.4.1")
        assert formatter._natural_sort_key("8.2.1") < formatter._natural_sort_key("8.3.1")
        assert formatter._natural_sort_key("10.2.1") < formatter._natural_sort_key("12.1.1")

    @patch("drystone.reports.formats.markdown.Path.exists")
    @patch("builtins.open")
    def test_get_all_checklist_controls(self, mock_open, mock_exists, mock_session):
        """Test extraction of all PCI controls from checklist."""
        # Mock checklist.json file
        checklist_data = {
            "items": [
                {"id": "IAM-001", "pci_dss": [{"control": "8.4.1"}, {"control": "7.2.1"}]},
                {"id": "IAM-002", "pci_dss": [{"control": "2.2.2"}]},
                {"id": "IAM-003", "pci_dss": []},
            ]
        }
        import json
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(checklist_data)
        mock_exists.return_value = True

        formatter = MarkdownFormatter({"skill": "iam"}, mock_session)
        controls = formatter._get_all_checklist_controls()

        assert sorted(controls) == ["2.2.2", "7.2.1", "8.4.1"]

    def test_format_findings_count(self, mock_session):
        """Test formatting findings count by severity."""
        formatter = MarkdownFormatter({}, mock_session)

        # Test with mixed severities
        findings = [
            {"severity": "Critical"}, {"severity": "Critical"},
            {"severity": "High"}, {"severity": "Medium"},
        ]
        result = formatter._format_findings_count(findings)
        assert result == "2 Critical, 1 High, 1 Medium"
        assert formatter._format_findings_count([{"severity": "Critical"}]) == "1 Critical"
        assert formatter._format_findings_count([]) == "-"
        assert formatter._format_findings_count([{"severity": "Unknown"}]) == "-"

    def test_extract_pci_controls_map(self, mock_session, findings_with_pci):
        """Test extraction of PCI controls map from findings."""
        formatter = MarkdownFormatter(findings_with_pci, mock_session)

        findings = findings_with_pci["findings"]
        control_map = formatter._extract_pci_controls_map(findings)

        assert "8.4.1" in control_map
        assert len(control_map["8.4.1"]) == 2
        assert control_map["8.4.1"][0]["id"] == "IAM-001"
        assert control_map["8.4.1"][1]["id"] == "IAM-003"
        assert "7.2.1" in control_map
        assert len(control_map["7.2.1"]) == 2
        assert "2.2.2" in control_map

    def test_pci_dss_compliance_summary_generation(self, mock_session, findings_with_pci):
        """Test PCI DSS compliance summary section generation."""
        formatter = MarkdownFormatter(findings_with_pci, mock_session)

        test_controls = ["7.2.1", "8.4.1", "2.2.2", "8.3.6", "8.2.6"]
        with patch.object(formatter, "_get_all_checklist_controls", return_value=test_controls):
            summary = formatter._pci_dss_compliance_summary()

            assert "PCI DSS v4.0 Compliance Summary" in summary
            assert "Compliance Rate" in summary
            assert "0/5" in summary # All controls have findings
            assert "0.0%" in summary

            assert "| 7.2.1 | ❌ KO | 2 Critical |" in summary
            assert "| 8.4.1 | ❌ KO | 1 Critical, 1 High |" in summary
            assert "| 2.2.2 | ❌ KO | 1 Critical |" in summary
            assert "| 8.3.6 | ❌ KO | 1 High |" in summary
            assert "| 8.2.6 | ❌ KO | 1 Medium |" in summary


    def test_pci_dss_compliance_summary_no_pci_mappings(self, mock_session, findings_no_pci):
        """Test that PCI DSS section is skipped when no PCI mappings exist."""
        formatter = MarkdownFormatter(findings_no_pci, mock_session)

        with patch.object(formatter, "_get_all_checklist_controls", return_value=[]):
            summary = formatter._pci_dss_compliance_summary()
            assert summary == ""

    def test_build_markdown_includes_pci_section(self, mock_session, findings_with_pci):
        """Test that build_markdown includes PCI section when appropriate."""
        formatter = MarkdownFormatter(findings_with_pci, mock_session)

        with patch.object(formatter, "_get_all_checklist_controls", return_value=["8.4.1"]):
            markdown = formatter._build_markdown()

            assert "Quick Summary" in markdown
            assert "Executive Summary" in markdown
            assert "PCI DSS v4.0 Compliance Summary" in markdown
            assert "Critical Severity" in markdown

            executive_pos = markdown.find("Executive Summary")
            pci_pos = markdown.find("PCI DSS v4.0 Compliance Summary")
            findings_pos = markdown.find("Severity")
            assert executive_pos < pci_pos < findings_pos

    def test_pci_section_filters_out_empty_sections(self, mock_session):
        """Test that empty PCI section is filtered out."""
        formatter = MarkdownFormatter({"findings": []}, mock_session)
        with patch.object(formatter, "_get_all_checklist_controls", return_value=[]):
            markdown = formatter._build_markdown()
            assert "PCI DSS v4.0 Compliance Summary" not in markdown


class TestNaturalSorting:
    """Test natural sorting of control IDs."""

    @pytest.fixture
    def mock_session(self, tmp_path):
        session = Mock()
        reports_path = tmp_path / "reports"
        reports_path.mkdir()
        session.get_reports_path.return_value = reports_path
        return session

    def test_sort_control_ids(self, mock_session):
        """Test sorting various control ID formats."""
        formatter = MarkdownFormatter({}, mock_session)

        unsorted = ["12.1.3", "1.3.1", "8.4.1", "2.2.2", "7.2.1", "10.2.1", "7.3.2"]
        expected = ["1.3.1", "2.2.2", "7.2.1", "7.3.2", "8.4.1", "10.2.1", "12.1.3"]

        sorted_controls = sorted(unsorted, key=formatter._natural_sort_key)
        assert sorted_controls == expected
