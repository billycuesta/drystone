"""Tests for markdown correlation report rendering."""

import json
from unittest.mock import Mock, patch

import pytest

from drystone.reports.formats.markdown import MarkdownFormatter
from drystone.storage.session import AuditSession


class TestCorrelationSection:
    """Tests for _correlation_section() method."""

    @pytest.fixture
    def mock_session(self, tmp_path):
        """Create mock session with findings directory."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"

        # Mock the required methods
        session.get_reports_path.return_value = tmp_path / "reports"
        session.get_findings_path.return_value = tmp_path / "findings"

        # Create findings directory
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        (tmp_path / "reports").mkdir(parents=True)

        return session

    @pytest.fixture
    def mock_config(self):
        """Create mock report config."""
        config = Mock()
        config.report_type = "general"
        return config

    @pytest.fixture
    def formatter(self, mock_session, mock_config):
        """Create formatter instance."""
        findings = {"skill": "iam", "findings": [], "summary": {"total_findings": 0}}
        formatter = MarkdownFormatter(findings, mock_session, mock_config)
        return formatter

    def test_no_correlated_file(self, formatter):
        """Test when correlated.json doesn't exist."""
        result = formatter._correlation_section()
        assert result == ""

    def test_empty_correlations_array(self, formatter):
        """Test when correlated.json exists but has no correlations."""
        corr_file = formatter.session.base_path / "findings" / "correlated.json"
        corr_data = {"correlations": [], "metadata": {"skills_analyzed": ["iam", "network"]}}
        with open(corr_file, "w") as f:
            json.dump(corr_data, f)

        result = formatter._correlation_section()
        assert "No cross-skill attack patterns detected" in result
        assert "✅" in result

    def test_malformed_json(self, formatter):
        """Test when correlated.json is invalid JSON."""
        corr_file = formatter.session.base_path / "findings" / "correlated.json"
        with open(corr_file, "w") as f:
            f.write("{ invalid json }")

        result = formatter._correlation_section()
        assert result == ""

    def test_single_correlation(self, formatter):
        """Test rendering single correlation."""
        corr_file = formatter.session.base_path / "findings" / "correlated.json"
        corr_data = {
            "correlations": [
                {
                    "id": "CORR-ssh-001",
                    "title": "SSH Compromise Risk",
                    "severity": "Critical",
                    "compound_risk_score": 9.5,
                    "description": "Open SSH port with weak credentials",
                    "attack_path": [
                        "Attacker discovers open SSH port",
                        "Attempts brute force attack",
                        "Gains access with weak password",
                        "Escalates privileges",
                    ],
                    "source_findings": [
                        {
                            "skill": "iam",
                            "id": "IAM-001",
                            "title": "Weak password policy",
                            "severity": "High",
                            "risk_score": 8.0,
                        },
                        {
                            "skill": "network",
                            "id": "NET-001",
                            "title": "SSH 0.0.0.0/0",
                            "severity": "Critical",
                            "risk_score": 9.0,
                        },
                    ],
                    "affected_resources": [
                        "arn:aws:ec2:us-east-1:123456789012:instance/i-001",
                        "arn:aws:ec2:us-east-1:123456789012:instance/i-002",
                    ],
                    "remediation_priority": "Immediate",
                    "remediation_steps": [
                        "1. Enable MFA on all IAM users",
                        "2. Restrict SSH to bastion host only",
                        "3. Enforce strong password policy",
                    ],
                }
            ],
            "metadata": {"skills_analyzed": ["iam", "network"]},
        }
        with open(corr_file, "w") as f:
            json.dump(corr_data, f)

        result = formatter._correlation_section()

        assert "## 🔗 Cross-Skill Correlations" in result
        assert "CORR-ssh-001" in result
        assert "SSH Compromise Risk" in result
        assert "9.5" in result
        assert "Attacker discovers open SSH port" in result
        assert "IAM-001" in result
        assert "NET-001" in result
        assert "Weak password policy" in result
        assert "SSH 0.0.0.0/0" in result

    def test_multiple_correlations_sorted(self, formatter):
        """Test that multiple correlations are sorted by risk score."""
        corr_file = formatter.session.base_path / "findings" / "correlated.json"
        corr_data = {
            "correlations": [
                {
                    "id": "CORR-001",
                    "title": "Low Risk Pattern",
                    "severity": "Medium",
                    "compound_risk_score": 5.0,
                    "description": "Low risk",
                    "attack_path": [],
                    "source_findings": [],
                    "affected_resources": [],
                    "remediation_priority": "Low",
                    "remediation_steps": [],
                },
                {
                    "id": "CORR-002",
                    "title": "High Risk Pattern",
                    "severity": "Critical",
                    "compound_risk_score": 9.5,
                    "description": "High risk",
                    "attack_path": [],
                    "source_findings": [],
                    "affected_resources": [],
                    "remediation_priority": "Immediate",
                    "remediation_steps": [],
                },
                {
                    "id": "CORR-003",
                    "title": "Medium Risk Pattern",
                    "severity": "High",
                    "compound_risk_score": 7.0,
                    "description": "Medium risk",
                    "attack_path": [],
                    "source_findings": [],
                    "affected_resources": [],
                    "remediation_priority": "Short-term",
                    "remediation_steps": [],
                },
            ],
            "metadata": {"skills_analyzed": ["iam", "network"]},
        }
        with open(corr_file, "w") as f:
            json.dump(corr_data, f)

        result = formatter._correlation_section()

        # Should appear in order: CORR-002 (9.5), CORR-003 (7.0), CORR-001 (5.0)
        idx_002 = result.index("CORR-002")
        idx_003 = result.index("CORR-003")
        idx_001 = result.index("CORR-001")

        assert idx_002 < idx_003 < idx_001

    def test_truncation_limit_10(self, formatter):
        """Test that only top 10 correlations are displayed."""
        corr_file = formatter.session.base_path / "findings" / "correlated.json"

        # Create 15 correlations
        correlations = []
        for i in range(15, 0, -1):
            correlations.append(
                {
                    "id": f"CORR-{i:03d}",
                    "title": f"Pattern {i}",
                    "severity": "High" if i % 2 == 0 else "Critical",
                    "compound_risk_score": float(i),
                    "description": f"Pattern {i}",
                    "attack_path": [],
                    "source_findings": [],
                    "affected_resources": [],
                    "remediation_priority": "Medium",
                    "remediation_steps": [],
                }
            )

        corr_data = {
            "correlations": correlations,
            "metadata": {"skills_analyzed": ["iam", "network"]},
        }
        with open(corr_file, "w") as f:
            json.dump(corr_data, f)

        result = formatter._correlation_section()

        # Top 10 should be displayed (CORR-015 through CORR-006)
        assert "CORR-015" in result
        assert "CORR-006" in result

        # CORR-005 and below should not be displayed
        assert "CORR-005" not in result
        assert "CORR-001" not in result

        # Should have "and 5 more" message
        assert "and 5 more correlations" in result


class TestFormatCorrelation:
    """Tests for _format_correlation() method."""

    @pytest.fixture
    def formatter(self, tmp_path):
        """Create formatter instance."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.report_type = "general"

        findings = {"skill": "iam", "findings": [], "summary": {"total_findings": 0}}
        return MarkdownFormatter(findings, session, config)

    def test_attack_path_numbering(self, formatter):
        """Test attack path rendered with arrows."""
        corr = {
            "id": "CORR-001",
            "title": "Test Pattern",
            "severity": "Critical",
            "compound_risk_score": 9.0,
            "description": "Test description",
            "attack_path": [
                "Step 1: Initial access",
                "Step 2: Privilege escalation",
                "Step 3: Data exfiltration",
            ],
            "source_findings": [],
            "affected_resources": [],
            "remediation_priority": "Immediate",
            "remediation_steps": [],
        }

        result = formatter._format_correlation(corr, 1)

        assert "1. Step 1: Initial access" in result
        assert "2. ➜ Step 2: Privilege escalation" in result
        assert "3. ➜ Step 3: Data exfiltration" in result

    def test_source_findings_table(self, formatter):
        """Test source findings rendered as table."""
        corr = {
            "id": "CORR-001",
            "title": "Test Pattern",
            "severity": "Critical",
            "compound_risk_score": 9.0,
            "description": "Test",
            "attack_path": [],
            "source_findings": [
                {
                    "skill": "iam",
                    "id": "IAM-001",
                    "title": "Root has active access keys",
                    "severity": "Critical",
                    "risk_score": 9.5,
                },
                {
                    "skill": "network",
                    "id": "NET-001",
                    "title": "SSH open to internet",
                    "severity": "Critical",
                    "risk_score": 9.0,
                },
            ],
            "affected_resources": [],
            "remediation_priority": "Immediate",
            "remediation_steps": [],
        }

        result = formatter._format_correlation(corr, 1)

        assert "| Skill | Finding ID | Title | Severity | Risk |" in result
        assert "🔐 IAM | IAM-001" in result
        assert "🌐 NETWORK | NET-001" in result
        assert "9.5" in result
        assert "9.0" in result

    def test_affected_resources_limit(self, formatter):
        """Test affected resources truncated to 3."""
        corr = {
            "id": "CORR-001",
            "title": "Test Pattern",
            "severity": "Critical",
            "compound_risk_score": 9.0,
            "description": "Test",
            "attack_path": [],
            "source_findings": [],
            "affected_resources": [
                "arn:aws:ec2:us-east-1:123456789012:instance/i-001",
                "arn:aws:ec2:us-east-1:123456789012:instance/i-002",
                "arn:aws:ec2:us-east-1:123456789012:instance/i-003",
                "arn:aws:ec2:us-east-1:123456789012:instance/i-004",
                "arn:aws:ec2:us-east-1:123456789012:instance/i-005",
            ],
            "remediation_priority": "Immediate",
            "remediation_steps": [],
        }

        result = formatter._format_correlation(corr, 1)

        assert "5 total" in result
        assert "i-001" in result
        assert "i-002" in result
        assert "i-003" in result
        assert "i-004" not in result  # Beyond limit
        assert "and 2 more" in result

    def test_remediation_steps_rendering(self, formatter):
        """Test remediation steps rendered correctly."""
        corr = {
            "id": "CORR-001",
            "title": "Test Pattern",
            "severity": "Critical",
            "compound_risk_score": 9.0,
            "description": "Test",
            "attack_path": [],
            "source_findings": [],
            "affected_resources": [],
            "remediation_priority": "Immediate",
            "remediation_steps": [
                "Enable MFA on all IAM users",
                "Restrict SSH to bastion host",
                "Implement intrusion detection",
            ],
        }

        result = formatter._format_correlation(corr, 1)

        assert "**Remediation Steps:**" in result
        assert "Enable MFA on all IAM users" in result
        assert "Restrict SSH to bastion host" in result
        assert "Implement intrusion detection" in result


class TestGetSkillEmoji:
    """Tests for _get_skill_emoji() method."""

    @pytest.fixture
    def formatter(self, tmp_path):
        """Create formatter instance."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"
        (tmp_path / "reports").mkdir(parents=True)

        config = Mock()
        config.report_type = "general"

        findings = {"skill": "iam", "findings": [], "summary": {"total_findings": 0}}
        return MarkdownFormatter(findings, session, config)

    def test_skill_emojis_mapped(self, formatter):
        """Test all skills have correct emojis."""
        assert formatter._get_skill_emoji("iam") == "🔐"
        assert formatter._get_skill_emoji("network") == "🌐"
        assert formatter._get_skill_emoji("exposure") == "🚪"
        assert formatter._get_skill_emoji("vulns") == "🐛"
        assert formatter._get_skill_emoji("hardening") == "🛡️"
        assert formatter._get_skill_emoji("alerting") == "🚨"

    def test_skill_emoji_case_insensitive(self, formatter):
        """Test emoji mapping is case insensitive."""
        assert formatter._get_skill_emoji("IAM") == "🔐"
        assert formatter._get_skill_emoji("Network") == "🌐"
        assert formatter._get_skill_emoji("EXPOSURE") == "🚪"

    def test_unknown_skill_default_emoji(self, formatter):
        """Test unknown skills get default emoji."""
        assert formatter._get_skill_emoji("unknown") == "🔹"
        assert formatter._get_skill_emoji("custom") == "🔹"


class TestIntegrationFullReport:
    """Integration tests for full report with correlations."""

    @pytest.fixture
    def formatter_with_data(self, tmp_path):
        """Create formatter with sample data."""
        session = Mock(spec=AuditSession)
        session.base_path = tmp_path
        session.account_id = "123456789012"
        session.client_name = "TestClient"
        session.get_reports_path.return_value = tmp_path / "reports"

        # Create findings directory
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        (tmp_path / "reports").mkdir(parents=True)

        # Create correlated.json
        corr_file = findings_dir / "correlated.json"
        corr_data = {
            "correlations": [
                {
                    "id": "CORR-001",
                    "title": "SSH Account Compromise",
                    "severity": "Critical",
                    "compound_risk_score": 9.5,
                    "description": "Multiple findings combine to enable account compromise via SSH",
                    "attack_path": [
                        "Network: Port 22 open to 0.0.0.0/0",
                        "IAM: Weak password policy allows brute force",
                        "IAM: No MFA required on root account",
                        "Result: Attacker gains full AWS access",
                    ],
                    "source_findings": [
                        {
                            "skill": "network",
                            "id": "NET-001",
                            "title": "SSH Open",
                            "severity": "Critical",
                            "risk_score": 9.0,
                        },
                        {
                            "skill": "iam",
                            "id": "IAM-001",
                            "title": "No MFA on root",
                            "severity": "Critical",
                            "risk_score": 9.5,
                        },
                    ],
                    "affected_resources": ["arn:aws:iam::123456789012:root"],
                    "remediation_priority": "Immediate",
                    "remediation_steps": [
                        "1. Enable MFA on root account",
                        "2. Restrict SSH to bastion hosts",
                    ],
                }
            ],
            "metadata": {"skills_analyzed": ["iam", "network"]},
        }
        with open(corr_file, "w") as f:
            json.dump(corr_data, f)

        config = Mock()
        config.report_type = "general"

        findings = {"skill": "iam", "findings": [], "summary": {"total_findings": 0}}

        return MarkdownFormatter(findings, session, config)

    def test_correlation_section_appears_in_report(self, formatter_with_data):
        """Test correlation section is included in markdown output."""
        # Mock the other sections to return empty
        with patch.object(formatter_with_data, "_header", return_value="# Header\n"):
            with patch.object(
                formatter_with_data, "_executive_summary", return_value="## Summary\n"
            ):
                with patch.object(formatter_with_data, "_architecture_diagram", return_value=""):
                    with patch.object(
                        formatter_with_data, "_remediation_timeline", return_value="## Timeline\n"
                    ):
                        with patch.object(
                            formatter_with_data,
                            "_findings_by_severity",
                            return_value="## Findings\n",
                        ):
                            with patch.object(
                                formatter_with_data, "_observations", return_value=""
                            ):
                                with patch.object(
                                    formatter_with_data, "_references", return_value=""
                                ):
                                    with patch.object(
                                        formatter_with_data, "_footer", return_value=""
                                    ):
                                        report = formatter_with_data._build_markdown()

        assert "## 🔗 Cross-Skill Correlations" in report
        assert "CORR-001" in report
        assert "SSH Account Compromise" in report
