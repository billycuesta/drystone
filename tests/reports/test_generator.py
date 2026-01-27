"""Unit tests for the report generator."""

import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from drystone.reports.generator import ReportGenerator
from drystone.models.config import WizardConfig
from drystone.storage.session import AuditSession

@pytest.fixture
def sample_findings():
    """Fixture for sample findings data with mixed severities."""
    return {
        "skill": "iam",
        "findings": [
            {"id": "IAM-001", "severity": "Critical", "risk_score": 9.5},
            {"id": "IAM-002", "severity": "High", "risk_score": 7.5},
            {"id": "IAM-003", "severity": "Medium", "risk_score": 5.0},
            {"id": "IAM-004", "severity": "Low", "risk_score": 2.0},
            {"id": "IAM-005", "severity": "Medium", "risk_score": 4.5},
        ],
        "summary": {
            "total_findings": 5, "critical": 1, "high": 1, "medium": 2, "low": 1, 
            "overall_risk_score": 5.7
        }
    }

@pytest.fixture
def mock_session(tmp_path: Path, sample_findings):
    """Fixture for a mock AuditSession."""
    session = AuditSession("test-client", "123456789012")
    
    # Create dummy findings file
    findings_path = session.get_findings_path()
    findings_path.mkdir(parents=True, exist_ok=True)
    with open(findings_path / "iam.json", "w") as f:
        json.dump(sample_findings, f)
        
    return session

@pytest.mark.parametrize("min_severity, expected_count", [
    ("low", 5),
    ("medium", 4),
    ("high", 2),
    ("critical", 1),
])
def test_filter_findings_by_severity(min_severity, expected_count, sample_findings):
    """Test that the finding filtering logic works correctly for each severity level."""
    config = WizardConfig(
        client_name="test",
        skills=["iam"],
        output_formats=["markdown"],
        min_severity=min_severity
    )
    # The session argument is not used in this specific method, so it can be a mock
    generator = ReportGenerator(session=Mock(), config=config)

    filtered_data = generator._filter_findings_by_severity(sample_findings)
    
    assert len(filtered_data["findings"]) == expected_count
    
    # Check that the summary is recalculated correctly
    assert filtered_data["summary"]["total_findings"] == expected_count

def test_generate_reports_with_filtering(mock_session):
    """Test the end-to-end report generation with an active severity filter."""
    config = WizardConfig(
        client_name="test",
        skills=["iam"],
        output_formats=["markdown"],
        min_severity="high" # Filter for High and Critical
    )
    generator = ReportGenerator(session=mock_session, config=config)

    # Create a mock for the formatter class
    MockFormatterClass = MagicMock()
    mock_formatter_instance = Mock()
    MockFormatterClass.return_value = mock_formatter_instance

    # Patch the FORMATTERS dict on the instance to use the mock
    generator.FORMATTERS["markdown"] = MockFormatterClass

    generator.generate_reports(skill="iam", formats=["markdown"])

    # Verify that the formatter class was instantiated with the *filtered* data
    # The first argument to the formatter's constructor is the findings_data
    MockFormatterClass.assert_called_once()
    call_args, _ = MockFormatterClass.call_args
    filtered_data = call_args[0]
    
    assert len(filtered_data["findings"]) == 2 # Only Critical and High
    assert filtered_data["summary"]["total_findings"] == 2
    assert filtered_data["summary"]["critical"] == 1
    assert filtered_data["summary"]["high"] == 1
    assert filtered_data["summary"]["medium"] == 0
    assert filtered_data["summary"]["low"] == 0

    # Check that generate() was called on the formatter instance
    mock_formatter_instance.generate.assert_called_once()
