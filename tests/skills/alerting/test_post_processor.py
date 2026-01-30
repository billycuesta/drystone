"""Tests for alerting post-processor."""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from drystone.skills.alerting.post_processor import AlertingPostProcessor
from drystone.storage.session import AuditSession


@pytest.fixture
def temp_session():
    """Create a temporary audit session for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create the session with mocked components
        session = MagicMock(spec=AuditSession)
        session.client_name = "TestClient"
        session.account_id = "123456789012"

        # Create evidence directory structure
        evidence_dir = Path(tmpdir) / "evidence" / "alerting"
        evidence_dir.mkdir(parents=True, exist_ok=True)

        session.get_evidence_path.return_value = evidence_dir
        session.base_path = Path(tmpdir)

        yield session, evidence_dir


class TestAlertingPostProcessor:
    """Test suite for AlertingPostProcessor."""

    def test_load_evidence_empty_directory(self, temp_session):
        """Test loading evidence from empty directory."""
        session, evidence_dir = temp_session

        # Create empty evidence files
        for filename in [
            "cloudtrail-trails.json",
            "cloudwatch-log-groups.json",
            "cloudwatch-alarms.json",
            "eventbridge-rules.json",
            "sns-topics.json",
            "config-rules.json",
            "vpc-flow-logs.json",
        ]:
            (evidence_dir / filename).write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        evidence = processor._load_evidence()

        # All keys should exist (from created files)
        assert "cloudtrail_trails" in evidence
        assert "sns_topics" in evidence
        assert all(isinstance(v, list) for v in evidence.values())

    def test_full_alerting_flow(self, temp_session):
        """Test complete alerting flow detection with all components."""
        session, evidence_dir = temp_session

        # Create sample evidence files
        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        log_groups = [
            {"LogGroupName": "/aws/cloudtrail/logs"}
        ]
        (evidence_dir / "cloudwatch-log-groups.json").write_text(
            json.dumps(log_groups)
        )

        alarms = [
            {"AlarmName": "SecurityAlertAlarm", "AlarmArn": "arn:aws:cloudwatch:..."}
        ]
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps(alarms))

        rules = [
            {
                "Name": "SecurityAlertRule",
                "State": "ENABLED",
                "EventPattern": "{}",
                "Targets": [],
            }
        ]
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps(rules))

        topics = [
            {
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:Security",
                "Attributes": {"SubscriptionsConfirmed": "1"},
                "Subscriptions": [
                    {
                        "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:Security:abc",
                        "Protocol": "email",
                        "Endpoint": "security@example.com",
                    }
                ],
            }
        ]
        (evidence_dir / "sns-topics.json").write_text(json.dumps(topics))

        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps(rules))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())

        # All components should be detected
        assert analysis["cloudtrail_enabled"] is True
        assert analysis["cloudtrail_multi_region"] is True
        assert analysis["cloudwatch_integration"] is True
        assert analysis["metric_filters_exist"] is True
        assert analysis["alarms_configured"] is True
        assert analysis["eventbridge_rules_exist"] is True
        assert analysis["sns_topics_exist"] is True
        assert analysis["sns_has_subscribers"] is True
        assert analysis["subscriptions_confirmed"] is True

    def test_missing_cloudtrail(self, temp_session):
        """Test diagram when CloudTrail is disabled."""
        session, evidence_dir = temp_session

        # Create empty evidence
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps([]))
        (evidence_dir / "cloudwatch-log-groups.json").write_text(json.dumps([]))
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps([]))
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "sns-topics.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())
        gaps = processor._identify_critical_gaps(analysis)

        assert analysis["cloudtrail_enabled"] is False
        assert "CloudTrail is not enabled" in gaps[0]

    def test_cloudtrail_without_cloudwatch(self, temp_session):
        """Test CloudTrail enabled but no CloudWatch Logs integration."""
        session, evidence_dir = temp_session

        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        # No CloudTrail-related log groups
        log_groups = [{"LogGroupName": "/aws/other/logs"}]
        (evidence_dir / "cloudwatch-log-groups.json").write_text(
            json.dumps(log_groups)
        )

        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps([]))
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "sns-topics.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())
        gaps = processor._identify_critical_gaps(analysis)

        assert analysis["cloudtrail_enabled"] is True
        assert analysis["cloudwatch_integration"] is False
        assert any(
            "CloudTrail not integrated with CloudWatch" in gap for gap in gaps
        )

    def test_sns_without_subscribers(self, temp_session):
        """Test SNS topics with no active subscriptions."""
        session, evidence_dir = temp_session

        # Minimal CloudTrail for flow
        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        log_groups = [{"LogGroupName": "/aws/cloudtrail/logs"}]
        (evidence_dir / "cloudwatch-log-groups.json").write_text(
            json.dumps(log_groups)
        )

        alarms = [{"AlarmName": "SecurityAlert"}]
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps(alarms))

        # SNS topic with no subscriptions
        topics = [
            {
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:Security",
                "Attributes": {"SubscriptionsConfirmed": "0"},
                "Subscriptions": [],
            }
        ]
        (evidence_dir / "sns-topics.json").write_text(json.dumps(topics))

        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())
        gaps = processor._identify_critical_gaps(analysis)

        assert analysis["sns_topics_exist"] is True
        assert analysis["sns_has_subscribers"] is False
        assert any("SNS topics exist but have no" in gap for gap in gaps)

    def test_pending_subscriptions(self, temp_session):
        """Test SNS topics with pending confirmations."""
        session, evidence_dir = temp_session

        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        log_groups = [{"LogGroupName": "/aws/cloudtrail/logs"}]
        (evidence_dir / "cloudwatch-log-groups.json").write_text(
            json.dumps(log_groups)
        )

        alarms = [{"AlarmName": "SecurityAlert"}]
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps(alarms))

        # SNS topic with pending subscription
        topics = [
            {
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:Security",
                "Attributes": {"SubscriptionsConfirmed": "0", "SubscriptionsPending": "1"},
                "Subscriptions": [
                    {
                        "SubscriptionArn": "PendingConfirmation",
                        "Protocol": "email",
                        "Endpoint": "security@example.com",
                    }
                ],
            }
        ]
        (evidence_dir / "sns-topics.json").write_text(json.dumps(topics))

        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())
        gaps = processor._identify_critical_gaps(analysis)

        assert analysis["sns_has_subscribers"] is True
        assert analysis["subscriptions_confirmed"] is False
        assert any("subscriptions exist but are not confirmed" in gap for gap in gaps)

    def test_eventbridge_only(self, temp_session):
        """Test EventBridge-based flow without CloudWatch Logs."""
        session, evidence_dir = temp_session

        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        # No CloudWatch log groups
        (evidence_dir / "cloudwatch-log-groups.json").write_text(json.dumps([]))

        alarms = [{"AlarmName": "SecurityAlert"}]
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps(alarms))

        # EventBridge rules exist
        rules = [
            {
                "Name": "SecurityAlertRule",
                "State": "ENABLED",
                "EventPattern": "{}",
            }
        ]
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps(rules))

        topics = [
            {
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:Security",
                "Subscriptions": [
                    {
                        "SubscriptionArn": "arn:aws:sns:...",
                        "Protocol": "https",
                        "Endpoint": "https://example.com/notify",
                    }
                ],
            }
        ]
        (evidence_dir / "sns-topics.json").write_text(json.dumps(topics))

        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())

        assert analysis["eventbridge_rules_exist"] is True
        assert analysis["cloudwatch_integration"] is False

    def test_minimal_configuration(self, temp_session):
        """Test minimal setup (only CloudTrail to S3)."""
        session, evidence_dir = temp_session

        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": False,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        (evidence_dir / "cloudwatch-log-groups.json").write_text(json.dumps([]))
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps([]))
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "sns-topics.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())
        gaps = processor._identify_critical_gaps(analysis)

        assert analysis["cloudtrail_enabled"] is True
        assert analysis["cloudtrail_multi_region"] is False
        assert len(gaps) > 0  # Multiple gaps expected

    def test_diagram_generation(self, temp_session):
        """Test that diagram is generated with correct indicators."""
        session, evidence_dir = temp_session

        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        (evidence_dir / "cloudwatch-log-groups.json").write_text(json.dumps([]))
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps([]))
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "sns-topics.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())
        diagram = processor._generate_diagram(analysis)

        # Check diagram contains expected elements
        assert "AWS SECURITY ALERTING FLOW ARCHITECTURE" in diagram
        assert "CloudTrail" in diagram
        assert "✅" in diagram  # At least one success indicator
        assert "❌" in diagram  # At least one failure indicator
        assert "SNS Topics" in diagram
        assert "LEGEND:" in diagram

    def test_process_adds_architecture_field(self, temp_session):
        """Test that process() adds architecture field to findings."""
        session, evidence_dir = temp_session

        # Create minimal evidence
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps([]))
        (evidence_dir / "cloudwatch-log-groups.json").write_text(json.dumps([]))
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps([]))
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "sns-topics.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        findings = {
            "skill": "alerting",
            "findings": [],
            "summary": {"total_findings": 0},
        }

        processor = AlertingPostProcessor(session)
        result = processor.process(findings)

        assert "architecture" in result
        assert "flow_diagram" in result["architecture"]
        assert "components_detected" in result["architecture"]
        assert "critical_gaps" in result["architecture"]

    def test_critical_gaps_list(self, temp_session):
        """Test that critical gaps are correctly identified."""
        session, evidence_dir = temp_session

        # Scenario: CloudTrail enabled but no downstream components
        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        (evidence_dir / "cloudwatch-log-groups.json").write_text(json.dumps([]))
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps([]))
        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "sns-topics.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        processor = AlertingPostProcessor(session)
        analysis = processor._analyze_flow(processor._load_evidence())
        gaps = processor._identify_critical_gaps(analysis)

        assert len(gaps) > 0
        assert any("CloudTrail not integrated with CloudWatch" in gap for gap in gaps)
        assert any("alarms" in gap for gap in gaps)
        assert any("SNS" in gap for gap in gaps)


class TestAlertingPostProcessorIntegration:
    """Integration tests for post-processor with report generator."""

    def test_post_processor_with_report_generator(self, temp_session):
        """Test post-processor integration with report generator flow."""
        session, evidence_dir = temp_session

        # Create evidence files
        trails = [
            {
                "Name": "management",
                "IsMultiRegionTrail": True,
                "Status": {"IsLogging": True},
            }
        ]
        (evidence_dir / "cloudtrail-trails.json").write_text(json.dumps(trails))

        log_groups = [{"LogGroupName": "/aws/cloudtrail/logs"}]
        (evidence_dir / "cloudwatch-log-groups.json").write_text(
            json.dumps(log_groups)
        )

        alarms = [{"AlarmName": "SecurityAlert"}]
        (evidence_dir / "cloudwatch-alarms.json").write_text(json.dumps(alarms))

        topics = [
            {
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:Security",
                "Subscriptions": [
                    {
                        "SubscriptionArn": "arn:aws:sns:...",
                        "Protocol": "email",
                        "Endpoint": "security@example.com",
                    }
                ],
            }
        ]
        (evidence_dir / "sns-topics.json").write_text(json.dumps(topics))

        (evidence_dir / "eventbridge-rules.json").write_text(json.dumps([]))
        (evidence_dir / "config-rules.json").write_text(json.dumps([]))
        (evidence_dir / "vpc-flow-logs.json").write_text(json.dumps([]))

        # Simulate findings from agent
        findings = {
            "skill": "alerting",
            "findings": [
                {
                    "id": "ALERT-001",
                    "severity": "High",
                    "title": "Test finding",
                }
            ],
            "summary": {"total_findings": 1},
        }

        processor = AlertingPostProcessor(session)
        enhanced_findings = processor.process(findings)

        # Verify architecture field was added
        assert "architecture" in enhanced_findings
        assert enhanced_findings["skill"] == "alerting"
        assert enhanced_findings["findings"][0]["id"] == "ALERT-001"
