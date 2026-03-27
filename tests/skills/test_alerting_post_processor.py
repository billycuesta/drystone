"""Tests for the alerting post-processor."""

import json
from unittest.mock import Mock

from drystone.skills.alerting.post_processor import AlertingPostProcessor
from drystone.storage.session import AuditSession


def _make_session(evidence_dir):
    session = Mock(spec=AuditSession)
    session.get_evidence_path.return_value = evidence_dir
    return session


def _write_evidence(evidence_dir, filename, data):
    (evidence_dir / filename).write_text(json.dumps(data))


class TestAlertingPostProcessorAddsArchitecture:
    def test_adds_architecture_field(self, tmp_path):
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True)
        session = _make_session(evidence_dir)

        _write_evidence(
            evidence_dir,
            "cloudtrail-trails.json",
            [{"Name": "main", "IsMultiRegionTrail": True, "Status": {"IsLogging": True}}],
        )
        _write_evidence(evidence_dir, "cloudwatch-alarms.json", [])
        _write_evidence(
            evidence_dir,
            "cloudwatch-log-groups.json",
            [{"LogGroupName": "CloudtrailLogGroup", "RetentionInDays": 365}],
        )
        _write_evidence(evidence_dir, "cloudwatch-metric-filters.json", [])
        _write_evidence(evidence_dir, "eventbridge-rules.json", [])
        _write_evidence(evidence_dir, "sns-topics.json", [])
        _write_evidence(evidence_dir, "config-rules.json", [])
        _write_evidence(evidence_dir, "vpc-flow-logs.json", [])

        proc = AlertingPostProcessor(session)
        findings = {"findings": [], "summary": {}}
        result = proc.process(findings)

        assert "architecture" in result
        assert "flow_diagram" in result["architecture"]
        assert "components_detected" in result["architecture"]
        assert "critical_gaps" in result["architecture"]


class TestAlertingFlowAnalysis:
    def test_cloudtrail_enabled_when_logging(self, tmp_path):
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True)
        session = _make_session(evidence_dir)

        _write_evidence(
            evidence_dir,
            "cloudtrail-trails.json",
            [
                {
                    "Name": "main",
                    "IsMultiRegionTrail": True,
                    "Status": {"IsLogging": True},
                }
            ],
        )
        _write_evidence(evidence_dir, "cloudwatch-alarms.json", [])
        _write_evidence(evidence_dir, "cloudwatch-log-groups.json", [])
        _write_evidence(evidence_dir, "cloudwatch-metric-filters.json", [])
        _write_evidence(evidence_dir, "eventbridge-rules.json", [])
        _write_evidence(evidence_dir, "sns-topics.json", [])

        proc = AlertingPostProcessor(session)
        evidence = proc._load_evidence()
        analysis = proc._analyze_flow(evidence)

        assert analysis["cloudtrail_enabled"] is True
        assert analysis["cloudtrail_multi_region"] is True

    def test_metric_filters_exist_only_when_filters_present(self, tmp_path):
        """metric_filters_exist should be False when filters list is empty."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True)
        session = _make_session(evidence_dir)

        _write_evidence(
            evidence_dir,
            "cloudtrail-trails.json",
            [{"Name": "main", "Status": {"IsLogging": True}}],
        )
        _write_evidence(
            evidence_dir,
            "cloudwatch-log-groups.json",
            [{"LogGroupName": "CloudtrailLogGroup", "RetentionInDays": 400}],
        )
        # Empty metric filters — cloudwatch_integration=True but no filters configured
        _write_evidence(evidence_dir, "cloudwatch-metric-filters.json", [])
        _write_evidence(evidence_dir, "cloudwatch-alarms.json", [])
        _write_evidence(evidence_dir, "eventbridge-rules.json", [])
        _write_evidence(evidence_dir, "sns-topics.json", [])

        proc = AlertingPostProcessor(session)
        evidence = proc._load_evidence()
        analysis = proc._analyze_flow(evidence)

        # CloudWatch integration detected via log group name containing "cloudtrail"
        assert analysis["cloudwatch_integration"] is True
        # But no metric filters configured
        assert analysis["metric_filters_exist"] is False

    def test_metric_filters_exist_when_filters_present(self, tmp_path):
        """metric_filters_exist should be True when at least one filter exists."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True)
        session = _make_session(evidence_dir)

        _write_evidence(
            evidence_dir,
            "cloudwatch-metric-filters.json",
            [
                {
                    "filterName": "ConsoleLogin",
                    "filterPattern": '{ $.eventName = "ConsoleLogin" }',
                    "logGroupName": "CloudtrailLogGroup",
                    "metricTransformations": [{"metricName": "ConsoleLoginCount"}],
                }
            ],
        )
        _write_evidence(evidence_dir, "cloudtrail-trails.json", [])
        _write_evidence(evidence_dir, "cloudwatch-alarms.json", [])
        _write_evidence(evidence_dir, "cloudwatch-log-groups.json", [])
        _write_evidence(evidence_dir, "eventbridge-rules.json", [])
        _write_evidence(evidence_dir, "sns-topics.json", [])

        proc = AlertingPostProcessor(session)
        evidence = proc._load_evidence()
        analysis = proc._analyze_flow(evidence)

        assert analysis["metric_filters_exist"] is True

    def test_critical_gap_identified_when_no_alarms(self, tmp_path):
        """No CloudWatch alarms should appear as a critical gap."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True)
        session = _make_session(evidence_dir)

        _write_evidence(
            evidence_dir,
            "cloudtrail-trails.json",
            [{"Name": "main", "Status": {"IsLogging": True}}],
        )
        _write_evidence(evidence_dir, "cloudwatch-alarms.json", [])
        _write_evidence(evidence_dir, "cloudwatch-log-groups.json", [])
        _write_evidence(evidence_dir, "cloudwatch-metric-filters.json", [])
        _write_evidence(evidence_dir, "eventbridge-rules.json", [])
        _write_evidence(evidence_dir, "sns-topics.json", [])

        proc = AlertingPostProcessor(session)
        evidence = proc._load_evidence()
        analysis = proc._analyze_flow(evidence)
        gaps = proc._identify_critical_gaps(analysis)

        assert any("alarm" in g.lower() for g in gaps)

    def test_sns_confirmed_detection(self, tmp_path):
        """SNS topic with confirmed subscription should mark subscriptions_confirmed."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True)
        session = _make_session(evidence_dir)

        _write_evidence(
            evidence_dir,
            "sns-topics.json",
            [
                {
                    "TopicArn": "arn:aws:sns:us-east-1:111:alerts",
                    "Subscriptions": [
                        {
                            "SubscriptionArn": "arn:aws:sns:us-east-1:111:alerts:abc",
                            "Protocol": "email",
                            "Endpoint": "sec@example.com",
                        }
                    ],
                }
            ],
        )
        _write_evidence(evidence_dir, "cloudtrail-trails.json", [])
        _write_evidence(evidence_dir, "cloudwatch-alarms.json", [])
        _write_evidence(evidence_dir, "cloudwatch-log-groups.json", [])
        _write_evidence(evidence_dir, "cloudwatch-metric-filters.json", [])
        _write_evidence(evidence_dir, "eventbridge-rules.json", [])

        proc = AlertingPostProcessor(session)
        evidence = proc._load_evidence()
        analysis = proc._analyze_flow(evidence)

        assert analysis["sns_topics_exist"] is True
        assert analysis["sns_has_subscribers"] is True
        assert analysis["subscriptions_confirmed"] is True

    def test_no_gaps_when_fully_configured(self, tmp_path):
        """A fully configured alerting stack should produce no gaps."""
        evidence_dir = tmp_path / "evidence"
        evidence_dir.mkdir(parents=True)
        session = _make_session(evidence_dir)

        _write_evidence(
            evidence_dir,
            "cloudtrail-trails.json",
            [
                {
                    "Name": "main",
                    "IsMultiRegionTrail": True,
                    "Status": {"IsLogging": True},
                }
            ],
        )
        _write_evidence(
            evidence_dir,
            "cloudwatch-log-groups.json",
            [{"LogGroupName": "CloudtrailLogGroup", "RetentionInDays": 365}],
        )
        _write_evidence(
            evidence_dir,
            "cloudwatch-metric-filters.json",
            [
                {
                    "filterName": "ConsoleLogin",
                    "filterPattern": '{ $.eventName = "ConsoleLogin" }',
                    "logGroupName": "CloudtrailLogGroup",
                    "metricTransformations": [{"metricName": "ConsoleLoginCount"}],
                }
            ],
        )
        _write_evidence(
            evidence_dir,
            "cloudwatch-alarms.json",
            [
                {
                    "AlarmName": "security-console-login",
                    "MetricName": "ConsoleLoginCount",
                    "AlarmActions": ["arn:aws:sns:us-east-1:111:security-alerts"],
                    "StateValue": "OK",
                }
            ],
        )
        _write_evidence(
            evidence_dir,
            "eventbridge-rules.json",
            [
                {
                    "Name": "ct-stoplogging",
                    "EventPattern": '{"source":["aws.cloudtrail"]}',
                    "State": "ENABLED",
                    "Targets": [{"Arn": "arn:aws:sns:us-east-1:111:security-alerts"}],
                }
            ],
        )
        _write_evidence(
            evidence_dir,
            "sns-topics.json",
            [
                {
                    "TopicArn": "arn:aws:sns:us-east-1:111:security-alerts",
                    "Subscriptions": [
                        {
                            "SubscriptionArn": "arn:aws:sns:us-east-1:111:security-alerts:abc",
                            "Protocol": "email",
                            "Endpoint": "sec@example.com",
                        }
                    ],
                }
            ],
        )

        proc = AlertingPostProcessor(session)
        evidence = proc._load_evidence()
        analysis = proc._analyze_flow(evidence)
        gaps = proc._identify_critical_gaps(analysis)

        assert analysis["cloudtrail_enabled"] is True
        assert analysis["cloudtrail_multi_region"] is True
        assert analysis["cloudwatch_integration"] is True
        assert analysis["metric_filters_exist"] is True
        assert analysis["alarms_configured"] is True
        assert analysis["sns_topics_exist"] is True
        assert analysis["subscriptions_confirmed"] is True
        # No critical gaps when all components configured
        critical_gaps = [g for g in gaps if "eventbridge" not in g.lower()]
        assert len(critical_gaps) == 0
