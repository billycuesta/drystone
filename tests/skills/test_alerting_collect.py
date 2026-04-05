"""Tests for AlertingSkill.collect() and _save_json().

Strategy:
- Patch boto3.client with a factory dispatch function (same pattern as test_hardening.py)
- Use _make_paginator() helper to avoid unconfigured-MagicMock infinite-loop pitfalls
- Test: happy path (all data collected + JSON files written)
- Test: each service exception is swallowed with a warning (error resilience)
- Test: per-resource sub-calls (get_trail_status, get_event_selectors,
        list_targets_by_rule, get_topic_attributes, list_subscriptions_by_topic,
        describe_compliance_by_config_rule) use inner try/except
- Test: session_token branch adds aws_session_token to client_kwargs
- Test: _save_json writes valid JSON
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from drystone.skills.alerting import AlertingSkill

# ── Low-level helpers ──────────────────────────────────────────────────────────


def _make_paginator(*pages):
    """Return a mock paginator whose .paginate() returns the given pages."""
    pag = MagicMock()
    pag.paginate.return_value = iter(pages)
    return pag


def _make_aws_client(access_key="AKID", secret="SECRET", region="us-east-1", token=None):
    client = MagicMock()
    client.access_key_id = access_key
    client.secret_access_key = secret
    client.region_name = region
    client.session_token = token
    return client


def _make_session(tmp_path, skill_name="alerting"):
    session = MagicMock()
    evidence_path = tmp_path / "evidence" / skill_name
    evidence_path.mkdir(parents=True)
    session.get_evidence_path.return_value = evidence_path
    return session, evidence_path


# ── Per-service mock factories ────────────────────────────────────────────────


def _make_ct_client():
    """CloudTrail mock: describe_trails, get_trail_status, get_event_selectors."""
    c = MagicMock()
    c.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "my-trail",
                "S3BucketName": "my-bucket",
                "IsMultiRegionTrail": True,
                "HomeRegion": "us-east-1",
                "HasCustomEventSelectors": True,
                "HasInsightSelectors": False,
                "IsOrganizationTrail": False,
                "CloudWatchLogsLogGroupArn": "arn:aws:logs::123:log-group:CloudTrail",
                "CloudWatchLogsRoleArn": "arn:aws:iam::123:role/CloudTrail",
                "KMSKeyId": None,
                "LogFileValidationEnabled": True,
            }
        ]
    }
    c.get_trail_status.return_value = {
        "IsLogging": True,
        "LatestDeliveryTime": "2026-01-01",
        "LatestDeliveryAttemptTime": "2026-01-01",
    }
    c.get_event_selectors.return_value = {"EventSelectors": [{"ReadWriteType": "All"}]}
    return c


def _make_logs_client():
    """CloudWatch Logs mock: paginators for log_groups and metric_filters."""
    c = MagicMock()

    log_group_page = {
        "logGroups": [
            {
                "logGroupName": "/aws/cloudtrail",
                "creationTime": 1700000000,
                "retentionInDays": 90,
                "storedBytes": 1024,
                "arn": "arn:aws:logs::123:log-group:/aws/cloudtrail",
            }
        ]
    }
    metric_filter_page = {
        "metricFilters": [
            {
                "filterName": "root-login",
                "filterPattern": '{ $.userIdentity.type = "Root" }',
                "logGroupName": "/aws/cloudtrail",
                "metricTransformations": [{"metricName": "RootLoginCount"}],
                "creationTime": 1700000000,
            }
        ]
    }

    def _get_paginator(name):
        if name == "describe_log_groups":
            return _make_paginator(log_group_page)
        if name == "describe_metric_filters":
            return _make_paginator(metric_filter_page)
        return _make_paginator({})

    c.get_paginator.side_effect = _get_paginator
    c.describe_resource_policies.return_value = {"resourcePolicies": []}
    return c


def _make_cw_client():
    """CloudWatch Alarms mock."""
    c = MagicMock()
    alarm_page = {
        "MetricAlarms": [
            {
                "AlarmName": "high-error-rate",
                "AlarmDescription": "Errors > threshold",
                "MetricName": "Errors",
                "Namespace": "AWS/Lambda",
                "Statistic": "Sum",
                "Period": 300,
                "EvaluationPeriods": 1,
                "Threshold": 10,
                "ComparisonOperator": "GreaterThanThreshold",
                "AlarmActions": ["arn:aws:sns::123:alerts"],
                "StateValue": "OK",
                "StateUpdatedTimestamp": "2026-01-01",
            }
        ]
    }
    c.get_paginator.return_value = _make_paginator(alarm_page)
    return c


def _make_events_client():
    """EventBridge mock."""
    c = MagicMock()
    rules_page = {
        "Rules": [
            {
                "Name": "detect-root-login",
                "EventPattern": '{"source":["aws.signin"]}',
                "ScheduleExpression": None,
                "State": "ENABLED",
                "Description": "Detect root login",
                "Arn": "arn:aws:events::123:rule/detect-root-login",
            }
        ]
    }
    c.get_paginator.return_value = _make_paginator(rules_page)
    c.list_targets_by_rule.return_value = {
        "Targets": [{"Id": "1", "Arn": "arn:aws:sns::123:alerts"}]
    }
    return c


def _make_sns_client():
    """SNS mock."""
    c = MagicMock()
    topics_page = {"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:123:alerts"}]}
    c.get_paginator.return_value = _make_paginator(topics_page)
    c.get_topic_attributes.return_value = {"Attributes": {"DisplayName": "Alerts"}}
    c.list_subscriptions_by_topic.return_value = {
        "Subscriptions": [{"Protocol": "email", "Endpoint": "ops@example.com"}]
    }
    return c


def _make_ec2_client():
    """EC2 mock for VPC Flow Logs."""
    c = MagicMock()
    c.describe_flow_logs.return_value = {
        "FlowLogs": [
            {
                "FlowLogId": "fl-123",
                "ResourceId": "vpc-abc",
                "ResourceType": "VPC",
                "TrafficType": "ALL",
                "LogGroupName": "/vpc/flow-logs",
                "LogDestinationType": "cloud-watch-logs",
                "LogDestination": "arn:aws:logs::123:log-group:/vpc/flow-logs",
                "FlowLogStatus": "ACTIVE",
                "Tags": [],
            }
        ]
    }
    return c


def _make_config_client():
    """AWS Config mock."""
    c = MagicMock()
    c.describe_config_rules.return_value = {
        "ConfigRules": [
            {
                "ConfigRuleName": "s3-bucket-public-read-prohibited",
                "ConfigRuleArn": "arn:aws:config::123:config-rule/s3-rule",
                "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
                "Scope": {},
                "ConfigRuleState": "ACTIVE",
            }
        ]
    }
    c.describe_compliance_by_config_rule.return_value = {
        "ComplianceByConfigRules": [{"Compliance": {"ComplianceType": "COMPLIANT"}}]
    }
    return c


def _make_s3_client(with_notifications=False):
    """S3 mock for bucket notification configuration."""
    c = MagicMock()
    if with_notifications:
        c.get_bucket_notification_configuration.return_value = {
            "LambdaFunctionConfigurations": [
                {
                    "LambdaFunctionArn": "arn:aws:lambda:us-east-1:123:function:process-logs",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ],
            "QueueConfigurations": [],
            "TopicConfigurations": [],
        }
    else:
        c.get_bucket_notification_configuration.return_value = {
            "LambdaFunctionConfigurations": [],
            "QueueConfigurations": [],
            "TopicConfigurations": [],
        }
    return c


def _make_logs_client_with_subscriptions(subscription_filters=None):
    """CloudWatch Logs mock that includes subscription filters."""
    base = _make_logs_client()
    filters = subscription_filters or []
    base.describe_subscription_filters.return_value = {"subscriptionFilters": filters}
    return base


def _boto3_factory(**overrides):
    """Dispatch factory: returns the appropriate mock client by service name."""
    clients = {
        "cloudtrail": _make_ct_client(),
        "logs": _make_logs_client(),
        "cloudwatch": _make_cw_client(),
        "events": _make_events_client(),
        "sns": _make_sns_client(),
        "ec2": _make_ec2_client(),
        "config": _make_config_client(),
        "s3": _make_s3_client(),
    }
    clients.update(overrides)

    def _factory(service, **kwargs):
        return clients[service]

    return _factory


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def skill():
    return AlertingSkill()


@pytest.fixture
def aws_client():
    return _make_aws_client()


# ── Happy path ────────────────────────────────────────────────────────────────


class TestCollectHappyPath:
    def test_all_evidence_files_created(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        expected = [
            "cloudtrail-trails.json",
            "cloudwatch-log-groups.json",
            "cloudwatch-metric-filters.json",
            "cloudwatch-alarms.json",
            "eventbridge-rules.json",
            "sns-topics.json",
            "vpc-flow-logs.json",
            "config-rules.json",
        ]
        for fname in expected:
            assert (evidence_path / fname).exists(), f"Missing: {fname}"

    def test_cloudtrail_trails_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-trails.json").read_text())
        assert len(data) == 1
        assert data[0]["Name"] == "my-trail"
        assert data[0]["Status"]["IsLogging"] is True
        assert data[0]["EventSelectors"] == [{"ReadWriteType": "All"}]

    def test_cloudwatch_log_groups_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudwatch-log-groups.json").read_text())
        assert len(data) == 1
        assert data[0]["LogGroupName"] == "/aws/cloudtrail"
        assert data[0]["RetentionInDays"] == 90

    def test_cloudwatch_metric_filters_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudwatch-metric-filters.json").read_text())
        assert len(data) == 1
        assert data[0]["filterName"] == "root-login"

    def test_cloudwatch_alarms_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudwatch-alarms.json").read_text())
        assert len(data) == 1
        assert data[0]["AlarmName"] == "high-error-rate"

    def test_eventbridge_rules_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "eventbridge-rules.json").read_text())
        assert len(data) == 1
        assert data[0]["Name"] == "detect-root-login"
        assert len(data[0]["Targets"]) == 1

    def test_sns_topics_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "sns-topics.json").read_text())
        assert len(data) == 1
        assert data[0]["TopicArn"] == "arn:aws:sns:us-east-1:123:alerts"
        assert data[0]["Attributes"]["DisplayName"] == "Alerts"
        assert len(data[0]["Subscriptions"]) == 1

    def test_vpc_flow_logs_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "vpc-flow-logs.json").read_text())
        assert len(data) == 1
        assert data[0]["FlowLogId"] == "fl-123"
        assert data[0]["FlowLogStatus"] == "ACTIVE"

    def test_config_rules_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "config-rules.json").read_text())
        assert len(data) == 1
        assert data[0]["ConfigRuleName"] == "s3-bucket-public-read-prohibited"
        assert data[0]["Compliance"]["ComplianceType"] == "COMPLIANT"


# ── Session token branch ──────────────────────────────────────────────────────


class TestSessionToken:
    def test_session_token_passed_to_boto3(self, skill, tmp_path):
        aws_client = _make_aws_client(token="STS-TOKEN-123")
        session, _ = _make_session(tmp_path)

        captured_kwargs = []

        def _tracking_factory(service, **kwargs):
            captured_kwargs.append(kwargs)
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_tracking_factory):
            skill.collect(aws_client, session)

        # At least one call should include aws_session_token
        token_calls = [k for k in captured_kwargs if "aws_session_token" in k]
        assert len(token_calls) > 0
        assert token_calls[0]["aws_session_token"] == "STS-TOKEN-123"

    def test_no_session_token_not_in_kwargs(self, skill, tmp_path):
        aws_client = _make_aws_client(token=None)
        session, _ = _make_session(tmp_path)

        captured_kwargs = []

        def _tracking_factory(service, **kwargs):
            captured_kwargs.append(kwargs)
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_tracking_factory):
            skill.collect(aws_client, session)

        token_calls = [k for k in captured_kwargs if "aws_session_token" in k]
        assert len(token_calls) == 0


# ── Error resilience: each service exception is swallowed ────────────────────


class TestErrorResilience:
    def _collect_with_broken(self, skill, tmp_path, broken_service):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        def _factory(service, **kwargs):
            if service == broken_service:
                raise Exception(f"{service} unavailable")
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            skill.collect(aws_client, session)  # Must not raise

        return evidence_path

    def test_cloudtrail_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "cloudtrail")
        # Other files still created
        assert (evidence_path / "cloudwatch-alarms.json").exists()
        assert not (evidence_path / "cloudtrail-trails.json").exists()

    def test_logs_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "logs")
        assert (evidence_path / "cloudwatch-alarms.json").exists()

    def test_cloudwatch_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "cloudwatch")
        assert (evidence_path / "cloudtrail-trails.json").exists()

    def test_events_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "events")
        assert (evidence_path / "cloudtrail-trails.json").exists()

    def test_sns_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "sns")
        assert (evidence_path / "cloudtrail-trails.json").exists()

    def test_ec2_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "ec2")
        assert (evidence_path / "cloudtrail-trails.json").exists()

    def test_config_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "config")
        assert (evidence_path / "cloudtrail-trails.json").exists()


# ── Inner sub-call exceptions swallowed ──────────────────────────────────────


class TestSubCallResilience:
    def test_get_trail_status_failure_still_saves_trail(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ct = _make_ct_client()
        ct.get_trail_status.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(cloudtrail=ct)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-trails.json").read_text())
        assert data[0]["Status"] == {}

    def test_get_event_selectors_failure_still_saves_trail(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ct = _make_ct_client()
        ct.get_event_selectors.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(cloudtrail=ct)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-trails.json").read_text())
        assert data[0]["EventSelectors"] == []

    def test_list_targets_by_rule_failure_still_saves_rule(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ev = _make_events_client()
        ev.list_targets_by_rule.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(events=ev)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "eventbridge-rules.json").read_text())
        assert data[0]["Targets"] == []

    def test_get_topic_attributes_failure_still_saves_topic(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        sns = _make_sns_client()
        sns.get_topic_attributes.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(sns=sns)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "sns-topics.json").read_text())
        assert data[0]["Attributes"] == {}

    def test_list_subscriptions_failure_still_saves_topic(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        sns = _make_sns_client()
        sns.list_subscriptions_by_topic.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(sns=sns)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "sns-topics.json").read_text())
        assert data[0]["Subscriptions"] == []

    def test_describe_compliance_failure_still_saves_rule(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        cfg = _make_config_client()
        cfg.describe_compliance_by_config_rule.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(config=cfg)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "config-rules.json").read_text())
        assert data[0]["Compliance"] == {}


# ── Empty responses ───────────────────────────────────────────────────────────


class TestEmptyResponses:
    def test_no_trails_writes_empty_list(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ct = _make_ct_client()
        ct.describe_trails.return_value = {"trailList": []}

        with patch("boto3.client", side_effect=_boto3_factory(cloudtrail=ct)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-trails.json").read_text())
        assert data == []

    def test_no_flow_logs_writes_empty_list(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ec2 = _make_ec2_client()
        ec2.describe_flow_logs.return_value = {"FlowLogs": []}

        with patch("boto3.client", side_effect=_boto3_factory(ec2=ec2)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "vpc-flow-logs.json").read_text())
        assert data == []


# ── _save_json ────────────────────────────────────────────────────────────────


class TestSaveJson:
    def test_saves_valid_json(self, skill, tmp_path):
        filepath = tmp_path / "test.json"
        skill._save_json(filepath, {"key": "value", "num": 42})
        data = json.loads(filepath.read_text())
        assert data == {"key": "value", "num": 42}

    def test_saves_list(self, skill, tmp_path):
        filepath = tmp_path / "list.json"
        skill._save_json(filepath, [1, 2, 3])
        assert json.loads(filepath.read_text()) == [1, 2, 3]

    def test_uses_default_str_for_non_serializable(self, skill, tmp_path):
        """datetime objects should be serialized via default=str."""
        from datetime import datetime

        filepath = tmp_path / "dt.json"
        now = datetime(2026, 1, 15, 10, 30, 0)
        skill._save_json(filepath, {"ts": now})
        data = json.loads(filepath.read_text())
        assert "2026" in data["ts"]

    def test_creates_file_with_indent(self, skill, tmp_path):
        """Output should be pretty-printed (indented)."""
        filepath = tmp_path / "pretty.json"
        skill._save_json(filepath, {"a": 1})
        content = filepath.read_text()
        assert "\n" in content  # indented → multi-line


# ── S3 bucket notifications ───────────────────────────────────────────────────


class TestS3BucketNotifications:
    def test_writes_cloudtrail_s3_notifications_file(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        assert (evidence_path / "cloudtrail-s3-notifications.json").exists()

    def test_no_notifications_returns_empty_configs(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        with patch("boto3.client", side_effect=_boto3_factory(s3=_make_s3_client(with_notifications=False))):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-s3-notifications.json").read_text())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["bucket_name"] == "my-bucket"
        assert data[0]["lambda_configs"] == []
        assert data[0]["sqs_configs"] == []
        assert data[0]["sns_configs"] == []

    def test_with_lambda_notification(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        s3 = _make_s3_client(with_notifications=True)

        with patch("boto3.client", side_effect=_boto3_factory(s3=s3)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-s3-notifications.json").read_text())
        assert len(data) == 1
        assert len(data[0]["lambda_configs"]) == 1
        assert "process-logs" in data[0]["lambda_configs"][0]["LambdaFunctionArn"]

    def test_s3_access_denied_stores_error(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        s3 = MagicMock()
        s3.get_bucket_notification_configuration.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(s3=s3)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-s3-notifications.json").read_text())
        assert len(data) == 1
        assert "error" in data[0]
        assert "AccessDenied" in data[0]["error"]

    def test_no_trails_writes_empty_list(self, skill, tmp_path):
        """If no trails, no S3 notifications to collect."""
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ct = _make_ct_client()
        ct.describe_trails.return_value = {"trailList": []}

        with patch("boto3.client", side_effect=_boto3_factory(cloudtrail=ct)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-s3-notifications.json").read_text())
        assert data == []


# ── CloudTrail log subscriptions ──────────────────────────────────────────────


class TestCloudTrailLogSubscriptions:
    def test_writes_cloudtrail_log_subscriptions_file(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        assert (evidence_path / "cloudtrail-log-subscriptions.json").exists()

    def test_no_subscriptions_returns_empty_list(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        logs = _make_logs_client_with_subscriptions([])

        with patch("boto3.client", side_effect=_boto3_factory(logs=logs)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-log-subscriptions.json").read_text())
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["subscription_filters"] == []

    def test_with_subscription_filter(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        filters = [
            {
                "filterName": "forward-to-lambda",
                "logGroupName": "CloudTrail",
                "destinationArn": "arn:aws:lambda:us-east-1:123:function:log-processor",
                "filterPattern": "",
            }
        ]
        logs = _make_logs_client_with_subscriptions(filters)

        with patch("boto3.client", side_effect=_boto3_factory(logs=logs)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-log-subscriptions.json").read_text())
        assert len(data) == 1
        assert len(data[0]["subscription_filters"]) == 1
        assert data[0]["subscription_filters"][0]["filterName"] == "forward-to-lambda"

    def test_log_group_name_extracted_from_arn(self, skill, tmp_path):
        """Log group name should be extracted correctly from the CloudWatchLogsLogGroupArn."""
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        logs = _make_logs_client_with_subscriptions([])

        with patch("boto3.client", side_effect=_boto3_factory(logs=logs)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-log-subscriptions.json").read_text())
        # ARN in _make_ct_client: "arn:aws:logs::123:log-group:CloudTrail"
        assert data[0]["log_group_name"] == "CloudTrail"

    def test_trail_without_cloudwatch_arn_skipped(self, skill, tmp_path):
        """Trails without CloudWatchLogsLogGroupArn should produce no subscription entries."""
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        ct = _make_ct_client()
        # Trail without CW logs
        ct.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "no-cw-trail",
                    "S3BucketName": "my-bucket",
                    "IsMultiRegionTrail": True,
                    "HomeRegion": "us-east-1",
                    "HasCustomEventSelectors": False,
                    "HasInsightSelectors": False,
                    "IsOrganizationTrail": False,
                    "CloudWatchLogsLogGroupArn": None,
                    "CloudWatchLogsRoleArn": None,
                    "KMSKeyId": None,
                    "LogFileValidationEnabled": True,
                }
            ]
        }

        with patch("boto3.client", side_effect=_boto3_factory(cloudtrail=ct)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-log-subscriptions.json").read_text())
        assert data == []

    def test_describe_subscription_filters_error_stores_error(self, skill, tmp_path):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)
        logs = _make_logs_client_with_subscriptions([])
        logs.describe_subscription_filters.side_effect = Exception("ResourceNotFound")

        with patch("boto3.client", side_effect=_boto3_factory(logs=logs)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "cloudtrail-log-subscriptions.json").read_text())
        assert len(data) == 1
        assert "error" in data[0]


# ── skill.name property ───────────────────────────────────────────────────────


def test_skill_name():
    assert AlertingSkill().name == "alerting"
