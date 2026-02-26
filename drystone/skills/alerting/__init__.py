"""Alerting and monitoring skill for AWS audit."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

import boto3

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession

if TYPE_CHECKING:
    pass


class AlertingSkill(BaseSkill):
    """Alerting and monitoring audit skill - analyzes CloudTrail, CloudWatch, and EventBridge."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "alerting"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect alerting and monitoring configuration from AWS account.

        Collects:
            - CloudTrail configuration and trails
            - CloudWatch log groups and retention policies
            - CloudWatch alarms (metrics and logs)
            - EventBridge rules and targets
            - SNS topics and subscriptions
            - IAM role monitoring
            - VPC Flow Logs configuration
            - AWS Config rules and compliance

        Args:
            aws_client: Authenticated AWS client
            session: Audit session for evidence storage
        """
        client_kwargs = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        evidence_path = session.get_evidence_path(self.name)

        # === CLOUDTRAIL ===
        print("  Collecting CloudTrail configuration...")
        try:
            ct_client = boto3.client("cloudtrail", **client_kwargs)
            trails = ct_client.describe_trails()
            trails_list = []

            for trail in trails.get("trailList", []):
                trail_name = trail.get("Name")
                trail_detail = {
                    "Name": trail_name,
                    "S3BucketName": trail.get("S3BucketName"),
                    "IsMultiRegionTrail": trail.get("IsMultiRegionTrail"),
                    "HomeRegion": trail.get("HomeRegion"),
                    "HasCustomEventSelectors": trail.get("HasCustomEventSelectors"),
                    "HasInsightSelectors": trail.get("HasInsightSelectors"),
                    "IsOrganizationTrail": trail.get("IsOrganizationTrail"),
                    # Fields required by pre-checks ALRT-001, ALRT-013, ALRT-014
                    "CloudWatchLogsLogGroupArn": trail.get("CloudWatchLogsLogGroupArn"),
                    "CloudWatchLogsRoleArn": trail.get("CloudWatchLogsRoleArn"),
                    "KMSKeyId": trail.get("KMSKeyId"),
                    "LogFileValidationEnabled": trail.get("LogFileValidationEnabled"),
                }

                # Get trail status
                try:
                    status = ct_client.get_trail_status(Name=trail_name)
                    trail_detail["Status"] = {
                        "IsLogging": status.get("IsLogging"),
                        "LatestDeliveryTime": status.get("LatestDeliveryTime"),
                        "LatestDeliveryAttemptTime": status.get("LatestDeliveryAttemptTime"),
                    }
                except Exception:
                    trail_detail["Status"] = {}

                # Get event selectors
                try:
                    selectors = ct_client.get_event_selectors(TrailName=trail_name)
                    trail_detail["EventSelectors"] = selectors.get("EventSelectors", [])
                except Exception:
                    trail_detail["EventSelectors"] = []

                trails_list.append(trail_detail)

            self._save_json(evidence_path / "cloudtrail-trails.json", trails_list)
        except Exception as e:
            print(f"    Warning: Could not collect CloudTrail data: {e}")

        # === CLOUDWATCH LOG GROUPS ===
        print("  Collecting CloudWatch log groups...")
        try:
            logs_client = boto3.client("logs", **client_kwargs)
            log_groups_list = []

            paginator = logs_client.get_paginator("describe_log_groups")
            for page in paginator.paginate():
                for log_group in page.get("logGroups", []):
                    lg_detail = {
                        "LogGroupName": log_group.get("logGroupName"),
                        "CreationTime": log_group.get("creationTime"),
                        "RetentionInDays": log_group.get("retentionInDays"),
                        "StoredBytes": log_group.get("storedBytes"),
                        "Arn": log_group.get("arn"),
                    }

                    # Get log group policy
                    try:
                        policy = logs_client.describe_resource_policies()
                        lg_detail["ResourcePolicies"] = policy.get("resourcePolicies", [])
                    except Exception:
                        lg_detail["ResourcePolicies"] = []

                    log_groups_list.append(lg_detail)

            self._save_json(evidence_path / "cloudwatch-log-groups.json", log_groups_list)
        except Exception as e:
            print(f"    Warning: Could not collect CloudWatch log groups: {e}")

        # === CLOUDWATCH METRIC FILTERS ===
        print("  Collecting CloudWatch metric filters...")
        try:
            logs_client = boto3.client("logs", **client_kwargs)
            metric_filters_list = []

            paginator = logs_client.get_paginator("describe_metric_filters")
            for page in paginator.paginate():
                for mf in page.get("metricFilters", []):
                    mf_detail = {
                        "filterName": mf.get("filterName"),
                        "filterPattern": mf.get("filterPattern"),
                        "logGroupName": mf.get("logGroupName"),
                        "metricTransformations": mf.get("metricTransformations", []),
                        "creationTime": mf.get("creationTime"),
                    }
                    metric_filters_list.append(mf_detail)

            self._save_json(evidence_path / "cloudwatch-metric-filters.json", metric_filters_list)
        except Exception as e:
            print(f"    Warning: Could not collect CloudWatch metric filters: {e}")

        # === CLOUDWATCH ALARMS ===
        print("  Collecting CloudWatch alarms...")
        try:
            cw_client = boto3.client("cloudwatch", **client_kwargs)
            alarms_list = []

            paginator = cw_client.get_paginator("describe_alarms")
            for page in paginator.paginate():
                for alarm in page.get("MetricAlarms", []):
                    alarm_detail = {
                        "AlarmName": alarm.get("AlarmName"),
                        "AlarmDescription": alarm.get("AlarmDescription"),
                        "MetricName": alarm.get("MetricName"),
                        "Namespace": alarm.get("Namespace"),
                        "Statistic": alarm.get("Statistic"),
                        "Period": alarm.get("Period"),
                        "EvaluationPeriods": alarm.get("EvaluationPeriods"),
                        "Threshold": alarm.get("Threshold"),
                        "ComparisonOperator": alarm.get("ComparisonOperator"),
                        "AlarmActions": alarm.get("AlarmActions", []),
                        "StateValue": alarm.get("StateValue"),
                        "StateUpdatedTimestamp": alarm.get("StateUpdatedTimestamp"),
                    }
                    alarms_list.append(alarm_detail)

            self._save_json(evidence_path / "cloudwatch-alarms.json", alarms_list)
        except Exception as e:
            print(f"    Warning: Could not collect CloudWatch alarms: {e}")

        # === EVENTBRIDGE RULES ===
        print("  Collecting EventBridge rules...")
        try:
            events_client = boto3.client("events", **client_kwargs)
            rules_list = []

            # List all rules
            paginator = events_client.get_paginator("list_rules")
            for page in paginator.paginate():
                for rule in page.get("Rules", []):
                    rule_name = rule.get("Name")
                    rule_detail = {
                        "Name": rule_name,
                        "EventPattern": rule.get("EventPattern"),
                        "ScheduleExpression": rule.get("ScheduleExpression"),
                        "State": rule.get("State"),
                        "Description": rule.get("Description"),
                        "Arn": rule.get("Arn"),
                    }

                    # Get targets for this rule
                    try:
                        targets = events_client.list_targets_by_rule(Rule=rule_name)
                        rule_detail["Targets"] = targets.get("Targets", [])
                    except Exception:
                        rule_detail["Targets"] = []

                    rules_list.append(rule_detail)

            self._save_json(evidence_path / "eventbridge-rules.json", rules_list)
        except Exception as e:
            print(f"    Warning: Could not collect EventBridge rules: {e}")

        # === SNS TOPICS ===
        print("  Collecting SNS topics...")
        try:
            sns_client = boto3.client("sns", **client_kwargs)
            topics_list = []

            paginator = sns_client.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    topic_arn = topic.get("TopicArn")
                    topic_detail = {
                        "TopicArn": topic_arn,
                    }

                    # Get topic attributes
                    try:
                        attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
                        topic_detail["Attributes"] = attrs.get("Attributes", {})
                    except Exception:
                        topic_detail["Attributes"] = {}

                    # List subscriptions
                    try:
                        subs = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
                        topic_detail["Subscriptions"] = subs.get("Subscriptions", [])
                    except Exception:
                        topic_detail["Subscriptions"] = []

                    topics_list.append(topic_detail)

            self._save_json(evidence_path / "sns-topics.json", topics_list)
        except Exception as e:
            print(f"    Warning: Could not collect SNS topics: {e}")

        # === VPC FLOW LOGS ===
        print("  Collecting VPC Flow Logs...")
        try:
            ec2_client = boto3.client("ec2", **client_kwargs)
            flow_logs_list = []

            flow_logs = ec2_client.describe_flow_logs()
            for flow_log in flow_logs.get("FlowLogs", []):
                flow_detail = {
                    "FlowLogId": flow_log.get("FlowLogId"),
                    "ResourceId": flow_log.get("ResourceId"),
                    "ResourceType": flow_log.get("ResourceType"),
                    "TrafficType": flow_log.get("TrafficType"),
                    "LogGroupName": flow_log.get("LogGroupName"),
                    "LogDestinationType": flow_log.get("LogDestinationType"),
                    "LogDestination": flow_log.get("LogDestination"),
                    "FlowLogStatus": flow_log.get("FlowLogStatus"),
                    "Tags": flow_log.get("Tags", []),
                }
                flow_logs_list.append(flow_detail)

            self._save_json(evidence_path / "vpc-flow-logs.json", flow_logs_list)
        except Exception as e:
            print(f"    Warning: Could not collect VPC Flow Logs: {e}")

        # === AWS CONFIG RULES ===
        print("  Collecting AWS Config rules...")
        try:
            config_client = boto3.client("config", **client_kwargs)
            config_rules_list = []

            rules = config_client.describe_config_rules()
            for rule in rules.get("ConfigRules", []):
                rule_detail = {
                    "ConfigRuleName": rule.get("ConfigRuleName"),
                    "ConfigRuleArn": rule.get("ConfigRuleArn"),
                    "Source": rule.get("Source", {}),
                    "Scope": rule.get("Scope", {}),
                    "ConfigRuleState": rule.get("ConfigRuleState"),
                }

                # Get compliance
                try:
                    compliance = config_client.describe_compliance_by_config_rule(
                        ConfigRuleNames=[rule.get("ConfigRuleName")]
                    )
                    rule_detail["Compliance"] = compliance.get("ComplianceByConfigRules", [{}])[
                        0
                    ].get("Compliance", {})
                except Exception:
                    rule_detail["Compliance"] = {}

                config_rules_list.append(rule_detail)

            self._save_json(evidence_path / "config-rules.json", config_rules_list)
        except Exception as e:
            print(f"    Warning: Could not collect Config rules: {e}")

        print("\n✅ Alerting collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["AlertingSkill"]
