"""Alerting AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"alerting"})

SOURCE_QUERIES = {
    "alerting": {
        "cloudtrail-trails": CliQuery(
            commands=("aws cloudtrail describe-trails\naws cloudtrail get-trail-status --name <trail-name>",),
            output=OutputSpec(
                source="cloudtrail-trails",
                rows="",
                columns=(
                    ("Name", "Name"),
                    ("IsMultiRegionTrail", "IsMultiRegionTrail"),
                    ("CloudWatchLogsLogGroupArn", "CloudWatchLogsLogGroupArn"),
                    ("KmsKeyId", "KmsKeyId"),
                    ("LogFileValidationEnabled", "LogFileValidationEnabled"),
                ),
            ),
        ),
        "cloudtrail-s3-notifications": CliQuery(
            commands=(
                'for trail in $(aws cloudtrail describe-trails --query "trailList[].S3BucketName" --output text); do\n'
                '  aws s3api get-bucket-notification-configuration --bucket "$trail"\n'
                "done",
            ),
            output=OutputSpec(
                source="cloudtrail-s3-notifications",
                rows="",
                columns=(
                    ("bucket_name", "bucket_name"),
                    ("trail_name", "trail_name"),
                    ("lambda_configs", "lambda_configs"),
                    ("sqs_configs", "sqs_configs"),
                    ("sns_configs", "sns_configs"),
                    ("error", "error"),
                ),
            ),
        ),
        "cloudtrail-log-subscriptions": CliQuery(
            commands=(
                'for group in $(aws logs describe-log-groups --query "logGroups[].logGroupName" --output text); do\n'
                '  aws logs describe-subscription-filters --log-group-name "$group"\n'
                "done",
            ),
            output=OutputSpec(
                source="cloudtrail-log-subscriptions",
                rows="",
                columns=(
                    ("log_group_name", "log_group_name"),
                    ("trail_name", "trail_name"),
                    ("subscription_filters", "subscription_filters"),
                    ("error", "error"),
                ),
            ),
        ),
        "cloudwatch-log-groups": CliQuery(
            commands=("aws logs describe-log-groups",),
            output=OutputSpec(
                source="cloudwatch-log-groups",
                rows="",
                columns=(
                    ("LogGroupName", "LogGroupName"),
                    ("RetentionInDays", "RetentionInDays"),
                    ("StoredBytes", "StoredBytes"),
                    ("Arn", "Arn"),
                    ("ResourcePolicies", "ResourcePolicies"),
                ),
            ),
        ),
        "cloudwatch-metric-filters": CliQuery(
            commands=(
                'for group in $(aws logs describe-log-groups --query "logGroups[].logGroupName" --output text); do\n'
                '  aws logs describe-metric-filters --log-group-name "$group"\n'
                "done",
            ),
            output=OutputSpec(
                source="cloudwatch-metric-filters",
                rows="",
                columns=(("FilterName", "FilterName"), ("LogGroupName", "LogGroupName"), ("FilterPattern", "FilterPattern")),
            ),
        ),
        "cloudwatch-alarms": CliQuery(
            commands=("aws cloudwatch describe-alarms",),
            output=OutputSpec(
                source="cloudwatch-alarms",
                rows="",
                columns=(
                    ("AlarmName", "AlarmName"),
                    ("MetricName", "MetricName"),
                    ("Namespace", "Namespace"),
                    ("AlarmActions", "AlarmActions"),
                    ("StateValue", "StateValue"),
                    ("Threshold", "Threshold"),
                ),
            ),
        ),
        "eventbridge-rules": CliQuery(
            commands=(
                'for rule in $(aws events list-rules --query "Rules[].Name" --output text); do\n'
                '  aws events describe-rule --name "$rule"\n'
                '  aws events list-targets-by-rule --rule "$rule"\n'
                "done",
            ),
            output=OutputSpec(
                source="eventbridge-rules",
                rows="",
                columns=(("Name", "Name"), ("EventPattern", "EventPattern"), ("ScheduleExpression", "ScheduleExpression"), ("Targets", "Targets")),
            ),
        ),
        "sns-topics": CliQuery(
            commands=(
                'for topic in $(aws sns list-topics --query "Topics[].TopicArn" --output text); do\n'
                '  aws sns get-topic-attributes --topic-arn "$topic"\n'
                '  aws sns list-subscriptions-by-topic --topic-arn "$topic"\n'
                "done",
            ),
            output=OutputSpec(
                source="sns-topics",
                rows="",
                columns=(("TopicArn", "TopicArn"), ("Policy", "Policy"), ("Subscriptions", "Subscriptions")),
            ),
        ),
        "vpc-flow-logs": CliQuery(
            commands=("aws ec2 describe-flow-logs",),
            output=OutputSpec(
                source="vpc-flow-logs",
                rows="",
                columns=(("FlowLogId", "FlowLogId"), ("ResourceId", "ResourceId"), ("FlowLogStatus", "FlowLogStatus")),
            ),
        ),
        "config-rules": CliQuery(
            commands=("aws configservice describe-config-rules",),
            output=OutputSpec(
                source="config-rules",
                rows="",
                columns=(("ConfigRuleName", "ConfigRuleName"), ("Source", "Source"), ("Scope", "Scope")),
            ),
        ),
    }
}

_CHECK_STEMS = {
    "ALRT-001": "cloudtrail-trails",
    "ALRT-002": "eventbridge-rules",
    "ALRT-003": "cloudwatch-metric-filters",
    "ALRT-004": "eventbridge-rules",
    "ALRT-005": "sns-topics",
    "ALRT-006": "sns-topics",
    "ALRT-007": "eventbridge-rules",
    "ALRT-008": "cloudtrail-trails",
    "ALRT-009": "cloudwatch-log-groups",
    "ALRT-010": "cloudwatch-alarms",
    "ALRT-011": "sns-topics",
    "ALRT-012": "eventbridge-rules",
    "ALRT-013": "cloudtrail-trails",
    "ALRT-014": "cloudtrail-trails",
    "ALRT-015": "eventbridge-rules",
    "ALRT-016": "eventbridge-rules",
    "ALRT-017": "cloudwatch-log-groups",
    "ALRT-018": "cloudwatch-alarms",
    "ALRT-019": "eventbridge-rules",
    "ALRT-020": "sns-topics",
    "ALRT-021": "sns-topics",
    "ALRT-022": "sns-topics",
    "ALRT-023": "sns-topics",
    "ALRT-024": "sns-topics",
    "ALRT-025": "eventbridge-rules",
    "ALRT-026": "cloudtrail-s3-notifications",
    "ALRT-027": "cloudtrail-log-subscriptions",
}

_DERIVED_NOTES = {
    "ALRT-007": "Drystone correlates CloudTrail critical event names with EventBridge rules and alarm targets.",
    "ALRT-012": "Drystone checks coverage by matching required CloudTrail event names to alerting rules.",
    "ALRT-015": "Drystone derives IAM-change alert coverage from rule event patterns and target bindings.",
    "ALRT-016": "Drystone derives security-group-change alert coverage from rule event patterns and target bindings.",
    "ALRT-019": "Drystone evaluates naming clarity from alerting resource names; this is governance metadata.",
    "ALRT-020": "Drystone evaluates governance tagging across alerting resources.",
    "ALRT-025": "Drystone correlates critical EventBridge rules with SNS targets to confirm alert delivery.",
    "ALRT-026": "Drystone correlates CloudTrail S3 buckets with bucket notification configuration.",
    "ALRT-027": "Drystone correlates CloudTrail log groups with subscription filter consumers.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["alerting"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
