# ruff: noqa
"""Alerting deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# ALERTING PRE-CHECKS
# ============================================================================


@_register("alerting")
def check_alr_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudTrail should have CloudWatch Logs integration."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or len(trails) == 0:
        return PreCheckResult("ALRT-001", "SKIP", "no trails (ALR-001 applies)", [])

    for trail in trails:
        if isinstance(trail, dict) and trail.get("CloudWatchLogsLogGroupArn"):
            return PreCheckResult("ALRT-001", "PASS", "LogGroupArn present", [])
    return PreCheckResult("ALRT-001", "FAIL", "no trail with CloudWatch Logs", [])


def _alerting_critical_topic_arns(evidence: Dict[str, Any]) -> List[str]:
    arns: List[str] = []
    alarms = evidence.get("cloudwatch-alarms")
    if isinstance(alarms, list):
        for a in alarms:
            if not isinstance(a, dict):
                continue
            for act in a.get("AlarmActions", []) or []:
                if isinstance(act, str) and act.startswith("arn:aws:sns:"):
                    arns.append(act)

    rules = evidence.get("eventbridge-rules")
    if isinstance(rules, list):
        for r in rules:
            if not isinstance(r, dict):
                continue
            for t in r.get("Targets", []) or []:
                if isinstance(t, dict):
                    arn = t.get("Arn")
                    if isinstance(arn, str) and arn.startswith("arn:aws:sns:"):
                        arns.append(arn)
    return list(dict.fromkeys(arns))


def _parse_policy_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and any(x == "*" for x in aws):
            return True
    return False


@_register("alerting")
def check_alr_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should not allow broad publish access."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-022", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:publish", "sns:*", "*"} for a in actions_list):
                continue
            if _principal_is_wildcard_any(
                st.get("Principal")
            ) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "ALRT-022", "FAIL", "alert SNS topic allows broad Publish", [arn]
                )

    return PreCheckResult(
        "ALRT-022", "PASS", "no broad publish permissions on alert SNS topics", []
    )


@_register("alerting")
def check_alr_023(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should not allow broad subscribe access."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-023", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:subscribe", "sns:*", "*"} for a in actions_list):
                continue
            if _principal_is_wildcard(
                st.get("Principal")
            ) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "ALRT-023", "FAIL", "alert SNS topic allows broad Subscribe", [arn]
                )

    return PreCheckResult(
        "ALRT-023", "PASS", "no broad subscribe permissions on alert SNS topics", []
    )


@_register("alerting")
def check_alr_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should avoid risky HTTP/HTTPS subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-024", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    risky = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        subs = t.get("Subscriptions") if isinstance(t.get("Subscriptions"), list) else []
        for s in subs:
            if not isinstance(s, dict):
                continue
            protocol = str(s.get("Protocol") or "").lower()
            if protocol in {"http", "https"}:
                risky.append(arn)
                break

    if not risky:
        return PreCheckResult(
            "ALRT-024", "PASS", "no risky HTTP/HTTPS subscriptions on alert topics", []
        )
    return PreCheckResult(
        "ALRT-024",
        "FAIL",
        f"{len(risky)} alert SNS topics with HTTP/HTTPS subscriptions",
        risky[:10],
    )


@_register("alerting")
def check_alr_025(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical EventBridge rules should forward to SNS alerting topics."""
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list) or not rules:
        return PreCheckResult("ALRT-025", "SKIP", "no eventbridge-rules evidence", [])

    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        # Skip AWS-managed service rules (e.g. Amazon Inspector managed rules)
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        is_security_rule = (
            "cloudtrail" in pattern or "consolelogin" in pattern or "stoplogging" in pattern
        )
        if not is_security_rule:
            continue
        targets = r.get("Targets") if isinstance(r.get("Targets"), list) else []
        has_sns = any(
            isinstance(t, dict) and str(t.get("Arn") or "").startswith("arn:aws:sns:")
            for t in targets
        )
        if not has_sns:
            return PreCheckResult(
                "ALRT-025",
                "FAIL",
                "security EventBridge rule without SNS target",
                [str(r.get("Arn") or r.get("Name") or "unknown")],
            )

    return PreCheckResult(
        "ALRT-025", "PASS", "critical security EventBridge rules route to SNS", []
    )


@_register("alerting")
def check_alrt_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-005: Critical alert SNS topics should have confirmed subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-005", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    no_subs = []

    # Build map: SNS topic ARN → list of alarm names that publish to it
    alarm_map: Dict[str, List[str]] = {}
    alarms = evidence.get("cloudwatch-alarms")
    if isinstance(alarms, list):
        for alarm in alarms:
            if not isinstance(alarm, dict):
                continue
            alarm_name = str(alarm.get("AlarmName") or "")
            for action_arn in alarm.get("AlarmActions") or []:
                action_arn = str(action_arn)
                if action_arn not in alarm_map:
                    alarm_map[action_arn] = []
                if alarm_name:
                    alarm_map[action_arn].append(alarm_name)

    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        confirmed = int(attrs.get("SubscriptionsConfirmed", 0) or 0)
        if confirmed == 0:
            no_subs.append(arn)

    if no_subs:
        affected_alarms = []
        resource_details: list = []
        for topic_arn in no_subs:
            alarm_names = alarm_map.get(topic_arn, [])
            affected_alarms.extend(alarm_names)
            resource_details.append(
                {
                    "topic_arn": topic_arn,
                    "affected_alarms": alarm_names,
                    "alarm_count": len(alarm_names),
                    "evidence_ref": f"sns-topics.json#TopicArn.{topic_arn}",
                }
            )

        resources = no_subs[:10]
        summary = (
            f"{len(no_subs)} alert SNS topic(s) have no confirmed subscriptions "
            f"({len(affected_alarms)} alarm(s) publish to them)"
            if affected_alarms
            else f"{len(no_subs)} alert SNS topic(s) have no confirmed subscriptions"
        )
        result = PreCheckResult("ALRT-005", "FAIL", summary, resources)
        result.metadata["resource_details"] = resource_details
        return result

    return PreCheckResult("ALRT-005", "PASS", "alert SNS topics have confirmed subscriptions", [])


@_register("alerting")
def check_alrt_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-006: Critical alert SNS topics should not have pending subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-006", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    pending_topics = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pending = int(attrs.get("SubscriptionsPending", 0) or 0)
        if pending > 0:
            pending_topics.append(arn)

    if pending_topics:
        return PreCheckResult(
            "ALRT-006",
            "FAIL",
            f"{len(pending_topics)} alert SNS topic(s) with pending subscriptions",
            pending_topics[:5],
        )
    return PreCheckResult("ALRT-006", "PASS", "no pending subscriptions on alert SNS topics", [])


@_register("alerting")
def check_alrt_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-008: At least one CloudTrail trail should be multi-region."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-008", "SKIP", "no cloudtrail-trails evidence", [])

    for trail in trails:
        if isinstance(trail, dict) and trail.get("IsMultiRegionTrail"):
            return PreCheckResult("ALRT-008", "PASS", "multi-region trail present", [])

    single_region_names = [str(t.get("Name") or "") for t in trails if isinstance(t, dict)]
    return PreCheckResult(
        "ALRT-008",
        "FAIL",
        "no multi-region trail configured",
        single_region_names[:5],
    )


@_register("alerting")
def check_alrt_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-013: CloudTrail trails should have log file validation enabled."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-013", "SKIP", "no cloudtrail-trails evidence", [])

    # Only check trails we own (not org trails from other accounts)
    invalid = []
    has_checkable_trail = False
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip org trails where we can't verify status (Status is empty dict)
        if trail.get("IsOrganizationTrail") and not trail.get("Status", {}).get("IsLogging"):
            continue
        has_checkable_trail = True
        if not trail.get("LogFileValidationEnabled"):
            invalid.append(str(trail.get("Name") or "unknown"))

    if not has_checkable_trail:
        return PreCheckResult("ALRT-013", "SKIP", "no locally-owned trails to check", [])
    if invalid:
        return PreCheckResult(
            "ALRT-013",
            "FAIL",
            f"{len(invalid)} trail(s) without log file validation",
            invalid[:5],
        )
    return PreCheckResult("ALRT-013", "PASS", "all trails have log file validation enabled", [])


@_register("alerting")
def check_alrt_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-014: CloudTrail trails should encrypt logs with KMS."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-014", "SKIP", "no cloudtrail-trails evidence", [])

    no_kms = []
    has_checkable_trail = False
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip org trails we don't own
        if trail.get("IsOrganizationTrail") and not trail.get("Status", {}).get("IsLogging"):
            continue
        has_checkable_trail = True
        if not trail.get("KMSKeyId"):
            no_kms.append(str(trail.get("Name") or "unknown"))

    if not has_checkable_trail:
        return PreCheckResult("ALRT-014", "SKIP", "no locally-owned trails to check", [])
    if no_kms:
        return PreCheckResult(
            "ALRT-014",
            "FAIL",
            f"{len(no_kms)} trail(s) without KMS encryption",
            no_kms[:5],
        )
    return PreCheckResult("ALRT-014", "PASS", "all trails encrypted with KMS", [])


@_register("alerting")
def check_alrt_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-002: CloudTrail should be integrated with EventBridge (active security rules).

    PASS if EventBridge rules consume CloudTrail events.
    PASS (alternative path) if CloudTrail -> CloudWatch Logs + metric filters provide equivalent
    alerting coverage (at least 3 security-relevant metric filters on the CT log group).
    FAIL otherwise — no alerting path configured.
    """
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list):
        return PreCheckResult("ALRT-002", "SKIP", "no eventbridge-rules evidence", [])

    # --- Primary path: EventBridge rules consuming CloudTrail ---
    cloudtrail_rules: List[str] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        # Skip AWS-managed service rules (e.g. Inspector managed rules)
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        # Must be ENABLED
        if str(r.get("State") or "").upper() != "ENABLED":
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        if "aws.cloudtrail" in pattern or '"cloudtrail"' in pattern:
            cloudtrail_rules.append(name)

    if cloudtrail_rules:
        return PreCheckResult(
            "ALRT-002",
            "PASS",
            f"{len(cloudtrail_rules)} enabled EventBridge rule(s) processing CloudTrail events",
            [],
        )

    # --- Alternative path: CloudTrail -> CloudWatch Logs + Metric Filters ---
    # If CloudTrail delivers to a CW Logs log group AND that group has security metric filters,
    # alerting coverage is equivalent; EventBridge integration is still a best-practice improvement
    # but NOT a critical gap. Downgrade to informational FAIL instead of blocking Critical.
    trails = evidence.get("cloudtrail-trails") or []
    metric_filters = evidence.get("cloudwatch-metric-filters") or []

    ct_log_groups: set = set()
    for t in trails:
        if not isinstance(t, dict):
            continue
        lg_arn = t.get("CloudWatchLogsLogGroupArn") or ""
        if lg_arn:
            # extract log group name from ARN
            parts = lg_arn.split(":log-group:")
            if len(parts) == 2:
                ct_log_groups.add(parts[1].rstrip(":*"))

    if ct_log_groups and isinstance(metric_filters, list):
        ct_metric_filters = [
            mf
            for mf in metric_filters
            if isinstance(mf, dict) and mf.get("logGroupName") in ct_log_groups
        ]
        if len(ct_metric_filters) >= 3:
            result = PreCheckResult(
                "ALRT-002",
                "FAIL",
                (
                    f"no EventBridge rules for CloudTrail, but {len(ct_metric_filters)} "
                    f"CloudWatch metric filter(s) provide alternative coverage — "
                    f"EventBridge integration is a best-practice improvement (Medium risk)"
                ),
                ["CloudTrail EventBridge security routing"],
            )
            result.metadata["resource_details"] = [
                {
                    "resource": "CloudTrail EventBridge security routing",
                    "cloudtrail_log_groups": sorted(ct_log_groups),
                    "metric_filter_count": len(ct_metric_filters),
                    "evidence_refs": ["eventbridge-rules.json", "cloudwatch-metric-filters.json"],
                }
            ]
            return result

    result = PreCheckResult(
        "ALRT-002",
        "FAIL",
        "no enabled EventBridge rules processing CloudTrail events and no CloudWatch metric filter coverage",
        ["CloudTrail EventBridge security routing"],
    )
    result.metadata["resource_details"] = [
        {
            "resource": "CloudTrail EventBridge security routing",
            "evidence_refs": ["eventbridge-rules.json", "cloudwatch-metric-filters.json"],
        }
    ]
    return result


@_register("alerting")
def check_alrt_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-003: Metric filters should have associated CloudWatch alarms."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-003", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = evidence collected but zero filters exist → no alarms possible → FAIL
    if not metric_filters:
        return PreCheckResult(
            "ALRT-003",
            "FAIL",
            "no metric filters configured (zero filters means no alarm coverage possible)",
            [],
        )

    alarms = evidence.get("cloudwatch-alarms")
    if not isinstance(alarms, list):
        alarms = []

    # Build set of metric names that have at least one alarm
    alarm_metric_names = {
        str(a.get("MetricName") or "")
        for a in alarms
        if isinstance(a, dict) and a.get("MetricName")
    }

    filters_without_alarm: List[str] = []
    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        for mt in mf.get("metricTransformations") or []:
            if not isinstance(mt, dict):
                continue
            metric_name = str(mt.get("metricName") or "")
            if metric_name and metric_name not in alarm_metric_names:
                filters_without_alarm.append(str(mf.get("filterName") or "unknown"))
                break

    if filters_without_alarm:
        return PreCheckResult(
            "ALRT-003",
            "FAIL",
            f"{len(filters_without_alarm)} metric filter(s) without associated CloudWatch alarm",
            filters_without_alarm[:10],
        )
    return PreCheckResult(
        "ALRT-003", "PASS", "all metric filters have associated CloudWatch alarms", []
    )


@_register("alerting")
def check_alrt_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-004: Security EventBridge rules should have SNS notification targets."""
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list):
        return PreCheckResult("ALRT-004", "SKIP", "no eventbridge-rules evidence", [])

    security_rules_without_sns: List[str] = []
    has_security_rules = False
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        if str(r.get("State") or "").upper() != "ENABLED":
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        if not ("aws.cloudtrail" in pattern or "cloudtrail" in pattern):
            continue
        has_security_rules = True
        targets = r.get("Targets") if isinstance(r.get("Targets"), list) else []
        has_sns = any(
            isinstance(t, dict) and str(t.get("Arn") or "").startswith("arn:aws:sns:")
            for t in targets
        )
        if not has_sns:
            security_rules_without_sns.append(name)

    if not has_security_rules:
        return PreCheckResult(
            "ALRT-004", "SKIP", "no security-relevant EventBridge rules found", []
        )
    if security_rules_without_sns:
        return PreCheckResult(
            "ALRT-004",
            "FAIL",
            f"{len(security_rules_without_sns)} security EventBridge rule(s) without SNS target",
            security_rules_without_sns[:5],
        )
    return PreCheckResult("ALRT-004", "PASS", "all security EventBridge rules have SNS targets", [])


@_register("alerting")
def check_alrt_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-007: Critical security events should be covered by metric filters."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-007", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = ALL critical events uncovered → FAIL

    # Critical events that must be covered by at least one metric filter
    critical_events = {
        "StopLogging": False,
        "DeleteTrail": False,
        "CreateUser": False,
        "ConsoleLogin": False,
    }

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        for event in list(critical_events.keys()):
            if event.lower() in pattern:
                critical_events[event] = True

    missing = [e for e, covered in critical_events.items() if not covered]
    if missing:
        risk_override = 4.5 if len(missing) == 1 else None
        result = PreCheckResult(
            "ALRT-007",
            "FAIL",
            f"critical events not covered by metric filters: {', '.join(missing)}",
            missing,
            risk_score_override=risk_override,
        )
        result.metadata["resource_details"] = [
            {
                "event_name": event,
                "evidence_ref": "cloudwatch-metric-filters.json",
            }
            for event in missing
        ]
        result.metadata["missing_events"] = missing
        return result
    return PreCheckResult(
        "ALRT-007", "PASS", "all critical security events covered by metric filters", []
    )


@_register("alerting")
def check_alrt_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-009: CloudTrail log group should have metric filters for security events."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-009", "SKIP", "no cloudtrail-trails evidence", [])

    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-009", "SKIP", "no cloudwatch-metric-filters evidence", [])

    # Find the local (non-org) CloudTrail-integrated log group name from the trail's ARN.
    # Org trails belong to a management account and cannot have metric filters added
    # from this account — always prefer non-org trails.
    ct_log_group: str = ""
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip organization trails — they're owned by a parent account
        if trail.get("IsOrganizationTrail"):
            continue
        if trail.get("CloudWatchLogsLogGroupArn"):
            arn = str(trail["CloudWatchLogsLogGroupArn"])
            # ARN format: arn:aws:logs:region:account:log-group:NAME:*
            parts = arn.split(":")
            if len(parts) >= 7:
                ct_log_group = parts[6]
                break

    if not ct_log_group:
        return PreCheckResult("ALRT-009", "SKIP", "no CloudTrail log group configured", [])

    filters_for_ct = [
        mf
        for mf in metric_filters
        if isinstance(mf, dict) and mf.get("logGroupName") == ct_log_group
    ]

    if filters_for_ct:
        return PreCheckResult(
            "ALRT-009",
            "PASS",
            f"{len(filters_for_ct)} metric filter(s) on CloudTrail log group '{ct_log_group}'",
            [],
        )
    return PreCheckResult(
        "ALRT-009",
        "FAIL",
        f"no metric filters on CloudTrail log group '{ct_log_group}'",
        [ct_log_group],
    )


@_register("alerting")
def check_alrt_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-017: CloudWatch log groups should have adequate retention (>=90 days)."""
    log_groups = evidence.get("cloudwatch-log-groups")
    if not isinstance(log_groups, list) or not log_groups:
        return PreCheckResult("ALRT-017", "SKIP", "no cloudwatch-log-groups evidence", [])

    short_retention: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for lg in log_groups:
        if not isinstance(lg, dict):
            continue
        retention = lg.get("RetentionInDays")
        # None means "never expire" — acceptable
        if retention is not None and int(retention) < 90:
            name = str(lg.get("LogGroupName") or "unknown")
            short_retention.append(name)
            resource_details.append(
                {
                    "log_group_name": name,
                    "retention_in_days": int(retention),
                    "evidence_ref": f"cloudwatch-log-groups.json#LogGroupName.{name}",
                }
            )

    if short_retention:
        result = PreCheckResult(
            "ALRT-017",
            "FAIL",
            f"{len(short_retention)} log group(s) with retention < 90 days",
            short_retention[:15],
        )
        result.metadata["resource_details"] = resource_details
        return result
    return PreCheckResult(
        "ALRT-017", "PASS", "all log groups have retention >= 90 days or unlimited", []
    )


@_register("alerting")
def check_alrt_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-010: CloudWatch alarms should not be in INSUFFICIENT_DATA state."""
    alarms = evidence.get("cloudwatch-alarms")
    if not isinstance(alarms, list) or not alarms:
        return PreCheckResult("ALRT-010", "SKIP", "no cloudwatch-alarms evidence", [])

    # Only check alarms that have a StateValue (collector must include it)
    alarms_with_state = [a for a in alarms if isinstance(a, dict) and a.get("StateValue")]
    if not alarms_with_state:
        return PreCheckResult(
            "ALRT-010", "SKIP", "no StateValue data in alarms (collector may not collect it)", []
        )

    insufficient: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for alarm in alarms_with_state:
        if str(alarm.get("StateValue") or "").upper() != "INSUFFICIENT_DATA":
            continue
        name = str(alarm.get("AlarmName") or "unknown")
        insufficient.append(name)
        resource_details.append(
            {
                "alarm_name": name,
                "state": alarm.get("StateValue"),
                "metric_name": alarm.get("MetricName"),
                "namespace": alarm.get("Namespace"),
                "alarm_actions": alarm.get("AlarmActions") or [],
                "evidence_ref": f"cloudwatch-alarms.json#AlarmName.{name}",
            }
        )

    if insufficient:
        operational_only = all(
            str(detail.get("namespace") or "") not in {"CustomAlerts", "LogMetrics"}
            for detail in resource_details
        )
        result = PreCheckResult(
            "ALRT-010",
            "FAIL",
            f"{len(insufficient)} alarm(s) in INSUFFICIENT_DATA state",
            insufficient[:10],
            risk_score_override=4.5 if operational_only else None,
        )
        result.metadata["resource_details"] = resource_details
        if operational_only:
            result.metadata["severity_rationale"] = (
                "Affected alarms monitor service-health namespaces rather than custom "
                "CloudTrail security metric filters; treat as an operational monitoring gap."
            )
        return result
    return PreCheckResult("ALRT-010", "PASS", "no alarms in INSUFFICIENT_DATA state", [])


@_register("alerting")
def check_alrt_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-011: Alert SNS topics should restrict Publish to authorized principals."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-011", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    if not critical:
        return PreCheckResult(
            "ALRT-011", "SKIP", "no alert SNS topics found (no alarm/EB actions)", []
        )

    # Authorized publishers: CloudWatch Alarms and EventBridge services
    _authorized_service_principals = {
        "cloudwatch.amazonaws.com",
        "events.amazonaws.com",
        "lambda.amazonaws.com",
    }

    broad_topics: List[str] = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:publish", "sns:*", "*"} for a in actions_list):
                continue
            principal = st.get("Principal")
            # PASS: service principal (e.g. cloudwatch.amazonaws.com)
            if isinstance(principal, dict):
                service = principal.get("Service")
                services = (
                    [service]
                    if isinstance(service, str)
                    else (service if isinstance(service, list) else [])
                )
                if all(str(s) in _authorized_service_principals for s in services if s):
                    continue
            # PASS: same-account restriction (Principal:* + SourceOwner condition) is
            # the AWS default policy. We only flag it if there is NO condition at all
            # or the condition does not restrict to same account.
            if _principal_is_wildcard_any(principal):
                if not _stmt_has_same_account_restriction(st):
                    broad_topics.append(arn)
                    break
                # Has same-account condition but still allows any IAM principal to Publish.
                # This is the AWS default policy — flag as informational (PASS here, LLM catches nuance)
                # We don't fail here because AWS auto-creates this policy for every new topic.

    if broad_topics:
        return PreCheckResult(
            "ALRT-011",
            "FAIL",
            f"{len(broad_topics)} alert topic(s) allow broad Publish without account restriction",
            broad_topics[:5],
        )
    return PreCheckResult(
        "ALRT-011", "PASS", "alert topics restrict Publish to authorized principals", []
    )


@_register("alerting")
def check_alrt_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-015: A metric filter should cover IAM change events."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-015", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = IAM events not monitored

    _iam_events = [
        "putuseropolicy",
        "attachuserpolicy",
        "attachgrouppolicy",
        "putgrouppolicy",
        "putrolepolicy",
        "attachrolepolicy",
        "createaccesskey",
        "putuserpolicy",  # alternate casing
    ]

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        if any(event in pattern for event in _iam_events):
            return PreCheckResult("ALRT-015", "PASS", "metric filter covers IAM change events", [])

    return PreCheckResult(
        "ALRT-015",
        "FAIL",
        "no metric filter covering IAM change events (PutUserPolicy, AttachUserPolicy, etc.)",
        [],
    )


@_register("alerting")
def check_alrt_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-016: A metric filter should cover Security Group change events."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-016", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = SG events not monitored

    _sg_events = [
        "authorizesecuritygroupingress",
        "authorizesecuritygroupegress",
        "revokesecuritygroupingress",
        "revokesecuritygroupegress",
        "createsecuritygroup",
        "deletesecuritygroup",
    ]

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        if any(event in pattern for event in _sg_events):
            return PreCheckResult(
                "ALRT-016", "PASS", "metric filter covers Security Group change events", []
            )

    return PreCheckResult(
        "ALRT-016",
        "FAIL",
        "no metric filter covering Security Group change events (AuthorizeSecurityGroupIngress, etc.)",
        [],
    )


@_register("alerting")
def check_alrt_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-012: Critical security events (ConsoleLogin, CreateUser, StopLogging) should be alerted via metric filter or EventBridge rule."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    rules = evidence.get("eventbridge-rules")

    # Need at least one evidence source to evaluate
    if not isinstance(metric_filters, list) and not isinstance(rules, list):
        return PreCheckResult("ALRT-012", "SKIP", "no metric-filter or eventbridge evidence", [])

    _critical_events = ["consolelogin", "createuser", "stoplogging"]

    # Check metric filters for coverage
    if isinstance(metric_filters, list):
        for mf in metric_filters:
            if not isinstance(mf, dict):
                continue
            pattern = str(mf.get("filterPattern") or "").lower()
            if any(evt in pattern for evt in _critical_events):
                return PreCheckResult(
                    "ALRT-012",
                    "PASS",
                    "metric filter covers critical security events (ConsoleLogin/CreateUser/StopLogging)",
                    [],
                )

    # Check EventBridge rules for security event coverage
    if isinstance(rules, list):
        for r in rules:
            if not isinstance(r, dict):
                continue
            name = str(r.get("Name") or "")
            if name.startswith("DO-NOT-DELETE-Amazon"):
                continue
            if str(r.get("State") or "").upper() != "ENABLED":
                continue
            pattern = str(r.get("EventPattern") or "").lower()
            if any(evt in pattern for evt in _critical_events):
                return PreCheckResult(
                    "ALRT-012",
                    "PASS",
                    "EventBridge rule covers critical security events (ConsoleLogin/CreateUser/StopLogging)",
                    [],
                )

    return PreCheckResult(
        "ALRT-012",
        "FAIL",
        "no alert configured for critical events: ConsoleLogin, CreateUser, StopLogging",
        [],
    )


@_register("alerting")
def check_alrt_026(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-026: CloudTrail S3 bucket exposes downstream attack surface via event notifications."""
    notifications = evidence.get("cloudtrail-s3-notifications")
    if not isinstance(notifications, list) or not notifications:
        return PreCheckResult("ALRT-026", "SKIP", "no cloudtrail-s3-notifications evidence", [])

    # Filter out entries with errors (cross-account or permission-denied buckets)
    valid = [n for n in notifications if isinstance(n, dict) and "error" not in n]
    if not valid:
        return PreCheckResult("ALRT-026", "SKIP", "cloudtrail S3 buckets not accessible", [])

    downstream_services = []
    for entry in valid:
        bucket_name = entry.get("bucket_name", "unknown")
        for cfg in entry.get("lambda_configs", []) or []:
            arn = cfg.get("LambdaFunctionArn", "")
            if arn:
                fn_name = arn.split(":")[-1]
                downstream_services.append(f"Lambda:{fn_name}")
        for cfg in entry.get("sqs_configs", []) or []:
            arn = cfg.get("QueueArn", "")
            if arn:
                queue_name = arn.split(":")[-1]
                downstream_services.append(f"SQS:{queue_name}")
        for cfg in entry.get("sns_configs", []) or []:
            arn = cfg.get("TopicArn", "")
            if arn:
                topic_name = arn.split(":")[-1]
                downstream_services.append(f"SNS:{topic_name}")

    if not downstream_services:
        return PreCheckResult(
            "ALRT-026",
            "PASS",
            "CloudTrail S3 bucket has no downstream event notification services",
            [],
        )

    bucket_name = valid[0].get("bucket_name", "unknown") if valid else "unknown"
    summary = (
        f"CloudTrail S3 bucket '{bucket_name}' has {len(downstream_services)} downstream "
        f"service(s): [{', '.join(downstream_services[:5])}]"
    )
    return PreCheckResult("ALRT-026", "FAIL", summary, downstream_services[:10])


@_register("alerting")
def check_alrt_027(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-027: CloudTrail CloudWatch log group has downstream subscription filter consumers."""
    subscriptions = evidence.get("cloudtrail-log-subscriptions")
    if not isinstance(subscriptions, list) or not subscriptions:
        return PreCheckResult("ALRT-027", "SKIP", "no cloudtrail-log-subscriptions evidence", [])

    # Filter out error entries
    valid = [s for s in subscriptions if isinstance(s, dict) and "error" not in s]
    if not valid:
        return PreCheckResult("ALRT-027", "SKIP", "cloudtrail log groups not accessible", [])

    filters_found = []
    for entry in valid:
        log_group_name = entry.get("log_group_name", "unknown")
        for sf in entry.get("subscription_filters", []) or []:
            dest = sf.get("destinationArn", "")
            filter_name = sf.get("filterName", "unknown")
            if dest:
                # Detect destination type
                if ":lambda:" in dest:
                    dest_label = f"Lambda:{dest.split(':')[-1]}"
                elif ":kinesis:" in dest:
                    dest_label = f"Kinesis:{dest.split('/')[-1]}"
                elif ":firehose:" in dest:
                    dest_label = f"Firehose:{dest.split('/')[-1]}"
                elif ":logs:" in dest:
                    dest_label = f"Logs:{dest.split(':')[-1]}"
                else:
                    dest_label = dest
                filters_found.append(f"{filter_name}→{dest_label}")

    if not filters_found:
        return PreCheckResult(
            "ALRT-027",
            "PASS",
            "CloudTrail log group has no downstream subscription consumers",
            [],
        )

    log_group_name = valid[0].get("log_group_name", "unknown") if valid else "unknown"
    summary = (
        f"CloudTrail log group '{log_group_name}' has {len(filters_found)} subscription "
        f"filter(s): [{', '.join(filters_found[:5])}]"
    )
    return PreCheckResult("ALRT-027", "FAIL", summary, filters_found[:10])


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
