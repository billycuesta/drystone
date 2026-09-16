"""Post-processor for alerting skill to add architecture diagram."""

import json
from typing import Any, Dict, List, Optional

from drystone.storage.session import AuditSession


class AlertingPostProcessor:
    """Post-processor for alerting skill to add architecture diagram.

    Analyzes alerting flow components from evidence files and generates
    an ASCII flow diagram showing CloudTrail → CloudWatch/EventBridge → SNS.
    Identifies gaps and adds architectural context to findings.
    """

    def __init__(self, session: AuditSession):
        """Initialize with audit session for evidence path access.

        Args:
            session: AuditSession instance to access evidence files
        """
        self.session = session
        self.evidence_path = session.get_evidence_path("alerting")

    def process(self, findings: Dict) -> Dict:
        """Add architecture diagram to findings.

        Args:
            findings: Raw findings dict from agent analysis

        Returns:
            Enhanced findings with "architecture" field containing:
            {
                "flow_diagram": str,  # ASCII art diagram
                "components_detected": Dict[str, bool],  # Component status
                "critical_gaps": List[str]  # List of critical gaps
            }
        """
        evidence = self._load_evidence()
        flow_analysis = self._analyze_flow(evidence)
        diagram = self._generate_diagram(flow_analysis)
        gaps = self._identify_critical_gaps(flow_analysis)

        findings["architecture"] = {
            "flow_diagram": diagram,
            "components_detected": flow_analysis,
            "critical_gaps": gaps,
        }

        return findings

    def _load_evidence(self) -> Dict[str, Any]:
        """Load all alerting evidence files from evidence/alerting/.

        Returns:
            Dictionary with evidence files as keys and parsed JSON as values.
            Returns empty dict if no evidence files found.
        """
        evidence = {}

        evidence_files = {
            "cloudtrail_trails": "cloudtrail-trails.json",
            "cloudwatch_alarms": "cloudwatch-alarms.json",
            "cloudwatch_log_groups": "cloudwatch-log-groups.json",
            "cloudwatch_metric_filters": "cloudwatch-metric-filters.json",
            "eventbridge_rules": "eventbridge-rules.json",
            "sns_topics": "sns-topics.json",
            "config_rules": "config-rules.json",
            "vpc_flow_logs": "vpc-flow-logs.json",
        }

        for key, filename in evidence_files.items():
            file_path = self.evidence_path / filename
            if file_path.exists():
                try:
                    with open(file_path) as f:
                        evidence[key] = json.load(f)
                except (json.JSONDecodeError, IOError):
                    evidence[key] = []

        return evidence

    def _analyze_flow(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze alerting flow components and their status.

        Returns:
            {
                "cloudtrail_enabled": bool,
                "cloudtrail_multi_region": bool,
                "cloudwatch_integration": bool,
                "eventbridge_rules_exist": bool,
                "metric_filters_exist": bool,
                "alarms_configured": bool,
                "sns_topics_exist": bool,
                "sns_has_subscribers": bool,
                "subscriptions_confirmed": bool
            }
        """
        analysis = {
            "region": "unknown",
            "account_id": "unknown",
            "cloudtrail_enabled": False,
            "cloudtrail_multi_region": False,
            "cloudwatch_integration": False,
            "eventbridge_rules_exist": False,
            "eventbridge_total_rules_exist": False,
            "metric_filters_exist": False,
            "alarms_configured": False,
            "sns_topics_exist": False,
            "sns_has_subscribers": False,
            "subscriptions_confirmed": False,
            "cloudtrail_names": [],
            "cloudtrail_s3_buckets": [],
            "cloudwatch_log_groups": [],
            "metric_filter_names": [],
            "alarm_names": [],
            "eventbridge_rule_names": [],
            "sns_topic_names": [],
            "subscription_protocols": [],
            "counts": {
                "trails": 0,
                "log_groups": 0,
                "metric_filters": 0,
                "alarms": 0,
                "eventbridge_rules": 0,
                "sns_topics": 0,
                "subscriptions": 0,
                "alert_topics": 0,
                "alert_topics_without_confirmed_subscribers": 0,
            },
            "alert_topic_arns": [],
            "alert_topic_names": [],
            "alert_topic_health": {},
            "alert_topics_without_confirmed_subscribers": [],
            "sns_delivery_status": "unknown",
        }

        # Check CloudTrail
        trails = evidence.get("cloudtrail_trails", [])
        if trails:
            analysis["counts"]["trails"] = len(trails)
            # Check if any trail is enabled and logging
            for trail in trails:
                name = trail.get("Name")
                if isinstance(name, str) and name:
                    analysis["cloudtrail_names"].append(name)
                bucket = trail.get("S3BucketName")
                if isinstance(bucket, str) and bucket:
                    analysis["cloudtrail_s3_buckets"].append(bucket)
                region = trail.get("HomeRegion")
                if analysis["region"] == "unknown" and isinstance(region, str) and region:
                    analysis["region"] = region
                self._maybe_set_account_id_from_arn(
                    analysis,
                    trail.get("CloudWatchLogsLogGroupArn")
                    or trail.get("CloudWatchLogsRoleArn")
                    or trail.get("KMSKeyId"),
                )
                status = trail.get("Status", {})
                if status.get("IsLogging"):
                    analysis["cloudtrail_enabled"] = True
                    if trail.get("IsMultiRegionTrail"):
                        analysis["cloudtrail_multi_region"] = True

        # Check CloudWatch Log Groups (integration with CloudTrail)
        log_groups = evidence.get("cloudwatch_log_groups", [])
        if log_groups:
            analysis["counts"]["log_groups"] = len(log_groups)
            # Look for CloudTrail-related log groups
            cloudtrail_logs = [
                lg for lg in log_groups if "cloudtrail" in lg.get("LogGroupName", "").lower()
            ]
            if cloudtrail_logs:
                analysis["cloudwatch_integration"] = True
                analysis["cloudwatch_log_groups"] = [
                    str(lg.get("LogGroupName"))
                    for lg in cloudtrail_logs
                    if isinstance(lg.get("LogGroupName"), str)
                ]

        # Check for metric filters using actual metric filters evidence
        metric_filters = evidence.get("cloudwatch_metric_filters", [])
        if metric_filters:
            analysis["metric_filters_exist"] = True
            analysis["counts"]["metric_filters"] = len(metric_filters)
            analysis["metric_filter_names"] = [
                str(f.get("filterName"))
                for f in metric_filters
                if isinstance(f, dict) and isinstance(f.get("filterName"), str)
            ]

        # Check CloudWatch Alarms
        alarms = evidence.get("cloudwatch_alarms", [])
        if alarms:
            analysis["counts"]["alarms"] = len(alarms)
            # Check for security-related alarms
            security_alarms = [
                a
                for a in alarms
                if any(
                    keyword in a.get("AlarmName", "").lower()
                    for keyword in [
                        "security",
                        "alert",
                        "unauthorized",
                        "root",
                        "privilege",
                    ]
                )
            ]
            analysis["alarms_configured"] = len(security_alarms) > 0
            analysis["alarm_names"] = [
                str(a.get("AlarmName"))
                for a in security_alarms
                if isinstance(a.get("AlarmName"), str)
            ]
            for alarm in alarms:
                for arn in alarm.get("AlarmActions", []) or []:
                    self._maybe_set_account_id_from_arn(analysis, arn)
                    if self._is_sns_arn(arn) and arn not in analysis["alert_topic_arns"]:
                        analysis["alert_topic_arns"].append(arn)

        # Check EventBridge Rules
        rules = evidence.get("eventbridge_rules", [])
        if rules:
            analysis["counts"]["eventbridge_rules"] = len(rules)
            analysis["eventbridge_total_rules_exist"] = True
            # Check for enabled security-related rules
            security_rules = [
                r
                for r in rules
                if r.get("State") == "ENABLED"
                and any(
                    keyword in r.get("Name", "").lower()
                    for keyword in ["security", "alert", "cloudtrail"]
                )
            ]
            analysis["eventbridge_rules_exist"] = len(security_rules) > 0
            analysis["eventbridge_rule_names"] = [
                str(r.get("Name"))
                for r in security_rules
                if isinstance(r.get("Name"), str)
            ]
            for rule in rules:
                for target in rule.get("Targets", []) or []:
                    if not isinstance(target, dict):
                        continue
                    arn = target.get("Arn")
                    self._maybe_set_account_id_from_arn(analysis, arn)
                    if self._is_sns_arn(arn) and arn not in analysis["alert_topic_arns"]:
                        analysis["alert_topic_arns"].append(arn)

        # Check SNS Topics
        topics = evidence.get("sns_topics", [])
        if topics:
            analysis["sns_topics_exist"] = True
            analysis["counts"]["sns_topics"] = len(topics)
            analysis["sns_topic_names"] = [
                str(t.get("TopicArn", "")).split(":")[-1]
                for t in topics
                if isinstance(t, dict) and isinstance(t.get("TopicArn"), str)
            ]

            topic_confirmed_status = {}
            for topic in topics:
                topic_arn = topic.get("TopicArn")
                self._maybe_set_account_id_from_arn(analysis, topic_arn)
                subscriptions = topic.get("Subscriptions", [])
                analysis["counts"]["subscriptions"] += len(subscriptions or [])
                if subscriptions:
                    analysis["sns_has_subscribers"] = True
                    for sub in subscriptions:
                        protocol = sub.get("Protocol")
                        if isinstance(protocol, str) and protocol:
                            analysis["subscription_protocols"].append(protocol)

                confirmed = self._topic_has_confirmed_subscription(topic)
                if isinstance(topic_arn, str) and topic_arn:
                    topic_confirmed_status[topic_arn] = confirmed

                if confirmed:
                    analysis["sns_has_subscribers"] = True
                    analysis["subscriptions_confirmed"] = True

            alert_topic_arns = analysis["alert_topic_arns"]
            if alert_topic_arns:
                missing_arns = [
                    arn for arn in alert_topic_arns if not topic_confirmed_status.get(arn, False)
                ]
                analysis["counts"]["alert_topics"] = len(alert_topic_arns)
                analysis["counts"]["alert_topics_without_confirmed_subscribers"] = len(missing_arns)
                analysis["alert_topic_names"] = [self._name_from_arn(arn) for arn in alert_topic_arns]
                analysis["alert_topic_health"] = {
                    self._name_from_arn(arn): bool(topic_confirmed_status.get(arn, False))
                    for arn in alert_topic_arns
                }
                analysis["alert_topics_without_confirmed_subscribers"] = [
                    self._name_from_arn(arn) for arn in missing_arns
                ]
                analysis["subscriptions_confirmed"] = len(missing_arns) == 0
                analysis["sns_has_subscribers"] = any(
                    topic_confirmed_status.get(arn, False) for arn in alert_topic_arns
                )
                analysis["sns_delivery_status"] = "ok" if not missing_arns else "warn"
            elif analysis["sns_topics_exist"]:
                analysis["sns_delivery_status"] = (
                    "ok" if analysis["subscriptions_confirmed"] else "bad"
                )

        return analysis

    def _is_sns_arn(self, arn: Any) -> bool:
        return isinstance(arn, str) and arn.startswith("arn:aws:sns:")

    def _name_from_arn(self, arn: str) -> str:
        return arn.split(":")[-1] if isinstance(arn, str) and ":" in arn else str(arn)

    def _topic_has_confirmed_subscription(self, topic: Dict[str, Any]) -> bool:
        attributes = topic.get("Attributes") or {}
        if isinstance(attributes, dict):
            try:
                if int(attributes.get("SubscriptionsConfirmed") or 0) > 0:
                    return True
            except (TypeError, ValueError):
                pass

        subscriptions = topic.get("Subscriptions", []) or []
        return any(
            isinstance(sub, dict)
            and sub.get("SubscriptionArn")
            and sub.get("SubscriptionArn") != "PendingConfirmation"
            for sub in subscriptions
        )

    def _maybe_set_account_id_from_arn(self, analysis: Dict[str, Any], arn: Optional[str]) -> None:
        if analysis.get("account_id") != "unknown" or not isinstance(arn, str):
            return
        parts = arn.split(":")
        if len(parts) > 4 and parts[4].isdigit():
            analysis["account_id"] = parts[4]

    def _generate_diagram(self, flow_analysis: Dict[str, bool]) -> str:
        """Generate ASCII flow diagram with status indicators.

        Uses:
        ✅ = Configured and working
        ⚠️ = Partially configured (needs review)
        ❌ = Missing or not configured

        Args:
            flow_analysis: Dictionary with component status

        Returns:
            ASCII diagram as string
        """

        # Helper function to get status symbol
        def status_icon(value: bool) -> str:
            return "✅" if value else "❌"

        def warn_icon(value: bool) -> str:
            return "⚠️" if value else "❌"

        def delivery_icon(status: str) -> str:
            if status == "ok":
                return "✅"
            if status == "warn":
                return "⚠️"
            return "❌"

        cloudtrail_status = status_icon(flow_analysis["cloudtrail_enabled"])
        cloudtrail_note = (
            "Multi-region trail: YES"
            if flow_analysis["cloudtrail_multi_region"]
            else "Multi-region trail: NO"
        )

        cloudwatch_status = status_icon(flow_analysis["cloudwatch_integration"])
        eventbridge_status = warn_icon(flow_analysis["eventbridge_rules_exist"])
        metric_status = status_icon(flow_analysis["metric_filters_exist"])
        alarm_status = status_icon(flow_analysis["alarms_configured"])
        sns_delivery_status = str(flow_analysis.get("sns_delivery_status") or "unknown")
        sns_status = status_icon(flow_analysis["sns_topics_exist"])
        subscriptions_status = delivery_icon(sns_delivery_status)
        if sns_delivery_status == "warn":
            subscription_note = "PARTIAL"
        else:
            subscription_note = str(flow_analysis.get("subscriptions_confirmed", False)).upper()
        alert_topics = flow_analysis.get("counts", {}).get("alert_topics", 0)
        missing_alert_topics = flow_analysis.get("counts", {}).get(
            "alert_topics_without_confirmed_subscribers", 0
        )
        sns_note = (
            f"Alert topics missing subs: {missing_alert_topics}/{alert_topics}"
            if alert_topics
            else f"Subscriptions: {str(flow_analysis.get('sns_has_subscribers', False)).upper()}"
        )

        diagram = f"""
┌─────────────────────────────────────────────────────────────────────┐
│               AWS SECURITY ALERTING FLOW ARCHITECTURE               │
└─────────────────────────────────────────────────────────────────────┘

              EVENT SOURCES
   ┌──────────────────────────────────────┐
   │   {cloudtrail_status} AWS CloudTrail                   │   {cloudtrail_note}
   │      (API calls, Console logins)     │
   └──────────────┬───────────────────────┘
                  │
                  ├─────────────┬────────────────────┐
                  │             │                    │
                  v             v                    v
        ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐
        │ {cloudwatch_status} CloudWatch │  │ {eventbridge_status} CT EventBr. │  │ {status_icon(True)} S3 Bucket    │
        │    Logs       │  │ Security Rules │  │   (Archive)     │
        └──────┬────────┘  └───────┬────────┘  └─────────────────┘
               │                   │
               v                   │
        ┌──────────────┐          │
        │ {metric_status} Metric     │          │
        │   Filters     │          │
        └──────┬────────┘          │
               │                   │
               v                   │
        ┌──────────────┐          │
        │ {alarm_status} CloudWatch │          │
        │    Alarms     │          │
        └──────┬────────┘          │
               │                   │
               └───────┬───────────┘
                       │
                       v
              ┌─────────────────┐
              │ {sns_status} SNS Topics    │  {sns_note}
              │  (Notifications) │
              └────────┬─────────┘
                       │
                       v
              ┌─────────────────┐
              │ {subscriptions_status} Subscriptions │  Confirmed: {subscription_note}
              │  (Email, HTTPS)  │
              └─────────────────┘
                       │
                       v
              [ Security Team ]

LEGEND:
  ✅ = Configured and working
  ⚠️ = Partially configured (needs review)
  ❌ = Missing or not configured
"""
        return diagram.strip()

    def _identify_critical_gaps(self, flow_analysis: Dict[str, bool]) -> List[str]:
        """Identify critical gaps in alerting architecture.

        Args:
            flow_analysis: Dictionary with component status

        Returns:
            List of critical gaps detected
        """
        gaps = []

        # Critical: No CloudTrail
        if not flow_analysis["cloudtrail_enabled"]:
            gaps.append("CloudTrail is not enabled or not logging events")

        # Critical: CloudTrail without CloudWatch integration
        if flow_analysis["cloudtrail_enabled"] and not flow_analysis["cloudwatch_integration"]:
            gaps.append("CloudTrail not integrated with CloudWatch Logs (events not monitored)")

        # Critical: CloudWatch without metric filters
        # Note: metric_filters_exist is always True if cloudwatch_integration is True
        # in our current logic, so this gap only triggers if CloudWatch exists but
        # we explicitly detect no metric filters (future enhancement)
        if flow_analysis["cloudwatch_integration"] and not flow_analysis["metric_filters_exist"]:
            gaps.append("No metric filters configured for security events")

        # Critical: No alarms
        if not flow_analysis["alarms_configured"]:
            gaps.append("No CloudWatch alarms configured for security events")

        # High: No SNS topics
        if not flow_analysis["sns_topics_exist"]:
            gaps.append("No SNS topics configured for alerting (notifications disabled)")

        # High: SNS without subscribers
        if flow_analysis["sns_topics_exist"] and not flow_analysis["sns_has_subscribers"]:
            gaps.append("SNS topics exist but have no active subscriptions")

        for topic_name in flow_analysis.get("alert_topics_without_confirmed_subscribers", []):
            gaps.append(
                f"SNS topic {topic_name} receives alert actions but has no confirmed subscriptions"
            )

        # High: SNS subscriptions not confirmed
        if (
            flow_analysis["sns_has_subscribers"]
            and not flow_analysis["subscriptions_confirmed"]
            and not flow_analysis.get("alert_topics_without_confirmed_subscribers")
        ):
            gaps.append("SNS subscriptions exist but are not confirmed (pending)")

        # Warning: Single-region CloudTrail
        if flow_analysis["cloudtrail_enabled"] and not flow_analysis["cloudtrail_multi_region"]:
            gaps.append("CloudTrail is single-region only (multi-region recommended)")

        # Warning: CloudTrail security EventBridge routing not configured
        if not flow_analysis["eventbridge_rules_exist"]:
            gaps.append(
                "No custom EventBridge rules route CloudTrail security events "
                "(alternative alerting path unused)"
            )

        return gaps
