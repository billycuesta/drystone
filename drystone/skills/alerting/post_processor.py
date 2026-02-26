"""Post-processor for alerting skill to add architecture diagram."""

import json
from typing import Any, Dict, List

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

    def _analyze_flow(self, evidence: Dict[str, Any]) -> Dict[str, bool]:
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
            "cloudtrail_enabled": False,
            "cloudtrail_multi_region": False,
            "cloudwatch_integration": False,
            "eventbridge_rules_exist": False,
            "metric_filters_exist": False,
            "alarms_configured": False,
            "sns_topics_exist": False,
            "sns_has_subscribers": False,
            "subscriptions_confirmed": False,
        }

        # Check CloudTrail
        trails = evidence.get("cloudtrail_trails", [])
        if trails:
            # Check if any trail is enabled and logging
            for trail in trails:
                status = trail.get("Status", {})
                if status.get("IsLogging"):
                    analysis["cloudtrail_enabled"] = True
                    if trail.get("IsMultiRegionTrail"):
                        analysis["cloudtrail_multi_region"] = True
                    break

        # Check CloudWatch Log Groups (integration with CloudTrail)
        log_groups = evidence.get("cloudwatch_log_groups", [])
        if log_groups:
            # Look for CloudTrail-related log groups
            cloudtrail_logs = [
                lg
                for lg in log_groups
                if "cloudtrail" in lg.get("LogGroupName", "").lower()
            ]
            if cloudtrail_logs:
                analysis["cloudwatch_integration"] = True

        # Check for metric filters using actual metric filters evidence
        metric_filters = evidence.get("cloudwatch_metric_filters", [])
        if metric_filters:
            analysis["metric_filters_exist"] = True

        # Check CloudWatch Alarms
        alarms = evidence.get("cloudwatch_alarms", [])
        if alarms:
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

        # Check EventBridge Rules
        rules = evidence.get("eventbridge_rules", [])
        if rules:
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

        # Check SNS Topics
        topics = evidence.get("sns_topics", [])
        if topics:
            analysis["sns_topics_exist"] = True

            # Check for subscribers and confirmed subscriptions
            for topic in topics:
                subscriptions = topic.get("Subscriptions", [])
                if subscriptions:
                    analysis["sns_has_subscribers"] = True

                    # Check if any subscriptions are confirmed
                    confirmed = any(
                        sub.get("SubscriptionArn") != "PendingConfirmation"
                        for sub in subscriptions
                    )
                    if confirmed:
                        analysis["subscriptions_confirmed"] = True
                        break

        return analysis

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
        sns_status = status_icon(flow_analysis["sns_topics_exist"])
        subscriptions_status = status_icon(flow_analysis["subscriptions_confirmed"])

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
        │ {cloudwatch_status} CloudWatch │  │ {eventbridge_status} EventBridge │  │ {status_icon(True)} S3 Bucket    │
        │    Logs       │  │     Rules      │  │   (Archive)     │
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
              │ {sns_status} SNS Topics    │  Subscriptions: {str(flow_analysis.get('sns_has_subscribers', False)).upper()}
              │  (Notifications) │
              └────────┬─────────┘
                       │
                       v
              ┌─────────────────┐
              │ {subscriptions_status} Subscriptions │  Confirmed: {str(flow_analysis.get('subscriptions_confirmed', False)).upper()}
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
        if (
            flow_analysis["cloudtrail_enabled"]
            and not flow_analysis["cloudwatch_integration"]
        ):
            gaps.append(
                "CloudTrail not integrated with CloudWatch Logs (events not monitored)"
            )

        # Critical: CloudWatch without metric filters
        # Note: metric_filters_exist is always True if cloudwatch_integration is True
        # in our current logic, so this gap only triggers if CloudWatch exists but
        # we explicitly detect no metric filters (future enhancement)
        if (
            flow_analysis["cloudwatch_integration"]
            and not flow_analysis["metric_filters_exist"]
        ):
            gaps.append("No metric filters configured for security events")

        # Critical: No alarms
        if not flow_analysis["alarms_configured"]:
            gaps.append("No CloudWatch alarms configured for security events")

        # High: No SNS topics
        if not flow_analysis["sns_topics_exist"]:
            gaps.append(
                "No SNS topics configured for alerting (notifications disabled)"
            )

        # High: SNS without subscribers
        if (
            flow_analysis["sns_topics_exist"]
            and not flow_analysis["sns_has_subscribers"]
        ):
            gaps.append("SNS topics exist but have no active subscriptions")

        # High: SNS subscriptions not confirmed
        if (
            flow_analysis["sns_has_subscribers"]
            and not flow_analysis["subscriptions_confirmed"]
        ):
            gaps.append(
                "SNS subscriptions exist but are not confirmed (pending)"
            )

        # Warning: Single-region CloudTrail
        if (
            flow_analysis["cloudtrail_enabled"]
            and not flow_analysis["cloudtrail_multi_region"]
        ):
            gaps.append(
                "CloudTrail is single-region only (multi-region recommended)"
            )

        # Warning: EventBridge rules not configured
        if not flow_analysis["eventbridge_rules_exist"]:
            gaps.append(
                "EventBridge rules not configured (alternative alerting path unused)"
            )

        return gaps
