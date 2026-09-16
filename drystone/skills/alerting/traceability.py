"""Alerting (ALRT-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, indexed_ref_for


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id == "ALRT-005":
        resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
        if resource_details:
            refs: List[str] = []
            for detail in resource_details:
                if not isinstance(detail, dict):
                    continue
                topic_arn = str(detail.get("topic_arn") or "")
                if topic_arn:
                    topic_ref = indexed_ref_for(
                        evidence,
                        "sns-topics",
                        lambda item, topic_arn=topic_arn: str(item.get("TopicArn") or "")
                        == topic_arn,
                    )
                    if topic_ref:
                        refs.append(topic_ref)
                    for alarm_name in detail.get("affected_alarms") or []:
                        alarm_ref = indexed_ref_for(
                            evidence,
                            "cloudwatch-alarms",
                            lambda item, alarm_name=str(alarm_name): str(
                                item.get("AlarmName") or ""
                            )
                            == alarm_name,
                        )
                        if alarm_ref:
                            refs.append(alarm_ref)
            return (
                dedupe_refs(refs or ["sns-topics.json"])[:50],
                {
                    "evidence_summary": (
                        f"{len(resource_details)} SNS topic(s) with no confirmed subscriptions"
                    ),
                    "affected_resources": resource_details,
                },
            )
        return None

    if check_id in {"ALRT-002", "ALRT-007", "ALRT-010", "ALRT-017"}:
        resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
        refs: List[str] = []
        if check_id == "ALRT-002":
            refs.extend(["eventbridge-rules.json", "cloudwatch-metric-filters.json"])
        elif check_id == "ALRT-007":
            refs.append("cloudwatch-metric-filters.json")
        elif check_id == "ALRT-010":
            for alarm_name in getattr(result, "affected_resources", []) or []:
                alarm_ref = indexed_ref_for(
                    evidence,
                    "cloudwatch-alarms",
                    lambda item, alarm_name=str(alarm_name): str(item.get("AlarmName") or "")
                    == alarm_name,
                )
                if alarm_ref:
                    refs.append(alarm_ref)
            if not refs:
                refs.append("cloudwatch-alarms.json")
        elif check_id == "ALRT-017":
            for log_group_name in getattr(result, "affected_resources", []) or []:
                lg_ref = indexed_ref_for(
                    evidence,
                    "cloudwatch-log-groups",
                    lambda item, log_group_name=str(log_group_name): str(
                        item.get("LogGroupName") or ""
                    )
                    == log_group_name,
                )
                if lg_ref:
                    refs.append(lg_ref)
            if not refs:
                refs.append("cloudwatch-log-groups.json")

        return (
            dedupe_refs(refs)[:50],
            {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                "affected_resources": resource_details
                or list(getattr(result, "affected_resources", []) or []),
            },
        )

    return None
