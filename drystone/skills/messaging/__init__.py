"""Messaging security audit skill (SQS/SNS).

Collects evidence about SQS queue policies, DLQ/redrive configuration, and SNS
topic policies/subscriptions.

Focus: persistence and data-plane abuse paths (HackTricks Cloud AWS).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

logger = get_logger(__name__)

# Human-readable labels for per-resource error keys, used to summarize
# partial failures in the collection status file (counts and codes only).
_SQS_PER_ITEM_LABELS = {"get_queue_attributes": "per-queue attribute lookups"}
_SNS_PER_ITEM_LABELS = {
    "get_topic_attributes": "per-topic attribute lookups",
    "list_subscriptions_by_topic": "per-topic subscription listings",
}


class MessagingSkill(BaseSkill):
    def _skill_specific_traceability(
        self,
        check_id: str,
        result: Any,
        evidence: Dict[str, Any],
    ) -> Optional["tuple[List[str], Optional[Dict[str, Any]]]"]:
        from drystone.skills.messaging.traceability import build_traceability

        return build_traceability(check_id, result, evidence)

    @property
    def name(self) -> str:
        return "messaging"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        region = aws_client.region_name
        print(f"  🔍 Scanning SQS/SNS in region: {region}...")

        evidence_path = session.get_evidence_path(self.name)
        evidence_path.mkdir(parents=True, exist_ok=True)

        session_obj = aws_client.boto3_session()
        sqs = session_obj.client("sqs", region_name=region)
        sns = session_obj.client("sns", region_name=region)

        metadata = {
            "_collected_at": datetime.now(timezone.utc).isoformat(),
            "_region": region,
            "_skill": self.name,
        }
        self._save_json(evidence_path / "_audit_metadata.json", metadata)

        components: Dict[str, Dict[str, Any]] = {}

        queues, q_errors = self._collect_sqs_queues(sqs)
        self._save_json(evidence_path / "sqs-queues.json", {"items": queues, "errors": q_errors})
        self._record_errors_component(
            components,
            "sqs-queues",
            q_errors,
            list_key="list_queues",
            per_item_labels=_SQS_PER_ITEM_LABELS,
        )

        topics, t_errors = self._collect_sns_topics(sns)
        self._save_json(evidence_path / "sns-topics.json", {"items": topics, "errors": t_errors})
        self._record_errors_component(
            components,
            "sns-topics",
            t_errors,
            list_key="list_topics",
            per_item_labels=_SNS_PER_ITEM_LABELS,
        )

        self._save_collection_status(evidence_path, {"components": components})

        ok = not (q_errors or t_errors)
        logger.info(
            "Messaging collection complete",
            extra={"region": region, "queues": len(queues), "topics": len(topics), "ok": ok},
        )

    def _record_errors_component(
        self,
        components: Dict[str, Dict[str, Any]],
        stem: str,
        errors: Dict[str, str],
        *,
        list_key: str,
        per_item_labels: Dict[str, str],
    ) -> None:
        """Derive a component status entry from a persisted errors dict.

        Only compact AWS error codes and counts are recorded; per-item keys
        (queue URLs, topic ARNs) and full exception messages never reach the
        status file. A list failure outranks per-item failures because the
        items may never have been seen.
        """
        if not errors:
            self._record_component_status(components, stem, ok=True)
            return

        list_value = errors.get(list_key)
        if list_value is not None:
            code = self._status_error_code(str(list_value))
            self._record_component_status(
                components,
                stem,
                ok=False,
                reason_code="collection_failed",
                error_code=code,
                error=f"{list_key}: {code}" if code else f"{list_key}: failed",
            )
            return

        counts: Dict[str, int] = {}
        codes: set = set()
        for key, value in errors.items():
            operation = key.split(":", 1)[0]
            label = per_item_labels.get(operation, operation)
            counts[label] = counts.get(label, 0) + 1
            code = self._status_error_code(str(value))
            if code:
                codes.add(code)
        summary = "; ".join(
            f"{count} {label} failed" for label, count in sorted(counts.items())
        )
        if codes:
            summary += f" ({', '.join(sorted(codes))})"
        self._record_component_status(
            components,
            stem,
            ok=False,
            reason_code="partial_collection",
            error_code=sorted(codes)[0] if codes else None,
            error=summary[:200],
        )

    def _collect_sqs_queues(self, sqs) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}

        try:
            paginator = sqs.get_paginator("list_queues")
            queue_urls: List[str] = []
            for page in paginator.paginate():
                queue_urls.extend(page.get("QueueUrls", []) or [])

            for url in queue_urls:
                try:
                    attrs = sqs.get_queue_attributes(
                        QueueUrl=url,
                        AttributeNames=[
                            "QueueArn",
                            "Policy",
                            "KmsMasterKeyId",
                            "RedrivePolicy",
                            "RedriveAllowPolicy",
                            "SqsManagedSseEnabled",
                        ],
                    ).get("Attributes", {})
                    policy_obj: Any = None
                    if isinstance(attrs.get("Policy"), str) and attrs.get("Policy"):
                        try:
                            policy_obj = json.loads(attrs.get("Policy"))
                        except Exception:
                            policy_obj = {"raw": attrs.get("Policy")}

                    redrive_obj: Any = None
                    if isinstance(attrs.get("RedrivePolicy"), str) and attrs.get("RedrivePolicy"):
                        try:
                            redrive_obj = json.loads(attrs.get("RedrivePolicy"))
                        except Exception:
                            redrive_obj = {"raw": attrs.get("RedrivePolicy")}

                    redrive_allow_obj: Any = None
                    if isinstance(attrs.get("RedriveAllowPolicy"), str) and attrs.get(
                        "RedriveAllowPolicy"
                    ):
                        try:
                            redrive_allow_obj = json.loads(attrs.get("RedriveAllowPolicy"))
                        except Exception:
                            redrive_allow_obj = {"raw": attrs.get("RedriveAllowPolicy")}

                    items.append(
                        {
                            "QueueUrl": url,
                            "QueueArn": attrs.get("QueueArn"),
                            "KmsMasterKeyId": attrs.get("KmsMasterKeyId"),
                            "SqsManagedSseEnabled": attrs.get("SqsManagedSseEnabled"),
                            "Policy": policy_obj,
                            "RedrivePolicy": redrive_obj,
                            "RedriveAllowPolicy": redrive_allow_obj,
                        }
                    )
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    errors[f"get_queue_attributes:{url}"] = code
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            errors["list_queues"] = code
        except Exception as e:
            errors["list_queues"] = str(e)

        return items, errors

    def _collect_sns_topics(self, sns) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}

        try:
            paginator = sns.get_paginator("list_topics")
            topic_arns: List[str] = []
            for page in paginator.paginate():
                for t in page.get("Topics", []) or []:
                    arn = t.get("TopicArn") if isinstance(t, dict) else None
                    if arn:
                        topic_arns.append(str(arn))

            for arn in topic_arns:
                topic_obj: Dict[str, Any] = {"TopicArn": arn}
                try:
                    attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                    policy_obj: Any = None
                    if isinstance(attrs.get("Policy"), str) and attrs.get("Policy"):
                        try:
                            policy_obj = json.loads(attrs.get("Policy"))
                        except Exception:
                            policy_obj = {"raw": attrs.get("Policy")}
                    topic_obj["Attributes"] = {**attrs, "Policy": policy_obj}
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    errors[f"get_topic_attributes:{arn}"] = code
                    topic_obj["Attributes"] = {"error": code}

                subs: List[Dict[str, Any]] = []
                try:
                    sub_p = sns.get_paginator("list_subscriptions_by_topic")
                    for page in sub_p.paginate(TopicArn=arn):
                        subs.extend(page.get("Subscriptions", []) or [])
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    errors[f"list_subscriptions_by_topic:{arn}"] = code
                topic_obj["Subscriptions"] = subs

                items.append(topic_obj)

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            errors["list_topics"] = code
        except Exception as e:
            errors["list_topics"] = str(e)

        return items, errors

# --- Skill registry manifest (see drystone/skills/registry.py) ---
# Declaring these here is what lets drystone auto-discover this skill —
# no other file needs to list it by name.
SKILL_NAME = "messaging"
SKILL_DISPLAY_NAME = "Messaging"
SKILL_CLASS = MessagingSkill
SKILL_WIZARD_SELECTABLE = True
SKILL_WIZARD_LABEL = "Messaging (SQS/SNS) Audit"
SKILL_WIZARD_ORDER = 12
