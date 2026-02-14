"""Messaging security audit skill (SQS/SNS).

Collects evidence about SQS queue policies, DLQ/redrive configuration, and SNS
topic policies/subscriptions.

Focus: persistence and data-plane abuse paths (HackTricks Cloud AWS).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

logger = get_logger(__name__)


class MessagingSkill(BaseSkill):
    @property
    def name(self) -> str:
        return "messaging"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        region = aws_client.region_name
        print(f"  🔍 Scanning SQS/SNS in region: {region}...")

        evidence_path = session.get_evidence_path(self.name)
        evidence_path.mkdir(parents=True, exist_ok=True)

        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
        }
        if getattr(aws_client, "session_token", None):
            client_kwargs["aws_session_token"] = aws_client.session_token

        session_obj = boto3.Session(**client_kwargs)
        sqs = session_obj.client("sqs", region_name=region)
        sns = session_obj.client("sns", region_name=region)

        metadata = {
            "_collected_at": datetime.utcnow().isoformat() + "Z",
            "_region": region,
            "_skill": self.name,
        }
        self._save_json(evidence_path / "_audit_metadata.json", metadata)

        queues, q_errors = self._collect_sqs_queues(sqs)
        self._save_json(evidence_path / "sqs-queues.json", {"items": queues, "errors": q_errors})

        topics, t_errors = self._collect_sns_topics(sns)
        self._save_json(evidence_path / "sns-topics.json", {"items": topics, "errors": t_errors})

        ok = not (q_errors or t_errors)
        logger.info(
            "Messaging collection complete",
            extra={"region": region, "queues": len(queues), "topics": len(topics), "ok": ok},
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

    def _save_json(self, filepath: Path, data: Any) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
