"""Tests for Messaging (SQS/SNS) skill evidence collection."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

from drystone.skills.messaging import MessagingSkill


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class _DummySQSClient:
    def get_paginator(self, op_name: str):
        assert op_name == "list_queues"
        return _DummyPaginator([{"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/1/q1"]}])

    def get_queue_attributes(self, QueueUrl: str, AttributeNames):  # noqa: N803
        assert QueueUrl
        assert "Policy" in AttributeNames
        return {
            "Attributes": {
                "QueueArn": "arn:aws:sqs:us-east-1:1:q1",
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "SQS:SendMessage",
                                "Resource": "*",
                            }
                        ],
                    }
                ),
                "RedrivePolicy": json.dumps({"deadLetterTargetArn": "arn:aws:sqs:us-east-1:1:dlq"}),
                "SqsManagedSseEnabled": "true",
            }
        }


class _DummySNSClient:
    def get_paginator(self, op_name: str):
        if op_name == "list_topics":
            return _DummyPaginator([{"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:1:t1"}]}])
        if op_name == "list_subscriptions_by_topic":
            return _DummyPaginator([{"Subscriptions": [{"Protocol": "sqs"}]}])
        raise AssertionError(f"Unexpected paginator: {op_name}")

    def get_topic_attributes(self, TopicArn: str):  # noqa: N803
        assert TopicArn
        return {"Attributes": {"Policy": '{"Version":"2012-10-17","Statement":[]}'}}


class _DummySession:
    def client(self, service_name: str, region_name: str):
        assert region_name
        if service_name == "sqs":
            return _DummySQSClient()
        if service_name == "sns":
            return _DummySNSClient()
        raise AssertionError(f"Unexpected service: {service_name}")


def test_messaging_collect_writes_expected_files(tmp_path: Path):
    aws_client = Mock()
    aws_client.access_key_id = "AKIA0000000000000000"
    aws_client.secret_access_key = "x" * 40
    aws_client.region_name = "us-east-1"
    aws_client.session_token = None

    session = Mock()
    session.get_evidence_path.return_value = tmp_path

    skill = MessagingSkill()
    aws_client.boto3_session.return_value = _DummySession()
    with patch("boto3.Session", return_value=_DummySession()):
        skill.collect(aws_client, session)

    metadata = json.loads((tmp_path / "_audit_metadata.json").read_text())
    queues = json.loads((tmp_path / "sqs-queues.json").read_text())
    topics = json.loads((tmp_path / "sns-topics.json").read_text())

    assert metadata["_region"] == "us-east-1"
    assert metadata["_skill"] == "messaging"
    assert queues["errors"] == {}
    assert queues["items"][0]["QueueUrl"].endswith("/q1")
    assert queues["items"][0]["QueueArn"].endswith(":q1")
    assert queues["items"][0]["Policy"]["Statement"][0]["Effect"] == "Allow"
    assert queues["items"][0]["RedrivePolicy"]["deadLetterTargetArn"].endswith(":dlq")
    assert queues["items"][0]["SqsManagedSseEnabled"] == "true"
    assert topics["errors"] == {}
    assert topics["items"][0]["TopicArn"].endswith(":t1")
    assert topics["items"][0]["Attributes"]["Policy"]["Version"] == "2012-10-17"
    assert topics["items"][0]["Subscriptions"] == [{"Protocol": "sqs"}]
