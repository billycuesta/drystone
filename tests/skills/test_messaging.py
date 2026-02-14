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

    def get_queue_attributes(self, queue_url: str, attribute_names):
        assert queue_url
        assert "Policy" in attribute_names
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
            }
        }


class _DummySNSClient:
    def get_paginator(self, op_name: str):
        if op_name == "list_topics":
            return _DummyPaginator([{"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:1:t1"}]}])
        if op_name == "list_subscriptions_by_topic":
            return _DummyPaginator([{"Subscriptions": [{"Protocol": "sqs"}]}])
        raise AssertionError(f"Unexpected paginator: {op_name}")

    def get_topic_attributes(self, topic_arn: str):
        assert topic_arn
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
    with patch("boto3.Session", return_value=_DummySession()):
        skill.collect(aws_client, session)

    assert (tmp_path / "_audit_metadata.json").exists()
    assert (tmp_path / "sqs-queues.json").exists()
    assert (tmp_path / "sns-topics.json").exists()
