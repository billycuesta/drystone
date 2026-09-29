"""Tests for messaging skill per-component collection status.

The messaging collectors swallow ClientErrors into per-file ``errors`` dicts.
These tests verify that ``collect`` also derives a shared
``messaging-collection-status.json`` with a ``components`` dict keyed by
evidence file stem, recording compact AWS error codes and counts only —
never queue URLs, topic ARNs, policy contents, or full exception messages.
"""

import json
from pathlib import Path
from unittest.mock import Mock

from botocore.exceptions import ClientError

from drystone.skills.messaging import MessagingSkill

Q1 = "https://sqs.us-east-1.amazonaws.com/123456789012/q1"
Q2 = "https://sqs.us-east-1.amazonaws.com/123456789012/q2"
T1 = "arn:aws:sns:us-east-1:123456789012:t1"

STATUS_NAME = "messaging-collection-status.json"
LEAK_TOKEN = "SECRET-MESSAGE-TOKEN"


def _client_error(code: str, operation: str, message: str = LEAK_TOKEN) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


class _DummyPaginator:
    def __init__(self, pages, error=None):
        self._pages = pages
        self._error = error

    def paginate(self, **_kwargs):
        if self._error is not None:
            raise self._error
        return iter(self._pages)


class _DummySubscriptionsPaginator:
    def __init__(self, errors):
        self._errors = errors or {}

    def paginate(self, TopicArn, **_kwargs):  # noqa: N803
        error = self._errors.get(TopicArn)
        if error is not None:
            raise error
        return iter([{"Subscriptions": []}])


class _DummySQSClient:
    def __init__(self, *, list_error=None, queue_urls=None, attr_errors=None):
        self._list_error = list_error
        self._queue_urls = [Q1, Q2] if queue_urls is None else queue_urls
        self._attr_errors = attr_errors or {}

    def get_paginator(self, op_name):
        assert op_name == "list_queues"
        if self._list_error is not None:
            return _DummyPaginator([], error=self._list_error)
        return _DummyPaginator([{"QueueUrls": self._queue_urls}])

    def get_queue_attributes(self, QueueUrl, AttributeNames):  # noqa: N803
        error = self._attr_errors.get(QueueUrl)
        if error is not None:
            raise error
        return {"Attributes": {"QueueArn": "arn:aws:sqs:us-east-1:123456789012:q"}}


class _DummySNSClient:
    def __init__(self, *, list_error=None, topics=None, attr_errors=None, sub_errors=None):
        self._list_error = list_error
        self._topics = [T1] if topics is None else topics
        self._attr_errors = attr_errors or {}
        self._sub_errors = sub_errors or {}

    def get_paginator(self, op_name):
        if op_name == "list_topics":
            if self._list_error is not None:
                return _DummyPaginator([], error=self._list_error)
            return _DummyPaginator([{"Topics": [{"TopicArn": a} for a in self._topics]}])
        if op_name == "list_subscriptions_by_topic":
            return _DummySubscriptionsPaginator(self._sub_errors)
        raise AssertionError(f"Unexpected paginator: {op_name}")

    def get_topic_attributes(self, TopicArn):  # noqa: N803
        error = self._attr_errors.get(TopicArn)
        if error is not None:
            raise error
        return {"Attributes": {"Policy": '{"Version":"2012-10-17","Statement":[]}'}}


def _run_collect(tmp_path: Path, sqs, sns):
    """Run MessagingSkill.collect against dummy clients; return (status, raw text)."""
    session_obj = Mock()
    session_obj.client.side_effect = lambda service_name, region_name: {
        "sqs": sqs,
        "sns": sns,
    }[service_name]

    aws_client = Mock()
    aws_client.region_name = "us-east-1"
    aws_client.boto3_session.return_value = session_obj

    audit_session = Mock()
    audit_session.get_evidence_path.return_value = tmp_path

    MessagingSkill().collect(aws_client, audit_session)

    status_file = tmp_path / STATUS_NAME
    raw = status_file.read_text()
    return json.loads(raw), raw


def test_collection_status_happy_path(tmp_path: Path):
    status, _raw = _run_collect(tmp_path, _DummySQSClient(), _DummySNSClient())

    assert status["ok"] is True
    assert status["components"]["sqs-queues"] == {"ok": True}
    assert status["components"]["sns-topics"] == {"ok": True}


def test_sqs_list_failure_records_collection_failed_without_message_leak(tmp_path: Path):
    sqs = _DummySQSClient(list_error=_client_error("AccessDenied", "ListQueues"))

    status, raw = _run_collect(tmp_path, sqs, _DummySNSClient())

    component = status["components"]["sqs-queues"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component["error_code"] == "AccessDenied"
    assert component["error"] == "list_queues: AccessDenied"
    assert status["ok"] is False
    # The other component is unaffected.
    assert status["components"]["sns-topics"] == {"ok": True}
    # Full exception messages never reach the status file.
    assert LEAK_TOKEN not in raw


def test_sqs_partial_attribute_failures_record_partial_collection(tmp_path: Path):
    sqs = _DummySQSClient(attr_errors={Q2: _client_error("Throttling", "GetQueueAttributes")})

    status, raw = _run_collect(tmp_path, sqs, _DummySNSClient())

    component = status["components"]["sqs-queues"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
    assert component["error_code"] == "Throttling"
    assert "1 per-queue attribute lookups failed" in component["error"]
    assert len(component["error"]) <= 200
    # Queue URLs and exception messages must not leak into the status file.
    assert Q2 not in raw
    assert LEAK_TOKEN not in raw


def test_sns_list_failure_isolated_from_sqs(tmp_path: Path):
    sns = _DummySNSClient(list_error=_client_error("AccessDenied", "ListTopics"))

    status, raw = _run_collect(tmp_path, _DummySQSClient(), sns)

    component = status["components"]["sns-topics"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component["error_code"] == "AccessDenied"
    assert component["error"] == "list_topics: AccessDenied"
    assert status["components"]["sqs-queues"] == {"ok": True}
    assert LEAK_TOKEN not in raw


def test_sns_partial_failures_summarize_counts_and_codes_only(tmp_path: Path):
    sns = _DummySNSClient(
        attr_errors={T1: _client_error("AccessDenied", "GetTopicAttributes")},
        sub_errors={T1: _client_error("ThrottlingException", "ListSubscriptionsByTopic")},
    )

    status, raw = _run_collect(tmp_path, _DummySQSClient(), sns)

    component = status["components"]["sns-topics"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
    assert "per-topic attribute lookups failed" in component["error"]
    assert "subscription listings failed" in component["error"]
    assert "AccessDenied" in component["error"]
    assert "ThrottlingException" in component["error"]
    assert len(component["error"]) <= 200
    # Topic ARNs and exception messages must not leak into the status file.
    assert T1 not in raw
    assert LEAK_TOKEN not in raw


def test_collection_status_component_keys_match_written_evidence_stems(tmp_path: Path):
    """Components consumed by pre-checks must use evidence file stems."""
    status, _raw = _run_collect(tmp_path, _DummySQSClient(), _DummySNSClient())

    evidence_stems = {
        path.stem
        for path in tmp_path.glob("*.json")
        if not path.name.endswith("-collection-status.json")
    }
    auxiliary_components: set = set()
    for component in status["components"]:
        assert component in evidence_stems | auxiliary_components


def test_list_failure_takes_precedence_over_per_item_failures():
    components = {}
    skill = MessagingSkill()

    skill._record_errors_component(
        components,
        "sqs-queues",
        {"list_queues": "AccessDenied", f"get_queue_attributes:{Q1}": "Throttling"},
        list_key="list_queues",
        per_item_labels={"get_queue_attributes": "per-queue attribute lookups"},
    )

    component = components["sqs-queues"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component["error_code"] == "AccessDenied"
    assert component["error"] == "list_queues: AccessDenied"


def test_non_code_list_error_message_does_not_leak_into_status():
    components = {}
    skill = MessagingSkill()

    skill._record_errors_component(
        components,
        "sqs-queues",
        {"list_queues": "could not connect to secret-host.internal"},
        list_key="list_queues",
        per_item_labels={},
    )

    component = components["sqs-queues"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component.get("error_code") is None
    assert "secret-host.internal" not in str(component.get("error", ""))
