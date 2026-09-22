"""Tests for secret-safe EC2 user-data collection."""

import base64
from unittest.mock import patch

from drystone.skills.vulns import VulnsSkill


class _Paginator:
    def paginate(self):
        yield {"Reservations": [{"Instances": [{"InstanceId": "i-test"}]}]}


class _EC2Client:
    def __init__(self, user_data: str):
        self.user_data = base64.b64encode(user_data.encode()).decode()

    def get_paginator(self, operation):
        assert operation == "describe_instances"
        return _Paginator()

    def describe_instance_attribute(self, InstanceId, Attribute):  # noqa: N803
        assert InstanceId == "i-test" and Attribute == "userData"
        return {"UserData": {"Value": self.user_data}}


def test_vulns_redacts_secret_user_data_before_evidence_persistence():
    text = "#cloud-config\nwrite_files: []\napi_key=plain-api-key-value\n"
    client = _EC2Client(text)
    with patch("boto3.client", return_value=client):
        items, error = VulnsSkill()._collect_ec2_user_data({})

    assert error is None
    item = items[0]
    assert "plain-api-key-value" not in item["UserData"]
    assert "#cloud-config" in item["UserData"]
    assert item["ContainsSecrets"]["api_key"] is True


def test_vulns_preserves_non_secret_user_data():
    text = "#!/bin/bash\necho bootstrap-complete\n"
    with patch("boto3.client", return_value=_EC2Client(text)):
        items, error = VulnsSkill()._collect_ec2_user_data({})

    assert error is None
    assert items[0]["UserData"] == text
    assert not any(items[0]["ContainsSecrets"].values())
