import types

import boto3
import pytest

from drystone.skills.vulns import VulnsSkill
from drystone.storage.session import AuditSession


class FakeS3:
    def __init__(self):
        self.calls = []

    def list_buckets(self):
        self.calls.append("list_buckets")
        return {"Buckets": [{"Name": "my-terraform-state-bucket"}]}

    def list_objects_v2(self, Bucket=None, MaxKeys=None):
        self.calls.append(("list_objects_v2", Bucket))
        return {"Contents": []}

    def get_object(self, Bucket=None, Key=None, Range=None):
        self.calls.append(("get_object", Bucket, Key, Range))
        raise RuntimeError("Should not actually read from network in tests")


def test_tfstate_scan_skipped_when_flag_off(monkeypatch, tmp_path):
    fake = FakeS3()

    def fake_client(service_name, **kwargs):
        if service_name == "s3":
            return fake
        raise RuntimeError("Unexpected client requested: %s" % service_name)

    monkeypatch.setattr("boto3.client", fake_client)

    skill = VulnsSkill()
    session = AuditSession("test-client", "000000000000")
    session.feature_flags = {"terraform_state_scan_enabled": False}

    data = skill._collect_terraform_state_secrets({}, session)

    # Expect early-skip marker tuple (items, error, skipped, reason)
    assert isinstance(data, tuple) and len(data) == 4
    items, error, skipped, reason = data
    assert skipped is True
    assert "opt-in" in reason or "opt-in required" in reason

    # list_buckets and other S3 read ops should not have been called
    assert fake.calls == []


def test_tfstate_scan_runs_when_flag_on(monkeypatch, tmp_path):
    fake = FakeS3()

    def fake_client(service_name, **kwargs):
        if service_name == "s3":
            return fake
        raise RuntimeError("Unexpected client requested: %s" % service_name)

    monkeypatch.setattr("boto3.client", fake_client)

    skill = VulnsSkill()
    session = AuditSession("test-client", "000000000000")
    session.feature_flags = {"terraform_state_scan_enabled": True}

    data = skill._collect_terraform_state_secrets({}, session)

    # When enabled, function should return (items, error) or similar non-skipped form
    assert isinstance(data, tuple)
    assert len(data) >= 2
    # list_buckets should have been called at least once
    assert any(c == "list_buckets" for c in fake.calls)
