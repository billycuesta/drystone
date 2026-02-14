"""Tests for KMS skill evidence collection."""

from pathlib import Path
from unittest.mock import Mock, patch

from drystone.skills.kms import KMSSkill


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class _DummyKMSClient:
    def get_paginator(self, op_name: str):
        if op_name == "list_keys":
            return _DummyPaginator(
                [{"Keys": [{"KeyId": "1234", "KeyArn": "arn:aws:kms:us-east-1:1:key/1234"}]}]
            )
        if op_name == "list_grants":
            return _DummyPaginator([{"Grants": [{"GrantId": "g-1", "Operations": ["Decrypt"]}]}])
        raise AssertionError(f"Unexpected paginator: {op_name}")

    def describe_key(self, key_id: str):
        assert key_id
        return {
            "KeyMetadata": {
                "KeyId": key_id,
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
            }
        }

    def list_key_policies(self, key_id: str):
        assert key_id
        return {"PolicyNames": ["default"]}

    def get_key_policy(self, key_id: str, policy_name: str):
        assert key_id
        assert policy_name
        return {"Policy": '{"Version":"2012-10-17","Statement":[]}'}


class _DummySession:
    def client(self, service_name: str, region_name: str):
        assert service_name == "kms"
        assert region_name
        return _DummyKMSClient()


def test_kms_collect_writes_expected_files(tmp_path: Path):
    aws_client = Mock()
    aws_client.access_key_id = "AKIA0000000000000000"
    aws_client.secret_access_key = "x" * 40
    aws_client.region_name = "us-east-1"
    aws_client.session_token = None

    session = Mock()
    session.get_evidence_path.return_value = tmp_path

    skill = KMSSkill()
    with patch("boto3.Session", return_value=_DummySession()):
        skill.collect(aws_client, session)

    assert (tmp_path / "_audit_metadata.json").exists()
    assert (tmp_path / "kms-keys.json").exists()
    assert (tmp_path / "kms-key-policies.json").exists()
    assert (tmp_path / "kms-grants.json").exists()
