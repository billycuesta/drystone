"""Tests for KMS skill evidence collection."""

import json
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
        if op_name == "list_aliases":
            return _DummyPaginator([{"Aliases": [{"AliasName": "alias/example"}]}])
        if op_name == "describe_custom_key_stores":
            return _DummyPaginator([{"CustomKeyStores": [{"CustomKeyStoreId": "cks-1"}]}])
        raise AssertionError(f"Unexpected paginator: {op_name}")

    def describe_key(self, KeyId: str):  # noqa: N803
        assert KeyId
        return {
            "KeyMetadata": {
                "KeyId": KeyId,
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
            }
        }

    def get_key_rotation_status(self, KeyId: str):  # noqa: N803
        assert KeyId
        return {"KeyRotationEnabled": True}

    def list_key_policies(self, KeyId: str):  # noqa: N803
        assert KeyId
        return {"PolicyNames": ["default"]}

    def get_key_policy(self, KeyId: str, PolicyName: str):  # noqa: N803
        assert KeyId
        assert PolicyName
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
    aws_client.boto3_session.return_value = _DummySession()
    with patch("boto3.Session", return_value=_DummySession()):
        skill.collect(aws_client, session)

    metadata = json.loads((tmp_path / "_audit_metadata.json").read_text())
    keys = json.loads((tmp_path / "kms-keys.json").read_text())
    policies = json.loads((tmp_path / "kms-key-policies.json").read_text())
    grants = json.loads((tmp_path / "kms-grants.json").read_text())
    aliases = json.loads((tmp_path / "kms-aliases.json").read_text())
    stores = json.loads((tmp_path / "kms-custom-key-stores.json").read_text())

    assert metadata["_region"] == "us-east-1"
    assert metadata["_skill"] == "kms"
    assert keys["errors"] == {}
    assert keys["items"][0]["KeyId"] == "1234"
    assert keys["items"][0]["Metadata"]["KeyState"] == "Enabled"
    assert keys["items"][0]["KeyRotationEnabled"] is True
    assert policies["items"][0] == {
        "KeyId": "1234",
        "PolicyName": "default",
        "Policy": {"Version": "2012-10-17", "Statement": []},
    }
    assert grants["items"][0] == {
        "KeyId": "1234",
        "GrantId": "g-1",
        "Operations": ["Decrypt"],
    }
    assert aliases["items"] == [{"AliasName": "alias/example"}]
    assert stores["items"] == [{"CustomKeyStoreId": "cks-1"}]
    assert all(data["errors"] == {} for data in (policies, grants, aliases, stores))
