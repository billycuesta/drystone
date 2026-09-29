"""Tests for KMS skill evidence collection."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from drystone.skills.kms import KMSSkill


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


def _client_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": code}}, "KMS")


class _DummyKMSClient:
    def get_paginator(self, op_name: str):
        if op_name == "list_keys":
            return _DummyPaginator(
                [{"Keys": [{"KeyId": "1234", "KeyArn": "arn:aws:kms:us-east-1:1:key/1234"}]}]
            )
        if op_name == "list_grants":
            return _DummyPaginator([{"Grants": [{"GrantId": "g-1", "Operations": ["Decrypt"]}]}])
        if op_name == "list_aliases":
            return _DummyPaginator([{"Aliases": [{"AliasName": "alias/test", "TargetKeyId": "1234"}]}])
        if op_name == "describe_custom_key_stores":
            return _DummyPaginator([{"CustomKeyStores": []}])
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

    def list_key_policies(self, KeyId: str):  # noqa: N803
        assert KeyId
        return {"PolicyNames": ["default"]}

    def get_key_policy(self, KeyId: str, PolicyName: str):  # noqa: N803
        assert KeyId
        assert PolicyName
        return {"Policy": '{"Version":"2012-10-17","Statement":[]}'}

    def get_key_rotation_status(self, KeyId: str):  # noqa: N803
        assert KeyId
        return {"KeyRotationEnabled": True}


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


def _run_kms_collect(tmp_path: Path, client):
    aws_client = Mock()
    aws_client.region_name = "us-east-1"

    class _Session:
        def client(self, service_name: str, region_name: str):
            assert service_name == "kms"
            assert region_name
            return client

    aws_client.boto3_session.return_value = _Session()
    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    KMSSkill().collect(aws_client, session)
    return json.loads((tmp_path / "kms-collection-status.json").read_text())


def test_kms_collection_status_happy_path(tmp_path: Path):
    status = _run_kms_collect(tmp_path, _DummyKMSClient())

    assert status["_schema"] == "drystone.collection_status.v1"
    assert status["_skill"] == "kms"
    assert status["ok"] is True
    assert status["components"]["kms-keys"] == {"ok": True}
    assert status["components"]["kms-key-policies"] == {"ok": True}
    assert status["components"]["kms-grants"] == {"ok": True}
    assert status["components"]["kms-aliases"] == {"ok": True}
    assert status["components"]["kms-custom-key-stores"] == {"ok": True}


def test_kms_list_keys_failure_is_collection_failed(tmp_path: Path):
    class _FailListKeysClient(_DummyKMSClient):
        def get_paginator(self, op_name: str):
            if op_name == "list_keys":
                raise _client_error("AccessDeniedException")
            return super().get_paginator(op_name)

    status = _run_kms_collect(tmp_path, _FailListKeysClient())

    component = status["components"]["kms-keys"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component["error_code"] == "AccessDeniedException"


def test_kms_per_key_rotation_failure_is_partial_collection(tmp_path: Path):
    class _RotationFailureClient(_DummyKMSClient):
        def get_key_rotation_status(self, KeyId: str):  # noqa: N803
            raise _client_error("UnsupportedOperationException")

    status = _run_kms_collect(tmp_path, _RotationFailureClient())

    component = status["components"]["kms-keys"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
