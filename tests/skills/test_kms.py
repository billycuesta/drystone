"""Tests for KMS skill evidence collection."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import botocore.exceptions

from drystone.skills.kms import KMSSkill


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class _DummyKMSClient:
    def __init__(self, rotation_error=None):
        self.rotation_error = rotation_error

    def get_paginator(self, op_name: str):
        if op_name == "list_keys":
            return _DummyPaginator(
                [{"Keys": [{"KeyId": "1234", "KeyArn": "arn:aws:kms:us-east-1:1:key/1234"}]}]
            )
        if op_name == "list_grants":
            return _DummyPaginator([{"Grants": [{"GrantId": "g-1", "Operations": ["Decrypt"]}]}])
        if op_name in {"list_aliases", "describe_custom_key_stores"}:
            return _DummyPaginator([{}])
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
        if self.rotation_error is not None:
            raise self.rotation_error
        return {"KeyRotationEnabled": True}

    def list_key_policies(self, KeyId: str):  # noqa: N803
        assert KeyId
        return {"PolicyNames": ["default"]}

    def get_key_policy(self, KeyId: str, PolicyName: str):  # noqa: N803
        assert KeyId
        assert PolicyName
        return {"Policy": '{"Version":"2012-10-17","Statement":[]}'}


class _DummySession:
    def __init__(self, kms_client=None):
        self.kms_client = kms_client or _DummyKMSClient()

    def client(self, service_name: str, region_name: str):
        assert service_name == "kms"
        assert region_name
        return self.kms_client


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


def _collect_kms(tmp_path: Path, kms_client: _DummyKMSClient):
    aws_client = Mock()
    aws_client.region_name = "us-east-1"
    aws_client.boto3_session.return_value = _DummySession(kms_client)
    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    KMSSkill().collect(aws_client, session)
    return json.loads((tmp_path / "kms-keys.json").read_text())


def test_unsupported_rotation_is_metadata_not_an_error(tmp_path: Path, caplog):
    error = botocore.exceptions.ClientError(
        {"Error": {"Code": "UnsupportedOperationException", "Message": "unsupported"}},
        "GetKeyRotationStatus",
    )

    with caplog.at_level("INFO", logger="drystone.skills.kms"):
        keys_doc = _collect_kms(tmp_path, _DummyKMSClient(rotation_error=error))

    assert keys_doc["errors"] == {}
    assert keys_doc["items"][0]["KeyRotationEnabled"] is None
    assert keys_doc["items"][0]["RotationSupported"] is False
    completion = next(record for record in caplog.records if record.message == "KMS collection complete")
    assert completion.ok is True


def test_genuine_rotation_error_remains_in_errors(tmp_path: Path):
    error = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        "GetKeyRotationStatus",
    )

    keys_doc = _collect_kms(tmp_path, _DummyKMSClient(rotation_error=error))

    assert keys_doc["errors"] == {"get_key_rotation_status:1234": "AccessDeniedException"}
    assert keys_doc["items"][0]["RotationSupported"] is None
