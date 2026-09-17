"""Integration regression for AssumeRole-backed skill collection."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from drystone.cloud.aws.client import AWSClient
from drystone.models import WizardConfig
from drystone.skills.cloudtrail_events import CloudTrailEventsSkill


class _FrozenCredentials:
    def __init__(self, access_key: str, secret_key: str, token: str | None = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = token


class _Credentials:
    def __init__(self, frozen: _FrozenCredentials):
        self._frozen = frozen

    def get_frozen_credentials(self) -> _FrozenCredentials:
        return self._frozen


class _SourceSTS:
    def assume_role(self, **kwargs):
        assert kwargs["RoleArn"] == "arn:aws:iam::222222222222:role/DrystoneAudit"
        return {
            "Credentials": {
                "AccessKeyId": "ASSUMEDKEY",
                "SecretAccessKey": "ASSUMEDSECRET",
                "SessionToken": "ASSUMEDTOKEN",
                "Expiration": datetime(2026, 1, 1, tzinfo=timezone.utc),
            }
        }


class _FakeBoto3Session:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def client(self, service_name: str, **kwargs):
        assert service_name == "sts"
        return _SourceSTS()

    def get_credentials(self):
        if self.kwargs.get("aws_access_key_id") == "ASSUMEDKEY":
            return _Credentials(_FrozenCredentials("ASSUMEDKEY", "ASSUMEDSECRET", "ASSUMEDTOKEN"))
        return _Credentials(_FrozenCredentials("SOURCEKEY", "SOURCESECRET", None))


class _EmptyPaginator:
    def paginate(self, **kwargs):
        return [{"Events": []}]


def test_skill_collect_uses_assumed_role_credentials_from_awsclient(tmp_path):
    """A skill must consume AWSClient-managed assumed credentials, not source creds."""
    config = WizardConfig(
        client_name="ACME",
        aws_access_key_id="SOURCEKEY",
        aws_secret_access_key="SOURCESECRET",
        aws_region="us-east-1",
        aws_role_arn="arn:aws:iam::222222222222:role/DrystoneAudit",
        aws_role_session_name="drystone-test",
        skills=["cloudtrail_events"],
        output_formats=["json"],
    )
    aws_client = AWSClient(config)

    session = MagicMock()
    evidence_path = tmp_path / "evidence" / "cloudtrail_events"
    evidence_path.mkdir(parents=True)
    session.get_evidence_path.return_value = evidence_path
    session.scan_depth = "shallow"
    session.account_id = "222222222222"

    captured_kwargs = []

    def _boto3_client(service_name: str, **kwargs):
        assert service_name == "cloudtrail"
        captured_kwargs.append(kwargs)
        client = MagicMock()
        client.get_paginator.return_value = _EmptyPaginator()
        return client

    with (
        patch("drystone.cloud.aws.client.boto3.Session", _FakeBoto3Session),
        patch("boto3.client", side_effect=_boto3_client),
    ):
        CloudTrailEventsSkill().collect(aws_client, session)

    assert captured_kwargs
    first = captured_kwargs[0]
    assert first["aws_access_key_id"] == "ASSUMEDKEY"
    assert first["aws_secret_access_key"] == "ASSUMEDSECRET"
    assert first["aws_session_token"] == "ASSUMEDTOKEN"
    assert first["region_name"] == "us-east-1"
    assert first["aws_access_key_id"] != "SOURCEKEY"
