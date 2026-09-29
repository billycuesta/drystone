"""Tests for CI/CD (CodeBuild) skill evidence collection."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from drystone.skills.cicd import CICDSkill


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


def _client_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": code}}, "CodeBuild")


class _DummyCodeBuildClient:
    def get_paginator(self, op_name: str):
        assert op_name == "list_projects"
        return _DummyPaginator([{"projects": ["p1"]}])

    def batch_get_projects(self, names):
        assert names == ["p1"]
        return {
            "projects": [
                {
                    "name": "p1",
                    "arn": "arn:aws:codebuild:us-east-1:1:project/p1",
                    "serviceRole": "arn:aws:iam::1:role/codebuild-role",
                    "source": {
                        "type": "GITHUB",
                        "location": "https://github.com/org/repo",
                        "insecureSsl": True,
                    },
                    "environment": {
                        "image": "aws/codebuild/standard:7.0",
                        "computeType": "BUILD_GENERAL1_SMALL",
                        "privilegedMode": False,
                        "environmentVariables": [
                            {
                                "name": "https_proxy",
                                "value": "http://proxy:8080",
                                "type": "PLAINTEXT",
                            }
                        ],
                    },
                    "artifacts": {"type": "NO_ARTIFACTS"},
                }
            ]
        }

    def list_source_credentials(self):
        return {
            "sourceCredentialsInfos": [
                {
                    "arn": "arn:aws:codebuild:us-east-1:1:token/abc",
                    "serverType": "GITHUB",
                    "authType": "PERSONAL_ACCESS_TOKEN",
                    "resource": "https://github.com",
                }
            ]
        }


class _DummySession:
    def client(self, service_name: str, region_name: str):
        assert region_name
        assert service_name == "codebuild"
        return _DummyCodeBuildClient()


def test_cicd_collect_writes_expected_files(tmp_path: Path):
    aws_client = Mock()
    aws_client.access_key_id = "AKIA0000000000000000"
    aws_client.secret_access_key = "x" * 40
    aws_client.region_name = "us-east-1"
    aws_client.session_token = None

    session = Mock()
    session.get_evidence_path.return_value = tmp_path

    skill = CICDSkill()
    with patch("boto3.Session", return_value=_DummySession()):
        skill.collect(aws_client, session)

    assert (tmp_path / "_audit_metadata.json").exists()
    assert (tmp_path / "codebuild-projects.json").exists()
    assert (tmp_path / "codebuild-source-credentials.json").exists()


def _run_cicd_collect(tmp_path: Path, client):
    aws_client = Mock()
    aws_client.region_name = "us-east-1"

    class _Session:
        def client(self, service_name: str, region_name: str):
            assert service_name == "codebuild"
            assert region_name
            return client

    aws_client.boto3_session.return_value = _Session()
    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    CICDSkill().collect(aws_client, session)
    return json.loads((tmp_path / "cicd-collection-status.json").read_text())


def test_cicd_collection_status_happy_path(tmp_path: Path):
    status = _run_cicd_collect(tmp_path, _DummyCodeBuildClient())

    assert status["ok"] is True
    assert status["components"]["codebuild-projects"] == {"ok": True}
    assert status["components"]["codebuild-source-credentials"] == {"ok": True}


def test_cicd_list_projects_failure_is_collection_failed(tmp_path: Path):
    class _FailListProjectsClient(_DummyCodeBuildClient):
        def get_paginator(self, op_name: str):
            if op_name == "list_projects":
                raise _client_error("AccessDeniedException")
            return super().get_paginator(op_name)

    status = _run_cicd_collect(tmp_path, _FailListProjectsClient())

    component = status["components"]["codebuild-projects"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component["error_code"] == "AccessDeniedException"


def test_cicd_batch_get_failure_is_partial_collection(tmp_path: Path):
    class _FailBatchClient(_DummyCodeBuildClient):
        def batch_get_projects(self, names):
            raise _client_error("AccessDeniedException")

    status = _run_cicd_collect(tmp_path, _FailBatchClient())

    component = status["components"]["codebuild-projects"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
