"""Tests for CI/CD (CodeBuild) skill evidence collection."""

from pathlib import Path
from unittest.mock import Mock, patch

from drystone.skills.cicd import CICDSkill


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


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
