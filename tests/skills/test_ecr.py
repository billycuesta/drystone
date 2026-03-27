"""Unit tests for ECR security skill."""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.ecr import ECRSkill
from drystone.storage.session import AuditSession


class TestECRSkill:
    @pytest.fixture
    def skill(self):
        return ECRSkill()

    @pytest.fixture
    def mock_aws_client(self):
        client = Mock(spec=AWSClient)
        client.access_key_id = "AKIAIOSFODNN7EXAMPLE"
        client.secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        client.session_token = None
        client.region_name = "us-east-1"
        return client

    @pytest.fixture
    def mock_session(self, tmp_path):
        session = Mock(spec=AuditSession)
        evidence_dir = tmp_path / "evidence" / "ecr"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        session.get_evidence_path.return_value = evidence_dir
        return session

    def test_skill_name(self, skill):
        assert skill.name == "ecr"

    def test_collect_writes_expected_files(self, skill, mock_aws_client, mock_session):
        with patch("boto3.Session") as mock_boto_session:
            mock_ecr = MagicMock()

            # Minimal registry calls
            mock_ecr.describe_registry.return_value = {"registryId": "123"}
            mock_ecr.get_registry_policy.side_effect = ClientError(
                {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
                "GetRegistryPolicy",
            )
            # SDK may expose either get_* or describe_*; set both to keep test stable.
            mock_ecr.get_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
            mock_ecr.describe_registry_scanning_configuration.return_value = {"scanType": "BASIC"}

            # No repositories
            paginator = MagicMock()
            paginator.paginate.return_value = [{"repositories": []}]
            mock_ecr.get_paginator.return_value = paginator

            mock_boto_session.return_value.client.side_effect = lambda service, **kwargs: (
                mock_ecr if service == "ecr" else MagicMock()
            )

            skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        expected = {
            "_audit_metadata.json",
            "registry.json",
            "repositories.json",
            "ecr-collection-status.json",
        }
        actual = {p.name for p in evidence_dir.glob("*.json")}
        assert expected.issubset(actual)

        # Basic structure check
        with open(evidence_dir / "repositories.json") as f:
            data = json.load(f)
        assert "repositories" in data

    def test_collect_registry_scanning_get_fallback(self, skill, mock_aws_client, mock_session):
        """If SDK doesn't expose describe_*, collector should fallback to get_*."""

        class _ECRStub:
            def describe_registry(self):
                return {"registryId": "123", "replicationConfiguration": {"rules": []}}

            def get_registry_policy(self):
                raise ClientError(
                    {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
                    "GetRegistryPolicy",
                )

            def get_registry_scanning_configuration(self):
                return {"scanningConfiguration": {"scanType": "BASIC"}}

            def get_paginator(self, name):
                p = MagicMock()
                p.paginate.return_value = [{"repositories": []}]
                return p

        with patch("boto3.Session") as mock_boto_session:
            mock_boto_session.return_value.client.side_effect = lambda service, **kwargs: (
                _ECRStub() if service == "ecr" else MagicMock()
            )

            skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        with open(evidence_dir / "registry.json") as f:
            reg = json.load(f)

        assert reg["registry_scanning"] == {"scanningConfiguration": {"scanType": "BASIC"}}

    def test_collect_registry_scanning_unsupported_sdk(self, skill, mock_aws_client, mock_session):
        """If boto3/botocore lacks registry scanning op, collector should not emit misleading errors."""

        class _ECRStub:
            def describe_registry(self):
                return {"registryId": "123", "replicationConfiguration": {"rules": []}}

            def get_registry_policy(self):
                raise ClientError(
                    {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
                    "GetRegistryPolicy",
                )

            def get_paginator(self, name):
                p = MagicMock()
                p.paginate.return_value = [{"repositories": []}]
                return p

        with patch("boto3.Session") as mock_boto_session:
            mock_boto_session.return_value.client.side_effect = lambda service, **kwargs: (
                _ECRStub() if service == "ecr" else MagicMock()
            )

            skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        with open(evidence_dir / "registry.json") as f:
            reg = json.load(f)

        assert reg["registry_scanning"]["error"] == "UnsupportedOperationInSDK"
