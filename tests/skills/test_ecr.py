"""Unit tests for ECR security skill."""

import json
from unittest.mock import MagicMock, Mock

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

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
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

        status = json.loads((evidence_dir / "ecr-collection-status.json").read_text())
        assert status["_schema"] == "drystone.collection_status.v1"
        assert status["_skill"] == "ecr"
        assert "ok" in status
        assert "errors" in status

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

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            _ECRStub() if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        with open(evidence_dir / "registry.json") as f:
            reg = json.load(f)

        assert reg["registry_scanning"] == {"scanningConfiguration": {"scanType": "BASIC"}}

    def test_collect_records_components_happy_path(self, skill, mock_aws_client, mock_session):
        """Both registry and repositories components should be ok on a clean collect()."""
        mock_ecr = MagicMock()
        mock_ecr.describe_registry.return_value = {"registryId": "123"}
        mock_ecr.get_registry_policy.side_effect = ClientError(
            {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
            "GetRegistryPolicy",
        )
        mock_ecr.get_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        mock_ecr.describe_registry_scanning_configuration.return_value = {"scanType": "BASIC"}

        paginator = MagicMock()
        paginator.paginate.return_value = [{"repositories": []}]
        mock_ecr.get_paginator.return_value = paginator

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            mock_ecr if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        status = json.loads((evidence_dir / "ecr-collection-status.json").read_text())
        assert status["components"]["registry"] == {"ok": True}
        assert status["components"]["repositories"] == {"ok": True}
        # Legacy keys must remain byte-compatible for category-C checks.
        assert status["ok"] is True
        assert status["errors"] == {"get_registry_policy": "RegistryPolicyNotFoundException"}

    def test_collect_records_registry_component_not_ok_on_describe_registry_failure(
        self, skill, mock_aws_client, mock_session
    ):
        mock_ecr = MagicMock()
        mock_ecr.describe_registry.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "DescribeRegistry"
        )
        mock_ecr.get_registry_policy.side_effect = ClientError(
            {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
            "GetRegistryPolicy",
        )
        mock_ecr.get_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        mock_ecr.describe_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        paginator = MagicMock()
        paginator.paginate.return_value = [{"repositories": []}]
        mock_ecr.get_paginator.return_value = paginator

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            mock_ecr if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        status = json.loads((evidence_dir / "ecr-collection-status.json").read_text())
        component = status["components"]["registry"]
        assert component["ok"] is False
        assert component["reason_code"] == "collection_failed"
        # Legacy key must remain byte-compatible.
        assert status["ok"] is False
        assert "describe_registry" in status["errors"]

    def test_collect_records_registry_component_partial_on_scanning_config_error(
        self, skill, mock_aws_client, mock_session
    ):
        """registry_scanning_configuration failures never flip legacy `ok` to False
        (existing behavior), but the new component must not stay ok=True after a
        swallowed error."""
        mock_ecr = MagicMock()
        mock_ecr.describe_registry.return_value = {"registryId": "123"}
        mock_ecr.get_registry_policy.side_effect = ClientError(
            {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
            "GetRegistryPolicy",
        )
        mock_ecr.describe_registry_scanning_configuration.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "DescribeRegistryScanningConfiguration",
        )
        paginator = MagicMock()
        paginator.paginate.return_value = [{"repositories": []}]
        mock_ecr.get_paginator.return_value = paginator

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            mock_ecr if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        status = json.loads((evidence_dir / "ecr-collection-status.json").read_text())
        component = status["components"]["registry"]
        assert component["ok"] is False
        assert component["reason_code"] == "partial_collection"
        # Legacy top-level ok stays True for this specific sub-call (existing behavior).
        assert status["ok"] is True

    def test_collect_records_repositories_component_collection_failed(
        self, skill, mock_aws_client, mock_session
    ):
        mock_ecr = MagicMock()
        mock_ecr.describe_registry.return_value = {"registryId": "123"}
        mock_ecr.get_registry_policy.side_effect = ClientError(
            {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
            "GetRegistryPolicy",
        )
        mock_ecr.get_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        mock_ecr.describe_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        mock_ecr.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "DescribeRepositories",
        )

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            mock_ecr if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        status = json.loads((evidence_dir / "ecr-collection-status.json").read_text())
        component = status["components"]["repositories"]
        assert component["ok"] is False
        assert component["reason_code"] == "collection_failed"

    def test_collect_records_repositories_component_partial_on_repo_policy_error(
        self, skill, mock_aws_client, mock_session
    ):
        """A per-repository policy lookup failure does not flip legacy `ok` to
        False (existing behavior), but the repositories component must reflect
        the coverage gap."""
        mock_ecr = MagicMock()
        mock_ecr.describe_registry.return_value = {"registryId": "123"}
        mock_ecr.get_registry_policy.side_effect = ClientError(
            {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
            "GetRegistryPolicy",
        )
        mock_ecr.get_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        mock_ecr.describe_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"repositories": [{"repositoryName": "repo-a", "repositoryArn": "arn:repo-a"}]}
        ]
        mock_ecr.get_paginator.return_value = paginator
        mock_ecr.get_repository_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "GetRepositoryPolicy",
        )
        mock_ecr.get_lifecycle_policy.side_effect = ClientError(
            {"Error": {"Code": "LifecyclePolicyNotFoundException", "Message": "not found"}},
            "GetLifecyclePolicy",
        )
        mock_ecr.list_tags_for_resource.return_value = {"tags": []}

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            mock_ecr if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        status = json.loads((evidence_dir / "ecr-collection-status.json").read_text())
        component = status["components"]["repositories"]
        assert component["ok"] is False
        assert component["reason_code"] == "partial_collection"
        # Legacy top-level ok is unaffected by repo_policy_errors (existing behavior).
        assert status["ok"] is True

    def test_collect_component_keys_match_written_evidence_stems(
        self, skill, mock_aws_client, mock_session
    ):
        mock_ecr = MagicMock()
        mock_ecr.describe_registry.return_value = {"registryId": "123"}
        mock_ecr.get_registry_policy.side_effect = ClientError(
            {"Error": {"Code": "RegistryPolicyNotFoundException", "Message": "not found"}},
            "GetRegistryPolicy",
        )
        mock_ecr.get_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        mock_ecr.describe_registry_scanning_configuration.return_value = {"scanType": "BASIC"}
        paginator = MagicMock()
        paginator.paginate.return_value = [{"repositories": []}]
        mock_ecr.get_paginator.return_value = paginator

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            mock_ecr if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        status = json.loads((evidence_dir / "ecr-collection-status.json").read_text())
        evidence_stems = {
            p.stem for p in evidence_dir.glob("*.json") if not p.name.endswith("-collection-status.json")
        }
        for component in status["components"]:
            assert component in evidence_stems

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

        mock_aws_client.boto3_session.return_value.client.side_effect = lambda service, **kwargs: (
            _ECRStub() if service == "ecr" else MagicMock()
        )

        skill.collect(mock_aws_client, mock_session)

        evidence_dir = mock_session.get_evidence_path.return_value
        with open(evidence_dir / "registry.json") as f:
            reg = json.load(f)

        assert reg["registry_scanning"]["error"] == "UnsupportedOperationInSDK"
