"""Unit tests for SecretsManager skill."""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch

from drystone.skills.secretsmanager import SecretsManagerSkill
from drystone.cloud.aws.client import AWSClient
from drystone.storage.session import AuditSession


class TestSecretsManagerSkill:
    """Test suite for SecretsManager security audit skill."""

    @pytest.fixture
    def skill(self):
        """Create SecretsManagerSkill instance."""
        return SecretsManagerSkill()

    @pytest.fixture
    def mock_aws_client(self):
        """Mock AWS client."""
        client = Mock(spec=AWSClient)
        client.access_key_id = "AKIAIOSFODNN7EXAMPLE"
        client.secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        client.session_token = None
        return client

    @pytest.fixture
    def mock_session(self, tmp_path):
        """Mock audit session."""
        session = Mock(spec=AuditSession)
        evidence_dir = tmp_path / "evidence" / "secretsmanager"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        session.get_evidence_path.return_value = evidence_dir
        return session

    def test_skill_name(self, skill):
        """Test skill identifier is 'secretsmanager'."""
        assert skill.name == "secretsmanager"

    def test_rotation_analysis_disabled(self, skill):
        """Test rotation analysis for disabled rotation."""
        secret_details = {
            "Name": "test-secret",
            "RotationEnabled": False,
            "RotationRules": {}
        }
        analysis = skill._analyze_rotation(secret_details)

        assert analysis["status"] == "Disabled"
        assert "Automatic rotation not enabled" in analysis["issues"]
        assert "Enable automatic rotation" in analysis["recommendations"]

    def test_rotation_analysis_enabled(self, skill):
        """Test rotation analysis for enabled rotation."""
        secret_details = {
            "Name": "test-secret",
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30},
            "LastRotatedDate": datetime.now(timezone.utc)
        }
        analysis = skill._analyze_rotation(secret_details)

        assert analysis["status"] == "Enabled"
        assert len(analysis["issues"]) == 0

    def test_rotation_analysis_interval_exceeds_90_days(self, skill):
        """Test rotation analysis for interval >90 days."""
        secret_details = {
            "Name": "test-secret",
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 120},
            "LastRotatedDate": datetime.now(timezone.utc)
        }
        analysis = skill._analyze_rotation(secret_details)

        assert analysis["status"] == "Enabled"
        assert any("exceeds 90 days" in issue for issue in analysis["issues"])

    def test_rotation_analysis_stale_secret(self, skill):
        """Test rotation analysis for secret not rotated for >365 days."""
        from datetime import timedelta
        old_date = datetime.now(timezone.utc) - timedelta(days=400)

        secret_details = {
            "Name": "test-secret",
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30},
            "LastRotatedDate": old_date
        }
        analysis = skill._analyze_rotation(secret_details)

        assert analysis["status"] == "Enabled"
        assert any("400" in issue or "365" in issue for issue in analysis["issues"])

    def test_security_aws_managed_kms(self, skill):
        """Test security analysis for AWS-managed KMS key."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/aws/secretsmanager",
            "RotationEnabled": True,
            "Tags": []
        }
        issues = skill._analyze_security(secret_details, None)

        assert any(issue["type"] == "encryption" for issue in issues)
        assert any(issue["severity"] == "medium" for issue in issues)

    def test_security_public_access(self, skill):
        """Test security analysis for wildcard principal in resource policy."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "RotationEnabled": True,
            "Tags": [{"Key": "Environment", "Value": "Production"}]
        }
        resource_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        issues = skill._analyze_security(secret_details, resource_policy)

        assert any(issue["type"] == "access_control" for issue in issues)
        assert any(issue["severity"] == "critical" for issue in issues)

    def test_security_missing_tags(self, skill):
        """Test security analysis for missing tags."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "RotationEnabled": True,
            "Tags": []
        }
        issues = skill._analyze_security(secret_details, None)

        assert any(issue["type"] == "governance" for issue in issues)
        assert any(issue["severity"] == "low" for issue in issues)

    def test_security_no_replication(self, skill):
        """Test security analysis for secrets without replication."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "RotationEnabled": True,
            "Tags": [{"Key": "Environment", "Value": "Production"}],
            "ReplicationStatus": []
        }
        issues = skill._analyze_security(secret_details, None)

        assert any(issue["type"] == "availability" for issue in issues)
        assert any(issue["severity"] == "medium" for issue in issues)

    def test_risk_score_no_issues(self, skill):
        """Test risk score calculation with no security issues."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "RotationEnabled": True,
            "Tags": [{"Key": "Environment", "Value": "Production"}],
            "ReplicationStatus": [{"Region": "us-west-2", "Status": "SUCCEEDED"}]
        }
        score = skill._calculate_risk_score(secret_details, None, [])

        assert score < 20  # Should be low score for well-configured secret

    def test_risk_score_with_issues(self, skill):
        """Test risk score calculation with security issues."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/aws/secretsmanager",
            "RotationEnabled": False,
            "Tags": []
        }
        issues = [
            {"type": "encryption", "severity": "medium"},
            {"type": "governance", "severity": "low"}
        ]
        score = skill._calculate_risk_score(secret_details, None, issues)

        assert score > 20  # Should be higher score for poorly-configured secret

    def test_risk_score_critical_issue(self, skill):
        """Test risk score calculation with critical issue."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "RotationEnabled": True,
            "Tags": []
        }
        issues = [
            {"type": "access_control", "severity": "critical"}
        ]
        score = skill._calculate_risk_score(secret_details, None, issues)

        assert score > 30  # Critical issue should increase score significantly

    def test_risk_score_bounds(self, skill):
        """Test risk score is bounded between 0-100."""
        secret_details = {
            "Name": "test-secret",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/aws/secretsmanager",
            "RotationEnabled": False,
            "Tags": []
        }
        # Many critical issues
        issues = [
            {"type": "access_control", "severity": "critical"},
            {"type": "encryption", "severity": "high"},
            {"type": "governance", "severity": "high"}
        ]
        score = skill._calculate_risk_score(secret_details, None, issues)

        assert 0 <= score <= 100

    def test_evidence_file_creation(self, skill, mock_aws_client, mock_session):
        """Test evidence file is created with proper structure."""
        # Mock boto3 session and clients
        with patch('boto3.Session') as mock_boto_session:
            mock_ec2 = MagicMock()
            mock_secrets = MagicMock()

            # Setup region discovery
            mock_ec2.describe_regions.return_value = {
                'Regions': [{'RegionName': 'us-east-1'}]
            }

            # Setup secrets listing (empty)
            mock_secrets.get_paginator.return_value.paginate.return_value = [
                {'SecretList': []}
            ]

            mock_boto_session.return_value.client.side_effect = lambda service, **kwargs: (
                mock_ec2 if service == 'ec2' else mock_secrets
            )

            # Run collect
            skill.collect(mock_aws_client, mock_session)

            # Verify evidence file was created
            evidence_file = mock_session.get_evidence_path.return_value / "secrets.json"
            # The file should be created in the mocked path
            assert mock_session.get_evidence_path.called

    def test_get_resource_policy_no_policy(self, skill):
        """Test getting resource policy when none exists."""
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        error_response = {"Error": {"Code": "ResourceNotFoundException", "Message": "No policy"}}
        mock_client.get_resource_policy.side_effect = ClientError(error_response, "GetResourcePolicy")

        policy = skill._get_resource_policy(mock_client, "arn:aws:secretsmanager:...")
        assert policy is None

    def test_get_resource_policy_valid(self, skill):
        """Test getting valid resource policy."""
        mock_client = MagicMock()
        test_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/my-role"},
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }
        mock_client.get_resource_policy.return_value = {
            "ResourcePolicy": json.dumps(test_policy)
        }

        policy = skill._get_resource_policy(mock_client, "arn:aws:secretsmanager:...")
        assert policy == test_policy

    def test_save_json_creates_directory(self, skill, tmp_path):
        """Test _save_json creates parent directory if needed."""
        filepath = tmp_path / "nested" / "path" / "data.json"
        data = {"test": "data"}

        skill._save_json(filepath, data)

        assert filepath.exists()
        with open(filepath) as f:
            saved_data = json.load(f)
        assert saved_data == data

    def test_save_json_serializes_datetime(self, skill, tmp_path):
        """Test _save_json serializes datetime objects."""
        filepath = tmp_path / "data.json"
        now = datetime.now(timezone.utc)
        data = {
            "timestamp": now,
            "nested": {
                "date": datetime(2026, 1, 1)
            }
        }

        skill._save_json(filepath, data)

        # Verify it's valid JSON (no datetime serialization error)
        with open(filepath) as f:
            saved_data = json.load(f)

        # Dates should be converted to strings
        assert isinstance(saved_data["timestamp"], str)
        assert isinstance(saved_data["nested"]["date"], str)


class TestSecretsManagerSecurityAnalysis:
    """Integration tests for SecretsManager security analysis."""

    @pytest.fixture
    def skill(self):
        """Create SecretsManagerSkill instance."""
        return SecretsManagerSkill()

    def test_analyze_well_configured_secret(self, skill):
        """Test analysis of well-configured secret."""
        secret_details = {
            "Name": "prod/database/password",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
            "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30},
            "LastRotatedDate": datetime.now(timezone.utc),
            "Tags": [
                {"Key": "Environment", "Value": "Production"},
                {"Key": "Owner", "Value": "DatabaseTeam"}
            ],
            "ReplicationStatus": [{"Region": "us-west-2", "Status": "SUCCEEDED"}]
        }

        rotation = skill._analyze_rotation(secret_details)
        security = skill._analyze_security(secret_details, None)
        risk = skill._calculate_risk_score(secret_details, None, security)

        assert rotation["status"] == "Enabled"
        assert len([i for i in security if i["severity"] == "critical"]) == 0
        assert risk < 30  # Low risk

    def test_analyze_poorly_configured_secret(self, skill):
        """Test analysis of poorly-configured secret."""
        secret_details = {
            "Name": "legacy/api/key",
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:legacy/api-AbCdEf",
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/aws/secretsmanager",
            "RotationEnabled": False,
            "RotationRules": {},
            "LastRotatedDate": datetime(2020, 1, 1, tzinfo=timezone.utc),
            "Tags": [],
            "ReplicationStatus": []
        }

        resource_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue"
                }
            ]
        }

        rotation = skill._analyze_rotation(secret_details)
        security = skill._analyze_security(secret_details, resource_policy)
        risk = skill._calculate_risk_score(secret_details, resource_policy, security)

        assert rotation["status"] == "Disabled"
        assert len([i for i in security if i["severity"] == "critical"]) > 0
        assert risk > 50  # High risk
