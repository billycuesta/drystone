"""Tests for correlation/evidence_schemas — TypedDict definitions."""

from drystone.correlation.evidence_schemas import (
    ExposureRDSSnippet,
    ExposureS3Snippet,
    HardeningConfigSnippet,
    IAMRoleSnippet,
    IAMUserSnippet,
    NetworkSGSnippet,
    VulnsInspectorSnippet,
)


class TestIAMUserSnippet:
    def test_full_construction(self):
        snippet: IAMUserSnippet = {
            "UserName": "alice",
            "Arn": "arn:aws:iam::123:user/alice",
            "MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}],
            "AccessKeys": [
                {"AccessKeyId": "AKIA...", "Status": "Active", "CreateDate": "2025-01-01"}
            ],
            "PasswordLastUsed": "2025-01-15",
        }
        assert snippet["UserName"] == "alice"
        assert snippet["MFADevices"] == [{"SerialNumber": "arn:aws:iam::123:mfa/alice"}]

    def test_partial_construction_total_false(self):
        """total=False means all keys are optional."""
        snippet: IAMUserSnippet = {"UserName": "bob"}
        assert snippet["UserName"] == "bob"

    def test_empty_construction(self):
        snippet: IAMUserSnippet = {}
        assert snippet.get("Arn") is None

    def test_no_mfa_pattern(self):
        snippet: IAMUserSnippet = {"UserName": "root", "MFADevices": [], "AccessKeys": []}
        assert snippet["MFADevices"] == []


class TestIAMRoleSnippet:
    def test_full_construction(self):
        snippet: IAMRoleSnippet = {
            "RoleName": "AdminRole",
            "Arn": "arn:aws:iam::123:role/AdminRole",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
        }
        assert snippet["RoleName"] == "AdminRole"

    def test_partial_construction(self):
        snippet: IAMRoleSnippet = {"RoleName": "ReadOnly"}
        assert snippet.get("Arn") is None


class TestNetworkSGSnippet:
    def test_full_construction(self):
        snippet: NetworkSGSnippet = {
            "GroupId": "sg-12345",
            "GroupName": "default",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
            "VpcId": "vpc-abc",
        }
        assert snippet["GroupId"] == "sg-12345"
        assert len(snippet["IpPermissions"]) == 1

    def test_empty_ip_permissions(self):
        snippet: NetworkSGSnippet = {"GroupId": "sg-00000", "IpPermissions": []}
        assert snippet["IpPermissions"] == []


class TestExposureS3Snippet:
    def test_public_bucket(self):
        snippet: ExposureS3Snippet = {
            "Bucket": "my-public-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "BucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
        }
        assert snippet["Bucket"] == "my-public-bucket"
        cfg = snippet["PublicAccessBlockConfiguration"]
        assert cfg["BlockPublicAcls"] is False

    def test_no_bucket_policy(self):
        snippet: ExposureS3Snippet = {
            "Bucket": "private-bucket",
            "PublicAccessBlockConfiguration": {"BlockPublicAcls": True},
            "BucketPolicy": None,
        }
        assert snippet["BucketPolicy"] is None


class TestExposureRDSSnippet:
    def test_public_rds(self):
        snippet: ExposureRDSSnippet = {
            "DBInstanceIdentifier": "prod-db",
            "PubliclyAccessible": True,
            "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-abc", "Status": "active"}],
        }
        assert snippet["PubliclyAccessible"] is True

    def test_private_rds(self):
        snippet: ExposureRDSSnippet = {
            "DBInstanceIdentifier": "internal-db",
            "PubliclyAccessible": False,
            "VpcSecurityGroups": [],
        }
        assert snippet["PubliclyAccessible"] is False


class TestVulnsInspectorSnippet:
    def test_full_construction(self):
        snippet: VulnsInspectorSnippet = {
            "FindingArn": "arn:aws:inspector2:us-east-1:123:finding/abc",
            "Severity": "CRITICAL",
            "PackageVulnerabilityDetails": {
                "VulnerabilityId": "CVE-2023-1234",
                "VulnerablePackages": [{"name": "openssl", "version": "1.0.0"}],
            },
        }
        assert snippet["Severity"] == "CRITICAL"
        assert snippet["PackageVulnerabilityDetails"]["VulnerabilityId"] == "CVE-2023-1234"

    def test_high_severity(self):
        snippet: VulnsInspectorSnippet = {"Severity": "HIGH"}
        assert snippet["Severity"] == "HIGH"


class TestHardeningConfigSnippet:
    def test_enabled_service(self):
        snippet: HardeningConfigSnippet = {
            "Service": "SecurityHub",
            "Configuration": {"AutoEnableControls": True},
            "Status": "ENABLED",
        }
        assert snippet["Status"] == "ENABLED"

    def test_disabled_service(self):
        snippet: HardeningConfigSnippet = {
            "Service": "GuardDuty",
            "Configuration": {},
            "Status": "DISABLED",
        }
        assert snippet["Status"] == "DISABLED"

    def test_partial_construction(self):
        snippet: HardeningConfigSnippet = {"Service": "Config"}
        assert snippet.get("Status") is None
