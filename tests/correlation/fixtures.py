"""Sample findings for correlation engine testing."""
from typing import Dict, List

from drystone.models.findings import Finding


def get_iam_no_mfa_findings() -> List[Finding]:
    """Return 3 IAM findings about missing MFA."""
    return [
        Finding(
            id="IAM-001",
            severity="Critical",
            risk_score=9.5,
            title="Root account has no MFA enabled",
            description="Root account must have MFA enabled to prevent unauthorized access.",
            evidence_refs=["root_user"],
            evidence_snippet={
                "UserName": "root",
                "Arn": "arn:aws:iam::123456789012:root",
                "MFADevices": []
            },
            affected_resources=["arn:aws:iam::123456789012:root"],
            remediation="Enable MFA on root account",
            cis_reference="1.5",
            pci_dss=[{"control": "8.4.1", "reason": "MFA required"}]
        ),
        Finding(
            id="IAM-007",
            severity="High",
            risk_score=8.0,
            title="IAM user admin lacks MFA protection",
            description="User admin has active access keys but no MFA configured.",
            evidence_refs=["users"],
            evidence_snippet={
                "UserName": "admin",
                "Arn": "arn:aws:iam::123456789012:user/admin",
                "AccessKeys": [{"AccessKeyId": "AKIA...", "Status": "Active"}],
                "MFADevices": []
            },
            affected_resources=["arn:aws:iam::123456789012:user/admin"],
            remediation="Enable MFA on user admin",
            cis_reference="1.7",
            pci_dss=[]
        ),
        Finding(
            id="IAM-008",
            severity="High",
            risk_score=8.0,
            title="IAM user developer lacks multi-factor authentication",
            description="Developer account active with no 2FA or MFA.",
            evidence_refs=["users"],
            evidence_snippet={
                "UserName": "developer",
                "Arn": "arn:aws:iam::123456789012:user/developer",
                "MFADevices": []
            },
            affected_resources=["arn:aws:iam::123456789012:user/developer"],
            remediation="Enable MFA on user",
            cis_reference=None
        )
    ]


def get_network_ssh_findings() -> List[Finding]:
    """Return 2 Network findings about exposed SSH."""
    return [
        Finding(
            id="NET-001",
            severity="Critical",
            risk_score=9.0,
            title="Security group allows SSH from 0.0.0.0/0",
            description="SSH (port 22) is open to the entire internet, allowing brute force attacks.",
            evidence_refs=["sg-123"],
            evidence_snippet={
                "GroupId": "sg-123",
                "GroupName": "web-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH"}]
                    }
                ]
            },
            affected_resources=["arn:aws:ec2:us-east-1:123456789012:security-group/sg-123"],
            remediation="Restrict SSH to bastion host IPs only",
            cis_reference="4.1"
        ),
        Finding(
            id="NET-012",
            severity="High",
            risk_score=7.5,
            title="ALB security group exposes SSH to public",
            description="Port 22 reachable from 0.0.0.0/0 on load balancer security group.",
            evidence_refs=["sg-456"],
            evidence_snippet={
                "GroupId": "sg-456",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            },
            affected_resources=["arn:aws:ec2:us-east-1:123456789012:security-group/sg-456"],
            remediation="Restrict source CIDR",
            cis_reference=None
        )
    ]


def get_exposure_public_s3_findings() -> List[Finding]:
    """Return 1 Exposure finding about public S3 bucket."""
    return [
        Finding(
            id="EXP-001",
            severity="Critical",
            risk_score=9.0,
            title="S3 bucket is publicly accessible",
            description="Bucket allows public read/write access, exposing sensitive data.",
            evidence_refs=["bucket-policy"],
            evidence_snippet={
                "Bucket": "sensitive-data-bucket",
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            },
            affected_resources=["arn:aws:s3:::sensitive-data-bucket"],
            remediation="Enable Block Public Access",
            cis_reference="3.1"
        )
    ]


def get_exposure_overprivileged_iam() -> List[Finding]:
    """Return 1 IAM finding about overprivileged access."""
    return [
        Finding(
            id="IAM-015",
            severity="Critical",
            risk_score=9.5,
            title="IAM role has wildcard S3 permissions (s3:*)",
            description="Role allows full S3 access on all buckets and actions.",
            evidence_refs=["role-policy"],
            evidence_snippet={
                "RoleName": "lambda-executor",
                "AssumeRolePolicyDocument": {},
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "*"
                        }
                    ]
                }
            },
            affected_resources=["arn:aws:iam::123456789012:role/lambda-executor"],
            remediation="Restrict to specific S3 actions and buckets",
            cis_reference=None
        )
    ]


def get_vulns_critical_findings() -> List[Finding]:
    """Return 1 Vuln finding about critical CVE."""
    return [
        Finding(
            id="VUL-042",
            severity="Critical",
            risk_score=9.5,
            title="Critical CVE-2024-12345 detected on EC2 instance",
            description="Ubuntu 20.04 package vulnerable to remote code execution.",
            evidence_refs=["vulnerability-detail"],
            evidence_snippet={
                "FindingArn": "arn:aws:inspector:us-east-1:123456789012:finding/abc123",
                "Severity": "CRITICAL",
                "PackageVulnerabilityDetails": {
                    "VulnerabilityId": "CVE-2024-12345",
                    "VulnerablePackages": [
                        {"Name": "openssh-server", "Version": "7.4"}
                    ]
                }
            },
            affected_resources=["arn:aws:ec2:us-east-1:123456789012:instance/i-12345"],
            remediation="Update openssh-server to latest version",
            cis_reference=None
        )
    ]


def get_hardening_no_patch_manager() -> List[Finding]:
    """Return 1 Hardening finding about missing patch automation."""
    return [
        Finding(
            id="HRD-002",
            severity="High",
            risk_score=8.0,
            title="Systems Manager Patch Manager not configured",
            description="Automated patching disabled, vulnerabilities may persist.",
            evidence_refs=["ssm-config"],
            evidence_snippet={
                "Service": "Systems Manager",
                "Configuration": "Patch Manager",
                "Status": "DISABLED"
            },
            affected_resources=[],  # Account-level
            remediation="Enable Systems Manager Patch Manager",
            cis_reference=None
        )
    ]


def get_all_sample_findings() -> Dict[str, List[Finding]]:
    """Return dict of all sample findings by skill."""
    return {
        "iam": get_iam_no_mfa_findings() + get_exposure_overprivileged_iam(),
        "network": get_network_ssh_findings(),
        "exposure": get_exposure_public_s3_findings(),
        "vulns": get_vulns_critical_findings(),
        "hardening": get_hardening_no_patch_manager()
    }
