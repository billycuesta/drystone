"""Reference schemas for evidence_snippet field by skill.

These are NOT enforced, but document expected structures for pattern matching.
"""
from typing import TypedDict, List, Optional


# IAM Evidence Snippets
class IAMUserSnippet(TypedDict, total=False):
    """Evidence for IAM user findings."""
    UserName: str
    Arn: str
    MFADevices: List[dict]  # Empty = no MFA
    AccessKeys: List[dict]  # [{AccessKeyId, Status, CreateDate}]
    PasswordLastUsed: Optional[str]


class IAMRoleSnippet(TypedDict, total=False):
    """Evidence for IAM role findings."""
    RoleName: str
    Arn: str
    AssumeRolePolicyDocument: dict


# Network Evidence Snippets
class NetworkSGSnippet(TypedDict, total=False):
    """Evidence for security group findings."""
    GroupId: str
    GroupName: str
    IpPermissions: List[dict]  # [{IpProtocol, FromPort, ToPort, IpRanges}]
    VpcId: str


# Exposure Evidence Snippets
class ExposureS3Snippet(TypedDict, total=False):
    """Evidence for S3 exposure findings."""
    Bucket: str
    PublicAccessBlockConfiguration: dict
    BucketPolicy: Optional[dict]


class ExposureRDSSnippet(TypedDict, total=False):
    """Evidence for RDS exposure findings."""
    DBInstanceIdentifier: str
    PubliclyAccessible: bool
    VpcSecurityGroups: List[dict]


# Vulns Evidence Snippets
class VulnsInspectorSnippet(TypedDict, total=False):
    """Evidence for vulnerability findings."""
    FindingArn: str
    Severity: str  # CRITICAL, HIGH, MEDIUM
    PackageVulnerabilityDetails: dict  # {VulnerabilityId, VulnerablePackages}


# Hardening Evidence Snippets
class HardeningConfigSnippet(TypedDict, total=False):
    """Evidence for hardening findings."""
    Service: str
    Configuration: dict
    Status: str  # ENABLED, DISABLED


"""
USAGE IN PATTERNS:

from drystone.correlation.evidence_schemas import IAMUserSnippet

def _extract_user_from_snippet(snippet: dict) -> Optional[str]:
    # Type hint guides IDE autocomplete
    if isinstance(snippet, dict):
        return snippet.get("UserName")
    return None
"""
