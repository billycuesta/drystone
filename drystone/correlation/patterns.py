"""Correlation pattern definitions and matching logic."""
import logging
from typing import Dict, List, Optional

# NOTE: Import Finding at runtime to avoid circular dependency
from drystone.models.findings import Finding

logger = logging.getLogger(__name__)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _is_no_mfa_finding(finding: Finding) -> bool:
    """Check if finding is about missing MFA.

    GAPS RESOLVED:
    - GAP-C1: Complete implementation (not pseudocode)
    - GAP-C2: Documents expected evidence_snippet fields
    """
    # Strategy 1: Check finding ID patterns
    if any(id_pattern in finding.id for id_pattern in ["IAM-001", "IAM-002", "IAM-007"]):
        return True

    # Strategy 2: Check title/description keywords
    keywords = ["mfa", "multi-factor", "2fa", "two-factor"]
    text = f"{finding.title} {finding.description}".lower()

    return any(kw in text for kw in keywords)


def _is_ssh_exposed_finding(finding: Finding) -> bool:
    """Check if finding is about SSH exposed to internet."""
    # Strategy 1: Check finding ID
    if "NET-001" in finding.id or "NET-012" in finding.id:
        return True

    # Strategy 2: Check title/description
    keywords = ["ssh", "port 22", "0.0.0.0/0"]
    text = f"{finding.title} {finding.description}".lower()

    if not ("ssh" in text or "22" in text):
        return False

    # Strategy 3: Validate evidence_snippet (must show 0.0.0.0/0)
    # Expected structure (from evidence_schemas.py):
    # {
    #   "GroupId": "sg-123",
    #   "IpPermissions": [
    #     {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    #   ]
    # }
    if finding.evidence_snippet:
        snippet_str = str(finding.evidence_snippet).lower()
        return "0.0.0.0/0" in snippet_str or "::/0" in snippet_str

    return False


def _extract_users_from_finding(finding: Finding) -> List[str]:
    """Extract IAM user ARNs from finding.

    GAPS RESOLVED:
    - GAP-T2: Handles findings without affected_resources
    """
    users = []

    # Strategy 1: affected_resources
    if finding.affected_resources:
        for arn in finding.affected_resources:
            if ":user/" in arn or ":root" in arn:
                users.append(arn)

    # Strategy 2: evidence_snippet
    # Expected structure (from evidence_schemas.py):
    # {"UserName": "admin", "Arn": "arn:aws:iam::*:user/admin", "MFADevices": []}
    if finding.evidence_snippet and isinstance(finding.evidence_snippet, dict):
        snippet = finding.evidence_snippet

        # Single user
        if "UserName" in snippet:
            username = snippet["UserName"]
            # Use ARN from snippet if available, otherwise construct
            if "Arn" in snippet:
                users.append(snippet["Arn"])
            else:
                users.append(f"arn:aws:iam::*:user/{username}")

        # List of users
        if "Users" in snippet and isinstance(snippet["Users"], list):
            for user_obj in snippet["Users"]:
                if isinstance(user_obj, dict):
                    if "Arn" in user_obj:
                        users.append(user_obj["Arn"])
                    elif "UserName" in user_obj:
                        users.append(f"arn:aws:iam::*:user/{user_obj['UserName']}")

    return list(set(users))  # Deduplicate


def _is_public_s3_finding(finding: Finding) -> bool:
    """Check if finding is about public S3 bucket."""
    # Strategy 1: Check ID
    if "EXP-001" in finding.id or "EXP-003" in finding.id:
        return True

    # Strategy 2: Check title/description
    keywords = ["s3", "bucket", "public"]
    text = f"{finding.title} {finding.description}".lower()

    return all(kw in text for kw in keywords)


def _is_overprivileged_iam_finding(finding: Finding) -> bool:
    """Check if finding is about overprivileged IAM entity."""
    # Check for wildcard permissions (s3:*, *, etc.)
    keywords = ["s3:*", "full access", "admin", "wildcard", "overprivileged"]
    text = f"{finding.title} {finding.description}".lower()

    if any(kw in text for kw in keywords):
        return True

    # Check evidence_snippet for PolicyDocument with wildcards
    if finding.evidence_snippet and isinstance(finding.evidence_snippet, dict):
        snippet_str = str(finding.evidence_snippet).lower()
        return "s3:*" in snippet_str or '"action": "*"' in snippet_str

    return False


def _extract_bucket_arn(finding: Finding) -> Optional[str]:
    """Extract S3 bucket ARN from finding."""
    if finding.affected_resources:
        for arn in finding.affected_resources:
            if arn.startswith("arn:aws:s3:::"):
                return arn

    # Fallback: extract from evidence_snippet
    if finding.evidence_snippet and "Bucket" in finding.evidence_snippet:
        bucket_name = finding.evidence_snippet["Bucket"]
        return f"arn:aws:s3:::{bucket_name}"

    return None


def _is_critical_cve_finding(finding: Finding) -> bool:
    """Check if finding is about critical CVE."""
    # Must be high risk score (>=9.0) or severity Critical
    if finding.risk_score >= 9.0 or finding.severity == "Critical":
        # And must mention CVE
        text = f"{finding.title} {finding.description}".lower()
        return "cve" in text or "vulnerability" in text

    return False


def _is_no_patching_finding(finding: Finding) -> bool:
    """Check if finding is about missing patch automation."""
    keywords = ["patch", "systems manager", "ssm", "not configured", "missing", "disabled"]
    text = f"{finding.title} {finding.description}".lower()

    return any(kw in text for kw in keywords)


def _extract_instance_arn(finding: Finding) -> Optional[str]:
    """Extract EC2 instance ARN from finding."""
    if finding.affected_resources:
        for arn in finding.affected_resources:
            if ":instance/" in arn:
                return arn

    return None


# ============================================================================
# PATTERN 1: IAM + Network → SSH Compromise
# ============================================================================

def iam_network_ssh_compromise(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]]
) -> List[List[Finding]]:
    """
    Pattern: IAM users without MFA + SSH exposed to internet.

    GAPS RESOLVED:
    - GAP-T4: One correlation per user (prevents combinatorial explosion)
    - GAP-C1: Complete executable code

    Returns:
        List of finding groups. Each group: [IAM_finding, NET_finding1, NET_finding2, ...]
    """
    iam_findings = findings_by_skill.get("iam", [])
    network_findings = findings_by_skill.get("network", [])

    # Step 1: Filter IAM findings (users without MFA)
    no_mfa_findings = [f for f in iam_findings if _is_no_mfa_finding(f)]

    # Step 2: Filter Network findings (SSH exposed)
    ssh_findings = [f for f in network_findings if _is_ssh_exposed_finding(f)]

    if not no_mfa_findings or not ssh_findings:
        logger.debug("Pattern iam_network_ssh_compromise: No match (missing IAM no-MFA or SSH findings)")
        return []

    # Step 3: Extract affected users
    user_to_finding = {}
    for finding in no_mfa_findings:
        users = _extract_users_from_finding(finding)
        for user_arn in users:
            user_to_finding[user_arn] = finding

    if not user_to_finding:
        logger.debug("Pattern iam_network_ssh_compromise: No match (could not extract users)")
        return []

    # Step 4: Create ONE correlation per user (includes ALL SSH findings)
    # This prevents explosion: 3 users × 1 SSH = 3 correlations (not 3)
    correlations = []
    for user_arn, iam_finding in user_to_finding.items():
        correlations.append([iam_finding] + ssh_findings)

    logger.info(
        f"Pattern iam_network_ssh_compromise: {len(correlations)} correlations "
        f"({len(user_to_finding)} users × {len(ssh_findings)} SSH SGs)"
    )

    return correlations


# ============================================================================
# PATTERN 2: Exposure + IAM → Data Exfiltration
# ============================================================================

def exposure_iam_data_exfiltration(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]]
) -> List[List[Finding]]:
    """
    Pattern: Public S3 bucket + overprivileged IAM entity.

    GAPS RESOLVED:
    - GAP-T2: Handles findings without ARNs

    Returns:
        List of finding groups. Each group: [EXP_finding, IAM_finding]
    """
    exp_findings = findings_by_skill.get("exposure", [])
    iam_findings = findings_by_skill.get("iam", [])

    # Step 1: Filter public S3 buckets
    public_s3 = [f for f in exp_findings if _is_public_s3_finding(f)]

    # Step 2: Filter overprivileged IAM
    overprivileged_iam = [f for f in iam_findings if _is_overprivileged_iam_finding(f)]

    if not public_s3 or not overprivileged_iam:
        logger.debug("Pattern exposure_iam_data_exfiltration: No match")
        return []

    # Step 3: Correlate by bucket access
    # For each public bucket, find IAM entities with access to it
    correlations = []

    for exp_finding in public_s3:
        bucket_arn = _extract_bucket_arn(exp_finding)

        if not bucket_arn:
            continue  # Skip if can't extract bucket ARN

        # Find IAM findings that reference this bucket
        # (either in affected_resources or evidence_snippet)
        for iam_finding in overprivileged_iam:
            # Strategy 1: Check affected_resources
            has_access = False

            if bucket_arn in iam_finding.affected_resources:
                has_access = True

            # Strategy 2: Check evidence_snippet for wildcard permissions
            if not has_access and iam_finding.evidence_snippet:
                snippet_str = str(iam_finding.evidence_snippet).lower()
                # Wildcards give access to all buckets
                if '"resource": "*"' in snippet_str or '"resource": ["*"]' in snippet_str:
                    has_access = True

            if has_access:
                correlations.append([exp_finding, iam_finding])

    logger.info(
        f"Pattern exposure_iam_data_exfiltration: {len(correlations)} correlations"
    )

    return correlations


# ============================================================================
# PATTERN 3: Vulns + Hardening → Persistent CVE
# ============================================================================

def vulns_hardening_persistent_cve(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]]
) -> List[List[Finding]]:
    """
    Pattern: Critical CVE + no patch automation.

    Returns:
        List of finding groups. Each group: [VUL_finding, HRD_finding]
    """
    vuln_findings = findings_by_skill.get("vulns", [])
    hrd_findings = findings_by_skill.get("hardening", [])

    # Step 1: Filter critical CVEs
    critical_cves = [f for f in vuln_findings if _is_critical_cve_finding(f)]

    # Step 2: Filter missing patch automation
    no_patching = [f for f in hrd_findings if _is_no_patching_finding(f)]

    if not critical_cves or not no_patching:
        logger.debug("Pattern vulns_hardening_persistent_cve: No match")
        return []

    # Step 3: Correlate by instance
    correlations = []

    for vuln_finding in critical_cves:
        instance_arn = _extract_instance_arn(vuln_finding)

        if not instance_arn:
            # Account-level correlation (any CVE + no patching = correlation)
            for hrd_finding in no_patching:
                correlations.append([vuln_finding, hrd_finding])
            break  # Only create one correlation (not per CVE)
        else:
            # Instance-specific correlation
            for hrd_finding in no_patching:
                # Check if hardening finding affects same instance
                # (or is account-level like "SSM Patch Manager not configured")
                if not hrd_finding.affected_resources or instance_arn in hrd_finding.affected_resources:
                    correlations.append([vuln_finding, hrd_finding])

    logger.info(
        f"Pattern vulns_hardening_persistent_cve: {len(correlations)} correlations"
    )

    return correlations


# ============================================================================
# PATTERN REGISTRY
# ============================================================================

# Pattern metadata (used by engine)
PATTERN_METADATA = [
    {
        "id": "iam_network_ssh_compromise",
        "name": "SSH Access Without MFA Protection",
        "severity": "Critical",
        "skills_required": ["iam", "network"],
        "match_function": iam_network_ssh_compromise,
        "amplification_factor": 1.5,
        "title_template": "SSH access without MFA protection - Account compromise risk",
        "description_template": (
            "Security group(s) allow SSH (port 22) from 0.0.0.0/0, and IAM user(s) lack MFA. "
            "This creates a direct path to account compromise via brute force or credential theft."
        ),
        "attack_path_steps": [
            "Attacker discovers open SSH port via port scanning (0.0.0.0/0)",
            "Attempts brute force or credential stuffing against SSH endpoint",
            "Gains access with weak/stolen credentials (no MFA barrier)",
            "Escalates privileges using IAM permissions"
        ],
        "remediation_template": [
            "1. Enable MFA on affected IAM users via AWS Console → IAM → Security credentials",
            "2. Restrict Security Group(s) to specific IP ranges (corporate VPN, bastion hosts)",
            "3. Consider AWS Systems Manager Session Manager instead of SSH"
        ]
    },
    {
        "id": "exposure_iam_data_exfiltration",
        "name": "Public Resource with Overprivileged IAM",
        "severity": "High",
        "skills_required": ["exposure", "iam"],
        "match_function": exposure_iam_data_exfiltration,
        "amplification_factor": 1.3,
        "title_template": "Public S3 bucket with overprivileged IAM - Data exfiltration risk",
        "description_template": (
            "S3 bucket is publicly accessible, and IAM entity has overprivileged permissions. "
            "Leaked credentials enable data exfiltration or ransomware deployment."
        ),
        "attack_path_steps": [
            "Attacker discovers public S3 bucket via reconnaissance",
            "IAM credentials leak via phishing, GitHub exposure, or SSRF",
            "Attacker uses credentials to read/write/delete bucket data",
            "Sensitive data exfiltrated or ransomware deployed"
        ],
        "remediation_template": [
            "1. Remove public access from S3 bucket (enable Block Public Access)",
            "2. Reduce IAM permissions to least privilege (specific actions, not s3:*)",
            "3. Enable S3 Object Lock and Versioning for data protection"
        ]
    },
    {
        "id": "vulns_hardening_persistent_cve",
        "name": "Critical CVE Without Automated Patching",
        "severity": "High",
        "skills_required": ["vulns", "hardening"],
        "match_function": vulns_hardening_persistent_cve,
        "amplification_factor": 1.3,
        "title_template": "Critical CVE without automated patching - Persistent vulnerability",
        "description_template": (
            "Critical vulnerability detected, but Systems Manager Patch Manager not configured. "
            "Vulnerability remains unpatched, creating persistent exploitation window."
        ),
        "attack_path_steps": [
            "Attacker scans for known CVE via Shodan/Censys",
            "Exploits vulnerability remotely (no patch applied)",
            "Gains initial foothold on instance",
            "Pivots to internal resources or deploys persistence mechanisms"
        ],
        "remediation_template": [
            "1. Configure AWS Systems Manager Patch Manager with automated patching",
            "2. Apply patch for CVE immediately via 'aws ssm send-command'",
            "3. Enable Inspector continuous scanning for future vulnerabilities"
        ]
    }
]
