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


def _match_privatelink_service_enumeration(
    findings_by_skill: Dict[str, List[Finding]],
    resource_index: Dict[str, List[Finding]],
    evidence_by_skill: Dict[str, Any],
) -> bool:
    network_evidence = (
        evidence_by_skill.get("network", {}) if isinstance(evidence_by_skill, dict) else {}
    )
    doc = network_evidence.get("privatelink-endpoints") or {}
    endpoints = doc.get("endpoints", []) if isinstance(doc, dict) else []
    services = doc.get("services", []) if isinstance(doc, dict) else []
    return (
        isinstance(endpoints, list)
        and isinstance(services, list)
        and len(endpoints) > 0
        and len(services) > 0
    )


def _privatelink_attack_path(_: Dict[str, Any]) -> List[str]:
    return [
        "Attacker enumerates existing interface endpoints and endpoint services",
        "Maps reachable internal service surfaces via PrivateLink",
        "Abuses overly permissive endpoint/service policies for lateral access",
    ]


def _privatelink_remediation(_: Dict[str, Any]) -> List[str]:
    return [
        "Harden endpoint/service policies with explicit principals and conditions",
        "Limit endpoint creation/use to tightly scoped roles",
        "Continuously review PrivateLink topology and consumer accounts",
    ]


PATTERN_REGISTRY.register(
    DynamicCorrelationPattern(
        id="network_privatelink_lateral_enumeration",
        name="PrivateLink Lateral Enumeration Risk",
        description="PrivateLink topology can expose additional internal attack paths.",
        severity="Medium",
        skills_required=["network"],
        matcher=_match_privatelink_service_enumeration,
        attack_path_generator=_privatelink_attack_path,
        remediation_generator=_privatelink_remediation,
        threat_context=ThreatContext(
            mitre_attack_tactics=["TA0007", "TA0008"],
            mitre_attack_techniques=["T1046", "T1021"],
            observed_in_wild=False,
            exploit_maturity="Proof-of-Concept",
        ),
        exploitability=ExploitabilityInfo(
            exploitation_steps=[
                "List VPC endpoints and endpoint services",
                "Identify cross-account service consumers/providers",
            ],
            tools_required=["aws-cli"],
            exploitation_complexity="Medium",
            estimated_time_to_compromise="75 minutes",
        ),
        amplification_factor=1.2,
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
