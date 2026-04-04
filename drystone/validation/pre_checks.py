"""Deterministic pre-checks executed BEFORE AI analysis.

Tier 1 of the 3-tier validation architecture:
  Tier 1: Pre-checks (deterministic, binary PASS/FAIL/SKIP)
  Tier 2: AI analysis (constrained by pre-computed facts)
  Tier 3: Post-validation (reconciliation + existing normalizer)

Each check function inspects raw evidence and returns a deterministic verdict.
The AI receives these verdicts as <pre_computed_facts> and must not contradict them.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PreCheckResult:
    """Result of a single deterministic pre-check."""

    check_id: str  # e.g. "IAM-001"
    status: str  # "PASS" | "FAIL" | "SKIP"
    evidence_summary: str  # e.g. "AccountMFAEnabled=0"
    affected_resources: List[str] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(
        default_factory=dict
    )  # structured extras (cve_details, attack_path, etc.)
    risk_score_override: Optional[float] = None  # overrides checklist severity-based score


# Type alias for check functions
PreCheckFn = Callable[[Dict[str, Any]], PreCheckResult]


# ---------------------------------------------------------------------------
# Registry: maps skill name → list of (check_id, check_function) pairs
# ---------------------------------------------------------------------------
PRE_CHECK_REGISTRY: Dict[str, List[PreCheckFn]] = {}


def _register(skill: str):
    """Decorator to register a pre-check function for a skill."""

    def decorator(fn: PreCheckFn) -> PreCheckFn:
        PRE_CHECK_REGISTRY.setdefault(skill, []).append(fn)
        return fn

    return decorator


# ---------------------------------------------------------------------------
# Impact narratives for deterministic pre-check findings.
# Used by the reconciler in base.py to populate the `impact` field on
# injected findings (pre-check FAIL → Finding). These are authoritative
# descriptions of what an attacker achieves by exploiting each finding.
# ---------------------------------------------------------------------------
PRE_CHECK_IMPACTS: Dict[str, str] = {
    # ── IAM ─────────────────────────────────────────────────────────────────
    "IAM-001": (
        "An attacker who compromises the root account gains unrestricted access to all AWS "
        "services and resources, including the ability to create backdoor IAM users, delete "
        "CloudTrail logs, and exfiltrate all data in the account.\n\n"
        "For a PCI DSS environment, root account compromise violates Requirement 7 (least "
        "privilege) and Requirement 8 (MFA for privileged accounts), potentially resulting "
        "in failed audits and regulatory penalties."
    ),
    "IAM-002": (
        "Console users without MFA are a single password away from full account access. "
        "Phishing or credential stuffing attacks are trivially successful against accounts "
        "protected only by a password, with no second factor to block unauthorized login.\n\n"
        "In a PCI DSS v4.0 context, absence of MFA for interactive users directly violates "
        "Requirement 8.4.2 (MFA for all non-console access into CDE)."
    ),
    "IAM-003": (
        "Inactive credentials are a persistent attack surface. If credentials are leaked "
        "(e.g., via GitHub secret scanning, phishing, or insider threat), a stale account "
        "with no recent activity is unlikely to trigger behavioral alerts, allowing prolonged "
        "unauthorized access without detection.\n\n"
        "Disabled accounts that retain active credentials extend the blast radius of any "
        "identity-related compromise beyond the active workforce."
    ),
    "IAM-004": (
        "An attacker who obtains a leaked or exposed access key with an active rotation gap "
        "has persistent programmatic access. If the key belongs to a privileged user, the "
        "attacker can enumerate the entire AWS environment and exfiltrate data without "
        "triggering console alerts.\n\n"
        "Long-lived credentials significantly increase the blast radius of credential "
        "exposure incidents, as organizations have no way to know when the key was first "
        "stolen."
    ),
    "IAM-030": (
        "Cross-account trust policies without ExternalId conditions are vulnerable to the "
        "'confused deputy' attack. Any AWS account that knows the role ARN can assume the "
        "role by impersonating a trusted service, bypassing all account boundary controls.\n\n"
        "This enables lateral movement from any AWS account that can discover the role ARN, "
        "which may be public through CloudTrail logs or AWS Config data."
    ),
    "IAM-033": (
        "Cross-account roles without an ExternalId condition allow any principal from the "
        "trusted account to assume the role. This expands the attack surface to all "
        "identities in the partner/vendor account, including potentially compromised ones.\n\n"
        "In a supply chain attack scenario, a compromised vendor account becomes an "
        "immediate pivot point into the target environment with no additional exploitation "
        "required."
    ),
    "IAM-040": (
        "Without restrictive Service Control Policies, any IAM principal with sufficient "
        "permissions can perform actions that bypass organizational guardrails. This includes "
        "creating admin users, disabling CloudTrail, or accessing data outside the "
        "authorized scope.\n\n"
        "SCPs are the last line of defense against privilege escalation within an AWS "
        "Organization. Without them, a single compromised account can escalate to "
        "organization-wide impact."
    ),
    "IAM-041": (
        "Any principal that can assume a role with AdministratorAccess immediately gains "
        "full account control. This creates a single-hop path to complete account compromise "
        "— no lateral movement required.\n\n"
        "In a PCI DSS context, overly privileged roles violate the principle of least "
        "privilege and expand the attack surface of the Cardholder Data Environment "
        "significantly."
    ),
    "IAM-043": (
        "Roles trusting AWS services without ExternalId or condition-based restrictions are "
        "vulnerable to confused deputy attacks. An attacker who can invoke the trusted "
        "service (e.g., Lambda, EC2) from any account can force it to assume the role on "
        "their behalf.\n\n"
        "This is particularly dangerous for roles used by compute services (Lambda, ECS), "
        "as the attacker only needs code execution in any function/container invoking that "
        "service role to pivot to the role's permissions."
    ),
    # ── RECON ────────────────────────────────────────────────────────────────
    "RECON-002": (
        "An unauthenticated attacker can invoke API Gateway endpoints directly, bypassing "
        "all authentication controls. This enables reconnaissance of backend logic, data "
        "extraction, and potentially business logic abuse without any credentials.\n\n"
        "In a payment processing context, unauthenticated API access to payment or "
        "transaction endpoints could expose customer financial data or allow unauthorized "
        "payment operations directly from the internet."
    ),
    "RECON-003": (
        "Elastic IPs attached to running instances expose those instances directly to the "
        "internet with a static, discoverable address. Combined with overly permissive "
        "security groups, this creates a direct attack surface for port scanning, "
        "exploitation, and brute-force attacks.\n\n"
        "Static IPs also appear in DNS records and certificate transparency logs, making "
        "them trivially discoverable by attackers."
    ),
    "RECON-005": (
        "Public Lambda Function URLs bypass API Gateway authentication and WAF inspection. "
        "Any code deployed at a public Lambda URL is directly reachable from the internet "
        "without any AWS authentication mechanism.\n\n"
        "Unauthenticated Lambda URLs are a common misconfiguration vector — if the function "
        "processes sensitive data or has broad IAM permissions, the exposure is equivalent "
        "to an unauthenticated admin API endpoint."
    ),
    "RECON-007": (
        "Load balancers without WAF protection are exposed to OWASP Top 10 web attacks "
        "including SQL injection, XSS, and request flooding. Without a WAF, there is no "
        "layer 7 defense to block malicious payloads before they reach the application.\n\n"
        "For PCI DSS compliance, WAF protection is mandatory for all web-facing components "
        "of the Cardholder Data Environment (Requirement 6.4.1)."
    ),
    "RECON-015": (
        "A high attack surface score indicates multiple exposed services with insufficient "
        "controls. Each exposed service is an independent attack vector — the compound risk "
        "of multiple simultaneous exposure findings significantly increases the probability "
        "of successful initial access.\n\n"
        "Attackers targeting the organization have multiple entry points to probe, increasing "
        "the likelihood of finding an exploitable vulnerability in at least one service."
    ),
    # ── EXPOSURE ─────────────────────────────────────────────────────────────
    "EXP-013": (
        "S3 buckets without enforced TLS encryption allow data in transit to be intercepted "
        "via man-in-the-middle attacks on any network path between clients and S3. For "
        "buckets containing sensitive data, this enables credential theft, data tampering, "
        "and session hijacking.\n\n"
        "PCI DSS Requirement 4.2.1 mandates encryption in transit for all cardholder data."
    ),
    "EXP-026": (
        "Publicly accessible S3 buckets can be enumerated and read by any internet user. "
        "If the bucket contains sensitive data (backups, logs, application data, PII), "
        "the attacker has immediate unauthenticated data access.\n\n"
        "Public S3 bucket misconfigurations account for a large proportion of cloud data "
        "breaches. The impact ranges from data theft to full credential compromise if the "
        "bucket contains configuration files or access keys."
    ),
    "EXP-028": (
        "Public EBS snapshots allow any AWS account to create a volume from the snapshot "
        "and mount it, gaining access to the full disk contents including operating system "
        "files, application data, credentials, and private keys.\n\n"
        "This is a critical finding — a single public snapshot can expose all data that "
        "existed on the disk at snapshot time, including database files, SSH keys, and "
        "application configuration with embedded secrets."
    ),
    # ── VULNS ────────────────────────────────────────────────────────────────
    "VULN-004": (
        "Active CVEs with exploits available represent validated, reproducible attack paths "
        "to the affected instances. Unlike theoretical vulnerabilities, these findings can "
        "be directly weaponized using publicly available proof-of-concept code.\n\n"
        "An attacker with network access to the affected instance can achieve code execution, "
        "privilege escalation, or data exfiltration depending on the specific CVE chain."
    ),
    "VULN-006": (
        "EC2 instances not enrolled in AWS Inspector continuous scanning have no automated "
        "vulnerability detection. Unscanned instances may have critical vulnerabilities that "
        "have been present for months without generating alerts.\n\n"
        "Without Inspector coverage, the organization has no visibility into the "
        "exploitability posture of its compute fleet, making remediation prioritization "
        "impossible."
    ),
    "VULN-008": (
        "HIGH severity findings without a documented remediation plan represent accepted "
        "risk without controls. Attackers can exploit these vulnerabilities knowing that "
        "no mitigation is in place and no timeline for remediation exists.\n\n"
        "In a PCI DSS context, unmitigated HIGH findings without compensating controls "
        "or documented risk acceptance violate Requirement 6.3.3 (all security "
        "vulnerabilities ranked)."
    ),
    "VULN-026": (
        "Terraform state files contain plaintext infrastructure secrets including database "
        "passwords, API keys, and service credentials embedded in resource definitions. "
        "An attacker with S3 read access can immediately obtain all credentials used during "
        "the last `terraform apply`.\n\n"
        "This finding has been exploited in the wild — it provides a direct path to lateral "
        "movement across all services whose credentials appear in the state file, without "
        "requiring any additional exploitation."
    ),
    "VULN-GD-001": (
        "GuardDuty disabled means no automated threat detection for the account. Malicious "
        "activity including credential abuse, C2 communication, crypto-mining, and data "
        "exfiltration will go undetected until manually discovered.\n\n"
        "Without GuardDuty, the mean time to detect (MTTD) for active intrusions increases "
        "dramatically. In a PCI DSS environment, lack of automated intrusion detection "
        "violates Requirement 10.7 (detect and report failures of critical security "
        "controls)."
    ),
    # ── NETWORK ──────────────────────────────────────────────────────────────
    "NET-EGR-001": (
        "Security groups with unrestricted egress (0.0.0.0/0 on all protocols) allow "
        "compromised instances to communicate with any external host. This enables "
        "data exfiltration, C2 beaconing, and lateral movement to other AWS services "
        "or internet endpoints without restriction.\n\n"
        "Unrestricted egress significantly increases the post-exploitation impact of any "
        "initial access — an attacker who gains code execution on one instance can "
        "immediately reach all other network destinations."
    ),
    "NET-007": (
        "Security groups allowing unrestricted inbound access (0.0.0.0/0) on sensitive "
        "ports expose services directly to the internet. This eliminates the network "
        "perimeter as a defense layer, relying entirely on application-level authentication "
        "to prevent unauthorized access.\n\n"
        "Internet-facing management ports (SSH/22, RDP/3389) are continuously scanned by "
        "automated attack infrastructure and are typically exploited within hours of "
        "becoming public."
    ),
}

# ---------------------------------------------------------------------------
# PRE_CHECK_ANALOGIES — Physical-world security analogies for pre-check findings.
# Used by the reconciler in base.py to populate the `security_analogy` field on
# injected findings, making technical risks accessible to non-technical stakeholders.
# ---------------------------------------------------------------------------
PRE_CHECK_ANALOGIES: Dict[str, str] = {
    # ── IAM ─────────────────────────────────────────────────────────────────
    "IAM-001": (
        "Like leaving the master key to an entire building on the reception desk "
        "with no lock, no guard, and no camera — anyone who picks it up owns everything."
    ),
    "IAM-002": (
        "Like protecting a bank vault with only a 4-digit PIN and no security guard — "
        "a single stolen password is all it takes to walk in."
    ),
    "IAM-003": (
        "Like keeping copies of old office keys that still open every door — "
        "a forgotten key found by a stranger grants full access."
    ),
    "IAM-004": (
        "Like never changing the locks after giving a copy of the key to a contractor "
        "who finished their project months ago."
    ),
    "IAM-005": ("Like allowing '1234' as the combination to a safe that holds company finances."),
    "IAM-007": (
        "Like taping handwritten permission slips directly onto employee badges instead of "
        "using a centralized access control system — impossible to audit or revoke."
    ),
    "IAM-008": (
        "Like issuing a skeleton key that opens every room in the building, including the vault, "
        "server room, and CEO's office."
    ),
    "IAM-009": (
        "Like the building owner carrying a set of master keys while walking through a crowded "
        "market — if pickpocketed, the thief has unrestricted access to every room."
    ),
    "IAM-010": (
        "Like giving the building superintendent a master key but not requiring them to show "
        "ID when entering — anyone who looks the part can walk in."
    ),
    "IAM-011": (
        "Like posting an open invitation on a public bulletin board: 'Anyone can use our "
        "building — no ID required.'"
    ),
    "IAM-012": (
        "Like keeping active badges for employees who left the company months ago — "
        "their badges still open every door."
    ),
    "IAM-014": (
        "Like giving an employee two separate sets of building keys — if one set is stolen, "
        "you might not even notice because the other set still works."
    ),
    "IAM-020": (
        "Like assigning permissions to individuals instead of departments — when someone "
        "moves teams, their old access lingers because nobody tracks it centrally."
    ),
    "IAM-029": (
        "Like a chain of delegated authorities where a janitor can promote themselves to "
        "building manager by exploiting a series of trust relationships."
    ),
    "IAM-030": (
        "Like accepting any delivery driver who claims to be from a trusted courier — "
        "without verifying their ID badge, an impersonator walks right in."
    ),
    "IAM-032": (
        "Like accepting any employee badge from a partner company without checking the photo — "
        "a stolen badge from any partner grants access."
    ),
    "IAM-033": (
        "Like signing a contract that says 'anyone from Company X can enter our vault' instead "
        "of 'only John from Company X, with badge #4521, can enter.'"
    ),
    "IAM-040": (
        "Like a corporate headquarters with no security policy — each department sets its own "
        "rules, and some departments have no rules at all."
    ),
    "IAM-041": (
        "Like giving a master key to every department head with no log of who uses it or when "
        "— a single compromised key holder means total building access."
    ),
    "IAM-042": (
        "Like having a fire escape that bypasses all security checkpoints — useful in an "
        "emergency but devastating if an intruder finds it."
    ),
    "IAM-043": (
        "Like a trusted delivery service that can open any door in the building on behalf of "
        "its customers — a compromised driver gains access to every room."
    ),
    # ── RECON ────────────────────────────────────────────────────────────────
    "RECON-002": (
        "Like putting a service window on the street with no cashier and no security camera — "
        "anyone can walk up and place orders anonymously."
    ),
    "RECON-003": (
        "Like having your home address publicly listed with the front door unlocked — "
        "anyone can find you and walk in."
    ),
    "RECON-004": (
        "Like posting your building's floor plan on a public bulletin board — attackers "
        "can map your infrastructure before attempting entry."
    ),
    "RECON-005": (
        "Like installing a backdoor directly to the street with no receptionist — "
        "anyone who finds it walks straight into the office."
    ),
    "RECON-007": (
        "Like removing the security screening at a building's main entrance — every visitor "
        "walks in unchecked, carrying whatever they want."
    ),
    "RECON-006": (
        "Like a building whose architectural plans are publicly available at city hall — "
        "an attacker can study every entrance, exit, and weak point before arriving."
    ),
    "RECON-008": (
        "Like a company that publishes its internal phone directory online — attackers "
        "know exactly who to impersonate and which extensions to call."
    ),
    "RECON-009": (
        "Like leaving a map of your security camera blind spots on the front desk — "
        "attackers know precisely where they will not be seen."
    ),
    "RECON-010": (
        "Like a building that advertises its alarm vendor and model on the front door — "
        "attackers can research known bypasses before attempting entry."
    ),
    "RECON-012": (
        "Like printing your building's maintenance schedule on a public sign — "
        "an attacker knows exactly when the guards change and the cameras reboot."
    ),
    "RECON-015": (
        "Like a building with multiple unlocked entrances on different streets — the more "
        "doors you leave open, the harder it is to watch them all."
    ),
    "RECON-019": (
        "Like labeling your vault door 'PCI VAULT' in a public directory — it tells attackers "
        "exactly where the valuable data is."
    ),
    # ── EXPOSURE ─────────────────────────────────────────────────────────────
    "EXP-006": (
        "Like a warehouse with loading docks open to the public street and no gate — "
        "anyone can drive up and start loading goods."
    ),
    "EXP-007": (
        "Like a database server sitting in a storefront window — visible and reachable "
        "to every passerby on the internet."
    ),
    "EXP-013": (
        "Like sending confidential documents via open postcard instead of sealed envelope — "
        "anyone along the delivery route can read them."
    ),
    "EXP-014": (
        "Like storing company blueprints in an unlocked public locker — anyone who knows "
        "the locker number can access them without identification."
    ),
    "EXP-015": (
        "Like a public filing cabinet that also accepts new documents from strangers — "
        "an attacker can plant malicious files alongside legitimate ones."
    ),
    "EXP-020": (
        "Like leaving a building's service entrance propped open with no camera or guard — "
        "it is technically accessible from the street but nobody is watching."
    ),
    "EXP-023": (
        "Like leaving a bank vault open with a sign saying 'anyone welcome' — no ID check, "
        "no access log."
    ),
    "EXP-024": (
        "Like a secure facility where the side gate has no lock because 'only employees "
        "know about it' — security through obscurity is not security."
    ),
    "EXP-026": (
        "Like storing sensitive files in an unlocked filing cabinet in the lobby — "
        "any visitor can browse through them."
    ),
    "EXP-028": (
        "Like throwing away a hard drive without wiping it — anyone who finds it in "
        "the dumpster has a complete copy of your data."
    ),
    # ── NETWORK ──────────────────────────────────────────────────────────────
    "NET-003": (
        "Like a building with no internal doors — once someone gets past the front entrance, "
        "they can walk freely into every room, including the vault."
    ),
    "NET-008": (
        "Like storing cash registers and safes in the lobby instead of behind the counter — "
        "critical assets are directly exposed to anyone who walks through the front door."
    ),
    "NET-007": (
        "Like removing the fence around a military base and posting signs for each building — "
        "anyone with a map can walk to any facility."
    ),
    "NET-010": (
        "Like a security checkpoint that only checks employee badges but lets anyone "
        "in a delivery uniform pass without verification."
    ),
    "NET-011": (
        "Like connecting two office buildings with an open hallway and no door — "
        "a breach in one building immediately compromises the other."
    ),
    "NET-016": (
        "Like a building with fire exits that also serve as unrestricted entrances — "
        "emergency routes become attack paths when they bypass security controls."
    ),
    "NET-022": (
        "Like having an office building entrance connected directly to your vault room "
        "without intermediate checkpoints — the entrance needs public access but valuables "
        "should be behind secured doors in restricted zones."
    ),
    "NET-025": (
        "Like a corporate campus where every building shares the same master key — "
        "compromising one lock compromises all facilities."
    ),
    "NET-EGR-001": (
        "Like having no exit inspection at a secure facility — a thief can walk out with "
        "anything and nobody will notice."
    ),
    # ── VULNS ────────────────────────────────────────────────────────────────
    "VULN-004": (
        "Like knowing the exact combination to a lock because someone published it online — "
        "exploits exist, and attackers have the recipe."
    ),
    "VULN-006": (
        "Like never sending a health inspector to check your restaurants — problems exist "
        "but nobody is looking for them."
    ),
    "VULN-008": (
        "Like knowing about a broken lock for months but never scheduling a locksmith — "
        "the problem is documented but nobody is fixing it."
    ),
    "VULN-009": (
        "Like a building where the fire alarm has a known defect but the manufacturer's patch "
        "has been sitting in a drawer for weeks — the fix exists but was never applied."
    ),
    "VULN-023": (
        "Like running an aging elevator that the manufacturer no longer services — "
        "when something breaks, there are no parts and no technician coming."
    ),
    "VULN-025": (
        "Like a security company that scans the lobby cameras but never checks the parking "
        "garage or loading dock — blind spots leave entire areas unmonitored."
    ),
    "VULN-026": (
        "Like storing all your building's alarm codes in a notebook labeled 'ALARM CODES' "
        "sitting on an unlocked shelf."
    ),
    "VULN-GD-001": (
        "Like disabling the alarm system in a jewelry store — burglars can operate "
        "freely because nothing will alert the police."
    ),
    # ── HARDENING ────────────────────────────────────────────────────────────
    "HRD-001": (
        "Like operating a building with no inventory of who entered, what changed, or "
        "when — you cannot detect tampering if you never recorded the baseline."
    ),
    "HRD-002": (
        "Like a security operations center that exists on paper but has no monitors "
        "plugged in — the infrastructure is there but nothing is being watched."
    ),
    "HRD-005": (
        "Like a hospital with critical alarms going off that nobody is responding to — "
        "the most urgent problems are being ignored."
    ),
    "HRD-007": (
        "Like a payment terminal that was never certified — it might work, but nobody "
        "has verified it meets the security standards required by law."
    ),
    "HRD-014": (
        "Like removing the motion sensors from a warehouse — intruders can move freely "
        "and nothing will trigger an alert."
    ),
    # ── ALERTING ─────────────────────────────────────────────────────────────
    "ALRT-001": (
        "Like a security camera system where the footage is recorded but nobody is watching "
        "the monitors — events happen but alerts never reach anyone."
    ),
    # ── SECRETS MANAGER ──────────────────────────────────────────────────────
    "SM-001": (
        "Like writing passwords on sticky notes and never replacing them — the longer "
        "a secret stays the same, the more likely it has been seen by the wrong person."
    ),
    "SM-012": (
        "Like a safe whose combination is shared verbally between employees — there is no "
        "record of who knows it, and no way to change it without telling everyone again."
    ),
    # ── ECR ──────────────────────────────────────────────────────────────────
    "ECR-001": (
        "Like shipping products without quality control — you are deploying containers "
        "that have never been inspected for defects."
    ),
}


def run_pre_checks(
    skill_name: str, evidence: Dict[str, Any], checklist: Dict[str, Any]
) -> List[PreCheckResult]:
    """Run all registered pre-checks for a skill.

    Args:
        skill_name: Skill identifier (e.g. 'iam', 'hardening')
        evidence: Evidence dict (file stems → parsed JSON)
        checklist: Checklist dict with 'items' array

    Returns:
        List of PreCheckResult for each check that could be evaluated
    """
    checks = PRE_CHECK_REGISTRY.get(skill_name.lower(), [])
    if not checks:
        return []

    results = []
    for check_fn in checks:
        try:
            result = check_fn(evidence)
            results.append(result)
        except Exception as e:
            # Pre-check failure → SKIP (let AI handle it)
            logger.debug(f"Pre-check {check_fn.__name__} failed: {e}")
    return results


def format_pre_checks_for_prompt(
    pre_checks: List[PreCheckResult], checklist: Optional[Dict[str, Any]] = None
) -> str:
    """Format pre-check results as XML for prompt injection.

    Args:
        pre_checks: List of pre-check results
        checklist: Optional checklist to look up severities

    Returns:
        XML string for SKILL_ADDENDUM injection
    """
    if not pre_checks:
        return ""

    # Build severity lookup from checklist
    severity_map: Dict[str, str] = {}
    if checklist and "items" in checklist:
        for item in checklist["items"]:
            if isinstance(item, dict) and "id" in item:
                severity_map[item["id"]] = item.get("severity", "Medium")

    lines = [
        "<pre_computed_facts>",
        "  <instructions>",
        "    These facts were verified deterministically against collected evidence.",
        "    They are AUTHORITATIVE — do not contradict them.",
        "    - For PASS items: DO NOT generate a finding (the check passed).",
        "    - For FAIL items: Generate a finding with professional description and remediation.",
        "    - For SKIP items: DO NOT generate a finding (the check is not applicable to this environment).",
        "    - For items NOT listed: Analyze evidence yourself.",
        "  </instructions>",
        "",
    ]

    for r in pre_checks:
        sev = severity_map.get(r.check_id, "")
        sev_attr = f' severity="{sev}"' if sev else ""
        resources = ""
        if r.affected_resources:
            resources = (
                f"\n    <affected_resources>{', '.join(r.affected_resources)}</affected_resources>"
            )
        lines.append(
            f'  <fact id="{r.check_id}" status="{r.status}"{sev_attr}>'
            f"\n    <evidence>{r.evidence_summary}</evidence>"
            f"{resources}"
            f"\n  </fact>"
        )

    lines.append("</pre_computed_facts>")
    return "\n".join(lines)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _get_summary_map(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Extract SummaryMap from account-summary evidence (handles both shapes)."""
    acct = evidence.get("account-summary", {})
    if not isinstance(acct, dict):
        return {}
    if "SummaryMap" in acct:
        sm = acct.get("SummaryMap")
        return sm if isinstance(sm, dict) else {}
    # Flattened shape (test fixtures)
    return acct


def _get_credential_report_by_user(evidence: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract by_user dict from credential-report evidence."""
    cred = evidence.get("credential-report")
    if isinstance(cred, dict):
        by_user = cred.get("by_user")
        if isinstance(by_user, dict):
            return by_user
    return {}


def _truthy(val: Any) -> bool:
    """Check if a value is truthy in the AWS evidence sense."""
    return val in {1, True, "1", "true", "True"}


def _falsy(val: Any) -> bool:
    """Check if a value is falsy in the AWS evidence sense."""
    return val in {0, False, "0", "false", "False"}


def _items_from_doc(doc: Any) -> list:
    """Extract items list from evidence doc (handles dict with 'items' or raw list)."""
    if isinstance(doc, dict) and isinstance(doc.get("items"), list):
        return doc["items"]
    if isinstance(doc, list):
        return doc
    return []


def _stmts_from_policy(policy: Any) -> list:
    """Extract Statement list from a policy document."""
    if not isinstance(policy, dict):
        return []
    stmts = policy.get("Statement")
    if isinstance(stmts, list):
        return stmts
    if isinstance(stmts, dict):
        return [stmts]
    return []


def _actions_from_stmt(stmt: Dict[str, Any]) -> List[str]:
    """Extract normalized action list from a statement."""
    a = stmt.get("Action")
    if isinstance(a, str):
        return [a]
    if isinstance(a, list):
        return [str(x) for x in a if x is not None]
    return []


def _principal_is_wildcard_any(principal: Any) -> bool:
    """Check if principal is '*' (public access)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and any(x == "*" for x in aws):
            return True
    return False


def _stmt_has_same_account_restriction(stmt: dict) -> bool:
    """Return True if the policy statement has a condition that restricts
    access to the same AWS account (AWS:SourceOwner or aws:SourceAccount).

    The default AWS SNS resource policy uses Principal:* + StringEquals
    AWS:SourceOwner = <account-id>, which is NOT a public exposure.
    """
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return False
    # Normalise keys to lower-case for comparison
    cond_lower = {k.lower(): v for k, v in cond.items()}
    # StringEquals or StringEqualsIgnoreCase operators
    for op_key in ("stringequals", "stringequalsignorecase"):
        op_val = cond_lower.get(op_key)
        if not isinstance(op_val, dict):
            continue
        for cond_key in op_val:
            if cond_key.lower() in (
                "aws:sourceowner",
                "aws:sourceaccount",
            ):
                return True
    return False


# ============================================================================
# IAM PRE-CHECKS
# ============================================================================


@_register("iam")
def check_iam_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Root account MFA enabled?"""
    summary_map = _get_summary_map(evidence)
    mfa = summary_map.get("AccountMFAEnabled")

    if _truthy(mfa):
        return PreCheckResult("IAM-001", "PASS", f"AccountMFAEnabled={mfa}", [])

    # Fallback: credential report
    by_user = _get_credential_report_by_user(evidence)
    for key in ("<root_account>", "root", "<root>"):
        root = by_user.get(key, {})
        if isinstance(root, dict) and _truthy(root.get("mfa_active")):
            return PreCheckResult("IAM-001", "PASS", "credential-report.mfa_active=true", [])

    return PreCheckResult("IAM-001", "FAIL", f"AccountMFAEnabled={mfa}", ["arn:aws:iam::*:root"])


@_register("iam")
def check_iam_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-002: IAM users with console access must have MFA enabled."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-002", "SKIP", "no users evidence", [])

    cred = evidence.get("credential-report", {})
    by_user: Dict[str, Any] = cred.get("by_user", {}) if isinstance(cred, dict) else {}

    affected: List[str] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("UserName") or "")
        row = by_user.get(uname, {})

        has_console = str(row.get("password_enabled", "false")).lower() == "true"
        # Users with active access keys also require MFA under PCI DSS 8.4.2
        has_active_keys = bool(u.get("AccessKeys"))
        if not has_console and not has_active_keys:
            continue

        has_mfa = bool(u.get("MFADevices"))
        if not has_mfa:
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)

    if affected:
        return PreCheckResult(
            "IAM-002",
            "FAIL",
            f"{len(affected)} user(s) without MFA (console or active access keys)",
            affected,
        )
    return PreCheckResult(
        "IAM-002", "PASS", "all users with console or active access keys have MFA enabled", []
    )


@_register("iam")
def check_iam_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-010: Administrative users must have MFA enabled."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-010", "SKIP", "no users evidence", [])

    _admin_policy_names = {"AdministratorAccess", "PowerUserAccess"}

    affected: List[str] = []
    for u in users:
        if not isinstance(u, dict):
            continue

        # Check if user has admin-level attached policy
        attached = u.get("AttachedPolicies") or []
        if not isinstance(attached, list):
            continue
        policy_names = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        is_admin = bool(policy_names & _admin_policy_names)
        if not is_admin:
            continue

        has_mfa = bool(u.get("MFADevices"))
        if not has_mfa:
            uname = str(u.get("UserName") or "")
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)

    if affected:
        return PreCheckResult(
            "IAM-010", "FAIL", f"{len(affected)} admin user(s) without MFA", affected
        )
    return PreCheckResult("IAM-010", "PASS", "all admin users have MFA enabled", [])


@_register("iam")
def check_iam_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Access keys should be rotated every 90 days."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-004", "SKIP", "no users evidence", [])

    now = datetime.now(timezone.utc)
    old_users = []
    for u in users:
        if not isinstance(u, dict):
            continue
        for k in u.get("AccessKeys", []) or []:
            if not isinstance(k, dict):
                continue
            if str(k.get("Status") or "").lower() != "active":
                continue
            cd = k.get("CreateDate")
            if not isinstance(cd, str) or not cd:
                continue
            try:
                created = datetime.fromisoformat(cd.replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            if (now - created).days > 90:
                uname = str(u.get("UserName") or "unknown")
                arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
                old_users.append(arn)
                break

    if not old_users:
        return PreCheckResult("IAM-004", "PASS", "no active keys >90 days", [])
    return PreCheckResult("IAM-004", "FAIL", f"{len(old_users)} users with old keys", old_users)


@_register("iam")
def check_iam_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """No policy should have full administrative permissions (*:*)."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-008", "SKIP", "no policies evidence", [])

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = [a.lower() for a in _actions_from_stmt(st)]
            if "*" not in acts and "iam:*" not in acts:
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            if not res_list or any(r == "*" for r in res_list):
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-008",
                    "FAIL",
                    f"Policy '{pname}' has Action:*/Resource:*",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-008", "PASS", "no wildcard admin policies", [])


@_register("iam")
def check_iam_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """Root account should not have active access keys."""
    summary_map = _get_summary_map(evidence)
    keys_present = summary_map.get("AccountAccessKeysPresent")

    if _falsy(keys_present):
        return PreCheckResult("IAM-009", "PASS", f"AccountAccessKeysPresent={keys_present}", [])

    # Fallback: credential report
    by_user = _get_credential_report_by_user(evidence)
    for key in ("<root_account>", "root", "<root>"):
        root = by_user.get(key, {})
        if isinstance(root, dict):
            k1 = root.get("access_key_1_active")
            k2 = root.get("access_key_2_active")
            if _falsy(k1) and _falsy(k2):
                return PreCheckResult(
                    "IAM-009", "PASS", "root keys inactive (credential-report)", []
                )

    return PreCheckResult(
        "IAM-009", "FAIL", f"AccountAccessKeysPresent={keys_present}", ["arn:aws:iam::*:root"]
    )


@_register("iam")
def check_iam_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Role trust policies should not allow public access (*)."""
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-011", "SKIP", "no roles evidence", [])

    for r in roles:
        if not isinstance(r, dict):
            continue
        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue
        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if _principal_is_wildcard_any(st.get("Principal")):
                rname = r.get("RoleName", "unknown")
                return PreCheckResult(
                    "IAM-011",
                    "FAIL",
                    f"Role '{rname}' trust has Principal:*",
                    [r.get("Arn", f"role/{rname}")],
                )

    return PreCheckResult("IAM-011", "PASS", "no public trust policies", [])


@_register("iam")
def check_iam_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """Inactive users (>90 days no activity) should be reviewed.

    Note: Root account inactivity is expected and excluded.
    """
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-012", "SKIP", "no users evidence", [])

    inactive = []
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = u.get("UserName", "")
        # Skip root
        if uname in ("<root_account>", "root"):
            continue
        arn = u.get("Arn", "")
        if isinstance(arn, str) and arn.endswith(":root"):
            continue

        last_used = u.get("PasswordLastUsed")
        has_keys = bool(u.get("AccessKeys"))
        if not last_used and not has_keys:
            inactive.append(f"arn:aws:iam::*:user/{uname}")

    if not inactive:
        return PreCheckResult("IAM-012", "PASS", "no inactive non-root users", [])
    return PreCheckResult("IAM-012", "FAIL", f"{len(inactive)} inactive users", inactive[:10])


@_register("iam")
def check_iam_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """Users should not have multiple active access keys."""
    users = evidence.get("users")
    if not isinstance(users, list):
        # Try credential report fallback
        by_user = _get_credential_report_by_user(evidence)
        if not by_user:
            return PreCheckResult("IAM-014", "SKIP", "no users/credential-report evidence", [])

        for uname, row in by_user.items():
            if not isinstance(row, dict):
                continue
            if _truthy(row.get("access_key_1_active")) and _truthy(row.get("access_key_2_active")):
                return PreCheckResult("IAM-014", "FAIL", f"User '{uname}' has 2 active keys", [])
        return PreCheckResult("IAM-014", "PASS", "no users with multiple active keys", [])

    multi = []
    for u in users:
        if not isinstance(u, dict):
            continue
        keys = u.get("AccessKeys")
        if not isinstance(keys, list):
            continue
        active = [
            k
            for k in keys
            if isinstance(k, dict) and str(k.get("Status") or "").lower() == "active"
        ]
        if len(active) >= 2:
            uname = u.get("UserName", "unknown")
            multi.append(f"arn:aws:iam::*:user/{uname}")

    if not multi:
        return PreCheckResult("IAM-014", "PASS", "no users with multiple active keys", [])
    return PreCheckResult("IAM-014", "FAIL", f"{len(multi)} users with 2+ active keys", multi[:10])


@_register("iam")
def check_iam_020(evidence: Dict[str, Any]) -> PreCheckResult:
    """Users should belong to at least one group."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-020", "SKIP", "no users evidence", [])

    ungrouped = []
    for u in users:
        if not isinstance(u, dict):
            continue
        groups = u.get("Groups")
        if isinstance(groups, list) and len(groups) == 0:
            # Use the full ARN from evidence if available (avoids * wildcard in account ID)
            arn = str(u.get("Arn") or "")
            if not arn:
                uname = u.get("UserName", "unknown")
                arn = f"arn:aws:iam::*:user/{uname}"
            ungrouped.append(arn)

    if not ungrouped:
        return PreCheckResult("IAM-020", "PASS", "all users belong to groups", [])
    return PreCheckResult(
        "IAM-020", "FAIL", f"{len(ungrouped)} users without groups", ungrouped[:10]
    )


@_register("iam")
def check_iam_029(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-029: Detect privilege escalation via cross-role AssumeRole chains.

    Flags roles that can be assumed by another IAM role (not a service) AND
    have AdministratorAccess or iam:* permissions attached — the classic
    'hop-to-admin' privilege escalation path.
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-029", "SKIP", "no roles evidence", [])

    _admin_policies = {"AdministratorAccess", "PowerUserAccess"}

    # Build a map: role ARN → attached policy names
    role_policies: Dict[str, set] = {}
    for r in roles:
        if not isinstance(r, dict):
            continue
        arn = str(r.get("Arn") or "")
        attached = r.get("AttachedPolicies") or []
        pnames = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        role_policies[arn] = pnames

    affected: List[str] = []
    for r in roles:
        if not isinstance(r, dict):
            continue
        role_arn = str(r.get("Arn") or "")

        # Does this role have admin-level policies?
        if not (role_policies.get(role_arn, set()) & _admin_policies):
            continue

        # Is it trusted by another IAM role (not an AWS service)?
        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue

        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            principal = st.get("Principal")
            aws_p = principal.get("AWS") if isinstance(principal, dict) else None
            principal_list = [aws_p] if isinstance(aws_p, str) else (aws_p or [])
            if not isinstance(principal_list, list):
                continue

            for p in principal_list:
                ps = str(p)
                # Flag if trusted by an IAM role (privilege escalation hop)
                if ":role/" in ps and not ps.endswith(".amazonaws.com"):
                    if role_arn not in affected:
                        affected.append(role_arn)
                    break

    if affected:
        return PreCheckResult(
            "IAM-029",
            "FAIL",
            f"{len(affected)} admin role(s) trusted by other IAM role(s) — escalation path",
            affected,
        )
    return PreCheckResult("IAM-029", "PASS", "no privilege escalation via role chain detected", [])


@_register("iam")
def check_iam_032(evidence: Dict[str, Any]) -> PreCheckResult:
    """OIDC trust policies for GitHub Actions should be tightly scoped."""
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-032", "SKIP", "no roles evidence", [])

    def _has_web_identity_action(stmt: Dict[str, Any]) -> bool:
        actions = [str(a).lower() for a in _actions_from_stmt(stmt)]
        return any(a in {"sts:assumerolewithwebidentity", "sts:*", "*"} for a in actions)

    def _collect_condition_values(condition: Any, key: str) -> List[str]:
        if not isinstance(condition, dict):
            return []
        out: List[str] = []
        for _, block in condition.items():
            if not isinstance(block, dict):
                continue
            val = block.get(key)
            if isinstance(val, str):
                out.append(val)
            elif isinstance(val, list):
                out.extend([str(x) for x in val if x is not None])
        return out

    for r in roles:
        if not isinstance(r, dict):
            continue
        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue
        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if not _has_web_identity_action(st):
                continue

            principal = st.get("Principal")
            federated = principal.get("Federated") if isinstance(principal, dict) else None
            fed_list = [federated] if isinstance(federated, str) else federated
            if not isinstance(fed_list, list):
                continue

            if not any(
                isinstance(x, str) and "token.actions.githubusercontent.com" in x for x in fed_list
            ):
                continue

            condition = st.get("Condition")
            aud_values = _collect_condition_values(
                condition, "token.actions.githubusercontent.com:aud"
            )
            sub_values = _collect_condition_values(
                condition, "token.actions.githubusercontent.com:sub"
            )

            has_aud = any(v == "sts.amazonaws.com" for v in aud_values)
            if not has_aud:
                return PreCheckResult(
                    "IAM-032",
                    "FAIL",
                    "GitHub OIDC trust missing strict aud=sts.amazonaws.com",
                    [r.get("Arn", f"role/{r.get('RoleName', 'unknown')}")],
                )

            if not sub_values:
                return PreCheckResult(
                    "IAM-032",
                    "FAIL",
                    "GitHub OIDC trust missing sub condition",
                    [r.get("Arn", f"role/{r.get('RoleName', 'unknown')}")],
                )

            if any("*" in str(v) for v in sub_values):
                return PreCheckResult(
                    "IAM-032",
                    "FAIL",
                    "GitHub OIDC trust has wildcard sub condition",
                    [r.get("Arn", f"role/{r.get('RoleName', 'unknown')}")],
                )

    return PreCheckResult("IAM-032", "PASS", "OIDC trust conditions appear scoped", [])


# Roles whose cross-account trust without ExternalId is by design
# (AWS-managed or AWS Organizations roles that use management-account trust).
_IAM_033_ROLE_EXCEPTIONS = frozenset(
    {
        "OrganizationAccountAccessRole",
        "AWSServiceRoleForOrganizations",
    }
)


@_register("iam")
def check_iam_033(evidence: Dict[str, Any]) -> PreCheckResult:
    """Cross-account role trust should require sts:ExternalId."""
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-033", "SKIP", "no roles evidence", [])

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    def _stmt_has_assume_role(stmt: Dict[str, Any]) -> bool:
        actions = [str(a).lower() for a in _actions_from_stmt(stmt)]
        return any(a in {"sts:assumerole", "sts:*", "*"} for a in actions)

    affected: List[str] = []

    for r in roles:
        if not isinstance(r, dict):
            continue
        role_name = str(r.get("RoleName") or "")
        role_arn = str(r.get("Arn") or "")

        # Skip AWS-managed roles where cross-account trust without ExternalId
        # is expected by design (e.g. AWS Organizations management account).
        if role_name in _IAM_033_ROLE_EXCEPTIONS:
            continue

        role_account = _account_from_arn(role_arn)
        if not role_account:
            continue

        trust = r.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue

        for st in _stmts_from_policy(trust):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if not _stmt_has_assume_role(st):
                continue

            principal = st.get("Principal")
            aws_p = principal.get("AWS") if isinstance(principal, dict) else None
            principal_list = [aws_p] if isinstance(aws_p, str) else aws_p
            if not isinstance(principal_list, list):
                continue

            has_external = False
            for p in principal_list:
                ps = str(p)
                if ps.startswith("arn:aws:iam::"):
                    p_account = _account_from_arn(ps)
                    if p_account and p_account != role_account:
                        has_external = True
                        break

            if not has_external:
                continue

            cond_text = json.dumps(st.get("Condition", {}), default=str)
            if "sts:ExternalId" not in cond_text:
                # Check for alternative strong-scoping conditions that mitigate
                # confused-deputy without sts:ExternalId (e.g. PrincipalArn scope,
                # SourceAccount, PrincipalOrgID).
                _strong_conds = {
                    "aws:principalarn",
                    "aws:sourceaccount",
                    "aws:principalorgid",
                    "aws:principalorgpaths",
                    "aws:sourceorgid",
                }
                cond_lower = cond_text.lower()
                if any(c in cond_lower for c in _strong_conds):
                    continue  # alternative confused-deputy protection present
                affected.append(role_arn or f"role/{role_name or 'unknown'}")
                break  # one violation per role is enough; move to next role

    if affected:
        return PreCheckResult(
            "IAM-033",
            "FAIL",
            f"{len(affected)} cross-account trust(s) without sts:ExternalId",
            affected,
        )
    return PreCheckResult(
        "IAM-033", "PASS", "cross-account trusts enforce ExternalId or are absent", []
    )


@_register("iam")
def check_iam_043(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-043: Confused Deputy — service trust policies without aws:SourceAccount or aws:SourceArn.

    Roles whose trust policy has a Service principal (e.g. lambda.amazonaws.com) but lacks
    a condition scoping the caller to a specific account/ARN are vulnerable to the Confused
    Deputy attack: a malicious service in another account could request AssumeRole on this role.

    Services excluded by design (instance profiles, cross-service internal use):
      - ec2.amazonaws.com, ecs-tasks.amazonaws.com, eks.amazonaws.com
      - edgelambda.amazonaws.com (Lambda@Edge, managed by CloudFront)
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-043", "SKIP", "no roles evidence", [])

    # Services where Confused Deputy condition is not applicable by design
    _excluded_services = {
        "ec2.amazonaws.com",
        "ecs-tasks.amazonaws.com",
        "eks.amazonaws.com",
        "edgelambda.amazonaws.com",
        "ec2.amazonaws.com.cn",
    }

    # Conditions that scope the service call to a specific origin (mitigate confused deputy)
    _source_conditions = {
        "aws:sourceaccount",
        "aws:sourcearn",
        "aws:sourceorgid",
        "aws:sourceorgpaths",
    }

    affected_fail: List[str] = []  # No source condition at all
    affected_warn: List[str] = []  # Has aws:SourceArn but not aws:SourceAccount (weaker)

    for role in roles:
        if not isinstance(role, dict):
            continue
        role_name = str(role.get("RoleName") or "unknown")
        role_arn = str(role.get("Arn") or f"role/{role_name}")
        role_path = str(role.get("Path") or "/")

        # Service-Linked Roles are managed by AWS and cannot have conditions added.
        # They are not actionable findings for Confused Deputy.
        if role_path.startswith("/aws-service-role/"):
            continue

        trust = role.get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            continue

        for stmt in _stmts_from_policy(trust):
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).upper() != "ALLOW":
                continue

            principal = stmt.get("Principal")
            if not isinstance(principal, dict):
                continue

            service_p = principal.get("Service")
            services: List[str] = (
                [service_p]
                if isinstance(service_p, str)
                else service_p if isinstance(service_p, list) else []
            )

            # Filter out excluded services
            relevant = [s for s in services if s not in _excluded_services]
            if not relevant:
                continue

            cond = stmt.get("Condition") or {}
            cond_text = json.dumps(cond, default=str).lower()

            has_source_cond = any(k in cond_text for k in _source_conditions)

            if not has_source_cond:
                # No scope restriction at all → Confused Deputy risk
                label = f"{role_arn} (service: {', '.join(relevant[:2])})"
                if label not in affected_fail:
                    affected_fail.append(label)
                break  # one violation per role
            # has_source_cond=True (SourceAccount, SourceArn, or SourceOrgId) → sufficient

    if not affected_fail and not affected_warn:
        return PreCheckResult(
            "IAM-043",
            "PASS",
            "all service trust policies have aws:SourceAccount, aws:SourceArn, or aws:SourceOrgID conditions",
            [],
        )

    all_affected = affected_fail + affected_warn
    count_fail = len(affected_fail)
    summary_parts = []
    if count_fail:
        summary_parts.append(
            f"{count_fail} role(s) with service trust and no source-scoping condition"
        )
    return PreCheckResult("IAM-043", "FAIL", "; ".join(summary_parts), all_affected[:10])


@_register("iam")
def check_iam_034(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow IdP takeover actions broadly."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-034", "SKIP", "no policies evidence", [])

    risky = {
        "iam:updatesamlprovider",
        "iam:updateopenidconnectproviderthumbprint",
        "iam:createopenidconnectprovider",
        "iam:createsamlprovider",
        "iam:deleteopenidconnectprovider",
        "iam:deletesamlprovider",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue

            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-034",
                    "FAIL",
                    f"policy '{pname}' allows IdP mutation actions broadly",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-034", "PASS", "no broad IdP mutation permissions found", [])


@_register("iam")
def check_iam_035(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow policy-version backdoor actions broadly."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-035", "SKIP", "no policies evidence", [])

    risky = {"iam:createpolicyversion", "iam:setdefaultpolicyversion"}

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue

            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue

            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(
                str(r) in {"*", "arn:aws:iam::*:policy/*"} for r in res_list
            )
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-035",
                    "FAIL",
                    f"policy '{pname}' allows policy-version escalation actions",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-035", "PASS", "no broad policy-version backdoor actions found", [])


@_register("iam")
def check_iam_036(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow broad service-specific credential takeover."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-036", "SKIP", "no policies evidence", [])

    risky = {
        "iam:createservicespecificcredential",
        "iam:resetservicespecificcredential",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-036",
                    "FAIL",
                    f"policy '{pname}' allows broad service-specific credential takeover",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult(
        "IAM-036", "PASS", "no broad service-specific credential takeover actions", []
    )


@_register("iam")
def check_iam_037(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM policies should not allow broad MFA device manipulation."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-037", "SKIP", "no policies evidence", [])

    risky = {
        "iam:enablemfadevice",
        "iam:createvirtualmfadevice",
        "iam:deactivatemfadevice",
        "iam:resyncmfadevice",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-037",
                    "FAIL",
                    f"policy '{pname}' allows broad MFA manipulation actions",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-037", "PASS", "no broad MFA manipulation actions", [])


@_register("iam")
def check_iam_038(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM wildcard delete permissions should be prohibited."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-038", "SKIP", "no policies evidence", [])

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if "iam:delete*" not in acts and "iam:*" not in acts and "*" not in acts:
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-038",
                    "FAIL",
                    f"policy '{pname}' allows iam:Delete* broadly",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-038", "PASS", "no broad iam:Delete* permissions", [])


@_register("iam")
def check_iam_039(evidence: Dict[str, Any]) -> PreCheckResult:
    """Broad policy detachment/deletion actions should be restricted."""
    pols = evidence.get("policies")
    if not isinstance(pols, list) or not pols:
        return PreCheckResult("IAM-039", "SKIP", "no policies evidence", [])

    risky = {
        "iam:detachuserpolicy",
        "iam:detachrolepolicy",
        "iam:detachgrouppolicy",
        "iam:deletepolicyversion",
        "iam:deletepolicy",
        "iam:deleteuserpolicy",
        "iam:deleterolepolicy",
        "iam:deletegrouppolicy",
    }

    for p in pols:
        if not isinstance(p, dict):
            continue
        doc = p.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for st in _stmts_from_policy(doc):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            acts = {str(a).lower() for a in _actions_from_stmt(st)}
            if not acts:
                continue
            if not (acts & risky or "iam:*" in acts or "*" in acts):
                continue
            res = st.get("Resource")
            res_list = [res] if isinstance(res, str) else (res if isinstance(res, list) else [])
            broad = not res_list or any(str(r) == "*" for r in res_list)
            if broad:
                pname = p.get("PolicyName", "unknown")
                return PreCheckResult(
                    "IAM-039",
                    "FAIL",
                    f"policy '{pname}' allows broad policy-detach/deletion actions",
                    [p.get("Arn", f"policy/{pname}")],
                )

    return PreCheckResult("IAM-039", "PASS", "no broad policy-detach/deletion actions", [])


@_register("iam")
def check_iam_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-005: Password policy minimum length should be 14+ characters."""
    pp_doc = evidence.get("password-policy")
    if not isinstance(pp_doc, dict):
        return PreCheckResult("IAM-005", "SKIP", "no password-policy evidence", [])

    policy = pp_doc.get("PasswordPolicy")
    if not isinstance(policy, dict):
        return PreCheckResult("IAM-005", "SKIP", "password-policy missing PasswordPolicy key", [])

    min_len = policy.get("MinimumPasswordLength")
    if min_len is None:
        return PreCheckResult("IAM-005", "SKIP", "MinimumPasswordLength not set", [])

    if int(min_len) >= 14:
        return PreCheckResult("IAM-005", "PASS", f"MinimumPasswordLength={min_len} (≥14)", [])
    return PreCheckResult(
        "IAM-005",
        "FAIL",
        f"MinimumPasswordLength={min_len} (required ≥14)",
        ["arn:aws:iam::*:account-password-policy"],
    )


@_register("iam")
def check_iam_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-015: IAM users should not have direct policy attachments — use groups instead."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-015", "SKIP", "no users evidence", [])

    affected: List[str] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        # Flag users that have attached/inline policies but belong to no groups
        has_attached = bool(u.get("AttachedPolicies"))
        has_inline = bool(u.get("InlinePolicies"))
        in_groups = bool(u.get("Groups"))
        if (has_attached or has_inline) and not in_groups:
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{u.get('UserName', 'unknown')}")
            affected.append(arn)

    if not affected:
        return PreCheckResult(
            "IAM-015", "PASS", "no users with direct permissions outside group", []
        )
    return PreCheckResult(
        "IAM-015",
        "FAIL",
        f"{len(affected)} user(s) with direct policy attachments and no group membership",
        affected[:5],
    )


@_register("iam")
def check_iam_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-016: Service accounts should use IAM roles, not IAM users."""
    users = evidence.get("users")
    if not isinstance(users, list) or not users:
        return PreCheckResult("IAM-016", "SKIP", "no users evidence", [])

    cred = evidence.get("credential-report", {})
    by_user: Dict[str, Any] = cred.get("by_user", {}) if isinstance(cred, dict) else {}

    affected: List[str] = []
    for u in users:
        if not isinstance(u, dict):
            continue
        uname = str(u.get("UserName") or "")
        row = by_user.get(uname, {})

        # Service account pattern: no console password + active access key
        password_enabled = str(row.get("password_enabled", "false")).lower()
        has_active_key = any(
            str(k.get("Status") or "").lower() == "active"
            for k in (u.get("AccessKeys") or [])
            if isinstance(k, dict)
        )
        if password_enabled == "false" and has_active_key:
            arn = str(u.get("Arn") or f"arn:aws:iam::*:user/{uname}")
            affected.append(arn)

    if not affected:
        return PreCheckResult("IAM-016", "PASS", "no service-account-pattern IAM users found", [])
    return PreCheckResult(
        "IAM-016",
        "FAIL",
        f"{len(affected)} IAM user(s) matching service-account pattern (no password, active access key)",
        affected[:5],
    )


@_register("iam")
def check_iam_040(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-040: Organization SCPs should impose Deny restrictions on all accounts."""
    scps_doc = evidence.get("effective-scps")
    if not isinstance(scps_doc, dict):
        return PreCheckResult("IAM-040", "SKIP", "effective-scps evidence not available", [])

    error = scps_doc.get("error")
    scps = scps_doc.get("service_control_policies", [])

    # If error and no SCPs: not in org or no permissions → SKIP
    if error and not scps:
        return PreCheckResult(
            "IAM-040",
            "SKIP",
            f"Account not in Organization or no org permissions: {str(error)[:100]}",
            [],
        )

    if not isinstance(scps, list) or not scps:
        return PreCheckResult("IAM-040", "SKIP", "No SCPs found (not in Organization)", [])

    # Check if any SCP has Deny statements (not just the AWS-managed FullAWSAccess)
    has_deny_scp = False
    non_managed_scps = [s for s in scps if isinstance(s, dict) and not s.get("AwsManaged", False)]

    for scp in non_managed_scps:
        doc = scp.get("PolicyDocument")
        if not isinstance(doc, dict):
            continue
        for stmt in doc.get("Statement", []) or []:
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).upper() == "DENY":
                has_deny_scp = True
                break
        if has_deny_scp:
            break

    if has_deny_scp:
        return PreCheckResult(
            "IAM-040",
            "PASS",
            f"{len(non_managed_scps)} custom SCP(s) found; at least one has Deny statements",
            [],
        )

    # In org, SCPs exist, but no Deny-based SCPs — only Allow (FullAWSAccess default)
    scp_names = [str(s.get("Name", "unknown")) for s in scps if isinstance(s, dict)]
    return PreCheckResult(
        "IAM-040",
        "FAIL",
        f"Account in Organization with {len(scps)} SCP(s) but no Deny-based custom SCPs: "
        + ", ".join(scp_names[:5]),
        [],
    )


@_register("iam")
def check_iam_041(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-041: Roles with AdministratorAccess or PowerUserAccess.

    Privileged roles are flagged unless they are ServiceLinkedRole.
    Severity is dynamic based on Access Advisor:
      - Never used (AccessAdvisorDaysAgo=None) or >90 days → Critical (zombi role)
      - <=90 days ago → High (active but privileged)

    Also checks Trust Policy for MFA condition.
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-041", "SKIP", "no roles evidence", [])

    admin_policies = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }

    affected_roles: List[Dict[str, Any]] = []

    for role in roles:
        if not isinstance(role, dict):
            continue

        # Skip ServiceLinkedRole (AWS-managed, not customer risk)
        role_type = role.get("RoleType", "Unknown")
        if role_type == "ServiceLinkedRole":
            continue

        role_name = str(role.get("RoleName") or "unknown")
        attached = role.get("AttachedPolicies") or []

        # Check AWS-managed admin policies
        has_admin = False
        for policy in attached:
            if not isinstance(policy, dict):
                continue
            policy_arn = str(policy.get("PolicyArn") or "")
            if policy_arn in admin_policies:
                has_admin = True
                break

        if not has_admin:
            continue

        # This role has privileged access; determine severity
        access_advisor_days = role.get("AccessAdvisorDaysAgo")

        # Determine severity based on last access
        if access_advisor_days is None or access_advisor_days > 90:
            severity = "Critical"  # Never used or zombi
        else:
            severity = "High"  # Active but privileged

        # Check Trust Policy for MFA condition
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        has_mfa_condition = _has_mfa_condition_in_policy(trust_policy)

        # Extract trusted principals for context
        principals: List[str] = []
        for stmt in trust_policy.get("Statement") or []:
            p = stmt.get("Principal")
            if isinstance(p, str):
                principals.append(p)
            elif isinstance(p, dict):
                for v in p.values():
                    if isinstance(v, list):
                        principals.extend(v)
                    elif isinstance(v, str):
                        principals.append(v)

        affected_roles.append(
            {
                "role_name": role_name,
                "role_type": role_type,
                "severity": severity,
                "access_days_ago": access_advisor_days,
                "has_mfa_condition": has_mfa_condition,
                "principals": principals[:2],  # Keep first 2 for display
            }
        )

    if not affected_roles:
        return PreCheckResult(
            "IAM-041",
            "PASS",
            "no customer-managed roles with AdministratorAccess/PowerUserAccess",
            [],
        )

    # Build evidence snippet with detailed role analysis
    snippet_roles = []
    affected_labels = []
    for r in affected_roles[:10]:
        snippet_roles.append(
            {
                "RoleName": r["role_name"],
                "RoleType": r["role_type"],
                "Severity": r["severity"],
                "AccessAdvisorDaysAgo": r["access_days_ago"],
                "HasMFACondition": r["has_mfa_condition"],
                "TrustedBy": r["principals"],
            }
        )
        # Build label with trust context for backward compatibility
        label = r["role_name"]
        if r["principals"]:
            label = f"{r['role_name']} (trusted by: {', '.join(r['principals'])})"
        affected_labels.append(label)

    # Determine overall severity
    has_critical = any(r["severity"] == "Critical" for r in affected_roles)
    overall_summary = f"{len(affected_roles)} privileged role(s) detected"
    if has_critical:
        overall_summary += (
            f" ({sum(1 for r in affected_roles if r['severity'] == 'Critical')} unused/zombi)"
        )

    return PreCheckResult(
        "IAM-041",
        "FAIL",
        overall_summary,
        affected_labels,
        metadata={"detailed_roles": snippet_roles},
    )


def _has_mfa_condition_in_policy(policy: Dict[str, Any]) -> bool:
    """Check if policy has aws:MultiFactorAuthPresent condition."""
    for stmt in policy.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        conditions = stmt.get("Condition", {})
        if "aws:MultiFactorAuthPresent" in str(conditions):
            return True
    return False


@_register("iam")
def check_iam_042(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-042: Privilege escalation paths via dangerous IAM permissions without MFA condition.

    Detects policies granting escalation-capable permissions (based on Rhino Security Labs taxonomy)
    without requiring aws:MultiFactorAuthPresent:true. These permissions allow a low-privilege
    identity to elevate to admin without additional authentication.

    Escalation categories:
      - Credential creation: iam:CreateAccessKey, iam:CreateLoginProfile, iam:UpdateLoginProfile
      - Policy attachment: iam:AttachUserPolicy, iam:AttachRolePolicy, iam:AttachGroupPolicy
      - Policy modification: iam:PutUserPolicy, iam:PutRolePolicy, iam:PutGroupPolicy
      - Role passing: iam:PassRole (combined with other services = privilege escalation vector)
      - MFA bypass: iam:CreateVirtualMFADevice without scoped resource
    """
    policies = evidence.get("policies")
    if not isinstance(policies, list) or not policies:
        return PreCheckResult("IAM-042", "SKIP", "no policies evidence", [])

    # Escalation permissions — must be checked with broad Resource scope
    _escalation_perms = {
        "iam:createaccesskey",
        "iam:createloginprofile",
        "iam:updateloginprofile",
        "iam:attachuserpolicy",
        "iam:attachrolepolicy",
        "iam:attachgrouppolicy",
        "iam:putuserpolicy",
        "iam:putrolepolicy",
        "iam:putgrouppolicy",
        "iam:passrole",
        "iam:createvirtualmfadevice",
    }

    affected: List[str] = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue

        policy_arn = str(policy.get("Arn") or policy.get("PolicyName") or "unknown")
        # Skip AWS-managed policies — we can't change them; focus on customer-managed
        if policy_arn.startswith("arn:aws:iam::aws:policy/"):
            continue

        doc = policy.get("PolicyDocument") or {}
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except Exception:
                continue
        if not isinstance(doc, dict):
            continue

        for stmt in _stmts_from_policy(doc):
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect", "")).upper() != "ALLOW":
                continue

            # Check resource scope — only broad resources are dangerous
            resource = stmt.get("Resource", "")
            resource_list = [resource] if isinstance(resource, str) else resource
            has_broad_resource = any(
                str(r) in ("*", "arn:aws:iam::*:*", "arn:aws:iam:::*") for r in resource_list
            )
            if not has_broad_resource:
                continue

            # Check for escalation actions
            actions_raw = stmt.get("Action", [])
            if isinstance(actions_raw, str):
                actions_raw = [actions_raw]
            actions_lower = [str(a).lower() for a in actions_raw]

            found_escalation = set()
            for act in actions_lower:
                if act == "*" or act == "iam:*":
                    found_escalation.add(act)
                elif act in _escalation_perms:
                    found_escalation.add(act)

            if not found_escalation:
                continue

            # Check if MFA condition is present
            cond = stmt.get("Condition") or {}
            cond_text = json.dumps(cond, default=str).lower()
            has_mfa_cond = "aws:multifactorauthpresent" in cond_text and '"true"' in cond_text

            if not has_mfa_cond:
                label = f"{policy_arn} ({', '.join(sorted(found_escalation)[:3])})"
                if label not in affected:
                    affected.append(label)
                break  # One violation per policy is enough

    if not affected:
        return PreCheckResult(
            "IAM-042",
            "PASS",
            "no customer-managed policies with unguarded escalation permissions found",
            [],
        )
    return PreCheckResult(
        "IAM-042",
        "FAIL",
        f"{len(affected)} policy(ies) with privilege escalation permissions without MFA condition",
        affected[:10],
    )


@_register("iam")
def check_iam_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-007: Inline policies must not be used on IAM roles — use managed policies instead."""
    roles = evidence.get("roles")
    if not isinstance(roles, list):
        return PreCheckResult("IAM-007", "SKIP", "no roles evidence", [])

    affected: List[str] = []
    for r in roles:
        if not isinstance(r, dict):
            continue
        inline = r.get("InlinePolicies") or []
        if inline:
            arn = str(r.get("Arn") or f"arn:aws:iam::*:role/{r.get('RoleName', 'unknown')}")
            affected.append(arn)

    if not affected:
        return PreCheckResult("IAM-007", "PASS", "no roles with inline policies", [])
    return PreCheckResult(
        "IAM-007",
        "FAIL",
        f"{len(affected)} role(s) have inline policies",
        affected[:5],
    )


@_register("iam")
def check_iam_018(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-018: IAM password policy should enforce maximum password age (90 days or less)."""
    pp_doc = evidence.get("password-policy")
    if not isinstance(pp_doc, dict):
        return PreCheckResult("IAM-018", "SKIP", "no password-policy evidence", [])

    policy = pp_doc.get("PasswordPolicy")
    if not isinstance(policy, dict):
        return PreCheckResult("IAM-018", "SKIP", "password-policy missing PasswordPolicy key", [])

    expire_passwords = policy.get("ExpirePasswords")
    max_age = policy.get("MaxPasswordAge")

    if not _truthy(expire_passwords):
        return PreCheckResult(
            "IAM-018",
            "FAIL",
            "ExpirePasswords=false — password expiry not enforced",
            ["arn:aws:iam::*:account-password-policy"],
        )

    if max_age is None:
        return PreCheckResult("IAM-018", "SKIP", "MaxPasswordAge not set", [])

    try:
        max_age_int = int(max_age)
    except (TypeError, ValueError):
        return PreCheckResult(
            "IAM-018", "SKIP", f"MaxPasswordAge={max_age!r} is not an integer", []
        )

    if max_age_int <= 90:
        return PreCheckResult(
            "IAM-018",
            "PASS",
            f"MaxPasswordAge={max_age_int} (≤90 days, ExpirePasswords=true)",
            [],
        )
    return PreCheckResult(
        "IAM-018",
        "FAIL",
        f"MaxPasswordAge={max_age_int} days (required ≤90)",
        ["arn:aws:iam::*:account-password-policy"],
    )


@_register("iam")
def check_iam_019(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-019: IAM password policy should require symbol characters."""
    pp_doc = evidence.get("password-policy")
    if not isinstance(pp_doc, dict):
        return PreCheckResult("IAM-019", "SKIP", "no password-policy evidence", [])

    policy = pp_doc.get("PasswordPolicy")
    if not isinstance(policy, dict):
        return PreCheckResult("IAM-019", "SKIP", "password-policy missing PasswordPolicy key", [])

    require_symbols = policy.get("RequireSymbols")
    if _truthy(require_symbols):
        return PreCheckResult("IAM-019", "PASS", "RequireSymbols=true", [])
    return PreCheckResult(
        "IAM-019",
        "FAIL",
        f"RequireSymbols={require_symbols!r}",
        ["arn:aws:iam::*:account-password-policy"],
    )


# AWS service account IDs that are legitimately used in bucket policies by design.
# These are documented AWS-managed accounts for services like ELB, CloudFront, etc.
# Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html
_AWS_SERVICE_ACCOUNTS: Dict[str, str] = {
    # ELB access logging (per-region accounts)
    "127311923021": "ELB us-east-1",
    "033677994240": "ELB us-east-2",
    "027434742980": "ELB us-west-1",
    "797873946194": "ELB us-west-2/CloudFront logs",
    "098369216593": "ELB af-south-1",
    "600734575887": "ELB ap-east-1",
    "718504428378": "ELB ap-southeast-3/ap-south-2",
    "383597477331": "ELB ap-southeast-4",
    "754344448648": "ELB ap-south-1",
    "589379963580": "ELB ap-northeast-3",
    "507241528517": "ELB ap-northeast-2",
    "582318560864": "ELB ap-southeast-1",
    "114774131450": "ELB ap-southeast-2",
    "783225319266": "ELB ap-northeast-1",
    "985666609251": "ELB ca-central-1",
    "045080605973": "ELB cn-north-1",
    "638102146993": "ELB cn-northwest-1/eu-south-2",
    "897822967062": "ELB eu-central-1/eu-north-1",
    "635631232610": "ELB eu-central-2",
    "054676820928": "ELB eu-west-1",
    "156460612806": "ELB eu-west-2",
    "009996457667": "ELB eu-south-1",
    "076674570225": "ELB eu-west-3/me-central-1",
    "086441151436": "ELB me-south-1",
    "507936923172": "ELB sa-east-1",
    "048591011584": "ELB us-gov-west-1",
    "190560391635": "ELB us-gov-east-1",
    # CloudFront access logging
    "210479947434": "CloudFront logs",
}


@_register("iam")
def check_iam_030(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-030: Resource-based policies with cross-account access — whitelist known AWS service accounts.

    Flags cross-account principals in S3/SQS/SNS/Lambda resource-based policies,
    excluding known AWS service accounts (ELB logging, CloudFront) that are documented
    and required by AWS for specific integrations.
    """
    rbp = evidence.get("resource-based-policies")
    if not isinstance(rbp, dict):
        return PreCheckResult("IAM-030", "SKIP", "no resource-based-policies evidence", [])

    meta = evidence.get("_audit_metadata")
    audit_account = meta.get("_account_id") if isinstance(meta, dict) else None

    # Infer audit account from IAM evidence ARNs when metadata is unavailable
    if not audit_account:
        for src_key in ("users", "roles"):
            for item in evidence.get(src_key) or []:
                arn = str(item.get("Arn") or "") if isinstance(item, dict) else ""
                parts = arn.split(":")
                if len(parts) > 4 and parts[4].isdigit():
                    audit_account = parts[4]
                    break
            if audit_account:
                break

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    affected: List[str] = []
    whitelisted: List[str] = []

    for service, resources in rbp.items():
        if not isinstance(resources, list):
            continue
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            policy = resource.get("Policy") or {}
            if not isinstance(policy, dict):
                continue
            resource_arn = resource.get("Arn") or ""
            resource_account = _account_from_arn(resource_arn) if resource_arn else audit_account
            resource_name = resource.get("Name") or resource_arn or "unknown"
            for stmt in policy.get("Statement", []) or []:
                if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal")
                if not isinstance(principal, dict):
                    continue
                aws_p = principal.get("AWS")
                principals = (
                    [aws_p]
                    if isinstance(aws_p, str)
                    else (aws_p if isinstance(aws_p, list) else [])
                )
                for p in principals:
                    if not isinstance(p, str):
                        continue
                    parts = p.split(":")
                    p_account = parts[4] if len(parts) > 4 else ""
                    if not p_account or not p_account.isdigit():
                        continue
                    # Same-account access is never cross-account
                    effective_account = resource_account or audit_account
                    if effective_account and p_account == effective_account:
                        continue
                    service_label = _AWS_SERVICE_ACCOUNTS.get(p_account)
                    if service_label:
                        whitelisted.append(f"{resource_name} → {p} ({service_label})")
                    else:
                        affected.append(f"{resource_name} → {p}")

    if affected:
        return PreCheckResult(
            "IAM-030",
            "FAIL",
            f"{len(affected)} resource-based policy(ies) grant cross-account access to non-whitelisted accounts",
            affected[:10],
        )
    if whitelisted:
        return PreCheckResult(
            "IAM-030",
            "PASS",
            f"cross-account access only to whitelisted AWS service accounts ({len(whitelisted)} entries)",
            [],
        )
    return PreCheckResult("IAM-030", "PASS", "no cross-account resource-based policies", [])


@_register("iam")
def check_iam_026(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-026: IAM roles should use PermissionsBoundary to limit maximum privilege.

    Flags when a significant portion of customer-managed roles lack PermissionsBoundary,
    indicating no boundary controls on privilege escalation paths.
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-026", "SKIP", "no roles evidence", [])

    customer_roles = [
        r
        for r in roles
        if isinstance(r, dict)
        and not str(r.get("Path") or "/").startswith("/aws-service-role/")
        and not str(r.get("RoleName") or "").startswith("AWSReserved")
    ]
    if not customer_roles:
        return PreCheckResult("IAM-026", "SKIP", "no customer-managed roles found", [])

    without_boundary = [r for r in customer_roles if not r.get("PermissionsBoundary")]

    ratio = len(without_boundary) / len(customer_roles)

    if ratio >= 0.5:
        sample = [str(r.get("Arn") or r.get("RoleName") or "unknown") for r in without_boundary[:5]]
        return PreCheckResult(
            "IAM-026",
            "FAIL",
            f"{len(without_boundary)}/{len(customer_roles)} customer-managed roles lack PermissionsBoundary ({ratio:.0%})",
            sample,
        )
    return PreCheckResult(
        "IAM-026",
        "PASS",
        f"most customer-managed roles have PermissionsBoundary ({len(customer_roles) - len(without_boundary)}/{len(customer_roles)})",
        [],
    )


@_register("iam")
def check_iam_044(evidence: Dict[str, Any]) -> PreCheckResult:
    """IAM-044: Privileged roles should not have MaxSessionDuration greater than 3600 seconds (1 hour).

    Long session durations on privileged roles extend the window of exposure if a
    temporary credential is leaked, violating PCI DSS 8.3.9 (credential validity).
    """
    roles = evidence.get("roles")
    if not isinstance(roles, list) or not roles:
        return PreCheckResult("IAM-044", "SKIP", "no roles evidence", [])

    _privileged_policy_names = {"AdministratorAccess", "PowerUserAccess"}
    _max_session_threshold = 3600  # 1 hour

    affected: List[str] = []
    for role in roles:
        if not isinstance(role, dict):
            continue
        role_path = str(role.get("Path") or "/")
        if role_path.startswith("/aws-service-role/"):
            continue

        max_session = role.get("MaxSessionDuration")
        if not isinstance(max_session, int) or max_session <= _max_session_threshold:
            continue

        # Only flag roles with privileged policies attached
        attached = role.get("AttachedPolicies") or []
        policy_names = {str(p.get("PolicyName") or "") for p in attached if isinstance(p, dict)}
        is_privileged = bool(policy_names & _privileged_policy_names)

        # Also flag SSO roles (they are often privileged)
        role_name = str(role.get("RoleName") or "")
        is_sso = "AWSReservedSSO" in role_name

        if is_privileged or is_sso:
            arn = str(role.get("Arn") or f"role/{role_name}")
            affected.append(f"{arn} (MaxSessionDuration={max_session}s / {max_session // 3600}h)")

    if affected:
        return PreCheckResult(
            "IAM-044",
            "FAIL",
            f"{len(affected)} privileged/SSO role(s) with MaxSessionDuration > 1h",
            affected,
        )
    return PreCheckResult(
        "IAM-044",
        "PASS",
        "all privileged roles have MaxSessionDuration ≤ 1h",
        [],
    )


# ============================================================================
# HARDENING PRE-CHECKS
# ============================================================================


@_register("hardening")
def check_hrd_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """AWS Config should be enabled."""
    config_recorders = evidence.get("config-recorders", {})
    recorders = (
        config_recorders.get("ConfigurationRecorders", [])
        if isinstance(config_recorders, dict)
        else []
    )
    if len(recorders) > 0:
        return PreCheckResult("HRD-001", "PASS", f"Config enabled ({len(recorders)} recorders)", [])
    return PreCheckResult("HRD-001", "FAIL", "ConfigurationRecorders=[]", [])


@_register("hardening")
def check_hrd_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub should be enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict):
        hub_status = {}
    hub_arn = hub_status.get("HubArn")
    if hub_arn:
        return PreCheckResult("HRD-002", "PASS", f"HubArn={hub_arn}", [])
    return PreCheckResult("HRD-002", "FAIL", "HubArn is empty/missing", [])


@_register("hardening")
def check_hrd_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub should have standards enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict) or not hub_status.get("HubArn"):
        return PreCheckResult("HRD-003", "SKIP", "Security Hub not enabled", [])

    enabled_standards = evidence.get("security-hub-enabled-standards", [])
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-003", "SKIP", "no standards evidence", [])

    ready = 0
    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        status = str(std.get("Status") or "").upper()
        controls = std.get("ControlsSummary") or {}
        enabled_controls = int(controls.get("enabled", 0)) if isinstance(controls, dict) else 0
        if status in {"READY", "ENABLED"} or enabled_controls > 0:
            ready += 1

    if ready > 0:
        return PreCheckResult("HRD-003", "PASS", f"{ready} standards enabled/ready", [])
    return PreCheckResult("HRD-003", "FAIL", "0 standards enabled", [])


@_register("hardening")
def check_hrd_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be >= 50%."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-004", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if score >= 50.0:
        return PreCheckResult("HRD-004", "PASS", f"compliance_score={score:.1f}%", [])
    return PreCheckResult("HRD-004", "FAIL", f"compliance_score={score:.1f}% (<50%)", [])


@_register("hardening")
def check_hrd_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical Security Hub findings should be zero."""
    sev_counts, _ = _get_hardening_counts(evidence)
    critical = sev_counts.get("CRITICAL", 0)
    if critical <= 0:
        return PreCheckResult("HRD-005", "PASS", f"CRITICAL count={critical}", [])
    return PreCheckResult("HRD-005", "FAIL", f"CRITICAL count={critical}", [])


@_register("hardening")
def check_hrd_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """AWS Config recorder should be recording with delivery channel."""
    config_recorders = evidence.get("config-recorders", {})
    if not isinstance(config_recorders, dict):
        config_recorders = {}
    recorders = config_recorders.get("ConfigurationRecorders", [])
    if not isinstance(recorders, list) or len(recorders) == 0:
        return PreCheckResult("HRD-006", "SKIP", "Config not enabled (HRD-001 applies)", [])

    recorder_status_doc = evidence.get("config-recorder-status", {})
    status_items = (
        recorder_status_doc.get("ConfigurationRecordersStatus", [])
        if isinstance(recorder_status_doc, dict)
        else []
    )

    recording_ok = False
    if isinstance(status_items, list):
        for s in status_items:
            if isinstance(s, dict) and s.get("recording") is True:
                recording_ok = True
                break

    channels_doc = evidence.get("config-delivery-channels", {})
    channels = channels_doc.get("DeliveryChannels", []) if isinstance(channels_doc, dict) else []
    channel_ok = False
    if isinstance(channels, list):
        for c in channels:
            if isinstance(c, dict) and c.get("s3BucketName"):
                channel_ok = True
                break

    if recording_ok and channel_ok:
        return PreCheckResult("HRD-006", "PASS", "recorder active, delivery channel configured", [])
    issues = []
    if not recording_ok:
        issues.append("recording=false")
    if not channel_ok:
        issues.append("no delivery channel")
    return PreCheckResult("HRD-006", "FAIL", "; ".join(issues), [])


@_register("hardening")
def check_hrd_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """High severity Security Hub findings should be <= 10."""
    sev_counts, _ = _get_hardening_counts(evidence)
    high = sev_counts.get("HIGH", 0)
    if high <= 10:
        return PreCheckResult("HRD-009", "PASS", f"HIGH count={high} (<=10)", [])
    return PreCheckResult("HRD-009", "FAIL", f"HIGH count={high} (>10)", [])


@_register("hardening")
def check_hrd_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """Medium severity Security Hub findings should be <= 20."""
    sev_counts, _ = _get_hardening_counts(evidence)
    medium = sev_counts.get("MEDIUM", 0)
    if medium <= 20:
        return PreCheckResult("HRD-012", "PASS", f"MEDIUM count={medium} (<=20)", [])
    return PreCheckResult("HRD-012", "FAIL", f"MEDIUM count={medium} (>20)", [])


@_register("hardening")
def check_hrd_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """Outdated Security Hub standards should be updated."""
    # SKIP when evidence key is entirely missing (cannot evaluate)
    if "security-hub-enabled-standards" not in evidence:
        return PreCheckResult("HRD-013", "SKIP", "no standards evidence", [])

    enabled_standards = evidence["security-hub-enabled-standards"]
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-013", "SKIP", "unexpected standards format", [])

    # ARNs use slash-separated versions: ".../benchmark/v/1.2.0"
    # Use path fragments (with leading slash) — "v1.2.0" would NOT match "v/1.2.0".
    outdated_fragments = ["/1.2.0", "/1.3.0", "/2016", "/2017"]
    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        arn = str(std.get("StandardsArn") or std.get("StandardsSubscriptionArn") or "")
        for fragment in outdated_fragments:
            if fragment in arn:
                return PreCheckResult("HRD-013", "FAIL", f"outdated standard: {arn}", [])

    return PreCheckResult("HRD-013", "PASS", "no outdated standards", [])


@_register("hardening")
def check_hrd_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """GuardDuty should be enabled."""
    gd_detectors = evidence.get("guardduty-detectors", [])
    if isinstance(gd_detectors, list) and len(gd_detectors) > 0:
        return PreCheckResult("HRD-014", "PASS", f"{len(gd_detectors)} detectors", [])
    # Also check dict shape
    if isinstance(gd_detectors, dict) and gd_detectors.get("DetectorIds"):
        ids = gd_detectors["DetectorIds"]
        if isinstance(ids, list) and len(ids) > 0:
            return PreCheckResult("HRD-014", "PASS", f"{len(ids)} detectors", [])
    return PreCheckResult("HRD-014", "FAIL", "no GuardDuty detectors", [])


@_register("hardening")
def check_hrd_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Low severity Security Hub findings should be zero."""
    sev_counts, _ = _get_hardening_counts(evidence)
    low = sev_counts.get("LOW", 0)
    if low <= 0:
        return PreCheckResult("HRD-016", "PASS", f"LOW count={low}", [])
    return PreCheckResult("HRD-016", "FAIL", f"LOW count={low} (>0)", [])


@_register("hardening")
def check_hrd_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Security Hub PCI DSS standard should be enabled."""
    hub_status = evidence.get("security-hub-status", {})
    if not isinstance(hub_status, dict) or not hub_status.get("HubArn"):
        return PreCheckResult("HRD-007", "SKIP", "Security Hub not enabled", [])

    enabled_standards = evidence.get("security-hub-enabled-standards", [])
    if not isinstance(enabled_standards, list):
        return PreCheckResult("HRD-007", "SKIP", "no standards evidence", [])

    for std in enabled_standards:
        if not isinstance(std, dict):
            continue
        arn = str(std.get("StandardsArn") or std.get("StandardsSubscriptionArn") or "")
        status = str(std.get("Status") or "").upper()
        if "pci-dss" in arn.lower() and status in {"READY", "ENABLED"}:
            return PreCheckResult("HRD-007", "PASS", f"PCI DSS standard enabled: {arn}", [])

    return PreCheckResult("HRD-007", "FAIL", "no PCI DSS standard enabled", [])


@_register("hardening")
def check_hrd_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 50-70% range (medium risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-008", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 50.0 <= score < 70.0:
        return PreCheckResult("HRD-008", "FAIL", f"compliance_score={score:.1f}% (50-70%)", [])
    return PreCheckResult(
        "HRD-008", "PASS", f"compliance_score={score:.1f}% (not in 50-70% band)", []
    )


@_register("hardening")
def check_hrd_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """No conformance packs configured."""
    packs = evidence.get("config-conformance-packs", None)
    if packs is None:
        return PreCheckResult("HRD-010", "SKIP", "no conformance-packs evidence", [])
    if not isinstance(packs, list):
        return PreCheckResult("HRD-010", "SKIP", "unexpected conformance-packs format", [])
    if len(packs) == 0:
        return PreCheckResult("HRD-010", "FAIL", "0 conformance packs configured", [])
    return PreCheckResult("HRD-010", "PASS", f"{len(packs)} conformance pack(s) configured", [])


@_register("hardening")
def check_hrd_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 70-85% range (acceptable risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-011", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 70.0 <= score < 85.0:
        return PreCheckResult("HRD-011", "FAIL", f"compliance_score={score:.1f}% (70-85%)", [])
    return PreCheckResult(
        "HRD-011", "PASS", f"compliance_score={score:.1f}% (not in 70-85% band)", []
    )


@_register("hardening")
def check_hrd_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """Compliance score should be in 85-95% range (low risk)."""
    sev_counts, comp_counts = _get_hardening_counts(evidence)
    passed = int(comp_counts.get("PASSED", 0))
    failed = int(comp_counts.get("FAILED", 0))
    warning = int(comp_counts.get("WARNING", 0))
    denom = passed + failed + warning
    if denom == 0:
        return PreCheckResult("HRD-015", "SKIP", "no compliance data", [])

    score = (passed / denom) * 100.0
    if 85.0 <= score < 95.0:
        return PreCheckResult("HRD-015", "FAIL", f"compliance_score={score:.1f}% (85-95%)", [])
    return PreCheckResult(
        "HRD-015", "PASS", f"compliance_score={score:.1f}% (not in 85-95% band)", []
    )


def _get_hardening_counts(evidence: Dict[str, Any]):
    """Return (severity_counts, compliance_counts) from hardening evidence."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
    comp_counts = {"PASSED": 0, "FAILED": 0, "WARNING": 0, "NOT_AVAILABLE": 0, "OTHER": 0}

    summary = evidence.get("security-hub-findings-summary")
    if isinstance(summary, dict):
        sc = summary.get("severity_counts")
        if isinstance(sc, dict):
            for k in sev_counts:
                sev_counts[k] = int(sc.get(k, 0) or 0)
        cc = summary.get("compliance_status_counts")
        if isinstance(cc, dict):
            for k in comp_counts:
                comp_counts[k] = int(cc.get(k, 0) or 0)

    # Fallback: derive from raw findings
    if sum(sev_counts.values()) == 0:
        findings = evidence.get("security-hub-findings")
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                sev = str(((f.get("Severity") or {}).get("Label") or "")).upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                comp = str(((f.get("Compliance") or {}).get("Status") or "")).upper()
                if comp in comp_counts:
                    comp_counts[comp] += 1

    return sev_counts, comp_counts


# ============================================================================
# ALERTING PRE-CHECKS
# ============================================================================


@_register("alerting")
def check_alr_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudTrail should have CloudWatch Logs integration."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or len(trails) == 0:
        return PreCheckResult("ALRT-001", "SKIP", "no trails (ALR-001 applies)", [])

    for trail in trails:
        if isinstance(trail, dict) and trail.get("CloudWatchLogsLogGroupArn"):
            return PreCheckResult("ALRT-001", "PASS", "LogGroupArn present", [])
    return PreCheckResult("ALRT-001", "FAIL", "no trail with CloudWatch Logs", [])


def _alerting_critical_topic_arns(evidence: Dict[str, Any]) -> List[str]:
    arns: List[str] = []
    alarms = evidence.get("cloudwatch-alarms")
    if isinstance(alarms, list):
        for a in alarms:
            if not isinstance(a, dict):
                continue
            for act in a.get("AlarmActions", []) or []:
                if isinstance(act, str) and act.startswith("arn:aws:sns:"):
                    arns.append(act)

    rules = evidence.get("eventbridge-rules")
    if isinstance(rules, list):
        for r in rules:
            if not isinstance(r, dict):
                continue
            for t in r.get("Targets", []) or []:
                if isinstance(t, dict):
                    arn = t.get("Arn")
                    if isinstance(arn, str) and arn.startswith("arn:aws:sns:"):
                        arns.append(arn)
    return list(dict.fromkeys(arns))


def _parse_policy_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and any(x == "*" for x in aws):
            return True
    return False


@_register("alerting")
def check_alr_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should not allow broad publish access."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-022", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:publish", "sns:*", "*"} for a in actions_list):
                continue
            if _principal_is_wildcard_any(
                st.get("Principal")
            ) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "ALRT-022", "FAIL", "alert SNS topic allows broad Publish", [arn]
                )

    return PreCheckResult(
        "ALRT-022", "PASS", "no broad publish permissions on alert SNS topics", []
    )


@_register("alerting")
def check_alr_023(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should not allow broad subscribe access."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-023", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:subscribe", "sns:*", "*"} for a in actions_list):
                continue
            if _principal_is_wildcard(
                st.get("Principal")
            ) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "ALRT-023", "FAIL", "alert SNS topic allows broad Subscribe", [arn]
                )

    return PreCheckResult(
        "ALRT-023", "PASS", "no broad subscribe permissions on alert SNS topics", []
    )


@_register("alerting")
def check_alr_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical alert topics should avoid risky HTTP/HTTPS subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-024", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    risky = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        subs = t.get("Subscriptions") if isinstance(t.get("Subscriptions"), list) else []
        for s in subs:
            if not isinstance(s, dict):
                continue
            protocol = str(s.get("Protocol") or "").lower()
            if protocol in {"http", "https"}:
                risky.append(arn)
                break

    if not risky:
        return PreCheckResult(
            "ALRT-024", "PASS", "no risky HTTP/HTTPS subscriptions on alert topics", []
        )
    return PreCheckResult(
        "ALRT-024",
        "FAIL",
        f"{len(risky)} alert SNS topics with HTTP/HTTPS subscriptions",
        risky[:10],
    )


@_register("alerting")
def check_alr_025(evidence: Dict[str, Any]) -> PreCheckResult:
    """Critical EventBridge rules should forward to SNS alerting topics."""
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list) or not rules:
        return PreCheckResult("ALRT-025", "SKIP", "no eventbridge-rules evidence", [])

    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        # Skip AWS-managed service rules (e.g. Amazon Inspector managed rules)
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        is_security_rule = (
            "cloudtrail" in pattern or "consolelogin" in pattern or "stoplogging" in pattern
        )
        if not is_security_rule:
            continue
        targets = r.get("Targets") if isinstance(r.get("Targets"), list) else []
        has_sns = any(
            isinstance(t, dict) and str(t.get("Arn") or "").startswith("arn:aws:sns:")
            for t in targets
        )
        if not has_sns:
            return PreCheckResult(
                "ALRT-025",
                "FAIL",
                "security EventBridge rule without SNS target",
                [str(r.get("Arn") or r.get("Name") or "unknown")],
            )

    return PreCheckResult(
        "ALRT-025", "PASS", "critical security EventBridge rules route to SNS", []
    )


@_register("alerting")
def check_alrt_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-005: Critical alert SNS topics should have confirmed subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-005", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    no_subs = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        confirmed = int(attrs.get("SubscriptionsConfirmed", 0) or 0)
        if confirmed == 0:
            no_subs.append(arn)

    if no_subs:
        return PreCheckResult(
            "ALRT-005", "FAIL", "alert SNS topic(s) have no confirmed subscriptions", no_subs[:5]
        )
    return PreCheckResult("ALRT-005", "PASS", "alert SNS topics have confirmed subscriptions", [])


@_register("alerting")
def check_alrt_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-006: Critical alert SNS topics should not have pending subscriptions."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-006", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    pending_topics = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if critical and arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pending = int(attrs.get("SubscriptionsPending", 0) or 0)
        if pending > 0:
            pending_topics.append(arn)

    if pending_topics:
        return PreCheckResult(
            "ALRT-006",
            "FAIL",
            f"{len(pending_topics)} alert SNS topic(s) with pending subscriptions",
            pending_topics[:5],
        )
    return PreCheckResult("ALRT-006", "PASS", "no pending subscriptions on alert SNS topics", [])


@_register("alerting")
def check_alrt_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-008: At least one CloudTrail trail should be multi-region."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-008", "SKIP", "no cloudtrail-trails evidence", [])

    for trail in trails:
        if isinstance(trail, dict) and trail.get("IsMultiRegionTrail"):
            return PreCheckResult("ALRT-008", "PASS", "multi-region trail present", [])

    single_region_names = [str(t.get("Name") or "") for t in trails if isinstance(t, dict)]
    return PreCheckResult(
        "ALRT-008",
        "FAIL",
        "no multi-region trail configured",
        single_region_names[:5],
    )


@_register("alerting")
def check_alrt_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-013: CloudTrail trails should have log file validation enabled."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-013", "SKIP", "no cloudtrail-trails evidence", [])

    # Only check trails we own (not org trails from other accounts)
    invalid = []
    has_checkable_trail = False
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip org trails where we can't verify status (Status is empty dict)
        if trail.get("IsOrganizationTrail") and not trail.get("Status", {}).get("IsLogging"):
            continue
        has_checkable_trail = True
        if not trail.get("LogFileValidationEnabled"):
            invalid.append(str(trail.get("Name") or "unknown"))

    if not has_checkable_trail:
        return PreCheckResult("ALRT-013", "SKIP", "no locally-owned trails to check", [])
    if invalid:
        return PreCheckResult(
            "ALRT-013",
            "FAIL",
            f"{len(invalid)} trail(s) without log file validation",
            invalid[:5],
        )
    return PreCheckResult("ALRT-013", "PASS", "all trails have log file validation enabled", [])


@_register("alerting")
def check_alrt_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-014: CloudTrail trails should encrypt logs with KMS."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-014", "SKIP", "no cloudtrail-trails evidence", [])

    no_kms = []
    has_checkable_trail = False
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip org trails we don't own
        if trail.get("IsOrganizationTrail") and not trail.get("Status", {}).get("IsLogging"):
            continue
        has_checkable_trail = True
        if not trail.get("KMSKeyId"):
            no_kms.append(str(trail.get("Name") or "unknown"))

    if not has_checkable_trail:
        return PreCheckResult("ALRT-014", "SKIP", "no locally-owned trails to check", [])
    if no_kms:
        return PreCheckResult(
            "ALRT-014",
            "FAIL",
            f"{len(no_kms)} trail(s) without KMS encryption",
            no_kms[:5],
        )
    return PreCheckResult("ALRT-014", "PASS", "all trails encrypted with KMS", [])


@_register("alerting")
def check_alrt_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-002: CloudTrail should be integrated with EventBridge (active security rules).

    PASS if EventBridge rules consume CloudTrail events.
    PASS (alternative path) if CloudTrail -> CloudWatch Logs + metric filters provide equivalent
    alerting coverage (at least 3 security-relevant metric filters on the CT log group).
    FAIL otherwise — no alerting path configured.
    """
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list):
        return PreCheckResult("ALRT-002", "SKIP", "no eventbridge-rules evidence", [])

    # --- Primary path: EventBridge rules consuming CloudTrail ---
    cloudtrail_rules: List[str] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        # Skip AWS-managed service rules (e.g. Inspector managed rules)
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        # Must be ENABLED
        if str(r.get("State") or "").upper() != "ENABLED":
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        if "aws.cloudtrail" in pattern or '"cloudtrail"' in pattern:
            cloudtrail_rules.append(name)

    if cloudtrail_rules:
        return PreCheckResult(
            "ALRT-002",
            "PASS",
            f"{len(cloudtrail_rules)} enabled EventBridge rule(s) processing CloudTrail events",
            [],
        )

    # --- Alternative path: CloudTrail -> CloudWatch Logs + Metric Filters ---
    # If CloudTrail delivers to a CW Logs log group AND that group has security metric filters,
    # alerting coverage is equivalent; EventBridge integration is still a best-practice improvement
    # but NOT a critical gap. Downgrade to informational FAIL instead of blocking Critical.
    trails = evidence.get("cloudtrail-trails") or []
    metric_filters = evidence.get("cloudwatch-metric-filters") or []

    ct_log_groups: set = set()
    for t in trails:
        if not isinstance(t, dict):
            continue
        lg_arn = t.get("CloudWatchLogsLogGroupArn") or ""
        if lg_arn:
            # extract log group name from ARN
            parts = lg_arn.split(":log-group:")
            if len(parts) == 2:
                ct_log_groups.add(parts[1].rstrip(":*"))

    if ct_log_groups and isinstance(metric_filters, list):
        ct_metric_filters = [
            mf for mf in metric_filters
            if isinstance(mf, dict) and mf.get("logGroupName") in ct_log_groups
        ]
        if len(ct_metric_filters) >= 3:
            return PreCheckResult(
                "ALRT-002",
                "FAIL",
                (
                    f"no EventBridge rules for CloudTrail, but {len(ct_metric_filters)} "
                    f"CloudWatch metric filter(s) provide alternative coverage — "
                    f"EventBridge integration is a best-practice improvement (Medium risk)"
                ),
                [],
            )

    return PreCheckResult(
        "ALRT-002",
        "FAIL",
        "no enabled EventBridge rules processing CloudTrail events and no CloudWatch metric filter coverage",
        [],
    )


@_register("alerting")
def check_alrt_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-003: Metric filters should have associated CloudWatch alarms."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-003", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = evidence collected but zero filters exist → no alarms possible → FAIL
    if not metric_filters:
        return PreCheckResult(
            "ALRT-003",
            "FAIL",
            "no metric filters configured (zero filters means no alarm coverage possible)",
            [],
        )

    alarms = evidence.get("cloudwatch-alarms")
    if not isinstance(alarms, list):
        alarms = []

    # Build set of metric names that have at least one alarm
    alarm_metric_names = {
        str(a.get("MetricName") or "")
        for a in alarms
        if isinstance(a, dict) and a.get("MetricName")
    }

    filters_without_alarm: List[str] = []
    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        for mt in mf.get("metricTransformations") or []:
            if not isinstance(mt, dict):
                continue
            metric_name = str(mt.get("metricName") or "")
            if metric_name and metric_name not in alarm_metric_names:
                filters_without_alarm.append(str(mf.get("filterName") or "unknown"))
                break

    if filters_without_alarm:
        return PreCheckResult(
            "ALRT-003",
            "FAIL",
            f"{len(filters_without_alarm)} metric filter(s) without associated CloudWatch alarm",
            filters_without_alarm[:10],
        )
    return PreCheckResult(
        "ALRT-003", "PASS", "all metric filters have associated CloudWatch alarms", []
    )


@_register("alerting")
def check_alrt_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-004: Security EventBridge rules should have SNS notification targets."""
    rules = evidence.get("eventbridge-rules")
    if not isinstance(rules, list):
        return PreCheckResult("ALRT-004", "SKIP", "no eventbridge-rules evidence", [])

    security_rules_without_sns: List[str] = []
    has_security_rules = False
    for r in rules:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "")
        if name.startswith("DO-NOT-DELETE-Amazon"):
            continue
        if str(r.get("State") or "").upper() != "ENABLED":
            continue
        pattern = str(r.get("EventPattern") or "").lower()
        if not ("aws.cloudtrail" in pattern or "cloudtrail" in pattern):
            continue
        has_security_rules = True
        targets = r.get("Targets") if isinstance(r.get("Targets"), list) else []
        has_sns = any(
            isinstance(t, dict) and str(t.get("Arn") or "").startswith("arn:aws:sns:")
            for t in targets
        )
        if not has_sns:
            security_rules_without_sns.append(name)

    if not has_security_rules:
        return PreCheckResult(
            "ALRT-004", "SKIP", "no security-relevant EventBridge rules found", []
        )
    if security_rules_without_sns:
        return PreCheckResult(
            "ALRT-004",
            "FAIL",
            f"{len(security_rules_without_sns)} security EventBridge rule(s) without SNS target",
            security_rules_without_sns[:5],
        )
    return PreCheckResult("ALRT-004", "PASS", "all security EventBridge rules have SNS targets", [])


@_register("alerting")
def check_alrt_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-007: Critical security events should be covered by metric filters."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-007", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = ALL critical events uncovered → FAIL

    # Critical events that must be covered by at least one metric filter
    critical_events = {
        "StopLogging": False,
        "DeleteTrail": False,
        "CreateUser": False,
        "ConsoleLogin": False,
    }

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        for event in list(critical_events.keys()):
            if event.lower() in pattern:
                critical_events[event] = True

    missing = [e for e, covered in critical_events.items() if not covered]
    if missing:
        return PreCheckResult(
            "ALRT-007",
            "FAIL",
            f"critical events not covered by metric filters: {', '.join(missing)}",
            missing,
        )
    return PreCheckResult(
        "ALRT-007", "PASS", "all critical security events covered by metric filters", []
    )


@_register("alerting")
def check_alrt_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-009: CloudTrail log group should have metric filters for security events."""
    trails = evidence.get("cloudtrail-trails", [])
    if not isinstance(trails, list) or not trails:
        return PreCheckResult("ALRT-009", "SKIP", "no cloudtrail-trails evidence", [])

    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-009", "SKIP", "no cloudwatch-metric-filters evidence", [])

    # Find the local (non-org) CloudTrail-integrated log group name from the trail's ARN.
    # Org trails belong to a management account and cannot have metric filters added
    # from this account — always prefer non-org trails.
    ct_log_group: str = ""
    for trail in trails:
        if not isinstance(trail, dict):
            continue
        # Skip organization trails — they're owned by a parent account
        if trail.get("IsOrganizationTrail"):
            continue
        if trail.get("CloudWatchLogsLogGroupArn"):
            arn = str(trail["CloudWatchLogsLogGroupArn"])
            # ARN format: arn:aws:logs:region:account:log-group:NAME:*
            parts = arn.split(":")
            if len(parts) >= 7:
                ct_log_group = parts[6]
                break

    if not ct_log_group:
        return PreCheckResult("ALRT-009", "SKIP", "no CloudTrail log group configured", [])

    filters_for_ct = [
        mf
        for mf in metric_filters
        if isinstance(mf, dict) and mf.get("logGroupName") == ct_log_group
    ]

    if filters_for_ct:
        return PreCheckResult(
            "ALRT-009",
            "PASS",
            f"{len(filters_for_ct)} metric filter(s) on CloudTrail log group '{ct_log_group}'",
            [],
        )
    return PreCheckResult(
        "ALRT-009",
        "FAIL",
        f"no metric filters on CloudTrail log group '{ct_log_group}'",
        [ct_log_group],
    )


@_register("alerting")
def check_alrt_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-017: CloudWatch log groups should have adequate retention (>=90 days)."""
    log_groups = evidence.get("cloudwatch-log-groups")
    if not isinstance(log_groups, list) or not log_groups:
        return PreCheckResult("ALRT-017", "SKIP", "no cloudwatch-log-groups evidence", [])

    short_retention: List[str] = []
    for lg in log_groups:
        if not isinstance(lg, dict):
            continue
        retention = lg.get("RetentionInDays")
        # None means "never expire" — acceptable
        if retention is not None and int(retention) < 90:
            short_retention.append(str(lg.get("LogGroupName") or "unknown"))

    if short_retention:
        return PreCheckResult(
            "ALRT-017",
            "FAIL",
            f"{len(short_retention)} log group(s) with retention < 90 days",
            short_retention[:15],
        )
    return PreCheckResult(
        "ALRT-017", "PASS", "all log groups have retention >= 90 days or unlimited", []
    )


@_register("alerting")
def check_alrt_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-010: CloudWatch alarms should not be in INSUFFICIENT_DATA state."""
    alarms = evidence.get("cloudwatch-alarms")
    if not isinstance(alarms, list) or not alarms:
        return PreCheckResult("ALRT-010", "SKIP", "no cloudwatch-alarms evidence", [])

    # Only check alarms that have a StateValue (collector must include it)
    alarms_with_state = [a for a in alarms if isinstance(a, dict) and a.get("StateValue")]
    if not alarms_with_state:
        return PreCheckResult(
            "ALRT-010", "SKIP", "no StateValue data in alarms (collector may not collect it)", []
        )

    insufficient = [
        str(a.get("AlarmName") or "unknown")
        for a in alarms_with_state
        if str(a.get("StateValue") or "").upper() == "INSUFFICIENT_DATA"
    ]

    if insufficient:
        return PreCheckResult(
            "ALRT-010",
            "FAIL",
            f"{len(insufficient)} alarm(s) in INSUFFICIENT_DATA state",
            insufficient[:10],
        )
    return PreCheckResult("ALRT-010", "PASS", "no alarms in INSUFFICIENT_DATA state", [])


@_register("alerting")
def check_alrt_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-011: Alert SNS topics should restrict Publish to authorized principals."""
    topics = evidence.get("sns-topics")
    if not isinstance(topics, list) or not topics:
        return PreCheckResult("ALRT-011", "SKIP", "no sns-topics evidence", [])

    critical = set(_alerting_critical_topic_arns(evidence))
    if not critical:
        return PreCheckResult(
            "ALRT-011", "SKIP", "no alert SNS topics found (no alarm/EB actions)", []
        )

    # Authorized publishers: CloudWatch Alarms and EventBridge services
    _authorized_service_principals = {
        "cloudwatch.amazonaws.com",
        "events.amazonaws.com",
        "lambda.amazonaws.com",
    }

    broad_topics: List[str] = []
    for t in topics:
        if not isinstance(t, dict):
            continue
        arn = str(t.get("TopicArn") or "")
        if arn not in critical:
            continue
        attrs = t.get("Attributes") if isinstance(t.get("Attributes"), dict) else {}
        pol = _parse_policy_json(attrs.get("Policy"))
        for st in pol.get("Statement", []) or []:
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = st.get("Action")
            actions_list = (
                [actions]
                if isinstance(actions, str)
                else (actions if isinstance(actions, list) else [])
            )
            actions_list = [str(a).lower() for a in actions_list]
            if not any(a in {"sns:publish", "sns:*", "*"} for a in actions_list):
                continue
            principal = st.get("Principal")
            # PASS: service principal (e.g. cloudwatch.amazonaws.com)
            if isinstance(principal, dict):
                service = principal.get("Service")
                services = (
                    [service]
                    if isinstance(service, str)
                    else (service if isinstance(service, list) else [])
                )
                if all(str(s) in _authorized_service_principals for s in services if s):
                    continue
            # PASS: same-account restriction (Principal:* + SourceOwner condition) is
            # the AWS default policy. We only flag it if there is NO condition at all
            # or the condition does not restrict to same account.
            if _principal_is_wildcard_any(principal):
                if not _stmt_has_same_account_restriction(st):
                    broad_topics.append(arn)
                    break
                # Has same-account condition but still allows any IAM principal to Publish.
                # This is the AWS default policy — flag as informational (PASS here, LLM catches nuance)
                # We don't fail here because AWS auto-creates this policy for every new topic.

    if broad_topics:
        return PreCheckResult(
            "ALRT-011",
            "FAIL",
            f"{len(broad_topics)} alert topic(s) allow broad Publish without account restriction",
            broad_topics[:5],
        )
    return PreCheckResult(
        "ALRT-011", "PASS", "alert topics restrict Publish to authorized principals", []
    )


@_register("alerting")
def check_alrt_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-015: A metric filter should cover IAM change events."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-015", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = IAM events not monitored

    _iam_events = [
        "putuseropolicy",
        "attachuserpolicy",
        "attachgrouppolicy",
        "putgrouppolicy",
        "putrolepolicy",
        "attachrolepolicy",
        "createaccesskey",
        "putuserpolicy",  # alternate casing
    ]

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        if any(event in pattern for event in _iam_events):
            return PreCheckResult("ALRT-015", "PASS", "metric filter covers IAM change events", [])

    return PreCheckResult(
        "ALRT-015",
        "FAIL",
        "no metric filter covering IAM change events (PutUserPolicy, AttachUserPolicy, etc.)",
        [],
    )


@_register("alerting")
def check_alrt_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-016: A metric filter should cover Security Group change events."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    if not isinstance(metric_filters, list):
        return PreCheckResult("ALRT-016", "SKIP", "no cloudwatch-metric-filters evidence", [])
    # Empty list = no filters at all = SG events not monitored

    _sg_events = [
        "authorizesecuritygroupingress",
        "authorizesecuritygroupegress",
        "revokesecuritygroupingress",
        "revokesecuritygroupegress",
        "createsecuritygroup",
        "deletesecuritygroup",
    ]

    for mf in metric_filters:
        if not isinstance(mf, dict):
            continue
        pattern = str(mf.get("filterPattern") or "").lower()
        if any(event in pattern for event in _sg_events):
            return PreCheckResult(
                "ALRT-016", "PASS", "metric filter covers Security Group change events", []
            )

    return PreCheckResult(
        "ALRT-016",
        "FAIL",
        "no metric filter covering Security Group change events (AuthorizeSecurityGroupIngress, etc.)",
        [],
    )


@_register("alerting")
def check_alrt_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """ALRT-012: Critical security events (ConsoleLogin, CreateUser, StopLogging) should be alerted via metric filter or EventBridge rule."""
    metric_filters = evidence.get("cloudwatch-metric-filters")
    rules = evidence.get("eventbridge-rules")

    # Need at least one evidence source to evaluate
    if not isinstance(metric_filters, list) and not isinstance(rules, list):
        return PreCheckResult("ALRT-012", "SKIP", "no metric-filter or eventbridge evidence", [])

    _critical_events = ["consolelogin", "createuser", "stoplogging"]

    # Check metric filters for coverage
    if isinstance(metric_filters, list):
        for mf in metric_filters:
            if not isinstance(mf, dict):
                continue
            pattern = str(mf.get("filterPattern") or "").lower()
            if any(evt in pattern for evt in _critical_events):
                return PreCheckResult(
                    "ALRT-012",
                    "PASS",
                    "metric filter covers critical security events (ConsoleLogin/CreateUser/StopLogging)",
                    [],
                )

    # Check EventBridge rules for security event coverage
    if isinstance(rules, list):
        for r in rules:
            if not isinstance(r, dict):
                continue
            name = str(r.get("Name") or "")
            if name.startswith("DO-NOT-DELETE-Amazon"):
                continue
            if str(r.get("State") or "").upper() != "ENABLED":
                continue
            pattern = str(r.get("EventPattern") or "").lower()
            if any(evt in pattern for evt in _critical_events):
                return PreCheckResult(
                    "ALRT-012",
                    "PASS",
                    "EventBridge rule covers critical security events (ConsoleLogin/CreateUser/StopLogging)",
                    [],
                )

    return PreCheckResult(
        "ALRT-012",
        "FAIL",
        "no alert configured for critical events: ConsoleLogin, CreateUser, StopLogging",
        [],
    )


# ============================================================================
# EXPOSURE PRE-CHECKS
# ============================================================================


@_register("exposure")
def check_exp_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public S3 bucket exposure."""
    s3_doc = evidence.get("s3-buckets")
    items = _items_from_doc(s3_doc)
    if not items:
        return PreCheckResult("EXP-001", "SKIP", "no s3-buckets evidence", [])

    def _is_public_acl(grants):
        if not isinstance(grants, list):
            return False
        for g in grants:
            if not isinstance(g, dict):
                continue
            gr = g.get("Grantee")
            if isinstance(gr, dict) and gr.get("Type") == "Group":
                uri = gr.get("URI", "")
                if "AllUsers" in str(uri) or "AuthenticatedUsers" in str(uri):
                    return True
        return False

    def _has_public_policy(policy):
        if not isinstance(policy, dict):
            return False
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if principal != "*" and not (
                isinstance(principal, dict) and principal.get("AWS") == "*"
            ):
                continue
            act = st.get("Action")
            actions = [act] if isinstance(act, str) else (act or [])
            if any(a in actions for a in ("s3:*", "s3:GetObject", "s3:ListBucket")):
                return True
        return False

    # Also try by_name lookup
    by_name = {}
    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
        by_name = s3_doc["by_name"]

    all_buckets = list(by_name.values()) if by_name else items
    public = []
    for b in all_buckets:
        if not isinstance(b, dict):
            continue
        if _is_public_acl(b.get("ACL")) or _has_public_policy(b.get("BucketPolicy")):
            public.append(f"arn:aws:s3:::{b.get('Name', 'unknown')}")

    if not public:
        return PreCheckResult("EXP-001", "PASS", "no public S3 buckets", [])
    return PreCheckResult("EXP-001", "FAIL", f"{len(public)} public buckets", public[:10])


@_register("exposure")
def check_exp_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """RDS instances publicly accessible from internet."""
    rds_doc = evidence.get("rds-instances")
    rds_items = _items_from_doc(rds_doc)
    if not rds_items:
        return PreCheckResult("EXP-002", "SKIP", "no rds-instances evidence", [])

    public = [i for i in rds_items if isinstance(i, dict) and i.get("PubliclyAccessible") is True]
    if not public:
        return PreCheckResult("EXP-002", "PASS", "no publicly accessible RDS", [])
    names = [p.get("DBInstanceIdentifier", "unknown") for p in public[:5]]
    return PreCheckResult("EXP-002", "FAIL", f"{len(public)} public RDS instances", names)


@_register("exposure")
def check_exp_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """SSH/RDP open to 0.0.0.0/0."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    # Also handle by_id shape
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("EXP-003", "SKIP", "no security-groups evidence", [])

    exposed = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            if _sg_allows_world(perm, port=22) or _sg_allows_world(perm, port=3389):
                exposed.append(sg.get("GroupId", "unknown"))
                break

    if not exposed:
        return PreCheckResult("EXP-003", "PASS", "no SSH/RDP open to world", [])
    return PreCheckResult("EXP-003", "FAIL", f"{len(exposed)} SGs with SSH/RDP open", exposed[:10])


@_register("exposure")
def check_exp_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Internet-facing ALB/NLB without WAF association."""
    lbs_doc = evidence.get("load-balancers")
    assoc_doc = evidence.get("wafv2-web-acl-alb-associations")
    if not isinstance(lbs_doc, dict) or not isinstance(assoc_doc, dict):
        return PreCheckResult("EXP-007", "SKIP", "missing LB/WAF evidence", [])

    lbs = _items_from_doc(lbs_doc)
    by_alb = assoc_doc.get("by_alb_arn", {})
    if not isinstance(by_alb, dict):
        by_alb = {}

    internet_albs = [
        lb
        for lb in lbs
        if isinstance(lb, dict)
        and lb.get("Type") == "application"
        and lb.get("Scheme") == "internet-facing"
        and isinstance(lb.get("LoadBalancerArn"), str)
    ]

    if not internet_albs:
        return PreCheckResult("EXP-007", "PASS", "no internet-facing ALBs", [])

    unprotected = []
    for alb in internet_albs:
        arn = alb["LoadBalancerArn"]
        if not (by_alb.get(arn) or []):
            unprotected.append(arn)

    if not unprotected:
        return PreCheckResult("EXP-007", "PASS", "all internet ALBs have WAF", [])
    return PreCheckResult(
        "EXP-007", "FAIL", f"{len(unprotected)} ALBs without WAF", unprotected[:5]
    )


@_register("exposure")
def check_exp_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """Obsolete TLS policies on internet-facing ALB."""
    lbs_doc = evidence.get("load-balancers")
    lis_doc = evidence.get("load-balancer-listeners")
    if not isinstance(lbs_doc, dict) or not isinstance(lis_doc, dict):
        return PreCheckResult("EXP-010", "SKIP", "missing ELBv2 evidence", [])

    lbs = _items_from_doc(lbs_doc)
    scheme_by_arn = {
        lb.get("LoadBalancerArn"): lb.get("Scheme")
        for lb in lbs
        if isinstance(lb, dict) and isinstance(lb.get("LoadBalancerArn"), str)
    }
    listeners = _items_from_doc(lis_doc)

    for li in listeners:
        if not isinstance(li, dict) or li.get("Protocol") != "HTTPS":
            continue
        lb_arn = li.get("LoadBalancerArn")
        if not isinstance(lb_arn, str) or scheme_by_arn.get(lb_arn) != "internet-facing":
            continue
        pol = li.get("SslPolicy")
        if not isinstance(pol, str):
            continue
        if (
            "TLS-1-0" in pol
            or "TLS-1-1" in pol
            or pol in {"ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08"}
        ):
            return PreCheckResult("EXP-010", "FAIL", f"obsolete TLS policy: {pol}", [lb_arn])

    return PreCheckResult("EXP-010", "PASS", "no obsolete TLS policies", [])


@_register("exposure")
def check_exp_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public object listing on S3."""
    s3_doc = evidence.get("s3-buckets")
    items = _items_from_doc(s3_doc)
    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
        items = list(s3_doc["by_name"].values())

    for b in items:
        if not isinstance(b, dict):
            continue
        policy = b.get("BucketPolicy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if principal != "*" and not (
                isinstance(principal, dict) and principal.get("AWS") == "*"
            ):
                continue
            act = st.get("Action")
            actions = [act] if isinstance(act, str) else (act or [])
            if "s3:ListBucket" in actions:
                return PreCheckResult(
                    "EXP-011",
                    "FAIL",
                    f"bucket '{b.get('Name')}' allows public ListBucket",
                    [f"arn:aws:s3:::{b.get('Name', '')}"],
                )

    return PreCheckResult("EXP-011", "PASS", "no public ListBucket", [])


@_register("exposure")
def check_exp_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 TLS enforcement (aws:SecureTransport deny)."""
    s3_doc = evidence.get("s3-buckets")
    if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
        return PreCheckResult("EXP-013", "SKIP", "no indexed s3-buckets", [])

    by_name = s3_doc["by_name"]
    missing = []
    for bn, b in by_name.items():
        if not isinstance(b, dict):
            continue
        policy = b.get("BucketPolicy")
        if not isinstance(policy, dict):
            missing.append(bn)
            continue
        has_tls = False
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Deny":
                continue
            cond = st.get("Condition")
            if isinstance(cond, dict):
                bl = cond.get("Bool")
                if isinstance(bl, dict) and bl.get("aws:SecureTransport") == "false":
                    has_tls = True
                    break
        if not has_tls:
            missing.append(bn)

    if not missing:
        return PreCheckResult("EXP-013", "PASS", "all buckets enforce TLS", [])
    return PreCheckResult(
        "EXP-013",
        "FAIL",
        f"{len(missing)} buckets without TLS enforcement",
        [f"arn:aws:s3:::{n}" for n in missing[:5]],
    )


@_register("exposure")
def check_exp_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 audit/log buckets should have versioning enabled."""
    s3_doc = evidence.get("s3-buckets")
    if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
        return PreCheckResult("EXP-014", "SKIP", "no indexed s3-buckets", [])

    by_name = s3_doc["by_name"]
    unversioned = []
    for bn, b in by_name.items():
        if not isinstance(b, dict):
            continue
        if (b.get("Versioning") or "") != "Enabled":
            unversioned.append(bn)

    if not unversioned:
        return PreCheckResult("EXP-014", "PASS", "all buckets have versioning", [])
    return PreCheckResult(
        "EXP-014",
        "FAIL",
        f"{len(unversioned)} buckets without versioning",
        [f"arn:aws:s3:::{n}" for n in unversioned[:5]],
    )


@_register("exposure")
def check_exp_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """S3 cross-account bucket policy access."""
    s3_doc = evidence.get("s3-buckets")
    items = _items_from_doc(s3_doc)
    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
        items = list(s3_doc["by_name"].values())

    meta = evidence.get("_audit_metadata")
    audit_account = meta.get("_account_id") if isinstance(meta, dict) else None

    if not audit_account:
        return PreCheckResult("EXP-015", "SKIP", "no audit account metadata", [])

    for b in items:
        if not isinstance(b, dict):
            continue
        policy = b.get("BucketPolicy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if principal == "*":
                return PreCheckResult(
                    "EXP-015",
                    "FAIL",
                    f"bucket '{b.get('Name')}' has Principal:*",
                    [f"arn:aws:s3:::{b.get('Name', '')}"],
                )
            if isinstance(principal, dict):
                aws_p = principal.get("AWS")
                principals = (
                    [aws_p]
                    if isinstance(aws_p, str)
                    else (aws_p if isinstance(aws_p, list) else [])
                )
                for p in principals:
                    if not isinstance(p, str):
                        continue
                    parts = p.split(":")
                    if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                        # Skip known AWS service accounts (e.g. ELB access logging)
                        if parts[4] in _AWS_SERVICE_ACCOUNTS:
                            continue
                        return PreCheckResult(
                            "EXP-015",
                            "FAIL",
                            f"cross-account principal {p}",
                            # Include both bucket and cross-account principal for traceability
                            [f"arn:aws:s3:::{b.get('Name', '')}", p],
                        )

    return PreCheckResult("EXP-015", "PASS", "no cross-account S3 policies", [])


@_register("exposure")
def check_exp_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda function URLs without authentication (AuthType=NONE)."""
    urls_doc = evidence.get("lambda-function-urls")
    items = _items_from_doc(urls_doc)
    if not items:
        return PreCheckResult("EXP-016", "SKIP", "no lambda-function-urls evidence", [])

    unauth = [
        u for u in items if isinstance(u, dict) and str(u.get("AuthType") or "").upper() == "NONE"
    ]
    if not unauth:
        return PreCheckResult("EXP-016", "PASS", "all Lambda URLs have authorization", [])

    resources = [str(u.get("FunctionArn") or u.get("FunctionUrl") or "unknown") for u in unauth[:5]]
    return PreCheckResult(
        "EXP-016",
        "FAIL",
        f"{len(unauth)} Lambda URL(s) without authorization",
        resources,
    )


@_register("exposure")
def check_exp_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 management/database ports (22, 3389, 3306, 5432) open to internet via SG."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())
    if not sgs:
        return PreCheckResult("EXP-004", "SKIP", "no security-groups evidence", [])

    mgmt_ports = {22, 3389, 3306, 5432, 1433}

    risky: List[str] = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = str(sg.get("GroupId") or "unknown")
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            if any(_sg_allows_world(perm, port=p) for p in mgmt_ports):
                risky.append(sg_id)
                break

    if not risky:
        return PreCheckResult("EXP-004", "PASS", "no management ports open to internet", [])
    return PreCheckResult(
        "EXP-004",
        "FAIL",
        f"{len(risky)} security group(s) with management/DB ports open to internet",
        risky[:10],
    )


@_register("exposure")
def check_exp_020(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudFront S3 origins should enforce OAI/OAC-style origin access controls."""
    cf_doc = evidence.get("cloudfront-distributions")
    dists = _items_from_doc(cf_doc)
    if not dists:
        return PreCheckResult("EXP-020", "SKIP", "no cloudfront-distributions evidence", [])

    risky = []
    for d in dists:
        if not isinstance(d, dict) or not d.get("Enabled"):
            continue
        did = str(d.get("Id") or "unknown")
        origins_obj = d.get("Origins")
        origins: List[Any] = []
        if isinstance(origins_obj, dict):
            maybe_items = origins_obj.get("Items")
            if isinstance(maybe_items, list):
                origins = maybe_items
        elif isinstance(origins_obj, list):
            origins = origins_obj

        for o in origins:
            if not isinstance(o, dict):
                continue
            domain = str(o.get("DomainName") or "").lower()
            if not domain or ".s3." not in domain and not domain.endswith(".s3.amazonaws.com"):
                continue

            s3_cfg = o.get("S3OriginConfig") if isinstance(o.get("S3OriginConfig"), dict) else {}
            oai = str(s3_cfg.get("OriginAccessIdentity") or "")
            has_oai = bool(oai.strip())

            # With list_distributions evidence we don't always get full OAC details.
            # Treat missing OAI as risky signal requiring follow-up verification.
            if not has_oai:
                risky.append(f"arn:aws:cloudfront::distribution/{did}")
                break

    if not risky:
        return PreCheckResult("EXP-020", "PASS", "no risky CloudFront S3 origins detected", [])
    return PreCheckResult(
        "EXP-020",
        "FAIL",
        f"{len(risky)} CloudFront distributions with S3 origin lacking clear OAI/OAC signal",
        risky[:10],
    )


@_register("exposure")
def check_exp_021(evidence: Dict[str, Any]) -> PreCheckResult:
    """API routes with mutating methods should not be unauthenticated."""
    routes_doc = evidence.get("api-gateway-routes")
    routes = _items_from_doc(routes_doc)
    if not routes:
        return PreCheckResult("EXP-021", "SKIP", "no api-gateway-routes evidence", [])

    mutating = {"POST", "PUT", "PATCH", "DELETE", "ANY"}
    exposed = []
    for r in routes:
        if not isinstance(r, dict):
            continue
        method = str(r.get("Method") or "").upper()
        if method not in mutating:
            continue
        auth = str(r.get("AuthorizationType") or "NONE").upper()
        if auth in {"NONE", ""}:
            api_id = str(r.get("ApiId") or "unknown")
            path = str(r.get("Path") or "")
            exposed.append(f"arn:aws:execute-api:*:*:{api_id}/*/{method}{path}")

    if not exposed:
        return PreCheckResult("EXP-021", "PASS", "no unauthenticated mutating API routes", [])
    return PreCheckResult(
        "EXP-021",
        "FAIL",
        f"{len(exposed)} unauthenticated mutating API routes",
        exposed[:10],
    )


@_register("exposure")
def check_exp_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """Wildcard proxy routes (ANY/{proxy+}) should not be unauthenticated."""
    routes_doc = evidence.get("api-gateway-routes")
    routes = _items_from_doc(routes_doc)
    if not routes:
        return PreCheckResult("EXP-022", "SKIP", "no api-gateway-routes evidence", [])

    risky = []
    for r in routes:
        if not isinstance(r, dict):
            continue
        method = str(r.get("Method") or "").upper()
        path = str(r.get("Path") or "")
        auth = str(r.get("AuthorizationType") or "NONE").upper()
        is_proxy = method == "ANY" or "{proxy+}" in path
        if is_proxy and auth in {"NONE", ""}:
            api_id = str(r.get("ApiId") or "unknown")
            risky.append(f"arn:aws:execute-api:*:*:{api_id}/*/{method}{path}")

    if not risky:
        return PreCheckResult("EXP-022", "PASS", "no unauthenticated wildcard API routes", [])
    return PreCheckResult(
        "EXP-022",
        "FAIL",
        f"{len(risky)} unauthenticated wildcard API routes",
        risky[:10],
    )


@_register("exposure")
def check_exp_023(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-023: Resource-based policies with Principal:* without effective conditions.

    Detects SQS, SNS, Secrets Manager, ECR, and OpenSearch resources whose resource-based
    policies allow any AWS identity (Principal: * or Principal.AWS: *) without conditions
    that restrict access.

    Severity:
      - Critical: Principal:* without ANY Condition clause (completely unrestricted)
      - High: Principal:* WITH Condition (but condition may be ineffective)

    A Principal:* without conditions allows any AWS identity from any account to access
    the resource, which is analogous to a public S3 bucket.
    """
    rbp_doc = evidence.get("resource-based-policies") or {}
    items = rbp_doc.get("items") if isinstance(rbp_doc, dict) else None

    if not isinstance(items, list):
        return PreCheckResult("EXP-023", "SKIP", "no resource-based-policies evidence", [])

    if not items:
        return PreCheckResult(
            "EXP-023", "PASS", "no resource-based policies found across checked services", []
        )

    critical_resources = []  # Principal:* without Condition
    high_resources = []  # Principal:* with Condition
    detailed_findings = []

    # Service principals that should always have SourceArn/SourceAccount conditions.
    # Without these conditions, any resource of that service type in any account can invoke the resource.
    _require_source_conditions = {"s3.amazonaws.com", "sns.amazonaws.com", "events.amazonaws.com"}
    _source_conditions_rbp = {"aws:sourcearn", "aws:sourceaccount", "aws:sourcevpce"}

    for item in items:
        if not isinstance(item, dict):
            continue

        resource_arn = str(item.get("ResourceArn") or "unknown")
        service = str(item.get("Service") or "unknown")
        policy_analysis = item.get("PolicyAnalysis", {})

        # Use enriched policy analysis if available, otherwise parse Policy directly
        wildcard_stmts = policy_analysis.get("WildcardStatements", [])

        # If no PolicyAnalysis, fall back to parsing Policy directly (for backward compatibility with tests)
        if not wildcard_stmts:
            policy_raw = item.get("Policy") or ""
            # Conditions that restrict the open Principal:* to a meaningful scope
            _scope_conditions_rbp = {
                "aws:sourceaccount",
                "aws:sourcearn",
                "aws:principalorgid",
                "aws:sourceorgid",
                "aws:sourcevpc",
                "aws:sourcevpce",
                "aws:principalaccount",
                "aws:sourceowner",
            }

            try:
                policy_doc = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
                if isinstance(policy_doc, dict):
                    for stmt in _stmts_from_policy(policy_doc):
                        if not isinstance(stmt, dict):
                            continue
                        if str(stmt.get("Effect", "")).upper() != "ALLOW":
                            continue

                        principal = stmt.get("Principal")
                        # Detect open principal: "*" string or {"AWS": "*"}
                        is_open_principal = False
                        if principal == "*":
                            is_open_principal = True
                        elif isinstance(principal, dict):
                            aws_p = principal.get("AWS")
                            if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
                                is_open_principal = True

                        if not is_open_principal:
                            continue

                        # Check for scope-restricting conditions (PASS if found)
                        cond = stmt.get("Condition") or {}
                        cond_text = json.dumps(cond, default=str).lower()
                        has_scope_cond = any(k in cond_text for k in _scope_conditions_rbp)

                        if has_scope_cond:
                            # If there's a restrictive condition, skip it (it's OK)
                            continue

                        # No restrictive condition found - this is a FAIL
                        if resource_arn not in [r["resource"] for r in critical_resources]:
                            critical_resources.append(
                                {
                                    "resource": resource_arn,
                                    "statement": stmt.get("Sid", "Unnamed"),
                                }
                            )

                        # Build detailed finding
                        detailed_findings.append(
                            {
                                "ResourceArn": resource_arn,
                                "Service": service,
                                "Severity": "Critical",
                                "Principal": principal,
                                "Action": stmt.get("Action"),
                                "Condition": stmt.get("Condition"),
                                "HasCondition": bool(stmt.get("Condition")),
                                "ReplacementPolicy": _generate_replacement_policy(
                                    resource_arn, service, stmt
                                ),
                            }
                        )
                        break  # one violation per resource
            except Exception:
                continue
            continue  # skip to next item after fallback parsing

        for stmt in wildcard_stmts:
            if not isinstance(stmt, dict):
                continue

            # Skip if has mitigating condition (scope-restricting)
            has_mitigating_cond = stmt.get("HasMitigatingCondition", False)
            if has_mitigating_cond:
                continue  # This is acceptable, skip to next statement

            # No mitigating condition - this is a FAIL
            if resource_arn not in [r["resource"] for r in critical_resources]:
                critical_resources.append(
                    {
                        "resource": resource_arn,
                        "statement": stmt.get("Sid", "Unnamed"),
                    }
                )

            # Build detailed finding for snippet
            detailed_findings.append(
                {
                    "ResourceArn": resource_arn,
                    "Service": service,
                    "Severity": "Critical",
                    "Principal": stmt.get("Principal"),
                    "Action": stmt.get("Action"),
                    "Condition": stmt.get("Condition"),
                    "HasCondition": bool(stmt.get("Condition")),
                    "ReplacementPolicy": _generate_replacement_policy(resource_arn, service, stmt),
                }
            )
            break  # one violation per resource

        # Also check service principals (confused deputy) in all policy statements
        # (Not covered by wildcard_stmts which only handles Principal:*)
        all_policy_raw = item.get("Policy") or ""
        try:
            all_policy_doc = (
                json.loads(all_policy_raw) if isinstance(all_policy_raw, str) else all_policy_raw
            )
            if isinstance(all_policy_doc, dict):
                for stmt in _stmts_from_policy(all_policy_doc):
                    if not isinstance(stmt, dict):
                        continue
                    if str(stmt.get("Effect", "")).upper() != "ALLOW":
                        continue
                    principal = stmt.get("Principal", {})
                    svc_principal = None
                    if isinstance(principal, dict):
                        svc = principal.get("Service")
                        if isinstance(svc, str):
                            svc_principal = svc.lower()
                        elif isinstance(svc, list):
                            for s in svc:
                                if str(s).lower() in _require_source_conditions:
                                    svc_principal = str(s).lower()
                                    break
                    if svc_principal and svc_principal in _require_source_conditions:
                        cond = stmt.get("Condition") or {}
                        cond_text = json.dumps(cond, default=str).lower()
                        has_source_cond = any(k in cond_text for k in _source_conditions_rbp)
                        if (
                            not has_source_cond
                            and resource_arn not in [r["resource"] for r in high_resources]
                            and resource_arn not in [r["resource"] for r in critical_resources]
                        ):
                            high_resources.append(
                                {
                                    "resource": resource_arn,
                                    "statement": stmt.get("Sid", "Unnamed"),
                                    "note": f"service principal {svc_principal} without SourceArn/SourceAccount",
                                }
                            )
                            detailed_findings.append(
                                {
                                    "ResourceArn": resource_arn,
                                    "Service": service,
                                    "Severity": "High",
                                    "Principal": principal,
                                    "Action": stmt.get("Action"),
                                    "Condition": stmt.get("Condition"),
                                    "Note": f"Confused deputy risk: {svc_principal} has no SourceArn condition",
                                }
                            )
                            break
        except Exception:
            pass

    if not critical_resources and not high_resources:
        return PreCheckResult(
            "EXP-023",
            "PASS",
            "no resource-based policies with unrestricted Principal:* found",
            [],
        )

    # Affected resources list (critical first)
    affected_labels = [r["resource"] for r in critical_resources] + [
        r["resource"] for r in high_resources
    ]

    # Summary
    summary_parts = []
    if critical_resources:
        summary_parts.append(f"{len(critical_resources)} CRITICAL (no Condition)")
    if high_resources:
        summary_parts.append(f"{len(high_resources)} HIGH (with Condition)")
    summary = "Principal:* found: " + ", ".join(summary_parts)

    return PreCheckResult(
        "EXP-023",
        "FAIL",
        summary,
        affected_labels[:10],
        metadata={"detailed_findings": detailed_findings[:5]},
    )


def _generate_replacement_policy(
    resource_arn: str, service: str, statement: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate a suggested replacement policy statement restricting Principal:*.

    Returns a sample replacement policy that scopes access to a specific role/account.
    """
    actions = statement.get("Action", ["*"])
    if isinstance(actions, str):
        actions = [actions]

    # Suggest restricting to a service role
    suggested_principal = {"AWS": "arn:aws:iam::ACCOUNT_ID:role/SERVICE_ROLE"}  # Placeholder

    # Use the existing condition if present, otherwise suggest one
    suggested_condition = statement.get("Condition") or {
        "StringEquals": {"aws:PrincipalAccount": "ACCOUNT_ID"}
    }

    replacement_statement = {
        "Sid": statement.get("Sid", "RestrictedAccess"),
        "Effect": "Allow",
        "Principal": suggested_principal,
        "Action": actions,
        "Resource": "*",
        "Condition": suggested_condition,
    }

    return {
        "Statement": [replacement_statement],
        "Comment": "Replace the unrestricted Principal:* with a specific role/account and Condition",
    }


@_register("exposure")
def check_exp_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-024: S3 buckets used for audit/logging without KMS encryption.

    AWS enables AES256 (SSE-S3) by default on all S3 buckets since 2023, but KMS (SSE-KMS)
    provides additional controls: key rotation auditing, per-operation CloudTrail events,
    key revocation capability, and cross-account access control.

    This check flags audit/log/config buckets that use AES256 instead of KMS, as these
    often contain sensitive security data (CloudTrail logs, Config snapshots, VPC flow logs).
    Buckets with no encryption at all are flagged as FAIL regardless of purpose.
    """
    s3_doc = evidence.get("s3-buckets") or {}
    items = s3_doc.get("items") if isinstance(s3_doc, dict) else None

    if not isinstance(items, list) or not items:
        return PreCheckResult("EXP-024", "SKIP", "no s3-buckets evidence", [])

    # Heuristic: bucket names suggesting audit/logging/compliance data
    _audit_pattern = re.compile(
        r"(?i)(log|audit|cloudtrail|config|compliance|security|siem|flow|access[_\-]log)",
        re.IGNORECASE,
    )

    no_encryption: List[str] = []  # FAIL: no encryption at all
    aes256_audit: List[str] = []  # WARN: AES256 on audit bucket (should be KMS)

    for bucket in items:
        if not isinstance(bucket, dict):
            continue
        name = str(bucket.get("Name") or "unknown")
        algorithm = bucket.get("EncryptionAlgorithm")  # None, "AES256", or "aws:kms"

        if algorithm is None:
            # No server-side encryption configured
            no_encryption.append(name)
        elif algorithm == "AES256":
            # AES256 is fine for most buckets, but audit buckets should use KMS
            if _audit_pattern.search(name):
                aes256_audit.append(name)
        # aws:kms → compliant, no action needed

    if not no_encryption and not aes256_audit:
        return PreCheckResult(
            "EXP-024",
            "PASS",
            "all S3 buckets have encryption; audit/log buckets use KMS",
            [],
        )

    affected = no_encryption + aes256_audit
    parts = []
    if no_encryption:
        parts.append(f"{len(no_encryption)} bucket(s) with no encryption")
    if aes256_audit:
        parts.append(f"{len(aes256_audit)} audit/log bucket(s) using AES256 instead of KMS")
    status = "FAIL" if no_encryption else "FAIL"
    return PreCheckResult("EXP-024", status, "; ".join(parts), affected[:10])


@_register("exposure")
def check_exp_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-005: Lambda function URLs without authentication (AuthType=NONE)."""
    urls_doc = evidence.get("lambda-function-urls")
    urls = _items_from_doc(urls_doc)
    if urls_doc is None:
        return PreCheckResult("EXP-005", "SKIP", "no lambda-function-urls evidence", [])

    risky: List[str] = []
    for u in urls:
        if not isinstance(u, dict):
            continue
        auth = str(u.get("AuthType") or u.get("auth_type") or "").upper()
        if auth in {"NONE", ""}:
            fn = str(
                u.get("FunctionArn") or u.get("function_arn") or u.get("FunctionName", "unknown")
            )
            risky.append(fn)

    if not risky:
        return PreCheckResult(
            "EXP-005", "PASS", "no unauthenticated Lambda function URLs found", []
        )
    return PreCheckResult(
        "EXP-005",
        "FAIL",
        f"{len(risky)} Lambda function URL(s) without authentication (AuthType=NONE)",
        risky[:5],
    )


@_register("exposure")
def check_exp_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """EXP-006: API Gateway routes without authentication or rate limiting."""
    routes_doc = evidence.get("api-gateway-routes")
    routes = _items_from_doc(routes_doc)
    if not routes:
        return PreCheckResult("EXP-006", "SKIP", "no api-gateway-routes evidence", [])

    _non_data_methods = {"OPTIONS", "HEAD"}
    risky: List[str] = []
    for r in routes:
        if not isinstance(r, dict):
            continue
        method = str(r.get("Method") or "").upper()
        if method in _non_data_methods:
            continue  # skip preflight/head-only routes
        auth = str(r.get("AuthorizationType") or "").upper()
        if auth in {"NONE", ""}:
            api_id = str(r.get("ApiId") or "unknown")
            path = str(r.get("Path") or "")
            key = f"{api_id}/{method}{path}"
            if key not in risky:
                risky.append(key)

    if not risky:
        return PreCheckResult(
            "EXP-006", "PASS", "all API Gateway data routes have authentication", []
        )
    return PreCheckResult(
        "EXP-006",
        "FAIL",
        f"{len(risky)} API Gateway route(s) without authentication",
        risky[:10],
    )


def _sg_allows_world(perm: Dict[str, Any], *, port: int) -> bool:
    """Check if a security group permission allows traffic from 0.0.0.0/0 or ::/0 on given port."""
    proto = perm.get("IpProtocol")
    from_p = perm.get("FromPort")
    to_p = perm.get("ToPort")

    port_match = False
    if proto == "-1":
        port_match = True
    elif proto == "tcp" and isinstance(from_p, int) and isinstance(to_p, int):
        port_match = from_p <= port <= to_p

    if not port_match:
        return False

    for r in perm.get("IpRanges", []) or []:
        if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
            return True
    for r in perm.get("Ipv6Ranges", []) or []:
        if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
            return True
    return False


# ============================================================================
# NETWORK PRE-CHECKS
# ============================================================================


@_register("network")
def check_net_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Sensitive ports exposed to world."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-001", "SKIP", "no security-groups evidence", [])

    sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379]
    exposed = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            for p in sensitive_ports:
                if _sg_allows_world(perm, port=p):
                    exposed.append(sg.get("GroupId", "unknown"))
                    break
            if sg.get("GroupId") in exposed:
                break

    if not exposed:
        return PreCheckResult("NET-001", "PASS", "no sensitive ports exposed", [])
    return PreCheckResult("NET-001", "FAIL", f"{len(exposed)} SGs with exposed ports", exposed[:10])


@_register("network")
def check_net_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Missing descriptions on critical security group rules."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-011", "SKIP", "no security-groups evidence", [])

    crit_ports = {22, 3389, 3306, 5432, 6379, 1433, 27017, 8080}

    def _perm_matches_critical(perm):
        proto = perm.get("IpProtocol")
        if proto == "-1":
            return True
        if proto != "tcp":
            return False
        fp, tp = perm.get("FromPort"), perm.get("ToPort")
        if not isinstance(fp, int) or not isinstance(tp, int):
            return False
        return any(fp <= p <= tp for p in crit_ports)

    def _has_missing_desc(perm):
        for key in ("IpRanges", "Ipv6Ranges", "UserIdGroupPairs"):
            for r in perm.get(key, []) or []:
                if isinstance(r, dict) and not r.get("Description"):
                    return True
        return False

    affected: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        all_rules = (sg.get("IngressRules", []) or []) + (sg.get("EgressRules", []) or [])
        for perm in all_rules:
            if isinstance(perm, dict) and _perm_matches_critical(perm) and _has_missing_desc(perm):
                if sg_id not in affected:
                    affected.append(sg_id)
                break

    if not affected:
        return PreCheckResult("NET-011", "PASS", "all critical rules have descriptions", [])
    return PreCheckResult(
        "NET-011",
        "FAIL",
        f"{len(affected)} SG(s) with undescribed critical rules",
        affected[:10],
    )


@_register("network")
def check_net_018(evidence: Dict[str, Any]) -> PreCheckResult:
    """VPC should have Flow Logs enabled."""
    vpc_doc = evidence.get("vpcs")
    vpcs = _items_from_doc(vpc_doc)
    if isinstance(vpc_doc, dict) and isinstance(vpc_doc.get("by_id"), dict):
        vpcs = list(vpc_doc["by_id"].values())

    if not vpcs:
        return PreCheckResult("NET-018", "SKIP", "no vpcs evidence", [])

    missing = []
    for v in vpcs:
        if not isinstance(v, dict):
            continue
        flow_logs = v.get("FlowLogs", []) or []
        has_active = any(
            isinstance(fl, dict) and fl.get("FlowLogStatus") in {"ACTIVE", "active"}
            for fl in flow_logs
            if isinstance(flow_logs, list)
        )
        if not has_active:
            missing.append(v.get("VpcId", "unknown"))

    if not missing:
        return PreCheckResult("NET-018", "PASS", "all VPCs have active Flow Logs", [])
    return PreCheckResult("NET-018", "FAIL", f"{len(missing)} VPCs without Flow Logs", missing[:5])


@_register("network")
def check_net_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-002: Security groups allowing ALL traffic (protocol -1) from 0.0.0.0/0."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-002", "SKIP", "no security-groups evidence", [])

    exposed = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict) or perm.get("IpProtocol") != "-1":
                continue
            for r in perm.get("IpRanges", []) or []:
                if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
                    if sg_id not in exposed:
                        exposed.append(sg_id)
            for r in perm.get("Ipv6Ranges", []) or []:
                if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
                    if sg_id not in exposed:
                        exposed.append(sg_id)

    if not exposed:
        return PreCheckResult("NET-002", "PASS", "no SGs with ALL traffic from internet", [])
    return PreCheckResult(
        "NET-002", "FAIL", f"{len(exposed)} SGs allow ALL traffic from 0.0.0.0/0", exposed[:10]
    )


@_register("network")
def check_net_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-003: NACLs with ALLOW ALL rules (protocol -1, allow, 0.0.0.0/0 inbound)."""
    nacl_doc = evidence.get("network-acls")
    nacls = _items_from_doc(nacl_doc)

    if not nacls:
        return PreCheckResult("NET-003", "SKIP", "no network-acls evidence", [])

    flagged = []
    for nacl in nacls:
        if not isinstance(nacl, dict):
            continue
        nacl_id = nacl.get("NetworkAclId", "unknown")
        for entry in nacl.get("Entries", []) or []:
            if not isinstance(entry, dict):
                continue
            if (
                entry.get("Protocol") == "-1"
                and entry.get("RuleAction") == "allow"
                and entry.get("CidrBlock") == "0.0.0.0/0"
                and not entry.get("Egress", True)  # inbound only
            ):
                if nacl_id not in flagged:
                    flagged.append(nacl_id)
                break

    if not flagged:
        return PreCheckResult("NET-003", "PASS", "no NACLs with ALLOW ALL from 0.0.0.0/0", [])
    return PreCheckResult(
        "NET-003", "FAIL", f"{len(flagged)} NACLs with ALLOW ALL from internet", flagged[:5]
    )


@_register("network")
def check_net_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-009: Security groups allowing overly broad CIDRs (prefix /16 or larger) to non-web ports."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-009", "SKIP", "no security-groups evidence", [])

    # Standard web ports excluded from check (these are expected to have broad access)
    web_ports = {80, 443}
    flagged = []

    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        found = False
        for perm in sg.get("IngressRules", []) or []:
            if not isinstance(perm, dict):
                continue
            proto = perm.get("IpProtocol")
            # Skip ALL-traffic rules (covered by NET-002) and non-TCP/UDP
            if proto == "-1" or proto not in ("tcp", "udp", "6", "17"):
                continue
            fp = perm.get("FromPort")
            tp = perm.get("ToPort")
            for r in perm.get("IpRanges", []) or []:
                if not isinstance(r, dict):
                    continue
                cidr = r.get("CidrIp", "")
                if not cidr or "/" not in cidr:
                    continue
                try:
                    prefix_len = int(cidr.split("/")[1])
                except (ValueError, IndexError):
                    continue
                if prefix_len > 16:  # /17 or more specific = not broadly permissive
                    continue
                # Broad CIDR — check if it covers only web ports
                if isinstance(fp, int) and isinstance(tp, int):
                    # If entire port range is within web_ports, skip
                    if fp == tp and fp in web_ports:
                        continue
                    flagged.append(f"{sg_id}:{cidr}:{fp}-{tp}")
                    found = True
                    break
            if found:
                break

    if not flagged:
        return PreCheckResult("NET-009", "PASS", "no overly broad CIDRs to non-web ports", [])
    sg_ids = list(dict.fromkeys(f.split(":")[0] for f in flagged))
    return PreCheckResult(
        "NET-009",
        "FAIL",
        f"{len(flagged)} SG rule(s) with broad CIDR (>=/16) to non-web port",
        sg_ids[:10],
    )


@_register("network")
def check_net_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-016: Subnets using default VPC NACL instead of a dedicated custom NACL."""
    nacl_doc = evidence.get("network-acls")
    nacls = _items_from_doc(nacl_doc)

    if not nacls:
        return PreCheckResult("NET-016", "SKIP", "no network-acls evidence", [])

    default_subnets: list = []
    for nacl in nacls:
        if not isinstance(nacl, dict) or not nacl.get("IsDefault", False):
            continue
        for assoc in nacl.get("Associations", []) or []:
            if isinstance(assoc, dict) and assoc.get("SubnetId"):
                default_subnets.append(assoc["SubnetId"])

    if not default_subnets:
        return PreCheckResult("NET-016", "PASS", "all subnets use custom NACLs", [])
    return PreCheckResult(
        "NET-016",
        "FAIL",
        f"{len(default_subnets)} subnet(s) using default NACL",
        default_subnets[:10],
    )


@_register("network")
def check_net_027(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-027: Security groups missing tags."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-027", "SKIP", "no security-groups evidence", [])

    untagged = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        tags = sg.get("Tags", []) or []
        if not tags:
            untagged.append(sg.get("GroupId", "unknown"))

    if not untagged:
        return PreCheckResult("NET-027", "PASS", "all security groups have tags", [])
    return PreCheckResult(
        "NET-027",
        "FAIL",
        f"{len(untagged)} SG(s) missing tags",
        untagged[:10],
    )


@_register("network")
def check_net_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-004: DB/private subnets have a default route to an Internet Gateway."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts:
        return PreCheckResult("NET-004", "SKIP", "no route-tables evidence", [])
    if not subnets:
        return PreCheckResult("NET-004", "SKIP", "no subnets evidence", [])

    # Build map: subnet_id → name tag
    subnet_name: Dict[str, str] = {}
    for s in subnets:
        if not isinstance(s, dict):
            continue
        sid = s.get("SubnetId", "")
        tags = {
            t.get("Key", ""): t.get("Value", "")
            for t in (s.get("Tags") or [])
            if isinstance(t, dict)
        }
        subnet_name[sid] = tags.get("Name", "").lower()

    # Private / DB keywords in subnet names
    private_keywords = ("private", "db", "database", "internal", "app", "cache", "elasticache")

    sensitive: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        igw_routes = [
            r
            for r in (rt.get("Routes") or [])
            if isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
        ]
        if not igw_routes:
            continue
        for assoc in rt.get("Associations") or []:
            if not isinstance(assoc, dict):
                continue
            sid = assoc.get("SubnetId")
            if not sid:
                continue
            name = subnet_name.get(sid, "")
            if any(kw in name for kw in private_keywords):
                sensitive.append(sid)

    if not sensitive:
        return PreCheckResult("NET-004", "PASS", "no DB/private subnets with IGW routes", [])
    return PreCheckResult(
        "NET-004", "FAIL", f"{len(sensitive)} private/DB subnet(s) with IGW route", sensitive[:5]
    )


@_register("network")
def check_net_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-006: Security groups referencing Security Groups from other AWS accounts."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-006", "SKIP", "no security-groups evidence", [])

    # Get account_id from metadata or infer from first local SG reference
    meta = evidence.get("_audit_metadata") or {}
    account_id = meta.get("_account_id", "") if isinstance(meta, dict) else ""

    if not account_id:
        # Infer from first UserIdGroupPairs entry seen
        for sg in sgs:
            if not isinstance(sg, dict):
                continue
            for rule in (sg.get("IngressRules") or []) + (sg.get("EgressRules") or []):
                for pair in rule.get("UserIdGroupPairs") or []:
                    if isinstance(pair, dict) and pair.get("UserId"):
                        account_id = pair["UserId"]
                        break
                if account_id:
                    break
            if account_id:
                break

    if not account_id:
        return PreCheckResult("NET-006", "SKIP", "cannot determine account_id", [])

    cross_account: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for rule in sg.get("IngressRules") or []:
            for pair in rule.get("UserIdGroupPairs") or []:
                if isinstance(pair, dict) and pair.get("UserId") and pair["UserId"] != account_id:
                    cross_account.append(
                        f"{sg_id}→{pair.get('GroupId', 'unknown')}@{pair['UserId']}"
                    )

    if not cross_account:
        return PreCheckResult("NET-006", "PASS", "no cross-account SG references", [])
    return PreCheckResult(
        "NET-006", "FAIL", f"{len(cross_account)} cross-account SG reference(s)", cross_account[:5]
    )


@_register("network")
def check_net_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-008: Critical workloads (RDS, Lambda) deployed in public subnets."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts or not subnets:
        return PreCheckResult(
            "NET-008", "SKIP", "insufficient evidence to determine public subnets", []
        )

    # Find public subnet IDs (route tables with IGW routes)
    public_subnet_ids: set = set()
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        igw = any(
            isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
            for r in (rt.get("Routes") or [])
        )
        if not igw:
            continue
        for assoc in rt.get("Associations") or []:
            if isinstance(assoc, dict) and assoc.get("SubnetId"):
                public_subnet_ids.add(assoc["SubnetId"])

    if not public_subnet_ids:
        return PreCheckResult("NET-008", "PASS", "no public subnets detected", [])

    critical_in_public: list = []

    # Check Lambda functions with VPC config
    lambda_doc = evidence.get("lambda-functions")
    lambdas = _items_from_doc(lambda_doc)
    for fn in lambdas:
        if not isinstance(fn, dict):
            continue
        vpc_config = fn.get("VpcConfig") or {}
        fn_subnets = vpc_config.get("SubnetIds") or []
        for sid in fn_subnets:
            if sid in public_subnet_ids:
                critical_in_public.append(f"lambda:{fn.get('FunctionName', 'unknown')}")
                break

    # Check RDS instances — handle both collector formats:
    #   1. Drystone collector: flat "SubnetIds" array (e.g. ["subnet-abc", ...])
    #   2. Raw AWS format: "DBSubnetGroup.Subnets" array of objects
    rds_doc = evidence.get("rds-instances")
    rds_items = _items_from_doc(rds_doc)
    for db in rds_items:
        if not isinstance(db, dict):
            continue
        # Try flat SubnetIds first (Drystone collector format)
        flat_subnets = db.get("SubnetIds") or []
        if flat_subnets:
            for sid in flat_subnets:
                if sid in public_subnet_ids:
                    critical_in_public.append(f"rds:{db.get('DBInstanceIdentifier', 'unknown')}")
                    break
        else:
            # Fallback to raw AWS DBSubnetGroup format
            sg_subnets = db.get("DBSubnetGroup", {}).get("Subnets") or []
            for s in sg_subnets:
                sid = s.get("SubnetIdentifier") if isinstance(s, dict) else s
                if sid and sid in public_subnet_ids:
                    critical_in_public.append(f"rds:{db.get('DBInstanceIdentifier', 'unknown')}")
                    break

    if not critical_in_public:
        return PreCheckResult("NET-008", "PASS", "no critical workloads in public subnets", [])
    return PreCheckResult(
        "NET-008",
        "FAIL",
        f"{len(critical_in_public)} critical workload(s) in public subnets",
        critical_in_public[:5],
    )


@_register("network")
def check_net_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-010: Default NACLs are overly permissive (protocol -1 ALLOW from 0.0.0.0/0)."""
    nacl_doc = evidence.get("network-acls")
    nacls = _items_from_doc(nacl_doc)

    if not nacls:
        return PreCheckResult("NET-010", "SKIP", "no network-acls evidence", [])

    permissive: list = []
    for nacl in nacls:
        if not isinstance(nacl, dict) or not nacl.get("IsDefault", False):
            continue
        nacl_id = nacl.get("NetworkAclId", "unknown")
        for entry in nacl.get("Entries") or []:
            if not isinstance(entry, dict):
                continue
            if (
                entry.get("Protocol") == "-1"
                and entry.get("RuleAction") == "allow"
                and entry.get("CidrBlock") == "0.0.0.0/0"
            ):
                permissive.append(nacl_id)
                break

    if not permissive:
        return PreCheckResult(
            "NET-010", "PASS", "no default NACLs with ALLOW ALL from internet", []
        )
    return PreCheckResult(
        "NET-010",
        "FAIL",
        f"{len(permissive)} default NACL(s) with ALLOW ALL from 0.0.0.0/0",
        permissive[:5],
    )


@_register("network")
def check_net_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-012: Transit Gateway attachments not inspected by Network Firewall."""
    tgw_doc = evidence.get("transit-gateway-topology")
    if not isinstance(tgw_doc, dict):
        return PreCheckResult("NET-012", "SKIP", "no transit-gateway-topology evidence", [])

    tgws = tgw_doc.get("transit_gateways") or []
    if not tgws:
        return PreCheckResult("NET-012", "SKIP", "no Transit Gateways deployed", [])

    # TGWs exist but we cannot verify Network Firewall inspection from this evidence
    return PreCheckResult(
        "NET-012", "SKIP", f"{len(tgws)} TGW(s) present — manual inspection required", []
    )


@_register("network")
def check_net_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-014: Route tables with active blackhole routes."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)

    if not rts:
        return PreCheckResult("NET-014", "SKIP", "no route-tables evidence", [])

    blackholes: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        for route in rt.get("Routes") or []:
            if isinstance(route, dict) and route.get("State") == "blackhole":
                rt_id = rt.get("RouteTableId", "unknown")
                dst = route.get(
                    "DestinationCidrBlock", route.get("DestinationIpv6CidrBlock", "unknown")
                )
                blackholes.append(f"{rt_id}:{dst}")
                break

    if not blackholes:
        return PreCheckResult("NET-014", "PASS", "no blackhole routes", [])
    rt_ids = [b.split(":")[0] for b in blackholes]
    return PreCheckResult(
        "NET-014", "FAIL", f"{len(blackholes)} route table(s) with blackhole route", rt_ids[:5]
    )


@_register("network")
def check_net_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-017: Private subnets (no 'public' in name) with a default route to an IGW."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts:
        return PreCheckResult("NET-017", "SKIP", "no route-tables evidence", [])
    if not subnets:
        return PreCheckResult("NET-017", "SKIP", "no subnets evidence", [])

    # Build subnet name map
    subnet_name: Dict[str, str] = {}
    for s in subnets:
        if not isinstance(s, dict):
            continue
        sid = s.get("SubnetId", "")
        tags = {
            t.get("Key", ""): t.get("Value", "")
            for t in (s.get("Tags") or [])
            if isinstance(t, dict)
        }
        subnet_name[sid] = tags.get("Name", "").lower()

    flagged: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        igw_routes = [
            r
            for r in (rt.get("Routes") or [])
            if isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
        ]
        if not igw_routes:
            continue
        for assoc in rt.get("Associations") or []:
            if not isinstance(assoc, dict):
                continue
            sid = assoc.get("SubnetId")
            if not sid:
                continue
            name = subnet_name.get(sid, "")
            # Only flag if the subnet name does NOT contain 'public'
            if "public" not in name:
                flagged.append(sid)

    if not flagged:
        return PreCheckResult("NET-017", "PASS", "no private subnets with IGW routes", [])
    return PreCheckResult(
        "NET-017", "FAIL", f"{len(flagged)} private subnet(s) with IGW route", flagged[:5]
    )


@_register("network")
def check_net_019(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-019: Security groups with more than 50 rules (hard to audit)."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-019", "SKIP", "no security-groups evidence", [])

    oversized: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        total_rules = len(sg.get("IngressRules") or []) + len(sg.get("EgressRules") or [])
        if total_rules > 50:
            oversized.append(sg.get("GroupId", "unknown"))

    if not oversized:
        return PreCheckResult("NET-019", "PASS", "no SGs with more than 50 rules", [])
    return PreCheckResult(
        "NET-019", "FAIL", f"{len(oversized)} SG(s) with more than 50 rules", oversized[:10]
    )


@_register("network")
def check_net_021(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-021: Orphaned security groups (no attached resources — requires ENI data)."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-021", "SKIP", "no security-groups evidence", [])

    # ENI attachment counts are not collected — cannot determine orphan status
    return PreCheckResult(
        "NET-021", "SKIP", "ENI attachment data not collected; manual review needed", []
    )


@_register("network")
def check_net_029(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-029: VPC CIDR blocks overlap across VPCs."""
    vpc_doc = evidence.get("vpcs")
    vpcs = _items_from_doc(vpc_doc)
    if isinstance(vpc_doc, dict) and isinstance(vpc_doc.get("by_id"), dict):
        vpcs = list(vpc_doc["by_id"].values())

    if not vpcs:
        return PreCheckResult("NET-029", "SKIP", "no vpcs evidence", [])
    if len(vpcs) < 2:
        return PreCheckResult("NET-029", "PASS", "single VPC — no overlap possible", [])

    # Simple CIDR prefix overlap check (no full IP math — flag same prefixes)
    cidrs: list = []
    overlaps: list = []
    for vpc in vpcs:
        if not isinstance(vpc, dict):
            continue
        cidr = vpc.get("CidrBlock", "")
        vpc_id = vpc.get("VpcId", "unknown")
        if cidr in cidrs:
            overlaps.append(f"{vpc_id}:{cidr}")
        cidrs.append(cidr)

    if not overlaps:
        return PreCheckResult(
            "NET-029", "PASS", f"{len(vpcs)} VPCs with no exact CIDR duplicates", []
        )
    return PreCheckResult("NET-029", "FAIL", f"CIDR overlap detected: {overlaps[:3]}", overlaps[:5])


@_register("network")
def check_net_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-005: VPC peering with broad bidirectional routing without filtering."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)

    if not rts:
        return PreCheckResult("NET-005", "SKIP", "no route-tables evidence", [])

    # VPC peering connections appear as routes with GatewayId starting with 'pcx-'
    peering_routes: list = []
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        for route in rt.get("Routes") or []:
            if isinstance(route, dict) and str(route.get("GatewayId", "")).startswith("pcx-"):
                rt_id = rt.get("RouteTableId", "unknown")
                dst = route.get(
                    "DestinationCidrBlock", route.get("DestinationIpv6CidrBlock", "unknown")
                )
                peering_routes.append(f"{rt_id}:{dst}")

    if not peering_routes:
        return PreCheckResult("NET-005", "PASS", "no VPC peering routes detected", [])
    # Peering found — cannot determine filtering adequacy without SG analysis
    return PreCheckResult(
        "NET-005", "SKIP", f"{len(peering_routes)} peering route(s) — review SG filtering", []
    )


@_register("network")
def check_net_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-007: Network Firewall not deployed for internet-facing VPCs."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    vpce_doc = evidence.get("vpc-endpoints")
    vpces = _items_from_doc(vpce_doc)

    if not rts:
        return PreCheckResult("NET-007", "SKIP", "no route-tables evidence", [])

    # Check if any VPC has a route to an Internet Gateway (north-south traffic)
    has_igw = any(
        isinstance(r, dict) and str(r.get("GatewayId", "")).startswith("igw-")
        for rt in rts
        if isinstance(rt, dict)
        for r in (rt.get("Routes") or [])
    )

    if not has_igw:
        return PreCheckResult(
            "NET-007", "PASS", "no Internet Gateway routes — north-south traffic absent", []
        )

    # Check VPC endpoints for AWS Network Firewall service
    nfw_vpce = [
        e
        for e in vpces
        if isinstance(e, dict) and "network-firewall" in (e.get("ServiceName") or "").lower()
    ]
    if nfw_vpce:
        return PreCheckResult("NET-007", "PASS", "Network Firewall VPC endpoint detected", [])

    # VPC has IGW but no Network Firewall endpoint visible in collected evidence
    return PreCheckResult(
        "NET-007",
        "FAIL",
        "VPC has Internet Gateway but no AWS Network Firewall endpoint detected in vpc-endpoints",
        [],
    )


@_register("network")
def check_net_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-015: Redundant SG references — SG ref and 0.0.0.0/0 in the same rule."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)
    if isinstance(sg_doc, dict) and isinstance(sg_doc.get("by_id"), dict):
        sgs = list(sg_doc["by_id"].values())

    if not sgs:
        return PreCheckResult("NET-015", "SKIP", "no security-groups evidence", [])

    affected: list = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = sg.get("GroupId", "unknown")
        for rule in (sg.get("EgressRules") or []) + (sg.get("IngressRules") or []):
            ip_ranges = rule.get("IpRanges") or []
            pairs = rule.get("UserIdGroupPairs") or []
            if pairs and any(
                isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges
            ):
                if sg_id not in affected:
                    affected.append(sg_id)

    if not affected:
        return PreCheckResult("NET-015", "PASS", "no redundant SG references detected", [])
    return PreCheckResult(
        "NET-015",
        "FAIL",
        f"{len(affected)} SG(s) with redundant SG ref + 0.0.0.0/0 in same rule",
        affected[:5],
    )


@_register("network")
def check_net_025(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-025: Subnets missing classification tags (Tier/Layer/Classification)."""
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not subnets:
        return PreCheckResult("NET-025", "SKIP", "no subnets evidence", [])

    classification_keys = {"tier", "layer", "classification", "subnet-type", "subnettype"}
    missing: list = []
    for s in subnets:
        if not isinstance(s, dict):
            continue
        tag_keys = {t.get("Key", "").lower() for t in (s.get("Tags") or []) if isinstance(t, dict)}
        if not (tag_keys & classification_keys):
            missing.append(s.get("SubnetId", "unknown"))

    if not missing:
        return PreCheckResult("NET-025", "PASS", "all subnets have classification tags", [])
    return PreCheckResult(
        "NET-025",
        "FAIL",
        f"{len(missing)} subnet(s) missing classification tags (Tier/Layer)",
        missing[:8],
    )


@_register("network")
def check_net_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-022: Public subnets (0.0.0.0/0 to IGW) — verify no sensitive workloads deployed."""
    rt_doc = evidence.get("route-tables")
    rts = _items_from_doc(rt_doc)
    subnet_doc = evidence.get("subnets")
    subnets = _items_from_doc(subnet_doc)

    if not rts:
        return PreCheckResult("NET-022", "SKIP", "no route-tables evidence", [])
    if not subnets:
        return PreCheckResult("NET-022", "SKIP", "no subnets evidence", [])

    # Find public subnet IDs (route tables with IGW default route)
    public_subnet_ids: set = set()
    for rt in rts:
        if not isinstance(rt, dict):
            continue
        igw = any(
            isinstance(r, dict)
            and str(r.get("GatewayId", "")).startswith("igw-")
            and r.get("DestinationCidrBlock") == "0.0.0.0/0"
            for r in (rt.get("Routes") or [])
        )
        if not igw:
            continue
        for assoc in rt.get("Associations") or []:
            if isinstance(assoc, dict) and assoc.get("SubnetId"):
                public_subnet_ids.add(assoc["SubnetId"])

    if not public_subnet_ids:
        return PreCheckResult("NET-022", "PASS", "no public subnets detected", [])
    return PreCheckResult(
        "NET-022",
        "FAIL",
        f"{len(public_subnet_ids)} public subnet(s) with IGW route require workload verification",
        sorted(public_subnet_ids)[:8],
    )


@_register("network")
def check_net_unrestricted_egress(evidence: Dict[str, Any]) -> PreCheckResult:
    """NET-EGR-001: Security groups with unrestricted egress (0.0.0.0/0 protocol -1)."""
    sg_doc = evidence.get("security-groups")
    sgs = _items_from_doc(sg_doc)

    if not sgs:
        return PreCheckResult("NET-EGR-001", "SKIP", "no security-groups evidence", [])

    # Find SGs with unrestricted egress: protocol=-1, cidr=0.0.0.0/0 or ::/0
    unrestricted = []
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        egress_rules = sg.get("IpPermissionsEgress", [])
        for rule in egress_rules:
            if not isinstance(rule, dict):
                continue
            # protocol -1 = all traffic
            if str(rule.get("IpProtocol", "")) != "-1":
                continue
            # Check for open CIDR
            ip_ranges = rule.get("IpRanges", [])
            ipv6_ranges = rule.get("Ipv6Ranges", [])
            has_open_ipv4 = any(
                isinstance(r, dict) and r.get("CidrIp") in {"0.0.0.0/0", "0.0.0.0"}
                for r in ip_ranges
            )
            has_open_ipv6 = any(
                isinstance(r, dict) and r.get("CidrIpv6") in {"::/0"} for r in ipv6_ranges
            )
            if has_open_ipv4 or has_open_ipv6:
                unrestricted.append(str(sg.get("GroupId") or sg.get("GroupName", "unknown")))
                break  # One open rule is enough to flag this SG

    if not unrestricted:
        return PreCheckResult(
            "NET-EGR-001", "PASS", "no security groups with unrestricted egress (all traffic)", []
        )
    return PreCheckResult(
        "NET-EGR-001",
        "FAIL",
        f"{len(unrestricted)} security group(s) with unrestricted egress (protocol=-1, 0.0.0.0/0)",
        unrestricted[:10],
    )


# ============================================================================
# WAF PRE-CHECKS
# ============================================================================


def _waf_collection_has_failures(evidence: Dict[str, Any]) -> bool:
    """Check if WAF collection status indicates failures."""
    coll_status = evidence.get("waf-collection-status")
    if not isinstance(coll_status, dict):
        return False
    try:
        if (coll_status.get("cloudfront") or {}).get("ok") is False:
            return True
        if ((coll_status.get("wafv2") or {}).get("CLOUDFRONT") or {}).get("ok") is False:
            return True
        for _, r in (
            ((coll_status.get("wafv2") or {}).get("REGIONAL") or {}).get("regions", {}).items()
        ):
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        for _, r in (coll_status.get("alb") or {}).get("regions", {}).items():
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        for _, r in (coll_status.get("api_entrypoints") or {}).items():
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        if (coll_status.get("waf_classic") or {}).get("ok") is False:
            return True
    except Exception:
        return False
    return False


@_register("waf")
def check_waf_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Internet-facing ALBs should have WAF protection."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-001", "SKIP", "WAF collection failures (WAF-013)", [])
    albs = evidence.get("alb-waf-associations")
    if not isinstance(albs, list) or len(albs) == 0:
        return PreCheckResult("WAF-001", "PASS", "no internet-facing ALBs detected", [])
    # Full deterministic check: WAFv2WebACL must be a dict without 'error' key
    unprotected = [
        a.get("LoadBalancerArn") or a.get("LoadBalancerName", "unknown")
        for a in albs
        if not isinstance(a.get("WAFv2WebACL"), dict)
        or "error" in (a.get("WAFv2WebACL") or {})
        or not a.get("WAFv2WebACL")
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-001",
            "FAIL",
            f"{len(unprotected)} internet-facing ALB(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-001", "PASS", "all internet-facing ALBs are WAF-protected", [])


@_register("waf")
def check_waf_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudFront distributions should have WAF protection."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-002", "SKIP", "WAF collection failures (WAF-013)", [])
    dists = evidence.get("cloudfront-distributions")
    if not isinstance(dists, list) or len(dists) == 0:
        return PreCheckResult("WAF-002", "PASS", "no CloudFront distributions detected", [])
    # Full deterministic check: WebACLId must be non-empty
    unprotected = [
        d.get("DomainName") or d.get("Id", "unknown") for d in dists if not d.get("WebACLId")
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-002",
            "FAIL",
            f"{len(unprotected)} CloudFront distribution(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-002", "PASS", "all CloudFront distributions are WAF-protected", [])


@_register("waf")
def check_waf_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAFv2 Web ACL logging should be enabled."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-003", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-003", "PASS", "no Web ACLs (N/A)", [])
    not_logging = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not (acl.get("Logging") or {}).get("enabled", False)
    ]
    if not_logging:
        return PreCheckResult(
            "WAF-003",
            "FAIL",
            f"{len(not_logging)} Web ACL(s) without logging enabled",
            not_logging[:5],
        )
    return PreCheckResult("WAF-003", "PASS", "all Web ACLs have logging enabled", [])


@_register("waf")
def check_waf_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF logging RedactedFields should cover sensitive headers."""
    _sensitive_headers = {"cookie", "x-api-key", "authorization", "x-auth-token"}
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-004", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-004", "PASS", "no Web ACLs (N/A)", [])
    incomplete: list = []
    all_missing: set = set()
    for acl in web_acls:
        logging_cfg = acl.get("Logging") or {}
        if not logging_cfg.get("enabled", False):
            continue  # WAF-003 covers disabled logging
        redacted = {
            (r.get("SingleHeader") or {}).get("Name", "").lower()
            for r in (logging_cfg.get("RedactedFields") or [])
        }
        missing = _sensitive_headers - redacted
        if missing:
            all_missing |= missing
            incomplete.append(acl.get("ARN") or acl.get("Name", "unknown"))
    if incomplete:
        missing_str = "/".join(sorted(all_missing))
        return PreCheckResult(
            "WAF-004",
            "FAIL",
            f"{len(incomplete)} Web ACL(s) with incomplete log redaction (missing: {missing_str})",
            incomplete[:5],
        )
    return PreCheckResult("WAF-004", "PASS", "all Web ACLs have complete log redaction", [])


@_register("waf")
def check_waf_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACL VisibilityConfig should have SampledRequestsEnabled=true."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-005", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-005", "PASS", "no Web ACLs (N/A)", [])
    failing = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not (acl.get("WebACL") or {})
        .get("VisibilityConfig", {})
        .get("SampledRequestsEnabled", True)
    ]
    if failing:
        return PreCheckResult(
            "WAF-005",
            "FAIL",
            f"{len(failing)} Web ACL(s) with SampledRequestsEnabled=false",
            failing[:5],
        )
    return PreCheckResult("WAF-005", "PASS", "all Web ACLs have sampled requests enabled", [])


_WAF_BASELINE_MANAGED_RULES = {
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
}


@_register("waf")
def check_waf_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs should include at least one baseline AWS Managed Rule group."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-006", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-006", "PASS", "no Web ACLs (N/A)", [])
    missing_baseline = []
    for acl in web_acls:
        rules = (acl.get("WebACL") or {}).get("Rules", [])
        used_managed = {
            (r.get("Statement") or {}).get("ManagedRuleGroupStatement", {}).get("Name", "")
            for r in rules
        }
        if not used_managed & _WAF_BASELINE_MANAGED_RULES:
            missing_baseline.append(acl.get("ARN") or acl.get("Name", "unknown"))
    if missing_baseline:
        return PreCheckResult(
            "WAF-006",
            "FAIL",
            f"{len(missing_baseline)} Web ACL(s) lack baseline AWS Managed Rules",
            missing_baseline[:5],
        )
    return PreCheckResult("WAF-006", "PASS", "all Web ACLs have baseline managed rules", [])


@_register("waf")
def check_waf_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Managed rule groups should not be overridden to Count-only mode in production."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-007", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-007", "PASS", "no Web ACLs (N/A)", [])
    count_only: list = []
    for acl in web_acls:
        rules = (acl.get("WebACL") or {}).get("Rules", [])
        for rule in rules:
            override = rule.get("OverrideAction") or {}
            if "Count" in override:
                count_only.append(f"{acl.get('Name', 'unknown')}/{rule.get('Name', 'unknown')}")
    if count_only:
        return PreCheckResult(
            "WAF-007",
            "FAIL",
            f"{len(count_only)} managed rule group(s) in Count-only mode",
            count_only[:5],
        )
    return PreCheckResult("WAF-007", "PASS", "no managed rule groups in Count-only mode", [])


@_register("waf")
def check_waf_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs should include at least one rate-based rule to limit abuse."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-008", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-008", "PASS", "no Web ACLs (N/A)", [])
    no_rate_rules = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not any(
            "RateBasedStatement" in (r.get("Statement") or {})
            for r in (acl.get("WebACL") or {}).get("Rules", [])
        )
    ]
    if no_rate_rules:
        return PreCheckResult(
            "WAF-008",
            "FAIL",
            f"{len(no_rate_rules)} Web ACL(s) without rate-based rules",
            no_rate_rules[:5],
        )
    return PreCheckResult("WAF-008", "PASS", "all Web ACLs have rate-based rules", [])


@_register("waf")
def check_waf_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF IP sets should not contain overly broad CIDRs (0.0.0.0/0 or ::/0)."""
    _broad_cidrs = {"0.0.0.0/0", "::/0"}
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-009", "SKIP", "WAF collection failures", [])
    ip_sets = evidence.get("wafv2-ip-sets")
    if not isinstance(ip_sets, list) or len(ip_sets) == 0:
        return PreCheckResult("WAF-009", "PASS", "no WAFv2 IP sets", [])
    broad = [
        ip_set.get("Name", "unknown")
        for ip_set in ip_sets
        if _broad_cidrs & set(ip_set.get("Addresses", []))
    ]
    if broad:
        return PreCheckResult(
            "WAF-009",
            "FAIL",
            f"{len(broad)} IP set(s) with broad CIDRs (0.0.0.0/0 or ::/0)",
            broad[:5],
        )
    return PreCheckResult("WAF-009", "PASS", "no IP sets with broad CIDRs", [])


@_register("waf")
def check_waf_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF Classic Web ACLs should be migrated to WAFv2."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-010", "SKIP", "WAF collection failures", [])
    classic = evidence.get("waf-classic") or {}
    global_acls = (classic.get("global") or {}).get("web_acls", [])
    regional_acls: list = []
    for region_data in (classic.get("regional") or {}).values():
        regional_acls.extend((region_data or {}).get("web_acls", []))
    total = len(global_acls) + len(regional_acls)
    if total > 0:
        names = [a.get("Name", "unknown") for a in global_acls + regional_acls]
        return PreCheckResult(
            "WAF-010",
            "FAIL",
            f"{total} WAF Classic Web ACL(s) detected; migrate to WAFv2",
            names[:5],
        )
    return PreCheckResult("WAF-010", "PASS", "no WAF Classic Web ACLs detected", [])


@_register("waf")
def check_waf_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs with no associated resources should be reviewed for cleanup."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-011", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-011", "PASS", "no Web ACLs (N/A)", [])
    unassociated = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not acl.get("AssociatedResourceArns")
    ]
    if unassociated:
        return PreCheckResult(
            "WAF-011",
            "FAIL",
            f"{len(unassociated)} Web ACL(s) with no associated resources",
            unassociated[:5],
        )
    return PreCheckResult("WAF-011", "PASS", "all Web ACLs have associated resources", [])


@_register("waf")
def check_waf_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF collection status indicates failures or unverifiable associations."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-013", "FAIL", "WAF collection has failures", [])
    # Detect HTTP API entries where GetWebACLForResource returned WAFInvalidParameterException.
    # This is an AWS SDK limitation: HTTP API V2 ARNs are not supported by that API call.
    # These endpoints have UNKNOWN WAF protection status and should be noted.
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if isinstance(api_eps, list):
        http_api_errors = [
            f"{e.get('Name', 'unknown')}/{e.get('Stage', '')}"
            for e in api_eps
            if e.get("ApiType") == "HTTP"
            and isinstance(e.get("WAFv2WebACL"), dict)
            and "error" in e["WAFv2WebACL"]
        ]
        if http_api_errors:
            return PreCheckResult(
                "WAF-013",
                "FAIL",
                f"WAF status unverifiable for {len(http_api_errors)} HTTP API stage(s) "
                f"(AWS GetWebACLForResource does not support HTTP API V2 ARN format): "
                f"{', '.join(http_api_errors[:3])}",
                http_api_errors[:5],
            )
    return PreCheckResult("WAF-013", "PASS", "no WAF collection failures", [])


@_register("waf")
def check_waf_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """API Gateway REST stages should be protected by AWS WAF."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-014", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-014", "SKIP", "no api-entrypoints evidence", [])
    # Only evaluate REST APIs (HTTP APIs return WAFInvalidParameterException — AWS limitation)
    rest_entries = [
        e for e in api_eps if e.get("Service") == "apigateway" and e.get("ApiType") == "REST"
    ]
    if not rest_entries:
        return PreCheckResult("WAF-014", "PASS", "no API Gateway REST stages detected", [])
    unprotected = [
        f"{e.get('Name', 'unknown')}/{e.get('Stage', '')}"
        for e in rest_entries
        if not isinstance(e.get("WAFv2WebACL"), dict) or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-014",
            "FAIL",
            f"{len(unprotected)} API Gateway REST stage(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-014", "PASS", "all API Gateway REST stages are WAF-protected", [])


@_register("waf")
def check_waf_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """AppSync GraphQL APIs should be protected by AWS WAF."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-015", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-015", "SKIP", "no api-entrypoints evidence", [])
    appsync_entries = [e for e in api_eps if e.get("Service") == "appsync"]
    if not appsync_entries:
        return PreCheckResult("WAF-015", "PASS", "no AppSync APIs detected (N/A)", [])
    unprotected = [
        e.get("Name", e.get("ApiId", "unknown"))
        for e in appsync_entries
        if not isinstance(e.get("WAFv2WebACL"), dict) or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-015",
            "FAIL",
            f"{len(unprotected)} AppSync API(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-015", "PASS", "all AppSync APIs are WAF-protected", [])


@_register("waf")
def check_waf_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Cognito User Pools should be protected by AWS WAF when publicly exposed."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-016", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-016", "SKIP", "no api-entrypoints evidence", [])
    cognito_entries = [e for e in api_eps if e.get("Service") == "cognito"]
    if not cognito_entries:
        return PreCheckResult("WAF-016", "PASS", "no Cognito User Pools detected (N/A)", [])
    unprotected = [
        e.get("Name", e.get("ApiId", "unknown"))
        for e in cognito_entries
        if not isinstance(e.get("WAFv2WebACL"), dict) or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-016",
            "FAIL",
            f"{len(unprotected)} Cognito User Pool(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-016", "PASS", "all Cognito User Pools are WAF-protected", [])


# ============================================================================
# VULNS PRE-CHECKS
# ============================================================================


@_register("vulns")
def check_vuln_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Inspector v2 should be enabled (inferred from inspector-findings presence)."""
    findings = evidence.get("inspector-findings")
    if isinstance(findings, list):
        # Collector successfully queried Inspector v2 → service is enabled
        return PreCheckResult(
            "VULN-001",
            "PASS",
            f"Inspector v2 is enabled ({len(findings)} finding(s) returned)",
            [],
        )
    return PreCheckResult(
        "VULN-001", "SKIP", "no inspector-findings evidence to determine status", []
    )


@_register("vulns")
def check_vuln_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """CRITICAL CVEs not remediated — scan inspector-findings for CRITICAL+ACTIVE entries."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-002", "SKIP", "no inspector-findings evidence", [])

    critical_active = [
        f.get("resources", [{}])[0].get("id", "unknown")
        for f in findings
        if isinstance(f, dict)
        and str(f.get("severity", "")).upper() == "CRITICAL"
        and str(f.get("status", "")).upper() == "ACTIVE"
    ]

    if not critical_active:
        return PreCheckResult("VULN-002", "PASS", "no CRITICAL active Inspector findings", [])
    return PreCheckResult(
        "VULN-002",
        "FAIL",
        f"{len(critical_active)} CRITICAL active Inspector finding(s)",
        critical_active[:10],
    )


@_register("vulns")
def check_vuln_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """Multiple CVEs on same resource — count ACTIVE Inspector findings per resource."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list) or not findings:
        return PreCheckResult("VULN-009", "SKIP", "no inspector-findings evidence", [])

    from collections import Counter

    resource_counts: Counter = Counter()
    for f in findings:
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        for res in f.get("resources", []):
            rid = res.get("id") if isinstance(res, dict) else None
            if rid:
                resource_counts[rid] += 1

    multi_vuln = {rid: cnt for rid, cnt in resource_counts.items() if cnt >= 3}
    if not multi_vuln:
        return PreCheckResult("VULN-009", "PASS", "no resource has 3+ active CVEs", [])

    top = sorted(multi_vuln.items(), key=lambda x: x[1], reverse=True)
    resources = [f"{rid} ({cnt} CVEs)" for rid, cnt in top[:5]]
    return PreCheckResult(
        "VULN-009",
        "FAIL",
        f"{len(multi_vuln)} resource(s) with 3+ active CVEs",
        resources,
    )


@_register("vulns")
def check_vuln_022(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect EC2 instances with IMDSv1/optional tokens enabled."""
    imds_doc = evidence.get("imds-configuration") or {}
    items = imds_doc.get("items") if isinstance(imds_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-022", "SKIP", "no imds-configuration evidence", [])

    vulnerable = []
    for it in items:
        if not isinstance(it, dict):
            continue
        if it.get("VulnerableToSSRF"):
            iid = it.get("InstanceId", "unknown")
            vulnerable.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not vulnerable:
        return PreCheckResult("VULN-022", "PASS", "all instances require IMDSv2", [])
    return PreCheckResult(
        "VULN-022",
        "FAIL",
        f"{len(vulnerable)} instances with IMDSv1/optional metadata tokens",
        vulnerable[:10],
    )


@_register("vulns")
def check_vuln_023(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect EC2 user-data scripts containing likely secrets."""
    user_data_doc = evidence.get("ec2-user-data") or {}
    items = user_data_doc.get("items") if isinstance(user_data_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-023", "SKIP", "no ec2-user-data evidence", [])

    exposed = []
    for it in items:
        if not isinstance(it, dict):
            continue
        flags = it.get("ContainsSecrets")
        if not isinstance(flags, dict):
            continue
        if any(bool(v) for v in flags.values()):
            iid = it.get("InstanceId", "unknown")
            exposed.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not exposed:
        return PreCheckResult("VULN-023", "PASS", "no user-data secret patterns detected", [])
    return PreCheckResult(
        "VULN-023", "FAIL", f"{len(exposed)} instances with secret-like user-data", exposed[:10]
    )


@_register("vulns")
def check_vuln_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect Lambda functions with potentially sensitive env var keys."""
    env_doc = evidence.get("lambda-environment-variables") or {}
    items = env_doc.get("items") if isinstance(env_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-024", "SKIP", "no lambda-environment-variables evidence", [])

    exposed = []
    for it in items:
        if not isinstance(it, dict):
            continue
        keys = it.get("PotentialSecretKeys")
        if isinstance(keys, list) and len(keys) > 0:
            arn = it.get("FunctionArn") or f"lambda/{it.get('FunctionName', 'unknown')}"
            exposed.append(str(arn))

    if not exposed:
        return PreCheckResult("VULN-024", "PASS", "no sensitive Lambda env keys detected", [])
    return PreCheckResult(
        "VULN-024", "FAIL", f"{len(exposed)} Lambda functions with sensitive env keys", exposed[:10]
    )


@_register("vulns")
def check_vuln_025(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect over-privileged instance profiles via attached policy names."""
    prof_doc = evidence.get("instance-profiles-permissions") or {}
    items = prof_doc.get("items") if isinstance(prof_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-025", "SKIP", "no instance-profiles-permissions evidence", [])

    risky_tokens = ["administratoraccess", "admin", "poweruser", "fullaccess"]
    affected = []

    for item in items:
        if not isinstance(item, dict):
            continue
        roles = item.get("Roles")
        if not isinstance(roles, list):
            continue
        for role in roles:
            if not isinstance(role, dict):
                continue
            attached = role.get("AttachedPolicies")
            if not isinstance(attached, list):
                continue
            for pol in attached:
                if not isinstance(pol, dict):
                    continue
                name = str(pol.get("PolicyName") or "").lower()
                if any(tok in name for tok in risky_tokens):
                    role_arn = role.get("RoleArn") or role.get("RoleName") or "unknown-role"
                    affected.append(str(role_arn))
                    break

    if not affected:
        return PreCheckResult(
            "VULN-025", "PASS", "no over-privileged instance profiles detected", []
        )
    return PreCheckResult(
        "VULN-025",
        "FAIL",
        f"{len(affected)} instance-profile roles with over-privileged policies",
        affected[:10],
    )


@_register("vulns")
def check_vuln_028(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect public EBS snapshots (createVolumePermission Group=all)."""
    snap_doc = evidence.get("ebs-snapshot-sharing") or {}
    items = snap_doc.get("items") if isinstance(snap_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-028", "SKIP", "no ebs-snapshot-sharing evidence", [])

    public_ids = []
    for it in items:
        if not isinstance(it, dict):
            continue
        if bool(it.get("IsPublic")):
            sid = str(it.get("SnapshotId") or "unknown")
            public_ids.append(sid)

    if not public_ids:
        return PreCheckResult("VULN-028", "PASS", "no public EBS snapshots detected", [])
    return PreCheckResult(
        "VULN-028", "FAIL", f"{len(public_ids)} public EBS snapshots", public_ids[:10]
    )


@_register("vulns")
def check_vuln_029(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-029: ECS task definitions with hardcoded secrets in environment variables."""
    ecs_doc = evidence.get("ecs-task-env-secrets") or {}
    items = ecs_doc.get("items") if isinstance(ecs_doc, dict) else None

    # Access denied or API not available
    error = ecs_doc.get("error") if isinstance(ecs_doc, dict) else None
    if error and not items:
        return PreCheckResult(
            "VULN-029", "SKIP", f"ECS task definitions not accessible: {str(error)[:100]}", []
        )

    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-029", "SKIP", "no ecs-task-env-secrets evidence", [])

    affected: List[str] = []
    for td in items:
        if not isinstance(td, dict):
            continue
        if td.get("HasSensitiveEnvVars"):
            arn = str(td.get("TaskDefinitionArn") or td.get("Family") or "unknown")
            affected.append(arn)

    if not affected:
        return PreCheckResult(
            "VULN-029",
            "PASS",
            "no ECS task definitions with sensitive environment variable keys detected",
            [],
        )
    return PreCheckResult(
        "VULN-029",
        "FAIL",
        f"{len(affected)} ECS task definition(s) with sensitive env var keys (potential hardcoded secrets)",
        affected[:10],
    )


@_register("vulns")
def check_vuln_026(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-026: S3 buckets with Terraform state files containing secrets in plaintext.

    Terraform state files (.tfstate) store the complete infrastructure state including
    resource attribute values. Secrets Manager secret_string, RDS passwords, and TLS private
    keys often appear in plaintext in tfstate files stored in S3.
    """
    tf_doc = evidence.get("terraform-state-scan") or {}
    items = tf_doc.get("items") if isinstance(tf_doc, dict) else None

    error = tf_doc.get("error") if isinstance(tf_doc, dict) else None
    if error and not items:
        return PreCheckResult(
            "VULN-026", "SKIP", f"Terraform state scan not accessible: {str(error)[:100]}", []
        )

    if not isinstance(items, list):
        return PreCheckResult("VULN-026", "SKIP", "no terraform-state-scan evidence", [])

    # Buckets with candidate names but no .tfstate objects found
    candidates_no_state: List[str] = []
    # Buckets with .tfstate files but read was denied
    candidates_access_denied: List[str] = []
    # Buckets with confirmed secrets in state files
    confirmed_secrets: List[str] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        bucket = str(item.get("BucketName") or "unknown")

        if item.get("HasSuspiciousContent"):
            patterns = item.get("MatchedPatterns") or []
            label = f"{bucket} (patterns: {', '.join(str(p)[:40] for p in patterns[:2])})"
            confirmed_secrets.append(label)
        elif item.get("AccessError") and "AccessDenied" in str(item.get("AccessError", "")):
            candidates_access_denied.append(bucket)
        elif not item.get("TfstateObjects"):
            candidates_no_state.append(bucket)

    if confirmed_secrets:
        return PreCheckResult(
            "VULN-026",
            "FAIL",
            f"{len(confirmed_secrets)} S3 bucket(s) with Terraform state files containing plaintext secrets",
            confirmed_secrets[:10],
        )

    if candidates_access_denied:
        # We found candidate buckets but couldn't read them — flag as WARN
        return PreCheckResult(
            "VULN-026",
            "FAIL",
            f"{len(candidates_access_denied)} Terraform state bucket(s) found but content unreadable (AccessDenied) — manual review required",
            candidates_access_denied[:10],
        )

    if candidates_no_state and not candidates_access_denied and not confirmed_secrets:
        return PreCheckResult(
            "VULN-026",
            "PASS",
            f"{len(candidates_no_state)} Terraform-named bucket(s) found but no .tfstate files detected",
            [],
        )

    return PreCheckResult(
        "VULN-026",
        "PASS",
        "no Terraform state files with secrets detected in candidate buckets",
        [],
    )


@_register("vulns")
def check_vuln_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-004: CVEs with known active exploit (exploitAvailable=YES + status=ACTIVE)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-004", "SKIP", "no inspector-findings evidence", [])

    exploitable = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if (
            str(f.get("exploitAvailable", "")).upper() == "YES"
            and str(f.get("status", "")).upper() == "ACTIVE"
        ):
            title = f.get("title", "unknown")
            resources = f.get("resources", [])
            rid = resources[0].get("id", "unknown") if resources else "unknown"
            exploitable.append(f"{title} @ {rid}")

    if not exploitable:
        return PreCheckResult("VULN-004", "PASS", "no actively exploitable CVEs detected", [])
    return PreCheckResult(
        "VULN-004",
        "FAIL",
        f"{len(exploitable)} CVE(s) with known active exploit and ACTIVE status",
        exploitable[:10],
    )


@_register("vulns")
def check_vuln_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-006: EC2 scanning by Inspector (inferred from EC2 findings presence)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-006", "SKIP", "no inspector-findings evidence", [])

    ec2_resources = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for res in f.get("resources", []):
            if isinstance(res, dict) and str(res.get("type", "")).upper() == "AWS_EC2_INSTANCE":
                rid = res.get("id", "unknown")
                if rid not in ec2_resources:
                    ec2_resources.append(rid)

    if ec2_resources:
        return PreCheckResult(
            "VULN-006",
            "PASS",
            f"Inspector EC2 scanning active ({len(ec2_resources)} instance(s) scanned)",
            ec2_resources[:5],
        )
    return PreCheckResult(
        "VULN-006",
        "SKIP",
        "no EC2 findings in inspector-findings — cannot confirm EC2 scanning status",
        [],
    )


@_register("vulns")
def check_vuln_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-007: ECR container scanning by Inspector (inferred from ECR findings presence)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-007", "SKIP", "no inspector-findings evidence", [])

    ecr_resources = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        for res in f.get("resources", []):
            if (
                isinstance(res, dict)
                and str(res.get("type", "")).upper() == "AWS_ECR_CONTAINER_IMAGE"
            ):
                rid = res.get("id", "unknown")
                if rid not in ecr_resources:
                    ecr_resources.append(rid)

    if ecr_resources:
        return PreCheckResult(
            "VULN-007",
            "PASS",
            f"Inspector ECR scanning active ({len(ecr_resources)} image(s) scanned)",
            ecr_resources[:5],
        )
    return PreCheckResult(
        "VULN-007",
        "SKIP",
        "no ECR findings in inspector-findings — cannot confirm ECR scanning status",
        [],
    )


@_register("vulns")
def check_vuln_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-008: HIGH severity vulnerabilities without remediation plan (accurate count)."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-008", "SKIP", "no inspector-findings evidence", [])

    high_active = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if (
            str(f.get("severity", "")).upper() == "HIGH"
            and str(f.get("status", "")).upper() == "ACTIVE"
        ):
            resources = f.get("resources", [])
            rid = resources[0].get("id", "unknown") if resources else "unknown"
            high_active.append(rid)

    if not high_active:
        return PreCheckResult("VULN-008", "PASS", "no ACTIVE HIGH Inspector findings", [])

    unique_resources = list(dict.fromkeys(high_active))
    return PreCheckResult(
        "VULN-008",
        "FAIL",
        f"{len(high_active)} ACTIVE HIGH Inspector finding(s) across {len(unique_resources)} resource(s) — no remediation plan evident",
        unique_resources[:10],
    )


@_register("vulns")
def check_vuln_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-003: Active vulnerabilities on publicly accessible EC2 resources."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-003", "SKIP", "no inspector-findings evidence", [])

    # Look for ACTIVE findings targeting EC2 instances
    active_ec2: List[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        for res in f.get("resources") or []:
            if isinstance(res, dict) and res.get("type") == "AWS_EC2_INSTANCE":
                rid = str(res.get("id") or "unknown")
                if rid not in active_ec2:
                    active_ec2.append(rid)

    if not active_ec2:
        return PreCheckResult(
            "VULN-003", "PASS", "no ACTIVE Inspector findings on EC2 instances", []
        )
    return PreCheckResult(
        "VULN-003",
        "FAIL",
        f"{len(active_ec2)} EC2 instance(s) with ACTIVE Inspector findings (potentially publicly accessible)",
        active_ec2[:5],
    )


@_register("vulns")
def check_vuln_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-005: Active vulnerabilities on high-criticality resources (databases, VPN, AD)."""
    import re

    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-005", "SKIP", "no inspector-findings evidence", [])

    # High-criticality resource keywords to detect database/VPN/AD assets.
    # NOTE: "ad" was removed — it matches "cards" and other service names as substring.
    #       Active Directory resources use AWS Directory Service → detected by "directory".
    # IMPORTANT: Use word-boundary matching to avoid false positives like "cards" matching "rds"
    # or "sandbox" matching "db". ECR image ARNs (ecr:.../sha256:...) are explicitly excluded.
    _crit_keywords = {"rds", "database", "db", "vpn", "directory", "ldap", "aurora"}
    _crit_pattern = re.compile(
        r"(?<![a-z])(" + "|".join(re.escape(k) for k in sorted(_crit_keywords)) + r")(?![a-z])"
    )

    def _is_ecr_image(resource_id: str) -> bool:
        """ECR image ARNs (ecr:.../repository/.../sha256:...) are app containers, not databases."""
        return "ecr:" in resource_id.lower() and "sha256:" in resource_id.lower()

    affected: List[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        for res in f.get("resources") or []:
            if not isinstance(res, dict):
                continue
            resource_id = str(res.get("id") or "unknown")
            # Skip ECR image digests — they are application containers, not DB/VPN infrastructure
            if _is_ecr_image(resource_id):
                continue
            rid = resource_id.lower()
            tags = res.get("tags") or {}
            service_tag = str(tags.get("Service") or tags.get("service") or "").lower()
            # Use word-boundary regex to avoid substring false positives (e.g. "cards" ≠ "rds")
            if _crit_pattern.search(rid) or _crit_pattern.search(service_tag):
                if resource_id not in affected:
                    affected.append(resource_id)

    if not affected:
        return PreCheckResult(
            "VULN-005", "PASS", "no ACTIVE Inspector findings on high-criticality resources", []
        )
    return PreCheckResult(
        "VULN-005",
        "FAIL",
        f"{len(affected)} high-criticality resource(s) with ACTIVE Inspector findings",
        affected[:5],
    )


@_register("vulns")
def check_vuln_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-010: Active HIGH/CRITICAL vulnerabilities on critical EC2 service components."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-010", "SKIP", "no inspector-findings evidence", [])

    affected: List[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        sev = str(f.get("severity", "")).upper()
        if sev not in {"HIGH", "CRITICAL"}:
            continue
        for res in f.get("resources") or []:
            if isinstance(res, dict) and res.get("type") == "AWS_EC2_INSTANCE":
                rid = str(res.get("id") or "unknown")
                if rid not in affected:
                    affected.append(rid)

    if not affected:
        return PreCheckResult(
            "VULN-010",
            "PASS",
            "no ACTIVE HIGH/CRITICAL Inspector findings on EC2 instances",
            [],
        )
    return PreCheckResult(
        "VULN-010",
        "FAIL",
        f"{len(affected)} EC2 instance(s) with ACTIVE HIGH/CRITICAL Inspector findings",
        affected[:5],
    )


@_register("vulns")
def check_vuln_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-011: ECR scanning not active — no container image findings from Inspector."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-011", "SKIP", "no inspector-findings evidence", [])

    ecr_findings = [
        f
        for f in findings
        if isinstance(f, dict)
        and any(
            isinstance(r, dict) and r.get("type") == "AWS_ECR_CONTAINER_IMAGE"
            for r in (f.get("resources") or [])
        )
    ]

    if ecr_findings:
        return PreCheckResult(
            "VULN-011",
            "PASS",
            f"ECR scanning is active ({len(ecr_findings)} container image finding(s) present)",
            [],
        )
    return PreCheckResult(
        "VULN-011",
        "FAIL",
        "no ECR container image findings from Inspector — scanning may be disabled or no images present",
        [],
    )


@_register("vulns")
def check_vuln_guardduty_disabled(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-GD-001: GuardDuty not enabled in account — no threat detection active."""
    gd = evidence.get("guardduty-status")
    if not isinstance(gd, dict):
        return PreCheckResult("VULN-GD-001", "SKIP", "no guardduty-status evidence", [])

    # If we got an access_error, GuardDuty is likely not set up at all
    if gd.get("access_error"):
        return PreCheckResult(
            "VULN-GD-001",
            "FAIL",
            "GuardDuty API not accessible — likely not enabled in this region",
            [],
        )

    detector_count = int(gd.get("detector_count", 0) or 0)
    if detector_count == 0:
        return PreCheckResult(
            "VULN-GD-001",
            "FAIL",
            "GuardDuty has no detectors configured (not enabled)",
            [],
        )

    enabled_count = int(gd.get("enabled_count", 0) or 0)
    if enabled_count == 0:
        disabled = [
            d.get("DetectorId", "unknown")
            for d in gd.get("detectors", [])
            if isinstance(d, dict) and d.get("Status") != "ENABLED"
        ]
        return PreCheckResult(
            "VULN-GD-001",
            "FAIL",
            f"GuardDuty has {detector_count} detector(s) but none are ENABLED",
            disabled[:5],
        )

    return PreCheckResult(
        "VULN-GD-001",
        "PASS",
        f"GuardDuty is active ({enabled_count} ENABLED detector(s))",
        [],
    )


@_register("vulns")
def check_vuln_guardduty_suppressed(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-GD-002: GuardDuty findings auto-archived without review (suppression rules)."""
    gd = evidence.get("guardduty-status")
    if not isinstance(gd, dict):
        return PreCheckResult("VULN-GD-002", "SKIP", "no guardduty-status evidence", [])

    if not gd.get("has_active_detector"):
        # If GuardDuty is not active, VULN-GD-001 handles it
        return PreCheckResult(
            "VULN-GD-002", "SKIP", "GuardDuty not active (covered by VULN-GD-001)", []
        )

    total_suppression_rules = sum(
        int(d.get("AutoArchiveRuleCount") or 0)
        for d in gd.get("detectors", [])
        if isinstance(d, dict) and d.get("AutoArchiveRuleCount") is not None
    )

    if total_suppression_rules == 0:
        return PreCheckResult(
            "VULN-GD-002",
            "PASS",
            "no GuardDuty auto-archive suppression rules configured",
            [],
        )

    rules = [
        r.get("FilterName", "unknown")
        for d in gd.get("detectors", [])
        if isinstance(d, dict)
        for r in (d.get("SuppressionRules") or [])
        if isinstance(r, dict)
    ]

    return PreCheckResult(
        "VULN-GD-002",
        "FAIL",
        f"{total_suppression_rules} GuardDuty auto-archive rule(s) may suppress threat findings",
        rules[:10],
    )


# ============================================================================
# SECRETS MANAGER PRE-CHECKS
# ============================================================================


@_register("secretsmanager")
def check_sm_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public wildcard resource policy on secrets."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        policy = s.get("ResourcePolicy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict):
                continue
            principal = st.get("Principal", {})
            if _principal_is_wildcard(principal):
                return PreCheckResult(
                    "SM-001",
                    "FAIL",
                    "secret has Principal:*",
                    [s.get("ARN", s.get("Name", "unknown"))],
                )

    return PreCheckResult("SM-001", "PASS", "no wildcard principals in secrets", [])


@_register("secretsmanager")
def check_sm_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Rotation interval > 90 days."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        if not s.get("RotationEnabled"):
            continue
        rules = s.get("RotationRules")
        if not isinstance(rules, dict):
            continue
        try:
            days = rules.get("AutomaticallyAfterDays")
            if days is not None and int(days) > 90:
                return PreCheckResult(
                    "SM-003",
                    "FAIL",
                    f"rotation interval={days} days (>90)",
                    [s.get("ARN", s.get("Name", "unknown"))],
                )
        except (ValueError, TypeError):
            continue

    return PreCheckResult("SM-003", "PASS", "no secrets with rotation >90 days", [])


@_register("secretsmanager")
def check_sm_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets resource policy grants external account access."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        secret_arn = str(s.get("ARN") or "")
        secret_account = _account_from_arn(secret_arn)
        if not secret_account:
            continue
        policy = s.get("ResourcePolicy")
        if not isinstance(policy, dict):
            continue

        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            continue

        for st in stmts:
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            principal = st.get("Principal")
            aws_p = None
            if isinstance(principal, dict):
                aws_p = principal.get("AWS")
            principals = (
                [aws_p] if isinstance(aws_p, str) else aws_p if isinstance(aws_p, list) else []
            )
            for p in principals:
                ps = str(p)
                if ps.startswith("arn:aws:iam::"):
                    p_account = _account_from_arn(ps)
                    if p_account and p_account != secret_account:
                        return PreCheckResult(
                            "SM-013",
                            "FAIL",
                            f"secret policy allows external account {p_account}",
                            [secret_arn or s.get("Name", "unknown")],
                        )

    return PreCheckResult(
        "SM-013", "PASS", "no external account principals in resource policies", []
    )


@_register("secretsmanager")
def check_sm_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """Rotation enabled but Lambda rotation config missing/inconsistent."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        if not bool(s.get("RotationEnabled")):
            continue
        lambda_arn = str(s.get("RotationLambdaARN") or "").strip()
        if not lambda_arn:
            return PreCheckResult(
                "SM-014",
                "FAIL",
                "rotation enabled without RotationLambdaARN",
                [s.get("ARN", s.get("Name", "unknown"))],
            )
        if not lambda_arn.startswith("arn:aws:lambda:"):
            return PreCheckResult(
                "SM-014",
                "FAIL",
                "rotation lambda ARN is malformed",
                [s.get("ARN", s.get("Name", "unknown"))],
            )

    return PreCheckResult("SM-014", "PASS", "rotation lambda configuration appears consistent", [])


@_register("secretsmanager")
def check_sm_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets encrypted with KMS keys from different account."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        secret_arn = str(s.get("ARN") or "")
        secret_account = _account_from_arn(secret_arn)
        kms_key = str(s.get("KmsKeyId") or "")
        if not secret_account or not kms_key.startswith("arn:aws:kms:"):
            continue
        kms_account = _account_from_arn(kms_key)
        if kms_account and kms_account != secret_account:
            return PreCheckResult(
                "SM-015",
                "FAIL",
                f"secret uses cross-account KMS key ({kms_account})",
                [secret_arn or s.get("Name", "unknown")],
            )

    return PreCheckResult("SM-015", "PASS", "no cross-account KMS key usage in secrets", [])


@_register("secretsmanager")
def check_sm_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """Replication + permissive/external resource policy increases backdoor risk."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    def _account_from_arn(arn: str) -> str:
        parts = arn.split(":")
        return parts[4] if len(parts) > 4 else ""

    for s in secrets_list if isinstance(secrets_list, list) else []:
        if not isinstance(s, dict):
            continue
        rep = s.get("ReplicationStatus")
        if not isinstance(rep, list) or not rep:
            continue

        secret_arn = str(s.get("ARN") or "")
        secret_account = _account_from_arn(secret_arn)
        policy = s.get("ResourcePolicy")
        if not isinstance(policy, dict):
            continue

        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list):
            continue

        for st in stmts:
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if _principal_is_wildcard(st.get("Principal")):
                return PreCheckResult(
                    "SM-017",
                    "FAIL",
                    "replicated secret has wildcard resource policy",
                    [secret_arn or s.get("Name", "unknown")],
                )

            principal = st.get("Principal")
            aws_p = principal.get("AWS") if isinstance(principal, dict) else None
            principals = (
                [aws_p] if isinstance(aws_p, str) else aws_p if isinstance(aws_p, list) else []
            )
            for p in principals:
                ps = str(p)
                if ps.startswith("arn:aws:iam::"):
                    p_account = _account_from_arn(ps)
                    if p_account and secret_account and p_account != secret_account:
                        return PreCheckResult(
                            "SM-017",
                            "FAIL",
                            f"replicated secret policy allows external account {p_account}",
                            [secret_arn or s.get("Name", "unknown")],
                        )

    return PreCheckResult(
        "SM-017", "PASS", "no risky replication + permissive policy combination", []
    )


@_register("secretsmanager")
def check_sm_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Automatic rotation disabled on secrets."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-002", "SKIP", "no secrets data available", [])

    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and not s.get("RotationEnabled")
    ]
    if not failed:
        return PreCheckResult("SM-002", "PASS", "all secrets have rotation enabled", [])
    return PreCheckResult(
        "SM-002",
        "FAIL",
        f"{len(failed)} secret(s) have automatic rotation disabled",
        failed,
    )


@_register("secretsmanager")
def check_sm_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets using AWS-managed KMS key instead of customer-managed key."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-004", "SKIP", "no secrets data available", [])

    # AWS-managed key indicators
    _aws_kms_patterns = ("alias/aws/secretsmanager", "aws/secretsmanager", "Default AWS managed")

    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and any(p in str(s.get("KmsKeyId") or "") for p in _aws_kms_patterns)
    ]
    if not failed:
        return PreCheckResult("SM-004", "PASS", "all secrets use customer-managed KMS keys", [])
    return PreCheckResult(
        "SM-004",
        "FAIL",
        f"{len(failed)} secret(s) use AWS-managed KMS key (not customer-managed)",
        failed,
    )


@_register("secretsmanager")
def check_sm_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets never rotated OR not changed in >365 days (stale credentials)."""
    from datetime import datetime, timezone

    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-005", "SKIP", "no secrets data available", [])

    now = datetime.now(tz=timezone.utc)
    never_rotated = []
    stale = []

    for s in secrets_list:
        if not isinstance(s, dict):
            continue
        arn = s.get("ARN", s.get("Name", "unknown"))

        # Case 1: LastRotatedDate is empty/null = never rotated (always FAIL)
        last_rotated = str(s.get("LastRotatedDate") or "").strip()
        rotation_enabled = bool(s.get("RotationEnabled"))
        if not last_rotated and not rotation_enabled:
            never_rotated.append(arn)
            continue

        # Case 2: LastChangedDate > 365 days ago
        raw = s.get("LastChangedDate") or s.get("CreatedDate")
        if not raw:
            continue
        try:
            dt_str = str(raw).replace(" ", "T")
            if "+" in dt_str[10:] or dt_str.endswith("Z"):
                dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(dt_str).replace(tzinfo=timezone.utc)
            if (now - dt).days > 365:
                stale.append(arn)
        except (ValueError, TypeError):
            continue

    failed = never_rotated + stale
    if not failed:
        return PreCheckResult("SM-005", "PASS", "no stale or never-rotated secrets", [])

    parts = []
    if never_rotated:
        parts.append(f"{len(never_rotated)} never rotated")
    if stale:
        parts.append(f"{len(stale)} unchanged >365 days")
    return PreCheckResult(
        "SM-005",
        "FAIL",
        f"stale credentials detected: {', '.join(parts)}",
        failed,
    )


@_register("secretsmanager")
def check_sm_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets missing required governance tags (Owner, DataClassification)."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-006", "SKIP", "no secrets data available", [])

    _required = {"Owner", "DataClassification"}
    failed = []
    for s in secrets_list:
        if not isinstance(s, dict):
            continue
        existing = {t["Key"] for t in (s.get("Tags") or []) if isinstance(t, dict) and "Key" in t}
        if _required - existing:
            failed.append(s.get("ARN", s.get("Name", "unknown")))

    if not failed:
        return PreCheckResult("SM-006", "PASS", "all secrets have required governance tags", [])
    return PreCheckResult(
        "SM-006",
        "FAIL",
        f"{len(failed)} secret(s) missing Owner or DataClassification tag",
        failed,
    )


@_register("secretsmanager")
def check_sm_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets without description (governance / discoverability)."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-007", "SKIP", "no secrets data available", [])

    _empty = {"", "no description", "none", "n/a"}
    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and str(s.get("Description") or "").strip().lower() in _empty
    ]
    if not failed:
        return PreCheckResult("SM-007", "PASS", "all secrets have descriptions", [])
    return PreCheckResult(
        "SM-007",
        "FAIL",
        f"{len(failed)} secret(s) have no description",
        failed,
    )


@_register("secretsmanager")
def check_sm_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Production secrets without cross-region replication."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-008", "SKIP", "no secrets data available", [])

    failed = []
    for s in secrets_list:
        if not isinstance(s, dict):
            continue
        # Only flag production secrets
        tags = {t.get("Key"): t.get("Value") for t in (s.get("Tags") or []) if isinstance(t, dict)}
        env = str(tags.get("Environment") or tags.get("env") or "").lower()
        if env not in ("prod", "production", ""):
            continue
        rep = s.get("ReplicationStatus")
        if isinstance(rep, list) and not rep:
            failed.append(s.get("ARN", s.get("Name", "unknown")))

    if not failed:
        return PreCheckResult(
            "SM-008", "PASS", "secrets have cross-region replication or are non-prod", []
        )
    return PreCheckResult(
        "SM-008",
        "FAIL",
        f"{len(failed)} production secret(s) not replicated to any secondary region",
        failed,
    )


@_register("secretsmanager")
def check_sm_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Secrets resource policies missing MFA condition (empty policy = no MFA)."""
    secrets_doc = evidence.get("secrets", {})
    secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

    if not isinstance(secrets_list, list) or not secrets_list:
        return PreCheckResult("SM-011", "SKIP", "no secrets data available", [])

    def _policy_has_mfa(policy: Any) -> bool:
        if not isinstance(policy, dict) or not policy:
            return False
        for st in policy.get("Statement", []) or []:
            cond = st.get("Condition", {}) if isinstance(st, dict) else {}
            for _op, kv in cond.items() if isinstance(cond, dict) else []:
                if isinstance(kv, dict) and "aws:MultiFactorAuthPresent" in kv:
                    return True
        return False

    failed = [
        s.get("ARN", s.get("Name", "unknown"))
        for s in secrets_list
        if isinstance(s, dict) and not _policy_has_mfa(s.get("ResourcePolicy"))
    ]
    if not failed:
        return PreCheckResult("SM-011", "PASS", "all secret resource policies require MFA", [])
    return PreCheckResult(
        "SM-011",
        "FAIL",
        f"{len(failed)} secret(s) lack MFA condition in resource policy",
        failed,
    )


@_register("secretsmanager")
def check_sm_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """No rotation failure alerting configured (CloudWatch + EventBridge)."""
    cw = evidence.get("cloudwatch_alarms", {})
    eb = evidence.get("eventbridge_rules", {})

    cw_relevant = sum(
        int(r.get("likely_relevant_count", 0))
        for r in (cw.get("regions", {}) or {}).values()
        if isinstance(r, dict)
    )
    eb_relevant = sum(
        int(r.get("relevant_rule_count", 0))
        for r in (eb.get("regions", {}) or {}).values()
        if isinstance(r, dict)
    )

    if cw_relevant == 0 and eb_relevant == 0:
        # Only FAIL if we have evidence data (not just missing files)
        if not cw and not eb:
            return PreCheckResult("SM-012", "SKIP", "alerting evidence files not collected", [])
        return PreCheckResult(
            "SM-012",
            "FAIL",
            "no CloudWatch alarms or EventBridge rules monitor Secrets Manager rotation failures",
            [],
        )
    return PreCheckResult(
        "SM-012",
        "PASS",
        f"rotation monitoring found: {cw_relevant} CW alarm(s), {eb_relevant} EventBridge rule(s)",
        [],
    )


# ============================================================================
# ECR PRE-CHECKS
# ============================================================================


@_register("ecr")
def check_ecr_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Public wildcard principals in ECR repository policies."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []

    for r in repos_list if isinstance(repos_list, list) else []:
        if not isinstance(r, dict):
            continue
        policy = r.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            if _principal_is_wildcard(st.get("Principal")):
                return PreCheckResult(
                    "ECR-001",
                    "FAIL",
                    "repo has Principal:*",
                    [r.get("RepositoryArn", r.get("repositoryName", "unknown"))],
                )

    return PreCheckResult("ECR-001", "PASS", "no wildcard principals in ECR", [])


@_register("ecr")
def check_ecr_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Image tags should be immutable."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []
    if not isinstance(repos_list, list) or not repos_list:
        return PreCheckResult("ECR-002", "SKIP", "no repositories evidence", [])

    mutable = []
    for r in repos_list:
        if not isinstance(r, dict):
            continue
        if str(r.get("ImageTagMutability") or "").upper() == "MUTABLE":
            mutable.append(str(r.get("RepositoryArn") or r.get("RepositoryName") or "unknown"))

    if mutable:
        return PreCheckResult(
            "ECR-002", "FAIL", f"{len(mutable)} repositories with mutable tags", mutable[:10]
        )
    return PreCheckResult("ECR-002", "PASS", "all repositories use immutable tags", [])


@_register("ecr")
def check_ecr_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Repositories should use KMS customer-managed keys when required."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []
    if not isinstance(repos_list, list) or not repos_list:
        return PreCheckResult("ECR-005", "SKIP", "no repositories evidence", [])

    non_cmk = []
    for r in repos_list:
        if not isinstance(r, dict):
            continue
        enc = str(r.get("EncryptionType") or "").upper()
        kms_key = str(r.get("KmsKey") or "")
        if enc != "KMS" or not kms_key:
            non_cmk.append(str(r.get("RepositoryArn") or r.get("RepositoryName") or "unknown"))

    if non_cmk:
        return PreCheckResult(
            "ECR-005", "FAIL", f"{len(non_cmk)} repositories without CMK encryption", non_cmk[:10]
        )
    return PreCheckResult("ECR-005", "PASS", "all repositories use KMS customer-managed keys", [])


@_register("ecr")
def check_ecr_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lifecycle policies should be configured to expire unused images."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []
    if not isinstance(repos_list, list) or not repos_list:
        return PreCheckResult("ECR-006", "SKIP", "no repositories evidence", [])

    missing = []
    for r in repos_list:
        if not isinstance(r, dict):
            continue
        has_policy = r.get("HasLifecyclePolicy")
        lifecycle = r.get("LifecyclePolicy")
        if has_policy is False or not lifecycle:
            missing.append(str(r.get("RepositoryArn") or r.get("RepositoryName") or "unknown"))

    if missing:
        return PreCheckResult(
            "ECR-006", "FAIL", f"{len(missing)} repositories without lifecycle policy", missing[:10]
        )
    return PreCheckResult("ECR-006", "PASS", "all repositories have lifecycle policies", [])


@_register("ecr")
def check_ecr_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Image scanning on push."""
    # If registry has ENHANCED scanning, this may be covered at registry level
    reg_doc = evidence.get("registry")
    if isinstance(reg_doc, dict):
        reg_scanning = reg_doc.get("registry_scanning")
        if isinstance(reg_scanning, dict):
            scan_cfg = reg_scanning.get("scanningConfiguration")
            if isinstance(scan_cfg, dict) and scan_cfg.get("scanType") == "ENHANCED":
                return PreCheckResult("ECR-003", "PASS", "ENHANCED scanning at registry level", [])

    return PreCheckResult("ECR-003", "SKIP", "requires AI analysis of per-repo scanning", [])


@_register("ecr")
def check_ecr_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Registry scanning configuration should be defined."""
    reg_doc = evidence.get("registry")
    if not isinstance(reg_doc, dict):
        return PreCheckResult("ECR-004", "SKIP", "no registry evidence", [])

    reg_scanning = reg_doc.get("registry_scanning")
    if isinstance(reg_scanning, dict) and reg_scanning.get("error"):
        return PreCheckResult(
            "ECR-004", "SKIP", f"scanning collection error: {reg_scanning.get('error')}", []
        )

    if isinstance(reg_scanning, dict) and reg_scanning.get("scanningConfiguration"):
        return PreCheckResult("ECR-004", "PASS", "registry scanning configured", [])

    return PreCheckResult("ECR-004", "FAIL", "no registry scanning configuration", [])


@_register("ecr")
def check_ecr_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Cross-account repository access review."""
    repos_doc = evidence.get("repositories", {})
    repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []

    # Determine current account
    current_account = None
    reg_doc = evidence.get("registry")
    if isinstance(reg_doc, dict):
        reg = reg_doc.get("registry")
        if isinstance(reg, dict) and reg.get("registryId"):
            current_account = str(reg["registryId"])

    if not current_account:
        for r in repos_list if isinstance(repos_list, list) else []:
            if isinstance(r, dict) and r.get("RepositoryArn"):
                parts = str(r["RepositoryArn"]).split(":")
                if len(parts) > 4:
                    current_account = parts[4]
                    break

    for r in repos_list if isinstance(repos_list, list) else []:
        if not isinstance(r, dict):
            continue
        policy = r.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if _principal_is_wildcard(principal):
                return PreCheckResult(
                    "ECR-007",
                    "FAIL",
                    "wildcard principal implies cross-account",
                    [r.get("RepositoryArn", "unknown")],
                )
            if isinstance(principal, dict) and "AWS" in principal:
                aws_p = principal["AWS"]
                aws_list = (
                    [aws_p]
                    if isinstance(aws_p, str)
                    else (aws_p if isinstance(aws_p, list) else [])
                )
                for p in aws_list:
                    if not isinstance(p, str):
                        continue
                    if p.isdigit() and current_account and p != current_account:
                        return PreCheckResult(
                            "ECR-007",
                            "FAIL",
                            f"cross-account principal: {p}",
                            [r.get("RepositoryArn", "unknown")],
                        )
                    if p.startswith("arn:aws:iam::"):
                        acct = p.split(":")[4] if len(p.split(":")) > 4 else ""
                        if acct and current_account and acct != current_account:
                            return PreCheckResult(
                                "ECR-007",
                                "FAIL",
                                f"cross-account ARN: {p}",
                                [r.get("RepositoryArn", "unknown")],
                            )

    return PreCheckResult("ECR-007", "PASS", "no cross-account ECR access", [])


# ============================================================================
# KMS PRE-CHECKS
# ============================================================================


def _kms_id_to_arn(evidence: Dict[str, Any]) -> Dict[str, str]:
    """Build a KeyId → KeyArn map from kms-keys evidence for use in pre-checks."""
    keys_doc = evidence.get("kms-keys")
    items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
    if not isinstance(items, list):
        return {}
    result: Dict[str, str] = {}
    for k in items:
        if not isinstance(k, dict):
            continue
        key_id = str(k.get("KeyId") or (k.get("Metadata") or {}).get("KeyId") or "")
        key_arn = str(k.get("KeyArn") or (k.get("Metadata") or {}).get("Arn") or "")
        if key_id and key_arn:
            result[key_id] = key_arn
    return result


def _kms_stmt_has_binding_conditions(stmt: Dict[str, Any]) -> bool:
    """Return True if the policy statement has conditions that restrict access to:
    - The same AWS account (kms:CallerAccount), AND
    - A specific AWS service (kms:ViaService or StringLike kms:ViaService).
    Together these constitute an unambiguous binding restriction equivalent to an
    account-scoped service principal — NOT a public wildcard exposure.
    """
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return False
    # Flatten all condition operators to a merged key→value map for inspection
    merged: Dict[str, Any] = {}
    for op_val in cond.values():
        if isinstance(op_val, dict):
            merged.update({k.lower(): v for k, v in op_val.items()})
    has_caller_account = "kms:calleraccount" in merged
    has_via_service = "kms:viaservice" in merged
    return has_caller_account and has_via_service


@_register("kms")
def check_kms_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Key policy with wildcard/broad principals not constrained to same account + service."""
    pol_doc = evidence.get("kms-key-policies")
    items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-001", "SKIP", "no kms-key-policies evidence", [])

    arn_map = _kms_id_to_arn(evidence)
    flagged_arns: List[str] = []

    for rec in items:
        if not isinstance(rec, dict):
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            if not _principal_is_wildcard(st.get("Principal")):
                continue
            # Standard AWS service-integrated CMK pattern:
            # Principal=* WITH kms:CallerAccount + kms:ViaService is NOT a wildcard risk.
            # It restricts access to the same account and a specific service (e.g. Secrets Manager).
            if _kms_stmt_has_binding_conditions(st):
                continue
            key_id = rec.get("KeyId", "unknown")
            key_arn = arn_map.get(key_id, rec.get("KeyArn", key_id))
            if key_arn not in flagged_arns:
                flagged_arns.append(key_arn)
            break  # one match per key is enough

    if flagged_arns:
        count = len(flagged_arns)
        return PreCheckResult(
            "KMS-001",
            "FAIL",
            f"{count} key(s) with wildcard principal without account+service binding conditions",
            flagged_arns[:10],
        )

    return PreCheckResult("KMS-001", "PASS", "no unbound wildcard principals in key policies", [])


@_register("kms")
def check_kms_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Unexpected grants with Decrypt/GenerateDataKey operations.

    Ignore expected service-managed grants (RDS/Lambda/etc.) when they have
    encryption-context constraints and service principals.
    """
    grants_doc = evidence.get("kms-grants")
    items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-002", "SKIP", "no kms-grants evidence", [])

    def _is_sensitive(ops: List[Any]) -> bool:
        ops_norm = {str(o) for o in ops if o is not None}
        return "Decrypt" in ops_norm or any(o.startswith("GenerateDataKey") for o in ops_norm)

    def _has_context_constraints(grant: Dict[str, Any]) -> bool:
        cons = grant.get("Constraints")
        if not isinstance(cons, dict):
            return False
        return bool(cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset"))

    def _is_service_managed_principal(grant: Dict[str, Any]) -> bool:
        grantee = str(grant.get("GranteePrincipal") or "")
        issuing = str(grant.get("IssuingAccount") or "")
        if grantee.endswith(".amazonaws.com"):
            return True
        if ":assumed-role/" in grantee and "arn:aws:sts::" in grantee:
            return True
        if issuing.endswith(".amazonaws.com"):
            return True
        return False

    for g in items:
        if not isinstance(g, dict):
            continue
        ops = g.get("Operations")
        if not isinstance(ops, list):
            continue

        if not _is_sensitive(ops):
            continue

        # Expected service grants with tight encryption-context constraints are noisy.
        if _is_service_managed_principal(g) and _has_context_constraints(g):
            continue

        key_id = str(g.get("KeyId") or "unknown")
        grant_id = str(g.get("GrantId") or "unknown")
        return PreCheckResult(
            "KMS-002",
            "FAIL",
            f"unexpected sensitive grant {grant_id} on {key_id}",
            [key_id],
        )

    return PreCheckResult("KMS-002", "PASS", "no sensitive grants", [])


@_register("kms")
def check_kms_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Policy allows admin modification (PutKeyPolicy/CreateGrant)."""
    pol_doc = evidence.get("kms-key-policies")
    items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-003", "SKIP", "no kms-key-policies evidence", [])

    arn_map = _kms_id_to_arn(evidence)
    flagged_arns: List[str] = []

    for rec in items:
        if not isinstance(rec, dict):
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        key_id = rec.get("KeyId", "unknown")
        key_arn = arn_map.get(key_id, rec.get("KeyArn", key_id))
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            for act in _actions_from_stmt(st):
                if act.lower() in {"kms:putkeypolicy", "kms:creategrant", "kms:*"}:
                    if key_arn not in flagged_arns:
                        flagged_arns.append(key_arn)
                    break  # one match per key is enough

    if flagged_arns:
        return PreCheckResult(
            "KMS-003",
            "FAIL",
            f"{len(flagged_arns)} key(s) allow admin modification (PutKeyPolicy/CreateGrant/kms:*)",
            flagged_arns[:10],
        )
    return PreCheckResult("KMS-003", "PASS", "no admin modification permissions", [])


@_register("kms")
def check_kms_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Customer-managed key rotation should be enabled."""
    keys_doc = evidence.get("kms-keys")
    items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-004", "SKIP", "no kms-keys evidence", [])

    for k in items:
        if not isinstance(k, dict):
            continue
        meta = k.get("Metadata")
        if isinstance(meta, dict) and str(meta.get("KeyManager") or "").upper() != "CUSTOMER":
            continue
        rot = k.get("KeyRotationEnabled")
        if rot is False or rot in {"false", "False", 0, "0"}:
            key_id = k.get("KeyId", (meta or {}).get("KeyId", "unknown"))
            return PreCheckResult(
                "KMS-004", "FAIL", f"key {key_id} rotation disabled", [k.get("KeyArn", key_id)]
            )

    return PreCheckResult("KMS-004", "PASS", "all customer keys have rotation enabled", [])


@_register("kms")
def check_kms_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Policies allowing destructive KMS actions to non-root, non-standard principals."""
    pol_doc = evidence.get("kms-key-policies")
    items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-005", "SKIP", "no kms-key-policies evidence", [])

    destructive = {
        "kms:disablekey",
        "kms:schedulekeydeletion",
        "kms:deleteimportedkeymaterial",
        "kms:deletealias",
        "kms:updatealias",
        "kms:*",
    }

    arn_map = _kms_id_to_arn(evidence)

    for rec in items:
        if not isinstance(rec, dict):
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue

            # Skip the AWS-required "Enable IAM User Permissions" root statement.
            # kms:* granted to the account root (arn:aws:iam::<account>:root) is the
            # standard, mandatory delegation pattern recommended by AWS KMS documentation.
            # It does NOT grant direct access to any entity — it only enables IAM policies.
            principal = st.get("Principal")
            if isinstance(principal, dict):
                aws_p = principal.get("AWS", "")
                if isinstance(aws_p, str) and aws_p.endswith(":root"):
                    continue
                if isinstance(aws_p, list) and all(
                    isinstance(p, str) and p.endswith(":root") for p in aws_p
                ):
                    continue

            for act in _actions_from_stmt(st):
                if str(act).lower() in destructive:
                    key_id = rec.get("KeyId", "unknown")
                    key_arn = arn_map.get(key_id, rec.get("KeyArn", key_id))
                    return PreCheckResult(
                        "KMS-005",
                        "FAIL",
                        f"key {key_id} allows destructive action {act} to non-root principal",
                        [key_arn],
                    )

    return PreCheckResult(
        "KMS-005", "PASS", "no destructive key actions to non-root principals", []
    )


@_register("kms")
def check_kms_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Imported key material can be deleted if policy allows it."""
    keys_doc = evidence.get("kms-keys")
    key_items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
    pol_doc = evidence.get("kms-key-policies")
    pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else None

    if not isinstance(key_items, list) or not key_items:
        return PreCheckResult("KMS-006", "SKIP", "no kms-keys evidence", [])
    if not isinstance(pol_items, list) or not pol_items:
        return PreCheckResult("KMS-006", "SKIP", "no kms-key-policies evidence", [])

    external_ids = set()
    for k in key_items:
        if not isinstance(k, dict):
            continue
        meta = k.get("Metadata") if isinstance(k.get("Metadata"), dict) else {}
        if str(meta.get("Origin") or "").upper() == "EXTERNAL":
            key_id = str(meta.get("KeyId") or k.get("KeyId") or "")
            if key_id:
                external_ids.add(key_id)

    if not external_ids:
        return PreCheckResult("KMS-006", "PASS", "no EXTERNAL origin keys found", [])

    for rec in pol_items:
        if not isinstance(rec, dict):
            continue
        key_id = str(rec.get("KeyId") or "")
        if key_id not in external_ids:
            continue
        policy = rec.get("Policy")
        if not isinstance(policy, dict):
            continue
        for st in _stmts_from_policy(policy):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            for act in _actions_from_stmt(st):
                if str(act).lower() in {"kms:deleteimportedkeymaterial", "kms:*"}:
                    return PreCheckResult(
                        "KMS-006",
                        "FAIL",
                        f"EXTERNAL key {key_id} policy allows {act}",
                        [rec.get("KeyArn", key_id)],
                    )

    return PreCheckResult("KMS-006", "PASS", "no delete-imported-key-material risk found", [])


@_register("kms")
def check_kms_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Grants that delegate CreateGrant can allow persistence."""
    grants_doc = evidence.get("kms-grants")
    items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("KMS-007", "SKIP", "no kms-grants evidence", [])

    flagged_keys: List[str] = []
    flagged_grants: List[str] = []

    for g in items:
        if not isinstance(g, dict):
            continue
        ops = g.get("Operations")
        if not isinstance(ops, list):
            continue
        if "CreateGrant" not in {str(o) for o in ops if o is not None}:
            continue

        cons = g.get("Constraints")
        has_ctx = isinstance(cons, dict) and bool(
            cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset")
        )
        if has_ctx:
            # constrained service grant - lower risk/noisy
            continue

        key_id = str(g.get("KeyId") or "unknown")
        grant_id = str(g.get("GrantId") or "unknown")
        if key_id not in flagged_keys:
            flagged_keys.append(key_id)
        flagged_grants.append(grant_id[:12])  # abbreviated for readability

    if flagged_keys:
        count = len(flagged_keys)
        return PreCheckResult(
            "KMS-007",
            "FAIL",
            f"{count} key(s) with grants that delegate CreateGrant without encryption context constraints",
            flagged_keys[:10],
        )

    return PreCheckResult("KMS-007", "PASS", "no unconstrained CreateGrant delegation", [])


# ============================================================================
# MESSAGING PRE-CHECKS
# ============================================================================


@_register("messaging")
def check_msg_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """SQS queue policy should include OrgID condition."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-001", "SKIP", "no sqs-queues evidence", [])

    for q in items:
        if not isinstance(q, dict):
            continue
        pol = q.get("Policy")
        if not isinstance(pol, dict):
            continue
        cond_text = json.dumps(pol, default=str)
        if "aws:PrincipalOrgID" in cond_text or "aws:PrincipalOrgId" in cond_text:
            return PreCheckResult("MSG-001", "PASS", "OrgID condition found", [])

    # No OrgID found → FAIL (if queues have policies)
    has_policy = any(isinstance(q, dict) and q.get("Policy") for q in items)
    if has_policy:
        return PreCheckResult("MSG-001", "FAIL", "no aws:PrincipalOrgID in queue policies", [])
    return PreCheckResult("MSG-001", "SKIP", "no queue policies to evaluate", [])


@_register("messaging")
def check_msg_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """DLQ/Redrive configuration presence."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-002", "SKIP", "no sqs-queues evidence", [])

    for q in items:
        if isinstance(q, dict) and (q.get("RedrivePolicy") or q.get("RedriveAllowPolicy")):
            return PreCheckResult("MSG-002", "PASS", "redrive config present", [])

    return PreCheckResult("MSG-002", "FAIL", "no redrive configuration", [])


@_register("messaging")
def check_msg_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS->SQS injection: SendMessage from SNS without SourceArn/SourceAccount."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-003", "SKIP", "no sqs-queues evidence", [])

    for q in items:
        if not isinstance(q, dict):
            continue
        pol = q.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict):
                continue
            if str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            # Check action includes SendMessage
            acts = _actions_from_stmt(st)
            has_send = any(a.lower() in {"sqs:sendmessage", "sqs:*", "*"} for a in acts)
            if not has_send:
                continue
            # Check principal is SNS
            principal = st.get("Principal")
            if isinstance(principal, dict):
                svc = principal.get("Service")
                if isinstance(svc, str) and svc.lower() == "sns.amazonaws.com":
                    pass
                elif isinstance(svc, list) and any(
                    isinstance(x, str) and x.lower() == "sns.amazonaws.com" for x in svc
                ):
                    pass
                else:
                    continue
            else:
                continue
            # Check missing SourceArn/SourceAccount
            cond = st.get("Condition")
            cond_text = json.dumps(cond, default=str) if isinstance(cond, dict) else ""
            if "aws:SourceArn" not in cond_text and "aws:SourceAccount" not in cond_text:
                return PreCheckResult(
                    "MSG-003",
                    "FAIL",
                    "SNS->SQS without SourceArn check",
                    [q.get("QueueUrl", q.get("QueueArn", "unknown"))],
                )

    return PreCheckResult("MSG-003", "PASS", "SNS->SQS policies have proper conditions", [])


@_register("messaging")
def check_msg_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """Message move task risk (only applies when DLQs exist)."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-004", "SKIP", "no sqs-queues evidence", [])

    has_dlq = any(isinstance(q, dict) and q.get("RedrivePolicy") for q in items)
    if not has_dlq:
        return PreCheckResult("MSG-004", "PASS", "no DLQs configured (N/A)", [])
    return PreCheckResult("MSG-004", "SKIP", "requires AI analysis of DLQ security", [])


@_register("messaging")
def check_msg_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Wildcard principals should not have SQS data-plane actions."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-005", "SKIP", "no sqs-queues evidence", [])

    risky_actions = {
        "sqs:sendmessage",
        "sqs:sendmessagebatch",
        "sqs:receivemessage",
        "sqs:deletemessage",
        "sqs:changemessagevisibility",
        "sqs:*",
        "*",
    }

    for q in items:
        if not isinstance(q, dict):
            continue
        pol = q.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            if not (actions & risky_actions):
                continue
            if _principal_is_wildcard_any(st.get("Principal")):
                return PreCheckResult(
                    "MSG-005",
                    "FAIL",
                    "queue policy allows wildcard principal data-plane actions",
                    [str(q.get("QueueArn") or q.get("QueueUrl") or "unknown")],
                )

    return PreCheckResult("MSG-005", "PASS", "no wildcard data-plane access in SQS policies", [])


@_register("messaging")
def check_msg_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """SQS queues should have encryption enabled."""
    q_doc = evidence.get("sqs-queues")
    items = q_doc.get("items") if isinstance(q_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-006", "SKIP", "no sqs-queues evidence", [])

    unencrypted = []
    for q in items:
        if not isinstance(q, dict):
            continue
        kms = q.get("KmsMasterKeyId")
        sse = str(q.get("SqsManagedSseEnabled") or "").lower() == "true"
        if not kms and not sse:
            unencrypted.append(str(q.get("QueueArn") or q.get("QueueUrl") or "unknown"))

    if not unencrypted:
        return PreCheckResult("MSG-006", "PASS", "all queues encrypted at rest", [])
    return PreCheckResult(
        "MSG-006", "FAIL", f"{len(unencrypted)} queues without encryption", unencrypted[:10]
    )


@_register("messaging")
def check_msg_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS topics should not allow wildcard Subscribe."""
    t_doc = evidence.get("sns-topics")
    items = t_doc.get("items") if isinstance(t_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-007", "SKIP", "no sns-topics evidence", [])

    for t in items:
        if not isinstance(t, dict):
            continue
        attrs = t.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        pol = attrs.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            if not ({"sns:subscribe", "sns:*", "*"} & actions):
                continue
            if _principal_is_wildcard_any(
                st.get("Principal")
            ) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "MSG-007",
                    "FAIL",
                    "topic policy allows wildcard Subscribe",
                    [str(t.get("TopicArn") or "unknown")],
                )

    return PreCheckResult("MSG-007", "PASS", "no wildcard Subscribe in SNS topic policies", [])


@_register("messaging")
def check_msg_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS topics should not allow wildcard Publish."""
    t_doc = evidence.get("sns-topics")
    items = t_doc.get("items") if isinstance(t_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-008", "SKIP", "no sns-topics evidence", [])

    for t in items:
        if not isinstance(t, dict):
            continue
        attrs = t.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        pol = attrs.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            if not ({"sns:publish", "sns:*", "*"} & actions):
                continue
            if _principal_is_wildcard_any(
                st.get("Principal")
            ) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "MSG-008",
                    "FAIL",
                    "topic policy allows wildcard Publish",
                    [str(t.get("TopicArn") or "unknown")],
                )

    return PreCheckResult("MSG-008", "PASS", "no wildcard Publish in SNS topic policies", [])


@_register("messaging")
def check_msg_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """SNS topic policy grants administrative actions (DeleteTopic, SetTopicAttributes,
    AddPermission, RemovePermission) to a wildcard principal."""
    _admin_actions = {
        "sns:deletetopic",
        "sns:settopicattributes",
        "sns:addpermission",
        "sns:removepermission",
        "sns:*",
        "*",
    }
    t_doc = evidence.get("sns-topics")
    items = t_doc.get("items") if isinstance(t_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("MSG-009", "SKIP", "no sns-topics evidence", [])

    for t in items:
        if not isinstance(t, dict):
            continue
        attrs = t.get("Attributes")
        if not isinstance(attrs, dict):
            continue
        pol = attrs.get("Policy")
        if not isinstance(pol, dict):
            continue
        for st in _stmts_from_policy(pol):
            if not isinstance(st, dict) or str(st.get("Effect") or "").upper() != "ALLOW":
                continue
            actions = {str(a).lower() for a in _actions_from_stmt(st)}
            matched = _admin_actions & actions
            if not matched:
                continue
            if _principal_is_wildcard_any(
                st.get("Principal")
            ) and not _stmt_has_same_account_restriction(st):
                return PreCheckResult(
                    "MSG-009",
                    "FAIL",
                    f"topic policy allows wildcard principal to perform admin actions: {sorted(matched)}",
                    [str(t.get("TopicArn") or "unknown")],
                )

    return PreCheckResult("MSG-009", "PASS", "no wildcard admin actions in SNS topic policies", [])


# ============================================================================
# CICD PRE-CHECKS
# ============================================================================


@_register("cicd")
def check_cicd_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """CodeBuild source credentials exist."""
    sc_doc = evidence.get("codebuild-source-credentials")
    items = sc_doc.get("items") if isinstance(sc_doc, dict) else None
    if not isinstance(items, list) or len(items) == 0:
        return PreCheckResult("CICD-001", "PASS", "no CodeBuild source credentials", [])
    return PreCheckResult("CICD-001", "FAIL", f"{len(items)} source credentials found", [])


@_register("cicd")
def check_cicd_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Insecure SSL or proxy config in CodeBuild projects."""
    proj_doc = evidence.get("codebuild-projects")
    items = proj_doc.get("items") if isinstance(proj_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("CICD-002", "SKIP", "no codebuild-projects evidence", [])

    for p in items:
        if not isinstance(p, dict):
            continue
        source = p.get("source") or {}
        if isinstance(source, dict) and source.get("insecureSsl") is True:
            return PreCheckResult(
                "CICD-002",
                "FAIL",
                "project has insecureSsl=true",
                [p.get("arn", p.get("name", "unknown"))],
            )
        env = p.get("environment") or {}
        if isinstance(env, dict):
            evs = env.get("environmentVariables")
            if isinstance(evs, list):
                for ev in evs:
                    if isinstance(ev, dict) and ev.get("looks_like_proxy") is True:
                        return PreCheckResult(
                            "CICD-002",
                            "FAIL",
                            "project has proxy-like env vars",
                            [p.get("arn", p.get("name", "unknown"))],
                        )

    return PreCheckResult("CICD-002", "PASS", "no insecure SSL/proxy config", [])


# ============================================================================
# COMPUTE PRE-CHECKS
# ============================================================================


@_register("compute")
def check_comp_eks_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """EKS public endpoint access."""
    eks_doc = evidence.get("eks-inventory")
    clusters = eks_doc.get("clusters") if isinstance(eks_doc, dict) else None
    if not isinstance(clusters, list) or not clusters:
        return PreCheckResult("COMP-EKS-001", "SKIP", "no eks-inventory evidence", [])

    for c in clusters:
        if not isinstance(c, dict):
            continue
        vpc_cfg = c.get("resourcesVpcConfig")
        if isinstance(vpc_cfg, dict) and vpc_cfg.get("endpointPublicAccess") is True:
            return PreCheckResult(
                "COMP-EKS-001",
                "FAIL",
                f"cluster {c.get('name')} has public endpoint",
                [c.get("arn", c.get("name", "unknown"))],
            )

    return PreCheckResult("COMP-EKS-001", "PASS", "no EKS clusters with public endpoint", [])


@_register("compute")
def check_comp_eks_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """EKS control plane logging should be fully enabled."""
    eks_doc = evidence.get("eks-inventory")
    clusters = eks_doc.get("clusters") if isinstance(eks_doc, dict) else None
    if not isinstance(clusters, list) or not clusters:
        return PreCheckResult("COMP-EKS-002", "SKIP", "no eks-inventory evidence", [])

    required = {"api", "audit", "authenticator", "controllerManager", "scheduler"}

    for c in clusters:
        if not isinstance(c, dict):
            continue
        logging_cfg = c.get("logging")
        if not isinstance(logging_cfg, dict):
            return PreCheckResult(
                "COMP-EKS-002",
                "FAIL",
                f"cluster {c.get('name')} has no logging config",
                [c.get("arn", c.get("name", "unknown"))],
            )
        cl = logging_cfg.get("clusterLogging")
        if not isinstance(cl, list):
            return PreCheckResult(
                "COMP-EKS-002",
                "FAIL",
                "missing clusterLogging",
                [c.get("arn", c.get("name", "unknown"))],
            )
        enabled_types = set()
        for entry in cl:
            if isinstance(entry, dict) and entry.get("enabled") is True:
                types = entry.get("types")
                if isinstance(types, list):
                    enabled_types.update(t for t in types if isinstance(t, str))
        if not required.issubset(enabled_types):
            missing = required - enabled_types
            return PreCheckResult(
                "COMP-EKS-002",
                "FAIL",
                f"cluster {c.get('name')} missing log types: {missing}",
                [c.get("arn", c.get("name", "unknown"))],
            )

    return PreCheckResult("COMP-EKS-002", "PASS", "all EKS clusters have full logging", [])


@_register("compute")
def check_comp_ecs_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Scheduled EventBridge rules targeting ECS RunTask."""
    ev_doc = evidence.get("eventbridge-rules")
    rules = ev_doc.get("rules") if isinstance(ev_doc, dict) else None
    if not isinstance(rules, list) or not rules:
        return PreCheckResult("COMP-ECS-001", "SKIP", "no eventbridge-rules evidence", [])

    for r in rules:
        if not isinstance(r, dict) or not r.get("ScheduleExpression"):
            continue
        targets = r.get("Targets")
        if not isinstance(targets, list):
            continue
        for t in targets:
            if not isinstance(t, dict):
                continue
            if t.get("EcsParameters"):
                return PreCheckResult(
                    "COMP-ECS-001",
                    "FAIL",
                    "scheduled ECS RunTask rule found",
                    [r.get("Arn", r.get("Name", "unknown"))],
                )
            arn = str(t.get("Arn") or "")
            if ":ecs:" in arn:
                return PreCheckResult(
                    "COMP-ECS-001",
                    "FAIL",
                    "scheduled ECS target found",
                    [r.get("Arn", r.get("Name", "unknown"))],
                )

    return PreCheckResult("COMP-ECS-001", "PASS", "no scheduled ECS rules", [])


@_register("compute")
def check_comp_ecs_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS task definitions with suspicious image patterns."""
    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-002", "SKIP", "no ecs-inventory evidence", [])

    def _suspicious(img: str) -> bool:
        img_l = img.lower()
        if "@sha256:" in img_l:
            return False
        if img_l.endswith(":latest") or ":latest" in img_l:
            return True
        for reg in ("docker.io/", "ghcr.io/", "quay.io/"):
            if reg in img_l:
                return True
        return False

    affected_arns: List[str] = []
    affected_images: List[str] = []
    for td in tdefs:
        if not isinstance(td, dict):
            continue
        cds = td.get("containerDefinitions")
        if not isinstance(cds, list):
            continue
        arn = td.get("taskDefinitionArn", "unknown")
        for cd in cds:
            if (
                isinstance(cd, dict)
                and isinstance(cd.get("image"), str)
                and _suspicious(cd["image"])
            ):
                if arn not in affected_arns:
                    affected_arns.append(arn)
                if cd["image"] not in affected_images:
                    affected_images.append(cd["image"])
                break  # one hit per task definition is enough

    if not affected_arns:
        return PreCheckResult("COMP-ECS-002", "PASS", "no suspicious container images", [])

    images_str = ", ".join(affected_images[:5])
    return PreCheckResult(
        "COMP-ECS-002",
        "FAIL",
        f"{len(affected_arns)} task definition(s) with suspicious images: {images_str}",
        affected_arns[:10],
    )


@_register("compute")
def check_comp_ecs_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS workloads should have centralized logging (awslogs)."""
    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-003", "SKIP", "no ecs-inventory evidence", [])

    for td in tdefs:
        if not isinstance(td, dict):
            continue
        cds = td.get("containerDefinitions")
        if not isinstance(cds, list):
            continue
        for cd in cds:
            if not isinstance(cd, dict):
                continue
            log_cfg = cd.get("logConfiguration")
            if not isinstance(log_cfg, dict):
                return PreCheckResult(
                    "COMP-ECS-003",
                    "FAIL",
                    "container missing logConfiguration",
                    [td.get("taskDefinitionArn", "unknown")],
                )
            if str(log_cfg.get("logDriver") or "").lower() != "awslogs":
                return PreCheckResult(
                    "COMP-ECS-003",
                    "FAIL",
                    f"container has logDriver={log_cfg.get('logDriver')} (not awslogs)",
                    [td.get("taskDefinitionArn", "unknown")],
                )

    return PreCheckResult("COMP-ECS-003", "PASS", "all containers have awslogs", [])


@_register("compute")
def check_comp_ecs_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS task definitions without a scoped task role (no taskRoleArn)."""
    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-004", "SKIP", "no ecs-inventory evidence", [])

    affected: List[str] = []
    seen: set = set()
    for td in tdefs:
        if not isinstance(td, dict):
            continue
        arn = td.get("taskDefinitionArn", "unknown")
        if arn in seen:
            continue
        seen.add(arn)
        if not td.get("taskRoleArn"):
            affected.append(arn)

    if not affected:
        return PreCheckResult(
            "COMP-ECS-004", "PASS", "all task definitions have a scoped task role", []
        )
    return PreCheckResult(
        "COMP-ECS-004",
        "FAIL",
        f"{len(affected)} task definition(s) without taskRoleArn (no scoped task identity)",
        affected[:10],
    )


@_register("compute")
def check_comp_ecs_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS task definitions must not embed plaintext credentials in environment variables."""
    import re as _re

    ecs_doc = evidence.get("ecs-inventory")
    tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
    if not isinstance(tdefs, list) or not tdefs:
        return PreCheckResult("COMP-ECS-005", "SKIP", "no ecs-inventory evidence", [])

    _secret_keywords = _re.compile(
        r"(pass(word)?|secret|api[_\-]?key|token|credential|private[_\-]?key|auth)",
        _re.IGNORECASE,
    )

    affected: List[str] = []
    seen: set = set()
    for td in tdefs:
        if not isinstance(td, dict):
            continue
        arn = td.get("taskDefinitionArn", "unknown")
        if arn in seen:
            continue
        cds = td.get("containerDefinitions")
        if not isinstance(cds, list):
            continue
        for cd in cds:
            if not isinstance(cd, dict):
                continue
            env_vars = cd.get("environment")
            if not isinstance(env_vars, list):
                continue
            for env in env_vars:
                if not isinstance(env, dict):
                    continue
                name = str(env.get("name") or "")
                value = str(env.get("value") or "")
                if _secret_keywords.search(name) and len(value) > 4:
                    affected.append(arn)
                    seen.add(arn)
                    break  # one hit per task definition is enough

    if not affected:
        return PreCheckResult(
            "COMP-ECS-005", "PASS", "no plaintext credentials detected in env vars", []
        )
    return PreCheckResult(
        "COMP-ECS-005",
        "FAIL",
        f"{len(affected)} task definition(s) with suspected plaintext credentials in env vars",
        affected[:10],
    )


@_register("compute")
def check_comp_ec2_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 instances with IMDSv1/optional tokens and instance profile attached."""
    ec2_doc = evidence.get("ec2-inventory")
    instances = ec2_doc.get("instances") if isinstance(ec2_doc, dict) else None
    if not isinstance(instances, list) or not instances:
        return PreCheckResult("COMP-EC2-001", "SKIP", "no ec2-inventory evidence", [])

    affected = []
    for it in instances:
        if not isinstance(it, dict):
            continue
        profile = it.get("IamInstanceProfile")
        if not isinstance(profile, dict) or not profile:
            continue
        md = it.get("MetadataOptions")
        md = md if isinstance(md, dict) else {}
        if str(md.get("HttpTokens") or "optional").lower() != "required":
            iid = str(it.get("InstanceId") or "unknown")
            affected.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not affected:
        return PreCheckResult("COMP-EC2-001", "PASS", "no IMDSv1+instance-profile combinations", [])
    return PreCheckResult(
        "COMP-EC2-001",
        "FAIL",
        f"{len(affected)} instances with IMDSv1/optional tokens and instance profile",
        affected[:10],
    )


@_register("compute")
def check_comp_ec2_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 user-data contains secrets or remote bootstrap risk patterns."""
    ec2_doc = evidence.get("ec2-inventory")
    instances = ec2_doc.get("instances") if isinstance(ec2_doc, dict) else None
    if not isinstance(instances, list) or not instances:
        return PreCheckResult("COMP-EC2-002", "SKIP", "no ec2-inventory evidence", [])

    affected = []
    for it in instances:
        if not isinstance(it, dict):
            continue
        contains = it.get("ContainsSecrets")
        has_secrets = isinstance(contains, dict) and any(bool(v) for v in contains.values())
        has_remote = bool(it.get("HasRemoteBootstrap"))
        if has_secrets or has_remote:
            iid = str(it.get("InstanceId") or "unknown")
            affected.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if not affected:
        return PreCheckResult("COMP-EC2-002", "PASS", "no risky user-data patterns", [])
    return PreCheckResult(
        "COMP-EC2-002",
        "FAIL",
        f"{len(affected)} instances with risky user-data patterns",
        affected[:10],
    )


@_register("compute")
def check_comp_lmb_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda function URLs should not be unauthenticated."""
    lmb_doc = evidence.get("lambda-inventory")
    funcs = lmb_doc.get("functions") if isinstance(lmb_doc, dict) else None
    if not isinstance(funcs, list) or not funcs:
        return PreCheckResult("COMP-LMB-001", "SKIP", "no lambda-inventory evidence", [])

    exposed = []
    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        if str(fn.get("AuthType") or "").upper() == "NONE" and fn.get("FunctionUrl"):
            exposed.append(str(fn.get("FunctionArn") or fn.get("FunctionName") or "unknown"))

    if not exposed:
        return PreCheckResult("COMP-LMB-001", "PASS", "no unauthenticated Lambda function URLs", [])
    return PreCheckResult(
        "COMP-LMB-001",
        "FAIL",
        f"{len(exposed)} Lambda functions with AuthType=NONE",
        exposed[:10],
    )


@_register("compute")
def check_comp_lmb_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda execution roles should avoid obviously over-privileged managed policies."""
    lmb_doc = evidence.get("lambda-inventory")
    funcs = lmb_doc.get("functions") if isinstance(lmb_doc, dict) else None
    if not isinstance(funcs, list) or not funcs:
        return PreCheckResult("COMP-LMB-002", "SKIP", "no lambda-inventory evidence", [])

    risky_tokens = ["administratoraccess", "admin", "poweruser", "fullaccess"]
    affected = []
    for fn in funcs:
        if not isinstance(fn, dict):
            continue
        attached = fn.get("AttachedPolicies")
        if not isinstance(attached, list):
            continue
        for p in attached:
            if not isinstance(p, dict):
                continue
            name = str(p.get("PolicyName") or "").lower()
            if any(tok in name for tok in risky_tokens):
                affected.append(str(fn.get("FunctionArn") or fn.get("FunctionName") or "unknown"))
                break

    if not affected:
        return PreCheckResult(
            "COMP-LMB-002", "PASS", "no over-privileged Lambda execution roles", []
        )
    return PreCheckResult(
        "COMP-LMB-002",
        "FAIL",
        f"{len(affected)} Lambda functions with over-privileged execution roles",
        affected[:10],
    )


# ============================================================================
# RECON PRE-CHECKS
# ============================================================================


@_register("recon")
def check_recon_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-001: DNS wildcard records exposing internal services."""
    route53 = evidence.get("route53-zones")
    if not isinstance(route53, dict):
        return PreCheckResult("RECON-001", "SKIP", "no route53-zones evidence", [])

    wildcard_count = int(route53.get("wildcard_record_count", 0) or 0)
    if wildcard_count == 0:
        return PreCheckResult("RECON-001", "PASS", "no DNS wildcard records found", [])

    # Collect wildcard record names
    wildcards = []
    for zone in route53.get("zones", []):
        if not isinstance(zone, dict):
            continue
        for rec in zone.get("Records", []):
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("Name", ""))
            if name.startswith("*."):
                wildcards.append(f"{name} ({rec.get('Type', '?')}) in {zone.get('Name', '?')}")

    return PreCheckResult(
        "RECON-001",
        "FAIL",
        f"{wildcard_count} DNS wildcard records expose internal service naming",
        wildcards[:10],
    )


@_register("recon")
def check_recon_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-002: API Gateway stages without authentication in production."""
    apigw = evidence.get("api-gateway-stages")
    if not isinstance(apigw, dict):
        return PreCheckResult("RECON-002", "SKIP", "no api-gateway-stages evidence", [])

    total_apis = int(apigw.get("total_apis", 0) or 0)
    if total_apis == 0:
        return PreCheckResult("RECON-002", "SKIP", "no API Gateway APIs configured", [])

    unauth_stages = int(apigw.get("unauthenticated_stages", 0) or 0)
    if unauth_stages == 0:
        return PreCheckResult("RECON-002", "PASS", "all API Gateway stages have authentication", [])

    # Collect unauthenticated stage/route identifiers for the finding
    unauth_urls = []
    for api in apigw.get("apis", []):
        if not isinstance(api, dict):
            continue
        api_type = api.get("Type", "")
        if api_type == "REST":
            # REST APIs: use pre-collected UnauthenticatedRoutes (non-OPTIONS methods)
            for route in api.get("UnauthenticatedRoutes", []):
                unauth_urls.append(str(route))
        else:
            # HTTP APIs (v2): auth is at stage/route level
            for stage in api.get("Stages", []):
                if not isinstance(stage, dict):
                    continue
                auth = stage.get("DefaultRouteAuthorizationType")
                if auth in {"NONE", None}:
                    url = (
                        stage.get("InvokeURL")
                        or f"{api.get('Id', '?')}:{stage.get('StageName', '?')}"
                    )
                    unauth_urls.append(url)

    # Build human-readable summary
    rest_unauth = sum(
        int(a.get("UnauthenticatedRouteCount", 0) or 0)
        for a in apigw.get("apis", [])
        if isinstance(a, dict) and a.get("Type") == "REST"
    )
    http_unauth = unauth_stages - sum(
        1
        for a in apigw.get("apis", [])
        if isinstance(a, dict)
        and a.get("Type") == "REST"
        and int(a.get("UnauthenticatedRouteCount", 0) or 0) > 0
    )
    parts = []
    if rest_unauth > 0:
        parts.append(f"{rest_unauth} REST API route(s) without auth")
    if http_unauth > 0:
        parts.append(f"{http_unauth} HTTP API stage(s) without auth")
    summary = (
        "; ".join(parts)
        if parts
        else f"{unauth_stages} API Gateway stage(s) without authentication"
    )

    return PreCheckResult(
        "RECON-002",
        "FAIL",
        summary,
        unauth_urls[:10],
    )


@_register("recon")
def check_recon_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-003: Elastic IPs assigned to instances (public IP inventory)."""
    public_eps = evidence.get("public-endpoints")
    if not isinstance(public_eps, dict):
        return PreCheckResult("RECON-003", "SKIP", "no public-endpoints evidence", [])

    eip_count = int(public_eps.get("elastic_ip_count", 0) or 0)
    if eip_count == 0:
        return PreCheckResult("RECON-003", "PASS", "no Elastic IPs allocated", [])

    # Collect EIPs attached to instances (those are the risky ones)
    instance_eips = [
        str(eip.get("PublicIp", ""))
        for eip in public_eps.get("elastic_ips", [])
        if isinstance(eip, dict) and eip.get("AssociatedWithInstance")
    ]

    if not instance_eips:
        return PreCheckResult(
            "RECON-003", "PASS", f"{eip_count} EIP(s) allocated but none attached to instances", []
        )

    # Build enriched evidence snippet with SG rules chain
    enriched_eips = []
    for eip in public_eps.get("elastic_ips", []):
        if isinstance(eip, dict) and eip.get("AssociatedWithInstance"):
            enriched_eips.append(
                {
                    "PublicIp": eip.get("PublicIp"),
                    "InstanceId": eip.get("InstanceId"),
                    "InstanceName": eip.get("InstanceName", "unknown"),
                    "PermissiveSGRules": eip.get("PermissiveSGRules", []),
                }
            )

    return PreCheckResult(
        "RECON-003",
        "FAIL",
        f"{len(instance_eips)}/{eip_count} Elastic IPs attached to EC2 instances (public IPs)",
        instance_eips[:10],
        metadata={"elastic_ips_with_sg_rules": enriched_eips[:5]},  # max 5 for readability
    )


@_register("recon")
def check_recon_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-005: Lambda Function URLs publicly accessible without authentication."""
    lambda_urls = evidence.get("lambda-urls")
    if not isinstance(lambda_urls, dict):
        return PreCheckResult("RECON-005", "SKIP", "no lambda-urls evidence", [])

    total = int(lambda_urls.get("total_function_urls", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-005", "SKIP", "no Lambda Function URLs configured", [])

    public = int(lambda_urls.get("public_function_urls", 0) or 0)
    if public == 0:
        return PreCheckResult(
            "RECON-005", "PASS", f"all {total} Lambda Function URLs require authentication", []
        )

    public_fn_urls = [
        str(u.get("FunctionUrl") or u.get("FunctionName", "unknown"))
        for u in lambda_urls.get("urls", [])
        if isinstance(u, dict) and u.get("IsPublic")
    ]

    return PreCheckResult(
        "RECON-005",
        "FAIL",
        f"{public}/{total} Lambda Function URLs are publicly accessible (AuthType=NONE)",
        public_fn_urls[:10],
    )


@_register("recon")
def check_recon_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-007: Internet-facing Load Balancers without WAF."""
    lb_data = evidence.get("load-balancer-dns")
    if not isinstance(lb_data, dict):
        return PreCheckResult("RECON-007", "SKIP", "no load-balancer-dns evidence", [])

    total_lbs = int(lb_data.get("total_load_balancers", 0) or 0)
    if total_lbs == 0:
        return PreCheckResult("RECON-007", "SKIP", "no load balancers configured", [])

    public_lbs = int(lb_data.get("public_load_balancers", 0) or 0)
    if public_lbs == 0:
        return PreCheckResult("RECON-007", "PASS", "no internet-facing load balancers", [])

    no_waf = int(lb_data.get("public_without_waf", 0) or 0)
    if no_waf == 0:
        return PreCheckResult(
            "RECON-007", "PASS", "all internet-facing load balancers have WAF attached", []
        )

    no_waf_dns = [
        str(lb.get("DNSName") or lb.get("Name", "unknown"))
        for lb in lb_data.get("load_balancers", [])
        if isinstance(lb, dict) and lb.get("IsPublic") and not lb.get("WafWebAclArn")
    ]

    return PreCheckResult(
        "RECON-007",
        "FAIL",
        f"{no_waf}/{public_lbs} internet-facing load balancers without WAF",
        no_waf_dns[:10],
    )


@_register("recon")
def check_recon_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-011: HTTP (non-HTTPS) listeners on public Load Balancers."""
    lb_data = evidence.get("load-balancer-dns")
    if not isinstance(lb_data, dict):
        return PreCheckResult("RECON-011", "SKIP", "no load-balancer-dns evidence", [])

    if int(lb_data.get("public_load_balancers", 0) or 0) == 0:
        return PreCheckResult("RECON-011", "SKIP", "no internet-facing load balancers", [])

    http_only_lbs = []
    for lb in lb_data.get("load_balancers", []):
        if not isinstance(lb, dict) or not lb.get("IsPublic"):
            continue
        # Only ALBs have HTTP protocol (NLBs use TCP)
        if lb.get("Type") != "application":
            continue
        has_https = False
        has_http = False
        for lst in lb.get("Listeners", []):
            if not isinstance(lst, dict):
                continue
            proto = str(lst.get("Protocol", "")).upper()
            if proto == "HTTPS":
                has_https = True
            elif proto == "HTTP":
                has_http = True
        # Flag if HTTP listener exists but no HTTPS (no redirect)
        if has_http and not has_https:
            http_only_lbs.append(str(lb.get("DNSName") or lb.get("Name", "unknown")))

    if not http_only_lbs:
        return PreCheckResult(
            "RECON-011", "PASS", "no internet-facing ALBs with HTTP-only listeners", []
        )
    return PreCheckResult(
        "RECON-011",
        "FAIL",
        f"{len(http_only_lbs)} internet-facing ALB(s) with HTTP listeners and no HTTPS",
        http_only_lbs[:10],
    )


@_register("recon")
def check_recon_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-015: Attack surface score is HIGH or CRITICAL."""
    score_doc = evidence.get("attack-surface-score")
    if not isinstance(score_doc, dict):
        return PreCheckResult("RECON-015", "SKIP", "no attack-surface-score evidence", [])

    score = float(score_doc.get("score", 0.0) or 0.0)
    rating = str(score_doc.get("rating", "LOW"))

    if score < 5.0:
        return PreCheckResult(
            "RECON-015",
            "PASS",
            f"attack surface score {score:.1f}/10 ({rating}) — within acceptable range",
            [],
        )

    # Collect contributing factors as resources
    factors = [
        f"{f.get('factor', '?')}: {f.get('count', 0)} ({f.get('contribution', 0.0):.1f} pts)"
        for f in score_doc.get("factors", [])
        if isinstance(f, dict)
    ]

    return PreCheckResult(
        "RECON-015",
        "FAIL",
        f"attack surface score {score:.1f}/10 ({rating}) — broad external exposure",
        factors[:10],
    )


@_register("recon")
def check_recon_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-006: CloudFront distributions without logging enabled."""
    cf = evidence.get("cloudfront-origins")
    if not isinstance(cf, dict):
        return PreCheckResult("RECON-006", "SKIP", "no cloudfront-origins evidence", [])

    total = int(cf.get("total_distributions", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-006", "SKIP", "no CloudFront distributions", [])

    no_log = int(cf.get("distributions_without_logging", 0) or 0)
    if no_log == 0:
        return PreCheckResult(
            "RECON-006", "PASS", "all CloudFront distributions have logging enabled", []
        )

    no_log_ids = [
        str(d.get("DomainName") or d.get("Id", "unknown"))
        for d in cf.get("distributions", [])
        if isinstance(d, dict) and not d.get("LoggingEnabled")
    ]

    return PreCheckResult(
        "RECON-006",
        "FAIL",
        f"{no_log}/{total} CloudFront distributions without access logging",
        no_log_ids[:10],
    )


@_register("recon")
def check_recon_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-008: Large external attack surface (many entry points)."""
    score_doc = evidence.get("attack-surface-score")
    if not isinstance(score_doc, dict):
        return PreCheckResult("RECON-008", "SKIP", "no attack-surface-score evidence", [])

    total_apis = int(score_doc.get("total_public_apis", 0) or 0)
    lbs = int(score_doc.get("public_load_balancers", 0) or 0)
    lambdas = int(score_doc.get("public_lambda_urls", 0) or 0)
    eips = int(score_doc.get("elastic_ips", 0) or 0)
    cf = int(score_doc.get("cloudfront_distributions", 0) or 0)
    total_entry_points = total_apis + lbs + lambdas + eips + cf

    if total_entry_points > 10:
        return PreCheckResult(
            "RECON-008",
            "FAIL",
            f"{total_entry_points} internet-facing entry points detected (APIs={total_apis}, LBs={lbs}, Lambda={lambdas}, EIPs={eips}, CF={cf})",
            [],
        )
    return PreCheckResult(
        "RECON-008",
        "PASS",
        f"{total_entry_points} entry points — within acceptable threshold (≤10)",
        [],
    )


@_register("recon")
def check_recon_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-009: REST API Gateway stages without access logging."""
    apigw = evidence.get("api-gateway-stages")
    if not isinstance(apigw, dict):
        return PreCheckResult("RECON-009", "SKIP", "no api-gateway-stages evidence", [])

    total_apis = int(apigw.get("total_apis", 0) or 0)
    if total_apis == 0:
        return PreCheckResult("RECON-009", "SKIP", "no API Gateway APIs configured", [])

    no_log_stages = []
    for api in apigw.get("apis", []):
        if not isinstance(api, dict):
            continue
        for stage in api.get("Stages", []):
            if not isinstance(stage, dict):
                continue
            if not stage.get("AccessLogEnabled"):
                url = (
                    stage.get("InvokeURL") or f"{api.get('Id', '?')}:{stage.get('StageName', '?')}"
                )
                no_log_stages.append(url)

    if not no_log_stages:
        return PreCheckResult(
            "RECON-009", "PASS", "all API Gateway stages have access logging enabled", []
        )

    return PreCheckResult(
        "RECON-009",
        "FAIL",
        f"{len(no_log_stages)} API Gateway stage(s) without access logging",
        no_log_stages[:10],
    )


@_register("recon")
def check_recon_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-010: NAT Gateway IPs add to public IP inventory."""
    public_eps = evidence.get("public-endpoints")
    if not isinstance(public_eps, dict):
        return PreCheckResult("RECON-010", "SKIP", "no public-endpoints evidence", [])

    nat_count = int(public_eps.get("nat_gateway_ip_count", 0) or 0)
    if nat_count == 0:
        return PreCheckResult("RECON-010", "PASS", "no NAT Gateway IPs detected", [])

    nat_ips = [
        str(gw.get("PublicIp", ""))
        for gw in public_eps.get("nat_gateway_ips", [])
        if isinstance(gw, dict)
    ]

    return PreCheckResult(
        "RECON-010",
        "FAIL",
        f"{nat_count} NAT Gateway public IP(s) — document and whitelist at third-party vendors",
        nat_ips[:10],
    )


@_register("recon")
def check_recon_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-012: CloudFront distributions without WAF."""
    cf = evidence.get("cloudfront-origins")
    if not isinstance(cf, dict):
        return PreCheckResult("RECON-012", "SKIP", "no cloudfront-origins evidence", [])

    total = int(cf.get("total_distributions", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-012", "SKIP", "no CloudFront distributions", [])

    no_waf = [
        str(d.get("DomainName") or d.get("Id", "unknown"))
        for d in cf.get("distributions", [])
        if isinstance(d, dict) and not d.get("WebAclId")
    ]

    if not no_waf:
        return PreCheckResult(
            "RECON-012", "PASS", "all CloudFront distributions have WAF associated", []
        )

    return PreCheckResult(
        "RECON-012",
        "FAIL",
        f"{len(no_waf)}/{total} CloudFront distributions without WAF",
        no_waf[:10],
    )


@_register("recon")
def check_recon_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-013: Public Route53 zone count exceeds threshold (broad DNS footprint)."""
    r53 = evidence.get("route53-zones")
    if not isinstance(r53, dict):
        return PreCheckResult("RECON-013", "SKIP", "no route53-zones evidence", [])

    public_zones = int(r53.get("public_zones", 0) or 0)
    if public_zones > 5:
        zone_names = [
            z.get("Name", "unknown")
            for z in r53.get("zones", [])
            if isinstance(z, dict) and not z.get("IsPrivate")
        ]
        return PreCheckResult(
            "RECON-013",
            "FAIL",
            f"{public_zones} public hosted zones — broad DNS footprint (threshold: 5)",
            zone_names[:10],
        )
    return PreCheckResult(
        "RECON-013",
        "PASS",
        f"{public_zones} public hosted zones — within acceptable threshold (≤5)",
        [],
    )


@_register("recon")
def check_recon_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-014: API Gateway has more than 5 unauthenticated endpoints."""
    apigw = evidence.get("api-gateway-stages")
    if not isinstance(apigw, dict):
        return PreCheckResult("RECON-014", "SKIP", "no api-gateway-stages evidence", [])

    unauth = int(apigw.get("unauthenticated_stages", 0) or 0)
    if unauth > 5:
        return PreCheckResult(
            "RECON-014",
            "FAIL",
            f"{unauth} API Gateway stages without authentication (threshold: 5)",
            [],
        )
    return PreCheckResult(
        "RECON-014",
        "PASS",
        f"{unauth} unauthenticated API Gateway stages — within threshold (≤5)",
        [],
    )


@_register("recon")
def check_recon_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-016: Unassociated Elastic IPs (not attached to any instance or NAT Gateway)."""
    public_eps = evidence.get("public-endpoints")
    if not isinstance(public_eps, dict):
        return PreCheckResult("RECON-016", "SKIP", "no public-endpoints evidence", [])

    eips = public_eps.get("elastic_ips", [])
    if not eips:
        return PreCheckResult("RECON-016", "PASS", "no Elastic IPs allocated", [])

    # Build set of NAT GW IPs — those are "associated" even if not attached to an EC2 instance
    nat_gw_ips = {
        str(gw.get("PublicIp", ""))
        for gw in public_eps.get("nat_gateway_ips", [])
        if isinstance(gw, dict)
    }

    # Truly unassociated: not attached to instance AND no ENI (NAT GW EIPs have an ENI)
    truly_unused = [
        str(eip.get("PublicIp", ""))
        for eip in eips
        if isinstance(eip, dict)
        and not eip.get("AssociatedWithInstance")
        and not eip.get("NetworkInterfaceId")  # NAT GW EIPs always have an ENI
        and str(eip.get("PublicIp", "")) not in nat_gw_ips
    ]

    if not truly_unused:
        return PreCheckResult(
            "RECON-016",
            "PASS",
            f"{len(eips)} EIP(s) — all associated with EC2 instances or NAT Gateways",
            [],
        )

    return PreCheckResult(
        "RECON-016",
        "FAIL",
        f"{len(truly_unused)} Elastic IP(s) not attached to any instance or NAT Gateway",
        truly_unused[:10],
    )


@_register("recon")
def check_recon_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-017: Load Balancer exposes non-standard high-risk ports."""
    lb_data = evidence.get("load-balancer-dns")
    if not isinstance(lb_data, dict):
        return PreCheckResult("RECON-017", "SKIP", "no load-balancer-dns evidence", [])

    public_lbs = int(lb_data.get("public_load_balancers", 0) or 0)
    if public_lbs == 0:
        return PreCheckResult("RECON-017", "SKIP", "no internet-facing load balancers", [])

    high_risk_ports = {3306, 5432, 27017, 1521, 8443, 8080}
    risky = []
    for lb in lb_data.get("load_balancers", []):
        if not isinstance(lb, dict) or not lb.get("IsPublic"):
            continue
        for listener in lb.get("Listeners", []):
            if not isinstance(listener, dict):
                continue
            port = int(listener.get("Port", 0) or 0)
            if port in high_risk_ports:
                risky.append(f"{lb.get('DNSName', '?')}:{port}")

    if risky:
        return PreCheckResult(
            "RECON-017",
            "FAIL",
            f"{len(risky)} high-risk port(s) exposed on internet-facing LBs",
            risky[:10],
        )
    return PreCheckResult(
        "RECON-017",
        "PASS",
        "no high-risk ports exposed on internet-facing load balancers",
        [],
    )


@_register("recon")
def check_recon_018(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-018: Lambda Function URLs with CORS allowing all origins."""
    lambda_urls = evidence.get("lambda-urls")
    if not isinstance(lambda_urls, dict):
        return PreCheckResult("RECON-018", "SKIP", "no lambda-urls evidence", [])

    total = int(lambda_urls.get("total_function_urls", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-018", "SKIP", "no Lambda Function URLs configured", [])

    wildcard_cors = [
        str(u.get("FunctionUrl", u.get("FunctionName", "unknown")))
        for u in lambda_urls.get("urls", [])
        if isinstance(u, dict) and "*" in (u.get("Cors") or {}).get("AllowOrigins", [])
    ]

    if wildcard_cors:
        return PreCheckResult(
            "RECON-018",
            "FAIL",
            f"{len(wildcard_cors)} Lambda Function URL(s) with CORS AllowOrigins=['*']",
            wildcard_cors[:10],
        )
    return PreCheckResult(
        "RECON-018",
        "PASS",
        "no Lambda Function URLs with wildcard CORS origins",
        [],
    )


@_register("recon")
def check_recon_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-004: Route53 public zones with records revealing internal architecture."""
    r53 = evidence.get("route53-zones")
    if not isinstance(r53, dict):
        return PreCheckResult("RECON-004", "SKIP", "no route53-zones evidence", [])

    public_zones = int(r53.get("public_zones", 0) or 0)
    if public_zones == 0:
        return PreCheckResult("RECON-004", "PASS", "no public Route53 zones", [])

    # Count DNS records in public zones — any public zone with records reveals architecture
    revealing_records = []
    for zone in r53.get("zones", []):
        if not isinstance(zone, dict) or zone.get("IsPrivate"):
            continue
        zone_name = zone.get("Name", "?")
        for rec in zone.get("Records", []):
            if not isinstance(rec, dict):
                continue
            rec_type = str(rec.get("Type", ""))
            rec_name = str(rec.get("Name", ""))
            # A, AAAA, CNAME, MX records in public zones reveal service endpoints
            if rec_type in {"A", "AAAA", "CNAME", "MX"}:
                revealing_records.append(f"{rec_name} ({rec_type}) in {zone_name}")

    if revealing_records:
        # Build enriched snippet with zone details and sensitivity analysis
        enriched_zones = []
        for zone in r53.get("zones", []):
            if not isinstance(zone, dict) or zone.get("IsPrivate"):
                continue
            enriched_zones.append(
                {
                    "HostedZoneId": zone.get("Id"),
                    "ZoneName": zone.get("Name"),
                    "IsPrivate": zone.get("IsPrivate", False),
                    "RecordCount": zone.get("RecordCount", 0),
                    "SensitivityAnalysis": zone.get("SensitivityAnalysis", {}),
                    "ExposedRecords": [
                        {"Name": r["Name"], "Type": r["Type"]} for r in zone.get("Records", [])[:5]
                    ],
                }
            )

        return PreCheckResult(
            "RECON-004",
            "FAIL",
            f"{len(revealing_records)} DNS record(s) in public zones reveal service endpoints",
            revealing_records[:10],
            metadata={"public_dns_zones": enriched_zones[:5]},
        )

    return PreCheckResult(
        "RECON-004",
        "PASS",
        f"{public_zones} public zone(s) present but no revealing A/AAAA/CNAME/MX records found",
        [],
    )


@_register("recon")
def check_recon_019(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-019: Public DNS zones with sensitive keywords expose architecture."""
    r53 = evidence.get("route53-zones")
    if not isinstance(r53, dict):
        return PreCheckResult("RECON-019", "SKIP", "no route53-zones evidence", [])

    critical_zones = []
    for zone in r53.get("zones", []):
        if not isinstance(zone, dict) or zone.get("IsPrivate"):
            continue
        analysis = zone.get("SensitivityAnalysis", {})
        if analysis.get("SeverityBump") in ("critical", "high"):
            critical_zones.append(
                {
                    "ZoneName": zone.get("Name"),
                    "Keywords": analysis.get("SensitiveKeywords"),
                    "GeoPatterns": analysis.get("GeoEnvPatterns"),
                    "IsPrivate": False,
                }
            )

    if critical_zones:
        return PreCheckResult(
            "RECON-019",
            "FAIL",
            f"{len(critical_zones)} public DNS zone(s) with sensitive keywords (pci/admin/internal/prod/dev)",
            [z["ZoneName"] for z in critical_zones][:10],
            metadata={"sensitive_public_zones": critical_zones[:5]},
        )

    return PreCheckResult(
        "RECON-019",
        "PASS",
        "no public zones with sensitive keywords detected",
        [],
    )


@_register("recon")
def check_recon_020(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-020: No public entry points detected (minimal attack surface)."""
    score_doc = evidence.get("attack-surface-score")
    if not isinstance(score_doc, dict):
        return PreCheckResult("RECON-020", "SKIP", "no attack-surface-score evidence", [])

    score = float(score_doc.get("score", 0.0) or 0.0)
    rating = str(score_doc.get("rating", ""))
    total_apis = int(score_doc.get("total_public_apis", 0) or 0)
    public_lbs = int(score_doc.get("public_load_balancers", 0) or 0)
    public_lambdas = int(score_doc.get("public_lambda_urls", 0) or 0)
    unauth_stages = int(score_doc.get("unauthenticated_api_stages", 0) or 0)

    # LOW rating with no unauthenticated entry points = PASS (minimal external exposure)
    if rating == "LOW" and unauth_stages == 0 and public_lbs == 0 and public_lambdas == 0:
        return PreCheckResult(
            "RECON-020",
            "PASS",
            f"attack surface score {score:.1f}/10 ({rating}) — minimal external exposure confirmed",
            [],
        )

    # If score is HIGH/CRITICAL, this check does not apply (RECON-015 handles that)
    if score >= 5.0:
        return PreCheckResult(
            "RECON-020",
            "SKIP",
            f"attack surface score {score:.1f}/10 ({rating}) — RECON-015 applies instead",
            [],
        )

    # Medium exposure — not minimal but not high either
    return PreCheckResult(
        "RECON-020",
        "PASS",
        f"attack surface score {score:.1f}/10 ({rating}) — {total_apis} API(s), {public_lbs} public LB(s), {public_lambdas} public Lambda URL(s)",
        [],
    )


# ============================================================================
# SISTEMAS EXPLOTABLES POR RED PRE-CHECKS
# ============================================================================


def _ser_engine_port(engine: str) -> int:
    eng = str(engine or "").lower()
    if "postgres" in eng:
        return 5432
    if "mysql" in eng or "mariadb" in eng:
        return 3306
    if "sqlserver" in eng:
        return 1433
    if "oracle" in eng:
        return 1521
    return 0


@_register("sistemas_explotables_red")
def check_ser_ec2_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """EC2 with SSH/RDP world-open ingress."""
    net_doc = evidence.get("network-controls", {})
    inv_doc = evidence.get("compute-inventory", {})

    if not isinstance(net_doc, dict) or not isinstance(inv_doc, dict):
        return PreCheckResult(
            "SER-EC2-001", "SKIP", "missing network-controls/compute-inventory", []
        )

    sgs = net_doc.get("security_groups", []) if isinstance(net_doc, dict) else []
    instances = inv_doc.get("ec2_instances", []) if isinstance(inv_doc, dict) else []
    if not isinstance(sgs, list) or not isinstance(instances, list):
        return PreCheckResult("SER-EC2-001", "SKIP", "invalid SG or EC2 evidence shape", [])

    risky_sg_ids = set()
    for sg in sgs:
        if not isinstance(sg, dict):
            continue
        sg_id = str(sg.get("GroupId") or "")
        if not sg_id:
            continue
        for perm in sg.get("IpPermissions", []) or []:
            if not isinstance(perm, dict):
                continue
            if _sg_allows_world(perm, port=22) or _sg_allows_world(perm, port=3389):
                risky_sg_ids.add(sg_id)
                break

    if not risky_sg_ids:
        return PreCheckResult("SER-EC2-001", "PASS", "no SSH/RDP world-open SG rules", [])

    # D3: Build subnet→route-table and vpc→main-route-table maps for IGW route verification
    route_tables = net_doc.get("route_tables", []) or []
    has_rt_info = isinstance(route_tables, list) and len(route_tables) > 0
    subnet_to_rt: Dict[str, Any] = {}
    vpc_main_rt: Dict[str, Any] = {}
    if has_rt_info:
        for rt in route_tables:
            if not isinstance(rt, dict):
                continue
            vpc_id_rt = str(rt.get("VpcId") or "")
            for assoc in rt.get("Associations", []) or []:
                if not isinstance(assoc, dict):
                    continue
                subnet_id_assoc = str(assoc.get("SubnetId") or "")
                if subnet_id_assoc:
                    subnet_to_rt[subnet_id_assoc] = rt
                if bool(assoc.get("Main")) and vpc_id_rt:
                    vpc_main_rt[vpc_id_rt] = rt

    def _has_igw_route(rt: Any) -> bool:
        if not isinstance(rt, dict):
            return False
        for route in rt.get("Routes", []) or []:
            if not isinstance(route, dict):
                continue
            gw = str(route.get("GatewayId") or "")
            state = str(route.get("State") or "").lower()
            if gw.startswith("igw-") and state == "active":
                return True
        return False

    def _instance_internet_routable(inst: Any) -> bool:
        """Return True if routing is unknown (conservative) or IGW route exists."""
        if not has_rt_info:
            return True  # no route info: conservative, assume possible
        subnet_id = str(inst.get("SubnetId") or "")
        vpc_id = str(inst.get("VpcId") or "")
        rt = subnet_to_rt.get(subnet_id) or vpc_main_rt.get(vpc_id)
        if rt is None:
            return True  # unknown routing: conservative
        return _has_igw_route(rt)

    affected: List[str] = []
    for inst in instances:
        if not isinstance(inst, dict):
            continue
        inst_sgs = inst.get("SecurityGroups", []) or []
        if not isinstance(inst_sgs, list):
            continue
        if not any(
            str(sg.get("GroupId") or "") in risky_sg_ids for sg in inst_sgs if isinstance(sg, dict)
        ):
            continue
        if not _instance_internet_routable(inst):
            continue
        iid = str(inst.get("InstanceId") or "")
        if iid:
            affected.append(f"arn:aws:ec2:*:*:instance/{iid}")

    if affected:
        return PreCheckResult(
            "SER-EC2-001",
            "FAIL",
            f"{len(affected)} EC2 instance(s) linked to SSH/RDP world-open SG with internet route",
            affected[:20],
        )

    if has_rt_info:
        return PreCheckResult(
            "SER-EC2-001",
            "PASS",
            f"{len(risky_sg_ids)} world-open SG(s) found but all attached instances are in private subnets",
            [],
        )

    return PreCheckResult(
        "SER-EC2-001",
        "FAIL",
        f"{len(risky_sg_ids)} world-open SG(s) with SSH/RDP (no EC2 attachment resolved)",
        sorted(risky_sg_ids)[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_lmb_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda Function URL with AuthType NONE."""
    front_doc = evidence.get("front-doors", {})
    if not isinstance(front_doc, dict):
        return PreCheckResult("SER-LMB-001", "SKIP", "missing front-doors evidence", [])

    urls = front_doc.get("lambda_function_urls", [])
    if not isinstance(urls, list):
        return PreCheckResult("SER-LMB-001", "SKIP", "invalid lambda_function_urls shape", [])

    unauth = [
        u for u in urls if isinstance(u, dict) and str(u.get("AuthType") or "").upper() == "NONE"
    ]
    if not unauth:
        return PreCheckResult("SER-LMB-001", "PASS", "no unauthenticated Lambda Function URLs", [])

    affected = [
        str(u.get("FunctionArn") or u.get("FunctionUrl") or "lambda-url-unknown")
        for u in unauth[:20]
    ]
    return PreCheckResult(
        "SER-LMB-001",
        "FAIL",
        f"{len(unauth)} Lambda Function URL(s) with AuthType=NONE",
        affected,
    )


@_register("sistemas_explotables_red")
def check_ser_rds_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """RDS publicly accessible and engine port world-open in SG."""
    net_doc = evidence.get("network-controls", {})
    inv_doc = evidence.get("compute-inventory", {})
    if not isinstance(net_doc, dict) or not isinstance(inv_doc, dict):
        return PreCheckResult(
            "SER-RDS-001", "SKIP", "missing network-controls/compute-inventory", []
        )

    sgs = net_doc.get("security_groups", [])
    rds_items = inv_doc.get("rds_instances", [])
    if not isinstance(sgs, list) or not isinstance(rds_items, list):
        return PreCheckResult("SER-RDS-001", "SKIP", "invalid SG or RDS evidence shape", [])

    sg_by_id = {}
    for sg in sgs:
        if isinstance(sg, dict) and isinstance(sg.get("GroupId"), str):
            sg_by_id[str(sg.get("GroupId"))] = sg

    affected: List[str] = []
    for db in rds_items:
        if not isinstance(db, dict):
            continue
        if not bool(db.get("PubliclyAccessible")):
            continue
        engine_port = _ser_engine_port(str(db.get("Engine") or ""))
        if engine_port <= 0:
            continue

        vpc_sgs = db.get("VpcSecurityGroups", []) or []
        sg_ids = [str(sg.get("VpcSecurityGroupId") or "") for sg in vpc_sgs if isinstance(sg, dict)]
        for sg_id in sg_ids:
            sg_doc = sg_by_id.get(sg_id)
            if not isinstance(sg_doc, dict):
                continue
            perms = sg_doc.get("IpPermissions", []) or []
            if any(isinstance(p, dict) and _sg_allows_world(p, port=engine_port) for p in perms):
                arn = str(db.get("DBInstanceArn") or f"rds:{db.get('DBInstanceIdentifier')}")
                affected.append(arn)
                break

    if not affected:
        return PreCheckResult(
            "SER-RDS-001", "PASS", "no public RDS with world-open engine port", []
        )

    return PreCheckResult(
        "SER-RDS-001",
        "FAIL",
        f"{len(affected)} RDS instance(s) publicly accessible with world-open DB port",
        affected[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_cor_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """Resource with combined high reachability + vulnerability + blast-radius signals."""
    paths_doc = evidence.get("attack-path-candidates", {})
    if not isinstance(paths_doc, dict):
        return PreCheckResult("SER-COR-003", "SKIP", "missing attack-path-candidates evidence", [])

    paths = paths_doc.get("paths", [])
    if not isinstance(paths, list) or not paths:
        return PreCheckResult("SER-COR-003", "SKIP", "no attack paths computed", [])

    risky = []
    for p in paths:
        if not isinstance(p, dict):
            continue
        r = float(p.get("reachability_score") or 0.0)
        v = float(p.get("vulnerability_score") or 0.0)
        b = float(p.get("blast_radius_score") or 0.0)
        o = float(p.get("overall_score") or 0.0)
        if r >= 0.8 and v >= 0.7 and b >= 0.7 and o >= 0.75:
            target = str(p.get("target_resource") or "")
            if target:
                risky.append(target)

    if not risky:
        return PreCheckResult(
            "SER-COR-003", "PASS", "no high-confidence correlated attack paths", []
        )

    return PreCheckResult(
        "SER-COR-003",
        "FAIL",
        f"{len(risky)} resource(s) with correlated exploitability signals",
        sorted(set(risky))[:20],
        confidence=0.9,
    )


@_register("sistemas_explotables_red")
def check_ser_ec2_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Internet-reachable EC2 with active Inspector findings."""
    paths_doc = evidence.get("attack-path-candidates", {})
    if not isinstance(paths_doc, dict):
        return PreCheckResult("SER-EC2-002", "SKIP", "missing attack-path-candidates evidence", [])

    paths = paths_doc.get("paths", [])
    if not isinstance(paths, list):
        return PreCheckResult("SER-EC2-002", "SKIP", "invalid attack path shape", [])

    # Build instance_id → CVE titles map from Inspector findings evidence
    inspector_doc = evidence.get("inspector-findings-normalized", {})
    instance_cves: Dict[str, List[str]] = {}
    if isinstance(inspector_doc, dict):
        for f in inspector_doc.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            title = str(f.get("title") or "")
            for r in f.get("resources", []) or []:
                if not isinstance(r, dict):
                    continue
                rid = str(r.get("id") or "")
                if not rid or r.get("type") != "AWS_EC2_INSTANCE":
                    continue
                # Normalize: strip ARN prefix if present
                iid = rid.split(":instance/")[-1] if ":instance/" in rid else rid
                instance_cves.setdefault(iid, [])
                if title and title not in instance_cves[iid]:
                    instance_cves[iid].append(title)

    affected: List[str] = []
    for path in paths:
        if not isinstance(path, dict):
            continue
        target = str(path.get("target_resource") or "")
        if ":instance/" not in target:
            continue
        signal = (
            path.get("inspector_signal", {})
            if isinstance(path.get("inspector_signal"), dict)
            else {}
        )
        crit = int(signal.get("critical", 0) or 0)
        high = int(signal.get("high", 0) or 0)
        med = int(signal.get("medium", 0) or 0)
        reach = int(signal.get("internet_reachability_findings", 0) or 0)
        if (crit + high + med) > 0 and (
            reach > 0 or float(path.get("reachability_score") or 0.0) >= 0.8
        ):
            affected.append(target)

    if not affected:
        return PreCheckResult(
            "SER-EC2-002",
            "PASS",
            "no internet-reachable EC2 with active Inspector findings",
            [],
        )

    unique = sorted(set(affected))

    # Clean evidence_summary — count only; CVE details go to metadata
    summary = f"{len(unique)} internet-reachable EC2 instance(s) with active Inspector findings"

    # Build structured cve_details for metadata
    cve_details: List[Dict[str, Any]] = []
    for arn in unique[:10]:
        iid = arn.split(":instance/")[-1] if ":instance/" in arn else arn
        for title in instance_cves.get(iid, [])[:10]:
            cve_details.append({"id": title, "resource": iid})

    # Read CVE intelligence file if available (enriched CVSS + attack path)
    cve_intel_doc = evidence.get("cve-intelligence", {})
    enriched_cve_details: List[Dict[str, Any]] = []
    per_instance_attack_paths: Dict[str, Any] = {}
    per_instance_sg_rules: Dict[str, Any] = {}
    per_instance_roles: Dict[str, str] = {}
    if isinstance(cve_intel_doc, dict):
        instances_intel = cve_intel_doc.get("instances", {})
        for arn in unique[:10]:
            iid = arn.split(":instance/")[-1] if ":instance/" in arn else arn
            inst_data = instances_intel.get(iid, {})
            if not isinstance(inst_data, dict):
                continue
            for cve_entry in inst_data.get("cves", []):
                if not isinstance(cve_entry, dict):
                    continue
                entry: Dict[str, Any] = {
                    "id": cve_entry.get("id", ""),
                    "package": cve_entry.get("package", ""),
                    "inspector_severity": cve_entry.get("inspector_severity", ""),
                    "cvss_score": cve_entry.get("cvss_score"),
                    "description": cve_entry.get("description", ""),
                    "attack_vector": cve_entry.get("attack_vector", ""),
                    "exploitable_from_internet": cve_entry.get(
                        "exploitable_from_internet", False
                    ),
                    "relevant_open_ports": cve_entry.get("relevant_open_ports", []),
                    "resource": iid,
                }
                # Propagate exploit_intel from cve-intelligence enrichment
                if cve_entry.get("exploit_intel"):
                    entry["exploit_intel"] = cve_entry["exploit_intel"]
                enriched_cve_details.append(entry)
            attack_path = inst_data.get("attack_path")
            if isinstance(attack_path, dict) and attack_path:
                per_instance_attack_paths[iid] = attack_path
            sg_rules = inst_data.get("sg_rules")
            if isinstance(sg_rules, list) and sg_rules:
                per_instance_sg_rules[iid] = sg_rules
            iam_role = inst_data.get("iam_role")
            if isinstance(iam_role, str) and iam_role:
                per_instance_roles[iid] = iam_role

    metadata: Dict[str, Any] = {
        "cve_details": enriched_cve_details if enriched_cve_details else cve_details,
    }
    if per_instance_attack_paths:
        metadata["attack_paths"] = per_instance_attack_paths
    if per_instance_sg_rules:
        metadata["sg_rules_context"] = per_instance_sg_rules
    if per_instance_roles:
        metadata["iam_roles"] = per_instance_roles

    # Contextual risk score: escalate when a NETWORK-vector CVSS≥9.0 CVE is present
    # on an internet-reachable instance → effectively a Critical attack path.
    all_cves_enriched = enriched_cve_details if enriched_cve_details else cve_details
    max_cvss = 0.0
    has_network_critical = False
    for cve_e in all_cves_enriched:
        score = cve_e.get("cvss_score") or 0.0
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0.0
        if score > max_cvss:
            max_cvss = score
        vector = str(cve_e.get("attack_vector") or "").upper()
        if score >= 9.0 and "NETWORK" in vector:
            has_network_critical = True

    if has_network_critical:
        risk_score_override = 9.0  # Critical path: CVSS≥9.0 + NETWORK + open port
    elif max_cvss >= 7.0:
        risk_score_override = 8.0  # Elevated high: significant CVSS but no confirmed NETWORK vector
    else:
        risk_score_override = None  # Fall back to checklist severity default (7.0)

    return PreCheckResult(
        "SER-EC2-002",
        "FAIL",
        summary,
        unique[:20],
        confidence=0.92,
        metadata=metadata,
        risk_score_override=risk_score_override,
    )


@_register("sistemas_explotables_red")
def check_ser_ecs_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """ECS service reachable via internet-facing ALB."""
    reach_doc = evidence.get("reachability-graph", {})
    if not isinstance(reach_doc, dict):
        return PreCheckResult("SER-ECS-001", "SKIP", "missing reachability-graph evidence", [])

    edges = reach_doc.get("edges", [])
    if not isinstance(edges, list):
        return PreCheckResult("SER-ECS-001", "SKIP", "invalid edges shape", [])

    affected: List[str] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("path_type") or "") == "alb->ecs-service":
            target = str(edge.get("target") or "")
            if target and target not in affected:
                affected.append(target)

    if not affected:
        return PreCheckResult(
            "SER-ECS-001", "PASS", "no ECS services reachable via internet-facing ALB", []
        )

    return PreCheckResult(
        "SER-ECS-001",
        "FAIL",
        f"{len(affected)} ECS service(s) reachable via internet-facing ALB",
        affected[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_lmb_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """Lambda exposed via API Gateway without authorization."""
    front_doc = evidence.get("front-doors", {})
    if not isinstance(front_doc, dict):
        return PreCheckResult("SER-LMB-002", "SKIP", "missing front-doors evidence", [])

    routes = front_doc.get("api_gateway_routes", [])
    if not isinstance(routes, list):
        return PreCheckResult("SER-LMB-002", "SKIP", "invalid api_gateway_routes shape", [])

    if not routes:
        return PreCheckResult("SER-LMB-002", "PASS", "no API Gateway routes found", [])

    # WebSocket API V2 routes: $connect is the handshake (must be authorized),
    # $disconnect and $default only execute after connection is established.
    # Flagging $disconnect/$default as separate issues inflates the count and
    # misleads remediation — the fix is always on $connect.
    _websocket_post_connect = {"$DISCONNECT", "$DEFAULT"}

    unauth: List[str] = []
    websocket_connect_unauth: List[str] = []  # Track WebSocket APIs missing auth on $connect

    for route in routes:
        if not isinstance(route, dict):
            continue
        method = str(route.get("Method") or "").upper()
        # OPTIONS is a CORS preflight — browsers send it automatically and
        # API Gateway requires it to be unauthenticated by design.
        if method == "OPTIONS":
            continue

        auth = str(route.get("AuthorizationType") or "").upper()
        api_id = str(route.get("ApiId") or "")
        path = str(route.get("Path") or "")
        # Detect WebSocket APIs by route method names ($connect/$disconnect/$default)
        # even when ApiType is not labelled as WEBSOCKET in the collector output.
        is_websocket_route = method in {"$CONNECT", "$DISCONNECT", "$DEFAULT"}

        if is_websocket_route and method in _websocket_post_connect:
            # Post-connect routes are only reachable after $connect authenticates;
            # skip them to avoid counting a single WebSocket issue 3× times.
            continue

        if auth in ("NONE", ""):
            key = f"{api_id} {method} {path}".strip()
            if not key:
                continue
            if is_websocket_route and method == "$CONNECT":
                # Report WebSocket issues as a group keyed by API ID
                ws_key = f"{api_id} (WebSocket API: $connect unauthenticated)"
                if ws_key not in websocket_connect_unauth:
                    websocket_connect_unauth.append(ws_key)
            else:
                if key not in unauth:
                    unauth.append(key)

    all_unauth = unauth + websocket_connect_unauth
    if not all_unauth:
        return PreCheckResult(
            "SER-LMB-002",
            "PASS",
            "all API Gateway routes have authorization (OPTIONS excluded)",
            [],
        )

    ws_count = len(websocket_connect_unauth)
    http_count = len(unauth)
    parts = []
    if http_count:
        parts.append(f"{http_count} HTTP/REST route(s) without authorization")
    if ws_count:
        parts.append(f"{ws_count} WebSocket API(s) with unauthenticated $connect")

    return PreCheckResult(
        "SER-LMB-002",
        "FAIL",
        "; ".join(parts),
        all_unauth[:20],
    )


@_register("sistemas_explotables_red")
def check_ser_cve_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """SER-CVE-001: Internet-exposed instance with CISA KEV vulnerability."""
    cve_intel = evidence.get("cve-intelligence")
    if not isinstance(cve_intel, dict):
        return PreCheckResult("SER-CVE-001", "SKIP", "no cve-intelligence evidence", [])

    instances = cve_intel.get("instances")
    if not isinstance(instances, dict) or not instances:
        return PreCheckResult("SER-CVE-001", "SKIP", "no instances in cve-intelligence", [])

    affected: List[str] = []
    for iid, intel in instances.items():
        if not isinstance(intel, dict):
            continue
        for cve in intel.get("cves", []):
            if not isinstance(cve, dict):
                continue
            if not cve.get("exploitable_from_internet"):
                continue
            exploit_intel = cve.get("exploit_intel") or {}
            kev = exploit_intel.get("cisa_kev") or {}
            if kev.get("listed"):
                affected.append(f"{iid}:{cve.get('id', '?')}")
                break  # one KEV CVE per instance is enough

    if not affected:
        return PreCheckResult(
            "SER-CVE-001",
            "PASS",
            "no internet-exposed instances with CISA KEV vulnerabilities",
            [],
        )
    return PreCheckResult(
        "SER-CVE-001",
        "FAIL",
        f"{len(affected)} instance(s) internet-exposed with CISA KEV vulnerability (actively exploited in wild)",
        affected[:20],
    )


# =============================================================================
# CLOUDTRAIL EVENTS PRE-CHECKS (CTEF-*)
# Deterministic checks on historical CloudTrail event evidence.
# Each check loads its evidence file(s) and returns PASS/FAIL/SKIP.
# =============================================================================


def _load_ctef_events(evidence: dict, key: str) -> list:
    """Helper: return event list for a given evidence key (default [])."""
    val = evidence.get(key, [])
    return val if isinstance(val, list) else []


@_register("cloudtrail_events")
def check_ctef_001(evidence: dict) -> PreCheckResult:
    """CTEF-001: Root account activity detected in audit period."""
    root_events = _load_ctef_events(evidence, "root-events")
    if root_events:
        sample = root_events[0].get("EventName", "unknown")
        return PreCheckResult(
            "CTEF-001",
            "FAIL",
            f"Root account used {len(root_events)} time(s); first event: {sample}",
            ["arn:aws:iam::*:root"],
        )
    return PreCheckResult("CTEF-001", "PASS", "No root account activity detected", [])


@_register("cloudtrail_events")
def check_ctef_002(evidence: dict) -> PreCheckResult:
    """CTEF-002: Excessive failed console login attempts (brute-force indicator)."""
    console_events = _load_ctef_events(evidence, "console-login-events")
    # ConsoleLogin failures have ErrorMessage = "Failed authentication"
    failed = [
        e for e in console_events
        if e.get("ErrorCode") or "failed" in str(e.get("ErrorMessage", "")).lower()
    ]
    threshold = 5
    if len(failed) >= threshold:
        usernames = list({e.get("Username", "unknown") for e in failed})[:5]
        return PreCheckResult(
            "CTEF-002",
            "FAIL",
            f"{len(failed)} failed login attempt(s) detected; affected users: {usernames}",
            [f"user:{u}" for u in usernames],
        )
    return PreCheckResult(
        "CTEF-002", "PASS", f"Failed logins below threshold ({len(failed)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_003(evidence: dict) -> PreCheckResult:
    """CTEF-003: CloudTrail audit tampering detected (StopLogging / DeleteTrail / UpdateTrail)."""
    tampering = _load_ctef_events(evidence, "audit-tampering-events")
    if tampering:
        event_names = list({e.get("EventName", "unknown") for e in tampering})
        usernames = list({e.get("Username", "unknown") for e in tampering})[:5]
        return PreCheckResult(
            "CTEF-003",
            "FAIL",
            f"Audit trail tampering detected: {event_names} by {usernames}",
            [f"user:{u}" for u in usernames],
            confidence=1.0,
        )
    return PreCheckResult("CTEF-003", "PASS", "No CloudTrail tampering events detected", [])


@_register("cloudtrail_events")
def check_ctef_004(evidence: dict) -> PreCheckResult:
    """CTEF-004: Privilege escalation events detected (policy attachment, access key creation)."""
    priv_esc = _load_ctef_events(evidence, "privilege-escalation-events")
    if priv_esc:
        event_names = list({e.get("EventName", "unknown") for e in priv_esc})
        actors = list({e.get("Username", "unknown") for e in priv_esc})[:5]
        return PreCheckResult(
            "CTEF-004",
            "FAIL",
            f"{len(priv_esc)} privilege escalation event(s): {event_names} by {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-004", "PASS", "No privilege escalation events detected", []
    )


@_register("cloudtrail_events")
def check_ctef_005(evidence: dict) -> PreCheckResult:
    """CTEF-005: API throttling spike (service disruption indicator)."""
    throttled = _load_ctef_events(evidence, "throttling-events")
    threshold = 50
    if len(throttled) >= threshold:
        sources = list({e.get("EventSource", "unknown") for e in throttled})[:5]
        return PreCheckResult(
            "CTEF-005",
            "FAIL",
            f"{len(throttled)} throttling events detected; services: {sources}",
            [],
        )
    return PreCheckResult(
        "CTEF-005", "PASS", f"Throttling events below threshold ({len(throttled)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_006(evidence: dict) -> PreCheckResult:
    """CTEF-006: IAM permission denial storm (AccessDenied spike)."""
    denied = _load_ctef_events(evidence, "access-denied-events")
    threshold = 20
    if len(denied) >= threshold:
        actors = list({e.get("Username", "unknown") for e in denied})[:5]
        return PreCheckResult(
            "CTEF-006",
            "FAIL",
            f"{len(denied)} AccessDenied events detected; actors: {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-006", "PASS", f"AccessDenied events below threshold ({len(denied)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_007(evidence: dict) -> PreCheckResult:
    """CTEF-007: Unusual off-hours console logins detected."""
    console_events = _load_ctef_events(evidence, "console-login-events")
    # Filter successful logins only
    successful = [
        e for e in console_events
        if not e.get("ErrorCode") and "failed" not in str(e.get("ErrorMessage", "")).lower()
    ]
    off_hours = []
    for e in successful:
        event_time_str = e.get("EventTime", "")
        try:
            from datetime import datetime as _dt
            if isinstance(event_time_str, str):
                et = _dt.fromisoformat(event_time_str.replace("Z", "+00:00"))
            else:
                continue
            # Off-hours: before 07:00 or after 20:00 UTC
            if et.hour < 7 or et.hour >= 20:
                off_hours.append(e)
        except (ValueError, AttributeError):
            continue

    threshold = 3
    if len(off_hours) >= threshold:
        users = list({e.get("Username", "unknown") for e in off_hours})[:5]
        return PreCheckResult(
            "CTEF-007",
            "FAIL",
            f"{len(off_hours)} off-hours console login(s) detected; users: {users}",
            [f"user:{u}" for u in users],
        )
    return PreCheckResult(
        "CTEF-007", "PASS", f"Off-hours logins below threshold ({len(off_hours)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_008(evidence: dict) -> PreCheckResult:
    """CTEF-008: Mass resource deletion detected (data destruction indicator)."""
    delete_events = _load_ctef_events(evidence, "delete-events")
    threshold = 10
    if len(delete_events) >= threshold:
        event_names = list({e.get("EventName", "unknown") for e in delete_events})[:5]
        actors = list({e.get("Username", "unknown") for e in delete_events})[:5]
        return PreCheckResult(
            "CTEF-008",
            "FAIL",
            f"{len(delete_events)} deletion event(s) detected: {event_names} by {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-008", "PASS", f"Deletion events below threshold ({len(delete_events)} < {threshold})", []
    )


@_register("cloudtrail_events")
def check_ctef_009(evidence: dict) -> PreCheckResult:
    """CTEF-009: Credential report accessed (reconnaissance indicator)."""
    gen_events = _load_ctef_events(evidence, "credential-report-events")
    get_events = _load_ctef_events(evidence, "get-credential-report-events")
    all_events = gen_events + get_events
    if all_events:
        actors = list({e.get("Username", "unknown") for e in all_events})[:5]
        return PreCheckResult(
            "CTEF-009",
            "FAIL",
            f"Credential report accessed {len(all_events)} time(s) by: {actors}",
            [f"user:{a}" for a in actors],
        )
    return PreCheckResult("CTEF-009", "PASS", "No credential report access detected", [])


@_register("cloudtrail_events")
def check_ctef_010(evidence: dict) -> PreCheckResult:
    """CTEF-010: Cross-account AssumeRole from unrecognized external accounts."""
    assume_role_events = _load_ctef_events(evidence, "assume-role-events")
    # Flag AssumeRole events where the caller is from a different account
    # Detected when username contains ':' (cross-account format: account-id:role-name)
    cross_account = [
        e for e in assume_role_events
        if ":" in str(e.get("Username", ""))
        and not str(e.get("Username", "")).startswith("AROA")  # exclude service role prefixes
    ]
    threshold = 1
    if len(cross_account) >= threshold:
        actors = list({e.get("Username", "unknown") for e in cross_account})[:5]
        return PreCheckResult(
            "CTEF-010",
            "FAIL",
            f"{len(cross_account)} cross-account AssumeRole event(s) detected: {actors}",
            [f"principal:{a}" for a in actors],
        )
    return PreCheckResult(
        "CTEF-010", "PASS", "No anomalous cross-account AssumeRole events detected", []
    )
