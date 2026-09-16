# ruff: noqa: I001
"""Metadata narratives for deterministic pre-check findings."""

from typing import Dict


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
        "IAM users without MFA rely on a single authentication factor for interactive or "
        "programmatic access. Phishing, credential stuffing, or access-key leakage can therefore "
        "lead directly to unauthorized account access with no second factor to interrupt use.\n\n"
        "In a PCI DSS v4.0 context, absence of MFA for interactive users and unprotected "
        "programmatic credentials weakens Requirement 8 controls for access into the CDE."
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
        "has persistent programmatic access for the permissions assigned to that identity. "
        "For read-only audit users this enables broad reconnaissance; for users with scoped "
        "write permissions, such as S3 backup-bucket access, it can expose or alter the data "
        "covered by those permissions without using the console.\n\n"
        "Long-lived credentials significantly increase the blast radius of credential "
        "exposure incidents, as organizations have no way to know when the key was first "
        "stolen."
    ),
    "IAM-007": (
        "Inline role policies embed permissions directly into each affected role, making them "
        "harder to version, compare, reuse, and centrally review than customer-managed policies. "
        "For operational roles such as AWS QuickSetup roles, this can hide drift in automation "
        "permissions, including IAM or PassRole-related grants, until a manual role review occurs.\n\n"
        "From a governance perspective, inline policies increase review effort and weaken change "
        "control because permission intent is fragmented across role objects instead of managed "
        "through reusable policy artifacts."
    ),
    "IAM-012": (
        "Inactive accounts with valid credentials are an unmonitored attack vector. An attacker "
        "who obtains credentials for a dormant user — via phishing, credential dumps, or dark web "
        "purchases — can operate for extended periods without triggering usage-based alerts, since "
        "there is no expected baseline of activity to compare against.\n\n"
        "In a PCI DSS context, dormant accounts violate Requirement 8.2.6, which requires disabling "
        "or removing inactive accounts within 90 days. Failure to remediate represents a direct "
        "compliance gap that will be flagged in a QSA assessment."
    ),
    "IAM-014": (
        "An attacker who compromises a user with multiple active access keys obtains redundant "
        "programmatic access that may go unnoticed longer — if one key is detected and rotated, "
        "the second key may remain active and undetected. This significantly extends the window "
        "of unauthorized access and complicates forensic attribution of API calls.\n\n"
        "From a compliance perspective, PCI DSS Requirement 8.2.1 requires unique identification "
        "of every user; multiple active keys per user create ambiguity in audit trails that makes "
        "it difficult to tie API actions to a specific authentication event."
    ),
    "IAM-015": (
        "Directly attached user policies bypass group-based access governance and make it harder "
        "to review or revoke permissions consistently. In this evidence pattern, the direct policy "
        "context identifies scoped but powerful service access, such as s3:* on a backup bucket, "
        "that remains tied to an individual IAM user instead of a role or group.\n\n"
        "Operationally, direct attachments increase the chance that permissions survive role "
        "changes, offboarding, or access-review cleanup, leaving sensitive bucket or service "
        "access harder to track."
    ),
    "IAM-016": (
        "Programmatic-only IAM users rely on long-lived access keys rather than short-lived role "
        "credentials. If those keys are copied from a host, CI system, script, or operator laptop, "
        "an attacker can use the exact services shown in the credential report, such as IAM, SSM, "
        "Inspector, or S3, until the key is revoked.\n\n"
        "For AWS workloads, IAM roles provide automatic rotation and resource-bound identity. "
        "Where a user is ambiguous rather than a confirmed service account, the risk is still the "
        "same long-lived credential lifecycle that must be reviewed and either migrated or tightly "
        "controlled."
    ),
    "IAM-026": (
        "Privileged roles without permission boundaries can receive or retain broad permissions "
        "without a maximum-permission guardrail. This is most relevant where the role already has "
        "AdministratorAccess or IAM policy-manipulation capability such as iam:PassRole over role "
        "resources.\n\n"
        "A boundary would not replace least-privilege policies, but it would cap future attached "
        "or inline permissions and reduce the blast radius of deployment mistakes or compromised "
        "automation paths."
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
    "EXP-002": (
        "The affected RDS instances are internet-reachable at the database network layer. "
        "For engines such as SQL Server, this exposes the database authentication surface "
        "directly to global scanning, brute-force attempts, and engine-specific exploitation "
        "on the open database port.\n\n"
        "A successful compromise can expose application data stored in the database and can "
        "provide a foothold for further movement through application credentials, database "
        "links, or trusted network paths."
    ),
    "EXP-007": (
        "Internet-facing Application Load Balancers without an associated WAF forward HTTP/S "
        "traffic to backend applications without layer-7 inspection. This removes a key "
        "control for blocking common web attacks such as SQL injection, cross-site scripting, "
        "known-bad user agents, request floods, and exploit probes before they reach the app.\n\n"
        "For public applications in PCI scope, missing WAF coverage weakens the automated "
        "technical control expected for public-facing web attack detection and prevention."
    ),
    "EXP-013": (
        "S3 buckets without an explicit aws:SecureTransport=false deny do not enforce TLS "
        "at the bucket policy layer. If any client or integration attempts non-TLS access, "
        "the bucket policy does not provide a final guardrail to reject the request.\n\n"
        "For audit or log buckets, this weakens confidentiality and integrity controls for "
        "security evidence in transit, especially where multiple services or external tools "
        "write to the bucket."
    ),
    "EXP-014": (
        "Audit and log buckets without versioning are more vulnerable to destructive or "
        "accidental changes. If an identity with write or delete access overwrites log files, "
        "the previous object state may not be recoverable from S3 version history.\n\n"
        "This reduces forensic reliability during incident response because audit evidence "
        "can be altered or removed without retaining prior versions for investigation."
    ),
    "EXP-015": (
        "S3 bucket policies with public or cross-account principals and missing or malformed "
        "security conditions can expose objects beyond the intended account boundary. An empty "
        "aws:PrincipalOrgID condition or a bare Principal:* grant does not provide meaningful "
        "organizational scoping.\n\n"
        "Where the statement grants access to operational artifacts such as QuickSetup policy "
        "files, an unintended principal may be able to read configuration data that should be "
        "limited to known accounts or organization members."
    ),
    "EXP-024": (
        "Audit and log buckets encrypted only with SSE-S3/AES256 do not provide customer-managed "
        "key policy controls, independent key revocation, or KMS-level audit and rotation "
        "governance. The data is encrypted, but key administration remains service-managed.\n\n"
        "For security evidence such as CloudTrail, Config, SSM, and access logs, customer-managed "
        "KMS keys provide stronger separation of duties and a clearer control point for who can "
        "decrypt retained audit data."
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
        "Active Inspector findings with exploitAvailable=YES are higher-priority than "
        "ordinary vulnerability backlog because exploit activity or exploit material is known "
        "to AWS. In this evidence set the affected CVE is reported as HIGH severity, so the "
        "finding should be treated as urgent without calling it CRITICAL unless separate "
        "evidence proves that escalation.\n\n"
        "An attacker still needs a viable path to the affected instance or package context. "
        "Network reachability, workload exposure, and local privilege boundaries determine the "
        "final blast radius."
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
        "ACTIVE HIGH Inspector findings require an owner, remediation decision, and SLA. "
        "When Inspector provides no remediation text or the evidence does not show an assigned "
        "plan, the reporting should describe that workflow gap without claiming the software is "
        "end-of-life unless fix or lifecycle evidence proves it.\n\n"
        "The business impact is delayed vulnerability response: exploitable or high-impact CVEs "
        "can remain open without a documented patch, exception, or compensating control path."
    ),
    "VULN-010": (
        "Active HIGH or CRITICAL Inspector findings on named application service instances "
        "increase operational risk for those services. In this evidence pattern, the affected "
        "instances are tagged as API and BO workloads, so remediation priority should account "
        "for service ownership and application role as well as CVE severity.\n\n"
        "This does not prove internet exploitability or an SLA breach by itself. The practical "
        "impact is that application service availability and integrity depend on timely patching "
        "or documented compensating controls for the listed package vulnerabilities."
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
    # ── HARDENING ───────────────────────────────────────────────────────────
    "HRD-004": (
        "A Security Hub compliance score below 50% means failed controls materially outnumber "
        "passed controls in the available evidence. This is not a single exploit path; it is "
        "a posture-level indicator that foundational controls are failing across services.\n\n"
        "The practical impact is weak prioritization confidence and elevated audit risk: "
        "critical and high failed controls must be triaged before the account can be treated "
        "as having a stable security baseline."
    ),
    "HRD-005": (
        "Active CRITICAL Security Hub findings represent known high-impact weaknesses that "
        "remain unresolved. The Security Hub sample includes account, EC2, RDS, IAM, and SSM "
        "control failures, so remediation must be owner-driven rather than summarized as a "
        "generic posture issue.\n\n"
        "The business impact is delayed treatment of risks Security Hub has already classified "
        "as urgent, increasing the chance that exposed resources or vulnerable workloads remain "
        "available to attackers."
    ),
    "HRD-009": (
        "A backlog of HIGH Security Hub findings indicates that multiple significant control "
        "failures are active at the same time. These findings may not each be critical, but the "
        "volume increases the chance that one weakness can be chained with another.\n\n"
        "The operational impact is remediation debt: teams need prioritization, ownership, and "
        "SLA tracking for the affected controls and resources."
    ),
    "HRD-010": (
        "Without AWS Config Conformance Packs, the account lacks packaged, framework-oriented "
        "compliance evaluation for selected control baselines. Individual Config rules may still "
        "exist, but there is no conformance-pack object to track a complete framework deployment.\n\n"
        "The impact is weaker continuous compliance governance and more manual evidence assembly "
        "for audits or policy reviews."
    ),
    "HRD-012": (
        "A large MEDIUM Security Hub backlog creates security debt even when individual findings "
        "are not urgent. These findings often represent missing hardening controls that can "
        "increase blast radius when combined with higher-severity issues.\n\n"
        "The impact is reduced baseline resilience and a growing queue of weaknesses that should "
        "be batch-remediated with ownership and SLA tracking."
    ),
    "HRD-014": (
        "GuardDuty disabled removes AWS-native threat detection for the audited region. Security "
        "Hub can still report compliance findings, but GuardDuty-specific detections for credential "
        "abuse, suspicious API activity, and malicious network behavior will not be generated.\n\n"
        "The impact is longer detection and response time for active compromise scenarios."
    ),
    # ── ALERTING ─────────────────────────────────────────────────────────────
    "ALRT-002": (
        "Existing CloudWatch metric filters may already provide direct alert coverage, but "
        "the absence of custom EventBridge rules removes an additional automation path for "
        "CloudTrail security events. This limits enrichment, cross-account routing, and "
        "integration with response workflows.\n\n"
        "The business impact is slower or less flexible incident automation, not proof that "
        "CloudTrail security events are entirely unmonitored."
    ),
    "ALRT-005": (
        "CloudWatch alarms that publish only to an SNS topic with zero confirmed subscriptions "
        "do not reach responders. The affected alarms may transition state, but notifications "
        "sent to the unsubscribed topic are silently discarded.\n\n"
        "The business impact is delayed incident detection and response for the alarms using "
        "that topic. This is an alert-delivery failure, not a direct attacker privilege "
        "escalation path."
    ),
    "ALRT-007": (
        "The listed event names are absent from configured CloudWatch metric-filter patterns. "
        "Those specific events may therefore fail to generate the intended alert even when "
        "other security categories, such as root usage or CloudTrail changes, are covered.\n\n"
        "The practical impact is a targeted monitoring blind spot for the missing event names, "
        "not evidence that all critical AWS activity is unmonitored."
    ),
    "ALRT-010": (
        "CloudWatch alarms in INSUFFICIENT_DATA state may not evaluate or notify as intended "
        "for their monitored condition. For the affected CPU, ALB health, and EC2 status-check "
        "alarms, this creates an operational monitoring blind spot.\n\n"
        "The impact is missed service-health or availability notification for those alarms, "
        "not direct privilege escalation or unauthorized data access."
    ),
    "ALRT-017": (
        "Log groups with retention below 90 days reduce the forensic window available after "
        "an incident. Relevant CloudWatch Logs data can expire before responders or auditors "
        "review the period under investigation.\n\n"
        "The business impact is weaker investigation and compliance evidence retention for "
        "the affected log groups."
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
    "NET-001": (
        "Internet-exposed sensitive ports create a direct network attack path to the "
        "service behind the Security Group. When the exposed port is a database port such "
        "as TCP/1433 and the associated workload is publicly accessible, attackers can "
        "attempt credential attacks, service fingerprinting, and vulnerability exploitation "
        "against the database listener from any internet source.\n\n"
        "The business impact is unauthorized access risk to the affected service and any "
        "data it exposes. The exact blast radius depends on database authentication, patch "
        "level, and the privileges available after successful login or exploitation."
    ),
    "NET-007": (
        "Internet-facing VPCs without AWS Network Firewall or equivalent stateful "
        "inspection have weaker centralized control over north-south traffic. Malicious "
        "payloads, command-and-control callbacks, and anomalous protocols are less likely "
        "to be blocked before reaching public subnets or leaving the VPC.\n\n"
        "The residual risk depends on Security Group, NACL, and workload controls, but the "
        "architecture lacks a dedicated inspection point for internet-routed traffic."
    ),
    "NET-003": (
        "Allow-all NACL entries remove a subnet-level guardrail that can otherwise limit "
        "traffic when Security Groups are misconfigured or overly broad. The evidence "
        "does not prove direct compromise by itself; it proves that subnet filtering is "
        "not providing an independent control for the associated subnets.\n\n"
        "The practical risk is weaker segmentation assurance and reduced containment if "
        "another control, such as a Security Group, later allows unintended traffic."
    ),
    "NET-008": (
        "Critical workloads in public subnets are closer to direct internet exposure than "
        "expected for databases or internal services. When the workload is also publicly "
        "accessible or attached to a permissive Security Group, the placement can turn a "
        "single rule mistake into internet reachability for a sensitive service.\n\n"
        "The business impact is increased probability of unauthorized access to data-tier "
        "services and a harder path to prove network segmentation for compliance reviews."
    ),
    "NET-009": (
        "Broad CIDR sources on non-web ports increase the number of hosts that can reach "
        "management, data, telemetry, or internal service ports. This expands lateral "
        "movement options for any compromised host inside the allowed network range and "
        "makes accidental service exposure harder to contain.\n\n"
        "The proven risk is excessive network reachability, not privilege escalation by "
        "itself. Business impact depends on the sensitivity of the services behind those "
        "ports and the trust level of the allowed CIDR ranges."
    ),
    "NET-010": (
        "Permissive default NACLs mean subnet-level filtering is not acting as a "
        "restrictive backstop for ingress or egress paths. This is most relevant when "
        "Security Groups, routing, or workload-level controls are changed incorrectly, "
        "because the default NACL will not independently limit the traffic.\n\n"
        "The impact is weaker defense-in-depth and auditability rather than direct proof "
        "of unauthorized access or privilege escalation."
    ),
    "NET-011": (
        "Security Group rules without descriptions weaken review and change-control quality. "
        "The finding is not directly exploitable and is not privilege escalation by itself; "
        "the risk is that broad or "
        "sensitive access can remain undocumented, unowned, and harder to challenge during "
        "firewall reviews.\n\n"
        "In incident response or audit scenarios, missing rule intent slows triage and "
        "increases the likelihood that risky network exceptions remain active longer than "
        "necessary."
    ),
    "NET-013": (
        "Private subnet AWS service access that relies on NAT instead of VPC endpoints "
        "reduces network-path control and observability. The evidence proves a design "
        "hardening gap: private subnet default traffic exits through a NAT Gateway while "
        "no VPC endpoints are configured for AWS services.\n\n"
        "This can increase NAT data-processing cost and makes it harder to enforce endpoint "
        "policies for services such as S3 or DynamoDB. Actual sensitive service traffic is "
        "not proven by route-table evidence alone and should not be overstated."
    ),
    "NET-016": (
        "Subnets associated with default NACLs lack an explicit subnet-level stateless "
        "filtering policy. This does not by itself create a direct exploit path, but it "
        "removes a defense-in-depth layer that can contain accidental Security Group "
        "exposure or tier-to-tier routing mistakes.\n\n"
        "The operational impact is weaker segmentation assurance: auditors and operators "
        "cannot rely on custom NACLs as an independent control aligned to public, private, "
        "application, or data subnet roles."
    ),
    "NET-022": (
        "Public subnets are valid for internet-facing tiers, but they require strict "
        "workload placement discipline. The risk is that any sensitive workload placed in "
        "these subnets is closer to direct internet exposure if a Security Group or resource "
        "policy is misconfigured.\n\n"
        "The finding should be treated as a placement and segmentation review item unless "
        "the evidence also proves sensitive workloads in those public subnets."
    ),
    "NET-025": (
        "Subnets without classification tags weaken governance automation and tier-based "
        "change control. The issue is not directly exploitable; it reduces confidence that "
        "public, private, application, and data subnets can be reliably identified by tooling.\n\n"
        "This can slow audits, make policy-as-code guardrails less precise, and increase "
        "the chance that future changes are applied to the wrong subnet tier."
    ),
    "NET-024": (
        "Inconsistent network resource naming weakens ownership, triage, and change-control "
        "workflows. The evidence supports a governance and inventory risk: operators may "
        "struggle to identify which team owns a Security Group or whether an exception is "
        "still required.\n\n"
        "The finding should not imply proven cardholder-data exposure or former-employee "
        "risk unless separate evidence establishes those facts."
    ),
    # ── SISTEMAS EXPLOTABLES EN RED (SER) ─────────────────────────────────────
    "SER-EC2-002": (
        "The affected EC2 instances are directly reachable from the internet on HTTPS/443 "
        "and have active Amazon Inspector findings, including at least one network-vector "
        "critical kernel CVE when present in the evidence. This creates a realistic initial "
        "access path through the exposed service, followed by local privilege-escalation "
        "findings as post-compromise accelerators.\n\n"
        "If code execution is obtained on the instance, the attached instance profile and "
        "IMDS become part of the blast radius. Impact should therefore be assessed against "
        "the exposed service, vulnerable package versions, IMDS posture, and IAM role "
        "permissions, not only the Security Group rule."
    ),
    # ── CLOUDTRAIL EVENTS ──────────────────────────────────────────────────
    "CTEF-003": (
        "Stopping and deleting a CloudTrail trail creates an audit-visibility gap for the "
        "affected account and trail. In this evidence, the same IAM user performed both "
        "actions within seconds, which is consistent with deliberate log tampering and "
        "requires incident-response review.\n\n"
        "The immediate risk is loss of reliable forensic evidence for activity during or "
        "after the logging interruption. Business impact includes delayed containment, "
        "weaker incident reconstruction, and potential PCI DSS audit-log protection issues."
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
        "Like a public reception desk with no visitor screening — every request reaches "
        "the staff before anyone checks whether it is malicious."
    ),
    "EXP-013": (
        "Like sending confidential documents via open postcard instead of sealed envelope — "
        "anyone along the delivery route can read them."
    ),
    "EXP-014": (
        "Like keeping an audit notebook in pencil with no photocopies — once a page is "
        "erased or overwritten, the original record is gone."
    ),
    "EXP-015": (
        "Like granting access to a records room based on a blank company-name field — "
        "the rule exists, but it does not actually identify the trusted organization."
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
        "Like storing audit archives in a locked room where only the building operator "
        "controls the master key — protected, but without independent key governance."
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
        "Like a building where every internal checkpoint is configured to wave traffic "
        "through by default — other locks may still protect rooms, but the checkpoint "
        "itself is no longer providing meaningful filtering."
    ),
    "NET-008": (
        "Like placing the payment safe in the storefront rather than a back room — it may "
        "still have a lock, but a single access-control mistake exposes it directly."
    ),
    "NET-007": (
        "Like removing the fence around a military base and posting signs for each building — "
        "anyone with a map can walk to any facility."
    ),
    "NET-010": (
        "Like relying on a default lobby checkpoint that allows every normal route unless "
        "someone adds a special exception — useful doors still need explicit rules."
    ),
    "NET-011": (
        "Like a door access list with no business reason written next to each exception — "
        "the access may be intentional, but reviewers cannot tell what should stay."
    ),
    "NET-016": (
        "Like every floor inheriting the building's generic access policy instead of a "
        "policy tailored to that floor's role and sensitivity."
    ),
    "NET-022": (
        "Like having an office building entrance connected directly to your vault room "
        "without intermediate checkpoints — the entrance needs public access but valuables "
        "should be behind secured doors in restricted zones."
    ),
    "NET-025": (
        "Like a campus map without labels for public areas, staff offices, and restricted "
        "rooms — automation and reviewers cannot reliably apply the right rules."
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
    "ALRT-002": (
        "CloudWatch metric filters may already provide alert coverage, but the absence of "
        "custom EventBridge rules removes an additional automation path for enrichment, "
        "cross-account routing, and incident-response workflows. This is a resilience and "
        "automation gap, not proof that CloudTrail security events are entirely unmonitored."
    ),
    "ALRT-005": (
        "Like a fire alarm wired to a silent receiver — the alarm triggers but nobody hears "
        "it. CloudWatch Alarms publish to an SNS topic with zero confirmed subscribers, so "
        "security notifications sent to that topic are silently discarded. This delays "
        "incident detection and response; it is not a direct privilege-escalation path."
    ),
    "ALRT-007": (
        "Specific critical event names are missing from the configured metric-filter "
        "patterns. Those event types may not trigger the intended alert path even when "
        "other CloudTrail security activity is monitored. This is a targeted monitoring "
        "gap, not proof that all account-compromise indicators are blind."
    ),
    "ALRT-010": (
        "CloudWatch Alarms in INSUFFICIENT_DATA state are not evaluating their metrics — "
        "they may not fire when the monitored condition occurs. This may indicate stale "
        "dimensions, deleted resources, missing metrics, or intentionally sparse metrics. "
        "The risk is missed operational or security notification for the affected alarm, "
        "not direct attacker privilege escalation."
    ),
    "ALRT-017": (
        "CloudWatch log groups with retention below 90 days do not satisfy PCI DSS "
        "Requirement 10.5.1 (12-month log availability and 3 months immediately available) "
        "requirement. Audit evidence needed for forensic investigation or compliance reviews "
        "will be automatically deleted before it can be used."
    ),
    # ── WAF ─────────────────────────────────────────────────────────────────
    "WAF-001": (
        "Internet-facing ALBs without any WAF association allow web traffic to reach backend "
        "targets without perimeter inspection for common application-layer attacks. This "
        "increases exposure to automated exploitation, malicious payloads, and abusive request "
        "patterns before application controls can respond."
    ),
    "WAF-004": (
        "WAF logs are valuable for incident response, but unredacted authentication headers or "
        "session material can turn the logging platform into a secondary exposure point. A user "
        "or process with log-read access could retrieve sensitive request components that should "
        "not be retained in raw security telemetry."
    ),
    "WAF-006": (
        "A Web ACL that lacks the organization's baseline AWS Managed Rule groups may still have "
        "some protection, but it does not provide the expected standardized AWS-managed coverage "
        "for common web attacks, known bad inputs, SQL injection patterns, and AWS IP reputation. "
        "This weakens consistency and makes rule effectiveness harder to audit across applications."
    ),
    "WAF-010": (
        "Continuing to operate WAF Classic creates a legacy-control dependency and splits WAF "
        "administration across old and current APIs. That does not mean traffic is unprotected, "
        "but it increases operational drift and can prevent consistent use of WAFv2 capabilities, "
        "logging workflows, and managed rule standards."
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


# ---------------------------------------------------------------------------
# Narrative descriptions for deterministic pre-check findings.
# Keys are check IDs. Templates support {resources}, {count}, {service}.
# Used by base.py reconciler to build the `description` field on injected findings.
# ---------------------------------------------------------------------------
PRE_CHECK_DESCRIPTIONS: Dict[str, str] = {
    # ── IAM ─────────────────────────────────────────────────────────────────
    "IAM-001": (
        "During the analysis of the IAM service, it was identified that the root account "
        "does not have multi-factor authentication (MFA) enabled.\n\n"
        "This situation implies that the most privileged account in the AWS environment "
        "is protected by a single authentication factor, exposing the entire account to "
        "full compromise if the root password is leaked or phished."
    ),
    "IAM-002": (
        "During the analysis of the IAM service, it was identified that {count} user account(s) "
        "do not have a multi-factor authentication (MFA) mechanism configured. Specifically, it was "
        "observed that {resources} lack MFA while having console access, active programmatic "
        "credentials, or both.\n\n"
        "This situation implies that access to these accounts relies on a single authentication "
        "factor (password or access keys), increasing the risk of compromise in the event of "
        "credential exposure or leakage."
    ),
    "IAM-003": (
        "During the analysis of the IAM service, it was identified that {count} user account(s) "
        "have been inactive for more than 90 days but remain active. Specifically, it was observed "
        "that {resources} show no login or API activity within the past 90 days.\n\n"
        "This situation implies that stale credentials remain valid attack vectors — if these "
        "accounts are compromised, unauthorized access could go undetected for extended periods "
        "due to the absence of a legitimate usage baseline."
    ),
    "IAM-004": (
        "During the analysis of the IAM service, the existence of programmatic credentials "
        "(access keys) that have not been rotated for a period exceeding 90 days was identified. "
        "Specifically, it was observed that the access keys corresponding to {resources} exceed "
        "the recommended rotation threshold.\n\n"
        "This situation implies that the credentials remain active for extended periods, "
        "increasing the likelihood of undetected exposure and the potential impact in the event "
        "of compromise of said keys."
    ),
    "IAM-005": (
        "During the analysis of the IAM service, it was identified that the account password "
        "policy does not enforce minimum length or complexity requirements. Specifically, "
        "the current policy permits passwords that do not meet security baseline standards.\n\n"
        "This situation implies that user accounts are susceptible to brute-force and "
        "dictionary attacks, significantly reducing the effort required to compromise "
        "console credentials."
    ),
    "IAM-007": (
        "During the analysis of the IAM service, it was identified that {count} IAM role(s) "
        "use inline policies instead of managed policies. Specifically, {resources} carry policy "
        "documents embedded directly in the role configuration.\n\n"
        "This situation implies that permissions are decentralized and harder to inventory, "
        "version, reuse, and review consistently, increasing the risk of unnoticed policy drift."
    ),
    "IAM-008": (
        "During the analysis of the IAM service, it was identified that {count} IAM user(s) "
        "have multiple active access keys simultaneously. Specifically, {resources} maintain "
        "more than one active programmatic credential.\n\n"
        "This situation implies that the attack surface for credential compromise is doubled, "
        "and auditing legitimate API usage becomes more complex, increasing the time to "
        "detect unauthorized access."
    ),
    "IAM-009": (
        "During the analysis of the IAM service, it was identified that the account password "
        "policy does not require periodic rotation. Specifically, no maximum password age "
        "is configured, allowing credentials to remain valid indefinitely.\n\n"
        "This situation implies that compromised passwords remain usable without expiry, "
        "giving attackers an unlimited window of access once credentials are obtained."
    ),
    "IAM-010": (
        "During the analysis of the IAM service, it was identified that {count} administrative "
        "user(s) do not have MFA enabled. Specifically, it was observed that {resources} hold "
        "elevated privileges without a second authentication factor.\n\n"
        "This situation implies that privileged accounts — with the ability to modify IAM "
        "policies, create users, and access all services — can be accessed through a single "
        "compromised password."
    ),
    "IAM-011": (
        "During the analysis of the IAM service, it was identified that {count} IAM user(s) "
        "have inline policies attached directly to them instead of using managed policies. "
        "Specifically, {resources} carry inline policy definitions.\n\n"
        "This situation implies that permission grants are decentralized and harder to audit, "
        "increasing the risk of privilege creep and policy drift going undetected."
    ),
    "IAM-012": (
        "During the analysis of the IAM service, it was identified that {count} IAM user(s) "
        "have not been used for more than 90 days but retain active credentials. "
        "Specifically, {resources} show no recent activity.\n\n"
        "This situation implies that dormant accounts with valid credentials represent an "
        "unmonitored access vector that could be exploited without triggering usage-based alerts."
    ),
    "IAM-014": (
        "During the analysis of the IAM service, it was identified that {count} IAM user(s) "
        "have multiple active access keys simultaneously. Specifically, {resources} maintain "
        "more than one active programmatic credential.\n\n"
        "This situation implies that the attack surface for credential compromise is doubled, "
        "and auditing legitimate API usage becomes more complex when multiple active keys exist."
    ),
    "IAM-020": (
        "During the analysis of the IAM service, it was identified that {count} IAM role(s) "
        "have overly permissive trust policies that allow broad principal assumptions. "
        "Specifically, {resources} can be assumed by any principal matching a wide condition.\n\n"
        "This situation implies that the effective blast radius of a compromised identity "
        "expands beyond the intended scope of the role's use."
    ),
    "IAM-029": (
        "During the analysis of the IAM service, it was identified that {count} IAM group(s) "
        "or role(s) grant permissions without enforcing MFA as a condition. Specifically, "
        "{resources} allow API access without requiring MFA authentication.\n\n"
        "This situation implies that programmatic access to sensitive actions is not gated "
        "by a second factor, weakening the account's defense against credential theft."
    ),
    "IAM-030": (
        "During the analysis of the IAM service, it was identified that {count} cross-account "
        "role(s) do not require an ExternalId condition in their trust policy. Specifically, "
        "{resources} are vulnerable to confused deputy attacks.\n\n"
        "This situation implies that any AWS account aware of these role ARNs can assume them "
        "by impersonating a trusted service, bypassing all account boundary controls."
    ),
    "IAM-032": (
        "During the analysis of the IAM service, it was identified that {count} IAM policy(ies) "
        "grant wildcard (*) resource access on sensitive actions. Specifically, {resources} "
        "allow operations against all resources in the account rather than specific targets.\n\n"
        "This situation implies that any principal using these policies can act on every "
        "resource of the given type, maximizing the blast radius of any misuse or compromise."
    ),
    "IAM-033": (
        "During the analysis of the IAM service, it was identified that {count} cross-account "
        "role(s) lack ExternalId conditions in their trust policies. Specifically, {resources} "
        "allow any principal in the trusted account to assume the role.\n\n"
        "This situation implies that a compromised identity in the partner or vendor account "
        "becomes an immediate pivot point into the target environment with no additional "
        "exploitation required."
    ),
    "IAM-040": (
        "During the analysis of the IAM service, it was identified that the AWS Organization "
        "does not have Service Control Policies (SCPs) configured to restrict actions across "
        "member accounts.\n\n"
        "This situation implies that IAM principals with sufficient permissions can perform "
        "actions that bypass organizational security guardrails, including creating privileged "
        "users, disabling CloudTrail, or accessing data outside the authorized scope."
    ),
    "IAM-041": (
        "During the analysis of the IAM service, it was identified that {count} IAM role(s) "
        "have AWS managed AdministratorAccess or PowerUserAccess attached. Specifically, "
        "{resources} grant broad privileged access through these managed policies.\n\n"
        "This situation implies that any principal assuming these roles can perform highly "
        "privileged operations, increasing the blast radius of a role compromise."
    ),
    "IAM-042": (
        "During the analysis of the IAM service, it was identified that {count} IAM user(s) "
        "have access keys that have never been used since creation. Specifically, {resources} "
        "have active but dormant programmatic credentials.\n\n"
        "This situation implies that unused credentials represent a persistent attack surface — "
        "if leaked, they could be exploited without generating any legitimate usage baseline "
        "to distinguish unauthorized access."
    ),
    "IAM-043": (
        "During the analysis of the IAM service, it was identified that IAM Access Analyzer "
        "is not enabled for the audited region. Without this service, cross-account and "
        "public resource exposure cannot be automatically detected.\n\n"
        "This situation implies that misconfigured trust policies or public resource policies "
        "may go undetected indefinitely, widening the window of exposure for unintentional "
        "external access grants."
    ),
    # ── EXPOSURE ─────────────────────────────────────────────────────────────
    "EXP-006": (
        "During the analysis of the Exposure service, it was identified that {count} S3 bucket(s) "
        "do not have server-side encryption enabled by default. Specifically, {resources} store "
        "data without encryption at rest.\n\n"
        "This situation implies that data in these buckets is not protected against physical "
        "media access or storage-layer breaches, and may violate data protection compliance requirements."
    ),
    "EXP-007": (
        "During the analysis of the Exposure service, it was identified that {count} "
        "internet-facing Application Load Balancer(s) do not have an associated AWS WAF WebACL. "
        "Specifically, {resources} receive public traffic without layer-7 WAF inspection.\n\n"
        "This situation implies that common web attack traffic reaches the backend application "
        "without WAF managed rules, custom request filtering, or centralized web-layer blocking."
    ),
    "EXP-013": (
        "During the analysis of the Exposure service, it was identified that {count} S3 bucket(s) "
        "do not enforce TLS with an explicit bucket policy Deny on aws:SecureTransport=false. "
        "Specifically, {resources} lack a policy guardrail that rejects non-TLS S3 requests.\n\n"
        "This situation implies that encryption in transit is not enforced at the bucket policy "
        "layer for these storage locations."
    ),
    "EXP-026": (
        "During the analysis of the Exposure service, it was identified that {count} RDS "
        "instance(s) are publicly accessible. Specifically, {resources} have the "
        "PubliclyAccessible flag set to true.\n\n"
        "This situation implies that the database endpoints are reachable from the internet, "
        "reducing the attacker's prerequisite from network-adjacent to internet-wide access "
        "for any authentication-layer attacks."
    ),
    "EXP-028": (
        "During the analysis of the Exposure service, it was identified that {count} "
        "resource(s) are exposed without appropriate access controls. Specifically, {resources} "
        "lack the necessary restrictions to prevent unauthorized external access.\n\n"
        "This situation implies that sensitive resources are reachable without requiring "
        "internal network access, expanding the attack surface to the global internet."
    ),
    # ── NETWORK ──────────────────────────────────────────────────────────────
    "NET-007": (
        "During the analysis of the Network service, it was identified that {count} "
        "internet-facing VPC(s) have Internet Gateway routing but no AWS Network Firewall "
        "endpoint in the collected evidence. Specifically, {resources} send north-south "
        "traffic through direct IGW paths without a visible stateful inspection layer.\n\n"
        "This situation implies that internet ingress and egress for the affected VPCs "
        "depends primarily on route tables, Security Groups, and NACLs, reducing the "
        "ability to inspect or block malicious traffic centrally."
    ),
    "NET-EGR-001": (
        "During the analysis of the Network service, it was identified that {count} security "
        "group(s) allow unrestricted outbound traffic (0.0.0.0/0) to all destinations. "
        "Specifically, {resources} impose no egress filtering.\n\n"
        "This situation implies that a compromised workload within these security groups "
        "can freely communicate with external command-and-control infrastructure, exfiltrate "
        "data, or participate in botnet activity without network-level detection."
    ),
    # ── VULNERABILITIES ──────────────────────────────────────────────────────
    "VULN-004": (
        "During the analysis of the Vulnerabilities service, it was identified that {count} "
        "ACTIVE Inspector finding(s) have exploitAvailable=YES. Specifically, {resources} "
        "are affected by CVEs where AWS Inspector reports exploit availability.\n\n"
        "This situation raises remediation priority, but the severity and exploit path must "
        "remain aligned with Inspector severity and any separate network reachability evidence."
    ),
    "VULN-006": (
        "During the analysis of the Vulnerabilities service, it was identified that {count} "
        "resource(s) have high-severity vulnerabilities pending remediation. Specifically, "
        "{resources} have not received security patches within the recommended timeframe.\n\n"
        "This situation implies that the window of exposure for known vulnerabilities "
        "extends beyond acceptable risk thresholds, giving attackers prolonged opportunity "
        "to exploit documented weaknesses."
    ),
    "VULN-008": (
        "During the analysis of the Vulnerabilities service, it was identified that {count} "
        "resource(s) have ACTIVE HIGH Inspector findings that require explicit remediation "
        "ownership, SLA tracking, or documented risk acceptance. Specifically, {resources} "
        "have active high-severity vulnerability records.\n\n"
        "This situation indicates a vulnerability-management workflow gap when the evidence "
        "does not show an assigned plan, exception, or compensating control."
    ),
    "VULN-026": (
        "During the analysis of the Vulnerabilities service, it was identified that {count} "
        "resource(s) have medium-severity unpatched vulnerabilities. Specifically, {resources} "
        "have pending patches that address known security weaknesses.\n\n"
        "This situation implies that while immediate exploitation may require additional "
        "conditions, chaining these vulnerabilities with others could enable a successful attack."
    ),
    # ── RECON ─────────────────────────────────────────────────────────────────
    "RECON-002": (
        "During the analysis of the Recon service, it was identified that {count} resource(s) "
        "expose sensitive metadata or configuration information accessible without authentication. "
        "Specifically, {resources} leak information that aids attacker reconnaissance.\n\n"
        "This situation implies that an attacker can map the environment's architecture, "
        "identify high-value targets, and plan attacks with reduced uncertainty before "
        "any exploitation attempt."
    ),
    "RECON-003": (
        "During the analysis of the Recon service, it was identified that {count} resource(s) "
        "have overly permissive read access that exposes configuration details. "
        "Specifically, {resources} allow enumeration of sensitive infrastructure information.\n\n"
        "This situation implies that the attack preparation phase is significantly accelerated "
        "for any adversary who gains initial access, reducing time-to-exploit for subsequent stages."
    ),
    "RECON-005": (
        "During the analysis of the Recon service, it was identified that {count} resource(s) "
        "expose information through public APIs or endpoints. Specifically, {resources} "
        "return sensitive data without requiring authentication.\n\n"
        "This situation implies that infrastructure reconnaissance can be performed by any "
        "internet actor without requiring any prior access to the environment."
    ),
    "RECON-007": (
        "During the analysis of the Recon service, it was identified that {count} resource(s) "
        "are internet-facing load balancers without an associated AWS WAF Web ACL. "
        "Specifically, {resources} accept internet traffic without web application firewall "
        "inspection.\n\n"
        "This situation implies that application-layer traffic reaches the load balancer "
        "without managed rule evaluation, reducing protection against common web attacks "
        "and automated abuse."
    ),
    "RECON-015": (
        "During the analysis of the Recon service, it was identified that {count} resource(s) "
        "provide unauthenticated access to account or service metadata. Specifically, {resources} "
        "expose details that should be restricted to authorized principals.\n\n"
        "This situation implies that an attacker can profile the target environment in detail "
        "before launching exploitation, significantly improving attack efficiency."
    ),
    # ── ALERTING ─────────────────────────────────────────────────────────────
    "ALRT-001": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that CloudTrail is not integrated with CloudWatch Logs. Audit events are captured "
        "but not forwarded to a centralized log group for real-time analysis.\n\n"
        "This situation implies that security events cannot trigger automated alerts, and "
        "incident detection depends entirely on manual log review — significantly increasing "
        "the mean time to detect unauthorized activity."
    ),
    "ALRT-002": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no custom EventBridge rules are configured for CloudTrail security events. "
        "Existing CloudWatch metric filters may still provide direct alarm coverage, but "
        "the EventBridge automation path is not being used for these events.\n\n"
        "This situation limits the account's ability to route security events into richer "
        "cross-service workflows such as Lambda enrichment, Security Hub ingestion, or "
        "cross-account event buses."
    ),
    "ALRT-003": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that {count} CloudWatch Metric Filter(s) exist without associated CloudWatch Alarms. "
        "Specifically, {resources} are defined but do not trigger any notifications.\n\n"
        "This situation implies that monitored log patterns generate no operational alerts, "
        "creating silent detection rules that provide no incident response value."
    ),
    "ALRT-004": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that {count} EventBridge rule(s) capture security events without SNS notification "
        "targets configured. Specifically, {resources} lack downstream notification channels.\n\n"
        "This situation implies that triggered events are processed without notifying the "
        "security team, creating blind spots in the incident notification pipeline."
    ),
    "ALRT-005": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that {count} SNS topic(s) used by security alarms have no active confirmed "
        "subscriptions. Specifically, {resources} have no endpoints receiving messages.\n\n"
        "This situation implies that alerts published to these topics are silently discarded "
        "and the security team receives no notifications in the event of an incident."
    ),
    "ALRT-006": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that {count} SNS subscription(s) remain in 'PendingConfirmation' state. "
        "Specifically, {resources} have never been confirmed by their intended recipients.\n\n"
        "This situation implies that the intended recipients of security alerts are not "
        "receiving notifications, creating an undetected gap in the alerting chain."
    ),
    "ALRT-007": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that the following critical AWS API event(s) do not appear in the configured "
        "CloudWatch metric filter patterns: {resources}.\n\n"
        "This situation implies that these specific event types may not trigger automated "
        "incident response even though other security event categories may already be covered."
    ),
    "ALRT-008": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that the CloudTrail trail is configured as single-region and does not capture API "
        "activity in other AWS regions.\n\n"
        "This situation implies that any unauthorized activity in non-monitored regions — "
        "including the creation of IAM backdoors or compute resources — remains completely "
        "invisible to the security team."
    ),
    "ALRT-009": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that the CloudWatch Log Group receiving CloudTrail events does not have Metric "
        "Filters defined for security-relevant events.\n\n"
        "This situation implies that security events stored in the log group cannot trigger "
        "automated alerts, requiring manual log analysis to detect unauthorized activity."
    ),
    "ALRT-010": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that {count} CloudWatch Alarm(s) are in 'INSUFFICIENT_DATA' state and cannot "
        "evaluate their associated metrics. Specifically, {resources} are non-functional.\n\n"
        "This situation implies that these alarms provide a false sense of monitoring coverage "
        "without delivering any actual detection capability."
    ),
    "ALRT-011": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that {count} SNS topic(s) do not have restrictive resource-based policies. "
        "Specifically, {resources} allow unauthorized principals to publish or subscribe.\n\n"
        "This situation implies that attackers could inject false alerts or suppress legitimate "
        "notifications by manipulating the notification pipeline directly."
    ),
    "ALRT-012": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured for three critical event types: ConsoleLogin, "
        "CreateUser, and StopLogging.\n\n"
        "This situation implies that unauthorized access attempts, backdoor account creation, "
        "and audit trail tampering cannot trigger automated incident response."
    ),
    "ALRT-013": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that the CloudTrail trail does not have Log File Validation enabled. Audit logs "
        "stored in S3 cannot be cryptographically verified for integrity.\n\n"
        "This situation implies that an attacker with S3 write access could alter or delete "
        "audit logs without detection, undermining the forensic value of the entire audit trail."
    ),
    "ALRT-014": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that the CloudTrail trail does not encrypt its S3 log files using a customer-managed "
        "KMS key.\n\n"
        "This situation implies that audit log data cannot be independently key-rotated or "
        "access-revoked in response to a key compromise, weakening the confidentiality of "
        "the audit trail."
    ),
    "ALRT-015": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no CloudWatch alarms or EventBridge rules are configured to detect IAM policy "
        "modifications, role changes, or MFA configuration changes.\n\n"
        "This situation implies that privilege escalation through IAM policy manipulation "
        "could go completely undetected during the window of attack."
    ),
    "ALRT-016": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured to detect Security Group rule changes "
        "(AuthorizeSecurityGroupIngress, RevokeSecurityGroupIngress).\n\n"
        "This situation implies that an attacker with IAM permissions could open network "
        "access to sensitive resources without triggering any immediate notification."
    ),
    "ALRT-017": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that {count} CloudWatch Log Group(s) retain logs for less than 90 days. "
        "Specifically, {resources} have retention periods below the minimum review baseline.\n\n"
        "This situation reduces the forensic window available for incident investigation "
        "and may cause audit evidence to expire before security or compliance teams can use it."
    ),
    "ALRT-022": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured to detect S3 bucket policy or ACL changes.\n\n"
        "This situation implies that unauthorized modifications that expose sensitive data "
        "publicly could occur without triggering any security notification."
    ),
    "ALRT-023": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured to detect changes to CloudTrail configuration.\n\n"
        "This situation implies that an attacker disabling, modifying, or deleting the audit "
        "trail would not trigger an immediate alert, allowing the action to go unnoticed."
    ),
    "ALRT-024": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured for AWS Config rule compliance changes.\n\n"
        "This situation implies that when resources drift from their compliant configuration, "
        "no automated notification reaches the team responsible for remediation."
    ),
    "ALRT-025": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured to detect VPC changes (VPC creation, deletion, or "
        "modification of internet gateways and route tables).\n\n"
        "This situation implies that unauthorized infrastructure modifications affecting "
        "network boundaries could be performed without triggering detection."
    ),
    "ALRT-026": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured to detect root account usage.\n\n"
        "This situation implies that any use of the most privileged account in the environment "
        "— authorized or not — passes without generating an immediate security notification."
    ),
    "ALRT-027": (
        "During the analysis of the alerting and monitoring configuration, it was identified "
        "that no alerts are configured to detect KMS key deletion or disablement events.\n\n"
        "This situation implies that actions that could permanently destroy encrypted data "
        "or disrupt critical workloads dependent on KMS keys would not trigger immediate "
        "incident response."
    ),
    # ── HARDENING ─────────────────────────────────────────────────────────────
    "HRD-001": (
        "During the analysis of the account hardening configuration, it was identified that "
        "AWS Config is not enabled in the audited region. No configuration change recording "
        "or compliance evaluation is taking place.\n\n"
        "This situation implies that unauthorized infrastructure changes are not tracked, "
        "resource compliance cannot be evaluated automatically, and forensic investigation "
        "of configuration drift is not possible."
    ),
    "HRD-002": (
        "During the analysis of the account hardening configuration, it was identified that "
        "AWS Security Hub is not enabled. No aggregation of security findings from Inspector, "
        "GuardDuty, Config, or Macie is taking place.\n\n"
        "This situation implies that the security posture of the account cannot be assessed "
        "holistically, and findings from individual services remain siloed without "
        "consolidated prioritization."
    ),
    "HRD-003": (
        "During the analysis of the account hardening configuration, it was identified that "
        "no compliance standards (FSBP, CIS AWS Foundations, PCI DSS) are enabled in "
        "AWS Security Hub.\n\n"
        "This situation implies that automated compliance checks against industry frameworks "
        "are not running, making it impossible to identify deviations from security baselines "
        "without manual review."
    ),
    "HRD-004": (
        "During the analysis of the account hardening configuration, it was identified that "
        "the overall Security Hub compliance score is below 50%, indicating that the majority "
        "of security controls fail their compliance checks.\n\n"
        "This situation implies that the account's security posture is severely deficient "
        "across multiple domains, significantly increasing the probability of successful "
        "exploitation."
    ),
    "HRD-005": (
        "During the analysis of the account hardening configuration, it was identified that "
        "{count} CRITICAL severity findings in AWS Security Hub remain unresolved. "
        "Specifically, {resources} represent unmitigated critical risks.\n\n"
        "This situation implies that known, high-impact security vulnerabilities remain "
        "exploitable, and the organization has not prioritized their remediation despite "
        "their critical severity classification."
    ),
    "HRD-006": (
        "During the analysis of the account hardening configuration, it was identified that "
        "AWS Config is enabled but {count} recorder(s) are not in 'RECORDING' state. "
        "Specifically, {resources} are configured but not actively capturing changes.\n\n"
        "This situation implies that configuration changes are not being recorded despite "
        "the service being provisioned, creating gaps in the compliance and audit trail."
    ),
    "HRD-007": (
        "During the analysis of the account hardening configuration, it was identified that "
        "the PCI DSS compliance standard is not enabled in AWS Security Hub for an account "
        "that processes or stores payment card data.\n\n"
        "This situation implies that automated PCI DSS control verification is not running, "
        "leaving compliance gaps undetected and increasing the risk of audit failure."
    ),
    "HRD-008": (
        "During the analysis of the account hardening configuration, it was identified that "
        "the Security Hub compliance score is between 50% and 70%, indicating significant "
        "gaps in the security baseline.\n\n"
        "This situation implies that a substantial portion of security controls are failing, "
        "leaving the account exposed across multiple risk domains simultaneously."
    ),
    "HRD-009": (
        "During the analysis of the account hardening configuration, it was identified that "
        "more than 10 HIGH severity Security Hub findings remain unresolved. Specifically, "
        "{count} HIGH findings are pending remediation.\n\n"
        "This situation implies that the accumulation of high-severity unresolved findings "
        "represents a broad, unmitigated attack surface across multiple services and controls."
    ),
    "HRD-010": (
        "During the analysis of the account hardening configuration, it was identified that "
        "no AWS Config Conformance Packs are configured. No automated compliance framework "
        "validation is being applied to the account.\n\n"
        "This situation implies that compliance with organizational policies or regulatory "
        "frameworks cannot be validated automatically, requiring entirely manual audit processes."
    ),
    "HRD-011": (
        "During the analysis of the account hardening configuration, it was identified that "
        "the Security Hub compliance score is between 70% and 85%, indicating a moderately "
        "strong but improvable security posture.\n\n"
        "This situation implies that a meaningful portion of security controls are failing "
        "and represent residual risk that should be addressed before the next audit cycle."
    ),
    "HRD-012": (
        "During the analysis of the account hardening configuration, it was identified that "
        "more than 20 MEDIUM severity Security Hub findings remain unresolved. Specifically, "
        "{count} MEDIUM findings are pending remediation.\n\n"
        "This situation implies that a large volume of medium-risk issues creates a broad "
        "attack surface that, while individually less severe, collectively represents "
        "significant organizational risk."
    ),
    "HRD-013": (
        "During the analysis of the account hardening configuration, it was identified that "
        "{count} compliance standard(s) in Security Hub are running outdated versions. "
        "Specifically, {resources} use deprecated standard versions.\n\n"
        "This situation implies that new controls added to updated framework versions are not "
        "being evaluated, potentially leaving recently discovered security gaps unchecked."
    ),
    "HRD-014": (
        "During the analysis of the account hardening configuration, it was identified that "
        "Amazon GuardDuty is not enabled in the audited region. No GuardDuty detector is "
        "present to analyze CloudTrail, DNS, VPC Flow Log, EKS, or runtime signals for "
        "threat activity.\n\n"
        "This situation implies that AWS-native threat detection coverage is missing for "
        "the account, delaying discovery of compromised credentials, reconnaissance, "
        "malicious network activity, or suspicious workload behavior."
    ),
    "HRD-015": (
        "During the analysis of the account hardening configuration, it was identified that "
        "the Security Hub compliance score is between 85% and 95%, indicating a strong but "
        "not fully compliant security posture.\n\n"
        "This situation implies that a small but non-trivial set of security controls are "
        "failing and should be remediated to achieve full compliance with the configured "
        "standards."
    ),
    "HRD-016": (
        "During the analysis of the account hardening configuration, it was identified that "
        "{count} LOW severity Security Hub finding(s) remain unresolved. Specifically, "
        "{resources} represent low-priority but pending security improvements.\n\n"
        "This situation implies that while individually low-risk, unresolved low-severity "
        "findings may contribute to audit findings and indicate a lack of systematic "
        "remediation discipline."
    ),
    # ── EXPOSURE (remaining) ─────────────────────────────────────────────────
    "EXP-001": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} S3 bucket(s) are publicly accessible and may contain sensitive data. "
        "Specifically, {resources} have public ACLs or bucket policies without Block Public "
        "Access controls enabled.\n\n"
        "This situation implies that any data stored in these buckets — including backups, "
        "PII, or application data — is readable by any anonymous internet user without "
        "authentication."
    ),
    "EXP-002": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} RDS instance(s) are directly accessible from the internet with permissive "
        "Security Groups. Specifically, {resources} have PubliclyAccessible=true and "
        "allow inbound database traffic from 0.0.0.0/0.\n\n"
        "This situation implies that the database engine is directly reachable from the "
        "internet, removing the network-layer barrier and exposing the authentication layer "
        "to brute-force and exploitation attacks."
    ),
    "EXP-003": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} Security Group(s) allow unrestricted access to SSH (port 22) or RDP "
        "(port 3389) from 0.0.0.0/0. Specifically, {resources} permit remote administration "
        "from any internet source.\n\n"
        "This situation implies that administrative access to the associated instances is "
        "exposed to the entire internet, enabling brute-force, credential stuffing, and "
        "exploitation of remote access vulnerabilities."
    ),
    "EXP-004": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} EC2 instance(s) have public IP addresses with Security Groups allowing "
        "access to management or database ports. Specifically, {resources} expose ports "
        "22, 3389, 3306, or 5432 to internet traffic.\n\n"
        "This situation implies that sensitive services — remote administration and database "
        "engines — are reachable from the global internet, significantly expanding the "
        "attack surface."
    ),
    "EXP-005": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} Lambda Function URL(s) are exposed without authentication (AuthType=NONE) "
        "and handle potentially sensitive application logic. Specifically, {resources} "
        "accept unauthenticated HTTP requests.\n\n"
        "This situation implies that the function's business logic and any data it accesses "
        "are reachable by any internet actor without requiring AWS credentials or API keys."
    ),
    "EXP-010": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} Application Load Balancer(s) support deprecated TLS versions (1.0 or 1.1). "
        "Specifically, {resources} have listener policies that accept connections using "
        "cryptographically weak TLS versions.\n\n"
        "This situation implies that clients connecting via TLS 1.0/1.1 are vulnerable to "
        "known protocol downgrade and decryption attacks such as BEAST and POODLE."
    ),
    "EXP-011": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} S3 bucket(s) allow public object listing via the s3:ListBucket permission. "
        "Specifically, {resources} permit anonymous enumeration of all stored objects.\n\n"
        "This situation implies that an attacker can discover every object stored in these "
        "buckets without authentication, enabling targeted data exfiltration attempts against "
        "known object paths."
    ),
    "EXP-014": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} audit or log S3 bucket(s) do not have versioning enabled. Specifically, "
        "{resources} store audit logs without protection against deletion or overwriting.\n\n"
        "This situation implies that an attacker with S3 write access could permanently "
        "delete or overwrite audit logs, destroying forensic evidence without the ability "
        "to recover previous versions."
    ),
    "EXP-015": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} S3 bucket policy statement(s) allow public or cross-account principals without "
        "effective restrictive security conditions. Specifically, {resources} use bare principals "
        "or malformed conditions such as an empty aws:PrincipalOrgID value.\n\n"
        "This situation implies that bucket access is not reliably constrained to the intended "
        "AWS account or organization boundary."
    ),
    "EXP-016": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} Lambda Function URL(s) are configured with AuthType=NONE. Specifically, "
        "{resources} accept HTTP requests from any source without requiring authentication.\n\n"
        "This situation implies that these Lambda functions — and any AWS services or data "
        "they access — are reachable by any internet actor without credentials."
    ),
    "EXP-020": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} CloudFront distribution(s) serve content from S3 origins without Origin "
        "Access Control (OAC) configured. Specifically, {resources} allow the S3 bucket "
        "to be accessed directly, bypassing CloudFront controls.\n\n"
        "This situation implies that the S3 bucket can be accessed directly without going "
        "through CloudFront's security policies, geo-restrictions, or signed URL enforcement."
    ),
    "EXP-021": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} API Gateway route(s) expose mutation methods (POST, PUT, PATCH, DELETE) "
        "without authentication configured. Specifically, {resources} accept write operations "
        "from unauthenticated callers.\n\n"
        "This situation implies that any internet actor can modify, create, or delete "
        "application data through these endpoints without requiring any form of "
        "authentication or authorization."
    ),
    "EXP-022": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} API Gateway route(s) use catch-all patterns (ANY or {proxy+}) without "
        "authorization controls. Specifically, {resources} forward all HTTP methods to "
        "the backend without authentication.\n\n"
        "This situation implies that the entire API surface, including all HTTP methods "
        "and paths matching the wildcard, is accessible to unauthenticated internet actors."
    ),
    "EXP-023": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} resource-based policy(ies) use unrestricted Principal:* grants. "
        "Specifically, {resources} (SQS, SNS, Secrets Manager, ECR, or OpenSearch) allow "
        "actions by any AWS principal.\n\n"
        "This situation implies that these resources can be accessed by any authenticated "
        "AWS identity — including identities from other accounts — without requiring "
        "explicit authorization from the resource owner."
    ),
    "EXP-024": (
        "During the analysis of the resource exposure configuration, it was identified that "
        "{count} audit or log S3 bucket(s) do not use customer-managed KMS encryption. "
        "Specifically, {resources} use AES256 (AWS-managed) encryption rather than a "
        "customer-managed CMK.\n\n"
        "This situation implies that the organization cannot independently control, rotate, "
        "or revoke access to the encryption keys protecting audit log data."
    ),
    # ── CICD ──────────────────────────────────────────────────────────────────
    "CICD-001": (
        "During the analysis of the CI/CD pipeline configuration (CodeBuild), it was "
        "identified that source credentials are configured in CodeBuild projects. "
        "Specifically, {resources} store VCS tokens or credentials within the build "
        "service configuration.\n\n"
        "This situation implies that these credentials are accessible to any principal "
        "with read access to the CodeBuild configuration and could be extracted by a "
        "malicious build step or compromised pipeline."
    ),
    "CICD-002": (
        "During the analysis of the CI/CD pipeline configuration (CodeBuild), it was "
        "identified that {count} CodeBuild project(s) have insecure SSL settings or "
        "proxy configurations that allow traffic interception. Specifically, {resources} "
        "have insecureSSL=true or non-validated proxy settings.\n\n"
        "This situation implies that build traffic — including downloaded dependencies "
        "and uploaded artifacts — could be intercepted and modified by a man-in-the-middle "
        "attacker during the build process."
    ),
    # ── COMPUTE ───────────────────────────────────────────────────────────────
    "COMP-EC2-001": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} EC2 instance(s) allow IMDSv1 (Instance Metadata Service v1) access and "
        "have an instance profile attached. Specifically, {resources} do not require "
        "IMDSv2 token-based requests (HttpTokens=optional).\n\n"
        "This situation implies that an SSRF vulnerability in any application running on "
        "these instances can be exploited to steal IAM credentials from the instance "
        "metadata endpoint without requiring any additional authentication."
    ),
    "COMP-EC2-002": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} EC2 instance(s) have user-data scripts containing patterns associated "
        "with hardcoded credentials or remote bootstrap risks. Specifically, {resources} "
        "have user-data with potential secrets or untrusted remote execution patterns.\n\n"
        "This situation implies that sensitive credentials or malicious code could be "
        "injected at instance launch time, compromising the instance from its first boot "
        "if the user-data is tampered with or contains hardcoded secrets."
    ),
    "COMP-ECS-001": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} EventBridge rule(s) are configured to launch ECS tasks on a schedule. "
        "Specifically, {resources} trigger container workloads via automated scheduling.\n\n"
        "This situation implies that an attacker with EventBridge write access could "
        "modify these rules to execute malicious container images or alter task parameters, "
        "establishing persistence through the scheduled task mechanism."
    ),
    "COMP-ECS-002": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} ECS task definition(s) show configuration drift with unexpected containers "
        "or parameter changes. Specifically, {resources} contain modifications not aligned "
        "with the expected baseline.\n\n"
        "This situation implies that unauthorized container images or configurations may "
        "be running in the environment, potentially introducing backdoors or data "
        "exfiltration capabilities within the container workload."
    ),
    "COMP-ECS-003": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} ECS task definition(s) or service(s) lack centralized logging "
        "configuration. Specifically, {resources} do not have CloudWatch Logs configured "
        "as the log driver.\n\n"
        "This situation implies that application activity and security events from these "
        "containers are not captured centrally, making forensic investigation after an "
        "incident significantly more difficult."
    ),
    "COMP-ECS-004": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} ECS task role(s) or execution role(s) appear overly permissive. "
        "Specifically, {resources} have wildcard actions or broad resource access in "
        "their IAM policies.\n\n"
        "This situation implies that a compromised container running under these roles "
        "can access AWS services and data far beyond what its operational function requires, "
        "maximizing the blast radius of a container escape or application compromise."
    ),
    "COMP-ECS-005": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} ECS task definition(s) contain plaintext credentials in environment "
        "variables. Specifically, {resources} have hardcoded secrets in their container "
        "definitions.\n\n"
        "This situation implies that anyone with access to the ECS task definition — "
        "including via the AWS console, API, or compromised CI/CD pipeline — can retrieve "
        "these credentials without requiring access to a secrets management system."
    ),
    "COMP-EKS-001": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} EKS cluster(s) have a publicly accessible API endpoint without IP "
        "allowlist restrictions. Specifically, {resources} allow connections to the "
        "Kubernetes API server from any IP address.\n\n"
        "This situation implies that the Kubernetes control plane is reachable from the "
        "entire internet, exposing it to credential brute-force and exploitation of any "
        "API server vulnerabilities."
    ),
    "COMP-EKS-002": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} EKS cluster(s) do not have all control-plane logging types enabled. "
        "Specifically, {resources} are missing audit, API, or authenticator log streams.\n\n"
        "This situation implies that Kubernetes control-plane events — including "
        "authentication attempts, RBAC decisions, and API calls — are not captured, "
        "making forensic investigation after a cluster compromise incomplete."
    ),
    "COMP-LMB-001": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} Lambda Function URL(s) are publicly accessible without authentication. "
        "Specifically, {resources} have AuthType=NONE and accept requests from any source.\n\n"
        "This situation implies that the function's logic and any AWS resources it accesses "
        "are exposed to unauthenticated internet traffic, enabling unauthorized invocation "
        "and potential abuse of the function's IAM role permissions."
    ),
    "COMP-LMB-002": (
        "During the analysis of the compute service configuration, it was identified that "
        "{count} Lambda execution role(s) appear over-privileged. Specifically, {resources} "
        "have AdministratorAccess or wildcard action grants that far exceed the function's "
        "operational requirements.\n\n"
        "This situation implies that a successful exploitation of the Lambda function — "
        "through code injection, event manipulation, or dependency compromise — grants the "
        "attacker broad control over the AWS account."
    ),
    # ── ECR ───────────────────────────────────────────────────────────────────
    "ECR-001": (
        "During the analysis of the ECR container registry configuration, it was identified "
        "that {count} repository policy(ies) use wildcard principals (Principal:*), making "
        "them publicly accessible. Specifically, {resources} can be pulled by any AWS "
        "identity without restriction.\n\n"
        "This situation implies that proprietary container images — including their embedded "
        "configurations, secrets, and application code — can be downloaded by any "
        "authenticated AWS account globally."
    ),
    "ECR-002": (
        "During the analysis of the ECR container registry configuration, it was identified "
        "that {count} repository(ies) have mutable image tags (ImageTagMutability=MUTABLE). "
        "Specifically, {resources} allow existing tags to be overwritten with different images.\n\n"
        "This situation implies that a compromised CI/CD pipeline or unauthorized user could "
        "silently replace a production image tag with a malicious image, enabling supply "
        "chain attacks without requiring the creation of new tags."
    ),
    "ECR-003": (
        "During the analysis of the ECR container registry configuration, it was identified "
        "that {count} repository(ies) do not have image scanning on push enabled. "
        "Specifically, {resources} allow unscanned images to be stored and deployed.\n\n"
        "This situation implies that container images with known CVEs can be pushed and "
        "deployed to production without any automated vulnerability gate, extending the "
        "window of exposure for vulnerable workloads."
    ),
    "ECR-004": (
        "During the analysis of the ECR container registry configuration, it was identified "
        "that no registry-level scanning configuration is defined. Vulnerability scanning "
        "is not systematically applied across all repositories.\n\n"
        "This situation implies that image security assessment is either absent or applied "
        "inconsistently, leaving some repositories without any vulnerability detection "
        "capability."
    ),
    "ECR-005": (
        "During the analysis of the ECR container registry configuration, it was identified "
        "that {count} repository(ies) use AWS-managed encryption keys instead of "
        "customer-managed KMS keys (CMK). Specifically, {resources} do not use CMK encryption.\n\n"
        "This situation implies that the organization cannot independently control or revoke "
        "access to the encryption keys protecting container image data stored in ECR."
    ),
    "ECR-006": (
        "During the analysis of the ECR container registry configuration, it was identified "
        "that {count} repository(ies) do not have lifecycle policies configured. Specifically, "
        "{resources} retain all image versions indefinitely without automated cleanup.\n\n"
        "This situation implies that outdated images with unpatched vulnerabilities remain "
        "available for deployment indefinitely, and the registry accumulates stale images "
        "that increase storage costs and the attack surface."
    ),
    "ECR-007": (
        "During the analysis of the ECR container registry configuration, it was identified "
        "that {count} repository(ies) grant cross-account access in their resource policies. "
        "Specifically, {resources} allow principals from external accounts to pull or "
        "push images.\n\n"
        "This situation implies that a compromise in any trusted external account could "
        "result in unauthorized access to proprietary container images or the injection "
        "of malicious images into the registry."
    ),
    # ── IAM (remaining) ───────────────────────────────────────────────────────
    "IAM-015": (
        "During the analysis of the IAM service, it was identified that {count} IAM user(s) "
        "have permissions attached directly rather than inherited through groups. Specifically, "
        "{resources} have inline or managed policies directly attached to the user object.\n\n"
        "This situation implies that permission management is decentralized and harder to "
        "audit, increasing the risk of permission drift and making access reviews significantly "
        "more complex."
    ),
    "IAM-016": (
        "During the analysis of the IAM service, it was identified that {count} IAM user(s) "
        "use programmatic-only long-lived access keys with no console password. "
        "Specifically, {resources} match a service-account pattern or require manual review "
        "because they use access keys instead of role-based temporary credentials.\n\n"
        "This situation implies that these identities carry long-lived credential exposure "
        "risk. Where the identity is used by an AWS workload, IAM roles would provide "
        "short-lived, automatically rotated credentials tied to the resource's identity."
    ),
    "IAM-018": (
        "During the analysis of the IAM service, it was identified that the account password "
        "policy does not enforce a maximum password age. Passwords are permitted to remain "
        "valid indefinitely without mandatory rotation.\n\n"
        "This situation implies that compromised passwords remain usable without expiry, "
        "giving attackers an unlimited window of access once credentials are obtained through "
        "phishing, credential stuffing, or data breaches."
    ),
    "IAM-019": (
        "During the analysis of the IAM service, it was identified that the account password "
        "policy does not require symbol characters. Passwords can be composed entirely of "
        "alphanumeric characters.\n\n"
        "This situation implies that the password character space is reduced, making "
        "brute-force and dictionary attacks more computationally feasible against "
        "console credentials."
    ),
    "IAM-026": (
        "During the analysis of the IAM service, it was identified that {count} IAM role(s) "
        "do not have permission boundaries configured. Specifically, {resources} can receive "
        "additional permissions without a boundary defining the maximum allowed privilege.\n\n"
        "This situation implies that future policy changes or compromised deployment paths have "
        "fewer guardrails, especially for privileged roles or roles with IAM policy-manipulation "
        "actions such as AdministratorAccess or iam:PassRole."
    ),
    "IAM-034": (
        "During the analysis of the IAM service, it was identified that {count} IAM "
        "policy(ies) grant permissions to modify identity provider configurations "
        "(UpdateSAMLProvider, UpdateOpenIDConnectProvider). Specifically, {resources} "
        "allow mutation of federated identity sources.\n\n"
        "This situation implies that an attacker with these permissions could redirect "
        "authentication to a malicious identity provider, enabling them to authenticate "
        "as any federated user without valid credentials."
    ),
    "IAM-035": (
        "During the analysis of the IAM service, it was identified that {count} IAM "
        "policy(ies) allow IAM policy version escalation via CreatePolicyVersion or "
        "SetDefaultPolicyVersion. Specifically, {resources} can create and activate "
        "new policy versions.\n\n"
        "This situation implies that an attacker with these permissions can escalate "
        "privileges by creating a new permissive policy version and setting it as default, "
        "without modifying the existing policy document."
    ),
    "IAM-036": (
        "During the analysis of the IAM service, it was identified that {count} IAM "
        "policy(ies) allow broad manipulation of service-specific credentials "
        "(CreateServiceSpecificCredential, ResetServiceSpecificCredential). Specifically, "
        "{resources} can create or reset credentials for AWS service integrations.\n\n"
        "This situation implies that an attacker with these permissions can generate "
        "alternative access credentials to AWS services (such as CodeCommit or Keyspaces) "
        "that bypass IAM key rotation policies."
    ),
    "IAM-037": (
        "During the analysis of the IAM service, it was identified that {count} IAM "
        "policy(ies) grant permissions to manipulate MFA devices (EnableMFADevice, "
        "DeactivateMFADevice) for any user. Specifically, {resources} allow MFA "
        "device management without resource-level restrictions.\n\n"
        "This situation implies that an attacker with these permissions can deactivate "
        "MFA on any user account, including administrators, bypassing the multi-factor "
        "authentication requirement."
    ),
    "IAM-038": (
        "During the analysis of the IAM service, it was identified that {count} IAM "
        "policy(ies) grant wildcard IAM delete permissions (iam:Delete*). Specifically, "
        "{resources} allow deletion of any IAM resource without resource-level restrictions.\n\n"
        "This situation implies that an attacker with these permissions can delete IAM "
        "users, roles, policies, and MFA devices, potentially destroying access controls "
        "and covering tracks by removing audit-relevant identities."
    ),
    "IAM-039": (
        "During the analysis of the IAM service, it was identified that {count} IAM "
        "policy(ies) grant permissions to detach or delete authorization controls "
        "(DetachUserPolicy, DetachRolePolicy, DeletePolicyVersion). Specifically, "
        "{resources} allow removal of access restrictions from any identity.\n\n"
        "This situation implies that an attacker with these permissions can remove "
        "restrictive policies from their own or other identities, achieving privilege "
        "escalation by subtracting access controls rather than adding permissions."
    ),
    "IAM-044": (
        "During the analysis of the IAM service, it was identified that {count} privileged "
        "or SSO role(s) have a MaxSessionDuration exceeding 1 hour (3600 seconds). "
        "Specifically, {resources} allow sessions lasting up to several hours.\n\n"
        "This situation implies that a stolen session token for these roles remains valid "
        "for an extended period, providing an attacker with a larger window to perform "
        "unauthorized actions before the credential naturally expires."
    ),
    # ── KMS ───────────────────────────────────────────────────────────────────
    "KMS-001": (
        "During the analysis of the KMS key management configuration, it was identified "
        "that {count} KMS key policy(ies) use wildcard or overly broad principal grants. "
        "Specifically, {resources} allow key operations by any AWS principal or across "
        "account boundaries without restriction.\n\n"
        "This situation implies that any AWS identity satisfying the broad principal "
        "condition can use these keys to decrypt sensitive data, even if they are not "
        "the intended consumers of the protected data."
    ),
    "KMS-002": (
        "During the analysis of the KMS key management configuration, it was identified "
        "that {count} KMS key(s) have grants allowing Decrypt or GenerateDataKey operations "
        "to unexpected principals. Specifically, {resources} have grants with sensitive "
        "cryptographic permissions.\n\n"
        "This situation implies that principals holding these grants can decrypt protected "
        "data without going through the key policy, and grants can persist even if the "
        "key policy is later restricted."
    ),
    "KMS-003": (
        "During the analysis of the KMS key management configuration, it was identified "
        "that {count} principal(s) have permissions to modify KMS key policies or create "
        "grants (PutKeyPolicy, CreateGrant). Specifically, {resources} can alter the "
        "access controls of encryption keys.\n\n"
        "This situation implies that a compromised identity with these permissions can "
        "grant itself or others decryption access to any data protected by these keys, "
        "bypassing all existing access restrictions."
    ),
    "KMS-004": (
        "During the analysis of the KMS key management configuration, it was identified "
        "that {count} customer-managed KMS key(s) do not have automatic key rotation "
        "enabled. Specifically, {resources} use static key material that never rotates.\n\n"
        "This situation implies that if the key material is ever compromised, all data "
        "encrypted with that key remains permanently exposed until re-encrypted with a "
        "new key — a process that may require significant operational effort."
    ),
    "KMS-005": (
        "During the analysis of the KMS key management configuration, it was identified "
        "that {count} principal(s) have permissions to perform destructive KMS actions "
        "(DisableKey, ScheduleKeyDeletion). Specifically, {resources} can render "
        "encryption keys permanently unavailable.\n\n"
        "This situation implies that a malicious or compromised identity can make "
        "protected data permanently inaccessible by disabling or scheduling deletion "
        "of the encryption keys, constituting a potential ransomware-equivalent threat."
    ),
    "KMS-006": (
        "During the analysis of the KMS key management configuration, it was identified "
        "that {count} KMS key(s) use imported key material (EXTERNAL origin) with the "
        "DeleteImportedKeyMaterial permission granted to external principals. Specifically, "
        "{resources} allow external parties to delete imported key material.\n\n"
        "This situation implies that a third party with this permission can destroy the "
        "key material, making all data encrypted with this key permanently inaccessible "
        "without advance warning."
    ),
    "KMS-007": (
        "During the analysis of the KMS key management configuration, it was identified "
        "that {count} KMS grant(s) include the CreateGrant permission, enabling grant "
        "delegation. Specifically, {resources} allow grantees to create additional grants "
        "for the same key.\n\n"
        "This situation implies that the original grant can be propagated to additional "
        "principals indefinitely, creating a chain of access that extends beyond the "
        "intended scope and is difficult to fully revoke."
    ),
    # ── MESSAGING ─────────────────────────────────────────────────────────────
    "MSG-001": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SQS queue policy(ies) use aws:PrincipalOrgID as the sole access control "
        "condition. Specifically, {resources} grant access to any principal in the "
        "entire AWS Organization.\n\n"
        "This situation implies that any identity in any account within the organization "
        "— including potentially compromised accounts — can send, receive, or delete "
        "messages from these queues."
    ),
    "MSG-002": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SQS queue(s) have RedrivePolicy configurations that could enable "
        "DLQ-based data exfiltration. Specifically, {resources} route failed messages "
        "to Dead Letter Queues without adequate access controls.\n\n"
        "This situation implies that messages containing sensitive application data "
        "could accumulate in DLQs accessible to broader principals, enabling passive "
        "data exfiltration through the error handling pipeline."
    ),
    "MSG-003": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SNS-to-SQS subscription(s) have permissive policies that could enable "
        "message injection. Specifically, {resources} lack Source account or SNS ARN "
        "conditions on the queue policy.\n\n"
        "This situation implies that any SNS topic — including those in attacker-controlled "
        "accounts — could deliver messages to these queues, potentially injecting malicious "
        "payloads into the application processing pipeline."
    ),
    "MSG-004": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SQS queue(s) support message move tasks (StartMessageMoveTask) without "
        "monitoring or alerting configured. Specifically, {resources} allow DLQ message "
        "movements without detection.\n\n"
        "This situation implies that messages containing sensitive data could be moved "
        "from dead letter queues to attacker-controlled destinations without triggering "
        "any security notification."
    ),
    "MSG-005": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SQS queue policy(ies) use Principal:* for data-plane operations "
        "(SendMessage, ReceiveMessage, DeleteMessage). Specifically, {resources} allow "
        "any AWS identity to interact with queue data.\n\n"
        "This situation implies that these queues can be read or written by any "
        "authenticated AWS identity globally, enabling unauthorized access to application "
        "messages and potential data exfiltration."
    ),
    "MSG-006": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SQS queue(s) do not have encryption at rest enabled. Specifically, "
        "{resources} store messages without KMS encryption.\n\n"
        "This situation implies that messages stored in these queues — which may contain "
        "sensitive application data, PII, or credentials — are not protected against "
        "unauthorized access at the storage layer."
    ),
    "MSG-007": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SNS topic policy(ies) allow unrestricted subscribe operations to "
        "external principals. Specifically, {resources} permit any identity to subscribe "
        "to receive topic notifications.\n\n"
        "This situation implies that an unauthorized actor could subscribe an attacker-"
        "controlled endpoint to receive all messages published to these topics, enabling "
        "passive interception of notification data."
    ),
    "MSG-008": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SNS topic policy(ies) allow unrestricted publish operations. Specifically, "
        "{resources} accept message publications from any AWS principal without restriction.\n\n"
        "This situation implies that an attacker with any level of AWS access could inject "
        "arbitrary messages into these topics, potentially triggering downstream processing "
        "logic or delivering malicious payloads to subscribers."
    ),
    "MSG-009": (
        "During the analysis of the messaging services (SQS/SNS), it was identified that "
        "{count} SNS topic policy(ies) grant administrative actions (DeleteTopic, "
        "SetTopicAttributes) to wildcard principals. Specifically, {resources} allow "
        "any identity to modify or delete the topic.\n\n"
        "This situation implies that an attacker with any AWS access could delete "
        "notification topics or modify their configuration, disrupting the alerting "
        "and notification infrastructure."
    ),
    # ── NETWORK (remaining) ───────────────────────────────────────────────────
    "NET-001": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group(s) allow unrestricted access from 0.0.0.0/0 to "
        "sensitive ports (SSH, RDP, database ports). Specifically, {resources} permit "
        "inbound traffic on management or data ports from any internet source.\n\n"
        "This situation implies that the services listening on these ports are directly "
        "exposed to the entire internet, enabling brute-force attacks, exploitation of "
        "service vulnerabilities, and unauthorized access attempts."
    ),
    "NET-002": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group(s) allow all traffic (protocol -1) from 0.0.0.0/0. "
        "Specifically, {resources} have rules that permit every port and protocol from "
        "any internet source.\n\n"
        "This situation implies that no network-layer filtering is applied to the "
        "associated resources, effectively removing the Security Group as a defense-"
        "in-depth control."
    ),
    "NET-003": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Network ACL(s) have ALLOW ALL rules that do not restrict traffic. "
        "Specifically, {resources} have subnet-level rules permitting all inbound or "
        "outbound traffic.\n\n"
        "This situation implies that NACLs are not providing meaningful stateless "
        "filtering for the associated subnets. Security Groups may still restrict "
        "resource access, so the proven issue is loss of a defense-in-depth layer rather "
        "than direct compromise by the NACL rule alone."
    ),
    "NET-004": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} subnet(s) hosting sensitive resources have a default route "
        "(0.0.0.0/0) pointing directly to an Internet Gateway. Specifically, {resources} "
        "are routed to the internet despite their sensitive classification.\n\n"
        "This situation implies that resources in these subnets are directly reachable "
        "from the internet, eliminating the network isolation that private subnets are "
        "designed to provide."
    ),
    "NET-005": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} VPC(s) have the default Security Group with rules allowing "
        "unrestricted traffic. Specifically, {resources} have non-empty default Security "
        "Group rules that should be empty by default.\n\n"
        "This situation implies that resources inadvertently placed in the default Security "
        "Group receive no network isolation, as all inbound and outbound traffic is permitted "
        "by default rules."
    ),
    "NET-006": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} VPC(s) do not have VPC Flow Logs enabled. Specifically, {resources} "
        "do not capture network traffic metadata for security analysis.\n\n"
        "This situation implies that network-level forensic investigation after a security "
        "incident is not possible, as there is no record of traffic patterns, connection "
        "attempts, or data transfer volumes."
    ),
    "NET-008": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} critical workload(s) are deployed in public subnets. Specifically, "
        "{resources} are associated with subnets that have a route to an Internet Gateway.\n\n"
        "This situation implies that sensitive services are closer to direct internet "
        "exposure than expected for a private workload. If the resource or its Security "
        "Group also permits public access, the workload can become reachable from "
        "untrusted networks without an additional subnet-routing change."
    ),
    "NET-009": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group rule(s) allow broad CIDR ranges to non-web ports. "
        "Specifically, {resources} permit access from /16-or-larger networks to services "
        "that should normally be scoped to precise peers.\n\n"
        "This situation implies that lateral movement or unauthorized access from broad "
        "network ranges is easier than necessary because network access is not limited "
        "to the smallest practical source set."
    ),
    "NET-010": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} default Network ACL(s) contain allow-all rules for 0.0.0.0/0. "
        "Specifically, {resources} rely on default permissive NACL behavior.\n\n"
        "This situation implies that subnet-level stateless filtering is not providing "
        "a restrictive guardrail, so traffic control depends mostly on Security Groups "
        "and routing. This is a segmentation hardening gap, not proof of direct resource "
        "reachability on its own."
    ),
    "NET-011": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group(s) have critical ingress or egress rules without "
        "descriptions. Specifically, {resources} contain sensitive-port or all-protocol "
        "rules that are not documented at the rule level.\n\n"
        "This situation implies that reviewers cannot reliably distinguish intentional "
        "business access from accidental exposure, increasing the chance that risky "
        "rules persist unnoticed."
    ),
    "NET-013": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} private route table(s) send default outbound traffic through NAT "
        "Gateway routes while no VPC endpoints are present in the collected evidence. "
        "Specifically, {resources} rely on NAT for private subnet egress.\n\n"
        "This situation implies that AWS service access from those private subnets cannot "
        "use endpoint policies or private endpoint routing controls unless endpoints are "
        "added. The evidence proves a network design hardening gap, not observed sensitive "
        "service traffic."
    ),
    "NET-012": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group(s) reference themselves as a source, creating "
        "implicit trust between all resources in the group. Specifically, {resources} "
        "allow unrestricted communication between instances sharing the Security Group.\n\n"
        "This situation implies that a compromised instance within the Security Group "
        "can directly communicate with all other instances in the group, facilitating "
        "lateral movement."
    ),
    "NET-014": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} network resource(s) lack adequate segmentation between application "
        "tiers. Specifically, {resources} allow direct communication between presentation, "
        "application, and data tiers without intermediate controls.\n\n"
        "This situation implies that a compromise of the web tier can directly reach "
        "database or internal services, bypassing the defense-in-depth that tiered "
        "architecture is designed to provide."
    ),
    "NET-015": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} VPC(s) do not have AWS Network Firewall or equivalent inspection "
        "capability configured. Specifically, {resources} lack stateful traffic inspection "
        "for east-west or north-south flows.\n\n"
        "This situation implies that malicious traffic patterns, C2 communications, and "
        "data exfiltration attempts cannot be detected or blocked at the network layer "
        "within the VPC."
    ),
    "NET-016": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} subnet(s) are associated with default VPC Network ACLs instead of "
        "dedicated custom NACLs. Specifically, {resources} inherit default subnet-level "
        "filtering.\n\n"
        "This situation implies that subnet segmentation lacks an explicit stateless "
        "control layer and is more dependent on Security Groups for all traffic filtering."
    ),
    "NET-017": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} subnet(s) automatically assign public IP addresses to all launched "
        "instances (MapPublicIpOnLaunch=true). Specifically, {resources} expose all "
        "resources to direct internet reachability by default.\n\n"
        "This situation implies that instances launched in these subnets receive public "
        "IP addresses automatically, requiring explicit Security Group rules as the only "
        "network isolation mechanism."
    ),
    "NET-018": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group(s) have stale rules referencing non-existent "
        "resources or Security Groups. Specifically, {resources} contain dangling "
        "references that may be reassigned to unintended resources.\n\n"
        "This situation implies that Security Group rules are not being actively "
        "maintained, and stale references could inadvertently permit access if the "
        "referenced resource IDs are reused."
    ),
    "NET-019": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} VPC(s) have DNS resolution or DNS hostnames disabled. Specifically, "
        "{resources} cannot resolve private DNS names, which may lead to insecure "
        "fallback to public DNS.\n\n"
        "This situation implies that private service discovery may fail, forcing "
        "applications to use public endpoints for internal communication, increasing "
        "unnecessary internet exposure."
    ),
    "NET-021": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} NAT Gateway(s) are not in highly available configurations across "
        "multiple Availability Zones. Specifically, {resources} represent single points "
        "of failure for outbound internet connectivity.\n\n"
        "This situation implies that a single AZ failure could disrupt all outbound "
        "traffic for private subnets, affecting business continuity for workloads "
        "dependent on internet access."
    ),
    "NET-022": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} subnet(s) are configured as public (route to Internet Gateway) "
        "and should be reviewed for workload placement. Specifically, {resources} have "
        "direct internet routing via an Internet Gateway.\n\n"
        "This situation implies potential exposure if resources in those subnets also "
        "have public addresses or public-facing resource policies and permissive Security "
        "Groups. Route-table evidence alone proves public subnet classification, not "
        "direct reachability of every resource in the subnet."
    ),
    "NET-025": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} subnet(s) are missing classification tags such as Tier, Layer, "
        "or Classification. Specifically, {resources} do not carry metadata that clearly "
        "identifies their intended network tier.\n\n"
        "This situation implies that automated governance, segmentation review, and "
        "change approval cannot reliably distinguish public, private, application, and "
        "data subnets."
    ),
    "NET-027": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group(s) are missing tags. Specifically, {resources} have "
        "no ownership, environment, application, or classification metadata attached.\n\n"
        "This situation implies that firewall ownership, exception review, and cleanup "
        "workflows cannot be reliably automated or assigned to the correct team."
    ),
    "NET-029": (
        "During the analysis of the network security configuration, it was identified "
        "that {count} Security Group(s) have no inbound rules but allow all outbound "
        "traffic without restriction. Specifically, {resources} impose no egress "
        "filtering on network communications.\n\n"
        "This situation implies that any compromise of associated resources enables "
        "unrestricted outbound connections to external destinations, facilitating "
        "data exfiltration or C2 communications."
    ),
    # ── RECON ─────────────────────────────────────────────────────────────────
    "RECON-001": (
        "During the analysis of the external attack surface, it was identified that "
        "Route53 hosted zone(s) contain wildcard DNS records (*.domain). Specifically, "
        "{resources} resolve any subdomain to internal or public IP addresses.\n\n"
        "This situation implies that attackers can infer the existence of wildcard DNS "
        "configurations and potentially exploit subdomain takeover vulnerabilities by "
        "registering services matching the wildcard pattern."
    ),
    "RECON-004": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} public Route53 hosted zone(s) contain DNS records that reveal internal "
        "architecture details. Specifically, {resources} expose naming conventions, "
        "internal IP ranges, or service topology information.\n\n"
        "This situation implies that an attacker can perform passive reconnaissance "
        "to map the internal architecture without any active scanning, reducing the "
        "effort required to identify high-value attack targets."
    ),
    "RECON-006": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} CloudFront distribution(s) do not have access logging enabled. "
        "Specifically, {resources} do not capture CDN access logs.\n\n"
        "This situation implies that HTTP traffic patterns — including scanning attempts, "
        "credential stuffing, and path enumeration — cannot be analyzed or correlated "
        "with security incidents."
    ),
    "RECON-008": (
        "During the analysis of the external attack surface, it was identified that the "
        "account has a large number of public entry points (more than 10 internet-facing "
        "resources). Specifically, {resources} contribute to a broad public attack surface.\n\n"
        "This situation implies that the organization has a large number of externally "
        "reachable services that each require individual hardening and monitoring, "
        "increasing the probability that one is misconfigured or vulnerable."
    ),
    "RECON-009": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} API Gateway REST stage(s) do not have access logging enabled. "
        "Specifically, {resources} do not capture API access logs.\n\n"
        "This situation implies that API enumeration attempts, authentication failures, "
        "and abuse patterns cannot be detected or investigated after the fact."
    ),
    "RECON-010": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} NAT Gateway(s) have public IP addresses that contribute to the "
        "organization's external IP footprint. Specifically, {resources} are associated "
        "with Elastic IPs visible to external parties.\n\n"
        "This situation implies that outbound traffic from private subnets originates "
        "from known, enumerable IP addresses that can be targeted for blocking or "
        "used in attribution during incident response."
    ),
    "RECON-011": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} public Application Load Balancer(s) have HTTP (port 80) listeners "
        "without redirect to HTTPS. Specifically, {resources} accept unencrypted "
        "connections from clients.\n\n"
        "This situation implies that user credentials, session tokens, and sensitive "
        "data transmitted over HTTP are exposed to network-level interception on "
        "untrusted networks."
    ),
    "RECON-012": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} CloudFront distribution(s) do not have AWS WAF associated. Specifically, "
        "{resources} process requests without web application firewall inspection.\n\n"
        "This situation implies that OWASP Top 10 attacks (SQL injection, XSS, path "
        "traversal), automated scanners, and known malicious IPs can reach the origin "
        "without any application-layer filtering."
    ),
    "RECON-013": (
        "During the analysis of the external attack surface, it was identified that "
        "the account has more than 5 public Route53 hosted zones. Specifically, "
        "{count} public zones contribute to a broad DNS footprint.\n\n"
        "This situation implies that the organization has a large public DNS surface "
        "that requires systematic monitoring for subdomain takeover, zone transfer "
        "exposure, and DNS record misconfiguration."
    ),
    "RECON-014": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} API Gateway stage(s) have more than 5 routes without authentication "
        "configured. Specifically, {resources} expose multiple unauthenticated endpoints.\n\n"
        "This situation implies that a significant portion of the API surface is "
        "accessible without credentials, enabling comprehensive API enumeration and "
        "targeted attacks against business logic."
    ),
    "RECON-016": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} Elastic IP address(es) are allocated but not associated with any "
        "active resource. Specifically, {resources} are unattached EIPs.\n\n"
        "This situation implies that these IP addresses remain part of the organization's "
        "public IP inventory without serving any purpose, generating unnecessary costs "
        "and potentially being reassigned to unintended resources in the future."
    ),
    "RECON-017": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} Application Load Balancer(s) expose non-standard high-risk ports "
        "such as database or administrative ports. Specifically, {resources} have "
        "listeners on ports 3306, 5432, 27017, 8443, or 8080.\n\n"
        "This situation implies that sensitive backend services (databases, admin panels) "
        "are exposed through the load balancer to a broader audience than intended."
    ),
    "RECON-018": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} Lambda Function URL(s) have CORS policies allowing all origins (*). "
        "Specifically, {resources} accept cross-origin requests from any domain.\n\n"
        "This situation implies that browser-based clients from any website can make "
        "authenticated requests to these functions, enabling cross-origin request "
        "forgery and unauthorized API invocation from attacker-controlled web pages."
    ),
    "RECON-019": (
        "During the analysis of the external attack surface, it was identified that "
        "{count} CloudFront distribution(s) share the same origin with other "
        "distributions. Specifically, {resources} point to an origin that is also "
        "served by another CloudFront distribution.\n\n"
        "This situation implies that misconfigurations or vulnerabilities in one "
        "distribution's WAF or access controls may affect the security posture of "
        "the shared origin, as the origin receives traffic from multiple distributions."
    ),
    "RECON-020": (
        "During the analysis of the external attack surface, it was identified that "
        "no public entry points are detected in the account. The infrastructure appears "
        "to operate entirely within private network boundaries.\n\n"
        "This situation implies a minimal external attack surface. While this is a "
        "positive security posture, it should be validated against the expected "
        "architecture to ensure no legitimate public endpoints are missing."
    ),
    # ── SECRETS MANAGER ───────────────────────────────────────────────────────
    "SM-001": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) have resource-based policies granting access via wildcard "
        "principal (Principal:*). Specifically, {resources} are accessible by any "
        "AWS identity.\n\n"
        "This situation implies that any authenticated AWS principal — including "
        "identities from external accounts — can retrieve these secrets without "
        "requiring explicit authorization from the secret owner."
    ),
    "SM-002": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) do not have automatic rotation enabled. Specifically, "
        "{resources} have RotationEnabled=false and use static, long-lived credentials.\n\n"
        "This situation implies that if these secrets are compromised through a data "
        "breach, phishing, or insider threat, they remain valid indefinitely until "
        "manually rotated — an action that requires an active response."
    ),
    "SM-003": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) have automatic rotation intervals exceeding 90 days. "
        "Specifically, {resources} are configured to rotate every {count}+ days.\n\n"
        "This situation implies that the window during which a compromised secret "
        "remains valid before natural rotation exceeds the industry-recommended "
        "90-day threshold, extending the potential exposure period."
    ),
    "SM-004": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) use AWS-managed encryption keys (aws/secretsmanager) instead "
        "of customer-managed KMS keys. Specifically, {resources} do not use CMK encryption.\n\n"
        "This situation implies that the organization cannot independently control, rotate, "
        "or revoke access to the encryption keys protecting these secrets, limiting "
        "the granularity of cryptographic access control."
    ),
    "SM-005": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) have not been rotated for more than 365 days or have never "
        "been rotated since creation. Specifically, {resources} have static credentials "
        "that have persisted for over a year.\n\n"
        "This situation implies that these credentials have had an extended exposure "
        "window, and the probability that they have been accessed by unauthorized "
        "parties through historical breaches or insider events is elevated."
    ),
    "SM-006": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) do not have descriptive tags for governance and classification. "
        "Specifically, {resources} lack ownership, environment, or classification tags.\n\n"
        "This situation implies that these secrets cannot be easily attributed to a "
        "specific team or application, making access reviews, cost allocation, and "
        "incident response significantly more difficult."
    ),
    "SM-007": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) have no description defined. Specifically, {resources} lack "
        "documentation about their purpose or usage context.\n\n"
        "This situation implies that it is difficult to determine the impact of these "
        "secrets during an incident response, and overly broad access grants may go "
        "undetected due to the lack of context about what the secret protects."
    ),
    "SM-008": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} critical secret(s) are not replicated to multiple AWS regions. "
        "Specifically, {resources} have no cross-region replication configured.\n\n"
        "This situation implies that a regional outage would make these secrets "
        "inaccessible, potentially causing business continuity failures for workloads "
        "that depend on them across regions."
    ),
    "SM-011": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) with sensitive access patterns do not require MFA as a "
        "condition for access in their resource policies. Specifically, {resources} "
        "can be retrieved without a second authentication factor.\n\n"
        "This situation implies that a stolen IAM credential is sufficient to retrieve "
        "these secrets without requiring a physical MFA device, reducing the attacker's "
        "barrier to accessing sensitive credentials."
    ),
    "SM-012": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) do not have alerting configured for rotation failures. "
        "Specifically, {resources} lack EventBridge or CloudWatch alarms for the "
        "RotationFailed event.\n\n"
        "This situation implies that if automatic rotation fails — leaving the secret "
        "static and potentially locked — no notification is sent, and the failure may "
        "go undetected until an application experiences an authentication error."
    ),
    "SM-014": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) use rotation Lambda functions that are not validated against "
        "an approved allowlist. Specifically, {resources} reference Lambda ARNs that "
        "could be hijacked or modified.\n\n"
        "This situation implies that an attacker with Lambda write access could modify "
        "the rotation function to exfiltrate secret values during the next rotation cycle."
    ),
    "SM-015": (
        "During the analysis of the Secrets Manager service, it was identified that "
        "{count} secret(s) can be re-encrypted with untrusted KMS keys. Specifically, "
        "{resources} allow the UpdateSecret action without restricting which KMS key "
        "can be specified.\n\n"
        "This situation implies that an attacker with UpdateSecret permissions could "
        "re-encrypt the secret with an attacker-controlled KMS key, effectively making "
        "the secret inaccessible to legitimate consumers while retaining their own access."
    ),
    # ── CLOUDTRAIL EVENTS ─────────────────────────────────────────────────────
    "CTEF-001": (
        "During the analysis of the CloudTrail audit logs, it was identified that root "
        "account activity was detected within the audit window. Specifically, API calls "
        "were recorded using the root account credentials.\n\n"
        "This situation implies that the most privileged account in the AWS environment "
        "is being used for operational tasks, violating the principle that root access "
        "should be reserved for emergency break-glass scenarios only."
    ),
    "CTEF-003": (
        "During the analysis of the CloudTrail audit logs, it was identified that audit "
        "trail tampering events were detected within the audit window. Specifically, "
        "StopLogging, DeleteTrail, or UpdateTrail events were recorded.\n\n"
        "This situation implies that an actor — potentially malicious — attempted to "
        "disable or modify the audit trail, which is a classic indicator of an attacker "
        "covering their tracks during or after a compromise."
    ),
    "CTEF-009": (
        "During the analysis of the CloudTrail audit logs, it was identified that the "
        "credential report was accessed within the audit window. Specifically, "
        "GenerateCredentialReport or GetCredentialReport API calls were recorded.\n\n"
        "This situation implies that an actor enumerated all IAM users, their access "
        "keys, MFA status, and last activity — information that is highly valuable for "
        "planning privilege escalation or identifying dormant accounts to target."
    ),
    "CTEF-011": (
        "During the analysis of the CloudTrail audit logs, it was identified that security "
        "monitoring services were disabled within the audit window. Specifically, "
        "DisableSecurityHub, DeleteDetector, or DisableAlarmActions events were recorded.\n\n"
        "This situation implies that an actor actively reduced the account's detection "
        "capability, which is a strong indicator of malicious activity consistent with "
        "the MITRE ATT&CK 'Impair Defenses' tactic (TA0005)."
    ),
    "CTEF-012": (
        "During the analysis of the CloudTrail audit logs, it was identified that secrets "
        "or parameter store values were accessed within the audit window. Specifically, "
        "GetSecretValue or GetParameter API calls were recorded.\n\n"
        "This situation implies that credentials or configuration secrets were retrieved "
        "from the secrets management layer. This access should be validated against "
        "known legitimate access patterns to rule out unauthorized credential harvesting."
    ),
    "CTEF-013": (
        "During the analysis of the CloudTrail audit logs, it was identified that IAM "
        "trust policies or inline policies were modified within the audit window. "
        "Specifically, UpdateAssumeRolePolicy or PutRolePolicy events were recorded.\n\n"
        "This situation implies that the trust relationships or permissions of one or "
        "more IAM roles were altered. This is a key indicator of privilege escalation "
        "attempts or the establishment of persistence through modified trust chains."
    ),
    # ── VULNERABILITIES (remaining) ───────────────────────────────────────────
    "VULN-002": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} CRITICAL severity CVE(s) remain unresolved. Specifically, "
        "{resources} contain known vulnerabilities with a CVSS score ≥ 9.0.\n\n"
        "This situation implies that the affected resources can be compromised using "
        "publicly documented exploits, and the high CVSS score indicates significant "
        "impact and low exploitation complexity."
    ),
    "VULN-003": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} vulnerability(ies) affect publicly accessible resources. "
        "Specifically, {resources} have unpatched CVEs and are reachable from the internet.\n\n"
        "This situation implies that these vulnerabilities can be exploited by any "
        "internet actor without requiring prior network access, combining internet exposure "
        "with known exploitability for maximum risk."
    ),
    "VULN-005": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} high-criticality resource(s) — such as domain controllers, "
        "databases, or API servers — have unpatched vulnerabilities. Specifically, "
        "{resources} are business-critical assets with pending security patches.\n\n"
        "This situation implies that a successful exploit against these resources would "
        "have a disproportionately high business impact due to the criticality and "
        "centrality of these systems."
    ),
    "VULN-007": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} HIGH severity CVE(s) exceed the acceptable remediation "
        "threshold. Specifically, {resources} have pending HIGH vulnerabilities beyond "
        "the defined SLA.\n\n"
        "This situation implies that the backlog of high-severity vulnerabilities has grown "
        "beyond manageable levels, indicating either insufficient patching capacity or "
        "a lack of prioritization in the vulnerability management process."
    ),
    "VULN-009": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} resource(s) each have three or more ACTIVE CVEs. "
        "Specifically, {resources} concentrate unresolved vulnerability backlog on the "
        "same assets.\n\n"
        "This situation increases compromise likelihood and remediation complexity because "
        "multiple exploitable conditions may coexist on the same runtime. It does not imply "
        "public exploit availability unless Inspector explicitly reports exploit evidence."
    ),
    "VULN-010": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} EC2 instance(s) supporting named application service components "
        "have ACTIVE HIGH or CRITICAL package findings. Specifically, {resources} have "
        "active Inspector records on service instances.\n\n"
        "This situation increases operational risk for those services. It does not prove an "
        "SLA breach or internet exploitability unless age and reachability evidence are also "
        "present."
    ),
    "VULN-011": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that ECR scanning is explicitly disabled for {count} repository or "
        "registry scope(s). Specifically, {resources} lack container image vulnerability "
        "scanning evidence.\n\n"
        "This situation creates a container vulnerability visibility gap. It should only be "
        "reported when scan configuration evidence proves disabled scanning, not merely when "
        "no image findings are present."
    ),
    "VULN-022": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} container image(s) in ECR have critical vulnerabilities "
        "in their base layers or installed packages. Specifically, {resources} have "
        "unresolved CVEs in the container image.\n\n"
        "This situation implies that workloads deployed from these images run vulnerable "
        "software, and any container instantiated from these images inherits the "
        "vulnerability risk at deployment time."
    ),
    "VULN-023": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} resource(s) have vulnerabilities classified as medium "
        "severity that have exceeded their remediation SLA. Specifically, {resources} "
        "have MEDIUM CVEs pending remediation.\n\n"
        "This situation implies that medium-severity vulnerabilities are accumulating "
        "without systematic remediation, and chaining multiple medium vulnerabilities "
        "can produce exploit chains equivalent to high-severity impact."
    ),
    "VULN-024": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that AWS Inspector is not enabled or is not scanning {count} "
        "resource type(s). Specifically, {resources} are not covered by Inspector scans.\n\n"
        "This situation implies that vulnerabilities in these resources are not being "
        "automatically detected, requiring entirely manual vulnerability assessment "
        "to maintain an accurate risk posture."
    ),
    "VULN-025": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} RDS database instance(s) have known vulnerabilities "
        "in their database engine version. Specifically, {resources} run engine versions "
        "with unpatched CVEs.\n\n"
        "This situation implies that the database engine itself contains exploitable "
        "weaknesses, and since databases typically store the most sensitive data in "
        "the environment, the impact of exploitation is particularly severe."
    ),
    "VULN-028": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} resource(s) have vulnerabilities that have been open "
        "for more than 90 days without remediation. Specifically, {resources} have "
        "long-overdue security patches pending.\n\n"
        "This situation implies that the vulnerability management process is not "
        "meeting remediation SLAs, and the extended exposure window significantly "
        "increases the probability of exploitation."
    ),
    "VULN-029": (
        "During the analysis of the vulnerability scan results (AWS Inspector), it was "
        "identified that {count} resource(s) have network reachability findings from "
        "AWS Inspector network path analysis. Specifically, {resources} are reachable "
        "from the internet on ports with associated vulnerabilities.\n\n"
        "This situation implies that known vulnerabilities on these resources are "
        "exploitable directly from the internet, combining network exposure with "
        "vulnerability risk for maximum severity."
    ),
    "VULN-GD-001": (
        "During the analysis of the vulnerability scan results, it was identified that "
        "AWS GuardDuty has detected {count} finding(s) indicating active threat activity. "
        "Specifically, {resources} are flagged with GuardDuty threat intelligence findings.\n\n"
        "This situation implies that the GuardDuty machine learning models have identified "
        "behavioral patterns consistent with active compromise, reconnaissance, or "
        "malicious use of AWS resources."
    ),
    "VULN-GD-002": (
        "During the analysis of the vulnerability scan results, it was identified that "
        "AWS GuardDuty has detected {count} high-severity finding(s) requiring immediate "
        "attention. Specifically, {resources} have GuardDuty HIGH severity alerts.\n\n"
        "This situation implies that GuardDuty has identified high-confidence indicators "
        "of compromise or malicious activity that warrant immediate investigation and "
        "incident response procedures."
    ),
    # ── WAF ───────────────────────────────────────────────────────────────────
    "WAF-001": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "internet-facing Application Load Balancer(s) are not protected by AWS WAF. "
        "Specifically, {resources} process web traffic without Web ACL inspection.\n\n"
        "This situation implies that OWASP Top 10 attacks (SQL injection, XSS, path "
        "traversal, command injection) can reach the application backend without any "
        "application-layer filtering or rate limiting."
    ),
    "WAF-002": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) do not have logging enabled. Specifically, {resources} process "
        "web requests without generating WAF access logs.\n\n"
        "This situation implies that blocked or suspicious requests cannot be analyzed "
        "for attack patterns, and forensic investigation of web-layer attacks is not "
        "possible without this log data."
    ),
    "WAF-003": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) do not have AWS Managed Rules enabled. Specifically, {resources} "
        "rely entirely on custom rules without the benefit of AWS threat intelligence.\n\n"
        "This situation implies that the WAF does not benefit from AWS's continuously "
        "updated threat intelligence, leaving the application potentially exposed to "
        "newly identified attack patterns and exploit techniques."
    ),
    "WAF-004": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) have WAF logging enabled but do not redact all expected sensitive "
        "request headers. Specifically, {resources} may log Authorization, Cookie, "
        "X-Api-Key, or X-Auth-Token values if those components are present in requests.\n\n"
        "This situation implies that security logs may retain credentials, session "
        "tokens, or API keys, increasing the impact of log disclosure or overly broad "
        "log-reader permissions."
    ),
    "WAF-005": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) do not have rate-limiting rules configured. Specifically, {resources} "
        "have no protection against high-volume request flooding.\n\n"
        "This situation implies that the application is vulnerable to brute-force attacks "
        "against authentication endpoints, credential stuffing, and HTTP-layer denial-of-"
        "service attacks that could affect application availability."
    ),
    "WAF-006": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) do not include the expected baseline AWS Managed Rule groups. "
        "Specifically, {resources} do not use AWSManagedRulesCommonRuleSet, "
        "AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesSQLiRuleSet, or "
        "AWSManagedRulesAmazonIpReputationList.\n\n"
        "This situation implies that the WAF posture depends on custom or third-party "
        "rules without the standard AWS-managed baseline for common web attacks, known "
        "bad inputs, SQL injection patterns, and AWS threat-intelligence IP reputation."
    ),
    "WAF-007": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) do not have XSS (Cross-Site Scripting) protection rules enabled. "
        "Specifically, {resources} lack application-layer XSS filtering.\n\n"
        "This situation implies that script injection payloads in user inputs are not "
        "filtered at the WAF layer, increasing the risk of reflected or stored XSS "
        "vulnerabilities being successfully exploited."
    ),
    "WAF-008": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) operate in COUNT mode rather than BLOCK mode for one or more rules. "
        "Specifically, {resources} log detected attacks without blocking them.\n\n"
        "This situation implies that known attack patterns are detected but permitted to "
        "reach the application backend, providing no protective value against the "
        "attacks being monitored."
    ),
    "WAF-009": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) are not associated with any CloudFront distribution, ALB, or API "
        "Gateway. Specifically, {resources} are provisioned but not protecting any resource.\n\n"
        "This situation implies that WAF rules are defined but not applied to any "
        "production traffic, providing no actual protection while consuming WAF capacity."
    ),
    "WAF-010": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "WAF Classic Web ACL(s) are still present. Specifically, {resources} use the "
        "legacy WAF Classic control plane instead of WAFv2.\n\n"
        "This situation implies that web application firewall configuration is split "
        "across legacy and current WAF APIs, reducing maintainability, consistency, "
        "and access to WAFv2 capabilities such as improved rule statements, capacity "
        "management, and modern association workflows."
    ),
    "WAF-011": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) have rules with overly permissive default actions. Specifically, "
        "{resources} allow traffic by default when no rule matches rather than denying "
        "by default.\n\n"
        "This situation implies that any request that does not match an explicit rule "
        "is permitted to reach the application, creating a permissive posture that "
        "favors availability over security."
    ),
    "WAF-013": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) do not have scope-down statements to limit rule evaluation to "
        "relevant endpoints. Specifically, {resources} apply all rules to every request "
        "without targeting.\n\n"
        "This situation implies that WAF capacity units are consumed evaluating rules "
        "against requests where they are not applicable, potentially leading to "
        "capacity exhaustion under high traffic loads."
    ),
    "WAF-014": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) have not been updated or had new rules added in the past 90 days. "
        "Specifically, {resources} show no rule update activity.\n\n"
        "This situation implies that the WAF configuration may not address recently "
        "discovered attack techniques or newly deployed application endpoints, creating "
        "gaps in protection coverage."
    ),
    "WAF-015": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) do not have Bot Control rules configured. Specifically, {resources} "
        "lack protection against automated bot traffic.\n\n"
        "This situation implies that credential stuffing bots, scrapers, and automated "
        "vulnerability scanners can interact with the application at scale without "
        "detection or rate limiting."
    ),
    "WAF-016": (
        "During the analysis of the WAF configuration, it was identified that {count} "
        "Web ACL(s) have a high number of rule group capacity units (WCU) consumed, "
        "approaching or exceeding recommended limits. Specifically, {resources} are "
        "near WAF capacity.\n\n"
        "This situation implies that adding new protection rules may not be possible "
        "without removing existing ones, creating a forced trade-off between "
        "protection coverage and rule capacity."
    ),
    # ── SISTEMAS EXPLOTABLES EN RED (SER) ─────────────────────────────────────
    "SER-EC2-001": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} EC2 instance(s) have administrative ports (SSH/RDP) exposed to the "
        "internet. Specifically, {resources} are reachable from 0.0.0.0/0 on ports "
        "22 or 3389.\n\n"
        "This situation implies that remote administration sessions for these instances "
        "can be initiated by any internet actor, exposing the login interface to brute-"
        "force attacks and exploitation of remote access service vulnerabilities."
    ),
    "SER-EC2-002": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} EC2 instance(s) are directly reachable from the internet and have "
        "active Amazon Inspector vulnerability findings. Specifically, {resources} "
        "are internet-facing on the service ports confirmed in the evidence and have "
        "unresolved Inspector findings on the host.\n\n"
        "This situation creates a combined exposure and vulnerability risk: the public "
        "listener provides the initial network entry point, while network-vector CVEs "
        "can enable initial exploitation and local CVEs can increase post-compromise "
        "impact after access is obtained."
    ),
    "SER-COR-003": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} resource(s) have correlated exposure and vulnerability findings. "
        "Specifically, {resources} are both internet-facing and have unpatched CVEs.\n\n"
        "This situation implies that the combination of network reachability and "
        "known vulnerabilities creates immediately exploitable attack paths, where "
        "the vulnerability can be triggered directly from the internet."
    ),
    "SER-CVE-001": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} internet-facing resource(s) have critical CVEs actively exploited "
        "in the wild. Specifically, {resources} combine public exposure with "
        "in-the-wild exploit availability.\n\n"
        "This situation implies an immediate exploitation risk — the vulnerable service "
        "is reachable from the internet and the exploit requires no special conditions "
        "or access beyond network connectivity."
    ),
    "SER-ECS-001": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} ECS service(s) are exposed to the internet without adequate access "
        "controls. Specifically, {resources} have public IP addresses or ALB associations "
        "without sufficient authentication.\n\n"
        "This situation implies that the containerized services are reachable from "
        "the internet and any vulnerabilities in the container application can be "
        "exploited directly without requiring internal network access."
    ),
    "SER-LMB-001": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} Lambda Function URL(s) are publicly accessible without authentication. "
        "Specifically, {resources} accept unauthenticated HTTP invocations from "
        "any internet source.\n\n"
        "This situation implies that the function logic and any AWS resources accessed "
        "through the function's IAM role are exposed to unauthorized invocation by "
        "any internet actor."
    ),
    "SER-LMB-002": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} Lambda function(s) are exposed via API Gateway without authorization "
        "requirements. Specifically, {resources} have API Gateway integrations with "
        "routes that have no AuthorizationType configured.\n\n"
        "This situation implies that the Lambda function can be invoked by any internet "
        "actor through the API Gateway endpoint without requiring API keys, JWT tokens, "
        "or IAM authorization."
    ),
    "SER-RDS-001": (
        "During the analysis of the network-exposed services, it was identified that "
        "{count} RDS instance(s) are publicly accessible with permissive Security Groups. "
        "Specifically, {resources} have PubliclyAccessible=true and accept connections "
        "from 0.0.0.0/0 on their database port.\n\n"
        "This situation implies that the database authentication layer is directly "
        "exposed to the internet, enabling brute-force attacks against database "
        "credentials and exploitation of database engine vulnerabilities."
    ),
}


PRE_CHECK_REMEDIATIONS: Dict[str, str] = {
    # ── IAM ──────────────────────────────────────────────────────────────────
    "IAM-001": (
        "It is recommended to enable multi-factor authentication (MFA) on the root account "
        "immediately via the AWS Management Console under Account Settings > Security Credentials. "
        "Use a hardware MFA token or a virtual authenticator application for the strongest protection. "
        "Once enabled, store the MFA device and root credentials in a secure, access-controlled location "
        "and restrict root usage to break-glass emergency scenarios only. "
        "Consider creating an IAM user or role with delegated administrative permissions for all routine "
        "operational tasks, eliminating the need to access the root account under normal circumstances. "
        "Periodically verify that MFA is still active by reviewing the IAM credential report."
    ),
    "IAM-002": (
        "For users with programmatic access only (no console password), first evaluate whether "
        "long-lived access keys can be replaced with IAM roles and temporary credentials via AWS STS. "
        "Where keys must remain, scope their permissions tightly, monitor CloudTrail usage, rotate "
        "them on a defined schedule, and consider IAM conditions that require MFA for sensitive API "
        "actions when human use is involved. "
        "For any affected users that also have console access, enforce MFA enrollment before granting "
        "production access by using a conditional policy that denies non-enrollment activity except "
        "the actions required to self-enroll an MFA device. "
        "Review the IAM credential report regularly to detect new identities without MFA or with "
        "unprotected active access keys."
    ),
    "IAM-003": (
        "It is recommended to remove all active access keys from the root account without exception. "
        "The root account should never have programmatic access keys, as any compromise of these keys "
        "would grant unrestricted access to all AWS resources and services without any scope limitation. "
        "To remove root access keys, navigate to the AWS Management Console > Security Credentials and "
        "delete any keys listed under 'Access keys'. "
        "If any automation or integration currently relies on root access keys, migrate it to an IAM "
        "role or IAM user with least-privilege permissions scoped to the specific actions required. "
        "After removal, verify the deletion using the IAM credential report and configure a CloudWatch "
        "alarm to alert on any future root account API activity."
    ),
    "IAM-004": (
        "It is recommended to implement a formal access key rotation process aligned with a maximum "
        "90-day interval. For each affected user, generate a new access key, update all applications, "
        "scripts, and integrations consuming the old key, and validate correct functionality before "
        "revoking the previous key. "
        "This staged approach — create new, migrate, validate, then delete old — ensures continuity "
        "while closing the exposure window of long-lived credentials. "
        "Establish monitoring controls such as CloudWatch alarms or AWS Config rules that alert when "
        "access keys approach or exceed the rotation threshold. "
        "Where technically feasible, evaluate replacing long-lived access keys with IAM roles and "
        "temporary credentials via AWS STS, which rotate automatically and eliminate the need for "
        "manual key management entirely."
    ),
    "IAM-005": (
        "It is recommended to immediately disable and subsequently delete access keys that have not "
        "been used for 90 days or more. Inactive keys represent dormant credentials that provide no "
        "operational value while maintaining an attack surface if compromised. "
        "Before deletion, notify the key owner and verify that no active integration depends on the "
        "key by reviewing CloudTrail logs for recent usage. Disable the key first and monitor for "
        "any authentication failures over a 7-day window before permanent deletion. "
        "Establish a recurring quarterly review of the IAM credential report to proactively identify "
        "and manage inactive keys before they accumulate. "
        "Consider adopting AWS IAM Identity Center or IAM roles for service-to-service authentication "
        "to reduce reliance on long-lived access keys."
    ),
    "IAM-007": (
        "It is recommended to migrate role inline policies to customer-managed IAM policies. "
        "Create managed policies with the same least-privilege statements, attach them to the "
        "affected roles, validate application behavior, and then remove the inline policy documents. "
        "Use versioning and tags on customer-managed policies so permission changes can be reviewed, "
        "reused consistently, and audited across roles."
    ),
    "IAM-008": (
        "It is recommended to review all users and roles currently associated with broad managed "
        "policies such as AdministratorAccess or PowerUserAccess and identify the permissions "
        "actually required based on their function. "
        "Replace these policies with custom least-privilege policies that restrict actions and "
        "resources to only what is strictly necessary. Use IAM Access Analyzer and AWS CloudTrail "
        "to identify actual permission usage and generate policy recommendations. "
        "In cases where elevated privileges are operationally required, formally document the "
        "business justification and define compensating controls such as restricted usage windows, "
        "enhanced monitoring, or on-demand access. "
        "Review trust policies of roles to ensure that only explicitly authorized entities can "
        "assume them, and implement periodic access reviews to keep permissions aligned with "
        "evolving operational needs."
    ),
    "IAM-009": (
        "It is recommended to verify that the root account has no active access keys and remove "
        "any that exist. Navigate to the AWS Console > Security Credentials and delete all root "
        "access keys. "
        "If automation currently uses root credentials, immediately migrate to a dedicated IAM "
        "user or role with the minimum permissions required. "
        "Configure a CloudTrail-based CloudWatch alarm to alert immediately on any root account "
        "API activity, and treat any such alert as a potential security incident requiring "
        "immediate investigation."
    ),
    "IAM-010": (
        "It is recommended to disable or delete access keys that have exceeded the maximum age "
        "policy. Review the IAM credential report to identify all keys older than the threshold "
        "and contact key owners to initiate the rotation process. "
        "For each key, create a replacement key, migrate all consumers, validate operation, then "
        "disable the old key and delete it after a brief observation window. "
        "Automate age tracking using AWS Config rule 'access-keys-rotated' to receive continuous "
        "compliance signals and prevent key age from exceeding policy limits in the future."
    ),
    "IAM-011": (
        "It is recommended to periodically review the IAM credential report to identify inactive "
        "user accounts that have not been used for an extended period. "
        "For users who no longer require active access, disable console credentials by removing "
        "the login profile and deactivate or delete any associated access keys. "
        "If the account is confirmed no longer needed, delete the IAM user after validating that "
        "no resources or policies are dependent on it. "
        "Establish a recurring quarterly review process to proactively manage inactive users and "
        "reduce the dormant identity surface. As a best practice, prefer federated identities "
        "or temporary access over permanent IAM users to prevent accumulation of inactive accounts."
    ),
    "IAM-012": (
        "It is recommended to disable or remove IAM users that have shown no activity for 90 or more "
        "days. Inactive credentials represent an unmonitored attack surface — if compromised, they "
        "are unlikely to trigger behavioral alerts due to the absence of normal activity baselines. "
        "Use the IAM credential report to identify dormant accounts, disable them first (set console "
        "password and access keys to inactive), and delete after confirming no service dependencies. "
        "Consider automating this process with AWS Config rules or a scheduled Lambda function that "
        "flags accounts inactive for more than 60 days and triggers a review workflow."
    ),
    "IAM-014": (
        "It is recommended to allow only one active access key per IAM user at any time, except "
        "during active key rotation. Review all users with multiple active keys and deactivate the "
        "older or less recently used key once the new one is confirmed working. Enforce a 90-day "
        "rotation policy and consider automating key rotation using AWS Secrets Manager or a "
        "scheduled Lambda function. Having multiple simultaneous active keys doubles the credential "
        "attack surface and complicates audit trails, making it harder to attribute API activity "
        "to a specific credential."
    ),
    "IAM-015": (
        "It is recommended to remove all directly attached policies from IAM users and migrate "
        "permission management to IAM groups. Attach policies to groups based on job functions, "
        "then add users to the appropriate groups. "
        "Direct user permissions create decentralized, harder-to-audit access controls that "
        "increase the risk of permission drift over time. Group-based management provides a "
        "single point of control for each permission set, making access reviews significantly "
        "more tractable. "
        "Use IAM Access Analyzer to review effective permissions and identify any outlier "
        "permissions that may have been granted individually."
    ),
    "IAM-016": (
        "It is recommended to replace long-lived access keys used by programmatic-only IAM users "
        "with IAM roles and temporary credentials wherever technically feasible. "
        "For EC2, Lambda, ECS, and other AWS compute services, assign IAM roles directly to the "
        "resource rather than embedding access keys. For external systems, use AWS IAM Identity "
        "Center or cross-account role assumption with STS to obtain short-lived credentials. "
        "If access keys cannot be replaced immediately, enforce strict rotation policies "
        "(90 days maximum), restrict key permissions to the minimum required, and monitor usage "
        "via CloudTrail for any anomalous access patterns."
    ),
    "IAM-018": (
        "It is recommended to configure the IAM account password policy to enforce a maximum "
        "password age of 90 days or fewer. Password expiration limits the window during which "
        "a compromised credential remains usable, reducing the impact of phishing, data breaches, "
        "and credential stuffing attacks. "
        "Notify users in advance of expiration and provide clear instructions for password rotation "
        "to minimize operational disruption. Combine with MFA to ensure that even an unexpired "
        "password alone cannot grant unauthorized console access."
    ),
    "IAM-019": (
        "It is recommended to update the IAM account password policy to require at least one "
        "symbol character in passwords. Including symbols increases the password character space, "
        "making brute-force and dictionary attacks significantly more computationally expensive. "
        "Ensure the policy also enforces minimum length (14+ characters), mixed case, and numbers "
        "for a comprehensive complexity baseline."
    ),
    "IAM-020": (
        "It is recommended to add all IAM users to at least one IAM group to ensure permissions "
        "are managed centrally. Create groups aligned with job functions and assign managed or "
        "inline policies to the groups rather than to individual users. "
        "This practice simplifies permission audits, ensures consistent access controls, and "
        "reduces the risk of granting inconsistent permissions across users with similar roles."
    ),
    "IAM-026": (
        "It is recommended to attach permission boundaries to customer-managed IAM roles that can "
        "accumulate elevated permissions. A permission boundary defines the maximum permissions a role can have, "
        "even if broader policies are later attached. "
        "This reduces privilege escalation risk when roles or deployment processes attach broader "
        "policies than intended. "
        "Define a boundary policy that reflects the maximum permissions appropriate for these "
        "roles, attach it at role creation, and enforce it through an SCP or IAM condition that "
        "prevents boundary removal."
    ),
    "IAM-029": (
        "It is recommended to review all cross-account IAM roles and restrict trust policies to "
        "explicitly named principals. Replace broad trust conditions with specific account IDs, "
        "role ARNs, or organizational unit conditions using aws:PrincipalOrgID. "
        "Require external ID conditions for cross-account roles to prevent confused deputy attacks. "
        "Periodically audit cross-account trust relationships and remove any roles that are no "
        "longer needed for active integrations."
    ),
    "IAM-030": (
        "It is recommended to audit all IAM role trust policies and restrict AssumeRole permissions "
        "to the minimum set of principals required. Remove any wildcard principals or overly broad "
        "service trust entries. "
        "For roles used by AWS services, restrict the trust to the specific service principal "
        "(e.g., ec2.amazonaws.com) rather than allowing any service to assume the role. "
        "Document the intended use case for each role and review trust policies quarterly to "
        "ensure they reflect current authorization requirements."
    ),
    "IAM-032": (
        "It is recommended to enforce MFA for all users with privileged access, including those "
        "with administrator, power user, or sensitive role assumption permissions. "
        "Implement a conditional IAM policy that denies privileged actions unless the "
        "aws:MultiFactorAuthPresent condition is true. "
        "This ensures that even a compromised password cannot be used to perform high-impact "
        "actions without possession of the MFA device. Audit compliance via the IAM credential "
        "report and treat any privileged user without MFA as a critical finding."
    ),
    "IAM-033": (
        "It is recommended to replace service accounts using long-lived access keys with IAM "
        "roles attached directly to the compute resource (EC2 instance profile, Lambda execution "
        "role, ECS task role). "
        "IAM roles provide automatically rotated, short-lived credentials via the instance "
        "metadata service or ECS task metadata endpoint, eliminating the key management burden "
        "and reducing the blast radius of a credential leak. "
        "For services that cannot use instance roles, consider AWS IAM Identity Center or "
        "Secrets Manager-stored credentials with automated rotation."
    ),
    "IAM-034": (
        "It is recommended to remove or strictly scope permissions that allow modification of "
        "identity provider configurations (UpdateSAMLProvider, UpdateOpenIDConnectProvider). "
        "These actions should be restricted to a small number of trusted IAM principals under "
        "strict change management controls. "
        "Any modification to a SAML or OIDC identity provider effectively changes who can "
        "authenticate to the AWS account, making these actions equivalent in risk to IAM "
        "administrator access. "
        "Implement CloudTrail alerting on any execution of these API calls and require "
        "multi-person approval for IdP configuration changes."
    ),
    "IAM-035": (
        "It is recommended to restrict CreatePolicyVersion and SetDefaultPolicyVersion permissions "
        "to a dedicated IAM administration role subject to strict access controls. "
        "These permissions allow an attacker to create a permissive policy version and activate "
        "it, achieving privilege escalation without modifying the existing policy document. "
        "Implement CloudTrail alarms on these API calls and require all policy changes to go "
        "through an approved change management process with peer review."
    ),
    "IAM-036": (
        "It is recommended to remove or tightly scope permissions for service-specific credential "
        "management (CreateServiceSpecificCredential, ResetServiceSpecificCredential). "
        "These permissions can be used to generate alternative authentication credentials for "
        "AWS services such as CodeCommit or Keyspaces that may bypass standard IAM key "
        "rotation policies. "
        "Restrict these actions to identity administrators and enable CloudTrail monitoring "
        "for any execution of these API calls."
    ),
    "IAM-037": (
        "It is recommended to restrict MFA device management permissions (EnableMFADevice, "
        "DeactivateMFADevice) to ensure users can only manage their own MFA devices. "
        "Use resource-level conditions (aws:RequestedRegion or iam:ResourceTag) combined with "
        "the iam:UserName condition key to prevent any user from deactivating another user's "
        "MFA device. "
        "Without this restriction, an attacker with IAM access could remove MFA from any "
        "account, including administrators, bypassing the MFA requirement entirely."
    ),
    "IAM-038": (
        "It is recommended to replace wildcard IAM delete permissions (iam:Delete*) with "
        "explicit, resource-scoped delete permissions limited to the specific IAM resources "
        "the principal legitimately manages. "
        "Wildcard delete permissions allow deletion of any IAM resource, including users, "
        "roles, policies, and MFA devices, potentially enabling an attacker to destroy "
        "access controls and cover tracks by removing audit-relevant identities. "
        "Apply the principle of least privilege by granting delete permissions only for "
        "the specific IAM object types and ARNs required."
    ),
    "IAM-039": (
        "It is recommended to restrict permissions that allow detaching or deleting IAM "
        "policies (DetachUserPolicy, DetachRolePolicy, DeletePolicyVersion) to a dedicated "
        "IAM administration role. "
        "An attacker with these permissions can remove restrictive boundary policies or "
        "permission guardrails from any identity, achieving privilege escalation by "
        "subtracting controls rather than adding permissions. "
        "Implement change management controls and CloudTrail alerts for all policy "
        "detachment events."
    ),
    "IAM-040": (
        "It is recommended to audit all IAM policies for privilege escalation patterns — "
        "combinations of permissions that together enable a principal to grant itself "
        "broader access than initially authorized. "
        "Common patterns include: PassRole + deployment actions, CreatePolicyVersion + "
        "SetDefaultPolicyVersion, and AssumeRole + UpdateAssumeRolePolicy. "
        "Use tools such as PMapper or IAM Access Analyzer to identify escalation paths "
        "and remove the minimum set of permissions required to break each chain."
    ),
    "IAM-041": (
        "It is recommended to remove AWS-managed AdministratorAccess or PowerUserAccess from "
        "the affected role and replace it with a customer-managed least-privilege policy scoped "
        "to the actions and resources the role actually requires. "
        "If broad administrative access is temporarily required, document the business "
        "justification, restrict which principals can assume the role, require compensating "
        "controls such as short session duration and CloudTrail monitoring, and set a time-bound "
        "review date. "
        "Use IAM Access Analyzer and CloudTrail access data to generate a narrowed policy before "
        "detaching the broad managed policy."
    ),
    "IAM-042": (
        "It is recommended to apply the principle of least privilege to all IAM policies "
        "that grant sensitive permissions. Review each policy granting access to high-risk "
        "actions (iam:*, sts:*, organizations:*, and similar) and scope them to the minimum "
        "resource ARNs and conditions required. "
        "Use IAM Access Analyzer to identify policies with findings and generate "
        "least-privilege replacements based on actual access patterns observed in CloudTrail."
    ),
    "IAM-043": (
        "It is recommended to review SSO permission sets and federated role policies to "
        "ensure they enforce least privilege. Replace any AdministratorAccess assignments "
        "in SSO permission sets with custom policies scoped to the specific actions "
        "required for each role. "
        "Implement time-limited or just-in-time access for elevated SSO permission sets "
        "using AWS IAM Identity Center's session duration controls, and require MFA "
        "re-authentication for sensitive permission sets."
    ),
    "IAM-044": (
        "It is recommended to reduce the MaxSessionDuration of privileged and SSO roles "
        "to the minimum necessary — ideally 1 hour (3600 seconds) or less. "
        "Shorter session durations limit the window during which a stolen session token "
        "remains valid, reducing the attacker's exploitation window after credential compromise. "
        "For roles requiring longer sessions for operational reasons, implement compensating "
        "controls such as CloudTrail monitoring for sustained session activity and anomaly "
        "detection for unexpected session usage patterns."
    ),
    # ── ALERTING ─────────────────────────────────────────────────────────────
    "ALRT-001": (
        "It is recommended to configure the CloudTrail trail to deliver log events to a "
        "dedicated CloudWatch Logs log group. This integration enables real-time metric "
        "filters and alarms on security-relevant API events, transforming passive audit "
        "records into an active detection capability. "
        "Create a CloudWatch Logs log group, grant CloudTrail the required IAM permissions "
        "to write to it, and update the trail configuration to specify the log group ARN. "
        "After integration, define metric filters for critical events (root account usage, "
        "IAM changes, CloudTrail modifications) and attach CloudWatch alarms with SNS "
        "notifications to each filter."
    ),
    "ALRT-002": (
        "It is recommended to create EventBridge rules that capture security-relevant "
        "CloudTrail events and route them to appropriate targets such as SNS topics, "
        "Lambda functions, or Security Hub. "
        "EventBridge provides richer event filtering, cross-account routing, and "
        "integration with a broader range of downstream services compared to CloudWatch "
        "alarms alone. "
        "Define rules for high-priority event patterns (IAM policy changes, Security Group "
        "modifications, root activity) and ensure each rule has at least one confirmed "
        "notification target. Test rules by simulating the target events in a non-production "
        "environment."
    ),
    "ALRT-003": (
        "It is recommended to create a CloudWatch alarm for every security-relevant metric "
        "filter defined in the CloudTrail log group. Without corresponding alarms, metric "
        "filters count events but generate no notifications, providing no operational value "
        "for incident detection. "
        "For each existing filter, create an alarm with a threshold of ≥1 occurrence, "
        "attach an SNS topic with confirmed subscriptions, and verify end-to-end delivery "
        "by triggering a test event. Document the expected response procedure for each alarm."
    ),
    "ALRT-004": (
        "It is recommended to add SNS topic targets to all EventBridge rules that capture "
        "security events. Rules without notification targets capture and process events but "
        "cannot alert the security team, providing no detection value. "
        "For each rule missing a target, add an SNS topic with confirmed subscriptions or "
        "a Lambda function that routes notifications to the appropriate channel. "
        "Verify target delivery by publishing a test event that matches the rule pattern."
    ),
    "ALRT-005": (
        "It is recommended to ensure that all SNS topics used for security notifications "
        "have at least one active, confirmed subscription. Topics with no confirmed "
        "subscriptions silently discard all published messages, meaning alerts never "
        "reach the security team. "
        "Review all security-related SNS topics and confirm subscriptions for all intended "
        "endpoints (email, SMS, HTTP/HTTPS, Lambda, SQS). "
        "Implement a periodic check that verifies at least one active subscription exists "
        "on each security SNS topic and alerts if the count drops to zero."
    ),
    "ALRT-006": (
        "It is recommended to confirm or replace all SNS subscriptions currently in "
        "'PendingConfirmation' state. Pending subscriptions receive no messages until "
        "confirmed, creating silent gaps in the notification chain. "
        "Re-send confirmation requests to intended recipients, or delete the pending "
        "subscription and create a replacement pointing to a confirmed endpoint. "
        "Establish a process to verify subscription status after any changes to "
        "notification infrastructure."
    ),
    "ALRT-007": (
        "It is recommended to add CloudWatch metric-filter coverage for the specific "
        "missing event names listed in the evidence, then create or map corresponding "
        "CloudWatch alarms with SNS notification actions. Do not replace existing "
        "working filters for other event categories; extend the current coverage and "
        "test each newly added event pattern in a non-production context."
    ),
    "ALRT-008": (
        "It is recommended to enable a multi-region CloudTrail trail that captures API "
        "activity across all AWS regions. Single-region trails create blind spots in "
        "regions where no monitoring is configured, which attackers can exploit to "
        "operate undetected. "
        "Update the existing trail to enable 'Apply trail to all regions' or create a "
        "new multi-region trail. Ensure the destination S3 bucket has appropriate "
        "retention and access policies for the increased log volume."
    ),
    "ALRT-009": (
        "It is recommended to create CloudWatch Metric Filters on the CloudTrail log "
        "group for security-critical event patterns. Without metric filters, logs are "
        "stored but cannot trigger automated alerts. "
        "Implement filters for: root account usage, unauthorized API calls, "
        "IAM policy changes, Security Group modifications, S3 bucket policy changes, "
        "CloudTrail configuration changes, and console login failures. "
        "For each filter, create a corresponding alarm with SNS notification."
    ),
    "ALRT-010": (
        "It is recommended to investigate and resolve all CloudWatch alarms in "
        "'INSUFFICIENT_DATA' state. This state indicates that the alarm cannot evaluate "
        "its metric due to missing data, stale dimensions, deleted resources, intentionally "
        "sparse metrics, or configuration errors. Review each affected alarm's namespace, "
        "metric name, dimensions, period, evaluation window, missing-data treatment, and "
        "notification actions. For metric-filter alarms, also verify the source log group "
        "and transformation name; for service metrics such as EC2 CPU, ALB health, or EC2 "
        "status checks, verify that the referenced resource still exists and emits data."
    ),
    "ALRT-011": (
        "It is recommended to apply restrictive resource-based policies to SNS topics "
        "used for security notifications. Topics without policies default to allowing "
        "all AWS principals to publish or modify subscriptions, potentially enabling "
        "attackers to inject false alerts or suppress legitimate ones. "
        "Restrict Publish permissions to the specific AWS services or accounts that "
        "legitimately publish to each topic (e.g., CloudWatch, EventBridge, Config) "
        "and deny all other principals."
    ),
    "ALRT-012": (
        "It is recommended to implement dedicated CloudWatch alarms or EventBridge rules "
        "for three critical event categories: ConsoleLogin (to detect unauthorized console "
        "access), CreateUser (to detect backdoor account creation), and StopLogging (to "
        "detect audit trail tampering). "
        "These three event types collectively cover the most common indicators of account "
        "compromise and insider threat activity. Each alarm should trigger an immediate "
        "SNS notification to the security team with sufficient context to begin triage."
    ),
    "ALRT-013": (
        "It is recommended to enable CloudTrail log file validation to ensure the "
        "cryptographic integrity of audit logs stored in S3. Log file validation generates "
        "a digest file for each log delivery that can be used to verify that logs have "
        "not been tampered with or deleted. "
        "Enable validation on the trail via the AWS Console or CLI and periodically "
        "run validation checks using the AWS CLI command: "
        "'aws cloudtrail validate-logs --trail-arn <ARN> --start-time <time>'. "
        "This control is essential for forensic investigations and compliance requirements "
        "that mandate audit log integrity."
    ),
    "ALRT-014": (
        "It is recommended to configure the CloudTrail trail to encrypt S3 log files "
        "using a customer-managed KMS key (CMK). Encryption with a CMK provides "
        "independent control over who can decrypt audit logs, enabling access revocation "
        "in the event of a key compromise. "
        "Create a KMS key with a policy that grants CloudTrail encrypt permissions and "
        "grants authorized auditors decrypt permissions. Update the trail configuration "
        "to reference the CMK ARN. "
        "Restrict key deletion and disable permissions to prevent unauthorized destruction "
        "of the encryption key protecting the audit trail."
    ),
    "ALRT-015": (
        "It is recommended to implement CloudWatch alarms or EventBridge rules that "
        "detect IAM policy modifications, role changes, and MFA configuration changes. "
        "Specifically, monitor for: CreatePolicy, DeletePolicy, AttachRolePolicy, "
        "DetachRolePolicy, PutUserPolicy, DeleteUserPolicy, EnableMFADevice, and "
        "DeactivateMFADevice API calls. "
        "Privilege escalation through IAM policy manipulation is one of the most "
        "frequently observed attacker techniques in compromised AWS environments. "
        "Immediate detection of these changes is critical to limiting the attacker's "
        "dwell time and blast radius."
    ),
    "ALRT-016": (
        "It is recommended to create CloudWatch alarms or EventBridge rules for Security "
        "Group ingress and egress rule changes (AuthorizeSecurityGroupIngress, "
        "RevokeSecurityGroupIngress, AuthorizeSecurityGroupEgress, RevokeSecurityGroupEgress). "
        "Security Group modifications can open unintended network access to sensitive "
        "resources, and detecting them immediately enables rapid response before "
        "exploitation can occur. "
        "Configure alerts to include the Security Group ID, the modified rule, and the "
        "IAM principal that made the change to accelerate triage."
    ),
    "ALRT-017": (
        "It is recommended to set the affected CloudWatch Log Groups to retain logs for "
        "at least 90 days, or to the organization's stricter compliance baseline where "
        "applicable. For audit and security log groups, consider 365 days or longer if "
        "required by incident-response or regulatory retention policy. Validate retention "
        "after the change with `aws logs describe-log-groups` and document any deliberate "
        "short-retention exceptions."
    ),
    "ALRT-022": (
        "It is recommended to implement CloudWatch alarms or EventBridge rules to detect "
        "S3 bucket policy and ACL changes (PutBucketPolicy, PutBucketAcl, "
        "DeleteBucketPolicy). These changes can inadvertently expose sensitive data "
        "publicly or grant unauthorized cross-account access. "
        "Alerts should include the bucket name and the principal that made the change "
        "to enable rapid assessment of whether the modification was authorized."
    ),
    "ALRT-023": (
        "It is recommended to create a CloudWatch alarm specifically for CloudTrail "
        "configuration changes, including StopLogging, DeleteTrail, UpdateTrail, and "
        "DeleteEventDataStore. "
        "Any modification to the audit trail by an unauthorized actor represents a "
        "high-confidence indicator of compromise, as disabling logging is a standard "
        "attacker technique for covering tracks. "
        "This alarm should have the highest priority and trigger immediate incident "
        "response procedures regardless of the time of day."
    ),
    "ALRT-024": (
        "It is recommended to configure EventBridge rules to detect AWS Config compliance "
        "state changes, specifically transitions from COMPLIANT to NON_COMPLIANT. "
        "Routing Config compliance change events to an SNS topic ensures the team "
        "responsible for remediation is notified immediately when a resource drifts "
        "from its compliant configuration, enabling faster remediation and reducing "
        "the compliance gap window."
    ),
    "ALRT-025": (
        "It is recommended to implement monitoring for VPC infrastructure changes, "
        "including VPC creation and deletion, internet gateway attachment/detachment, "
        "and route table modifications. "
        "These changes can fundamentally alter network boundaries and exposure, and "
        "should be subject to change management controls backed by automated detection. "
        "Alert on CreateVpc, DeleteVpc, AttachInternetGateway, DetachInternetGateway, "
        "and CreateRoute events from CloudTrail."
    ),
    "ALRT-026": (
        "It is recommended to create a dedicated CloudWatch alarm that triggers on any "
        "root account API activity, regardless of the action performed. "
        "Root account usage outside of documented break-glass scenarios should be "
        "treated as a potential security incident. "
        "Configure the alarm with zero tolerance (threshold ≥ 1) and route alerts to "
        "the security team's highest-priority notification channel with immediate "
        "response procedures documented."
    ),
    "ALRT-027": (
        "It is recommended to implement CloudWatch alarms or EventBridge rules for KMS "
        "key lifecycle events, specifically DisableKey, ScheduleKeyDeletion, and "
        "CancelKeyDeletion. "
        "Unauthorized disablement or deletion of a KMS key can render encrypted data "
        "permanently inaccessible, constituting a potential ransomware-equivalent event. "
        "Alerts should be routed to both the security team and the data owners of the "
        "workloads protected by the affected key, enabling immediate escalation and "
        "CancelKeyDeletion invocation if needed."
    ),
    # ── HARDENING ─────────────────────────────────────────────────────────────
    "HRD-001": (
        "It is recommended to enable AWS Config in the audited region with a recording "
        "configuration that captures all supported resource types. "
        "Configure a delivery channel pointing to a dedicated S3 bucket with appropriate "
        "retention and encryption policies, and grant Config the required IAM service role. "
        "Once enabled, activate relevant Config Rules (managed or custom) to evaluate "
        "resource compliance against your security baseline. "
        "AWS Config is a foundational control that enables continuous compliance monitoring, "
        "change tracking, and forensic investigation of configuration drift."
    ),
    "HRD-002": (
        "It is recommended to enable AWS Security Hub in the audited region and configure "
        "it to automatically aggregate findings from all integrated services including "
        "Inspector, GuardDuty, Config, Macie, and Firewall Manager. "
        "Enable the automatic standards enablement feature to activate the AWS Foundational "
        "Security Best Practices standard upon activation. "
        "Security Hub provides a consolidated, normalized view of security posture across "
        "services, enabling prioritized remediation and a single dashboard for compliance "
        "monitoring."
    ),
    "HRD-003": (
        "It is recommended to enable relevant compliance standards in AWS Security Hub "
        "based on the organization's regulatory obligations. At minimum, enable the AWS "
        "Foundational Security Best Practices (FSBP) standard, which provides automated "
        "checks against AWS security recommendations. "
        "For PCI DSS-scoped environments, enable the PCI DSS standard. For CIS benchmark "
        "alignment, enable CIS AWS Foundations. "
        "Review the compliance score for each standard after enablement and prioritize "
        "remediation of CRITICAL and HIGH failed controls."
    ),
    "HRD-004": (
        "It is recommended to conduct a comprehensive remediation effort targeting the "
        "Security Hub findings responsible for the compliance score below 50%. "
        "Export all failed CRITICAL and HIGH findings, assign ownership, and establish "
        "a time-bound remediation plan with executive visibility. "
        "A compliance score below 50% indicates pervasive security gaps across multiple "
        "domains that require a structured, prioritized remediation program rather than "
        "ad-hoc fixes. "
        "Consider engaging AWS Professional Services or a qualified security partner "
        "to accelerate remediation and establish a sustainable security baseline."
    ),
    "HRD-005": (
        "It is recommended to immediately prioritize remediation of all CRITICAL severity "
        "Security Hub findings. Export the current findings list, assign each to an "
        "owning team, and establish a 7-day remediation SLA for CRITICAL findings. "
        "Use Security Hub's built-in workflow status to track progress and escalate "
        "overdue findings to management. "
        "Implement automated suppression only for confirmed false positives with documented "
        "justification — do not suppress findings to improve the compliance score without "
        "addressing the underlying risk."
    ),
    "HRD-006": (
        "It is recommended to investigate all AWS Config recorders that are not in "
        "'RECORDING' state and restore their recording status. "
        "Common causes include: the recorder was manually stopped, the IAM service role "
        "lost permissions, or the S3 delivery bucket became inaccessible. "
        "Identify and resolve the root cause, re-enable recording, and implement a "
        "CloudWatch alarm on the 'ConfigurationRecorderStatus' metric to detect any "
        "future recording failures immediately."
    ),
    "HRD-007": (
        "It is recommended to enable the PCI DSS compliance standard in AWS Security Hub "
        "for all accounts that process, store, or transmit payment card data. "
        "This standard provides automated control checks mapped to PCI DSS requirements, "
        "enabling continuous compliance monitoring and gap identification. "
        "Review the initial compliance score after enablement, export all failed controls, "
        "and integrate findings into the organization's PCI DSS remediation tracking process."
    ),
    "HRD-008": (
        "It is recommended to prioritize remediation of Security Hub findings to improve "
        "the compliance score above 70%. Focus first on CRITICAL and HIGH findings, "
        "which typically have the greatest impact on the overall score. "
        "Establish a weekly remediation review cadence, assign findings to owning teams "
        "with clear SLAs, and track progress through Security Hub's workflow status. "
        "A score between 50-70% indicates significant but addressable security gaps."
    ),
    "HRD-009": (
        "It is recommended to establish a structured remediation program for the backlog "
        "of HIGH severity Security Hub findings. Assign each finding to an owning team, "
        "set a 30-day remediation SLA for HIGH findings, and review progress weekly. "
        "Implement Security Hub custom actions to route HIGH findings to ticketing systems "
        "(e.g., Jira, ServiceNow) for tracking outside the AWS console."
    ),
    "HRD-010": (
        "It is recommended to implement AWS Config Conformance Packs aligned with the "
        "organization's compliance requirements. Conformance Packs bundle multiple Config "
        "Rules into a single deployable unit, enabling automated evaluation against "
        "established frameworks such as CIS AWS Foundations, PCI DSS, or the AWS "
        "Operational Best Practices. "
        "Deploy conformance packs using AWS Organizations to ensure consistent coverage "
        "across all accounts and regions."
    ),
    "HRD-011": (
        "It is recommended to address the Security Hub findings responsible for the "
        "score between 70-85% to achieve full compliance. Identify the specific failed "
        "controls driving the gap, prioritize those with the highest risk impact, and "
        "establish a 60-day remediation plan. "
        "A score in this range indicates a generally sound posture with specific gaps "
        "that should be closed before the next audit or compliance assessment."
    ),
    "HRD-012": (
        "It is recommended to establish a systematic remediation process for the backlog "
        "of MEDIUM severity Security Hub findings. While individually lower risk, a large "
        "volume of unresolved MEDIUM findings can combine into high-impact attack chains "
        "and indicates a lack of remediation discipline. "
        "Set a 90-day SLA for MEDIUM findings, implement batch remediation for common "
        "finding types, and use AWS Systems Manager Automation for auto-remediation "
        "where applicable."
    ),
    "HRD-013": (
        "It is recommended to update Security Hub compliance standards to their latest "
        "versions. Outdated standard versions do not evaluate controls introduced in "
        "newer versions, creating blind spots for recently identified security gaps. "
        "Disable the outdated standard versions and enable the current versions. "
        "Review the new controls introduced in updated versions and assess them against "
        "your current configuration to identify any new gaps."
    ),
    "HRD-014": (
        "It is recommended to enable Amazon GuardDuty in the audited region and configure "
        "it across all production accounts through AWS Organizations where applicable. "
        "After enabling GuardDuty, route findings to Security Hub and EventBridge so "
        "critical detections can create tickets or notify the security team. "
        "Review any initial GuardDuty findings after activation and confirm detector "
        "coverage is enabled for relevant data sources."
    ),
    "HRD-015": (
        "It is recommended to remediate the remaining Security Hub findings to achieve "
        "a compliance score above 95%. Identify the specific failed controls in the "
        "remaining gap, prioritize them by remediation effort vs. risk reduction impact, "
        "and complete remediation within the next audit cycle. "
        "A score between 85-95% indicates a strong posture with a small number of "
        "addressable gaps."
    ),
    "HRD-016": (
        "It is recommended to review and remediate the outstanding LOW severity Security "
        "Hub findings in a scheduled maintenance window. While low individual risk, "
        "their accumulation indicates gaps in systematic remediation processes. "
        "Implement AWS Systems Manager Automation runbooks for common LOW finding types "
        "to enable bulk remediation and prevent future accumulation."
    ),
    # ── EXPOSURE ─────────────────────────────────────────────────────────────
    "EXP-001": (
        "It is recommended to enable S3 Block Public Access at both the account level "
        "and the bucket level for all S3 buckets. Navigate to the S3 console > Block "
        "Public Access settings and enable all four block settings: BlockPublicAcls, "
        "IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets. "
        "Review existing bucket ACLs and policies to identify and remove any public "
        "access grants. If a bucket legitimately serves public content, use CloudFront "
        "with Origin Access Control (OAC) rather than direct public bucket access, "
        "providing CDN caching and WAF protection as additional benefits."
    ),
    "EXP-002": (
        "It is recommended to set PubliclyAccessible to false for all RDS instances "
        "and place databases in private subnets with no internet gateway route. "
        "Update Security Groups to restrict inbound database traffic to specific "
        "application server security groups or IP ranges rather than 0.0.0.0/0. "
        "If external access is required for specific operational needs, use an SSH "
        "bastion host or AWS Systems Manager Session Manager as a secure, auditable "
        "alternative to direct internet exposure."
    ),
    "EXP-003": (
        "It is recommended to restrict Security Group rules allowing unrestricted SSH "
        "(port 22) or RDP (port 3389) access from 0.0.0.0/0. Replace these rules with "
        "rules that allow access only from specific corporate IP ranges or a dedicated "
        "bastion host security group. "
        "For a more secure alternative, eliminate SSH/RDP entirely and use AWS Systems "
        "Manager Session Manager for instance access, which requires no open inbound "
        "ports, provides session logging, and integrates with IAM for access control."
    ),
    "EXP-004": (
        "It is recommended to audit Security Group rules for EC2 instances with public "
        "IP addresses and remove any rules that expose management ports (22, 3389) or "
        "database ports (3306, 5432) to internet traffic. "
        "Apply the principle of least privilege: open only the ports required for the "
        "instance's function and restrict sources to specific security groups or "
        "CIDR ranges. "
        "Consider removing public IP assignments from instances that do not require "
        "direct internet reachability and routing traffic through a load balancer instead."
    ),
    "EXP-005": (
        "It is recommended to add authentication to Lambda Function URLs by changing "
        "AuthType from NONE to AWS_IAM. With AWS_IAM authentication, callers must "
        "sign their requests using AWS Signature Version 4, limiting invocation to "
        "authorized IAM principals. "
        "If the function must be publicly invocable, implement an API Gateway with "
        "Cognito, Lambda authorizer, or API key authentication as the entry point, "
        "and restrict the Lambda function URL to internal use only."
    ),
    "EXP-006": (
        "It is recommended to restrict S3 bucket policies to remove any public access "
        "grants that expose bucket contents to anonymous internet users. "
        "Review each bucket policy statement and remove or scope conditions that allow "
        "Principal: '*' without authentication requirements. "
        "Enable S3 Block Public Access at the account level to prevent future "
        "accidental public access grants."
    ),
    "EXP-007": (
        "It is recommended to associate an AWS WAFv2 WebACL with each internet-facing "
        "Application Load Balancer that serves public application traffic. Start with AWS "
        "managed rule groups for common web exploits and known bad inputs, then add custom "
        "rules for application-specific paths, rate limits, and allow or block lists. "
        "Validate the rules in count mode before enforcement where downtime risk exists, "
        "then monitor WAF logs and tune false positives."
    ),
    "EXP-010": (
        "It is recommended to update ALB listener TLS policies to require TLS 1.2 or "
        "higher. Select a security policy such as ELBSecurityPolicy-TLS13-1-2-2021-06 "
        "that disables TLS 1.0 and TLS 1.1. "
        "Older TLS versions are vulnerable to known attacks such as BEAST and POODLE. "
        "Before updating, validate that all clients connecting to the ALB support "
        "TLS 1.2 or higher to avoid service disruption."
    ),
    "EXP-011": (
        "It is recommended to remove s3:ListBucket permissions from any bucket policy "
        "that grants it to public or unauthenticated principals. "
        "Object enumeration should be restricted to authorized IAM principals only. "
        "If a public-facing application requires listing, implement an API Gateway "
        "or Lambda function that performs filtered listing with proper authentication "
        "and authorization checks."
    ),
    "EXP-013": (
        "It is recommended to add an explicit Deny statement to each affected bucket "
        "policy for s3:* on both the bucket ARN and object ARN when "
        "aws:SecureTransport=false. Apply the deny before service-specific Allow "
        "statements so all principals, including AWS services and cross-account roles, "
        "are required to use TLS. Validate the final policy with IAM Access Analyzer "
        "or the AWS Policy Simulator."
    ),
    "EXP-014": (
        "It is recommended to enable versioning on all S3 buckets storing audit logs "
        "and security evidence. Versioning protects against accidental or malicious "
        "deletion and overwriting by retaining previous object versions. "
        "Additionally, configure S3 Object Lock in Compliance mode for buckets "
        "containing regulatory audit data, preventing deletion or modification for "
        "the retention period regardless of IAM permissions."
    ),
    "EXP-015": (
        "It is recommended to replace public or cross-account S3 policy grants with "
        "explicit trusted principal ARNs and effective conditions. If organization "
        "scoping is required, set aws:PrincipalOrgID to the actual organization ID; "
        "do not leave it empty. For service integrations, use aws:SourceAccount and "
        "aws:SourceArn where supported. Remove any Principal:* Allow statements that "
        "are not strictly required."
    ),
    "EXP-016": (
        "It is recommended to configure Lambda Function URLs with AuthType=AWS_IAM "
        "to require signed request authentication. This restricts invocation to "
        "IAM principals with explicit lambda:InvokeFunctionUrl permissions. "
        "If the function must accept public traffic, front it with API Gateway and "
        "implement rate limiting, WAF protection, and appropriate authentication."
    ),
    "EXP-020": (
        "It is recommended to configure Origin Access Control (OAC) for all CloudFront "
        "distributions serving content from S3 origins. OAC replaces the legacy Origin "
        "Access Identity (OAI) and ensures that only CloudFront can read from the S3 "
        "bucket, preventing direct bucket access that bypasses WAF and geo-restrictions. "
        "Update the S3 bucket policy to allow access only from the CloudFront distribution's "
        "service principal with the specific distribution ID condition."
    ),
    "EXP-021": (
        "It is recommended to add authorization to all API Gateway routes that expose "
        "mutation methods (POST, PUT, PATCH, DELETE). "
        "Implement Cognito User Pool authorization, Lambda authorizers, or IAM "
        "authorization on each route. Start with mutation methods as they carry the "
        "highest risk of unauthorized data modification. "
        "Use API Gateway usage plans and API keys as an additional layer for "
        "rate limiting, even for authenticated routes."
    ),
    "EXP-022": (
        "It is recommended to replace catch-all API Gateway routes (ANY or {proxy+}) "
        "with explicit, authorized routes for each HTTP method and path. "
        "Catch-all routes make it easy to inadvertently expose functionality that "
        "was not intended to be public. Define explicit routes with appropriate "
        "authorization for each operation and remove the catch-all pattern."
    ),
    "EXP-023": (
        "It is recommended to replace wildcard Principal:* grants in resource-based "
        "policies with explicit principal ARNs or organizational conditions. "
        "Use aws:PrincipalOrgID to restrict access to principals within the organization, "
        "or specify exact IAM role ARNs for cross-account access. "
        "Review each service's resource policy (SQS, SNS, Secrets Manager, ECR, "
        "OpenSearch) and apply the principle of least privilege."
    ),
    "EXP-024": (
        "It is recommended to encrypt audit and log S3 buckets with customer-managed "
        "KMS keys (CMK). CMK encryption provides independent control over who can "
        "decrypt bucket contents via the KMS key policy, enabling access revocation "
        "independent of S3 bucket policies. "
        "Create a dedicated CMK for log encryption, restrict Decrypt permissions to "
        "authorized auditors, and update the bucket's default encryption configuration "
        "to reference the CMK ARN."
    ),
    "EXP-026": (
        "It is recommended to disable the PubliclyAccessible flag on all RDS instances "
        "that do not require direct internet connectivity. Navigate to RDS > Instances > "
        "Modify and set 'Publicly Accessible' to No. Ensure the instance is only reachable "
        "through the VPC via private subnets and security groups. If external access is "
        "genuinely required, restrict it to specific IP ranges via security group inbound "
        "rules rather than exposing the RDS endpoint to the entire internet."
    ),
    "EXP-028": (
        "It is recommended to audit all internet-facing resources and disable or "
        "restrict those that no longer serve a legitimate business function. "
        "Reduce the external attack surface by removing unused Elastic IPs, "
        "decommissioning unused ALB listeners, and disabling API Gateway stages "
        "that are no longer in use."
    ),
    # ── CICD ─────────────────────────────────────────────────────────────────
    "CICD-001": (
        "It is recommended to remove source credentials from CodeBuild project "
        "configurations and replace them with OAuth-based connections via AWS "
        "CodeConnections (formerly CodeStar Connections). "
        "CodeConnections provides short-lived, scoped access tokens that are managed "
        "by AWS and do not require storing VCS credentials in project configuration. "
        "Audit all CodeBuild projects for stored credentials, migrate to CodeConnections, "
        "and implement a policy preventing future manual credential configuration."
    ),
    "CICD-002": (
        "It is recommended to disable insecureSSL settings and remove non-validated "
        "proxy configurations from all CodeBuild projects. "
        "insecureSSL=true allows man-in-the-middle attacks against build traffic, "
        "potentially enabling dependency poisoning or artifact tampering during the "
        "build process. "
        "Update each affected project's source configuration to set insecureSSL=false "
        "and validate that all external connections use certificate-verified TLS."
    ),
    # ── COMPUTE ──────────────────────────────────────────────────────────────
    "COMP-EC2-001": (
        "It is recommended to enforce IMDSv2 (token-based) on all EC2 instances with "
        "attached IAM instance profiles by setting HttpTokens=required. "
        "IMDSv2 requires a session-oriented PUT request to obtain a token before "
        "metadata can be retrieved, blocking SSRF attacks that can steal IAM credentials "
        "via the metadata endpoint in IMDSv1. "
        "Apply this change incrementally: first verify application compatibility by "
        "monitoring IMDSv2 usage via CloudWatch, then update the instance metadata "
        "options using: aws ec2 modify-instance-metadata-options --instance-id <id> "
        "--http-tokens required --http-endpoint enabled. "
        "Use an AWS Config rule or SCP to enforce IMDSv2 on all new instances."
    ),
    "COMP-EC2-002": (
        "It is recommended to review and sanitize EC2 user-data scripts to remove any "
        "hardcoded credentials, secrets, or remote code execution patterns. "
        "Replace hardcoded secrets with references to AWS Secrets Manager or Parameter "
        "Store, which can be retrieved at instance startup using the instance's IAM role. "
        "Prevent remote execution patterns (e.g., curl | bash) by hosting bootstrap "
        "scripts in private S3 buckets accessible only via the instance role. "
        "Implement a code review process for user-data scripts and scan them with "
        "secrets detection tools as part of the CI/CD pipeline."
    ),
    "COMP-ECS-001": (
        "It is recommended to restrict who can create and modify EventBridge rules that "
        "target ECS RunTask actions. Apply IAM policies that limit events:PutRule and "
        "iam:PassRole permissions to a dedicated CI/CD role. "
        "Implement monitoring for changes to EventBridge rules targeting ECS tasks, "
        "and require change management approval for any modifications to scheduled "
        "container workloads. "
        "Review existing rules to verify that all scheduled ECS tasks run expected, "
        "authorized container images."
    ),
    "COMP-ECS-002": (
        "It is recommended to enforce immutable deployments for ECS task definitions "
        "by managing them through Infrastructure as Code (IaC) and restricting "
        "direct RegisterTaskDefinition and UpdateService permissions. "
        "Implement a baseline comparison process that detects configuration drift in "
        "task definitions and alerts on unexpected changes. "
        "Use ECR immutable image tags to prevent silent replacement of container images "
        "in existing task definitions."
    ),
    "COMP-ECS-003": (
        "It is recommended to configure the awslogs log driver for all ECS task "
        "definitions, directing container stdout/stderr to a dedicated CloudWatch "
        "Logs log group. "
        "Centralized logging enables forensic investigation, anomaly detection, and "
        "compliance reporting for containerized workloads. "
        "Set appropriate log retention periods and implement metric filters for "
        "security-relevant log patterns such as authentication failures or "
        "unexpected process execution."
    ),
    "COMP-ECS-004": (
        "It is recommended to apply the principle of least privilege to ECS task roles "
        "and execution roles. Review each role's attached policies and remove any "
        "wildcard actions or overly broad resource grants. "
        "Use IAM Access Analyzer to generate least-privilege policy recommendations "
        "based on actual access patterns observed in CloudTrail. "
        "Implement permission boundaries on task roles to limit the maximum permissions "
        "a compromised container can use, regardless of the attached policies."
    ),
    "COMP-ECS-005": (
        "It is recommended to remove all plaintext credentials from ECS task definition "
        "environment variables and replace them with references to AWS Secrets Manager "
        "or Parameter Store. "
        "ECS supports native Secrets Manager integration: specify the secret ARN in the "
        "'secrets' field of the container definition rather than the 'environment' field. "
        "The ECS execution role will retrieve and inject the secret value at task launch "
        "time, ensuring credentials are never visible in the task definition configuration. "
        "Rotate any credentials that were previously exposed in task definitions."
    ),
    "COMP-EKS-001": (
        "It is recommended to restrict public access to the EKS cluster API endpoint "
        "by enabling the private endpoint and adding an IP allowlist to the public "
        "endpoint configuration. "
        "Specify only the CIDR ranges of authorized networks (VPN, office IPs, CI/CD "
        "systems) in the public access CIDR list. "
        "For maximum security, disable the public endpoint entirely and access the "
        "Kubernetes API exclusively through VPN or AWS PrivateLink. "
        "Monitor for unauthorized authentication attempts via EKS control plane logs "
        "in CloudWatch."
    ),
    "COMP-EKS-002": (
        "It is recommended to enable all EKS control plane log types: api, audit, "
        "authenticator, controllerManager, and scheduler. "
        "These logs capture all Kubernetes API server requests, authentication events, "
        "RBAC authorization decisions, and controller activity, providing comprehensive "
        "forensic coverage for incident investigation. "
        "Route EKS logs to CloudWatch Logs and implement retention policies appropriate "
        "for your compliance requirements."
    ),
    "COMP-LMB-001": (
        "It is recommended to add AWS_IAM authentication to Lambda Function URLs or "
        "replace them with API Gateway endpoints that implement appropriate authorization. "
        "If the function must accept public unauthenticated requests, implement a "
        "Lambda authorizer that validates tokens or API keys before allowing execution, "
        "and add AWS WAF to protect against abuse."
    ),
    "COMP-LMB-002": (
        "It is recommended to replace over-privileged Lambda execution roles with "
        "least-privilege roles scoped to the specific AWS services and resources the "
        "function actually accesses. "
        "Use IAM Access Analyzer to review the role's effective permissions and generate "
        "a least-privilege policy based on CloudTrail activity. "
        "Never attach AdministratorAccess or wildcard action policies to Lambda execution "
        "roles, as a function compromise would grant full account control."
    ),
    # ── ECR ──────────────────────────────────────────────────────────────────
    "ECR-001": (
        "It is recommended to update ECR repository policies to replace wildcard "
        "principals (Principal: '*') with explicit IAM role ARNs or account IDs "
        "limited to the services and accounts that legitimately pull images. "
        "Add aws:PrincipalOrgID conditions to cross-account grants to restrict access "
        "to principals within the organization. "
        "Enabling public repository policies effectively publishes proprietary container "
        "images — including embedded configurations and potentially hardcoded secrets — "
        "to the global internet."
    ),
    "ECR-002": (
        "It is recommended to enable immutable image tags on all ECR repositories that "
        "store production images. Immutable tags prevent any push from overwriting an "
        "existing tag, ensuring that once an image tag is published, it always refers "
        "to the same image digest. "
        "This prevents a compromised CI/CD pipeline or unauthorized user from silently "
        "replacing a production image with a malicious version. "
        "Enable with: aws ecr put-image-tag-mutability --repository-name <name> "
        "--image-tag-mutability IMMUTABLE"
    ),
    "ECR-003": (
        "It is recommended to enable image scanning on push for all ECR repositories "
        "to automatically detect known CVEs in container images at the point of upload. "
        "Configure Enhanced Scanning (using Inspector v2) for comprehensive coverage "
        "including OS packages and application dependencies. "
        "Implement a policy that blocks deployment of images with CRITICAL or HIGH "
        "unresolved CVEs by integrating scan results into the CI/CD pipeline gate. "
        "Enable with: aws ecr put-image-scanning-configuration --repository-name <name> "
        "--image-scanning-configuration scanOnPush=true"
    ),
    "ECR-004": (
        "It is recommended to configure registry-level scanning settings in ECR to "
        "apply consistent vulnerability scanning across all repositories. "
        "Use ECR Enhanced Scanning powered by AWS Inspector v2, which provides "
        "continuous scanning (not just on push), deeper dependency analysis, and "
        "integration with Security Hub for centralized finding management."
    ),
    "ECR-005": (
        "It is recommended to configure customer-managed KMS encryption for ECR "
        "repositories storing sensitive container images. "
        "Create a dedicated CMK for ECR, restrict Decrypt and GenerateDataKey "
        "permissions to authorized principals, and update the repository's encryption "
        "configuration to reference the CMK ARN. "
        "CMK encryption enables independent access control and revocation for "
        "container image data separate from ECR repository policies."
    ),
    "ECR-006": (
        "It is recommended to configure lifecycle policies on all ECR repositories "
        "to automatically expire and delete outdated image versions. "
        "Define rules that retain only the N most recent tagged versions (e.g., last "
        "10 tagged images) and expire untagged images after a defined period. "
        "Lifecycle policies reduce storage costs, prevent accumulation of images with "
        "unpatched vulnerabilities, and limit the available attack surface for "
        "supply chain attacks using stale images."
    ),
    "ECR-007": (
        "It is recommended to audit cross-account repository policy grants and restrict "
        "them to the minimum principals required. "
        "Specify exact IAM role ARNs for cross-account pull access rather than granting "
        "broad account-level access. Add aws:PrincipalOrgID conditions to ensure access "
        "is limited to accounts within the organization. "
        "Implement monitoring for unusual cross-account pull activity via CloudTrail "
        "ecr:GetAuthorizationToken and ecr:BatchGetImage events."
    ),
    # ── KMS ──────────────────────────────────────────────────────────────────
    "KMS-001": (
        "It is recommended to update KMS key policies to restrict principal grants "
        "to the specific IAM roles, users, or services that legitimately need "
        "cryptographic access. "
        "Replace wildcard or overly broad principal conditions with explicit ARNs "
        "and add aws:SourceAccount conditions for cross-account grants. "
        "Follow the principle of separation of duties: key administrators should not "
        "also have cryptographic usage permissions, and key users should not have "
        "administrative permissions on the key."
    ),
    "KMS-002": (
        "It is recommended to review all KMS grants and revoke any that grant Decrypt "
        "or GenerateDataKey permissions to unexpected principals. "
        "Grants persist independently of key policies and can survive key policy updates, "
        "so they must be managed explicitly. "
        "Use: aws kms list-grants --key-id <id> to enumerate all grants, and "
        "aws kms retire-grant or revoke-grant to remove unauthorized ones. "
        "Implement CloudTrail monitoring for CreateGrant events to detect future "
        "unauthorized grant creation."
    ),
    "KMS-003": (
        "It is recommended to restrict KMS key policy and grant management permissions "
        "(PutKeyPolicy, CreateGrant) to a small number of trusted key administrator "
        "principals with enforced separation of duties. "
        "Implement CloudTrail alerts for any execution of these actions and require "
        "peer review or change management approval for key policy modifications. "
        "An identity with PutKeyPolicy permission can grant itself or others full "
        "cryptographic access to any data encrypted with the key."
    ),
    "KMS-004": (
        "It is recommended to enable automatic annual key rotation for all "
        "customer-managed KMS keys. Automatic rotation generates new cryptographic "
        "material each year while preserving the ability to decrypt data encrypted "
        "with previous key versions, requiring no application-level changes. "
        "Enable rotation with: aws kms enable-key-rotation --key-id <key-id>. "
        "Key rotation limits the amount of data encrypted under any single key version, "
        "reducing the impact of a potential key compromise."
    ),
    "KMS-005": (
        "It is recommended to restrict KMS key deletion and disable permissions "
        "(DisableKey, ScheduleKeyDeletion) to a dedicated key custodian role that "
        "is subject to strict access controls and multi-person approval requirements. "
        "Configure a deletion waiting period of at least 7 days (maximum 30) to "
        "allow time for detection and cancellation of unauthorized deletion. "
        "Implement CloudTrail alarms on ScheduleKeyDeletion and DisableKey events "
        "that trigger immediate security team notification."
    ),
    "KMS-006": (
        "It is recommended to restrict DeleteImportedKeyMaterial permissions on keys "
        "with imported key material (EXTERNAL origin) to only the key owner within "
        "the organization. "
        "If this permission has been granted to external principals, revoke it "
        "immediately and audit for any recent invocations in CloudTrail. "
        "Consider re-importing or rotating the key material if there is any doubt "
        "about whether the permission was misused."
    ),
    "KMS-007": (
        "It is recommended to audit KMS grants that include the CreateGrant permission "
        "and revoke those that are not explicitly required for the integration's function. "
        "CreateGrant delegation enables a chain of access propagation that can become "
        "difficult to fully revoke. "
        "Where grant delegation is required, restrict it to specific grantee principals "
        "and add a retiring principal to enable controlled grant retirement."
    ),
    # ── MESSAGING ─────────────────────────────────────────────────────────────
    "MSG-001": (
        "It is recommended to restrict SQS queue policies from using aws:PrincipalOrgID "
        "as the sole access condition and replace broad organizational grants with "
        "explicit IAM role ARNs for the specific services or accounts that require "
        "queue access. "
        "Org-wide grants allow any identity in any account, including potentially "
        "compromised ones, to interact with queue data. "
        "Apply least-privilege: grant SendMessage to producers only, ReceiveMessage "
        "and DeleteMessage to consumers only, and specify exact principal ARNs."
    ),
    "MSG-002": (
        "It is recommended to review Dead Letter Queue (DLQ) configurations and "
        "apply restrictive access policies to DLQ buckets. "
        "Ensure that DLQ access is restricted to the same principals authorized to "
        "access the source queue, and that DLQ contents are monitored and purged "
        "on a regular schedule. "
        "Implement encryption at rest for DLQs containing sensitive message data "
        "and audit access to DLQ messages via CloudTrail."
    ),
    "MSG-003": (
        "It is recommended to add aws:SourceArn and aws:SourceAccount conditions "
        "to SQS queue policies that accept messages from SNS subscriptions. "
        "These conditions ensure that only messages from the specific authorized "
        "SNS topic ARN can be delivered to the queue, preventing message injection "
        "from other SNS topics, including attacker-controlled ones. "
        'Example condition: {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:region:account:topic-name"}}'
    ),
    "MSG-004": (
        "It is recommended to implement CloudTrail monitoring for StartMessageMoveTask "
        "events on SQS queues containing sensitive data. "
        "Configure an EventBridge rule that triggers an SNS notification when this "
        "API is called, enabling the security team to verify that message moves are "
        "authorized before data reaches an unintended destination."
    ),
    "MSG-005": (
        "It is recommended to replace Principal:* grants in SQS queue policies with "
        "explicit IAM role ARNs for each authorized producer and consumer. "
        "Apply separate grant statements for SendMessage (producers) and "
        "ReceiveMessage + DeleteMessage (consumers) to enforce role separation. "
        "Test policy changes in a non-production environment before applying to "
        "queues serving production workloads."
    ),
    "MSG-006": (
        "It is recommended to enable server-side encryption for all SQS queues "
        "using AWS KMS. For queues containing sensitive data, use a customer-managed "
        "KMS key to enable independent access control over message decryption. "
        "Enable with: aws sqs set-queue-attributes --queue-url <url> "
        "--attributes KmsMasterKeyId=<key-id>. "
        "Encryption at rest protects message content from unauthorized access at "
        "the storage layer, even if SQS permissions are misconfigured."
    ),
    "MSG-007": (
        "It is recommended to restrict sns:Subscribe permissions in SNS topic policies "
        "to specific IAM principals and protocol types. "
        "Replace unrestricted subscribe grants with explicit principal ARNs and add "
        "aws:SourceAccount conditions for cross-account subscriptions. "
        "Unrestricted subscribe access allows any identity to receive all messages "
        "published to the topic, enabling passive interception of notification data."
    ),
    "MSG-008": (
        "It is recommended to restrict sns:Publish permissions to specific IAM "
        "principals and AWS services that legitimately publish to each topic. "
        "Use aws:SourceArn conditions for service-published topics (e.g., CloudWatch "
        "alarms, EventBridge) to ensure only the authorized source can publish. "
        "Unrestricted publish access enables injection of arbitrary messages into "
        "downstream processing pipelines."
    ),
    "MSG-009": (
        "It is recommended to restrict administrative SNS topic permissions (DeleteTopic, "
        "SetTopicAttributes, AddPermission) to a dedicated topic administrator role "
        "and remove these permissions from wildcard principals. "
        "Implement CloudTrail monitoring for DeleteTopic events on security-critical "
        "notification topics to detect unauthorized destruction of alerting infrastructure."
    ),
    # ── NETWORK ──────────────────────────────────────────────────────────────
    "NET-001": (
        "It is recommended to restrict Security Group rules that allow unrestricted "
        "access (0.0.0.0/0) to sensitive ports. Replace broad CIDR rules with specific "
        "sources: corporate VPN CIDR ranges for administrative access, specific security "
        "group IDs for service-to-service communication, and load balancer security "
        "groups for application traffic. "
        "For SSH and RDP, consider eliminating open inbound rules entirely by using "
        "AWS Systems Manager Session Manager, which provides authenticated, audited "
        "shell access without requiring any inbound port to be open."
    ),
    "NET-002": (
        "It is recommended to remove 'allow all traffic' Security Group rules "
        "(protocol -1 from 0.0.0.0/0) and replace them with specific, least-privilege "
        "rules that permit only the protocols and ports required for each resource's function. "
        "Audit each affected Security Group to understand legitimate traffic patterns, "
        "define minimum necessary rules, and validate that removing the broad rule "
        "does not break application functionality in a staging environment before "
        "applying to production."
    ),
    "NET-003": (
        "It is recommended to replace permissive ALLOW ALL NACL rules with specific "
        "rules that permit only required traffic flows. NACLs operate at the subnet "
        "level and provide a second layer of defense behind Security Groups. "
        "Remember that NACLs are stateless: both inbound and outbound rules must be "
        "defined for each traffic flow. Apply the principle of least privilege: allow "
        "only the ports and protocols needed for resources in each subnet."
    ),
    "NET-004": (
        "It is recommended to review route tables for subnets hosting sensitive resources "
        "and remove default routes (0.0.0.0/0) pointing to Internet Gateways unless "
        "the resources legitimately require direct internet reachability. "
        "Move sensitive resources (databases, internal services) to private subnets with "
        "no internet route, and use NAT Gateways for outbound-only internet access. "
        "If resources require inbound internet access, place them behind a load balancer "
        "in a dedicated public subnet rather than giving them direct internet routes."
    ),
    "NET-005": (
        "It is recommended to clear all inbound and outbound rules from the default "
        "Security Group in every VPC, ensuring it allows no traffic. "
        "Resources should never be placed in the default Security Group; instead, "
        "create purpose-built Security Groups with explicitly defined rules. "
        "Apply an AWS Config rule ('vpc-default-security-group-closed') to continuously "
        "monitor and alert when the default Security Group has non-empty rules."
    ),
    "NET-006": (
        "It is recommended to enable VPC Flow Logs for all VPCs to capture network "
        "traffic metadata for security analysis, anomaly detection, and forensic "
        "investigation. "
        "Configure Flow Logs to publish to CloudWatch Logs or S3 with appropriate "
        "retention periods. Use the 'ALL' traffic filter (not just REJECT) to capture "
        "a complete traffic picture. "
        "VPC Flow Logs are essential for investigating security incidents, detecting "
        "lateral movement, and identifying data exfiltration patterns."
    ),
    "NET-007": (
        "It is recommended to deploy AWS Network Firewall, or an equivalent central "
        "inspection layer, for internet-facing VPC traffic. Route north-south traffic "
        "through inspection endpoints before it reaches public subnets or exits the VPC. "
        "Define firewall policies for known malicious destinations, command-and-control "
        "patterns, and protocol anomalies."
    ),
    "NET-008": (
        "It is recommended to move critical workloads such as databases and internal "
        "application services to private subnets without direct Internet Gateway routes. "
        "Expose only the required frontend or ingress components in public subnets, and "
        "route administrative or application access through controlled private paths."
    ),
    "NET-009": (
        "It is recommended to narrow broad Security Group CIDR sources to the smallest "
        "required ranges or replace them with Security Group references where workloads "
        "are in the same VPC. Document any intentionally broad rule and add monitoring "
        "or compensating controls for services that cannot be scoped further."
    ),
    "NET-010": (
        "It is recommended to replace default allow-all Network ACL behavior with "
        "custom NACLs that explicitly allow only required inbound and outbound traffic "
        "for each subnet tier. Review both ingress and egress entries and remove broad "
        "0.0.0.0/0 allow-all rules where they are not required."
    ),
    "NET-011": (
        "It is recommended to add clear descriptions to all critical Security Group "
        "rules, especially rules covering sensitive ports, all protocols, broad CIDRs, "
        "or cross-tier access. Use descriptions to record the business owner, purpose, "
        "source system, and expected review cadence."
    ),
    "NET-013": (
        "It is recommended to create VPC Gateway Endpoints for S3 and DynamoDB where "
        "private subnets access those services, and VPC Interface Endpoints for services "
        "such as SSM, KMS, CloudWatch, ECR, and EC2 APIs when used by private workloads. "
        "Keep the NAT Gateway for required internet egress, but route supported AWS service "
        "traffic through endpoints so endpoint policies and private routing can be enforced."
    ),
    "NET-012": (
        "It is recommended to review Security Groups that reference themselves as a "
        "source and assess whether the implicit trust between all group members is "
        "appropriate. "
        "If all resources in the group should communicate freely, document this as an "
        "intentional design decision. If not, break the group into smaller, more "
        "specific groups with explicit rules between them. "
        "Self-referencing Security Groups enable lateral movement between all group "
        "members if any one instance is compromised."
    ),
    "NET-014": (
        "It is recommended to implement network segmentation between application tiers "
        "by creating separate Security Groups and subnets for the presentation (web), "
        "application, and data layers. "
        "Define explicit Security Group rules that allow only required traffic between "
        "tiers (e.g., web tier → app tier on specific ports, app tier → database tier). "
        "This prevents direct communication between the web tier and database tier, "
        "limiting the blast radius of a web application compromise."
    ),
    "NET-015": (
        "It is recommended to implement AWS Network Firewall or equivalent stateful "
        "inspection for production VPCs handling sensitive data. "
        "Network Firewall provides stateful inspection, intrusion prevention, and "
        "domain-based filtering for both north-south (internet-facing) and east-west "
        "(inter-VPC) traffic flows. "
        "Deploy Network Firewall in a dedicated inspection VPC using a hub-and-spoke "
        "architecture with Transit Gateway to centralize inspection across all VPCs."
    ),
    "NET-016": (
        "It is recommended to associate subnets with custom Network ACLs aligned to "
        "their tier and exposure model. Public, private, application, and data subnets "
        "should have explicit stateless rules instead of inheriting default VPC NACLs."
    ),
    "NET-017": (
        "It is recommended to disable MapPublicIpOnLaunch on subnets that should not "
        "automatically assign public IPs to launched instances. "
        "Instances that require internet access should receive Elastic IPs explicitly "
        "or use a NAT Gateway for outbound-only access. "
        "Automatic public IP assignment means a misconfigured Security Group rule "
        "immediately exposes the instance to the internet without any additional action."
    ),
    "NET-018": (
        "It is recommended to audit Security Groups for stale rules referencing "
        "non-existent resources or Security Groups and remove them. "
        "Stale references to deleted Security Group IDs can be reassigned to new "
        "resources, inadvertently granting them access. "
        "Use AWS Config rule 'restricted-common-ports' and regular Security Group "
        "audits to maintain rule hygiene."
    ),
    "NET-019": (
        "It is recommended to enable DNS resolution and DNS hostnames for VPCs that "
        "require private service discovery. Without these settings, instances cannot "
        "resolve private DNS names, potentially forcing applications to use public "
        "endpoints for internal communication. "
        "Enable both settings for all VPCs: aws ec2 modify-vpc-attribute "
        "--vpc-id <id> --enable-dns-support and --enable-dns-hostnames."
    ),
    "NET-021": (
        "It is recommended to deploy NAT Gateways in multiple Availability Zones to "
        "ensure high availability of outbound internet connectivity for private subnets. "
        "Create a NAT Gateway in each AZ where private subnets exist and update each "
        "subnet's route table to use the NAT Gateway in the same AZ. "
        "This prevents a single AZ failure from disrupting all outbound connectivity "
        "for private resources."
    ),
    "NET-022": (
        "It is recommended to review all public subnets (those with a default route "
        "to an Internet Gateway) and verify that only resources that legitimately "
        "require direct internet reachability are hosted there. "
        "Move internal resources to private subnets and ensure that Security Groups "
        "on public-subnet resources implement strict inbound filtering."
    ),
    "NET-025": (
        "It is recommended to tag all subnets with a consistent classification model, "
        "for example Tier, Layer, Classification, Environment, and Owner. Use these tags "
        "in compliance checks, routing reviews, and change workflows so public, private, "
        "application, and data subnets can be governed automatically."
    ),
    "NET-027": (
        "It is recommended to apply consistent tags to all Security Groups, including "
        "Owner, Application, Environment, DataClassification, and ReviewDate. Enforce "
        "tagging at creation time and use periodic checks to identify orphaned or "
        "unowned Security Groups."
    ),
    "NET-029": (
        "It is recommended to implement egress filtering rules in Security Groups "
        "for sensitive resources. Replace allow-all outbound rules with specific "
        "rules that permit only required outbound traffic flows (e.g., HTTPS to "
        "specific AWS service endpoints, database port to specific data tier). "
        "Restrictive egress rules limit the ability of a compromised resource to "
        "exfiltrate data or establish command-and-control communications."
    ),
    # ── RECON ─────────────────────────────────────────────────────────────────
    "RECON-001": (
        "It is recommended to remove wildcard DNS records (*.domain) from public "
        "Route53 hosted zones and replace them with explicit A or CNAME records "
        "for each legitimate subdomain. "
        "Wildcard records resolve any subdomain to a resource, potentially exposing "
        "infrastructure to subdomain takeover if any matching service is decommissioned "
        "without removing the DNS record. "
        "Implement DNS monitoring to detect unexpected subdomain resolution patterns "
        "and periodically audit hosted zone records for unused or stale entries."
    ),
    "RECON-002": (
        "It is recommended to add authentication and authorization to all API Gateway "
        "stages and routes that should not be publicly accessible. "
        "Implement Cognito User Pool authorizers for consumer-facing APIs, IAM "
        "authorization for service-to-service APIs, and Lambda authorizers for "
        "custom authentication logic. "
        "Restrict API key usage to rate limiting only, not as a security control."
    ),
    "RECON-003": (
        "It is recommended to restrict Security Groups attached to instances with "
        "Elastic IPs to allow only the minimum required inbound traffic. "
        "Review each Elastic IP and its associated resource to verify that its "
        "internet exposure is intentional and necessary. "
        "Disassociate Elastic IPs from resources that do not require direct "
        "internet reachability."
    ),
    "RECON-004": (
        "It is recommended to audit public Route53 hosted zones for DNS records that "
        "reveal internal architecture details such as internal naming conventions, "
        "RFC-1918 IP addresses, or service topology information. "
        "Remove or obfuscate records that provide unnecessary reconnaissance value "
        "to potential attackers, replacing descriptive internal hostnames with "
        "generic external-facing names where possible."
    ),
    "RECON-005": (
        "It is recommended to review public API endpoints and endpoints that return "
        "sensitive metadata and add authentication requirements or remove unnecessary "
        "information from unauthenticated responses. "
        "Implement response filtering to ensure that error messages, headers, and "
        "API responses do not reveal internal system details."
    ),
    "RECON-006": (
        "It is recommended to enable access logging for all CloudFront distributions "
        "by configuring a logging bucket in the distribution settings. "
        "CloudFront access logs capture all HTTP requests including URI, headers, "
        "response codes, and client IP addresses, providing essential data for "
        "security analysis, anomaly detection, and forensic investigation."
    ),
    "RECON-007": (
        "It is recommended to associate AWS WAF Web ACLs with all internet-facing "
        "Application Load Balancers and any other supported public HTTP entry points. "
        "Start with AWS Managed Rules, add rate-based rules for abusive clients, and "
        "enable WAF logging so blocked and counted requests can be reviewed. "
        "Where WAF is intentionally omitted, document the compensating controls and "
        "business justification for each load balancer."
    ),
    "RECON-008": (
        "It is recommended to conduct an internet-facing asset inventory review to "
        "verify that all public entry points are intentional, documented, and properly "
        "protected. "
        "For each public resource, verify that WAF protection is in place, TLS "
        "is enforced, access logging is enabled, and Security Groups restrict "
        "access to required ports only. "
        "Consider implementing an external attack surface management (EASM) tool "
        "to continuously monitor the organization's public-facing footprint."
    ),
    "RECON-009": (
        "It is recommended to enable access logging for all API Gateway REST stages "
        "by configuring a CloudWatch Logs log group as the access log destination. "
        "API access logs capture request details including caller identity, latency, "
        "status codes, and request/response size, enabling detection of abuse patterns "
        "and forensic investigation of API-based incidents."
    ),
    "RECON-010": (
        "It is recommended to review the organization's Elastic IP allocation and "
        "release any EIPs not currently associated with an active resource. "
        "Unattached EIPs incur unnecessary costs and contribute to the organization's "
        "trackable public IP footprint without serving any purpose. "
        "Document all retained EIPs with their associated resources and purpose "
        "for attack surface management purposes."
    ),
    "RECON-011": (
        "It is recommended to configure HTTP-to-HTTPS redirect rules on all public "
        "Application Load Balancers. Add an HTTP (port 80) listener with a redirect "
        "action that forwards all requests to HTTPS (port 443) with a 301 status code. "
        "This ensures that all application traffic is encrypted regardless of whether "
        "the client initially connects on HTTP, preventing credential interception "
        "on untrusted networks."
    ),
    "RECON-012": (
        "It is recommended to associate an AWS WAF Web ACL with all public CloudFront "
        "distributions. "
        "Start with AWS Managed Rules (AWSManagedRulesCommonRuleSet and "
        "AWSManagedRulesKnownBadInputsRuleSet) to immediately gain OWASP Top 10 "
        "protection, then add custom rules for application-specific threats. "
        "Enable WAF logging to capture blocked and sampled requests for security analysis."
    ),
    "RECON-013": (
        "It is recommended to review the necessity of all public Route53 hosted zones "
        "and consolidate where possible to reduce DNS footprint complexity. "
        "Implement Route53 Resolver DNS Firewall to filter outbound DNS queries and "
        "detect DNS-based data exfiltration. "
        "Regularly audit zone records to remove stale entries that could enable "
        "subdomain takeover attacks."
    ),
    "RECON-014": (
        "It is recommended to add authentication to all API Gateway routes, prioritizing "
        "those that expose more than 5 unauthenticated endpoints. "
        "Use AWS WAF rate limiting on unauthenticated routes that must remain public "
        "to prevent automated enumeration and abuse. "
        "Implement API Gateway usage plans for rate limiting even on authenticated routes."
    ),
    "RECON-015": (
        "It is recommended to restrict public access to account and service metadata "
        "endpoints by requiring authentication for all metadata retrieval operations. "
        "Review which resources expose metadata without authentication and apply "
        "appropriate access controls."
    ),
    "RECON-016": (
        "It is recommended to release all Elastic IP addresses that are not currently "
        "associated with an active resource. "
        "Run: aws ec2 describe-addresses --query 'Addresses[?AssociationId==null]' "
        "to identify unattached EIPs, then release them with: "
        "aws ec2 release-address --allocation-id <id>. "
        "Unattached EIPs generate unnecessary charges and contribute to the "
        "organization's external IP footprint."
    ),
    "RECON-017": (
        "It is recommended to review ALB listeners that expose non-standard or "
        "high-risk ports and assess whether this exposure is intentional and necessary. "
        "Database and administrative ports should not be exposed via public load "
        "balancers. If these ports require external access, restrict it via Security "
        "Group rules to specific authorized IP ranges only."
    ),
    "RECON-018": (
        "It is recommended to update Lambda Function URL CORS configurations to "
        "restrict allowed origins to specific trusted domains rather than the wildcard '*'. "
        "A restrictive CORS policy prevents browser-based CSRF attacks where an "
        "attacker-controlled website can make authenticated requests to the function "
        "on behalf of a logged-in user. "
        "Specify only the exact origin domains that legitimately need to call the "
        "function from a browser context."
    ),
    "RECON-019": (
        "It is recommended to review CloudFront distributions sharing the same origin "
        "and ensure that each distribution has equivalent WAF and access control "
        "policies. "
        "A shared origin means a less-protected distribution can bypass the stricter "
        "controls of another distribution. "
        "Consider using Origin Access Control to ensure that origin access is always "
        "routed through CloudFront rather than directly."
    ),
    "RECON-020": (
        "The absence of public entry points is a positive finding indicating a minimal "
        "external attack surface. It is recommended to validate this against the "
        "expected architecture to confirm that no legitimate public endpoints are "
        "inadvertently absent or misconfigured. "
        "Maintain this posture by implementing SCPs that require VPC endpoints for "
        "AWS service access and enforce private subnet placement for compute resources."
    ),
    # ── SECRETS MANAGER ───────────────────────────────────────────────────────
    "SM-001": (
        "It is recommended to update Secrets Manager resource policies to replace "
        "wildcard principal grants (Principal: '*') with specific IAM role ARNs "
        "for each service or user that legitimately needs to retrieve the secret. "
        "Add aws:SourceAccount or aws:PrincipalOrgID conditions for cross-account "
        "access to ensure only identities within the organization can retrieve secrets. "
        "Audit CloudTrail for GetSecretValue events to identify all legitimate consumers "
        "and scope the policy to exactly those principals."
    ),
    "SM-002": (
        "It is recommended to enable automatic rotation for all secrets in Secrets Manager. "
        "Configure a rotation Lambda function appropriate for the secret type (RDS "
        "credentials, API keys, etc.) and set a rotation interval of 90 days or fewer. "
        "AWS provides managed rotation functions for common database engines via "
        "Serverless Application Repository. "
        "Automatic rotation ensures that even if a secret is compromised, it becomes "
        "invalid after the next rotation without requiring manual intervention. "
        "Test the rotation function after configuration to confirm it completes "
        "successfully without disrupting dependent services."
    ),
    "SM-003": (
        "It is recommended to reduce the rotation interval for secrets with "
        "automatic rotation intervals exceeding 90 days. "
        "Update the rotation schedule to a maximum of 90 days to align with the "
        "industry-standard maximum validity window for shared credentials. "
        "Use: aws secretsmanager rotate-secret --secret-id <ARN> --rotation-rules "
        "AutomaticallyAfterDays=90 to update the schedule. "
        "Consider shorter intervals (30 days) for secrets with higher sensitivity "
        "or broader access."
    ),
    "SM-004": (
        "It is recommended to re-encrypt sensitive secrets using customer-managed "
        "KMS keys (CMK) rather than the default aws/secretsmanager managed key. "
        "A CMK provides independent control over who can decrypt secrets via the "
        "KMS key policy, enabling access revocation that is independent of the "
        "Secrets Manager resource policy. "
        "Create a dedicated CMK for secrets, restrict Decrypt permissions to "
        "authorized service roles, and update each secret's encryption configuration "
        "to reference the CMK ARN."
    ),
    "SM-005": (
        "It is recommended to immediately rotate all secrets that have not been "
        "rotated for more than 365 days or have never been rotated. "
        "Long-lived static credentials have an extended exposure window: they may "
        "have been accessed by unauthorized parties through historical breaches, "
        "insider threats, or logging leakage without any indication in current logs. "
        "Enable automatic rotation after the immediate manual rotation to prevent "
        "recurrence. "
        "Audit CloudTrail for GetSecretValue events over the past 12 months to "
        "identify any unexpected access to these long-lived secrets."
    ),
    "SM-006": (
        "It is recommended to apply consistent governance tags to all Secrets Manager "
        "secrets, including at minimum: Application (owning application), Environment "
        "(production, staging), Owner (team or individual responsible), and "
        "Classification (sensitivity level). "
        "Tags enable cost allocation, access reviews, incident response attribution, "
        "and automated governance policies. "
        "Use an AWS Config rule or SCP to enforce mandatory tag keys on all new "
        "secrets."
    ),
    "SM-007": (
        "It is recommended to add a meaningful description to all Secrets Manager "
        "secrets explaining their purpose, the service they authenticate, and "
        "the rotation Lambda function in use. "
        "Clear descriptions accelerate incident response by enabling the security "
        "team to quickly assess the impact of a secret compromise without needing "
        "to trace the secret to its consuming application."
    ),
    "SM-008": (
        "It is recommended to configure cross-region replication for secrets that "
        "are accessed by multi-region workloads or are critical for business continuity. "
        "Replicated secrets are automatically kept in sync during rotation and are "
        "available for retrieval in the replica region if the primary region becomes "
        "unavailable. "
        "Configure replication via: aws secretsmanager replicate-secret-to-regions "
        "--secret-id <ARN> --add-replica-regions Region=<region>"
    ),
    "SM-011": (
        "It is recommended to add an MFA authentication condition to Secrets Manager "
        "resource policies for the most sensitive secrets. "
        "Add the condition aws:MultiFactorAuthPresent: 'true' to the policy's Condition "
        "block to require that the requesting identity authenticated with MFA in the "
        "current session. "
        "This ensures that a stolen long-term IAM credential alone cannot retrieve "
        "the secret without also having access to the user's MFA device."
    ),
    "SM-012": (
        "It is recommended to implement EventBridge rules or CloudWatch alarms that "
        "alert on Secrets Manager rotation failure events. "
        "Create an EventBridge rule matching RotationFailed events from Secrets Manager "
        "and route it to an SNS topic with confirmed subscriptions. "
        "Rotation failures can leave secrets static indefinitely — often without "
        "any visible indication — making automated failure detection critical to "
        "maintaining the rotation guarantees the configuration promises."
    ),
    "SM-014": (
        "It is recommended to validate rotation Lambda function ARNs against an "
        "approved allowlist and implement change detection for rotation function "
        "configurations. "
        "If an unexpected Lambda ARN is found, immediately investigate for potential "
        "compromise and rotate the affected secrets. "
        "Restrict lambda:UpdateFunctionCode and lambda:UpdateFunctionConfiguration "
        "permissions for rotation functions to a dedicated deployment role under "
        "change management controls."
    ),
    "SM-015": (
        "It is recommended to restrict the KMS key that can be specified when calling "
        "UpdateSecret by adding a KMS key condition to the secret's resource policy. "
        "Add an explicit Deny statement that blocks UpdateSecret with any KMS key "
        "other than the approved CMK: use a condition with kms:RequestedKeyId. "
        "This prevents an attacker with UpdateSecret permissions from re-encrypting "
        "the secret with an attacker-controlled key, rendering it inaccessible to "
        "legitimate consumers."
    ),
    # ── CLOUDTRAIL EVENTS ─────────────────────────────────────────────────────
    "CTEF-001": (
        "It is recommended to immediately investigate any root account API activity "
        "detected in CloudTrail logs. Determine who performed the action, why, and "
        "whether it was authorized per documented break-glass procedures. "
        "If the activity was unauthorized, initiate incident response immediately: "
        "rotate root credentials, review all actions taken during the session, and "
        "assess whether any resources were created, modified, or compromised. "
        "To prevent recurrence, enforce MFA on the root account, store root credentials "
        "in a physical safe, and implement a CloudWatch alarm that triggers on any "
        "future root account activity."
    ),
    "CTEF-002": (
        "It is recommended to immediately investigate the detected IAM activity and "
        "determine whether it represents authorized changes or unauthorized access. "
        "Review CloudTrail for the source IP, user agent, and identity of the caller. "
        "If unauthorized, initiate incident response: disable affected credentials, "
        "revert unauthorized IAM changes, and assess whether any privilege escalation "
        "occurred. "
        "Enforce MFA for all IAM users and implement alerting for IAM changes going forward."
    ),
    "CTEF-003": (
        "It is recommended to treat detected audit trail tampering events as a potential "
        "security incident and initiate incident response immediately. "
        "Review the CloudTrail event details to identify who performed the StopLogging, "
        "DeleteTrail, or UpdateTrail action, from which IP address, and at what time. "
        "Re-enable CloudTrail immediately and assess whether any actions performed "
        "during the logging gap require forensic investigation using other log sources "
        "(VPC Flow Logs, S3 access logs, ALB access logs). "
        "Implement an SCP that prevents CloudTrail modification in production accounts "
        "and configure a real-time alarm that triggers on any future CloudTrail changes."
    ),
    "CTEF-004": (
        "It is recommended to investigate detected network perimeter changes and verify "
        "whether they were authorized by reviewing change management records. "
        "If unauthorized, revert the changes and initiate incident response. "
        "Implement automated detection for network configuration changes going forward."
    ),
    "CTEF-005": (
        "It is recommended to investigate detected S3 bucket policy changes and verify "
        "whether any bucket was inadvertently exposed publicly. "
        "Review the changed policies and revert any unauthorized modifications immediately. "
        "Implement S3 Block Public Access at the account level as a preventive control."
    ),
    "CTEF-006": (
        "It is recommended to investigate detected console login activity for "
        "authentication anomalies such as failed logins, logins from unexpected "
        "geographies, or logins outside business hours. "
        "Correlate login events with CloudTrail API activity to assess whether "
        "any post-login actions warrant investigation."
    ),
    "CTEF-007": (
        "It is recommended to investigate detected Security Group modifications and "
        "verify whether any unintended network access was opened. "
        "Review the specific rule changes and assess whether any sensitive resources "
        "were exposed. Revert unauthorized changes and implement monitoring for "
        "future Security Group modifications."
    ),
    "CTEF-008": (
        "It is recommended to investigate detected KMS key lifecycle events and verify "
        "whether any key deletions or disablements were authorized. "
        "If unauthorized, immediately cancel any scheduled key deletions using "
        "aws kms cancel-key-deletion and re-enable disabled keys. "
        "Assess whether any encrypted data became inaccessible and initiate "
        "recovery procedures if needed."
    ),
    "CTEF-009": (
        "It is recommended to investigate who accessed the IAM credential report and "
        "verify this was an authorized activity performed by a known identity for "
        "a legitimate purpose such as a scheduled access review. "
        "The credential report contains highly sensitive information about all IAM "
        "users, their access keys, and MFA status — ideal reconnaissance data for "
        "an attacker planning privilege escalation. "
        "If the access was unauthorized, assume the attacker has mapped all user "
        "accounts and dormant credentials and prioritize reviewing the active user "
        "landscape for suspicious access patterns."
    ),
    "CTEF-010": (
        "It is recommended to investigate detected privilege escalation indicators "
        "and determine whether unauthorized permissions were granted. "
        "Review all IAM changes made by the detected principal and revert any "
        "unauthorized policy modifications. "
        "Assess the scope of permissions potentially granted and initiate incident "
        "response if account-level access may have been obtained."
    ),
    "CTEF-011": (
        "It is recommended to treat the detected disablement of security monitoring "
        "services as a high-confidence indicator of malicious activity and initiate "
        "incident response immediately. "
        "Re-enable all disabled services (Security Hub, GuardDuty, CloudTrail alarms) "
        "and review all API activity performed by the responsible identity, particularly "
        "in the window after the monitoring services were disabled. "
        "Apply an SCP that prevents disabling security monitoring services in production "
        "accounts and configure a real-time alarm for any future attempts."
    ),
    "CTEF-012": (
        "It is recommended to review the detected secrets and parameter store access "
        "events and validate each access against known legitimate service patterns. "
        "Compare the source identity, IP address, and user agent of each GetSecretValue "
        "or GetParameter call against expected access patterns documented for the "
        "consuming service. "
        "Identify and investigate any accesses from unexpected identities, IP addresses, "
        "or at unusual times, as these may represent unauthorized credential harvesting. "
        "Rotate any secrets that were accessed by unknown or unexpected principals."
    ),
    "CTEF-013": (
        "It is recommended to treat detected IAM trust policy or inline policy "
        "modifications as potential privilege escalation indicators and investigate "
        "immediately. "
        "Review the specific changes made: if trust policies were broadened or "
        "new permissions were added, assess whether this enabled unauthorized role "
        "assumption or privilege escalation. "
        "Revert unauthorized changes, disable the responsible identity's credentials "
        "if the changes appear malicious, and audit all AssumeRole events by the "
        "modified roles in the hours following the policy change."
    ),
    # ── VULNERABILITIES ───────────────────────────────────────────────────────
    "VULN-001": (
        "It is recommended to enable AWS Inspector v2 for all required resource types "
        "(EC2, Lambda, ECR containers) in all regions where workloads operate. "
        "Inspector v2 provides continuous vulnerability scanning with integration "
        "into Security Hub for centralized finding management. "
        "After enablement, configure suppression rules for known false positives "
        "and establish remediation SLAs: CRITICAL 7 days, HIGH 30 days, MEDIUM 90 days."
    ),
    "VULN-002": (
        "It is recommended to immediately prioritize remediation of all CRITICAL "
        "severity CVEs (CVSS ≥ 9.0) identified by AWS Inspector. "
        "For EC2 instances, apply OS patches via AWS Systems Manager Patch Manager "
        "using the Critical patch baseline. For Lambda functions, update dependencies "
        "to patched versions and redeploy. For containers, rebuild images from updated "
        "base images and redeploy. "
        "If immediate patching is not possible, implement compensating controls: "
        "restrict network access to the affected resource, increase monitoring "
        "sensitivity, and document the accepted risk with executive sign-off."
    ),
    "VULN-003": (
        "It is recommended to prioritize patching vulnerabilities on internet-facing "
        "resources above all others, as these combine network reachability with "
        "exploitability to create immediately actionable attack paths. "
        "If direct patching is not immediately possible, temporarily restrict network "
        "access via Security Group changes to limit exposure while patching is "
        "being scheduled. "
        "Use AWS WAF virtual patching rules to block known exploit patterns "
        "for specific CVEs while permanent patches are prepared."
    ),
    "VULN-004": (
        "It is recommended to prioritize the affected CVEs where Inspector reports "
        "exploitAvailable=YES. Apply the vendor patch where fixAvailable=YES, or document "
        "a time-bound exception with compensating controls when no fix exists. "
        "Validate whether the affected workloads are reachable from untrusted networks "
        "before escalating the issue beyond Inspector's reported severity."
    ),
    "VULN-005": (
        "It is recommended to treat vulnerabilities on business-critical resources "
        "(domain controllers, databases, API servers) with the highest urgency "
        "regardless of their CVSS score. "
        "Apply patches to these resources during the next available maintenance "
        "window and implement network-layer compensating controls in the interim. "
        "Establish dedicated patch maintenance windows for critical infrastructure "
        "with appropriate change management and rollback procedures."
    ),
    "VULN-006": (
        "It is recommended to implement a systematic vulnerability remediation process "
        "with defined SLAs by severity. Assign vulnerability ownership to engineering "
        "teams, track remediation progress in a ticketing system, and escalate "
        "overdue findings to management. "
        "Use AWS Inspector's integration with Security Hub to route findings into "
        "existing operations workflows."
    ),
    "VULN-007": (
        "It is recommended to address the backlog of HIGH severity CVEs by establishing "
        "a remediation sprint. Assign findings to owning teams, set a 30-day "
        "remediation deadline, and implement automated patching via Systems Manager "
        "Patch Manager where feasible. "
        "Consider using AWS Lambda or Systems Manager Automation to automatically "
        "remediate specific finding types such as outdated packages."
    ),
    "VULN-008": (
        "It is recommended to assign each ACTIVE HIGH Inspector finding to an owner with "
        "a remediation due date, patch decision, exception status, and compensating control "
        "where patching is not immediately possible. Track these records in the vulnerability "
        "management workflow and reconcile them against Inspector until the findings close."
    ),
    "VULN-009": (
        "It is recommended to prioritize resources with accumulated ACTIVE CVEs as "
        "remediation bundles rather than handling each CVE independently. "
        "Assign an owner per affected resource, patch or rebuild the underlying image, "
        "and verify closure in Inspector after deployment. "
        "If immediate patching is not possible, isolate the resource, reduce inbound "
        "reachability, and record a time-bound exception with compensating controls."
    ),
    "VULN-010": (
        "It is recommended to route the affected EC2 service instances to the owning "
        "application teams, prioritize fixes by exploitAvailable and fixAvailable status, "
        "and patch through AWS Systems Manager Patch Manager or replace instances with "
        "patched AMIs. Where patching is delayed, document service-specific compensating "
        "controls such as network isolation, monitoring, or temporary feature restrictions."
    ),
    "VULN-011": (
        "It is recommended to enable ECR image scanning through ECR Enhanced Scanning or "
        "repository-level scan-on-push controls, then verify scan coverage with ECR registry "
        "and repository configuration evidence. Do not use Lambda dependency remediation for "
        "this finding; Lambda package vulnerabilities require a separate Lambda-specific finding."
    ),
    "VULN-022": (
        "It is recommended to rebuild affected container images from updated base "
        "images that include patches for all identified CVEs. "
        "Update the Dockerfile to reference the latest patched base image version, "
        "rebuild the image, scan it with ECR Enhanced Scanning to verify CVE "
        "resolution, and deploy the updated image. "
        "Implement a CI/CD pipeline gate that prevents deployment of images with "
        "CRITICAL or HIGH unresolved CVEs."
    ),
    "VULN-023": (
        "It is recommended to address the backlog of MEDIUM severity findings that "
        "have exceeded their remediation SLA. While individually lower risk, "
        "chained medium vulnerabilities can produce high-impact exploit paths. "
        "Schedule a batch patching effort, prioritizing medium findings on "
        "internet-facing or high-criticality resources first."
    ),
    "VULN-024": (
        "It is recommended to enable AWS Inspector v2 scanning for all uncovered "
        "resource types. Inspector v2 supports EC2 instances, Lambda functions, "
        "and ECR container images. "
        "Enable the relevant scanning types in the Inspector console and verify "
        "that findings begin appearing within 24 hours of enablement."
    ),
    "VULN-025": (
        "It is recommended to upgrade affected RDS database instances to the latest "
        "minor or patch version within the current major version to resolve "
        "known engine CVEs. "
        "RDS supports minor version auto-upgrade: enable it in the instance "
        "settings to automatically apply engine patches during the next maintenance "
        "window. "
        "Test the upgrade in a non-production environment first to validate "
        "compatibility with the application."
    ),
    "VULN-026": (
        "It is recommended to establish a remediation SLA enforcement process with "
        "automated escalation for overdue findings. "
        "Use Security Hub custom actions to route overdue Inspector findings to "
        "management escalation workflows and track compliance with SLAs in a "
        "dashboard visible to engineering leadership."
    ),
    "VULN-028": (
        "It is recommended to prioritize and remediate all vulnerabilities that have "
        "been open for more than 90 days. These represent the highest-risk findings "
        "due to their extended exposure window and the availability of exploit tools "
        "that evolve over time. "
        "Establish a formal remediation SLA program with defined escalation paths "
        "for findings that approach and exceed the SLA threshold."
    ),
    "VULN-029": (
        "It is recommended to immediately address vulnerabilities on resources that "
        "have AWS Inspector network reachability findings indicating internet "
        "accessibility. "
        "Network reachability combined with vulnerability findings creates an immediately "
        "exploitable attack path. Apply patches or restrict network access within 24 hours. "
        "Use AWS WAF to apply virtual patches for known CVE exploit patterns as "
        "an interim control while permanent patches are prepared."
    ),
    "VULN-GD-001": (
        "It is recommended to immediately review and investigate all AWS GuardDuty "
        "findings. GuardDuty uses machine learning and threat intelligence to identify "
        "behavioral anomalies that indicate potential compromise. "
        "Triage each finding by reviewing the associated CloudTrail events, VPC Flow "
        "Logs, and DNS logs to determine whether the activity is authorized or malicious. "
        "For confirmed malicious findings, initiate the incident response process: "
        "isolate affected resources, rotate compromised credentials, and collect "
        "forensic evidence."
    ),
    "VULN-GD-002": (
        "It is recommended to treat all HIGH severity GuardDuty findings as potential "
        "active incidents requiring immediate investigation. "
        "HIGH severity GuardDuty findings indicate high-confidence malicious activity "
        "such as credential exfiltration, cryptocurrency mining, or data exfiltration. "
        "Initiate incident response procedures immediately: isolate the affected "
        "resource, suspend the associated IAM identity, and begin forensic investigation "
        "before the attacker has time to establish additional persistence mechanisms."
    ),
    # ── WAF ───────────────────────────────────────────────────────────────────
    "WAF-001": (
        "It is recommended to associate an AWS WAF Web ACL with all internet-facing "
        "Application Load Balancers. "
        "Start by creating a WAFv2 Web ACL with AWS Managed Rules Common Rule Set "
        "(AWSManagedRulesCommonRuleSet) in Count mode to evaluate its impact on "
        "legitimate traffic before switching to Block mode. "
        "Add the IP reputation managed rule set to block known malicious IP addresses "
        "and configure rate-based rules to protect authentication endpoints from "
        "credential stuffing. "
        "Enable WAF logging to a Kinesis Data Firehose or S3 bucket for security "
        "analysis and compliance."
    ),
    "WAF-002": (
        "It is recommended to enable WAF logging for all Web ACLs to capture complete "
        "request and rule evaluation data. "
        "Configure a logging destination (Kinesis Data Firehose, CloudWatch Logs, "
        "or S3) and set appropriate retention periods for your compliance requirements. "
        "WAF logs are essential for investigating security incidents, tuning rule "
        "false positive rates, and demonstrating WAF effectiveness to auditors."
    ),
    "WAF-003": (
        "It is recommended to enable AWS Managed Rules on all Web ACLs to benefit "
        "from AWS's continuously updated threat intelligence. "
        "At minimum, add AWSManagedRulesCommonRuleSet (OWASP Top 10 protection) and "
        "AWSManagedRulesKnownBadInputsRuleSet. "
        "Enable managed rules in Count mode initially to monitor their impact on "
        "legitimate traffic before switching to Block mode, preventing unintended "
        "disruption to production traffic."
    ),
    "WAF-004": (
        "It is recommended to configure WAF log redaction for request components that "
        "can contain secrets or personal data. "
        "At minimum, redact Authorization, Cookie, X-Api-Key, and other application-"
        "specific authentication headers or sensitive parameters before logs are stored. "
        "Review the current RedactedFields configuration for each Web ACL and align it "
        "with the application's actual authentication and session-management patterns."
    ),
    "WAF-005": (
        "It is recommended to add rate-based rules to all Web ACLs to protect against "
        "brute-force attacks and HTTP flooding. "
        "Configure rate limits based on source IP with a threshold appropriate for "
        "your application's expected traffic patterns — typically 100-1000 requests "
        "per 5-minute window depending on the endpoint sensitivity. "
        "Apply stricter rate limits specifically to authentication and password reset "
        "endpoints, which are the most common targets for credential stuffing attacks."
    ),
    "WAF-006": (
        "It is recommended to add the baseline AWS Managed Rule groups required by "
        "the organization's WAF standard, such as AWSManagedRulesCommonRuleSet, "
        "AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesSQLiRuleSet, and "
        "AWSManagedRulesAmazonIpReputationList. "
        "Deploy new managed rules in Count mode first, review sampled requests and "
        "false positives, then move tuned rules to enforcement. Keep any third-party "
        "managed rule group as an additional layer rather than the only baseline."
    ),
    "WAF-007": (
        "It is recommended to enable XSS protection in all Web ACLs by adding "
        "AWSManagedRulesCommonRuleSet (which includes XSS rules) or custom "
        "XSS match conditions. "
        "XSS filtering should be applied to all request components where user "
        "input is reflected: query strings, request bodies, and URI paths."
    ),
    "WAF-008": (
        "It is recommended to transition WAF rules from COUNT mode to BLOCK mode "
        "after validating that they do not produce false positives against legitimate "
        "traffic. "
        "Review COUNT mode rule sampled requests in the WAF console or logs to "
        "identify any legitimate traffic being counted. If false positives exist, "
        "add exclusion conditions before enabling BLOCK mode. "
        "Rules in COUNT mode provide visibility but no protection — they detect "
        "attacks and log them while allowing them to reach the application backend."
    ),
    "WAF-009": (
        "It is recommended to associate all provisioned Web ACLs with at least one "
        "CloudFront distribution, ALB, or API Gateway stage. "
        "Web ACLs that are not associated with any resource consume WAF capacity "
        "costs without providing any protection. "
        "Review each unassociated Web ACL and either associate it with the appropriate "
        "resource or delete it if it is no longer needed."
    ),
    "WAF-010": (
        "It is recommended to migrate WAF Classic Web ACLs and associations to WAFv2. "
        "Inventory each Classic Web ACL, recreate equivalent protections in WAFv2, "
        "validate behavior in Count mode, then move ALB or CloudFront associations to "
        "the WAFv2 Web ACL. Remove Classic ACLs only after traffic behavior, logging, "
        "and rule metrics have been validated."
    ),
    "WAF-011": (
        "It is recommended to review and tighten Web ACL default actions. "
        "If the default action is Allow, ensure all rule sets provide adequate coverage "
        "and consider switching to a default Deny posture with explicit Allow rules "
        "for known-good traffic patterns. "
        "A default Deny posture is more secure but requires careful rule design "
        "to avoid blocking legitimate traffic."
    ),
    "WAF-013": (
        "It is recommended to add scope-down statements to WAF rules to limit "
        "evaluation to the specific request components and paths where each rule "
        "is relevant. "
        "Scope-down statements reduce WAF Capacity Unit (WCU) consumption and "
        "improve rule evaluation efficiency, allowing more rules within capacity limits. "
        "For example, apply SQL injection rules only to requests targeting paths "
        "that interact with database queries."
    ),
    "WAF-014": (
        "It is recommended to review Web ACL configurations for currency with recently "
        "discovered attack techniques and newly deployed application endpoints. "
        "Update WAF rule sets at least quarterly and whenever significant application "
        "changes are deployed. "
        "Enable automatic rule group version updates for AWS Managed Rules to receive "
        "AWS's latest threat intelligence without manual intervention."
    ),
    "WAF-015": (
        "It is recommended to add AWS WAF Bot Control to Web ACLs protecting "
        "applications that are targets for automated bot traffic, credential stuffing, "
        "or scraping. "
        "Bot Control categorizes bots as verified bots (search engines, monitoring "
        "tools) and unverified bots, enabling targeted blocking of malicious "
        "automated traffic while allowing legitimate bot activity."
    ),
    "WAF-016": (
        "It is recommended to optimize Web ACL rule group WCU consumption to stay "
        "within the 5000 WCU limit per Web ACL. "
        "Review each rule group's WCU cost and assess whether all rules are necessary "
        "and appropriately scoped. "
        "Remove redundant rules, add scope-down statements to expensive rules, and "
        "consider splitting protection across multiple Web ACLs if capacity limits "
        "are constraining necessary protections."
    ),
    # ── SISTEMAS EXPLOTABLES EN RED (SER) ─────────────────────────────────────
    "SER-EC2-001": (
        "It is recommended to immediately restrict Security Group rules that expose "
        "SSH (port 22) or RDP (port 3389) to the internet (0.0.0.0/0) on EC2 instances. "
        "Replace these rules with source-specific rules limiting access to corporate "
        "VPN or bastion host IP ranges. "
        "For the most secure approach, remove all SSH/RDP inbound rules and use "
        "AWS Systems Manager Session Manager for interactive access, which requires "
        "no open inbound ports, provides session logging, and integrates with "
        "IAM for access control. "
        "Treat instances currently exposed on these ports as potentially compromised "
        "until their access logs have been reviewed for unauthorized activity."
    ),
    "SER-EC2-002": (
        "It is recommended to treat the finding as a combined exposure and patching "
        "remediation. First, verify whether the internet-facing listener is required; "
        "if it is not, remove the public inbound rule, and if it is required, restrict "
        "the source CIDR or place the service behind the approved edge controls for the "
        "application. "
        "Next, remediate the active Amazon Inspector findings on the affected instances, "
        "prioritizing network-vector critical CVEs and the vulnerable package versions "
        "identified in the evidence. "
        "Finally, validate IMDSv2 enforcement and least-privilege permissions for the "
        "attached instance profile so that a service compromise cannot easily become an "
        "AWS credential compromise."
    ),
    "SER-COR-003": (
        "It is recommended to address the correlated internet exposure and vulnerability "
        "findings as a combined remediation effort. "
        "Restrict network access to the affected resource immediately as an interim "
        "control, then apply vulnerability patches as the permanent fix. "
        "Network-reachable resources with known CVEs represent the highest-priority "
        "remediation targets as they combine exploitability with accessibility."
    ),
    "SER-CVE-001": (
        "It is recommended to treat internet-facing resources with actively exploited "
        "CVEs as critical incidents requiring immediate action. "
        "Restrict network access within the hour of detection by updating Security "
        "Group rules to remove the internet-facing exposure. "
        "Apply available patches within 24 hours and verify patch effectiveness "
        "using AWS Inspector before restoring internet access. "
        "If patches are not immediately available, maintain network restrictions "
        "and implement WAF virtual patching rules for the specific CVE exploit patterns."
    ),
    "SER-ECS-001": (
        "It is recommended to review the network exposure of ECS services and restrict "
        "public accessibility to only those services that require it for their function. "
        "For services requiring internet access, route traffic through an Application "
        "Load Balancer with WAF protection rather than assigning public IPs directly "
        "to task network interfaces. "
        "Implement authentication on all API endpoints and restrict Security Groups "
        "to the minimum required ports."
    ),
    "SER-LMB-001": (
        "It is recommended to add authentication to Lambda Function URLs by changing "
        "AuthType from NONE to AWS_IAM, requiring all callers to sign requests "
        "with AWS Signature Version 4. "
        "If the function must accept unauthenticated public requests, implement "
        "rate limiting via AWS WAF, add input validation at the function entry "
        "point, and scope the function's IAM execution role to the minimum "
        "required permissions to limit blast radius."
    ),
    "SER-LMB-002": (
        "It is recommended to add authorization requirements to API Gateway routes "
        "that invoke Lambda functions without authentication. "
        "Implement Cognito User Pool authorization for consumer-facing routes, "
        "IAM authorization for service-to-service routes, or Lambda authorizers "
        "for custom authentication logic. "
        "At minimum, add API key requirements and rate limiting as a baseline "
        "control while more robust authentication is being implemented."
    ),
    "SER-RDS-001": (
        "It is recommended to immediately set PubliclyAccessible to false for all "
        "RDS instances and update Security Group rules to remove 0.0.0.0/0 inbound "
        "access on database ports. "
        "Move databases to private subnets with routes to a NAT Gateway only (no "
        "direct internet gateway route), and restrict Security Group inbound rules "
        "to specific application server security group IDs. "
        "If external database access is required for administrative purposes, use "
        "AWS Systems Manager Session Manager port forwarding rather than opening "
        "database ports to the internet."
    ),
    "NET-EGR-001": (
        "It is recommended to restrict egress Security Group rules from allowing all traffic "
        "(protocol -1 to 0.0.0.0/0) and replace them with specific outbound rules that "
        "permit only the protocols and destinations required for the resource's function. "
        "Unrestricted egress enables a compromised instance to initiate communication with "
        "any external host, facilitating data exfiltration, command-and-control beaconing, "
        "and lateral movement without restriction. "
        "Define explicit egress rules for each required destination: for example, HTTPS (443) "
        "to AWS service endpoints, specific database ports to the data tier, and DNS (53) to "
        "the VPC resolver. Remove the default allow-all outbound rule after validating that "
        "all legitimate traffic flows are explicitly permitted. "
        "Use VPC endpoints for AWS services to eliminate the need for internet-bound egress "
        "entirely on instances that only consume AWS services."
    ),
}

__all__ = [
    "PRE_CHECK_IMPACTS",
    "PRE_CHECK_ANALOGIES",
    "PRE_CHECK_DESCRIPTIONS",
    "PRE_CHECK_REMEDIATIONS",
]
