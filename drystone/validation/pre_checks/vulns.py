# ruff: noqa
"""Vulns deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


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

    critical_active: list = []
    resource_details: list = []
    now = datetime.now(tz=timezone.utc)

    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        if str(f.get("severity", "")).upper() != "CRITICAL":
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        resources = f.get("resources") or [{}]
        resource_id = (
            resources[0].get("id", "unknown") if isinstance(resources[0], dict) else "unknown"
        )
        critical_active.append(resource_id)

        vuln_details = f.get("packageVulnerabilityDetails") or f.get("vulnerabilityDetails") or {}
        pkgs = vuln_details.get("vulnerablePackages") or []
        pkg = pkgs[0] if pkgs else {}
        first_observed = f.get("firstObservedAt") or f.get("createdAt")
        days_open: Optional[int] = None
        if first_observed:
            dt = _parse_date(first_observed)
            if dt:
                days_open = (now - dt).days

        resource_details.append(
            {
                "resource_id": resource_id,
                "cve_id": vuln_details.get("vulnerabilityId") or f.get("title", ""),
                "package": pkg.get("name") if isinstance(pkg, dict) else "",
                "version": pkg.get("version") if isinstance(pkg, dict) else "",
                "fix_available": (
                    bool(pkg.get("fixedInVersion")) if isinstance(pkg, dict) else False
                ),
                "days_open": days_open,
                "evidence_ref": f"inspector-findings.json#/{idx}",
            }
        )

    if not critical_active:
        return PreCheckResult("VULN-002", "PASS", "no CRITICAL active Inspector findings", [])
    result = PreCheckResult(
        "VULN-002",
        "FAIL",
        f"{len(critical_active)} CRITICAL active Inspector finding(s)",
        critical_active[:10],
    )
    result.metadata["resource_details"] = resource_details[:15]
    return result


@_register("vulns")
def check_vuln_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """Multiple CVEs on same resource — count ACTIVE Inspector findings per resource."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list) or not findings:
        return PreCheckResult("VULN-009", "SKIP", "no inspector-findings evidence", [])

    from collections import Counter

    resource_counts: Counter = Counter()
    resource_severities: Dict[str, Counter] = {}
    resource_refs: Dict[str, list[str]] = {}
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        sev = str(f.get("severity", "UNKNOWN")).upper()
        for res in f.get("resources", []):
            rid = res.get("id") if isinstance(res, dict) else None
            if rid:
                resource_counts[rid] += 1
                if rid not in resource_severities:
                    resource_severities[rid] = Counter()
                resource_severities[rid][sev] += 1
                resource_refs.setdefault(rid, []).append(f"inspector-findings.json#/{idx}")

    multi_vuln = {rid: cnt for rid, cnt in resource_counts.items() if cnt >= 3}
    if not multi_vuln:
        return PreCheckResult("VULN-009", "PASS", "no resource has 3+ active CVEs", [])

    top = sorted(multi_vuln.items(), key=lambda x: x[1], reverse=True)
    resources = [f"{rid} ({cnt} CVEs)" for rid, cnt in top[:5]]
    resource_details = [
        {
            "resource_id": rid,
            "cve_count": cnt,
            "severities": dict(resource_severities.get(rid, {})),
            "evidence_refs": resource_refs.get(rid, [])[:10],
        }
        for rid, cnt in top[:10]
    ]
    result = PreCheckResult(
        "VULN-009",
        "FAIL",
        f"{len(multi_vuln)} resource(s) with 3+ active CVEs",
        resources,
    )
    result.metadata["resource_details"] = resource_details
    return result


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

    exposed: list = []
    resource_details: list = []
    for it in items:
        if not isinstance(it, dict):
            continue
        flags = it.get("ContainsSecrets")
        if not isinstance(flags, dict):
            continue
        secret_types = {k: v for k, v in flags.items() if bool(v)}
        if not secret_types:
            continue
        iid = it.get("InstanceId", "unknown")
        arn = f"arn:aws:ec2:*:*:instance/{iid}"
        exposed.append(arn)
        resource_details.append(
            {
                "instance_id": iid,
                "instance_name": it.get("InstanceName") or it.get("Name") or "",
                "secret_types": list(secret_types.keys()),
                "secret_count": len(secret_types),
            }
        )

    if not exposed:
        return PreCheckResult("VULN-023", "PASS", "no user-data secret patterns detected", [])
    result = PreCheckResult(
        "VULN-023", "FAIL", f"{len(exposed)} instances with secret-like user-data", exposed[:10]
    )
    result.metadata["resource_details"] = resource_details[:15]
    return result


@_register("vulns")
def check_vuln_024(evidence: Dict[str, Any]) -> PreCheckResult:
    """Detect Lambda functions with potentially sensitive env var keys."""
    env_doc = evidence.get("lambda-environment-variables") or {}
    items = env_doc.get("items") if isinstance(env_doc, dict) else None
    if not isinstance(items, list) or not items:
        return PreCheckResult("VULN-024", "SKIP", "no lambda-environment-variables evidence", [])

    exposed: list = []
    resource_details: list = []
    for it in items:
        if not isinstance(it, dict):
            continue
        keys = it.get("PotentialSecretKeys")
        if not isinstance(keys, list) or len(keys) == 0:
            continue
        fn_arn = it.get("FunctionArn") or f"lambda/{it.get('FunctionName', 'unknown')}"
        exposed.append(str(fn_arn))
        resource_details.append(
            {
                "function_arn": str(fn_arn),
                "function_name": it.get("FunctionName") or "",
                "sensitive_keys": keys[:10],
                "key_count": len(keys),
            }
        )

    if not exposed:
        return PreCheckResult("VULN-024", "PASS", "no sensitive Lambda env keys detected", [])
    result = PreCheckResult(
        "VULN-024", "FAIL", f"{len(exposed)} Lambda functions with sensitive env keys", exposed[:10]
    )
    result.metadata["resource_details"] = resource_details[:15]
    return result


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

    exploitable: List[str] = []
    details: List[Dict[str, Any]] = []
    for idx, f in enumerate(findings):
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
            details.append(
                {
                    "finding_arn": f.get("findingArn"),
                    "evidence_ref": (
                        f"inspector-findings.json#items.{idx}"
                        if f.get("findingArn") is None
                        else f"inspector-findings.json#findingArn.{f.get('findingArn')}"
                    ),
                    "title": title,
                    "resource_id": rid,
                    "resource_type": resources[0].get("type") if resources else None,
                    "status": f.get("status"),
                    "severity": f.get("severity"),
                    "inspector_score": f.get("inspectorScore"),
                    "exploit_available": f.get("exploitAvailable"),
                    "fix_available": f.get("fixAvailable"),
                    "remediation": (
                        ((f.get("remediation") or {}).get("recommendation") or {}).get("text")
                        if isinstance(f.get("remediation"), dict)
                        else None
                    ),
                }
            )

    if not exploitable:
        return PreCheckResult("VULN-004", "PASS", "no actively exploitable CVEs detected", [])
    max_score = max(
        [
            float(d.get("inspector_score") or 0.0)
            for d in details
            if isinstance(d.get("inspector_score"), (int, float))
        ]
        or [7.0]
    )
    return PreCheckResult(
        "VULN-004",
        "FAIL",
        f"{len(exploitable)} CVE(s) with known active exploit and ACTIVE status",
        exploitable[:10],
        metadata={"resource_details": details[:25]},
        risk_score_override=max_score,
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
    details: List[Dict[str, Any]] = []
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        if (
            str(f.get("severity", "")).upper() == "HIGH"
            and str(f.get("status", "")).upper() == "ACTIVE"
        ):
            resources = f.get("resources", [])
            rid = resources[0].get("id", "unknown") if resources else "unknown"
            high_active.append(rid)
            details.append(
                {
                    "finding_arn": f.get("findingArn"),
                    "evidence_ref": (
                        f"inspector-findings.json#items.{idx}"
                        if f.get("findingArn") is None
                        else f"inspector-findings.json#findingArn.{f.get('findingArn')}"
                    ),
                    "title": f.get("title"),
                    "resource_id": rid,
                    "resource_type": resources[0].get("type") if resources else None,
                    "status": f.get("status"),
                    "severity": f.get("severity"),
                    "inspector_score": f.get("inspectorScore"),
                    "exploit_available": f.get("exploitAvailable"),
                    "fix_available": f.get("fixAvailable"),
                    "remediation": (
                        ((f.get("remediation") or {}).get("recommendation") or {}).get("text")
                        if isinstance(f.get("remediation"), dict)
                        else None
                    ),
                }
            )

    if not high_active:
        return PreCheckResult("VULN-008", "PASS", "no ACTIVE HIGH Inspector findings", [])

    unique_resources = list(dict.fromkeys(high_active))
    return PreCheckResult(
        "VULN-008",
        "FAIL",
        f"{len(high_active)} ACTIVE HIGH Inspector finding(s) across {len(unique_resources)} resource(s) requiring remediation tracking",
        unique_resources[:10],
        metadata={"resource_details": details[:50]},
    )


@_register("vulns")
def check_vuln_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-003: Active vulnerabilities on publicly accessible EC2 resources."""
    findings = evidence.get("inspector-findings")
    if not isinstance(findings, list):
        return PreCheckResult("VULN-003", "SKIP", "no inspector-findings evidence", [])

    public_instance_ids: set = set()
    for key in ("public-vulnerability-paths", "internet-reachable-vulnerabilities"):
        doc = evidence.get(key)
        items = doc.get("items") if isinstance(doc, dict) else doc if isinstance(doc, list) else []
        for item in items or []:
            if not isinstance(item, dict):
                continue
            rid = item.get("InstanceId") or item.get("instance_id") or item.get("resource_id")
            if isinstance(rid, str) and rid:
                public_instance_ids.add(rid)

    for key in ("ec2-instances", "instances"):
        doc = evidence.get(key)
        items = doc.get("items") if isinstance(doc, dict) else doc if isinstance(doc, list) else []
        for item in items or []:
            if not isinstance(item, dict):
                continue
            rid = str(item.get("InstanceId") or "")
            if not rid:
                continue
            public_ip = item.get("PublicIpAddress") or item.get("PublicIp")
            publicly_reachable = item.get("PubliclyReachable") or item.get("InternetReachable")
            if public_ip or publicly_reachable is True:
                public_instance_ids.add(rid)

    if not public_instance_ids:
        return PreCheckResult(
            "VULN-003",
            "SKIP",
            "no network reachability evidence proving public EC2 exposure",
            [],
        )

    # Look for ACTIVE findings targeting EC2 instances with separate public exposure proof.
    active_public_ec2: List[str] = []
    details: List[Dict[str, Any]] = []
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).upper() != "ACTIVE":
            continue
        for res in f.get("resources") or []:
            if isinstance(res, dict) and res.get("type") == "AWS_EC2_INSTANCE":
                rid = str(res.get("id") or "unknown")
                if rid not in public_instance_ids:
                    continue
                if rid not in active_public_ec2:
                    active_public_ec2.append(rid)
                details.append(
                    {
                        "finding_arn": f.get("findingArn"),
                        "evidence_ref": (
                            f"inspector-findings.json#items.{idx}"
                            if f.get("findingArn") is None
                            else f"inspector-findings.json#findingArn.{f.get('findingArn')}"
                        ),
                        "title": f.get("title"),
                        "resource_id": rid,
                        "status": f.get("status"),
                        "severity": f.get("severity"),
                        "exploit_available": f.get("exploitAvailable"),
                        "fix_available": f.get("fixAvailable"),
                        "public_exposure_evidence": "network reachability evidence present",
                    }
                )

    if not active_public_ec2:
        return PreCheckResult(
            "VULN-003",
            "PASS",
            "no ACTIVE Inspector findings on publicly reachable EC2 instances",
            [],
        )
    return PreCheckResult(
        "VULN-003",
        "FAIL",
        f"{len(active_public_ec2)} publicly reachable EC2 instance(s) with ACTIVE Inspector findings",
        active_public_ec2[:5],
        metadata={"resource_details": details[:25]},
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

    instance_names: Dict[str, str] = {}
    patch_doc = evidence.get("ec2-patch-status")
    patch_items = patch_doc if isinstance(patch_doc, list) else []
    for item in patch_items:
        if not isinstance(item, dict):
            continue
        iid = str(item.get("InstanceId") or "")
        if not iid:
            continue
        name = ""
        for tag in item.get("Tags") or []:
            if isinstance(tag, dict) and tag.get("Key") == "Name":
                name = str(tag.get("Value") or "")
                break
        instance_names[iid] = name

    affected: List[str] = []
    details: List[Dict[str, Any]] = []
    for idx, f in enumerate(findings):
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
                details.append(
                    {
                        "finding_arn": f.get("findingArn"),
                        "evidence_ref": (
                            f"inspector-findings.json#items.{idx}"
                            if f.get("findingArn") is None
                            else f"inspector-findings.json#findingArn.{f.get('findingArn')}"
                        ),
                        "title": f.get("title"),
                        "resource_id": rid,
                        "instance_name": instance_names.get(rid),
                        "status": f.get("status"),
                        "severity": f.get("severity"),
                        "inspector_score": f.get("inspectorScore"),
                        "exploit_available": f.get("exploitAvailable"),
                        "fix_available": f.get("fixAvailable"),
                    }
                )

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
        metadata={"resource_details": details[:50]},
    )


@_register("vulns")
def check_vuln_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """VULN-011: ECR scanning explicitly disabled by configuration evidence."""
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

    disabled: List[str] = []
    for key in ("ecr-scanning-config", "scanning-config", "registry"):
        doc = evidence.get(key)
        if not isinstance(doc, dict):
            continue
        scan_type = str(doc.get("scanType") or doc.get("ScanType") or "").upper()
        rules = doc.get("rules") or doc.get("Rules") or []
        if scan_type in {"BASIC", "NONE", "DISABLED"} or rules == []:
            disabled.append(key)

    repos = evidence.get("repositories")
    repo_items = (
        repos.get("items") if isinstance(repos, dict) else repos if isinstance(repos, list) else []
    )
    for repo in repo_items or []:
        if not isinstance(repo, dict):
            continue
        name = str(repo.get("repositoryName") or repo.get("RepositoryName") or "")
        scan_cfg = (
            repo.get("imageScanningConfiguration") or repo.get("ImageScanningConfiguration") or {}
        )
        if isinstance(scan_cfg, dict) and scan_cfg.get("scanOnPush") is False:
            disabled.append(name or "repository-with-scanOnPush-false")

    if disabled:
        return PreCheckResult(
            "VULN-011",
            "FAIL",
            f"{len(disabled)} ECR scanning configuration item(s) explicitly disabled",
            disabled[:10],
            metadata={
                "resource_details": [
                    {"resource": r, "scan_status": "disabled"} for r in disabled[:25]
                ]
            },
        )

    return PreCheckResult(
        "VULN-011",
        "SKIP",
        "no ECR image findings and no scan configuration evidence; cannot infer disabled scanning",
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

__all__ = [name for name in globals() if name.startswith("check_")]
