"""Orchestrates active verification against a completed audit session.

Scope (deliberate, see roadmap doc): only two verifiers exist today --
AssumeRole chain verification (targets the iam_assume_role_privilege_escalation
correlation pattern) and S3 public-access verification (targets EXP-001).
Adding a verifier means adding a target lookup here plus a function in
active_verifier.py -- this module is intentionally small and explicit rather
than a plugin registry, since there are only two entries; revisit if/when
more verifiers land (see the TODO list in the roadmap doc).
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

import boto3

from drystone.verification.active_verifier import (
    VerificationResult,
    verify_assume_role,
    verify_s3_public_access,
)
from drystone.verification.log import write_verification_log

ASSUME_ROLE_PATTERN_ID = "iam_assume_role_privilege_escalation"
S3_PUBLIC_CHECK_IDS = {"EXP-001"}

_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\d+:role/")
_S3_ARN_PREFIX = "arn:aws:s3:::"

WARNING_BANNER = (
    "\n"
    "\U0001f50d Active verification enabled: Drystone will attempt real, "
    "read-only AWS API calls\n"
    "   (sts:AssumeRole, unauthenticated S3 HEAD/List) to confirm specific "
    "findings are exploitable,\n"
    "   not just inferred. This activity WILL appear in the target "
    "account's CloudTrail logs.\n"
    "   Use --no-active-verification to skip this phase.\n"
)


def _role_arns_from_correlated(correlated_path: Path) -> List[Tuple[str, str]]:
    """Return [(correlation_id, role_arn), ...] for AssumeRole-pattern matches."""
    if not correlated_path.exists():
        return []
    try:
        data = json.loads(correlated_path.read_text())
    except Exception:
        return []

    targets: List[Tuple[str, str]] = []
    for corr in data.get("correlations", []) or []:
        if not isinstance(corr, dict) or corr.get("pattern_id") != ASSUME_ROLE_PATTERN_ID:
            continue
        corr_id = str(corr.get("id") or "unknown")
        for arn in corr.get("affected_resources") or []:
            if isinstance(arn, str) and _ROLE_ARN_RE.match(arn):
                targets.append((corr_id, arn))
    return targets


def _s3_buckets_from_findings(findings_dir: Path) -> List[Tuple[str, str]]:
    """Return [(finding_id, bucket_name), ...] for EXP-001-type findings."""
    exposure_path = findings_dir / "exposure.json"
    if not exposure_path.exists():
        return []
    try:
        data = json.loads(exposure_path.read_text())
    except Exception:
        return []

    targets: List[Tuple[str, str]] = []
    for f in data.get("findings", []) or []:
        if not isinstance(f, dict) or f.get("id") not in S3_PUBLIC_CHECK_IDS:
            continue
        for arn in f.get("affected_resources") or []:
            if isinstance(arn, str) and arn.startswith(_S3_ARN_PREFIX):
                bucket = arn[len(_S3_ARN_PREFIX) :].split("/")[0]
                if bucket:
                    targets.append((str(f.get("id")), bucket))
    return targets


def _attach_result(
    file_path: Path,
    id_field: str,
    target_id: str,
    result: VerificationResult,
) -> None:
    """Best-effort: attach active_verification to the matching entry in a
    findings/correlated JSON file and re-save. Never raises -- a failure to
    persist the annotation shouldn't break report generation.
    """
    try:
        data = json.loads(file_path.read_text())
    except Exception:
        return

    entries = data.get("correlations") if "correlations" in data else data.get("findings", [])
    if not isinstance(entries, list):
        return
    changed = False
    for entry in entries:
        if isinstance(entry, dict) and str(entry.get(id_field)) == target_id:
            entry["active_verification"] = {
                "method": result.method,
                "result": result.result,
                "detail": result.detail,
                "timestamp": result.timestamp,
            }
            changed = True
    if changed:
        try:
            file_path.write_text(json.dumps(data, indent=2, default=str))
        except Exception:
            pass


def run_active_verification(
    session_base_path: Path,
    aws_session: boto3.Session,
) -> Dict[str, Any]:
    """Run every in-scope active verifier against this session's findings.

    Returns a small summary dict for the CLI to print: counts of attempts
    by result, and the log file path. Never raises -- any individual
    verifier failure is captured as an "error" VerificationResult, not
    propagated, so this phase can never abort the audit.
    """
    findings_dir = session_base_path / "findings"
    results: List[VerificationResult] = []

    correlated_path = findings_dir / "correlated.json"
    for corr_id, role_arn in _role_arns_from_correlated(correlated_path):
        result = verify_assume_role(aws_session, role_arn, session_label=corr_id)
        results.append(result)
        if result.result == "success":
            _attach_result(correlated_path, "id", corr_id, result)

    exposure_path = findings_dir / "exposure.json"
    for finding_id, bucket in _s3_buckets_from_findings(findings_dir):
        result = verify_s3_public_access(bucket)
        results.append(result)
        if result.result == "success":
            _attach_result(exposure_path, "id", finding_id, result)

    log_path = write_verification_log(session_base_path, results)

    return {
        "attempted": len(results),
        "succeeded": sum(1 for r in results if r.result == "success"),
        "denied": sum(1 for r in results if r.result == "denied"),
        "errored": sum(1 for r in results if r.result == "error"),
        "log_path": str(log_path),
    }
