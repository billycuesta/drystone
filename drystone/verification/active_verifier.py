"""Non-destructive active verifiers.

Two verifiers only, by deliberate scope decision (see roadmap doc):
- verify_assume_role: proves an IAM privilege-escalation chain is real by
  actually assuming the target role, once, read-only.
- verify_s3_public_access: proves an S3 bucket is genuinely public by making
  an unauthenticated HEAD/LIST call — never reads object content.

Both are non-destructive: no writes, no deletes, no resource creation.
Every call is described by the VerificationResult returned, which the
caller (drystone/verification/runner.py) is responsible for logging.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import boto3
import botocore.exceptions
from botocore import UNSIGNED
from botocore.config import Config

_ROLE_SESSION_NAME_MAX = 64
_ROLE_SESSION_NAME_SAFE = re.compile(r"[^\w+=,.@-]")


@dataclass
class VerificationResult:
    """Outcome of a single active-verification attempt.

    `result` is one of: "success", "denied", "error". A "denied"/"error"
    result is NOT evidence the underlying finding is wrong -- it only means
    this particular verification attempt didn't succeed (e.g. MFA required,
    ExternalId required, network issue). Callers must not downgrade an
    existing exploitability_status based on a non-"success" result.
    """

    method: str
    target: str
    attempted: bool
    result: str  # "success" | "denied" | "error"
    detail: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def _role_session_name(label: str) -> str:
    """Build a valid, clearly-labeled STS RoleSessionName.

    Must match [\\w+=,.@-]{2,64}. Prefixed so a defender reviewing
    CloudTrail can immediately recognize this as authorized audit activity,
    not an attacker.
    """
    safe_label = _ROLE_SESSION_NAME_SAFE.sub("-", label)
    name = f"drystone-authorized-security-audit-{safe_label}"
    return name[:_ROLE_SESSION_NAME_MAX]


def verify_assume_role(
    session: boto3.Session,
    role_arn: str,
    session_label: str,
) -> VerificationResult:
    """Attempt to assume role_arn using the audit's own AWS credentials.

    On success, makes exactly one further call (sts:get_caller_identity)
    with the assumed credentials to confirm the identity actually changed,
    then discards them. Does nothing else with the assumed session --
    no enumeration, no resource access.
    """
    session_name = _role_session_name(session_label)
    try:
        sts = session.client("sts")
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=900,  # minimum allowed -- least-privilege in time too
        )
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        return VerificationResult(
            method="sts_assume_role",
            target=role_arn,
            attempted=True,
            result="denied",
            detail=f"AssumeRole denied: {code}",
        )
    except Exception as e:
        return VerificationResult(
            method="sts_assume_role",
            target=role_arn,
            attempted=True,
            result="error",
            detail=f"AssumeRole failed: {e}",
        )

    creds = resp.get("Credentials") or {}
    try:
        assumed_sts = boto3.client(
            "sts",
            aws_access_key_id=creds.get("AccessKeyId"),
            aws_secret_access_key=creds.get("SecretAccessKey"),
            aws_session_token=creds.get("SessionToken"),
        )
        identity = assumed_sts.get_caller_identity()
        assumed_arn = identity.get("Arn", "")
    except Exception as e:
        # The assume-role call itself succeeded (real proof), but we
        # couldn't confirm identity afterwards -- still meaningful signal,
        # report as success with a note rather than discarding the proof.
        return VerificationResult(
            method="sts_assume_role",
            target=role_arn,
            attempted=True,
            result="success",
            detail=f"AssumeRole succeeded; get_caller_identity confirmation failed: {e}",
        )

    return VerificationResult(
        method="sts_assume_role",
        target=role_arn,
        attempted=True,
        result="success",
        detail=f"AssumeRole succeeded; confirmed identity change to {assumed_arn}",
    )


def verify_s3_public_access(
    bucket_name: str,
    region_name: str = "us-east-1",
    s3_client_factory: Optional[Any] = None,
) -> VerificationResult:
    """Attempt an UNAUTHENTICATED head/list against bucket_name.

    Uses an unsigned (anonymous) S3 client on purpose -- this proves the
    bucket is reachable from the open internet without any credentials,
    which is what "public" actually means. Never reads object content
    (no get_object, ever): head_bucket first, then list_objects_v2 with
    MaxKeys=1 only if head_bucket was inconclusive.
    """
    if s3_client_factory is not None:
        s3 = s3_client_factory()
    else:
        s3 = boto3.client(
            "s3",
            config=Config(signature_version=UNSIGNED),
            region_name=region_name,
        )

    try:
        s3.head_bucket(Bucket=bucket_name)
        return VerificationResult(
            method="s3_unauthenticated_head_bucket",
            target=bucket_name,
            attempted=True,
            result="success",
            detail="Unauthenticated HEAD succeeded -- bucket is publicly accessible",
        )
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code not in {"403", "AccessDenied", "Forbidden"}:
            # Bucket doesn't exist / other definitive non-access error --
            # no point trying list_objects_v2 too.
            return VerificationResult(
                method="s3_unauthenticated_head_bucket",
                target=bucket_name,
                attempted=True,
                result="denied" if code == "404" else "error",
                detail=f"Unauthenticated HEAD failed: {code}",
            )
    except Exception as e:
        return VerificationResult(
            method="s3_unauthenticated_head_bucket",
            target=bucket_name,
            attempted=True,
            result="error",
            detail=f"Unauthenticated HEAD failed: {e}",
        )

    # HEAD was ambiguous (403) -- some public buckets deny HEAD but allow
    # listing (bucket policy grants s3:ListBucket but not the implicit
    # permission HEAD relies on). Try a bounded, metadata-only list.
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        key_count = resp.get("KeyCount", 0)
        return VerificationResult(
            method="s3_unauthenticated_list_objects",
            target=bucket_name,
            attempted=True,
            result="success",
            detail=f"Unauthenticated ListObjectsV2 succeeded (KeyCount={key_count})",
        )
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        return VerificationResult(
            method="s3_unauthenticated_list_objects",
            target=bucket_name,
            attempted=True,
            result="denied",
            detail=f"Unauthenticated ListObjectsV2 denied: {code}",
        )
    except Exception as e:
        return VerificationResult(
            method="s3_unauthenticated_list_objects",
            target=bucket_name,
            attempted=True,
            result="error",
            detail=f"Unauthenticated ListObjectsV2 failed: {e}",
        )
