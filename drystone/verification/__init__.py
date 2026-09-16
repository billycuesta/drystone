"""Active verification: real, non-destructive AWS API calls that prove specific
findings are actually exploitable, instead of only inferring exploitability
from evidence.

Scope is deliberately narrow (see PLAN_PROFESSIONAL_GRADE_ROADMAP.md, "Pentest
Skill Quality Audit", recommendation G): AssumeRole chain verification and S3
public-access verification only. Every call made is logged to
<session>/active_verification_log.json.
"""

from drystone.verification.active_verifier import (
    VerificationResult,
    verify_assume_role,
    verify_s3_public_access,
)
from drystone.verification.runner import run_active_verification

__all__ = [
    "VerificationResult",
    "verify_assume_role",
    "verify_s3_public_access",
    "run_active_verification",
]
