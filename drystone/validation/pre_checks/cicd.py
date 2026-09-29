# ruff: noqa
"""Cicd deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# CICD PRE-CHECKS
# ============================================================================


def _cicd_source_credentials_failure(evidence: Dict[str, Any]) -> Optional[str]:
    """Return a reason when CodeBuild source-credentials collection failed."""
    doc = evidence.get("codebuild-source-credentials")
    errors = doc.get("errors") if isinstance(doc, dict) else None
    if errors:
        return f"codebuild-source-credentials collection reported errors: {errors}"
    return None


@_register("cicd")
def check_cicd_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """CodeBuild source credentials exist."""
    if warning := check_evidence_or_warn(
        "CICD-001", evidence, ["codebuild-source-credentials"], expected_type=dict
    ):
        return warning
    sc_doc = evidence.get("codebuild-source-credentials")
    items = sc_doc.get("items") if isinstance(sc_doc, dict) else None
    if isinstance(items, list) and len(items) > 0:
        return PreCheckResult("CICD-001", "FAIL", f"{len(items)} source credentials found", [])
    return pass_or_warn(
        PreCheckResult("CICD-001", "PASS", "no CodeBuild source credentials", []),
        evidence,
        "CICD-001",
        "codebuild-source-credentials",
        _cicd_source_credentials_failure,
    )


@_register("cicd")
@requires_components("cicd", "codebuild-projects")
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

__all__ = [name for name in globals() if name.startswith("check_")]
