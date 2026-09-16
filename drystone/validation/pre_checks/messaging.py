# ruff: noqa
"""Messaging deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


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

__all__ = [name for name in globals() if name.startswith("check_")]
