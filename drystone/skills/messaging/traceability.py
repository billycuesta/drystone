"""Messaging (MSG-*) pre-check traceability."""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, generic_traceability, indexed_ref_for

_SQS_CHECKS = {"MSG-001", "MSG-002", "MSG-003", "MSG-005", "MSG-006"}
_SNS_CHECKS = {"MSG-007", "MSG-008", "MSG-009"}


def _affected(result: Any) -> set[str]:
    return {str(r) for r in (getattr(result, "affected_resources", []) or []) if r}


def _matches(value: Any, affected: set[str]) -> bool:
    candidate = str(value or "")
    if not candidate or not affected:
        return False
    if candidate in affected:
        return True
    return any(candidate in resource or resource.endswith(candidate) for resource in affected)


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if not check_id.startswith("MSG-"):
        return None

    affected = _affected(result)
    refs: List[str] = []

    if check_id in _SQS_CHECKS:
        ref = indexed_ref_for(
            evidence,
            "sqs-queues",
            lambda item: _matches(item.get("QueueArn"), affected)
            or _matches(item.get("QueueUrl"), affected),
        )
        if ref:
            refs.append(ref)

    if check_id in _SNS_CHECKS:
        ref = indexed_ref_for(
            evidence,
            "sns-topics",
            lambda item: _matches(item.get("TopicArn"), affected),
        )
        if ref:
            refs.append(ref)

    refs = dedupe_refs(refs)
    if refs:
        return refs[:10], {
            "evidence_summary": getattr(result, "evidence_summary", "messaging pre-check fail"),
            "affected_resources": list(affected)[:10],
        }

    return generic_traceability(result, evidence)
