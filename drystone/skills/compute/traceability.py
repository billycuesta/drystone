"""Compute (COMP-*) pre-check traceability."""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import dedupe_refs, generic_traceability, indexed_ref_for


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
    if not check_id.startswith("COMP-"):
        return None

    affected = _affected(result)
    refs: List[str] = []

    if check_id.startswith("COMP-EKS-"):
        ref = indexed_ref_for(
            evidence,
            "eks-inventory",
            lambda item: _matches(item.get("arn") or item.get("Arn"), affected)
            or _matches(item.get("name") or item.get("Name"), affected),
            preferred_index="clusters",
        )
        if ref:
            refs.append(ref)

    if check_id.startswith("COMP-ECS-"):
        ref = indexed_ref_for(
            evidence,
            "ecs-inventory",
            lambda item: _matches(item.get("taskDefinitionArn"), affected),
            preferred_index="task_definitions",
        )
        if ref:
            refs.append(ref)
        rule_ref = indexed_ref_for(
            evidence,
            "eventbridge-rules",
            lambda item: _matches(item.get("Arn"), affected) or _matches(item.get("Name"), affected),
            preferred_index="rules",
        )
        if rule_ref:
            refs.append(rule_ref)

    if check_id.startswith("COMP-EC2-"):
        ref = indexed_ref_for(
            evidence,
            "ec2-inventory",
            lambda item: _matches(item.get("InstanceId"), affected),
            preferred_index="instances",
        )
        if ref:
            refs.append(ref)

    if check_id.startswith("COMP-LMB-"):
        ref = indexed_ref_for(
            evidence,
            "lambda-inventory",
            lambda item: _matches(item.get("FunctionArn"), affected)
            or _matches(item.get("FunctionName"), affected),
            preferred_index="functions",
        )
        if ref:
            refs.append(ref)

    refs = dedupe_refs(refs)
    if refs:
        return refs[:10], {
            "evidence_summary": getattr(result, "evidence_summary", "compute pre-check fail"),
            "affected_resources": list(affected)[:10],
        }

    return generic_traceability(result, evidence)
