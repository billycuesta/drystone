"""Checklist routing to reduce unnecessary LLM evaluation."""

from typing import Any, Dict, List, Set, Tuple


def route_checklist_for_llm(
    checklist: Dict[str, Any],
    pass_ids: Set[str],
    fail_ids: Set[str],
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Filter checklist items that require LLM analysis.

    PASS/FAIL checks are already resolved deterministically and are excluded from
    the LLM prompt. SKIP/pending checks remain for AI analysis.
    """
    items = checklist.get("items", []) if isinstance(checklist, dict) else []
    if not isinstance(items, list):
        items = []

    pre_resolved = set(pass_ids) | set(fail_ids)
    llm_items: List[Dict[str, Any]] = []
    item_ids: Set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("id", ""))
        if check_id:
            item_ids.add(check_id)
        if check_id and check_id in pre_resolved:
            continue
        llm_items.append(item)

    # Only count pre-checks that belong to the (possibly qsa_depth-filtered) checklist.
    # Without this guard, pre-checks registered for IDs outside the filtered set inflate
    # deterministic_resolved beyond total_checks, producing impossible confidence ratios.
    resolved_in_checklist = pre_resolved & item_ids

    routed = dict(checklist)
    routed["items"] = llm_items
    stats = {
        "total_checks": len(items),
        "deterministic_resolved": len(resolved_in_checklist),
        "llm_checks": len(llm_items),
    }
    return routed, stats
