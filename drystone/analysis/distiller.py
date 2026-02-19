"""Evidence distillation to reduce prompt/token size."""

from typing import Any, Dict, Tuple


def distill_evidence(
    evidence: Dict[str, Any], max_list_items: int = 25
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Create a compact evidence view while keeping traceability.

    Rules:
    - Keep metadata keys untouched.
    - For long lists, keep first N elements and attach summary metadata.
    - For dicts containing long lists, apply same truncation recursively (1 level).
    """
    distilled: Dict[str, Any] = {}
    files_reduced = 0
    items_removed = 0

    for key, value in evidence.items():
        if str(key).startswith("_"):
            distilled[key] = value
            continue

        if isinstance(value, list):
            if len(value) > max_list_items:
                files_reduced += 1
                items_removed += len(value) - max_list_items
                distilled[key] = {
                    "_distilled": True,
                    "_original_count": len(value),
                    "_kept_count": max_list_items,
                    "items": value[:max_list_items],
                }
            else:
                distilled[key] = value
            continue

        if isinstance(value, dict):
            compact = dict(value)
            changed = False
            for sub_key, sub_value in list(compact.items()):
                if isinstance(sub_value, list) and len(sub_value) > max_list_items:
                    changed = True
                    files_reduced += 1
                    items_removed += len(sub_value) - max_list_items
                    compact[sub_key] = {
                        "_distilled": True,
                        "_original_count": len(sub_value),
                        "_kept_count": max_list_items,
                        "items": sub_value[:max_list_items],
                    }
            distilled[key] = compact if changed else value
            continue

        distilled[key] = value

    stats = {
        "files_reduced": files_reduced,
        "items_removed": items_removed,
    }
    return distilled, stats
