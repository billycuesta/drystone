"""CloudTrail Events pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import (
    dedupe_refs,
    generic_traceability,
    list_from_evidence,
)


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id != "CTEF-003":
        return None
    return _cloudtrail_event_refs(result, evidence)


def _cloudtrail_event_refs(
    result: Any, evidence: Dict[str, Any]
) -> "tuple[List[str], Optional[Dict[str, Any]]]":
    target_event_names = {"StopLogging", "DeleteTrail", "UpdateTrail"}
    refs: List[str] = []
    events: List[Dict[str, Any]] = []
    seen_event_ids: set = set()

    def _add_event(key: str, idx: int, event: Dict[str, Any]) -> None:
        event_name = str(event.get("EventName") or "")
        if event_name not in target_event_names:
            return
        refs.append(f"{key}.json#/{idx}")
        event_id = str(event.get("EventId") or f"{key}:{idx}")
        if event_id in seen_event_ids:
            return
        seen_event_ids.add(event_id)
        events.append(event)

    for idx, event in enumerate(list_from_evidence(evidence, "audit-tampering-events")):
        _add_event("audit-tampering-events", idx, event)

    for key in ("stop-logging-events", "delete-trail-events", "update-trail-events"):
        for idx, event in enumerate(list_from_evidence(evidence, key)):
            _add_event(key, idx, event)

    if not refs:
        return generic_traceability(result, evidence)

    return dedupe_refs(refs), {
        "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
        "affected_resources": list(getattr(result, "affected_resources", []) or [])[:10],
        "items": events[:10],
    }
