"""TrailDiscover threat intelligence lookup for CloudTrail events.

Bundles the TrailDiscover catalog (https://github.com/adanalvarez/TrailDiscover)
as a local static JSON file for O(1) lookups without network dependency at runtime.

Catalog schema per event:
  eventName, eventSource, awsService, description, mitreAttackTactics,
  mitreAttackTechniques, mitreAttackSubTechniques, usedInWild, incidents,
  securityImplications, simulation, permissions

Usage:
  from drystone.threat_intel.traildiscover import enrich_finding, is_used_in_wild
"""

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_CATALOG_PATH = Path(__file__).parent / "traildiscover_events.json"


@lru_cache(maxsize=1)
def _load_catalog() -> Dict[str, Any]:
    """Load TrailDiscover catalog indexed by eventName (loaded once per process)."""
    try:
        with open(_CATALOG_PATH) as f:
            events = json.load(f)
        index = {
            e["eventName"]: e
            for e in events
            if isinstance(e, dict) and e.get("eventName")
        }
        logger.debug("TrailDiscover catalog loaded: %d events", len(index))
        return index
    except Exception as exc:
        logger.warning("Failed to load TrailDiscover catalog: %s", exc)
        return {}


def get_event_context(event_name: str) -> Optional[Dict[str, Any]]:
    """Return TrailDiscover metadata for a CloudTrail event, or None if not found."""
    return _load_catalog().get(event_name)


def get_mitre_context(event_name: str) -> Dict[str, List[str]]:
    """Return MITRE ATT&CK context for a CloudTrail event."""
    entry = get_event_context(event_name)
    if not entry:
        return {}
    return {
        "tactics": entry.get("mitreAttackTactics") or [],
        "techniques": entry.get("mitreAttackTechniques") or [],
        "sub_techniques": entry.get("mitreAttackSubTechniques") or [],
    }


def is_used_in_wild(event_name: str) -> bool:
    """Return True if this event has been observed in real-world attacks."""
    entry = get_event_context(event_name)
    return bool(entry and entry.get("usedInWild", False))


def get_incidents(event_name: str) -> List[Dict[str, str]]:
    """Return list of real-world incidents where this event was used."""
    entry = get_event_context(event_name)
    return (entry or {}).get("incidents") or []


def enrich_finding(finding: Dict[str, Any], event_names: List[str]) -> Dict[str, Any]:
    """Enrich a Drystone FAIL finding with TrailDiscover threat intelligence.

    Merges MITRE tactics/techniques, usedInWild flag, and real-world incidents
    from all relevant CloudTrail event names into the finding's metadata.

    Only enriches FAIL findings — PASS/SKIP are not modified.

    Args:
        finding: Drystone finding dict (mutated in-place and returned).
        event_names: CloudTrail event names relevant to this finding
                     (e.g. ["DeleteTrail", "StopLogging"] for CTEF-003).

    Returns:
        The (mutated) finding dict.
    """
    if finding.get("status") not in ("FAIL", "fail") and finding.get("severity") is None:
        # Only enrich genuine findings (have severity), not pre-check intermediaries
        pass

    all_tactics: List[str] = []
    all_techniques: List[str] = []
    all_sub_techniques: List[str] = []
    all_incidents: List[Dict[str, str]] = []
    any_wild = False
    best_implications: Optional[str] = None
    best_simulation: Optional[str] = None

    for event_name in event_names:
        entry = get_event_context(event_name)
        if not entry:
            continue

        for t in entry.get("mitreAttackTactics") or []:
            if t not in all_tactics:
                all_tactics.append(t)

        for t in entry.get("mitreAttackTechniques") or []:
            if t not in all_techniques:
                all_techniques.append(t)

        for t in entry.get("mitreAttackSubTechniques") or []:
            if t not in all_sub_techniques:
                all_sub_techniques.append(t)

        for incident in entry.get("incidents") or []:
            desc = incident.get("description", "")
            if desc and not any(i.get("description") == desc for i in all_incidents):
                all_incidents.append(incident)

        if entry.get("usedInWild"):
            any_wild = True

        # Use securityImplications from the first event that has it
        if not best_implications and entry.get("securityImplications"):
            best_implications = entry["securityImplications"]

        if not best_simulation and entry.get("simulation"):
            sim = entry["simulation"]
            # simulation may be a list or a string
            if isinstance(sim, list) and sim:
                best_simulation = sim[0].get("command") if isinstance(sim[0], dict) else str(sim[0])
            elif isinstance(sim, str):
                best_simulation = sim

    # Only add threat_intel block if we found something useful
    if any_wild or all_tactics or all_incidents:
        finding["threat_intel"] = {
            "mitre_tactics": all_tactics,
            "mitre_techniques": all_techniques,
            "mitre_sub_techniques": all_sub_techniques,
            "used_in_wild": any_wild,
            "real_incidents": [i.get("description", "") for i in all_incidents if i.get("description")],
            "incident_refs": all_incidents,
        }
        if best_implications:
            finding["threat_intel"]["security_implications"] = best_implications
        if best_simulation:
            finding["threat_intel"]["simulation"] = best_simulation

    return finding
