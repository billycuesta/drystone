"""Shared helpers for per-skill pre-check traceability (evidence_refs/evidence_snippet).

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
These are the functions that were used by 2+ skill-specific blocks in the
original god-method; skill-only helpers live in that skill's own
skills/{skill}/traceability.py instead.
"""

from typing import Any, Dict, List, Optional


def resource_matches(obj: Dict[str, Any], affected: set) -> bool:
    if not affected:
        return False
    candidates = [
        str(obj.get("Arn") or ""),
        str(obj.get("ARN") or ""),
        str(obj.get("RepositoryArn") or ""),
        str(obj.get("RoleArn") or ""),
        str(obj.get("UserArn") or ""),
        str(obj.get("KeyArn") or ""),
        str(obj.get("LoadBalancerArn") or ""),
        str(obj.get("DBInstanceIdentifier") or ""),
        str(obj.get("GroupId") or ""),
        str(obj.get("BucketName") or ""),
        str(obj.get("VpcId") or ""),
        str(obj.get("Id") or ""),
        str(obj.get("Name") or ""),
        str(obj.get("RepositoryName") or ""),
        str(obj.get("ResourceName") or ""),
        str(obj.get("Username") or ""),
        str(obj.get("callerArn") or ""),
        str(obj.get("EventId") or ""),
    ]
    for resource in obj.get("Resources") or []:
        if isinstance(resource, dict):
            candidates.append(str(resource.get("ResourceName") or ""))
    for c in candidates:
        if not c:
            continue
        if c in affected:
            return True
        for a in affected:
            if c and c in a:
                return True
    return False


def generic_traceability(
    result: Any, evidence: Dict[str, Any]
) -> "tuple[List[str], Optional[Dict[str, Any]]]":
    affected = set(str(r) for r in (getattr(result, "affected_resources", []) or []))
    refs: List[str] = []
    snippets: List[Dict[str, Any]] = []

    for file_key, doc in (evidence or {}).items():
        if not isinstance(file_key, str) or file_key.startswith("_"):
            continue

        # Common envelope: {"<collection>": [..]}
        if isinstance(doc, dict):
            for coll_key in (
                "items",
                "repositories",
                "users",
                "roles",
                "vpcs",
                "security_groups",
                "securityGroups",
                "subnets",
                "policies",
                "keys",
                "findings",
            ):
                items = doc.get(coll_key)
                if not isinstance(items, list):
                    continue
                for idx, item in enumerate(items):
                    if not isinstance(item, dict):
                        continue
                    if resource_matches(item, affected):
                        refs.append(f"{file_key}.json#/{coll_key}/{idx}")
                        snippets.append(item)
                        if len(snippets) >= 3:
                            return refs[:10], {"items": snippets}

            # Single object fallback
            if resource_matches(doc, affected):
                refs.append(f"{file_key}.json#/")
                snippets.append(doc)
                if len(snippets) >= 3:
                    return refs[:10], {"items": snippets}

        elif isinstance(doc, list):
            for idx, item in enumerate(doc):
                if not isinstance(item, dict):
                    continue
                if resource_matches(item, affected):
                    refs.append(f"{file_key}.json#/{idx}")
                    snippets.append(item)
                    if len(snippets) >= 3:
                        return refs[:10], {"items": snippets}

    if refs and snippets:
        return refs[:10], {"items": snippets[:10]}

    if affected:
        return [], {
            "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
            "affected_resources": list(affected)[:10],
        }

    return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}


def list_from_evidence(evidence: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    doc = (evidence or {}).get(key)
    if isinstance(doc, list):
        return [item for item in doc if isinstance(item, dict)]
    if isinstance(doc, dict):
        items = doc.get(key)
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        singular = key[:-1] if key.endswith("s") else key
        items = doc.get(singular)
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def refs_for_resources(
    evidence: Dict[str, Any],
    key: str,
    resources: List[str],
    name_fields: "tuple[str, ...]",
) -> "tuple[List[str], List[Dict[str, Any]]]":
    affected = {str(r) for r in resources or []}
    refs: List[str] = []
    matched: List[Dict[str, Any]] = []
    doc = (evidence or {}).get(key)
    items = list_from_evidence(evidence, key)
    pointer_prefix = f"{key}.json#/"
    if isinstance(doc, dict) and isinstance(doc.get(key), list):
        pointer_prefix = f"{key}.json#/{key}/"

    for idx, item in enumerate(items):
        candidates = {str(item.get("Arn") or item.get("ARN") or "")}
        for field_name in name_fields:
            val = item.get(field_name)
            if val:
                candidates.add(str(val))
        if not candidates & affected:
            if not any(c and any(c in a for a in affected) for c in candidates):
                continue
        refs.append(f"{pointer_prefix}{idx}")
        matched.append(item)
    return refs[:10], matched[:10]


def dedupe_refs(refs: List[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for ref in refs:
        if not ref or ref in seen:
            continue
        seen.add(ref)
        out.append(ref)
    return out


def indexed_ref_for(
    evidence: Dict[str, Any],
    key: str,
    predicate: Any,
    preferred_index: str = "items",
) -> Optional[str]:
    doc = (evidence or {}).get(key)
    if isinstance(doc, dict):
        if preferred_index and isinstance(doc.get(preferred_index), list):
            for idx, item in enumerate(doc[preferred_index]):
                if isinstance(item, dict) and predicate(item):
                    return f"{key}.json#/{preferred_index}/{idx}"
        if isinstance(doc.get("items"), list):
            for idx, item in enumerate(doc["items"]):
                if isinstance(item, dict) and predicate(item):
                    return f"{key}.json#/items/{idx}"
        for map_name in ("by_name", "by_id", "by_alb_arn"):
            mapping = doc.get(map_name)
            if not isinstance(mapping, dict):
                continue
            for map_key, item in mapping.items():
                value = item if isinstance(item, dict) else {"value": item}
                if predicate(value):
                    return f"{key}.json#{map_name}.{map_key}"
    elif isinstance(doc, list):
        for idx, item in enumerate(doc):
            if isinstance(item, dict) and predicate(item):
                return f"{key}.json#/{idx}"
    return None
