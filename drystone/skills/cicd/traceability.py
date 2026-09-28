"""CI/CD (CICD-*) pre-check traceability."""

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
    if not check_id.startswith("CICD-"):
        return None

    affected = _affected(result)
    refs: List[str] = []

    if check_id == "CICD-001":
        doc = (evidence or {}).get("codebuild-source-credentials")
        items = doc.get("items") if isinstance(doc, dict) else None
        if isinstance(items, list):
            if affected:
                for idx, item in enumerate(items):
                    if isinstance(item, dict) and (
                        _matches(item.get("arn"), affected) or _matches(item.get("resource"), affected)
                    ):
                        refs.append(f"codebuild-source-credentials.json#/items/{idx}")
            else:
                refs.extend(
                    f"codebuild-source-credentials.json#/items/{idx}"
                    for idx, item in enumerate(items[:10])
                    if isinstance(item, dict)
                )

    if check_id == "CICD-002":
        ref = indexed_ref_for(
            evidence,
            "codebuild-projects",
            lambda item: _matches(item.get("arn"), affected) or _matches(item.get("name"), affected),
        )
        if ref:
            refs.append(ref)

    refs = dedupe_refs(refs)
    if refs:
        return refs[:10], {
            "evidence_summary": getattr(result, "evidence_summary", "CI/CD pre-check fail"),
            "affected_resources": list(affected)[:10],
        }

    return generic_traceability(result, evidence)
