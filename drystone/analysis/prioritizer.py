"""Chunk prioritization for budget trimming."""

from typing import Any, Dict


FILE_PRIORITY = {
    "inspector-findings": 100,
    "security-groups": 95,
    "roles": 90,
    "policies": 88,
    "resource-based-policies": 86,
    "vpcs": 82,
    "route-tables": 80,
    "subnets": 78,
    "users": 76,
}


def score_chunk(source_file: str, evidence: Dict[str, Any]) -> int:
    """Return deterministic priority score for a chunk.

    Higher score means keep first when budget cap is applied.
    """
    key = str(source_file).replace(".json", "").lower()
    score = FILE_PRIORITY.get(key, 50)

    data = evidence.get(source_file)
    if isinstance(data, dict) and data.get("_distilled"):
        score += 5
    if isinstance(data, list):
        score += min(len(data), 20)
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        score += min(len(data.get("items", [])), 20)
    return score
