"""Confidence scoring for token-optimized analysis pipelines (P2)."""

from typing import Dict


def compute_skill_confidence(
    *,
    total_checks: int,
    deterministic_checks: int,
    llm_checks: int,
    partial_run: bool = False,
) -> Dict[str, object]:
    """Compute confidence score/label for a skill analysis.

    Heuristic:
    - More deterministic coverage increases confidence.
    - Partial runs significantly reduce confidence.
    - Presence of unresolved checks keeps confidence below max.
    """
    if total_checks <= 0:
        return {"score": 0.0, "level": "low"}

    deterministic_ratio = max(0.0, min(1.0, deterministic_checks / float(total_checks)))
    llm_ratio = max(0.0, min(1.0, llm_checks / float(total_checks)))

    score = 0.55 + (0.35 * deterministic_ratio) + (0.10 * (1.0 - llm_ratio))
    if partial_run:
        score -= 0.35
    score = max(0.0, min(1.0, score))

    if score >= 0.85:
        level = "high"
    elif score >= 0.6:
        level = "medium"
    else:
        level = "low"

    return {"score": round(score, 3), "level": level}
