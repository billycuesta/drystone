"""Cross-skill deduplication of findings.

When multiple skills report the same underlying issue on the same resources,
this module keeps the single best finding and marks the rest as superseded.

Strategy:
1. Group findings by affected_resources overlap.
2. For pairs with >=80% resource overlap *and* same severity, keep the one
   with the highest quality_score (more fields populated).
3. Log superseded findings but exclude them from the final report.
"""

import logging
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

# Cross-skill pairs where dedup applies, with minimum resource overlap threshold
CROSS_SKILL_DEDUP_RULES: List[Tuple[str, str, float]] = [
    ("RECON-", "EXP-", 0.8),   # Recon vs Exposure (same public endpoints)
    ("IAM-", "EXP-", 0.8),     # IAM vs Exposure (cross-account resources)
    ("SM-", "SM-", 0.9),       # Within-skill semantic dedup (rotation variants)
]

# Skill priority: when quality is tied, prefer the more authoritative skill
_SKILL_PRIORITY = {
    "exposure": 5,
    "iam": 4,
    "vulns": 3,
    "network": 3,
    "secretsmanager": 2,
    "recon": 1,
}


def _resource_set(finding: Dict[str, Any]) -> Set[str]:
    """Extract normalized affected_resources as a set."""
    resources = finding.get("affected_resources", [])
    if not isinstance(resources, list):
        return set()
    return {str(r).lower().strip() for r in resources if r}


def _quality_score(finding: Dict[str, Any]) -> int:
    """Score how complete a finding is (more fields = higher quality)."""
    score = 0
    for field in ("description", "impact", "remediation", "evidence_snippet",
                  "evidence_refs", "pci_dss", "cis_reference", "affected_resources"):
        val = finding.get(field)
        if val:
            if isinstance(val, list) and len(val) > 0:
                score += 1
            elif isinstance(val, (str, dict)) and val:
                score += 1
    return score


def _resource_overlap(set_a: Set[str], set_b: Set[str]) -> float:
    """Jaccard-like overlap: intersection / min(len_a, len_b)."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    min_size = min(len(set_a), len(set_b))
    return intersection / min_size if min_size > 0 else 0.0


def _matches_rule(id_a: str, id_b: str) -> float:
    """Return the overlap threshold if the pair matches a dedup rule, else 0."""
    for prefix_a, prefix_b, threshold in CROSS_SKILL_DEDUP_RULES:
        if (id_a.startswith(prefix_a) and id_b.startswith(prefix_b)) or \
           (id_a.startswith(prefix_b) and id_b.startswith(prefix_a)):
            return threshold
    return 0.0


def _pick_winner(finding_a: Dict[str, Any], finding_b: Dict[str, Any]) -> Dict[str, Any]:
    """Choose the better finding to keep."""
    qa = _quality_score(finding_a)
    qb = _quality_score(finding_b)
    if qa != qb:
        return finding_a if qa > qb else finding_b
    # Tie-break: prefer the skill with higher priority
    skill_a = str(finding_a.get("skill", ""))
    skill_b = str(finding_b.get("skill", ""))
    pa = _SKILL_PRIORITY.get(skill_a, 0)
    pb = _SKILL_PRIORITY.get(skill_b, 0)
    return finding_a if pa >= pb else finding_b


def deduplicate_cross_skill(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings across skills based on resource overlap.

    Returns:
        Filtered list with duplicates removed. Superseded findings are logged.
    """
    if len(findings) < 2:
        return findings

    # Pre-compute resource sets
    resource_sets = {i: _resource_set(f) for i, f in enumerate(findings)}

    # Track indices to remove
    superseded: Set[int] = set()

    for i in range(len(findings)):
        if i in superseded:
            continue
        fi = findings[i]
        id_i = str(fi.get("id", ""))
        sev_i = fi.get("severity")
        rs_i = resource_sets[i]

        if not rs_i:  # No resources to compare
            continue

        for j in range(i + 1, len(findings)):
            if j in superseded:
                continue
            fj = findings[j]
            id_j = str(fj.get("id", ""))
            sev_j = fj.get("severity")

            # Must match a dedup rule
            threshold = _matches_rule(id_i, id_j)
            if threshold == 0.0:
                continue

            # Same severity required
            if sev_i != sev_j:
                continue

            rs_j = resource_sets[j]
            if not rs_j:
                continue

            overlap = _resource_overlap(rs_i, rs_j)
            if overlap >= threshold:
                winner = _pick_winner(fi, fj)
                loser_idx = j if winner is fi else i
                loser = findings[loser_idx]
                superseded.add(loser_idx)
                logger.info(
                    "Cross-skill dedup: %s superseded by %s (overlap=%.0f%%)",
                    loser.get("id"),
                    winner.get("id"),
                    overlap * 100,
                )

    result = [f for i, f in enumerate(findings) if i not in superseded]
    if superseded:
        logger.info(
            "Cross-skill dedup removed %d duplicate finding(s) (%d → %d)",
            len(superseded),
            len(findings),
            len(result),
        )
    return result
