"""Prompt/chunk budget policies for cost-safe analysis."""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BudgetPolicy:
    max_tokens_per_chunk: int
    max_chunks: int
    distill_max_list_items: int


def _load_overrides() -> dict:
    path = Path.home() / ".drystone" / "budget-overrides.json"
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def get_budget_policy(
    provider_type: str, skill_name: str, scan_depth: str = "normal"
) -> BudgetPolicy:
    """Return conservative token/chunk budgets by provider.

    P0 default: prioritize stability/cost over exhaustive context volume.
    """
    p = (provider_type or "").lower()
    s = (skill_name or "").lower()

    if p == "claude-cli":
        base = BudgetPolicy(max_tokens_per_chunk=14000, max_chunks=8, distill_max_list_items=20)
    else:
        base = BudgetPolicy(max_tokens_per_chunk=30000, max_chunks=12, distill_max_list_items=30)

    if s in {"iam", "network"}:
        base.max_chunks = min(base.max_chunks, 10)
    if s in {"vulns"}:
        base.max_chunks = min(base.max_chunks + 1, 12)

    depth = str(scan_depth or "normal").lower()
    depth_factors = {
        "shallow": (0.6, 0.7),
        "normal": (1.0, 1.0),
        "deep": (1.4, 1.25),
        "very-deep": (1.8, 1.5),
    }
    chunk_factor, list_factor = depth_factors.get(depth, (1.0, 1.0))
    base.max_chunks = max(4, int(base.max_chunks * chunk_factor))
    base.distill_max_list_items = max(12, int(base.distill_max_list_items * list_factor))

    overrides = _load_overrides().get("skills", {})
    key = f"{p}:{s}"
    custom = overrides.get(key)
    if isinstance(custom, dict):
        base.max_tokens_per_chunk = int(
            custom.get("max_tokens_per_chunk", base.max_tokens_per_chunk)
        )
        base.max_chunks = int(custom.get("max_chunks", base.max_chunks))
        base.distill_max_list_items = int(
            custom.get("distill_max_list_items", base.distill_max_list_items)
        )
    return base
