"""Prompt/chunk budget policies for cost-safe analysis."""

from dataclasses import dataclass


@dataclass
class BudgetPolicy:
    max_tokens_per_chunk: int
    max_chunks: int
    distill_max_list_items: int


def get_budget_policy(provider_type: str, skill_name: str) -> BudgetPolicy:
    """Return conservative token/chunk budgets by provider.

    P0 default: prioritize stability/cost over exhaustive context volume.
    """
    p = (provider_type or "").lower()
    s = (skill_name or "").lower()

    if p == "claude-cli":
        base = BudgetPolicy(max_tokens_per_chunk=14000, max_chunks=8, distill_max_list_items=20)
    elif p == "openai-api":
        base = BudgetPolicy(max_tokens_per_chunk=22000, max_chunks=10, distill_max_list_items=25)
    else:
        base = BudgetPolicy(max_tokens_per_chunk=30000, max_chunks=12, distill_max_list_items=30)

    if s in {"iam", "network"}:
        base.max_chunks = min(base.max_chunks, 10)
    if s in {"vulns"}:
        base.max_chunks = min(base.max_chunks + 1, 12)
    return base
