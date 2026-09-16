"""Adaptive budget optimizer based on prior run telemetry (P3)."""

import json
from pathlib import Path
from typing import Any, Dict


def optimize_budgets_from_metrics(metrics_file: Path) -> Dict[str, Any]:
    """Create/update budget overrides from metrics.json.

    Heuristic:
    - If skill failed with quota/rate issues, reduce max_chunks and distill size.
    - If skill completed partially or fell back from LLM, reduce per-prompt size.
    - If skill completed with llm_skipped=true, reduce budget modestly.
    """
    if not metrics_file.exists():
        return {"updated": 0}

    try:
        with open(metrics_file) as f:
            metrics = json.load(f)
    except Exception:
        return {"updated": 0}

    skills = metrics.get("skills", {})
    if not isinstance(skills, dict):
        return {"updated": 0}

    overrides_path = Path.home() / ".drystone" / "budget-overrides.json"
    overrides_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if overrides_path.exists():
            with open(overrides_path) as f:
                payload = json.load(f)
        else:
            payload = {"skills": {}}
    except Exception:
        payload = {"skills": {}}

    entries = payload.setdefault("skills", {})
    updated = 0

    for skill_name, data in skills.items():
        if not isinstance(data, dict):
            continue
        provider = str(data.get("provider", "claude-cli"))
        key = f"{provider}:{skill_name}"
        current = entries.get(
            key,
            {
                "max_tokens_per_chunk": 30000 if provider == "claude-api" else 14000,
                "max_chunks": 12 if provider == "claude-api" else 8,
                "distill_max_list_items": 30 if provider == "claude-api" else 20,
            },
        )

        status = str(data.get("status", ""))
        llm_skipped = bool(data.get("llm_skipped", False))
        llm_fallback = bool(data.get("llm_fallback_used", False))
        partial_results = bool(data.get("partial_results", False))
        validation_failed = data.get("validation_passed") is False
        failed_chunks = int(data.get("failed_chunks") or 0)
        retries = data.get("retries", [])
        had_quota = any("quota" in str(r.get("reason", "")).lower() for r in retries)
        had_partial_execution = (
            status == "partial"
            or partial_results
            or llm_fallback
            or failed_chunks > 0
            or (validation_failed and status not in {"complete", "success"})
        )

        next_cfg = dict(current)
        if status == "failed" or had_quota:
            next_cfg["max_chunks"] = max(4, int(current.get("max_chunks", 8)) - 2)
            next_cfg["distill_max_list_items"] = max(
                12, int(current.get("distill_max_list_items", 20)) - 3
            )
            next_cfg["max_tokens_per_chunk"] = max(
                8000, int(int(current.get("max_tokens_per_chunk", 14000)) * 0.75)
            )
        elif had_partial_execution:
            next_cfg["max_tokens_per_chunk"] = max(
                8000, int(int(current.get("max_tokens_per_chunk", 14000)) * 0.75)
            )
            next_cfg["distill_max_list_items"] = max(
                12, int(current.get("distill_max_list_items", 20)) - 5
            )
            if llm_skipped or llm_fallback:
                next_cfg["max_chunks"] = max(4, int(current.get("max_chunks", 8)) - 1)
        elif llm_skipped:
            next_cfg["max_chunks"] = max(4, int(current.get("max_chunks", 8)) - 1)

        if next_cfg != current:
            entries[key] = next_cfg
            updated += 1

    payload["last_optimized_from"] = str(metrics_file)
    with open(overrides_path, "w") as f:
        json.dump(payload, f, indent=2)

    return {"updated": updated, "overrides_file": str(overrides_path)}
