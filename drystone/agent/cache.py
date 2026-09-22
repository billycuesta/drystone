"""Persistent LLM findings cache for token reduction (P1)."""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from drystone.models.findings import SkillFindings


class FindingsCache:
    """File-based cache keyed by provider+model+evidence+checklist fingerprint."""

    DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
    DEFAULT_MAX_ENTRIES = 1000

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: Optional[float] = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        self.cache_dir = cache_dir or (Path.home() / ".drystone" / "llm-cache")
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def build_key(
        self,
        *,
        skill_name: str,
        provider_type: str,
        model: str,
        evidence: Dict[str, Any],
        checklist: Dict[str, Any],
        pre_checks: Optional[list],
    ) -> str:
        payload = {
            "skill": skill_name,
            "provider": provider_type,
            "model": model,
            "checklist_version": checklist.get("version", "unknown"),
            "normalizer_version": "v1",
            "evidence": evidence,
            "checklist": checklist,
            "pre_checks": [
                {
                    "check_id": getattr(p, "check_id", ""),
                    "status": getattr(p, "status", ""),
                    "evidence_summary": getattr(p, "evidence_summary", ""),
                }
                for p in (pre_checks or [])
            ],
        }
        serialized = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _path_for(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def get(self, key: str) -> Optional[SkillFindings]:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            if self.ttl_seconds is not None and time.time() - path.stat().st_mtime > self.ttl_seconds:
                path.unlink()
                return None
            with open(path) as f:
                raw = json.load(f)
            return SkillFindings(**raw)
        except Exception:
            return None

    def set(self, key: str, findings: SkillFindings) -> None:
        path = self._path_for(key)
        try:
            with open(path, "w") as f:
                json.dump(findings.model_dump(mode="json"), f, indent=2, default=str)
        except Exception:
            return

        try:
            entries = [p for p in self.cache_dir.glob("*.json") if p.is_file()]
            if len(entries) <= self.max_entries:
                return
            entries.sort(key=lambda p: p.stat().st_mtime)
            for stale_path in entries[: len(entries) - self.max_entries]:
                try:
                    stale_path.unlink()
                except Exception:
                    continue
        except Exception:
            return
