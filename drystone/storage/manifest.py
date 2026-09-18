"""Evidence & findings chain-of-custody manifest.

Hashes every evidence/findings/report artifact in a session directory and
persists a manifest.json (file -> sha256 -> size) so post-audit
tampering can be detected later, independently of the report itself.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

MANIFEST_FILENAME = "manifest.json"
_HASHABLE_SUBDIRS = ("evidence", "findings", "reports")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hashable_files(base_path: Path) -> List[Path]:
    files: List[Path] = []
    for subdir in _HASHABLE_SUBDIRS:
        d = base_path / subdir
        if not d.exists():
            continue
        for p in sorted(x for x in d.rglob("*") if x.is_file()):
            if p.name == MANIFEST_FILENAME:
                continue
            files.append(p)
    return files


def build_manifest(base_path: Path) -> Dict[str, Any]:
    """Hash every evidence/findings/report artifact under base_path.

    Args:
        base_path: Session root directory (contains evidence/, findings/).

    Returns:
        Manifest dict with one entry per file (relative path -> hash/size).
    """
    files: Dict[str, Any] = {}
    for p in _hashable_files(base_path):
        rel = str(p.relative_to(base_path))
        files[rel] = {
            "sha256": _sha256_file(p),
            "size_bytes": p.stat().st_size,
        }
    return {
        "algorithm": "sha256",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(files),
        "files": files,
    }


def write_manifest(base_path: Path) -> "tuple[Path, str]":
    """Compute and persist manifest.json for a session.

    Returns:
        (manifest_path, manifest_content_sha256) — the second value is the
        hash of the manifest.json file itself, meant to be embedded in
        generated reports so a report can be checked against the manifest
        without trusting the manifest file in isolation.
    """
    manifest = build_manifest(base_path)
    manifest_path = base_path / MANIFEST_FILENAME
    content = json.dumps(manifest, indent=2, sort_keys=True)
    manifest_path.write_text(content)
    manifest_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return manifest_path, manifest_hash


def verify_manifest(base_path: Path) -> Dict[str, Any]:
    """Re-hash evidence/findings and compare against the stored manifest.json.

    Returns:
        {
          "ok": bool,
          "tampered": [relative paths whose hash no longer matches],
          "missing": [relative paths recorded but no longer on disk],
          "added": [relative paths on disk but not in the manifest],
          "checked_files": int,
          "manifest_generated_at": str | None,
          "error": str | None (set only if manifest.json itself is missing/unreadable),
        }
    """
    manifest_path = base_path / MANIFEST_FILENAME
    if not manifest_path.exists():
        return {
            "ok": False,
            "tampered": [],
            "missing": [],
            "added": [],
            "checked_files": 0,
            "manifest_generated_at": None,
            "error": f"No manifest found at {manifest_path}",
        }

    try:
        recorded = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        return {
            "ok": False,
            "tampered": [],
            "missing": [],
            "added": [],
            "checked_files": 0,
            "manifest_generated_at": None,
            "error": f"manifest.json is not valid JSON: {e}",
        }

    recorded_files: Dict[str, Any] = recorded.get("files") or {}
    current_files: Dict[str, str] = {
        str(p.relative_to(base_path)): _sha256_file(p) for p in _hashable_files(base_path)
    }

    tampered = sorted(
        rel
        for rel, meta in recorded_files.items()
        if rel in current_files and current_files[rel] != meta.get("sha256")
    )
    missing = sorted(rel for rel in recorded_files if rel not in current_files)
    added = sorted(rel for rel in current_files if rel not in recorded_files)

    return {
        "ok": not (tampered or missing or added),
        "tampered": tampered,
        "missing": missing,
        "added": added,
        "checked_files": len(current_files),
        "manifest_generated_at": recorded.get("generated_at"),
        "error": None,
    }
