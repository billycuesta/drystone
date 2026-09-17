#!/usr/bin/env python3
"""Refresh Drystone's bundled TrailDiscover catalog.

P2.5 helper: fetch the aggregate TrailDiscover event catalog from GitHub,
write `drystone/threat_intel/traildiscover_events.json`, and write a sibling
metadata file so report consumers can see when/where the threat-intel bundle
came from.

Usage:
    python3 scripts/update_traildiscover.py --dry-run
    python3 scripts/update_traildiscover.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = "adanalvarez/TrailDiscover"
BRANCH = "main"
CATALOG_REPO_PATH = "docs/events.json"
RAW_CATALOG_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/{CATALOG_REPO_PATH}"
COMMITS_URL = (
    f"https://api.github.com/repos/{REPO}/commits"
    f"?path={CATALOG_REPO_PATH}&sha={BRANCH}&per_page=1"
)
USER_AGENT = "drystone-traildiscover-updater"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG_PATH = PROJECT_ROOT / "drystone" / "threat_intel" / "traildiscover_events.json"
DEFAULT_METADATA_PATH = PROJECT_ROOT / "drystone" / "threat_intel" / "traildiscover_metadata.json"


def _fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _fetch_json(url: str) -> Any:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def _latest_commit_metadata() -> tuple[str | None, str | None]:
    try:
        commits = _fetch_json(COMMITS_URL)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None, None
    if not isinstance(commits, list) or not commits:
        return None, None
    first = commits[0]
    if not isinstance(first, dict):
        return None, None
    commit = first.get("commit") or {}
    committer = commit.get("committer") or {}
    return first.get("sha"), committer.get("date")


def build_metadata(catalog_bytes: bytes, events: list[dict[str, Any]]) -> dict[str, Any]:
    source_commit, source_commit_date = _latest_commit_metadata()
    return {
        "schema_version": "1.0",
        "source": "TrailDiscover",
        "repository": f"https://github.com/{REPO}",
        "source_path": CATALOG_REPO_PATH,
        "source_url": RAW_CATALOG_URL,
        "source_branch": BRANCH,
        "source_commit": source_commit,
        "source_commit_date": source_commit_date,
        "refreshed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_count": len(events),
        "sha256": hashlib.sha256(catalog_bytes).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-path", type=Path, default=DEFAULT_CATALOG_PATH)
    parser.add_argument("--metadata-path", type=Path, default=DEFAULT_METADATA_PATH)
    parser.add_argument("--dry-run", action="store_true", help="Fetch and validate without writing files")
    args = parser.parse_args()

    try:
        catalog_bytes = _fetch_bytes(RAW_CATALOG_URL)
        events = json.loads(catalog_bytes)
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"error: could not fetch TrailDiscover catalog: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: upstream catalog is not valid JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        print("error: upstream catalog must be a JSON array of objects", file=sys.stderr)
        return 1

    metadata = build_metadata(catalog_bytes, events)
    catalog_text = json.dumps(events, indent=2, ensure_ascii=False) + "\n"
    metadata_text = json.dumps(metadata, indent=2, sort_keys=True) + "\n"

    print(f"TrailDiscover events: {len(events)}", file=sys.stderr)
    print(f"SHA-256: {metadata['sha256']}", file=sys.stderr)
    if metadata.get("source_commit"):
        print(f"Source commit: {metadata['source_commit']}", file=sys.stderr)
    if args.dry_run:
        print("Dry run: no files written", file=sys.stderr)
        return 0

    args.catalog_path.parent.mkdir(parents=True, exist_ok=True)
    args.catalog_path.write_text(catalog_text)
    args.metadata_path.write_text(metadata_text)
    print(f"Wrote {args.catalog_path}", file=sys.stderr)
    print(f"Wrote {args.metadata_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
