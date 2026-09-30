"""Tests for internal consistency of skill checklist.json metadata."""

import json
from pathlib import Path

import pytest

CHECKLIST_DIR = Path(__file__).parent.parent.parent / "drystone" / "skills"

CHECKLIST_PATHS = sorted(CHECKLIST_DIR.glob("*/checklist.json"))


def _checklist_id(path: Path) -> str:
    return path.parent.name


@pytest.mark.parametrize("checklist_path", CHECKLIST_PATHS, ids=_checklist_id)
def test_total_checks_matches_items_length(checklist_path: Path):
    """A checklist's declared total_checks must match its actual item count.

    total_checks is read by report formatters (e.g. checklist version/count
    reporting) and is easy to leave stale when items are added or removed by
    hand. Keeping it asserted here catches that drift immediately instead of
    silently shipping a misleading count.
    """
    with open(checklist_path) as f:
        checklist = json.load(f)

    items = checklist.get("items", [])
    assert checklist.get("total_checks") == len(items), (
        f"{checklist_path}: total_checks={checklist.get('total_checks')} "
        f"but items has {len(items)} entries"
    )
