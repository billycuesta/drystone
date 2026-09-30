"""Guard against deprecated naive UTC timestamps in production code."""

from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "drystone"


@pytest.mark.parametrize(
    "path", sorted(PACKAGE_ROOT.rglob("*.py")), ids=lambda p: str(p.relative_to(PACKAGE_ROOT))
)
def test_no_datetime_utcnow(path: Path) -> None:
    """datetime.utcnow() is deprecated; use datetime.now(timezone.utc)."""
    assert "utcnow(" not in path.read_text(encoding="utf-8")
