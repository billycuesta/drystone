"""Text table rendering helpers for PCI DSS evidence output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from drystone.reports.pci_cli_queries import OutputSpec

_MAX_ROWS = 200


def _flatten(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(_flatten(item) for item in value)
    return str(value).replace("\n", r"\n")


def _get_path(value: Any, path: str) -> Any:
    if not path:
        return value
    current = value
    for part in path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return None
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def render_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Render a left-aligned, ``column -t``-style text table."""

    text_rows = [[_flatten(cell) for cell in row] for row in rows]
    text_headers = [str(header).replace("\n", r"\n") for header in headers]
    all_rows = [text_headers, *text_rows]
    widths = [max(len(row[index]) for row in all_rows) for index in range(len(text_headers))]

    def render_row(row: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()

    return "\n".join(render_row(row) for row in all_rows)


def render_kv(mapping: Mapping[str, Any]) -> str:
    """Render a flat mapping as a two-column key/value table."""

    rows = [(key, value) for key, value in mapping.items()]
    return render_table(("Key", "Value"), rows)


def _rows_for_spec(spec: OutputSpec, evidence: Any) -> Optional[list[Any]]:
    raw_rows = _get_path(evidence, spec.rows)
    if raw_rows is None:
        return None
    if isinstance(raw_rows, list):
        return raw_rows
    if spec.style == "kv" and isinstance(raw_rows, Mapping):
        return [raw_rows]
    if spec.rows == "" and isinstance(raw_rows, Mapping):
        return [raw_rows]
    return None


def apply_output_spec(spec: OutputSpec, evidence: Any) -> Optional[str]:
    """Apply an OutputSpec to stored evidence.

    Returns ``None`` when the requested source/path/columns cannot be resolved.
    """

    source_evidence = _get_path(evidence, spec.source) if isinstance(evidence, Mapping) else None
    if source_evidence is None:
        return None

    if spec.style == "kv":
        target = _get_path(source_evidence, spec.rows) if spec.rows else source_evidence
        if not isinstance(target, Mapping):
            return None
        return render_kv(target)

    rows = _rows_for_spec(spec, source_evidence)
    if rows is None or not spec.columns:
        return None

    rendered_rows: list[list[Any]] = []
    for row in rows[:_MAX_ROWS]:
        rendered_rows.append([_get_path(row, path) for _, path in spec.columns])

    if len(rows) > _MAX_ROWS:
        rendered_rows.append([f"... ({len(rows) - _MAX_ROWS} more rows)", *[""] * (len(spec.columns) - 1)])

    return render_table([header for header, _ in spec.columns], rendered_rows)
