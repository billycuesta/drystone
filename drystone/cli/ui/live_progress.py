"""Live single-line progress rendering for `drystone audit` (visual only).

Wraps the existing `on_message(str)` narration stream from
`core/audit_runner.py` -- unchanged, still ~150 call sites emitting plain
strings -- into a persistent 2-row terminal view (`[N/M] <current action>`
above a bracketed solid-fill bar with its percentage) instead of one
scrolling line per message. Every message is still written in full to the
session's file logger, so nothing seen on screen during the run is lost
for later review.

Falls back to plain line-by-line printing (the previous behavior) when
stdout isn't a real terminal (piped output, CI, the E2E test runner's
`subprocess.run(capture_output=True)`), since Rich's `Live` can't overwrite
a non-interactive stream in place anyway.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import click
from rich.console import Console, Group
from rich.live import Live
from rich.text import Text

from drystone.cli.ui.branding import _interpolate_color

# Mirrors the exact message shapes core/audit_runner.py emits today -- see
# its `_msg(f"🔄 Phase ...")` / `_msg(f"   Phase ... progress: ...")` /
# `_msg(f"   📦 ...")` / `_msg(f"📊 Progress: ...")` call sites.
_PHASE_START_RE = re.compile(r"^🔄 Phase (\d+)/(\d+) \S+: 0/(\d+)")
_PHASE_PROGRESS_RE = re.compile(r"Phase (\d+)/(\d+) progress: (\d+)/(\d+)")
_CHUNK_START_RE = re.compile(r"📦 \S+: chunking started \(0/(\d+)\)")
_CHUNK_PROGRESS_RE = re.compile(r"📦 \S+: chunks (\d+)/(\d+)")
_OVERALL_PROGRESS_RE = re.compile(r"^📊 Progress: (\d+)/(\d+) phases \((\d+)%\)")

_COMPLETION_MARKER = "✅ Audit Complete"

_BAR_FILL_CHAR = "█"

# Same lilac -> orange gradient as the startup banner (branding.py::print_banner),
# so the progress bar reads as part of the same visual identity.
_GRADIENT_START = (180, 100, 220)  # Lilac/Purple
_GRADIENT_END = (255, 165, 0)  # Orange
_ACCENT_STYLE = _interpolate_color(0.5, _GRADIENT_START, _GRADIENT_END)


class LiveProgressReporter:
    """Drop-in replacement for `on_message=click.echo` in `run_audit()`.

    Use as a context manager:

        with LiveProgressReporter() as reporter:
            result = run_audit(config, account_id, on_message=reporter)
    """

    def __init__(self, *, force_terminal: Optional[bool] = None) -> None:
        """
        Args:
            force_terminal: Override terminal auto-detection. `None` (default)
                lets Rich decide from `stdout.isatty()`; pass `True`/`False`
                for deterministic behavior in tests.
        """
        self._console = Console(force_terminal=force_terminal)
        self._logger = logging.getLogger("drystone")
        self._live: Optional[Live] = None

        self._percent = 0.0
        self._status_message = "Starting audit..."

        self._total_phases = 3
        self._current_phase = 0
        self._phase_units_done = 0
        self._phase_units_total = 1
        self._sub_fraction = 0.0

    def __enter__(self) -> "LiveProgressReporter":
        if self._console.is_terminal:
            self._live = Live(
                self._render(),
                console=self._console,
                refresh_per_second=8,
                transient=False,
            )
            self._live.start()
        return self

    def __exit__(self, *exc_info) -> None:
        if self._live is not None:
            self._live.stop()
            self._live = None

    def __call__(self, message: str) -> None:
        """The `on_message(str)` callback `run_audit()` invokes per event."""
        stripped = message.strip()
        if stripped:
            self._logger.info(stripped)

        if self._live is not None and stripped.startswith(_COMPLETION_MARKER):
            # Freeze the bar at 100% and let the final summary (audit
            # complete banner, token usage, output path) print as normal
            # persistent lines below it, instead of flashing through the
            # single overwriting status line and disappearing.
            self._percent = 100.0
            self._live.update(self._render(), refresh=True)
            self._live.stop()
            self._live = None

        if self._live is None:
            click.echo(message)
            return

        pct = self._update_percent(message)
        if pct is not None:
            self._percent = pct
        if stripped:
            self._status_message = stripped

        self._live.update(self._render(), refresh=True)

    def _bar_width(self) -> int:
        # Leave room for "[N/N] " + "] 100%" and a small margin either side.
        return max(20, min(50, (self._console.width or 80) - 20))

    def _render(self) -> Group:
        step_line = Text(
            f"[{self._current_phase}/{self._total_phases}] {self._status_message}",
            style=_ACCENT_STYLE,
        )

        width = self._bar_width()
        filled = min(max(int(round(width * self._percent / 100)), 0), width)

        bar_line = Text()
        bar_line.append("[")
        # Same lilac -> orange gradient as the banner, spread across the full
        # bar width so the color at each position stays fixed as it fills in.
        for i in range(filled):
            position = i / max(width - 1, 1)
            color = _interpolate_color(position, _GRADIENT_START, _GRADIENT_END)
            bar_line.append(_BAR_FILL_CHAR, style=color)
        bar_line.append(" " * (width - filled))
        bar_line.append("] ")
        bar_line.append(f"{self._percent:.0f}%", style=f"bold {_ACCENT_STYLE}")

        return Group(step_line, bar_line)

    def _update_percent(self, message: str) -> Optional[float]:
        m = _OVERALL_PROGRESS_RE.search(message)
        if m:
            completed, total, pct = int(m.group(1)), int(m.group(2)), int(m.group(3))
            self._total_phases = total
            self._current_phase = completed
            self._phase_units_done = 0
            self._phase_units_total = 1
            self._sub_fraction = 0.0
            return float(pct)

        m = _PHASE_START_RE.match(message)
        if m:
            self._current_phase = int(m.group(1))
            self._total_phases = int(m.group(2))
            self._phase_units_total = max(int(m.group(3)), 1)
            self._phase_units_done = 0
            self._sub_fraction = 0.0
            return self._compute_fraction_percent()

        m = _PHASE_PROGRESS_RE.search(message)
        if m:
            self._current_phase = int(m.group(1))
            self._total_phases = int(m.group(2))
            self._phase_units_done = int(m.group(3))
            self._phase_units_total = max(int(m.group(4)), 1)
            self._sub_fraction = 0.0
            return self._compute_fraction_percent()

        m = _CHUNK_PROGRESS_RE.search(message)
        if m:
            current, total = int(m.group(1)), max(int(m.group(2)), 1)
            self._sub_fraction = current / total
            return self._compute_fraction_percent()

        if _CHUNK_START_RE.search(message):
            self._sub_fraction = 0.0
            return self._compute_fraction_percent()

        return None

    def _compute_fraction_percent(self) -> float:
        if self._current_phase <= 0 or self._total_phases <= 0:
            return 0.0
        unit_fraction = (self._phase_units_done + self._sub_fraction) / self._phase_units_total
        unit_fraction = min(max(unit_fraction, 0.0), 1.0)
        overall = ((self._current_phase - 1) + unit_fraction) / self._total_phases
        return min(max(overall * 100.0, 0.0), 100.0)
