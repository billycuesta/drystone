"""Tests for LiveProgressReporter — the audit's live bar + status line."""

import logging

from drystone.cli.ui.live_progress import LiveProgressReporter

# ── Non-terminal fallback: exact prior click.echo behavior ────────────────────


class TestNonTerminalFallback:
    def test_prints_every_message_as_its_own_line(self, capsys):
        reporter = LiveProgressReporter(force_terminal=False)
        with reporter:
            reporter("📁 Creating audit session...")
            reporter("   Session: /tmp/audit-logs/acme_2026-09-18")

        out = capsys.readouterr().out
        assert "📁 Creating audit session..." in out
        assert "   Session: /tmp/audit-logs/acme_2026-09-18" in out

    def test_no_live_display_started(self):
        reporter = LiveProgressReporter(force_terminal=False)
        with reporter:
            assert reporter._live is None


# ── Message logging (dual-sink: always logged, regardless of terminal) ────────


class TestLogging:
    def test_non_empty_message_logged_to_drystone_logger(self, caplog):
        reporter = LiveProgressReporter(force_terminal=False)
        with caplog.at_level(logging.INFO, logger="drystone"):
            with reporter:
                reporter("🔍 Executing IAM Security Audit...")
        assert "🔍 Executing IAM Security Audit..." in caplog.text

    def test_empty_message_not_logged(self, caplog):
        reporter = LiveProgressReporter(force_terminal=False)
        with caplog.at_level(logging.INFO, logger="drystone"):
            with reporter:
                reporter("")
        assert caplog.text == ""


# ── Terminal mode: live bar + status line ──────────────────────────────────────


class TestTerminalMode:
    def test_live_display_started_and_stopped(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            assert reporter._live is not None
        assert reporter._live is None

    def test_status_message_updates_to_latest_message(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔍 Executing IAM Security Audit...")
            assert reporter._status_message == "🔍 Executing IAM Security Audit..."
            reporter("  Collecting IAM users...")
            assert reporter._status_message == "Collecting IAM users..."

    def test_blank_message_does_not_clear_status_message(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔍 Executing IAM Security Audit...")
            reporter("")
            assert reporter._status_message == "🔍 Executing IAM Security Audit..."

    def test_message_rendered_through_live_not_plain_echo(self, capsys):
        """In terminal mode, messages go through the Live region (ANSI-styled
        redraws), never the bare click.echo() fallback line."""
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔍 Executing IAM Security Audit...")
        out = capsys.readouterr().out
        # Live's cursor-hide sequence only appears when rendering interactively.
        assert "\x1b[?25l" in out
        assert "🔍 Executing IAM Security Audit..." in out


class TestPercentParsing:
    def test_overall_progress_marker_snaps_to_exact_percent(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("📊 Progress: 1/3 phases (33%) - Collection complete")
            assert reporter._percent == 33.0

    def test_phase_start_message_sets_zero_percent_for_that_phase(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔄 Phase 2/3 Analysis: 0/1 skills")
            # Phase 2 of 3 just started -> exactly 1/3 of the way through.
            assert round(reporter._percent) == round(100 / 3)

    def test_phase_start_updates_step_counter(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔄 Phase 2/3 Analysis: 0/1 skills")
            assert reporter._current_phase == 2
            assert reporter._total_phases == 3

    def test_phase_progress_advances_within_phase(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔄 Phase 1/3 Collection: 0/2 skills")
            first = reporter._percent
            reporter("   Phase 1/3 progress: 1/2")
            second = reporter._percent
            assert second > first

    def test_chunk_progress_advances_within_a_phase_unit(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔄 Phase 2/3 Analysis: 0/1 skills")
            reporter("   📦 IAM: chunking started (0/7)")
            before = reporter._percent
            reporter("   📦 IAM: chunks 3/7")
            after = reporter._percent
            assert after > before

    def test_unrecognized_message_does_not_change_percent(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("📊 Progress: 1/3 phases (33%) - Collection complete")
            before = reporter._percent
            reporter("  Collecting password policy...")
            after = reporter._percent
            assert after == before


class TestRendering:
    def test_render_shows_bracketed_bar_and_percent(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("📊 Progress: 1/3 phases (60%) - Collection complete")
            _, bar_line = reporter._render().renderables
        assert bar_line.plain.startswith("[") and "]" in bar_line.plain
        assert "60%" in bar_line.plain

    def test_render_bar_fill_width_matches_percent(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("📊 Progress: 1/3 phases (50%) - Collection complete")
            _, bar_line = reporter._render().renderables
            width = reporter._bar_width()
        assert bar_line.plain.count("█") == round(width * 0.5)

    def test_render_step_line_shows_phase_counter_and_status(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("🔄 Phase 2/3 Analysis: 0/1 skills")
            step_line, _ = reporter._render().renderables
            assert step_line.plain == "[2/3] 🔄 Phase 2/3 Analysis: 0/1 skills"


class TestCompletionHandoff:
    def test_completion_marker_stops_live_and_prints_summary_as_plain_lines(self, capsys):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("📊 Progress: 2/3 phases (66%) - Analysis complete")
            assert reporter._live is not None

            reporter("\n✅ Audit Complete")
            assert reporter._live is None

            reporter("   Audit data: /tmp/audit-logs/acme_2026-09-18")

        out = capsys.readouterr().out
        assert "Audit Complete" in out
        assert "Audit data: /tmp/audit-logs/acme_2026-09-18" in out

    def test_completion_snaps_bar_to_100_percent(self):
        reporter = LiveProgressReporter(force_terminal=True)
        with reporter:
            reporter("📊 Progress: 2/3 phases (66%) - Analysis complete")
            reporter("\n✅ Audit Complete")
        assert reporter._percent == 100.0
