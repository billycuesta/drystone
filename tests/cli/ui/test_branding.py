"""Tests for cli/ui/branding.py — color interpolation, print_banner, print_summary."""

from io import StringIO
from unittest.mock import MagicMock, patch

from rich.console import Console

from drystone.cli.ui.branding import _interpolate_color, print_banner, print_summary

# ── _interpolate_color ─────────────────────────────────────────────────────────


class TestInterpolateColor:
    def test_position_zero_returns_start_color(self):
        result = _interpolate_color(0.0, (100, 150, 200), (200, 50, 100))
        assert result == "rgb(100,150,200)"

    def test_position_one_returns_end_color(self):
        result = _interpolate_color(1.0, (100, 150, 200), (200, 50, 100))
        assert result == "rgb(200,50,100)"

    def test_position_half_interpolates_midpoint(self):
        result = _interpolate_color(0.5, (0, 0, 0), (200, 100, 50))
        assert result == "rgb(100,50,25)"

    def test_returns_rgb_format_string(self):
        result = _interpolate_color(0.0, (255, 165, 0), (180, 100, 220))
        assert result.startswith("rgb(")
        assert result.endswith(")")

    def test_same_start_end_always_same_color(self):
        color = (128, 64, 32)
        for pos in [0.0, 0.25, 0.5, 0.75, 1.0]:
            assert _interpolate_color(pos, color, color) == "rgb(128,64,32)"

    def test_integer_output(self):
        """Result values must be integers, not floats."""
        result = _interpolate_color(0.3, (0, 0, 0), (10, 10, 10))
        # Should be integer values: rgb(3,3,3)
        assert "." not in result

    def test_gradient_increases_monotonically(self):
        """R channel should increase from (0,0,0) to (255,0,0)."""
        r_values = []
        for i in range(6):
            color = _interpolate_color(i / 5, (0, 0, 0), (255, 0, 0))
            r = int(color.split("(")[1].split(",")[0])
            r_values.append(r)
        assert r_values == sorted(r_values)

    def test_midpoint_banner_color(self):
        """Smoke test with the actual banner colors used in print_banner."""
        start = (180, 100, 220)
        end = (255, 165, 0)
        result = _interpolate_color(0.5, start, end)
        assert result == "rgb(217,132,110)"


# ── print_banner ───────────────────────────────────────────────────────────────


class TestPrintBanner:
    def test_runs_without_error(self):
        """print_banner must not raise under any circumstance."""
        console = Console(file=StringIO(), force_terminal=True)
        with patch("drystone.cli.ui.branding.Console", return_value=console):
            print_banner()  # Should not raise

    def test_outputs_something(self):
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        with patch("drystone.cli.ui.branding.Console", return_value=console):
            print_banner()
        output = buf.getvalue()
        assert len(output) > 0

    def test_output_contains_drystone_text(self):
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        with patch("drystone.cli.ui.branding.Console", return_value=console):
            print_banner()
        output = buf.getvalue()
        # The banner contains "AWS Security Audit" or version string
        assert "v1.0.0" in output or "AWS" in output or "DRYSTONE" in output.upper()

    def test_console_print_called(self):
        """Console.print should be called at least twice (panel + blank line)."""
        mock_console = MagicMock()
        with patch("drystone.cli.ui.branding.Console", return_value=mock_console):
            print_banner()
        assert mock_console.print.call_count >= 2


# ── print_summary ──────────────────────────────────────────────────────────────


def _make_config(**overrides):
    """Build a minimal WizardConfig-like mock for print_summary."""
    config = MagicMock()
    config.client_name = overrides.get("client_name", "ACME Corp")
    config.aws_region = overrides.get("aws_region", "us-east-1")
    config.skills = overrides.get("skills", ["iam", "network"])
    config.output_formats = overrides.get("output_formats", ["markdown"])
    config.min_severity = overrides.get("min_severity", "medium")
    config.scan_depth = overrides.get("scan_depth", "normal")
    # Credential fields — default to direct credentials
    config.aws_access_key_id = overrides.get("aws_access_key_id", "AKIAIOSFODNN7EXAMPLE")
    config.aws_secret_access_key = overrides.get(
        "aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    config.aws_credentials_file = overrides.get("aws_credentials_file", None)
    config.aws_profile = overrides.get("aws_profile", None)
    return config


class TestPrintSummary:
    def _capture(self, config):
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        with patch("drystone.cli.ui.branding.Console", return_value=console):
            print_summary(config)
        return buf.getvalue()

    # ── client name ──────────────────────────────────────────────────────────

    def test_client_name_in_output(self):
        output = self._capture(_make_config(client_name="Contoso"))
        assert "Contoso" in output

    def test_region_in_output(self):
        output = self._capture(_make_config(aws_region="eu-west-1"))
        assert "eu-west-1" in output

    def test_skills_listed(self):
        output = self._capture(_make_config(skills=["iam", "waf"]))
        assert "iam" in output
        assert "waf" in output

    def test_output_formats_listed(self):
        output = self._capture(_make_config(output_formats=["html", "json"]))
        assert "html" in output
        assert "json" in output

    def test_min_severity_shown(self):
        output = self._capture(_make_config(min_severity="low"))
        assert "Low" in output

    # ── credential branches ───────────────────────────────────────────────────

    def test_direct_credentials_masked(self):
        config = _make_config(
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="supersecretkey12345",
            aws_credentials_file=None,
            aws_profile=None,
        )
        output = self._capture(config)
        # Raw key must NOT appear; masked prefix must appear
        assert "supersecretkey12345" not in output
        assert "AKIA" in output  # First 4 chars of key ID shown
        assert "Direct" in output

    def test_direct_credentials_secret_masked_with_stars(self):
        config = _make_config(
            aws_access_key_id="AKIATEST1234",
            aws_secret_access_key="mysecret",
            aws_credentials_file=None,
            aws_profile=None,
        )
        output = self._capture(config)
        assert "mysecret" not in output
        assert "*" in output

    def test_file_credentials_shows_path(self):
        config = _make_config(
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_credentials_file="/home/user/.aws/creds.json",
            aws_profile=None,
        )
        output = self._capture(config)
        assert "/home/user/.aws/creds.json" in output
        assert "File" in output

    def test_profile_credentials_shows_profile_name(self):
        config = _make_config(
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_credentials_file=None,
            aws_profile="prod-admin",
        )
        output = self._capture(config)
        assert "prod-admin" in output
        assert "Profile" in output

    def test_env_variable_fallback(self):
        config = _make_config(
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_credentials_file=None,
            aws_profile=None,
        )
        output = self._capture(config)
        assert "Environment" in output

    # ── scan_depth via getattr ────────────────────────────────────────────────

    def test_scan_depth_shown_capitalized(self):
        output = self._capture(_make_config(scan_depth="deep"))
        assert "Deep" in output

    def test_scan_depth_normal(self):
        output = self._capture(_make_config(scan_depth="normal"))
        assert "Normal" in output

    # ── console calls ─────────────────────────────────────────────────────────

    def test_console_print_called_multiple_times(self):
        mock_console = MagicMock()
        with patch("drystone.cli.ui.branding.Console", return_value=mock_console):
            print_summary(_make_config())
        assert mock_console.print.call_count >= 3  # blank + table + blank
