"""RPT-J: cross-format parity test matrix.

Documents field-by-field parity across Markdown, PDF, JSON, and Pentest
report formatters for six report-level fields: report format version,
evidence integrity manifest, multi-run trend, cross-skill correlation,
active (unauthenticated) verification, and basic metadata.

Known gaps are asserted explicitly as CURRENT ABSENCE, not skipped --
fixing one (see the referenced roadmap rec) must break the matching
assertion here, so drift is caught instead of silently accepted forever.
"""

import json
import sys
import types
from unittest.mock import Mock

import pytest

from drystone.reports.formats.json import JSONFormatter
from drystone.reports.formats.markdown import MarkdownFormatter
from drystone.reports.formats.pdf import PDFFormatter
from drystone.reports.formats.pentest import PentestFormatter
from drystone.reports.formats.pentest_pdf import PentestPDFFormatter
from drystone.storage.session import AuditSession

INTEGRITY_HASH = "a" * 64


def _mock_session(tmp_path):
    session = Mock(spec=AuditSession)
    session.base_path = tmp_path
    session.account_id = "123456789012"
    session.client_name = "Acme"
    session.get_reports_path.return_value = tmp_path / "reports"
    session.get_findings_path.return_value = tmp_path / "findings"
    session.get_evidence_path.return_value = tmp_path / "evidence"
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    (tmp_path / "findings").mkdir(parents=True, exist_ok=True)
    (tmp_path / "evidence").mkdir(parents=True, exist_ok=True)
    return session


def _write_sidecars(tmp_path):
    (tmp_path / "findings").mkdir(parents=True, exist_ok=True)
    (tmp_path / "findings" / "trend.json").write_text(
        json.dumps(
            {
                "previous_session": "2026-08-01T00:00:00",
                "skills": [
                    {
                        "skill": "iam",
                        "new": [],
                        "fixed": [{"id": "IAM-002", "title": "Old finding fixed"}],
                        "persisting_count": 0,
                    }
                ],
            }
        )
    )
    (tmp_path / "findings" / "correlated.json").write_text(
        json.dumps(
            {
                "total_correlations": 1,
                "correlations": [
                    {
                        "id": "CORR-001",
                        "title": "Public bucket reachable via over-privileged role",
                        "severity": "Critical",
                        "attack_path": ["IAM-001", "EXPO-001"],
                        "active_verification": {
                            "method": "s3_unauthenticated_head_bucket",
                            "target": "public-bucket",
                            "attempted": True,
                            "result": "success",
                            "detail": "HEAD succeeded",
                            "timestamp": "2026-09-18T10:00:00+00:00",
                        },
                    }
                ],
            }
        )
    )


def _sample_findings():
    return {
        "skill": "iam",
        "analyzed_at": "2026-09-18T10:00:00",
        "report_metadata": {"integrity_manifest_sha256": INTEGRITY_HASH},
        "summary": {
            "total_findings": 1,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk_score": 9.0,
        },
        "findings": [
            {
                "id": "IAM-001",
                "severity": "Critical",
                "risk_score": 9.0,
                "title": "Root key active",
                "description": "Root account has active access keys.",
                "remediation": "Disable root access keys and enable MFA.",
                "affected_resources": ["arn:aws:iam::123456789012:root"],
                "active_verification": {
                    "method": "sts_assume_role",
                    "target": "arn:aws:iam::123456789012:role/Admin",
                    "attempted": True,
                    "result": "denied",
                    "detail": "AccessDenied",
                    "timestamp": "2026-09-18T10:01:00+00:00",
                },
            }
        ],
    }


def _config():
    config = Mock()
    config.aws_region = "us-east-1"
    config.min_severity = "low"
    config.report_type = "general"
    config.report_language = "en"
    config.skills = ["iam"]
    return config


def _render_html(formatter, monkeypatch):
    """Capture the HTML weasyprint would have received, without needing it installed."""
    captured = {}

    class FakeHTML:
        def __init__(self, string):
            captured["html"] = string

        def write_pdf(self, output_path):
            with open(output_path, "wb") as f:
                f.write(b"%PDF-1.4 test")

    fake_module = types.SimpleNamespace(HTML=FakeHTML)
    monkeypatch.setitem(sys.modules, "weasyprint", fake_module)
    formatter.generate()
    return captured["html"]


class TestReportFormatVersionParity:
    """All 4 report families stamp their own REPORT_FORMAT_VERSION. Full parity."""

    def test_markdown(self, tmp_path):
        formatter = MarkdownFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert formatter.REPORT_FORMAT_VERSION in formatter.generate().read_text()

    def test_json(self, tmp_path):
        formatter = JSONFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        payload = json.loads(formatter.generate().read_text())
        assert payload["metadata"]["report_format_version"] == formatter.REPORT_FORMAT_VERSION

    def test_pentest_markdown(self, tmp_path):
        formatter = PentestFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert formatter.REPORT_FORMAT_VERSION in formatter.generate().read_text()

    def test_pdf(self, tmp_path, monkeypatch):
        formatter = PDFFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert formatter.REPORT_FORMAT_VERSION in _render_html(formatter, monkeypatch)

    def test_pentest_pdf(self, tmp_path, monkeypatch):
        formatter = PentestPDFFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert formatter.REPORT_FORMAT_VERSION in _render_html(formatter, monkeypatch)


class TestIntegrityManifestParity:
    """Markdown/PDF/JSON render the evidence integrity hash. Pentest Markdown
    does not -- current gap, tracked as RPT-O (no dedicated rec existed for
    this before RPT-J's parity sweep)."""

    def test_markdown_renders_integrity_hash(self, tmp_path):
        formatter = MarkdownFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert INTEGRITY_HASH in formatter.generate().read_text()

    def test_json_includes_integrity_hash(self, tmp_path):
        formatter = JSONFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        payload = json.loads(formatter.generate().read_text())
        assert payload["metadata"]["integrity_manifest_sha256"] == INTEGRITY_HASH

    def test_pdf_renders_integrity_hash(self, tmp_path, monkeypatch):
        formatter = PDFFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert INTEGRITY_HASH in _render_html(formatter, monkeypatch)

    def test_pentest_markdown_does_not_render_integrity_hash_known_gap(self, tmp_path):
        """RPT-O: pentest.py has no equivalent of markdown.py's integrity row."""
        formatter = PentestFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert INTEGRITY_HASH not in formatter.generate().read_text()


class TestTrendParity:
    """Markdown and JSON render multi-run trend data; PDF/Pentest do not.
    Tracked as RPT-F (pre-existing rec, not fixed here)."""

    def test_markdown_renders_trend(self, tmp_path):
        _write_sidecars(tmp_path)
        formatter = MarkdownFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        text = formatter.generate().read_text()
        assert "Trend Since Last Audit" in text

    def test_json_includes_trend(self, tmp_path):
        _write_sidecars(tmp_path)
        formatter = JSONFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        payload = json.loads(formatter.generate().read_text())
        assert payload["trend"]["previous_session"] == "2026-08-01T00:00:00"

    def test_pdf_has_no_trend_section_known_gap(self, tmp_path, monkeypatch):
        """RPT-F: PDFFormatter has no equivalent of markdown.py's _trend_section()."""
        assert not hasattr(PDFFormatter, "_trend_section")

    def test_pentest_markdown_has_no_trend_section_known_gap(self):
        """RPT-F: PentestFormatter has no equivalent of markdown.py's _trend_section()."""
        assert not hasattr(PentestFormatter, "_trend_section")


class TestCorrelationParity:
    """Markdown/PDF/Pentest render the actual correlation chain narrative.
    JSON is asymmetric by design: `correlation_summary` only carries
    truncation metadata (total_correlations/truncated/warnings), not the
    chains themselves -- `correlated.json` is a separate sidecar file, not
    part of `self.findings`, so it never enters `redacted_findings` either."""

    def test_markdown_renders_correlation(self, tmp_path):
        _write_sidecars(tmp_path)
        formatter = MarkdownFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        text = formatter.generate().read_text()
        assert "Public bucket reachable via over-privileged role" in text

    def test_json_correlation_summary_is_truncation_metadata_only(self, tmp_path):
        _write_sidecars(tmp_path)
        formatter = JSONFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        payload = json.loads(formatter.generate().read_text())
        assert payload["correlation_summary"]["total_correlations"] == 1
        assert "Public bucket reachable via over-privileged role" not in json.dumps(payload)

    def test_pentest_markdown_renders_correlation(self, tmp_path):
        _write_sidecars(tmp_path)
        formatter = PentestFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        text = formatter.generate().read_text()
        assert "IAM-001" in text and "EXPO-001" in text

    def test_pdf_renders_correlation(self, tmp_path, monkeypatch):
        _write_sidecars(tmp_path)
        formatter = PDFFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        html = _render_html(formatter, monkeypatch)
        assert "Public bucket reachable via over-privileged role" in html


class TestActiveVerificationParity:
    """PDF/Pentest PDF/Pentest Markdown/JSON render active_verification results.
    General Markdown does not -- current gap, tracked as RPT-P (RPT-E's fix
    was scoped to PDF/Pentest PDF only; general Markdown was never asked for)."""

    def test_pdf_renders_active_verification(self, tmp_path, monkeypatch):
        formatter = PDFFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        html = _render_html(formatter, monkeypatch)
        assert "sts_assume_role" in html

    def test_pentest_markdown_renders_active_verification(self, tmp_path):
        formatter = PentestFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        text = formatter.generate().read_text()
        assert "sts_assume_role" in text

    def test_json_includes_active_verification(self, tmp_path):
        formatter = JSONFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        payload = json.loads(formatter.generate().read_text())
        assert payload["findings"][0]["active_verification"]["method"] == "sts_assume_role"

    def test_markdown_does_not_render_active_verification_known_gap(self, tmp_path):
        """RPT-P: MarkdownFormatter has no equivalent of pdf.py's/pentest.py's
        active_verification rendering."""
        formatter = MarkdownFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        text = formatter.generate().read_text()
        assert "sts_assume_role" not in text


class TestMetadataParity:
    """All 4 report families expose client/account/skill identifying metadata."""

    @pytest.mark.parametrize(
        "formatter_cls,render",
        [
            (MarkdownFormatter, lambda f: f.generate().read_text()),
            (PentestFormatter, lambda f: f.generate().read_text()),
        ],
    )
    def test_markdown_family_renders_account_id(self, tmp_path, formatter_cls, render):
        formatter = formatter_cls(_sample_findings(), _mock_session(tmp_path), _config())
        assert "123456789012" in render(formatter)

    def test_json_includes_account_id(self, tmp_path):
        formatter = JSONFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        payload = json.loads(formatter.generate().read_text())
        assert payload["metadata"]["aws_account"] == "123456789012"

    def test_pdf_renders_account_id(self, tmp_path, monkeypatch):
        formatter = PDFFormatter(_sample_findings(), _mock_session(tmp_path), _config())
        assert "123456789012" in _render_html(formatter, monkeypatch)
