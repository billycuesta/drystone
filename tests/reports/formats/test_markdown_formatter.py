"""Tests for MarkdownFormatter pure-logic methods."""

from unittest.mock import Mock

from drystone.reports.formats.markdown import MarkdownFormatter
from drystone.storage.session import AuditSession

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_formatter(tmp_path, findings=None, report_language="en", report_type="general"):
    session = Mock(spec=AuditSession)
    session.base_path = tmp_path
    session.account_id = "123456789012"
    session.client_name = "TestClient"
    session.get_reports_path.return_value = tmp_path / "reports"
    session.get_findings_path.return_value = tmp_path / "findings"
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    (tmp_path / "findings").mkdir(parents=True, exist_ok=True)

    config = Mock()
    config.report_type = report_type
    config.report_language = report_language

    if findings is None:
        findings = {
            "skill": "iam",
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "overall_risk_score": 0.0,
            },
        }

    return MarkdownFormatter(findings, session, config)


# ── _is_english_report ────────────────────────────────────────────────────────


class TestIsEnglishReport:
    def test_en_is_english(self, tmp_path):
        f = _make_formatter(tmp_path, report_language="en")
        assert f._is_english_report() is True

    def test_en_uppercase_case_insensitive(self, tmp_path):
        f = _make_formatter(tmp_path, report_language="EN")
        assert f._is_english_report() is True

    def test_es_is_not_english(self, tmp_path):
        f = _make_formatter(tmp_path, report_language="es")
        assert f._is_english_report() is False

    def test_missing_attribute_defaults_to_en(self, tmp_path):
        f = _make_formatter(tmp_path)
        del f.config.report_language
        # getattr with default "en"
        assert f._is_english_report() is True


# ── _looks_spanish ─────────────────────────────────────────────────────────────


class TestLooksSpanish:
    def setup_method(self):
        pass

    def test_spanish_marker_sin(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish("bucket sin cifrado") is True

    def test_spanish_marker_con(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish("acceso con credenciales") is True

    def test_spanish_marker_hallazgos(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish("Hallazgos críticos encontrados") is True

    def test_english_text_false(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish("Root account without MFA enabled") is False

    def test_empty_string_false(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish("") is False

    def test_none_false(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish(None) is False

    def test_marker_debe(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish("La política debe ser actualizada") is True

    def test_marker_multiple(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._looks_spanish("Múltiples hallazgos detectados") is True


# ── _translate_to_english ─────────────────────────────────────────────────────


class TestTranslateToEnglish:
    def test_translates_multiple(self, tmp_path):
        f = _make_formatter(tmp_path)
        result = f._translate_to_english("Múltiples vulnerabilidades detectadas")
        assert "Multiple" in result
        assert "Múltiples" not in result

    def test_translates_hallazgos(self, tmp_path):
        f = _make_formatter(tmp_path)
        result = f._translate_to_english("Hallazgos duplicados encontrados")
        assert "Findings" in result or "findings" in result

    def test_translates_deshabilitado(self, tmp_path):
        f = _make_formatter(tmp_path)
        result = f._translate_to_english("Servicio deshabilitado")
        assert "disabled" in result

    def test_english_unchanged(self, tmp_path):
        f = _make_formatter(tmp_path)
        text = "Root account without MFA"
        assert f._translate_to_english(text) == text

    def test_none_handled(self, tmp_path):
        f = _make_formatter(tmp_path)
        result = f._translate_to_english(None)
        assert result == ""

    def test_translates_recursos(self, tmp_path):
        f = _make_formatter(tmp_path)
        result = f._translate_to_english("múltiples recursos afectados")
        assert "resources" in result


# ── _normalize_finding_language ────────────────────────────────────────────────


class TestNormalizeFindingLanguage:
    def test_english_report_translates_spanish_title(self, tmp_path):
        f = _make_formatter(tmp_path, report_language="en")
        finding = {
            "title": "Múltiples hallazgos detectados",
            "description": "desc",
            "remediation": "fix",
        }
        result = f._normalize_finding_language(finding)
        assert "Múltiples" not in result["title"]

    def test_non_english_report_skips_translation(self, tmp_path):
        f = _make_formatter(tmp_path, report_language="es")
        finding = {
            "title": "Múltiples hallazgos detectados",
            "description": "desc",
            "remediation": "fix",
        }
        result = f._normalize_finding_language(finding)
        assert result["title"] == "Múltiples hallazgos detectados"

    def test_english_title_unchanged(self, tmp_path):
        f = _make_formatter(tmp_path, report_language="en")
        finding = {"title": "Root MFA not enabled", "description": "desc", "remediation": "fix"}
        result = f._normalize_finding_language(finding)
        assert result["title"] == "Root MFA not enabled"

    def test_original_finding_not_mutated(self, tmp_path):
        f = _make_formatter(tmp_path, report_language="en")
        original = {"title": "Múltiples hallazgos", "description": "desc", "remediation": "fix"}
        f._normalize_finding_language(original)
        assert original["title"] == "Múltiples hallazgos"


# ── _get_skill_display_name ────────────────────────────────────────────────────


class TestGetSkillDisplayName:
    def test_known_skills(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._get_skill_display_name("iam") == "IAM"
        assert f._get_skill_display_name("waf") == "WAF"
        assert f._get_skill_display_name("ecr") == "ECR"
        assert f._get_skill_display_name("hardening") == "Hardening"
        assert f._get_skill_display_name("network") == "Network"

    def test_case_insensitive(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._get_skill_display_name("IAM") == "IAM"

    def test_unknown_skill_uppercased(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._get_skill_display_name("newskill") == "NEWSKILL"

    def test_sistemas_explotables_red(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert "Network" in f._get_skill_display_name("sistemas_explotables_red")


# ── _get_risk_level ────────────────────────────────────────────────────────────


class TestGetRiskLevel:
    def test_critical_threshold(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert "CRITICAL" in f._get_risk_level(8.5)
        assert "CRITICAL" in f._get_risk_level(10.0)

    def test_high_threshold(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert "HIGH" in f._get_risk_level(6.0)
        assert "HIGH" in f._get_risk_level(8.4)

    def test_medium_threshold(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert "MEDIUM" in f._get_risk_level(3.0)
        assert "MEDIUM" in f._get_risk_level(5.9)

    def test_low_threshold(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert "LOW" in f._get_risk_level(0.0)
        assert "LOW" in f._get_risk_level(2.9)

    def test_boundary_8_5_is_critical(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert "CRITICAL" in f._get_risk_level(8.5)

    def test_boundary_just_below_high(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert "MEDIUM" in f._get_risk_level(5.999)


# ── _natural_sort_key ──────────────────────────────────────────────────────────


class TestNaturalSortKey:
    def test_numeric_parts_sorted_numerically(self, tmp_path):
        f = _make_formatter(tmp_path)
        controls = ["10.1.1", "8.4.1", "7.2.1", "2.1.0"]
        sorted_controls = sorted(controls, key=f._natural_sort_key)
        assert sorted_controls == ["2.1.0", "7.2.1", "8.4.1", "10.1.1"]

    def test_string_parts_sorted_lexically(self, tmp_path):
        f = _make_formatter(tmp_path)
        key_a = f._natural_sort_key("abc")
        key_b = f._natural_sort_key("def")
        assert key_a < key_b

    def test_mixed_numeric_string(self, tmp_path):
        f = _make_formatter(tmp_path)
        k = f._natural_sort_key("IAM-001")
        assert isinstance(k, list)


# ── _extract_pci_controls_map ──────────────────────────────────────────────────


class TestExtractPciControlsMap:
    def test_single_finding_single_control(self, tmp_path):
        f = _make_formatter(tmp_path)
        findings = [{"id": "IAM-001", "pci_dss": [{"control": "8.4.1", "reason": "MFA"}]}]
        result = f._extract_pci_controls_map(findings)
        assert "8.4.1" in result
        assert len(result["8.4.1"]) == 1

    def test_multiple_findings_same_control(self, tmp_path):
        f = _make_formatter(tmp_path)
        findings = [
            {"id": "IAM-001", "pci_dss": [{"control": "8.4.1", "reason": "x"}]},
            {"id": "IAM-002", "pci_dss": [{"control": "8.4.1", "reason": "y"}]},
        ]
        result = f._extract_pci_controls_map(findings)
        assert len(result["8.4.1"]) == 2

    def test_finding_without_pci_dss_skipped(self, tmp_path):
        f = _make_formatter(tmp_path)
        findings = [{"id": "IAM-001", "pci_dss": []}]
        result = f._extract_pci_controls_map(findings)
        assert result == {}

    def test_empty_findings(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._extract_pci_controls_map([]) == {}

    def test_multiple_controls_per_finding(self, tmp_path):
        f = _make_formatter(tmp_path)
        findings = [
            {
                "id": "IAM-001",
                "pci_dss": [
                    {"control": "8.4.1", "reason": "MFA"},
                    {"control": "7.2.1", "reason": "Least privilege"},
                ],
            }
        ]
        result = f._extract_pci_controls_map(findings)
        assert "8.4.1" in result
        assert "7.2.1" in result


# ── _format_findings_count ─────────────────────────────────────────────────────


class TestFormatFindingsCount:
    def test_empty_returns_dash(self, tmp_path):
        f = _make_formatter(tmp_path)
        assert f._format_findings_count([]) == "-"

    def test_single_critical(self, tmp_path):
        f = _make_formatter(tmp_path)
        result = f._format_findings_count([{"severity": "Critical"}])
        assert "Critical" in result
        assert "1" in result

    def test_mixed_severities(self, tmp_path):
        f = _make_formatter(tmp_path)
        findings = [
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "High"},
            {"severity": "Medium"},
        ]
        result = f._format_findings_count(findings)
        assert "Critical" in result
        assert "High" in result

    def test_only_low(self, tmp_path):
        f = _make_formatter(tmp_path)
        result = f._format_findings_count([{"severity": "Low"}, {"severity": "Low"}])
        assert "Low" in result
        assert "2" in result

    def test_zero_severity_counts_hidden(self, tmp_path):
        """Severities with 0 count should not appear in output."""
        f = _make_formatter(tmp_path)
        result = f._format_findings_count([{"severity": "Critical"}])
        # High/Medium/Low counts should not appear
        assert "High" not in result
        assert "Medium" not in result


# ── _compute_assessment_rating ─────────────────────────────────────────────────


class TestComputeAssessmentRating:
    def test_no_findings_excellent(self, tmp_path):
        f = _make_formatter(tmp_path)
        icon, label, _ = f._compute_assessment_rating(0, 0, 0, 0, 0.0, 0)
        assert label == "Excellent"
        assert icon == "🟢"

    def test_low_risk_very_good(self, tmp_path):
        f = _make_formatter(tmp_path)
        icon, label, _ = f._compute_assessment_rating(0, 0, 2, 1, 3.0, 3)
        assert label == "Very Good"

    def test_one_high_good(self, tmp_path):
        f = _make_formatter(tmp_path)
        icon, label, _ = f._compute_assessment_rating(0, 1, 1, 0, 5.0, 2)
        assert label == "Good"

    def test_one_critical_needs_improvement(self, tmp_path):
        f = _make_formatter(tmp_path)
        icon, label, _ = f._compute_assessment_rating(1, 2, 1, 0, 7.0, 4)
        assert label == "Needs Improvement"

    def test_high_risk_immediate_attention(self, tmp_path):
        f = _make_formatter(tmp_path)
        icon, label, _ = f._compute_assessment_rating(3, 5, 2, 1, 9.5, 11)
        assert label == "Immediate Attention Required"
        assert icon == "🔴"

    def test_rating_returns_description(self, tmp_path):
        f = _make_formatter(tmp_path)
        _, _, description = f._compute_assessment_rating(0, 0, 0, 0, 0.0, 0)
        assert len(description) > 10


# ── _narrative_executive_summary branches ─────────────────────────────────────


class TestNarrativeExecutiveSummary:
    def _fmt(self, tmp_path, critical=0, high=0, medium=0, low=0, total=None, risk=0.0):
        if total is None:
            total = critical + high + medium + low
        findings = {
            "skill": "iam",
            "findings": [],
            "summary": {
                "total_findings": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "overall_risk_score": risk,
            },
        }
        return _make_formatter(tmp_path, findings=findings)

    def test_no_findings_text(self, tmp_path):
        f = self._fmt(tmp_path, total=0)
        result = f._narrative_executive_summary()
        assert "No security findings" in result

    def test_critical_and_high_text(self, tmp_path):
        f = self._fmt(tmp_path, critical=2, high=3, total=5)
        result = f._narrative_executive_summary()
        assert "critical" in result.lower()
        assert "high" in result.lower()
        assert "Immediate action" in result

    def test_critical_only_text(self, tmp_path):
        f = self._fmt(tmp_path, critical=1, total=1)
        result = f._narrative_executive_summary()
        assert "critical" in result.lower()
        assert "immediate" in result.lower()

    def test_high_only_text(self, tmp_path):
        f = self._fmt(tmp_path, high=2, total=2)
        result = f._narrative_executive_summary()
        assert "high" in result.lower()
        assert "promptly" in result.lower()

    def test_medium_only_text(self, tmp_path):
        f = self._fmt(tmp_path, medium=3, total=3)
        result = f._narrative_executive_summary()
        assert "medium" in result.lower() or "improvement" in result.lower()

    def test_low_only_text(self, tmp_path):
        f = self._fmt(tmp_path, low=2, total=2)
        result = f._narrative_executive_summary()
        assert "low" in result.lower()

    def test_contains_client_name(self, tmp_path):
        f = self._fmt(tmp_path, total=0)
        result = f._narrative_executive_summary()
        assert "TestClient" in result

    def test_contains_rating_icon(self, tmp_path):
        f = self._fmt(tmp_path, total=0)
        result = f._narrative_executive_summary()
        assert "🟢" in result or "🟡" in result or "🟠" in result or "🔴" in result

    def test_unknown_skill_uses_uppercase(self, tmp_path):
        findings = {
            "skill": "newskill",
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "overall_risk_score": 0.0,
            },
        }
        f = _make_formatter(tmp_path, findings=findings)
        result = f._narrative_executive_summary()
        assert "NEWSKILL" in result


# ── generate (file output) ────────────────────────────────────────────────────


class TestGenerate:
    def test_creates_markdown_file(self, tmp_path):
        f = _make_formatter(tmp_path)
        path = f.generate()
        assert path.exists()
        assert path.suffix == ".md"

    def test_file_contains_skill_name(self, tmp_path):
        f = _make_formatter(tmp_path)
        path = f.generate()
        assert "iam" in path.name

    def test_file_content_not_empty(self, tmp_path):
        f = _make_formatter(tmp_path)
        path = f.generate()
        assert len(path.read_text()) > 100

    def test_report_skill_slug_in_filename(self, tmp_path):
        findings = {
            "skill": "network",
            "findings": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "overall_risk_score": 0.0,
            },
        }
        f = _make_formatter(tmp_path, findings=findings)
        path = f.generate()
        assert "network" in path.name
