"""Tests for the PCI DSS evidence folder generator."""

import json
from pathlib import Path
from unittest.mock import patch

from drystone.core.audit_runner import _generate_pci_evidence_folder
from drystone.models import WizardConfig
from drystone.reports.pci_evidence_folder import (
    _EvidenceEntry,
    _filename,
    _slugify,
    generate_pci_evidence_folder,
)
from drystone.storage.session import AuditSession

# ── helpers ───────────────────────────────────────────────────────────────────


def make_session(tmp_path: Path, client_name="AcmeCorp") -> AuditSession:
    with (
        patch("drystone.storage.session.Path.cwd", return_value=tmp_path),
        patch("drystone.storage.session.setup_file_logging"),
    ):
        return AuditSession(client_name=client_name, account_id="123456789012")


def make_config(report_type="pci-dss", qsa_depth="standard") -> WizardConfig:
    return WizardConfig(
        client_name="AcmeCorp",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="us-east-1",
        skills=["iam"],
        output_formats=["markdown"],
        report_type=report_type,
        ai_provider="claude-cli",
        qsa_depth=qsa_depth,
    )


def write_evidence(session: AuditSession, files: dict) -> None:
    evidence_dir = session.get_evidence_path("iam")
    for name, content in files.items():
        (evidence_dir / name).write_text(
            content if isinstance(content, str) else json.dumps(content)
        )


def root_mfa_finding(**overrides) -> dict:
    finding = {
        "id": "IAM-001",
        "severity": "Critical",
        "risk_score": 9.5,
        "title": "Root account must have MFA enabled",
        "description": "The root account has no MFA device configured.",
        "impact": "An attacker with the root password gains unrestricted access.",
        "security_analogy": "Like leaving the master key in the vault door.",
        "remediation": "Enable a hardware MFA device on the root account.",
        "evidence_refs": ["evidence/iam/account-summary.json#/SummaryMap/AccountMFAEnabled"],
        "evidence_snippet": {"AccountMFAEnabled": 0},
        "affected_resources": ["arn:aws:iam::123456789012:root"],
        "exploitability_status": "validated",
        "pci_dss": [
            {"control": "8.4.1", "reason": "Finding-specific reason for 8.4.1."},
            {"control": "7.2.1", "reason": "Finding-specific reason for 7.2.1."},
        ],
    }
    finding.update(overrides)
    return finding


def generate(tmp_path, evidence, findings, **config_kwargs):
    session = make_session(tmp_path)
    write_evidence(session, evidence)
    all_findings = {"iam": {"findings": findings, "summary": {}}}
    out = generate_pci_evidence_folder(make_config(**config_kwargs), session, all_findings, ["iam"])
    return session, out


def read(out: Path, name: str) -> str:
    return (out / name).read_text()


ROOT_8_4_1 = "AcmeCorp_8.4.1_iam-001-root-account-must-have-mfa-enabled.md"
ROOT_7_2_1 = "AcmeCorp_7.2.1_iam-001-root-account-must-have-mfa-enabled.md"


# ── folder / fan-out ──────────────────────────────────────────────────────────


class TestFolder:
    def test_writes_into_session_pci_evidence_dir(self, tmp_path):
        session, out = generate(
            tmp_path, {"account-summary.json": {"SummaryMap": {"AccountMFAEnabled": 1}}}, []
        )
        assert out == session.base_path / "pci-evidence"
        assert out.is_dir()
        assert all(p.suffix == ".md" for p in out.iterdir())

    def test_multi_control_item_fans_out_to_one_file_per_control(self, tmp_path):
        _, out = generate(
            tmp_path, {"account-summary.json": {"SummaryMap": {"AccountMFAEnabled": 1}}}, []
        )
        iam_001 = sorted(p.name for p in out.glob("*_iam-001-*.md"))
        assert iam_001 == sorted([ROOT_8_4_1, ROOT_7_2_1])

    def test_every_mapped_checklist_item_produces_files(self, tmp_path):
        _, out = generate(tmp_path, {}, [], qsa_depth="deep")
        checklist = json.loads(
            (Path(__file__).resolve().parents[2] / "drystone/skills/iam/checklist.json").read_text()
        )
        expected = sum(
            len({p["control"] for p in item.get("pci_dss") or []}) for item in checklist["items"]
        )
        assert len(list(out.glob("*.md"))) == expected

    def test_qsa_depth_filters_items_like_analysis(self, tmp_path):
        _, deep = generate(tmp_path / "a", {}, [], qsa_depth="deep")
        _, obvious = generate(tmp_path / "b", {}, [], qsa_depth="obvious")
        assert 0 < len(list(obvious.glob("*.md"))) < len(list(deep.glob("*.md")))

    def test_sections_are_ordered_query_result_assessment(self, tmp_path):
        _, out = generate(
            tmp_path, {"account-summary.json": {"SummaryMap": {"AccountMFAEnabled": 1}}}, []
        )
        text = read(out, ROOT_8_4_1)
        assert text.index("## Query") < text.index("## Raw result") < text.index("## Assessment")


# ── Case A: PASS, no finding ──────────────────────────────────────────────────


class TestCasePass:
    def test_pass_file_content(self, tmp_path):
        _, out = generate(
            tmp_path, {"account-summary.json": {"SummaryMap": {"AccountMFAEnabled": 1}}}, []
        )
        text = read(out, ROOT_8_4_1)
        assert "# PCI DSS Control 8.4.1" in text
        assert "**Client:** AcmeCorp" in text
        assert "Identification & Authentication" in text
        assert "**Status:** PASS" in text
        assert "check_iam_001" in text
        assert "Root account MFA enabled?" in text
        assert "`account-summary.json`" in text
        assert "AccountMFAEnabled=1" in text
        # Checklist reason for this specific control, not the other one.
        assert "non-console administrative access" in text
        assert "job classification" not in text
        assert "Control requirement met based on automated evidence" in text

    def test_pass_via_credential_report_csv_hook(self, tmp_path):
        """IAM's _load_extra_evidence (credential-report.csv) must be mirrored."""
        csv = "user,arn,mfa_active\n<root_account>,arn:aws:iam::123456789012:root,true\n"
        _, out = generate(tmp_path, {"credential-report.csv": csv}, [])
        text = read(out, ROOT_8_4_1)
        assert "**Status:** PASS" in text
        assert "credential-report.mfa_active=true" in text


# ── Case B: FAIL ──────────────────────────────────────────────────────────────


class TestCaseFail:
    def test_fail_uses_finding_narrative_and_snippet(self, tmp_path):
        evidence = {"account-summary.json": {"SummaryMap": {"AccountMFAEnabled": 0}}}
        _, out = generate(tmp_path, evidence, [root_mfa_finding()])
        text = read(out, ROOT_8_4_1)
        assert "**Status:** FAIL" in text
        assert "evidence/iam/account-summary.json#/SummaryMap/AccountMFAEnabled" in text
        assert '```json\n{\n  "AccountMFAEnabled": 0\n}\n```' in text
        assert "The root account has no MFA device configured." in text
        assert "An attacker with the root password" in text
        assert "master key in the vault door" in text
        assert "Enable a hardware MFA device" in text
        assert "Control requirement not met" in text

    def test_fail_picks_finding_reason_for_this_control(self, tmp_path):
        _, out = generate(tmp_path, {}, [root_mfa_finding()])
        assert "Finding-specific reason for 8.4.1." in read(out, ROOT_8_4_1)
        assert "Finding-specific reason for 7.2.1." not in read(out, ROOT_8_4_1)
        assert "Finding-specific reason for 7.2.1." in read(out, ROOT_7_2_1)

    def test_fail_falls_back_to_checklist_reason(self, tmp_path):
        _, out = generate(tmp_path, {}, [root_mfa_finding(pci_dss=[])])
        assert "non-console administrative access" in read(out, ROOT_8_4_1)

    def test_finding_overrides_passing_pre_check(self, tmp_path):
        evidence = {"account-summary.json": {"SummaryMap": {"AccountMFAEnabled": 1}}}
        _, out = generate(tmp_path, evidence, [root_mfa_finding()])
        assert "**Status:** FAIL" in read(out, ROOT_8_4_1)

    def test_theoretical_finding_without_snippet_falls_back(self, tmp_path):
        finding = root_mfa_finding(
            evidence_snippet=None, evidence_refs=[], exploitability_status="theoretical"
        )
        _, out = generate(tmp_path, {}, [finding])
        text = read(out, ROOT_8_4_1)
        assert "No raw evidence snippet captured -- theoretical finding." in text
        assert "arn:aws:iam::123456789012:root" in text
        assert "```json" not in text

    def test_pre_check_fail_without_finding_still_reported_as_fail(self, tmp_path):
        evidence = {"account-summary.json": {"SummaryMap": {"AccountMFAEnabled": 0}}}
        _, out = generate(tmp_path, evidence, [])
        text = read(out, ROOT_8_4_1)
        assert "**Status:** FAIL" in text
        assert "AccountMFAEnabled=0" in text

    def test_snippet_with_backticks_does_not_break_fence(self, tmp_path):
        finding = root_mfa_finding(evidence_snippet={"note": "```injected```"})
        _, out = generate(tmp_path, {}, [finding])
        assert "````json" in read(out, ROOT_8_4_1)


# ── Case C: SKIP / no verdict ─────────────────────────────────────────────────


class TestCaseInconclusive:
    def test_skip_is_inconclusive_not_omitted(self, tmp_path):
        _, out = generate(tmp_path, {}, [])
        files = list(out.glob("AcmeCorp_8.4.2_iam-002-*.md"))
        assert len(files) == 1
        text = files[0].read_text()
        assert "**Status:** INCONCLUSIVE" in text
        assert "no verdict was reached (SKIP)" in text
        assert "no users evidence" in text
        assert "Manual QSA review recommended." in text
        assert "Control requirement met" not in text

    def test_item_without_pre_check_or_finding_is_inconclusive(self, tmp_path):
        _, out = generate(tmp_path, {}, [])
        files = list(out.glob("AcmeCorp_8.2.6_iam-003-*.md"))
        assert len(files) == 1
        text = files[0].read_text()
        assert "**Status:** INCONCLUSIVE" in text
        assert "No deterministic pre-check exists" in text


# ── filenames ─────────────────────────────────────────────────────────────────


def _entry(control="8.4.1", item_id="IAM-001", title="Root account must have MFA enabled"):
    return _EvidenceEntry(
        skill_name="iam",
        item={"id": item_id, "title": title},
        control=control,
        reason="",
        status="PASS",
        pre_check=None,
        finding=None,
    )


class TestFilenames:
    def test_convention(self):
        assert _filename("AcmeCorp", _entry(), set()) == ROOT_8_4_1

    def test_client_name_is_sanitized(self):
        name = _filename("Acme Corp/../x", _entry(), set())
        assert "/" not in name and ".." not in name and " " not in name
        assert name.endswith("_8.4.1_iam-001-root-account-must-have-mfa-enabled.md")

    def test_control_and_title_are_sanitized(self):
        name = _filename("Acme", _entry(control="../8.4.1", title="Évil `title`/../*?"), set())
        assert "/" not in name and ".." not in name
        assert name == "Acme_8.4.1_iam-001-vil-title.md"

    def test_collision_gets_numeric_suffix(self):
        used: set = set()
        first = _filename("Acme", _entry(), used)
        second = _filename("Acme", _entry(), used)
        assert first != second
        assert second.endswith("-2.md")

    def test_slugify_truncates_on_word_boundary(self):
        slug = _slugify("word " * 40, max_len=20)
        assert len(slug) <= 20
        assert not slug.endswith("-")


# ── pipeline phase gating ─────────────────────────────────────────────────────


class TestPhaseGating:
    def test_no_op_when_report_type_is_not_pci_dss(self, tmp_path):
        session = make_session(tmp_path)
        messages = []
        _generate_pci_evidence_folder(
            make_config(report_type="general"), session, {"iam": {"findings": []}}, messages.append
        )
        assert not (session.base_path / "pci-evidence").exists()
        assert messages == []

    def test_generates_when_report_type_is_pci_dss(self, tmp_path):
        session = make_session(tmp_path)
        messages = []
        _generate_pci_evidence_folder(
            make_config(report_type="pci-dss"), session, {"iam": {"findings": []}}, messages.append
        )
        assert any((session.base_path / "pci-evidence").glob("*.md"))
        assert any("PCI DSS evidence folder" in m for m in messages)
