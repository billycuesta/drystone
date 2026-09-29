"""Tests for the PCI DSS evidence folder P1 output contract."""

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

from drystone.core.audit_runner import _generate_pci_evidence_folder
from drystone.models import WizardConfig
from drystone.reports.pci_evidence_folder import (
    _EvidenceEntry,
    _filename,
    _short_description,
    generate_pci_evidence_folder,
)
from drystone.validation.pre_checks import PreCheckResult
from drystone.storage.session import AuditSession

FIXTURES = Path(__file__).parent / "fixtures" / "pci_cli" / "iam"


def make_session(tmp_path: Path, client_name: str = "Acme Corp") -> AuditSession:
    with (
        patch("drystone.storage.session.Path.cwd", return_value=tmp_path),
        patch("drystone.storage.session.setup_file_logging"),
    ):
        return AuditSession(client_name=client_name, account_id="123456789012")


def make_config(report_type: str = "pci-dss", qsa_depth: str = "standard", **overrides: Any) -> WizardConfig:
    values: dict[str, Any] = {
        "client_name": "Acme Corp",
        "project_id": "AEA2026",
        "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_region": "us-east-1",
        "skills": ["iam"],
        "output_formats": ["markdown"],
        "report_type": report_type,
        "ai_provider": "claude-cli",
        "qsa_depth": qsa_depth,
    }
    values.update(overrides)
    return WizardConfig(**values)


def copy_iam_fixtures(session: AuditSession, *names: str) -> None:
    evidence_dir = session.get_evidence_path("iam")
    for name in names:
        shutil.copyfile(FIXTURES / name, evidence_dir / name)


def generate(tmp_path: Path, fixture_names: tuple[str, ...], findings: list[dict] | None = None, **config_kwargs):
    session = make_session(tmp_path)
    copy_iam_fixtures(session, *fixture_names)
    all_findings = {"iam": {"findings": findings or [], "summary": {}}}
    out = generate_pci_evidence_folder(make_config(**config_kwargs), session, all_findings, ["iam"])
    return session, out


def read(out: Path, name: str) -> str:
    return (out / name).read_text(encoding="utf-8")


def entry(control: str = "8.4.1", item_id: str = "IAM-999", title: str = "Évidence name") -> _EvidenceEntry:
    return _EvidenceEntry(
        skill_name="iam",
        item={"id": item_id, "title": title},
        control=control,
        reason="",
        status="PASS",
        pre_check=None,
        finding=None,
        consulted_stems=(),
        evidence={},
        region="us-east-1",
        captured_at="2026-01-01",
    )


def test_d7_renders_only_query_output_and_evidence_description_labels(tmp_path):
    _, out = generate(tmp_path, ("account-summary.json",))

    text = read(out, "AEA2026_8.4.1_Root account MFA.md")

    assert text.startswith("Query:\n```bash\naws iam get-account-summary")
    assert "\n\nOutput:\n```\nKey" in text
    assert "\n\nEvidence description:\n```\nPCI DSS 8.4.1 evidence" in text
    assert "## Query" not in text
    assert "## Raw result" not in text
    assert "## Assessment" not in text


def test_d6_fail_evidence_description_excludes_remediation_text(tmp_path):
    finding = {
        "id": "IAM-001",
        "title": "Root account MFA missing",
        "description": "Root account lacks MFA.",
        "severity": "Critical",
        "pci_dss": [{"control": "8.4.1", "reason": "Finding-specific PCI reason."}],
        "remediation": "Enable MFA on the root account immediately.",
    }

    _, out = generate(tmp_path, ("account-summary.json",), findings=[finding])

    text = read(out, "AEA2026_8.4.1_Root account MFA.md")
    assert "Evidence description:" in text
    assert "PCI DSS 8.4.1 evidence for IAM-001 (Root account must have MFA enabled) is fail" in text
    assert "Finding-specific PCI reason." in text
    assert "Root account lacks MFA." not in text
    assert "Enable MFA on the root account immediately." not in text
    assert "Remediation:" not in text


def test_filename_uses_project_id_and_qsa_readable_evidence_name_spaces(tmp_path):
    _, out = generate(tmp_path, ("account-summary.json",))

    assert (out / "AEA2026_8.4.1_Root account MFA.md").exists()


def test_filename_collision_gets_parenthesized_numeric_suffix():
    used: set[str] = set()

    first = _filename("AEA2026", entry(title="Same Evidence"), used)
    second = _filename("AEA2026", entry(title="Same Evidence"), used)

    assert first == "AEA2026_8.4.1_Same Evidence.md"
    assert second == "AEA2026_8.4.1_Same Evidence (2).md"


def test_filename_sanitizes_accents_punctuation_and_preserves_spaces():
    name = _filename("Ácme 2026/../x", entry(control="../8.4.1", title="Raíz inválida / MFA *"), set())

    assert name == "Acme 2026.x_8.4.1_Raiz invalida MFA.md"
    assert "/" not in name
    assert ".." not in name


def test_d2_consulted_stems_let_iam_002_render_credential_report_table(tmp_path):
    _, out = generate(tmp_path, ("users.json", "credential-report.csv"))

    text = read(out, "AEA2026_8.4.2_IAM users MFA.md")

    assert "aws iam get-credential-report" in text
    assert "user" in text and "password_enabled" in text and "access_key_2_active" in text
    assert "alice" in text and "true              true        false                false" in text
    assert "IAM users MFA" in out.joinpath("AEA2026_8.4.2_IAM users MFA.md").name


def test_warn_precheck_renders_inconclusive_with_collection_gap_reason():
    warn = PreCheckResult(
        "IAM-999",
        "WARN",
        "users evidence missing",
        metadata={"reason_code": "missing_evidence"},
    )
    evidence_entry = entry()
    evidence_entry.status = "INCONCLUSIVE"
    evidence_entry.pre_check = warn

    description = _short_description(evidence_entry, "2026-01-01T00:00:00Z", None)

    assert "is inconclusive" in description
    assert "collection gap" in description
    assert "missing_evidence" in description
    assert "insufficient" in description


def test_d5_placeholder_is_written_for_unmapped_non_iam_skill_check(tmp_path, monkeypatch):
    def fake_checklist(skill_name: str, qsa_depth: str) -> dict:
        assert skill_name == "fake"
        assert qsa_depth == "standard"
        return {
            "items": [
                {
                    "id": "FAKE-001",
                    "title": "Unmapped fake check",
                    "evidence_files": ["fake-source.json"],
                    "pci_dss": [{"control": "1.2.3", "reason": "Fake PCI reason."}],
                }
            ]
        }

    session = make_session(tmp_path)
    monkeypatch.setattr("drystone.reports.pci_evidence_folder._load_checklist", fake_checklist)

    out = generate_pci_evidence_folder(
        make_config(project_id="FAKE2026"),
        session,
        {"fake": {"findings": [], "summary": {}}},
        ["fake"],
    )

    text = read(out, "FAKE2026_1.2.3_Unmapped fake check.md")
    assert "# No AWS CLI equivalent catalogued yet for FAKE-001 (evidence consulted: fake-source)" in text
    assert "Evidence collected during this audit was insufficient" in text


def test_phase_gating_is_noop_for_non_pci_report_type(tmp_path):
    session = make_session(tmp_path)
    messages: list[str] = []

    _generate_pci_evidence_folder(
        make_config(report_type="general"),
        session,
        {"iam": {"findings": []}},
        messages.append,
    )

    assert not (session.base_path / "pci-evidence").exists()
    assert messages == []
