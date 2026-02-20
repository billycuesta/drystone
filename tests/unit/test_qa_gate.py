from pathlib import Path

from drystone.validation.qa_gate import run_qa_gate


def test_qa_gate_detects_missing_critical_and_placeholders(tmp_path: Path):
    (tmp_path / "reports").mkdir(parents=True)
    (tmp_path / "audit.log").write_text(
        "2026-01-01 - x - WARNING - Missing Critical check: ECR-001\n"
    )
    (tmp_path / "reports" / "audit-report-ecr.md").write_text(
        "Observations about positive security controls will be listed here."
    )

    result = run_qa_gate(tmp_path, ["ecr"])
    assert result.passed is False
    assert any("Missing critical checks" in i for i in result.issues)
    assert any("Placeholder text" in i for i in result.issues)


def test_qa_gate_passes_for_clean_session(tmp_path: Path):
    (tmp_path / "reports").mkdir(parents=True)
    (tmp_path / "audit.log").write_text("all good")
    (tmp_path / "reports" / "audit-report-ecr.md").write_text("No placeholder content.")

    result = run_qa_gate(tmp_path, ["ecr"])
    assert result.passed is True
