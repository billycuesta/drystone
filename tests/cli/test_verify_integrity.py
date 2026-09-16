"""Tests for the `drystone verify-integrity` command (P0 #2 chain-of-custody)."""

import json

import pytest
from click.testing import CliRunner

from drystone.cli.main import cli
from drystone.storage.manifest import write_manifest


@pytest.fixture
def runner():
    return CliRunner()


def _make_session_tree(base_path):
    evidence_dir = base_path / "evidence" / "iam"
    evidence_dir.mkdir(parents=True)
    (base_path / "findings").mkdir(parents=True)
    (evidence_dir / "users.json").write_text(json.dumps({"users": ["alice"]}))
    return evidence_dir


def test_verify_integrity_passes_when_untampered(runner, tmp_path):
    _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    result = runner.invoke(cli, ["verify-integrity", str(tmp_path)])

    assert result.exit_code == 0
    assert "Integrity verified" in result.output


def test_verify_integrity_fails_when_tampered(runner, tmp_path):
    evidence_dir = _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    (evidence_dir / "users.json").write_text(json.dumps({"users": ["alice", "mallory"]}))

    result = runner.invoke(cli, ["verify-integrity", str(tmp_path)])

    assert result.exit_code == 1
    assert "modified since the audit ran" in result.output
    assert "evidence/iam/users.json" in result.output


def test_verify_integrity_fails_when_no_manifest(runner, tmp_path):
    _make_session_tree(tmp_path)

    result = runner.invoke(cli, ["verify-integrity", str(tmp_path)])

    assert result.exit_code == 1
    assert "No manifest found" in result.output


def test_verify_integrity_rejects_nonexistent_dir(runner, tmp_path):
    result = runner.invoke(cli, ["verify-integrity", str(tmp_path / "does-not-exist")])

    assert result.exit_code != 0
