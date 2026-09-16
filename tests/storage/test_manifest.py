import json

from drystone.storage.manifest import build_manifest, verify_manifest, write_manifest


def _make_session_tree(base_path):
    evidence_dir = base_path / "evidence" / "iam"
    evidence_dir.mkdir(parents=True)
    findings_dir = base_path / "findings"
    findings_dir.mkdir(parents=True)

    (evidence_dir / "users.json").write_text(json.dumps({"users": ["alice"]}))
    (findings_dir / "iam.json").write_text(json.dumps({"findings": []}))
    return evidence_dir, findings_dir


def test_build_manifest_hashes_evidence_and_findings(tmp_path):
    _make_session_tree(tmp_path)

    manifest = build_manifest(tmp_path)

    assert manifest["file_count"] == 2
    assert set(manifest["files"].keys()) == {
        "evidence/iam/users.json",
        "findings/iam.json",
    }
    for entry in manifest["files"].values():
        assert len(entry["sha256"]) == 64
        assert entry["size_bytes"] > 0


def test_build_manifest_ignores_non_json_and_reports_dir(tmp_path):
    evidence_dir, _ = _make_session_tree(tmp_path)
    (evidence_dir / "notes.txt").write_text("not json")
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    (reports_dir / "audit.md").write_text("# report")

    manifest = build_manifest(tmp_path)

    assert manifest["file_count"] == 2  # reports/ and .txt not included


def test_write_manifest_persists_file_and_returns_stable_hash(tmp_path):
    _make_session_tree(tmp_path)

    manifest_path, manifest_hash = write_manifest(tmp_path)

    assert manifest_path == tmp_path / "manifest.json"
    assert manifest_path.exists()
    assert len(manifest_hash) == 64
    recorded = json.loads(manifest_path.read_text())
    assert recorded["file_count"] == 2


def test_verify_manifest_ok_when_untampered(tmp_path):
    _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    result = verify_manifest(tmp_path)

    assert result["ok"] is True
    assert result["tampered"] == []
    assert result["missing"] == []
    assert result["added"] == []
    assert result["checked_files"] == 2


def test_verify_manifest_detects_tampering(tmp_path):
    """Regression test for P0 #2: post-audit tampering with an evidence file
    must be detectable via the manifest, independent of the report itself."""
    evidence_dir, _ = _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    # Simulate an attacker/insider editing evidence after the audit completed.
    (evidence_dir / "users.json").write_text(json.dumps({"users": ["alice", "mallory"]}))

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert result["tampered"] == ["evidence/iam/users.json"]
    assert result["missing"] == []
    assert result["added"] == []


def test_verify_manifest_detects_missing_file(tmp_path):
    evidence_dir, _ = _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    (evidence_dir / "users.json").unlink()

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert result["missing"] == ["evidence/iam/users.json"]


def test_verify_manifest_detects_added_file(tmp_path):
    evidence_dir, _ = _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    (evidence_dir / "roles.json").write_text(json.dumps({"roles": []}))

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert result["added"] == ["evidence/iam/roles.json"]


def test_verify_manifest_missing_manifest_file(tmp_path):
    _make_session_tree(tmp_path)

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert "No manifest found" in result["error"]


def test_verify_manifest_corrupt_manifest_file(tmp_path):
    _make_session_tree(tmp_path)
    (tmp_path / "manifest.json").write_text("{not valid json")

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert "not valid JSON" in result["error"]
