import json

from drystone.storage.manifest import build_manifest, verify_manifest, write_manifest


def _make_session_tree(base_path):
    evidence_dir = base_path / "evidence" / "iam"
    evidence_dir.mkdir(parents=True)
    findings_dir = base_path / "findings"
    findings_dir.mkdir(parents=True)
    reports_dir = base_path / "reports"
    reports_dir.mkdir(parents=True)

    (evidence_dir / "users.json").write_text(json.dumps({"users": ["alice"]}))
    (findings_dir / "iam.json").write_text(json.dumps({"findings": []}))
    (reports_dir / "iam.md").write_text("# IAM Report")
    return evidence_dir, findings_dir, reports_dir


def test_build_manifest_hashes_evidence_and_findings(tmp_path):
    _make_session_tree(tmp_path)

    manifest = build_manifest(tmp_path)

    assert manifest["file_count"] == 3
    assert set(manifest["files"].keys()) == {
        "evidence/iam/users.json",
        "findings/iam.json",
        "reports/iam.md",
    }
    for entry in manifest["files"].values():
        assert len(entry["sha256"]) == 64
        assert entry["size_bytes"] > 0


def test_build_manifest_includes_reports_and_non_json_evidence_artifacts(tmp_path):
    evidence_dir, _, reports_dir = _make_session_tree(tmp_path)
    (evidence_dir / "notes.txt").write_text("not json")
    (reports_dir / "audit.pdf").write_bytes(b"%PDF fake")

    manifest = build_manifest(tmp_path)

    assert set(manifest["files"]) >= {
        "evidence/iam/users.json",
        "evidence/iam/notes.txt",
        "findings/iam.json",
        "reports/iam.md",
        "reports/audit.pdf",
    }


def test_write_manifest_persists_file_and_returns_stable_hash(tmp_path):
    _make_session_tree(tmp_path)

    manifest_path, manifest_hash = write_manifest(tmp_path)

    assert manifest_path == tmp_path / "manifest.json"
    assert manifest_path.exists()
    assert len(manifest_hash) == 64
    recorded = json.loads(manifest_path.read_text())
    assert recorded["file_count"] == 3


def test_verify_manifest_ok_when_untampered(tmp_path):
    _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    result = verify_manifest(tmp_path)

    assert result["ok"] is True
    assert result["tampered"] == []
    assert result["missing"] == []
    assert result["added"] == []
    assert result["checked_files"] == 3


def test_verify_manifest_detects_tampering(tmp_path):
    """Regression test for P0 #2: post-audit tampering with an evidence file
    must be detectable via the manifest, independent of the report itself."""
    evidence_dir, _, _ = _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    # Simulate an attacker/insider editing evidence after the audit completed.
    (evidence_dir / "users.json").write_text(json.dumps({"users": ["alice", "mallory"]}))

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert result["tampered"] == ["evidence/iam/users.json"]
    assert result["missing"] == []
    assert result["added"] == []


def test_verify_manifest_detects_missing_file(tmp_path):
    evidence_dir, _, _ = _make_session_tree(tmp_path)
    write_manifest(tmp_path)

    (evidence_dir / "users.json").unlink()

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert result["missing"] == ["evidence/iam/users.json"]


def test_verify_manifest_detects_added_file(tmp_path):
    evidence_dir, _, _ = _make_session_tree(tmp_path)
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


def test_build_manifest_includes_metrics_json(tmp_path):
    """Verify metrics.json is hashed if present at top level."""
    _make_session_tree(tmp_path)
    (tmp_path / "metrics.json").write_text(json.dumps({"llm_checks": 10}))

    manifest = build_manifest(tmp_path)

    assert "metrics.json" in manifest["files"]
    assert manifest["file_count"] == 4  # 3 from session tree + metrics.json
    assert len(manifest["files"]["metrics.json"]["sha256"]) == 64
    assert manifest["files"]["metrics.json"]["size_bytes"] > 0


def test_build_manifest_includes_active_verification_log_json(tmp_path):
    """Verify active_verification_log.json is hashed if present at top level."""
    _make_session_tree(tmp_path)
    (tmp_path / "active_verification_log.json").write_text(
        json.dumps({"verifications": []})
    )

    manifest = build_manifest(tmp_path)

    assert "active_verification_log.json" in manifest["files"]
    assert manifest["file_count"] == 4  # 3 from session tree + active_verification_log.json


def test_build_manifest_includes_both_top_level_files(tmp_path):
    """Verify both metrics.json and active_verification_log.json are hashed when present."""
    _make_session_tree(tmp_path)
    (tmp_path / "metrics.json").write_text(json.dumps({"llm_checks": 10}))
    (tmp_path / "active_verification_log.json").write_text(
        json.dumps({"verifications": []})
    )

    manifest = build_manifest(tmp_path)

    assert "metrics.json" in manifest["files"]
    assert "active_verification_log.json" in manifest["files"]
    assert manifest["file_count"] == 5  # 3 from session tree + 2 top-level files
    assert set(manifest["files"].keys()) >= {
        "evidence/iam/users.json",
        "findings/iam.json",
        "reports/iam.md",
        "metrics.json",
        "active_verification_log.json",
    }


def test_build_manifest_gracefully_skips_missing_top_level_files(tmp_path):
    """Verify missing top-level files are silently skipped (e.g., active verification disabled)."""
    _make_session_tree(tmp_path)
    (tmp_path / "metrics.json").write_text(json.dumps({"llm_checks": 10}))
    # active_verification_log.json is intentionally NOT created

    manifest = build_manifest(tmp_path)

    assert "metrics.json" in manifest["files"]
    assert "active_verification_log.json" not in manifest["files"]
    assert manifest["file_count"] == 4  # 3 from session tree + only metrics.json


def test_verify_manifest_detects_tampering_of_metrics_json(tmp_path):
    """Verify that tampering with metrics.json after manifest write is detected."""
    _make_session_tree(tmp_path)
    (tmp_path / "metrics.json").write_text(json.dumps({"llm_checks": 10}))
    write_manifest(tmp_path)

    # Simulate tampering: change metrics.json after manifest was written
    (tmp_path / "metrics.json").write_text(json.dumps({"llm_checks": 999}))

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert "metrics.json" in result["tampered"]
    assert result["missing"] == []
    assert result["added"] == []


def test_verify_manifest_detects_tampering_of_active_verification_log_json(tmp_path):
    """Verify that tampering with active_verification_log.json after manifest write is detected."""
    _make_session_tree(tmp_path)
    (tmp_path / "active_verification_log.json").write_text(
        json.dumps({"verifications": [{"status": "pass"}]})
    )
    write_manifest(tmp_path)

    # Simulate tampering: change active_verification_log.json after manifest was written
    (tmp_path / "active_verification_log.json").write_text(
        json.dumps({"verifications": [{"status": "fail"}]})
    )

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert "active_verification_log.json" in result["tampered"]
    assert result["missing"] == []
    assert result["added"] == []


def test_verify_manifest_ok_with_all_top_level_and_subdir_files(tmp_path):
    """End-to-end: verify manifest is ok when all files (both top-level and subdir) are untampered."""
    _make_session_tree(tmp_path)
    (tmp_path / "metrics.json").write_text(json.dumps({"llm_checks": 10}))
    (tmp_path / "active_verification_log.json").write_text(
        json.dumps({"verifications": []})
    )
    write_manifest(tmp_path)

    result = verify_manifest(tmp_path)

    assert result["ok"] is True
    assert result["tampered"] == []
    assert result["missing"] == []
    assert result["added"] == []
    assert result["checked_files"] == 5  # 3 subdir files + 2 top-level files
