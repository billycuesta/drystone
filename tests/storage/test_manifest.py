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


def test_build_manifest_includes_audit_log(tmp_path):
    _make_session_tree(tmp_path)
    (tmp_path / "audit.log").write_text("Audit completed\n")

    manifest = build_manifest(tmp_path)

    assert "audit.log" in manifest["files"]
    assert manifest["file_count"] == 4


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


def test_build_manifest_includes_pci_evidence_markdown_files(tmp_path):
    _make_session_tree(tmp_path)
    pci_dir = tmp_path / "pci-evidence"
    pci_dir.mkdir()
    (pci_dir / "Acme_8.4.1_iam-001-root-mfa.md").write_text("# PCI DSS Control 8.4.1")
    (pci_dir / "Acme_7.2.1_iam-001-root-mfa.md").write_text("# PCI DSS Control 7.2.1")

    manifest = build_manifest(tmp_path)

    assert manifest["file_count"] == 5
    assert "pci-evidence/Acme_8.4.1_iam-001-root-mfa.md" in manifest["files"]
    assert "pci-evidence/Acme_7.2.1_iam-001-root-mfa.md" in manifest["files"]


def test_verify_manifest_detects_tampered_pci_evidence(tmp_path):
    _make_session_tree(tmp_path)
    pci_dir = tmp_path / "pci-evidence"
    pci_dir.mkdir()
    evidence_file = pci_dir / "Acme_8.4.1_iam-001-root-mfa.md"
    evidence_file.write_text("**Status:** FAIL")
    write_manifest(tmp_path)

    evidence_file.write_text("**Status:** PASS")

    result = verify_manifest(tmp_path)

    assert result["ok"] is False
    assert result["tampered"] == ["pci-evidence/Acme_8.4.1_iam-001-root-mfa.md"]


def test_build_manifest_without_pci_evidence_dir_is_unaffected(tmp_path):
    _make_session_tree(tmp_path)

    manifest = build_manifest(tmp_path)

    assert manifest["file_count"] == 3
    assert not any(k.startswith("pci-evidence/") for k in manifest["files"])
