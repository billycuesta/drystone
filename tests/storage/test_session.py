"""Tests for AuditSession — directory structure and path helpers."""

from pathlib import Path
from unittest.mock import patch

from drystone.storage.session import AuditSession

# ── helpers ───────────────────────────────────────────────────────────────────


def make_session(tmp_path: Path, client_name="acme", account_id="123456789012") -> AuditSession:
    """Create an AuditSession rooted in tmp_path."""
    with (
        patch("drystone.storage.session.Path.cwd", return_value=tmp_path),
        patch("drystone.storage.session.setup_file_logging"),
    ):
        return AuditSession(client_name=client_name, account_id=account_id)


# ── AuditSession.__init__: directory creation ──────────────────────────────────


class TestAuditSessionInit:
    def test_base_path_created(self, tmp_path):
        session = make_session(tmp_path)
        assert session.base_path.exists()

    def test_evidence_dir_created(self, tmp_path):
        session = make_session(tmp_path)
        assert (session.base_path / "evidence").is_dir()

    def test_findings_dir_created(self, tmp_path):
        session = make_session(tmp_path)
        assert (session.base_path / "findings").is_dir()

    def test_reports_dir_created(self, tmp_path):
        session = make_session(tmp_path)
        assert (session.base_path / "reports").is_dir()

    def test_base_path_contains_client_name(self, tmp_path):
        session = make_session(tmp_path, client_name="myorg")
        assert "myorg" in str(session.base_path)

    def test_base_path_contains_timestamp(self, tmp_path):
        session = make_session(tmp_path)
        # Timestamp format: YYYY-MM-DDTHH-MM-SS
        assert session.timestamp in str(session.base_path)

    def test_client_name_stored(self, tmp_path):
        session = make_session(tmp_path, client_name="testclient")
        assert session.client_name == "testclient"

    def test_account_id_stored(self, tmp_path):
        session = make_session(tmp_path, account_id="999888777666")
        assert session.account_id == "999888777666"

    def test_setup_file_logging_called(self, tmp_path):
        with (
            patch("drystone.storage.session.Path.cwd", return_value=tmp_path),
            patch("drystone.storage.session.setup_file_logging") as mock_log,
        ):
            AuditSession(client_name="test", account_id="123")
        mock_log.assert_called_once()

    def test_log_file_path_passed_to_setup(self, tmp_path):
        with (
            patch("drystone.storage.session.Path.cwd", return_value=tmp_path),
            patch("drystone.storage.session.setup_file_logging") as mock_log,
        ):
            session = AuditSession(client_name="test", account_id="123")
        expected_log = session.base_path / "audit.log"
        mock_log.assert_called_once_with(expected_log)

    def test_path_traversal_prevented(self, tmp_path):
        """client_name with path separators should only use the final component."""
        session = make_session(tmp_path, client_name="../../evil")
        # Path(name).name strips directory components
        assert session.client_name == "evil"

    def test_base_path_under_audit_logs(self, tmp_path):
        session = make_session(tmp_path)
        assert session.base_path.parent.name == "audit-logs"


# ── AuditSession.get_evidence_path ────────────────────────────────────────────


class TestGetEvidencePath:
    def test_returns_path_under_evidence(self, tmp_path):
        session = make_session(tmp_path)
        path = session.get_evidence_path("iam")
        assert path == session.base_path / "evidence" / "iam"

    def test_directory_created(self, tmp_path):
        session = make_session(tmp_path)
        path = session.get_evidence_path("network")
        assert path.is_dir()

    def test_idempotent_when_called_twice(self, tmp_path):
        session = make_session(tmp_path)
        p1 = session.get_evidence_path("iam")
        p2 = session.get_evidence_path("iam")
        assert p1 == p2
        assert p2.is_dir()

    def test_different_skills_different_paths(self, tmp_path):
        session = make_session(tmp_path)
        iam_path = session.get_evidence_path("iam")
        net_path = session.get_evidence_path("network")
        assert iam_path != net_path

    def test_nested_skill_name_creates_parents(self, tmp_path):
        session = make_session(tmp_path)
        path = session.get_evidence_path("sub/skill")
        assert path.exists()


# ── AuditSession.get_findings_path ────────────────────────────────────────────


class TestGetFindingsPath:
    def test_returns_findings_directory(self, tmp_path):
        session = make_session(tmp_path)
        path = session.get_findings_path()
        assert path == session.base_path / "findings"

    def test_path_is_directory(self, tmp_path):
        session = make_session(tmp_path)
        path = session.get_findings_path()
        assert path.is_dir()


# ── AuditSession.get_reports_path ─────────────────────────────────────────────


class TestGetReportsPath:
    def test_returns_reports_directory(self, tmp_path):
        session = make_session(tmp_path)
        path = session.get_reports_path()
        assert path == session.base_path / "reports"

    def test_path_is_directory(self, tmp_path):
        session = make_session(tmp_path)
        path = session.get_reports_path()
        assert path.is_dir()


# ── AuditSession.__repr__ ─────────────────────────────────────────────────────


class TestAuditSessionRepr:
    def test_repr_contains_client_name(self, tmp_path):
        session = make_session(tmp_path, client_name="acme")
        assert "acme" in repr(session)

    def test_repr_contains_account_id(self, tmp_path):
        session = make_session(tmp_path, account_id="123456789012")
        assert "123456789012" in repr(session)

    def test_repr_contains_path(self, tmp_path):
        session = make_session(tmp_path)
        assert str(session.base_path) in repr(session)
