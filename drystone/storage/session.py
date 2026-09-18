"""Audit session and evidence storage management."""

import uuid
from datetime import datetime
from pathlib import Path

from drystone.utils.logging import setup_file_logging


class AuditSession:
    """Manages audit session directory structure and evidence storage.

    Creates directory layout:
        audit-logs/{client}_{timestamp}/
        ├── evidence/
        │   └── {skill}/
        ├── findings/
        └── reports/
        └── audit.log
    """

    def __init__(self, client_name: str, account_id: str):
        """Create audit session with proper directory structure.

        Args:
            client_name: Organization or client name (used in dirname)
            account_id: AWS account ID for metadata
        """
        # Sanitize client_name to prevent path traversal. Only the final
        # path component is used.
        self.client_name = Path(client_name).name
        self.account_id = account_id
        self.integrity_manifest_sha256: str | None = None
        self.timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        # Base path: audit-logs/{client}_{timestamp}_{rand}/. The trailing
        # 6-hex-char suffix guards against two audits for the same client
        # starting within the same second, which would otherwise collide on
        # the same directory and silently mix their evidence/findings
        # (`_create_directories()` used to `mkdir(exist_ok=True)` into
        # whatever was already there). `trend_analysis.py`'s directory-name
        # parser tolerates this optional suffix, matching on client name +
        # timestamp alone.
        rand_suffix = uuid.uuid4().hex[:6]
        self.base_path = (
            Path.cwd() / "audit-logs" / f"{self.client_name}_{self.timestamp}_{rand_suffix}"
        )

        # Create directory structure
        self._create_directories()

        # Setup file logging for the session
        log_file = self.base_path / "audit.log"
        setup_file_logging(log_file)

    def _create_directories(self):
        """Create all required subdirectories.

        Raises:
            FileExistsError: if `base_path` already exists and is non-empty.
                With the random suffix in `base_path`, this should be
                virtually impossible -- checked explicitly anyway rather
                than silently reusing it via `exist_ok=True`, since merging
                into an existing session directory would corrupt its
                evidence/findings.
        """
        if self.base_path.exists() and any(self.base_path.iterdir()):
            raise FileExistsError(
                f"Audit session directory already exists and is not empty: {self.base_path}"
            )
        self.base_path.mkdir(parents=True, exist_ok=True)
        (self.base_path / "evidence").mkdir(exist_ok=True)
        (self.base_path / "findings").mkdir(exist_ok=True)
        (self.base_path / "reports").mkdir(exist_ok=True)

    def get_evidence_path(self, skill_name: str) -> Path:
        """Get or create evidence directory for a specific skill.

        Args:
            skill_name: Name of the skill (e.g., 'iam', 'exposure')

        Returns:
            Path to skill evidence directory
        """
        path = self.base_path / "evidence" / skill_name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_findings_path(self) -> Path:
        """Get findings directory for all skills.

        Returns:
            Path to findings directory
        """
        return self.base_path / "findings"

    def get_reports_path(self) -> Path:
        """Get reports directory for generated reports.

        Returns:
            Path to reports directory
        """
        return self.base_path / "reports"

    def __repr__(self) -> str:
        return f"AuditSession(client={self.client_name}, account={self.account_id}, path={self.base_path})"
