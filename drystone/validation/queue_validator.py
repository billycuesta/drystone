"""Queue validation for evidence/findings handoff symmetry.

Implements a Shannon-style guardrail before running cross-skill correlation:
- Avoid correlating partial or malformed skill outputs
- Ensure evidence and findings are structurally consistent
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class ValidationResult:
    """Result of queue validation for one skill."""

    valid: bool
    retryable: bool = True
    error: Optional[str] = None
    should_correlate: bool = False


class QueueValidator:
    """Validate per-skill evidence/findings handoff before correlation."""

    def validate_skill_output(self, skill: str, session_dir: Path) -> ValidationResult:
        """Validate one skill output under a session directory.

        Supported layouts:
        1) Current session layout:
           - evidence/<skill>/*.json
           - findings/<skill>.json
        2) Legacy orchestrator layout:
           - <skill>/evidence/raw.json
           - <skill>/findings/findings.json
        """

        evidence_dir = session_dir / "evidence" / skill
        findings_path = session_dir / "findings" / f"{skill}.json"

        # Legacy fallback layout
        if not evidence_dir.exists() and not findings_path.exists():
            evidence_dir = session_dir / skill / "evidence"
            findings_path = session_dir / skill / "findings" / "findings.json"

        evidence_files = list(evidence_dir.glob("*.json")) if evidence_dir.exists() else []
        evidence_exists = len(evidence_files) > 0
        findings_exists = findings_path.exists()

        # Rule 1: symmetric existence
        if evidence_exists != findings_exists:
            return ValidationResult(
                valid=False,
                retryable=True,
                error=self._get_existence_error(skill, evidence_exists, findings_exists),
                should_correlate=False,
            )

        # If both missing => skill not executed; valid but excluded from correlation.
        if not evidence_exists and not findings_exists:
            return ValidationResult(valid=True, retryable=False, should_correlate=False)

        # Rule 2: findings structure
        try:
            findings_data = json.loads(findings_path.read_text())
        except json.JSONDecodeError as exc:
            return ValidationResult(
                valid=False,
                retryable=True,
                error=f"Skill {skill}: invalid JSON in findings file - {exc}",
                should_correlate=False,
            )

        findings = findings_data.get("findings")
        if not isinstance(findings, list):
            return ValidationResult(
                valid=False,
                retryable=True,
                error=f"Skill {skill}: findings payload missing array field 'findings'",
                should_correlate=False,
            )

        # Rule 3: evidence refs must point to collected files (best-effort)
        evidence_index = self._build_evidence_index(evidence_files)
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding_id = str(finding.get("id") or "UNKNOWN")
            refs = finding.get("evidence_refs") or []
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, str):
                    continue
                if not self._resolve_evidence_ref(ref, evidence_index):
                    return ValidationResult(
                        valid=False,
                        retryable=True,
                        error=f"Skill {skill}: finding {finding_id} has unresolved evidence ref '{ref}'",
                        should_correlate=False,
                    )

        return ValidationResult(valid=True, retryable=False, should_correlate=True)

    def _build_evidence_index(self, evidence_files: list[Path]) -> Dict[str, Any]:
        """Load evidence files into an index by filename/stem for ref resolution."""

        index: Dict[str, Any] = {}
        for file_path in evidence_files:
            try:
                data = json.loads(file_path.read_text())
            except Exception:
                continue
            index[file_path.name] = data
            index[file_path.stem] = data
        return index

    def _get_existence_error(self, skill: str, evidence_exists: bool, findings_exists: bool) -> str:
        if evidence_exists and not findings_exists:
            return (
                f"Skill {skill}: analysis incomplete - evidence exists but findings are missing "
                "(agent analysis likely failed)"
            )
        return (
            f"Skill {skill}: analysis incomplete - findings exist but evidence is missing "
            "(collection likely failed)"
        )

    def _resolve_evidence_ref(self, ref: str, evidence_index: Dict[str, Any]) -> bool:
        """Resolve reference to an evidence file key.

        Accepted formats:
        - evidence/iam/users.json#root
        - users.json#root
        - users#root
        - users.json
        """

        file_ref = ref.split("#", 1)[0].strip()
        if not file_ref:
            return False

        filename = Path(file_ref).name
        stem = Path(filename).stem

        return file_ref in evidence_index or filename in evidence_index or stem in evidence_index
