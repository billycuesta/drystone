"""Tests for canonical report context construction."""

import json
from unittest.mock import Mock

from drystone.reports.context import ReportContext
from drystone.storage.session import AuditSession


def _session(tmp_path):
    session = Mock(spec=AuditSession)
    session.base_path = tmp_path
    session.account_id = "123456789012"
    session.client_name = "TestClient"
    return session


def test_report_context_collects_shared_metadata_and_sidecars(tmp_path):
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "trend.json").write_text(
        json.dumps({"previous_session": "TestClient_2026-09-01T10-00-00", "skills": []})
    )
    (findings_dir / "correlated.json").write_text(
        json.dumps(
            {
                "total_correlations": 200,
                "truncated": True,
                "warnings": ["cap reached"],
                "truncation": {"reasons": ["max_total_correlations"]},
            }
        )
    )
    evidence_dir = tmp_path / "evidence" / "network"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "attack-path-candidates.json").write_text(
        json.dumps({"paths": [{"id": "AP-NET-001", "overall_score": 0.91}]})
    )

    findings = {
        "skill": "network",
        "analyzed_at": "2026-03-04T00:00:00Z",
        "checklist_version": "2.0",
        "evidence_count": 3,
        "report_metadata": {
            "integrity_manifest_sha256": "abc123",
            "integrity_manifest_file": "manifest.json",
        },
        "findings": [],
    }

    context = ReportContext.from_findings(findings, _session(tmp_path), report_format_version="1.0")

    assert context.metadata["client"] == "TestClient"
    assert context.metadata["skill"] == "network"
    assert context.metadata["integrity_manifest_sha256"] == "abc123"
    assert context.trend["previous_session"] == "TestClient_2026-09-01T10-00-00"
    assert context.correlation_summary["truncated"] is True
    assert context.attack_path_candidates[0]["id"] == "AP-NET-001"
    assert context.attack_path_candidates[0]["skill"] == "network"


def test_report_context_redacts_finding_secret_material(tmp_path):
    findings = {
        "skill": "iam",
        "findings": [
            {
                "id": "IAM-001",
                "title": "Leaked key",
                "evidence_snippet": {
                    "AccessKeyId": "AKIA1234567890ABCDE1",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                },
            }
        ],
    }

    context = ReportContext.from_findings(findings, _session(tmp_path), report_format_version="1.0")

    dumped = json.dumps(context.redacted_findings)
    assert "AKIA1234567890ABCDE1" not in dumped
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in dumped
    assert "AKIA****************" in dumped
    assert "[REDACTED_SECRET]" in dumped
    assert context.redaction_count >= 2
