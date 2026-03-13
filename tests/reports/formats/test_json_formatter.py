"""Tests for JSON formatter attack path export."""

import json
from unittest.mock import Mock

from drystone.reports.formats.json import JSONFormatter
from drystone.storage.session import AuditSession


def _build_formatter(tmp_path, skill: str) -> JSONFormatter:
    session = Mock(spec=AuditSession)
    session.base_path = tmp_path
    session.account_id = "123456789012"
    session.client_name = "TestClient"
    session.get_reports_path.return_value = tmp_path / "reports"
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)

    config = Mock()
    config.report_type = "general"

    findings = {
        "skill": skill,
        "analyzed_at": "2026-03-04T00:00:00Z",
        "summary": {"overall_risk_score": 7.1},
        "findings": [],
    }
    return JSONFormatter(findings, session, config)


def test_json_formatter_exports_attack_paths_for_single_skill(tmp_path) -> None:
    evidence_dir = tmp_path / "evidence" / "sistemas_explotables_red"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with open(evidence_dir / "attack-path-candidates.json", "w") as f:
        json.dump(
            {
                "paths": [
                    {
                        "id": "AP-SER-001",
                        "target_resource": "arn:aws:ec2:*:*:instance/i-123",
                        "overall_score": 0.82,
                    }
                ]
            },
            f,
        )

    formatter = _build_formatter(tmp_path, "sistemas_explotables_red")
    payload = formatter._build_json()
    assert "attack_path_candidates" in payload
    assert len(payload["attack_path_candidates"]) == 1
    assert payload["attack_path_candidates"][0]["id"] == "AP-SER-001"
    assert payload["attack_path_candidates"][0]["skill"] == "sistemas_explotables_red"


def test_json_formatter_exports_attack_paths_for_aggregated_context(tmp_path) -> None:
    ser_dir = tmp_path / "evidence" / "sistemas_explotables_red"
    ser_dir.mkdir(parents=True, exist_ok=True)
    with open(ser_dir / "attack-path-candidates.json", "w") as f:
        json.dump({"paths": [{"id": "AP-SER-001", "overall_score": 0.81}]}, f)

    other_dir = tmp_path / "evidence" / "network"
    other_dir.mkdir(parents=True, exist_ok=True)
    with open(other_dir / "attack-path-candidates.json", "w") as f:
        json.dump({"paths": [{"id": "AP-NET-001", "overall_score": 0.91}]}, f)

    formatter = _build_formatter(tmp_path, "aggregated")
    payload = formatter._build_json()
    exported = payload["attack_path_candidates"]

    assert len(exported) == 2
    assert exported[0]["id"] == "AP-NET-001"
    assert exported[1]["id"] == "AP-SER-001"
