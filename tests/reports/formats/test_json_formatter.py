"""Tests for JSON formatter attack path export."""

import json
from unittest.mock import Mock

from drystone.reports.formats.json import JSONFormatter
from drystone.storage.session import AuditSession


def _build_formatter(tmp_path, skill: str, findings_override: dict | None = None) -> JSONFormatter:
    session = Mock(spec=AuditSession)
    session.base_path = tmp_path
    session.account_id = "123456789012"
    session.client_name = "TestClient"
    session.get_reports_path.return_value = tmp_path / "reports"
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)

    config = Mock()
    config.report_type = "general"

    findings = findings_override or {
        "skill": skill,
        "analyzed_at": "2026-03-04T00:00:00Z",
        "summary": {"overall_risk_score": 7.1},
        "findings": [],
    }
    return JSONFormatter(findings, session, config)


def test_json_formatter_includes_report_format_version(tmp_path) -> None:
    """P2: Report schema versioning -- downstream consumers (SIEM/ticket
    export, trend analysis) need a stable field to know the JSON shape."""
    formatter = _build_formatter(tmp_path, "iam")
    payload = formatter._build_json()
    assert payload["metadata"]["report_format_version"] == JSONFormatter.REPORT_FORMAT_VERSION


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


def test_json_formatter_includes_correlation_warning_summary(tmp_path) -> None:
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    with open(findings_dir / "correlated.json", "w") as f:
        json.dump(
            {
                "total_correlations": 200,
                "truncated": True,
                "warnings": ["Correlation analysis was truncated after reaching the cap."],
                "truncation": {
                    "reasons": ["max_total_correlations"],
                    "max_total_correlations": 200,
                    "returned_correlations": 200,
                },
            },
            f,
        )

    formatter = _build_formatter(tmp_path, "aggregated")
    payload = formatter._build_json()

    assert payload["correlation_summary"]["total_correlations"] == 200
    assert payload["correlation_summary"]["truncated"] is True
    assert "max_total_correlations" in payload["correlation_summary"]["truncation"]["reasons"]
    assert payload["correlation_summary"]["warnings"]


def test_json_formatter_includes_trend_when_baseline_exists(tmp_path) -> None:
    """P2 #3: multi-run trend analysis surfaces in the JSON export."""
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    with open(findings_dir / "trend.json", "w") as f:
        json.dump(
            {
                "previous_session": "TestClient_2026-09-01T10-00-00",
                "skills": [{"skill": "iam", "new": [{"id": "IAM-002"}], "fixed": [], "persisting_count": 3}],
            },
            f,
        )

    formatter = _build_formatter(tmp_path, "iam")
    payload = formatter._build_json()

    assert payload["trend"]["previous_session"] == "TestClient_2026-09-01T10-00-00"
    assert payload["trend"]["skills"][0]["new"] == [{"id": "IAM-002"}]


def test_json_formatter_omits_trend_when_no_baseline(tmp_path) -> None:
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    with open(findings_dir / "trend.json", "w") as f:
        json.dump({"previous_session": None, "skills": []}, f)

    formatter = _build_formatter(tmp_path, "iam")
    payload = formatter._build_json()

    assert "trend" not in payload


def test_json_formatter_omits_trend_when_file_absent(tmp_path) -> None:
    formatter = _build_formatter(tmp_path, "iam")
    payload = formatter._build_json()

    assert "trend" not in payload


def test_json_formatter_redacts_secret_material_in_findings(tmp_path) -> None:
    formatter = _build_formatter(
        tmp_path,
        "iam",
        {
            "skill": "iam",
            "analyzed_at": "2026-03-04T00:00:00Z",
            "summary": {"overall_risk_score": 7.1},
            "findings": [
                {
                    "id": "IAM-SECRET",
                    "evidence_snippet": {
                        "AccessKeyId": "AKIA1234567890ABCDE1",
                        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    },
                }
            ],
        },
    )

    payload = formatter._build_json()
    dumped = json.dumps(payload)

    assert "AKIA1234567890ABCDE1" not in dumped
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in dumped
    assert "AKIA****************" in dumped
    assert "[REDACTED_SECRET]" in dumped
    assert payload["metadata"]["redactions_applied"] >= 2


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
