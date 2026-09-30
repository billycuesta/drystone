import json
from pathlib import Path

from drystone.validation.qa_gate import run_qa_gate


def test_qa_gate_detects_missing_critical_and_placeholders(tmp_path: Path):
    (tmp_path / "reports").mkdir(parents=True)
    (tmp_path / "audit.log").write_text(
        "2026-01-01 - x - WARNING - Missing Critical check: ECR-001\n"
    )
    (tmp_path / "reports" / "audit-report-ecr.md").write_text(
        "Observations about positive security controls will be listed here."
    )

    result = run_qa_gate(tmp_path, ["ecr"])
    assert result.passed is False
    assert any("Missing critical checks" in i for i in result.issues)
    assert any("Placeholder text" in i for i in result.issues)


def test_qa_gate_passes_for_clean_session(tmp_path: Path):
    (tmp_path / "reports").mkdir(parents=True)
    (tmp_path / "audit.log").write_text("all good")
    (tmp_path / "reports" / "audit-report-ecr.md").write_text("No placeholder content.")

    result = run_qa_gate(tmp_path, ["ecr"])
    assert result.passed is True


def test_qa_gate_fails_for_partial_low_confidence_metrics(tmp_path: Path):
    (tmp_path / "audit.log").write_text("run completed")
    (tmp_path / "metrics.json").write_text(
        json.dumps(
            {
                "validation_failures": 2,
                "skills": {
                    "iam": {
                        "status": "partial",
                        "confidence_level": "low",
                        "validation_passed": False,
                        "partial_results": True,
                        "llm_fallback_used": True,
                    },
                    "recon": {
                        "status": "complete",
                        "confidence_level": "high",
                        "validation_passed": True,
                    },
                },
            }
        )
    )

    result = run_qa_gate(tmp_path, ["iam", "recon"])
    assert result.passed is False
    assert any("validation failure" in issue for issue in result.issues)
    assert any("Skill iam execution incomplete" in issue for issue in result.issues)


def test_qa_gate_detects_iam_topic_mismatch(tmp_path: Path):
    (tmp_path / "findings").mkdir(parents=True)
    (tmp_path / "findings" / "iam.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "IAM-007",
                        "title": "Inline policies",
                        "description": "The password policy allows password reuse.",
                        "remediation": "Fix password policy.",
                        "affected_resources": [],
                        "evidence_refs": [],
                    }
                ]
            }
        )
    )

    result = run_qa_gate(tmp_path, ["iam"])
    assert result.passed is False
    assert any("IAM-007" in issue and "mismatched text" in issue for issue in result.issues)


def test_qa_gate_detects_network_topic_mismatch(tmp_path: Path):
    (tmp_path / "findings").mkdir(parents=True)
    (tmp_path / "findings" / "network.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "NET-011",
                        "title": "Security group critical rules missing descriptions",
                        "description": "VPC endpoints allow unrestricted AWS service access.",
                        "remediation": "Tighten VPC endpoint policies.",
                        "affected_resources": ["sg-1"],
                        "evidence_refs": ["security-groups.json#/items/0"],
                    }
                ]
            }
        )
    )

    result = run_qa_gate(tmp_path, ["network"])
    assert result.passed is False
    assert any("NET-011" in issue and "mismatched text" in issue for issue in result.issues)


def test_qa_gate_detects_wildcard_iam_arn_when_real_arn_exists(tmp_path: Path):
    (tmp_path / "findings").mkdir(parents=True)
    (tmp_path / "evidence" / "iam").mkdir(parents=True)
    (tmp_path / "evidence" / "iam" / "users.json").write_text(
        json.dumps([{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}])
    )
    (tmp_path / "findings" / "iam.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "IAM-014",
                        "title": "Multiple keys",
                        "description": "Multiple keys",
                        "remediation": "Fix",
                        "exploitability_status": "validated",
                        "affected_resources": ["arn:aws:iam::*:user/alice"],
                        "evidence_refs": ["users.json#/0"],
                    }
                ]
            }
        )
    )

    result = run_qa_gate(tmp_path, ["iam"])
    assert result.passed is False
    assert any("wildcard account ARN" in issue for issue in result.issues)


def test_qa_gate_detects_validated_finding_missing_resource_refs(tmp_path: Path):
    (tmp_path / "findings").mkdir(parents=True)
    (tmp_path / "findings" / "iam.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "IAM-014",
                        "title": "Multiple keys",
                        "description": "Multiple keys",
                        "remediation": "Fix",
                        "exploitability_status": "validated",
                        "affected_resources": [
                            "arn:aws:iam::123:user/a",
                            "arn:aws:iam::123:user/b",
                        ],
                        "evidence_refs": ["users.json#/0"],
                    }
                ]
            }
        )
    )

    result = run_qa_gate(tmp_path, ["iam"])
    assert result.passed is False
    assert any("evidence_refs do not cover" in issue for issue in result.issues)


def test_qa_gate_detects_high_finding_empty_impact_even_when_probable(tmp_path: Path):
    (tmp_path / "findings").mkdir(parents=True)
    (tmp_path / "findings" / "exposure.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "EXP-013",
                        "severity": "High",
                        "title": "S3 TLS",
                        "description": "S3 TLS",
                        "remediation": "Fix",
                        "impact": None,
                        "exploitability_status": "probable",
                        "affected_resources": ["arn:aws:s3:::logs"],
                        "evidence_refs": ["s3-buckets.json#/items/0"],
                    }
                ]
            }
        )
    )

    result = run_qa_gate(tmp_path, ["exposure"])
    assert result.passed is False
    assert any("empty impact" in issue for issue in result.issues)


def test_qa_gate_detects_high_finding_missing_resource_refs_even_when_probable(tmp_path: Path):
    (tmp_path / "findings").mkdir(parents=True)
    (tmp_path / "findings" / "exposure.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "EXP-014",
                        "severity": "High",
                        "title": "S3 versioning",
                        "description": "S3 versioning",
                        "remediation": "Fix",
                        "impact": "Audit log objects can be overwritten without version history.",
                        "exploitability_status": "probable",
                        "affected_resources": [
                            "arn:aws:s3:::logs-a",
                            "arn:aws:s3:::logs-b",
                        ],
                        "evidence_refs": ["s3-buckets.json#/items/0"],
                    }
                ]
            }
        )
    )

    result = run_qa_gate(tmp_path, ["exposure"])
    assert result.passed is False
    assert any("evidence_refs do not cover" in issue for issue in result.issues)



def test_qa_gate_reports_coverage_gap_metrics_without_failing(tmp_path):
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "iam.json").write_text(
        json.dumps(
            {
                "skill": "iam",
                "analysis_metadata": {
                    "pre_check_warn_ids": ["IAM-001"],
                    "pre_check_warn_reasons": [
                        {"check_id": "IAM-001", "reason_code": "collection_failed", "evidence_summary": "collection failed"}
                    ],
                },
                "findings": [],
            }
        )
    )

    result = run_qa_gate(tmp_path, ["iam"])

    assert result.passed is True
    assert result.coverage_gap_count == 1
    assert result.coverage_gap_ratio > 0
    assert result.coverage_gap_policy == "warn-only"
    assert not result.issues
