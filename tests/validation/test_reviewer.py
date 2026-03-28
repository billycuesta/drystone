"""Tests for AI-powered findings reviewer."""

import json
from unittest.mock import MagicMock

import pytest

from drystone.validation.reviewer import FindingsReviewer

# ── fixtures ──────────────────────────────────────────────────────────────────

EVIDENCE = {"users": [{"UserName": "root", "MFAActive": False}]}
CHECKLIST = {"items": [{"id": "IAM-001", "title": "Root MFA enabled", "severity": "Critical"}]}
FINDINGS = [
    {
        "id": "IAM-001",
        "severity": "Critical",
        "title": "Root MFA not enabled",
        "remediation": "Enable MFA on root account",
    }
]

VALID_REVIEW = {
    "validation_status": "PASS",
    "confidence_score": 0.95,
    "severity_mismatches": [],
    "missing_critical_findings": [],
    "remediation_issues": [],
    "summary": "All findings are accurate and complete.",
    "recommendations": [],
}


def make_client(response_text: str) -> MagicMock:
    """Build a mock Anthropic client that returns a given text."""
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=response_text)]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    return mock_client


# ── FindingsReviewer.validate: empty findings ─────────────────────────────────


class TestValidateEmptyFindings:
    def test_empty_findings_returns_pass(self):
        reviewer = FindingsReviewer(client=MagicMock())
        result = reviewer.validate("iam", EVIDENCE, CHECKLIST, findings=[])
        assert result["validation_status"] == "PASS"

    def test_empty_findings_confidence_is_one(self):
        reviewer = FindingsReviewer(client=MagicMock())
        result = reviewer.validate("iam", EVIDENCE, CHECKLIST, findings=[])
        assert result["confidence_score"] == 1.0

    def test_empty_findings_no_api_call(self):
        mock_client = MagicMock()
        reviewer = FindingsReviewer(client=mock_client)
        reviewer.validate("iam", EVIDENCE, CHECKLIST, findings=[])
        mock_client.messages.create.assert_not_called()

    def test_empty_findings_summary_indicates_clean(self):
        reviewer = FindingsReviewer(client=MagicMock())
        result = reviewer.validate("iam", EVIDENCE, CHECKLIST, findings=[])
        assert "clean" in result["summary"].lower() or "no findings" in result["summary"].lower()


# ── FindingsReviewer.validate: success ────────────────────────────────────────


class TestValidateSuccess:
    def test_returns_parsed_json_from_api(self):
        client = make_client(json.dumps(VALID_REVIEW))
        reviewer = FindingsReviewer(client=client)
        result = reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)
        assert result["validation_status"] == "PASS"
        assert result["confidence_score"] == 0.95

    def test_api_called_once(self):
        client = make_client(json.dumps(VALID_REVIEW))
        reviewer = FindingsReviewer(client=client)
        reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)
        client.messages.create.assert_called_once()

    def test_api_called_with_correct_model(self):
        client = make_client(json.dumps(VALID_REVIEW))
        reviewer = FindingsReviewer(client=client)
        reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)
        call_kwargs = client.messages.create.call_args.kwargs
        assert call_kwargs["model"] == reviewer.model

    def test_api_called_with_user_role(self):
        client = make_client(json.dumps(VALID_REVIEW))
        reviewer = FindingsReviewer(client=client)
        reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)
        call_kwargs = client.messages.create.call_args.kwargs
        assert call_kwargs["messages"][0]["role"] == "user"

    def test_severity_mismatches_returned(self):
        review = {
            **VALID_REVIEW,
            "validation_status": "FAIL",
            "severity_mismatches": [
                {
                    "finding_id": "IAM-001",
                    "agent_severity": "Low",
                    "recommended_severity": "Critical",
                    "reason": "Root MFA is always critical",
                }
            ],
        }
        client = make_client(json.dumps(review))
        reviewer = FindingsReviewer(client=client)
        result = reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)
        assert len(result["severity_mismatches"]) == 1
        assert result["severity_mismatches"][0]["finding_id"] == "IAM-001"

    def test_missing_critical_findings_returned(self):
        review = {
            **VALID_REVIEW,
            "validation_status": "FAIL",
            "missing_critical_findings": [
                {"check_id": "IAM-002", "check_title": "MFA check", "reason": "missed"}
            ],
        }
        client = make_client(json.dumps(review))
        reviewer = FindingsReviewer(client=client)
        result = reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)
        assert len(result["missing_critical_findings"]) == 1


# ── FindingsReviewer.validate: error handling ─────────────────────────────────


class TestValidateErrors:
    def test_invalid_json_raises_runtime_error(self):
        client = make_client("this is not json at all")
        reviewer = FindingsReviewer(client=client)
        with pytest.raises(RuntimeError, match="Invalid JSON"):
            reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)

    def test_api_exception_raises_runtime_error(self):
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API timeout")
        reviewer = FindingsReviewer(client=mock_client)
        with pytest.raises(RuntimeError, match="API call failed"):
            reviewer.validate("iam", EVIDENCE, CHECKLIST, FINDINGS)


# ── FindingsReviewer._build_review_prompt ─────────────────────────────────────


class TestBuildReviewPrompt:
    def test_prompt_contains_skill_name(self):
        reviewer = FindingsReviewer(client=MagicMock())
        prompt = reviewer._build_review_prompt("iam", EVIDENCE, CHECKLIST, FINDINGS)
        assert "IAM" in prompt

    def test_prompt_contains_evidence(self):
        reviewer = FindingsReviewer(client=MagicMock())
        prompt = reviewer._build_review_prompt("iam", EVIDENCE, CHECKLIST, FINDINGS)
        assert "root" in prompt

    def test_prompt_contains_finding_id(self):
        reviewer = FindingsReviewer(client=MagicMock())
        prompt = reviewer._build_review_prompt("iam", EVIDENCE, CHECKLIST, FINDINGS)
        assert "IAM-001" in prompt

    def test_large_evidence_is_truncated(self):
        large_evidence = {"data": "x" * 10000}
        reviewer = FindingsReviewer(client=MagicMock())
        prompt = reviewer._build_review_prompt("iam", large_evidence, CHECKLIST, FINDINGS)
        assert "truncated" in prompt

    def test_large_findings_is_truncated(self):
        large_findings = [{"id": f"IAM-{i:03}", "data": "x" * 500} for i in range(20)]
        reviewer = FindingsReviewer(client=MagicMock())
        prompt = reviewer._build_review_prompt("iam", EVIDENCE, CHECKLIST, large_findings)
        assert "truncated" in prompt

    def test_prompt_requests_json_response(self):
        reviewer = FindingsReviewer(client=MagicMock())
        prompt = reviewer._build_review_prompt("iam", EVIDENCE, CHECKLIST, FINDINGS)
        assert "JSON" in prompt
        assert "validation_status" in prompt


# ── FindingsReviewer.validate_batch ───────────────────────────────────────────


class TestValidateBatch:
    def test_returns_result_per_skill(self):
        client = make_client(json.dumps(VALID_REVIEW))
        reviewer = FindingsReviewer(client=client)
        skills_data = [
            {"skill": "iam", "evidence": EVIDENCE, "checklist": CHECKLIST, "findings": FINDINGS},
            {"skill": "network", "evidence": {}, "checklist": {}, "findings": FINDINGS},
        ]
        results = reviewer.validate_batch(skills_data)
        assert "iam" in results
        assert "network" in results

    def test_api_called_once_per_skill(self):
        client = make_client(json.dumps(VALID_REVIEW))
        reviewer = FindingsReviewer(client=client)
        skills_data = [
            {"skill": "iam", "evidence": EVIDENCE, "checklist": CHECKLIST, "findings": FINDINGS},
            {"skill": "network", "evidence": {}, "checklist": {}, "findings": FINDINGS},
        ]
        reviewer.validate_batch(skills_data)
        assert client.messages.create.call_count == 2

    def test_failed_skill_recorded_as_error(self):
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("boom")
        reviewer = FindingsReviewer(client=mock_client)
        skills_data = [
            {"skill": "iam", "evidence": EVIDENCE, "checklist": CHECKLIST, "findings": FINDINGS}
        ]
        results = reviewer.validate_batch(skills_data)
        assert results["iam"]["validation_status"] == "ERROR"
        assert "boom" in results["iam"]["error"]

    def test_failed_skill_does_not_stop_remaining_skills(self):
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("first skill fails")
            mock_message = MagicMock()
            mock_message.content = [MagicMock(text=json.dumps(VALID_REVIEW))]
            return mock_message

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = side_effect
        reviewer = FindingsReviewer(client=mock_client)
        skills_data = [
            {"skill": "iam", "evidence": EVIDENCE, "checklist": CHECKLIST, "findings": FINDINGS},
            {"skill": "network", "evidence": {}, "checklist": {}, "findings": FINDINGS},
        ]
        results = reviewer.validate_batch(skills_data)
        assert results["iam"]["validation_status"] == "ERROR"
        assert results["network"]["validation_status"] == "PASS"

    def test_empty_skill_list_returns_empty_dict(self):
        reviewer = FindingsReviewer(client=MagicMock())
        results = reviewer.validate_batch([])
        assert results == {}
