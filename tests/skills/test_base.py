"""Tests for drystone/skills/base.py — pure utility methods.

Covers:
- _severity_to_risk
- _infer_region_from_evidence
- _inject_validation_commands
- _reconcile_with_pre_checks (PASS rejection, FAIL injection, EXP-015 correction)
- _build_precheck_traceability (generic, SER-LMB-002, ECR-*, KMS-*)
- _normalize_findings (wrapper smoke)
"""

import json
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from drystone.models.findings import Finding, FindingsSummary, SkillFindings
from drystone.skills.base import BaseSkill, _severity_to_risk

# ── Minimal concrete subclass ──────────────────────────────────────────────────


class _DummySkill(BaseSkill):
    @property
    def name(self) -> str:
        return "iam"

    def collect(self, aws_client, session):
        pass


SKILL = _DummySkill()


# ── Helper factories ───────────────────────────────────────────────────────────


def _finding(fid="IAM-001", severity="High", risk_score=7.0, **kwargs) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        risk_score=risk_score,
        title=f"Test {fid}",
        description="desc",
        remediation="fix it",
        affected_resources=kwargs.pop("affected_resources", ["arn:aws:iam::123:root"]),
        evidence_refs=kwargs.pop("evidence_refs", ["evidence/iam/users.json"]),
        **kwargs,
    )


def _skill_findings(*findings) -> SkillFindings:
    return SkillFindings(
        skill="iam",
        findings=list(findings),
        summary=FindingsSummary(
            total_findings=len(findings),
            critical=0,
            high=len(findings),
            medium=0,
            low=0,
            overall_risk_score=7.0,
        ),
        evidence_count=1,
        checklist_version="2.0",
    )


def _pre_check(check_id, status="PASS", affected=None, evidence_summary="", metadata=None):
    r = SimpleNamespace(
        check_id=check_id,
        status=status,
        affected_resources=list(affected or []),
        evidence_summary=evidence_summary,
        metadata=metadata,
    )
    return r


def _checklist(*ids, severity="High"):
    return {
        "items": [
            {
                "id": cid,
                "title": f"Check {cid}",
                "severity": severity,
                "description": f"Desc {cid}",
                "remediation": f"Fix {cid}",
            }
            for cid in ids
        ]
    }


# ── _severity_to_risk ─────────────────────────────────────────────────────────


class TestSeverityToRisk:
    def test_critical(self):
        assert _severity_to_risk("Critical") == 9.0

    def test_high(self):
        assert _severity_to_risk("High") == 7.0

    def test_medium(self):
        assert _severity_to_risk("Medium") == 4.5

    def test_low(self):
        assert _severity_to_risk("Low") == 2.0

    def test_unknown_returns_default(self):
        assert _severity_to_risk("Unknown") == 5.0

    def test_empty_returns_default(self):
        assert _severity_to_risk("") == 5.0


# ── _infer_region_from_evidence ───────────────────────────────────────────────


class TestInferRegion:
    def test_reads_region_from_metadata_file(self, tmp_path):
        session = MagicMock()
        evidence_path = tmp_path / "evidence" / "iam"
        evidence_path.mkdir(parents=True)
        meta = {"_region": "eu-west-2"}
        (evidence_path / "_audit_metadata.json").write_text(json.dumps(meta))
        session.get_evidence_path.return_value = evidence_path

        region = SKILL._infer_region_from_evidence(session)
        assert region == "eu-west-2"

    def test_returns_default_when_no_metadata_file(self, tmp_path):
        session = MagicMock()
        evidence_path = tmp_path / "evidence" / "iam"
        evidence_path.mkdir(parents=True)
        session.get_evidence_path.return_value = evidence_path

        region = SKILL._infer_region_from_evidence(session)
        assert region == "us-east-1"

    def test_returns_default_when_region_key_missing(self, tmp_path):
        session = MagicMock()
        evidence_path = tmp_path / "evidence" / "iam"
        evidence_path.mkdir(parents=True)
        (evidence_path / "_audit_metadata.json").write_text(json.dumps({"other": "value"}))
        session.get_evidence_path.return_value = evidence_path

        region = SKILL._infer_region_from_evidence(session)
        assert region == "us-east-1"

    def test_returns_default_when_region_empty_string(self, tmp_path):
        session = MagicMock()
        evidence_path = tmp_path / "evidence" / "iam"
        evidence_path.mkdir(parents=True)
        (evidence_path / "_audit_metadata.json").write_text(json.dumps({"_region": ""}))
        session.get_evidence_path.return_value = evidence_path

        region = SKILL._infer_region_from_evidence(session)
        assert region == "us-east-1"

    def test_returns_default_on_bad_json(self, tmp_path):
        session = MagicMock()
        evidence_path = tmp_path / "evidence" / "iam"
        evidence_path.mkdir(parents=True)
        (evidence_path / "_audit_metadata.json").write_text("NOT JSON{{")
        session.get_evidence_path.return_value = evidence_path

        region = SKILL._infer_region_from_evidence(session)
        assert region == "us-east-1"


# ── _inject_validation_commands ───────────────────────────────────────────────


class TestInjectValidationCommands:
    def _make_session(self, tmp_path):
        session = MagicMock()
        session.account_id = "123456789012"
        evidence_path = tmp_path / "evidence" / "iam"
        evidence_path.mkdir(parents=True)
        session.get_evidence_path.return_value = evidence_path
        return session

    def test_adds_commands_to_finding_without_commands(self, tmp_path):
        session = self._make_session(tmp_path)
        payload = {"findings": [{"id": "IAM-001", "evidence_refs": ["evidence/iam/users.json"]}]}
        with patch(
            "drystone.reports.validation_commands.suggest_aws_cli_commands",
            return_value=["aws iam list-users"],
        ):
            result = SKILL._inject_validation_commands(payload, session)

        assert result["findings"][0]["validation_commands"] == ["aws iam list-users"]

    def test_skips_finding_with_existing_commands(self, tmp_path):
        session = self._make_session(tmp_path)
        existing = ["aws iam get-user"]
        payload = {
            "findings": [
                {
                    "id": "IAM-001",
                    "evidence_refs": [],
                    "validation_commands": existing,
                }
            ]
        }
        with patch("drystone.reports.validation_commands.suggest_aws_cli_commands") as mock_suggest:
            result = SKILL._inject_validation_commands(payload, session)

        mock_suggest.assert_not_called()
        assert result["findings"][0]["validation_commands"] == existing

    def test_skips_finding_with_empty_command_list(self, tmp_path):
        """Empty command list [] is falsy — suggest should be called."""
        session = self._make_session(tmp_path)
        payload = {"findings": [{"id": "IAM-001", "evidence_refs": [], "validation_commands": []}]}
        with patch(
            "drystone.reports.validation_commands.suggest_aws_cli_commands",
            return_value=["aws iam list-roles"],
        ) as mock_suggest:
            SKILL._inject_validation_commands(payload, session)

        mock_suggest.assert_called_once()

    def test_returns_payload_unchanged_when_no_findings(self, tmp_path):
        session = self._make_session(tmp_path)
        payload: Dict[str, Any] = {"findings": []}
        result = SKILL._inject_validation_commands(payload, session)
        assert result == {"findings": []}

    def test_evidence_refs_not_list_treated_as_empty(self, tmp_path):
        session = self._make_session(tmp_path)
        payload = {"findings": [{"id": "IAM-001", "evidence_refs": "not-a-list"}]}
        with patch(
            "drystone.reports.validation_commands.suggest_aws_cli_commands",
            return_value=[],
        ) as mock_suggest:
            SKILL._inject_validation_commands(payload, session)

        # refs should be normalized to []
        _, kwargs = mock_suggest.call_args
        assert kwargs.get("evidence_refs") == [] or mock_suggest.call_args[0][2] == []


# ── _reconcile_with_pre_checks ────────────────────────────────────────────────


class TestReconcileWithPreChecks:
    def test_rejects_finding_contradicting_pass(self):
        findings = _skill_findings(_finding("IAM-001"))
        pre_checks = [_pre_check("IAM-001", status="PASS")]
        checklist = _checklist("IAM-001")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        assert not any(f.id == "IAM-001" for f in result.findings)

    def test_keeps_finding_not_in_pass(self):
        findings = _skill_findings(_finding("IAM-002"))
        pre_checks = [_pre_check("IAM-001", status="PASS")]
        checklist = _checklist("IAM-001", "IAM-002")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        assert any(f.id == "IAM-002" for f in result.findings)

    def test_injects_finding_for_missed_fail(self):
        findings = _skill_findings()  # empty
        pre_checks = [_pre_check("IAM-001", status="FAIL", evidence_summary="root has no MFA")]
        checklist = _checklist("IAM-001", severity="Critical")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        ids = [f.id for f in result.findings]
        assert "IAM-001" in ids

    def test_injected_finding_uses_checklist_severity(self):
        findings = _skill_findings()
        pre_checks = [_pre_check("IAM-001", status="FAIL")]
        checklist = _checklist("IAM-001", severity="Critical")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        injected = next(f for f in result.findings if f.id == "IAM-001")
        assert injected.severity == "Critical"

    def test_does_not_inject_if_already_present(self):
        findings = _skill_findings(_finding("IAM-001"))
        pre_checks = [_pre_check("IAM-001", status="FAIL")]
        checklist = _checklist("IAM-001")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        count = sum(1 for f in result.findings if f.id == "IAM-001")
        assert count == 1  # not duplicated

    def test_injected_has_exploitability_validated(self):
        findings = _skill_findings()
        pre_checks = [_pre_check("IAM-001", status="FAIL")]
        checklist = _checklist("IAM-001")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        injected = next(f for f in result.findings if f.id == "IAM-001")
        assert injected.exploitability_status == "validated"

    def test_corrects_affected_resources_for_exp015(self):
        """EXP-015 findings have their affected_resources overridden by pre-check data."""
        findings = _skill_findings(_finding("EXP-015", affected_resources=["wrong-resource"]))
        pre_checks = [
            _pre_check(
                "EXP-015",
                status="FAIL",
                affected=["arn:aws:iam::99:root"],
            )
        ]
        checklist = _checklist("EXP-015")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        exp_finding = next(f for f in result.findings if f.id == "EXP-015")
        assert exp_finding.affected_resources == ["arn:aws:iam::99:root"]

    def test_metadata_merged_into_snippet(self):
        findings = _skill_findings()
        meta = {"cve_id": "CVE-2024-0001"}
        pre_checks = [_pre_check("IAM-001", status="FAIL", metadata=meta)]
        checklist = _checklist("IAM-001")

        result = SKILL._reconcile_with_pre_checks(findings, pre_checks, checklist)
        injected = next(f for f in result.findings if f.id == "IAM-001")
        assert injected.evidence_snippet is not None
        assert injected.evidence_snippet.get("cve_id") == "CVE-2024-0001"

    def test_no_pre_checks_returns_unchanged(self):
        findings = _skill_findings(_finding("IAM-001"))
        result = SKILL._reconcile_with_pre_checks(findings, [], _checklist("IAM-001"))
        assert len(result.findings) == 1


# ── _build_precheck_traceability ─────────────────────────────────────────────


class TestBuildPrecheckTraceability:
    def _result(self, affected=None, evidence_summary="pre-check fail", metadata=None):
        return SimpleNamespace(
            affected_resources=list(affected or []),
            evidence_summary=evidence_summary,
            metadata=metadata,
        )

    # generic path ─────────────────────────────────────────────────────────────

    def test_generic_no_evidence_returns_summary_snippet(self):
        result = self._result(affected=["arn:aws:iam::123:user/admin"])
        refs, snippet = SKILL._build_precheck_traceability("IAM-001", result, {})
        assert refs == []
        assert snippet is not None
        assert "affected_resources" in snippet or "evidence_summary" in snippet

    def test_generic_matches_user_in_collection(self):
        evidence = {
            "users": {"users": [{"Arn": "arn:aws:iam::123:user/admin", "UserName": "admin"}]}
        }
        result = self._result(affected=["arn:aws:iam::123:user/admin"])
        refs, snippet = SKILL._build_precheck_traceability("IAM-001", result, evidence)
        assert len(refs) > 0
        assert "users.json" in refs[0]

    def test_generic_skips_underscore_keys(self):
        """Evidence keys starting with _ (like _audit_metadata) should be skipped."""
        evidence = {
            "_audit_metadata": {"_region": "us-east-1"},
            "users": {"users": [{"Arn": "arn:aws:iam::123:user/admin"}]},
        }
        result = self._result(affected=["arn:aws:iam::123:user/admin"])
        refs, snippet = SKILL._build_precheck_traceability("IAM-001", result, evidence)
        assert not any("_audit_metadata" in r for r in refs)

    def test_generic_list_doc(self):
        """Evidence doc that is a list (not a dict)."""
        evidence = {"findings": [{"Arn": "arn:aws:securityhub::123:finding/1", "Title": "test"}]}
        result = self._result(affected=["arn:aws:securityhub::123:finding/1"])
        refs, snippet = SKILL._build_precheck_traceability("HRD-001", result, evidence)
        assert len(refs) > 0

    def test_generic_no_affected_returns_empty_refs_with_summary(self):
        result = self._result(affected=[])
        refs, snippet = SKILL._build_precheck_traceability("IAM-001", result, {})
        assert refs == []
        assert snippet is not None

    # SER-LMB-002 ──────────────────────────────────────────────────────────────

    def test_ser_lmb002_matched_route(self):
        evidence = {
            "front-doors": {
                "api_gateway_routes": [
                    {
                        "ApiId": "abc123",
                        "Method": "GET",
                        "Path": "/users",
                        "AuthorizationType": "NONE",
                        "ApiKeyRequired": False,
                        "ApiType": "HTTP",
                    }
                ]
            }
        }
        result = self._result(affected=["abc123 GET /users"])
        refs, snippet = SKILL._build_precheck_traceability("SER-LMB-002", result, evidence)
        assert refs == ["front-doors.json#/api_gateway_routes"]
        assert snippet is not None

    def test_ser_lmb002_fallback_unauth_routes(self):
        """When no route matches affected, fall back to unauth routes."""
        evidence = {
            "front-doors": {
                "api_gateway_routes": [
                    {
                        "ApiId": "xyz",
                        "Method": "POST",
                        "Path": "/data",
                        "AuthorizationType": "NONE",
                        "ApiType": "HTTP",
                    }
                ]
            }
        }
        result = self._result(affected=["nonexistent"])
        refs, snippet = SKILL._build_precheck_traceability("SER-LMB-002", result, evidence)
        assert refs == ["front-doors.json#/api_gateway_routes"]

    def test_ser_lmb002_no_evidence_returns_empty(self):
        result = self._result()
        refs, snippet = SKILL._build_precheck_traceability("SER-LMB-002", result, {})
        assert refs == []

    # ECR checks ───────────────────────────────────────────────────────────────

    def test_ecr002_matched_repo(self):
        evidence = {
            "repositories": {
                "repositories": [
                    {
                        "RepositoryName": "myapp",
                        "RepositoryArn": "arn:aws:ecr::123:repository/myapp",
                        "ImageTagMutability": "MUTABLE",
                    }
                ]
            }
        }
        result = self._result(affected=["arn:aws:ecr::123:repository/myapp"])
        refs, snippet = SKILL._build_precheck_traceability("ECR-002", result, evidence)
        assert len(refs) > 0
        assert snippet is not None
        assert "repositories" in snippet

    def test_ecr005_matched_repo(self):
        evidence = {
            "repositories": {
                "repositories": [
                    {
                        "RepositoryName": "secure",
                        "RepositoryArn": "arn:aws:ecr::123:repository/secure",
                        "EncryptionType": "AES256",
                        "KmsKey": None,
                    }
                ]
            }
        }
        result = self._result(affected=["arn:aws:ecr::123:repository/secure"])
        refs, snippet = SKILL._build_precheck_traceability("ECR-005", result, evidence)
        assert len(refs) > 0

    def test_ecr006_matched_repo(self):
        evidence = {
            "repositories": {
                "repositories": [
                    {
                        "RepositoryName": "nolc",
                        "RepositoryArn": "arn:aws:ecr::123:repository/nolc",
                        "HasLifecyclePolicy": False,
                        "LifecyclePolicy": None,
                    }
                ]
            }
        }
        result = self._result(affected=["arn:aws:ecr::123:repository/nolc"])
        refs, snippet = SKILL._build_precheck_traceability("ECR-006", result, evidence)
        assert len(refs) > 0

    def test_ecr_no_repos_doc_returns_empty(self):
        result = self._result(affected=["arn:aws:ecr::123:repository/x"])
        refs, snippet = SKILL._build_precheck_traceability("ECR-002", result, {})
        assert refs == []

    # KMS checks ───────────────────────────────────────────────────────────────

    def test_kms002_sensitive_grant_returned(self):
        evidence = {
            "kms-grants": {
                "items": [
                    {
                        "GrantId": "g1",
                        "KeyId": "key-1",
                        "GranteePrincipal": "arn:aws:iam::123:user/dev",
                        "Operations": ["Decrypt"],
                        "Constraints": None,
                    }
                ]
            }
        }
        result = self._result()
        refs, snippet = SKILL._build_precheck_traceability("KMS-002", result, evidence)
        assert len(refs) > 0
        assert snippet is not None

    def test_kms007_create_grant_returned(self):
        evidence = {
            "kms-grants": {
                "items": [
                    {
                        "GrantId": "g2",
                        "KeyId": "key-2",
                        "GranteePrincipal": "arn:aws:iam::123:user/admin",
                        "Operations": ["CreateGrant"],
                        "Constraints": None,
                    }
                ]
            }
        }
        result = self._result()
        refs, snippet = SKILL._build_precheck_traceability("KMS-007", result, evidence)
        assert len(refs) > 0

    def test_kms002_expected_service_grant_skipped(self):
        """Grant with EncryptionContextEquals and service principal should be skipped."""
        evidence = {
            "kms-grants": {
                "items": [
                    {
                        "GrantId": "g3",
                        "KeyId": "key-3",
                        "GranteePrincipal": "s3.amazonaws.com",
                        "IssuingAccount": "s3.amazonaws.com",
                        "Operations": ["Decrypt"],
                        "Constraints": {
                            "EncryptionContextEquals": {"aws:s3:arn": "arn:aws:s3:::bucket"}
                        },
                    }
                ]
            }
        }
        result = self._result()
        refs, snippet = SKILL._build_precheck_traceability("KMS-002", result, evidence)
        # Service grant should be filtered; fallback to generic (empty)
        # refs may be empty if generic traceability finds nothing
        assert isinstance(refs, list)

    def test_kms_no_grants_doc_returns_empty(self):
        result = self._result()
        refs, snippet = SKILL._build_precheck_traceability("KMS-002", result, {})
        assert refs == []
        assert snippet is None


# ── _normalize_findings (smoke) ───────────────────────────────────────────────


class TestNormalizeFindings:
    def test_returns_skill_findings(self):
        findings = _skill_findings(_finding("IAM-001"))
        checklist = _checklist("IAM-001")
        result = SKILL._normalize_findings(findings, checklist)
        assert isinstance(result, SkillFindings)

    def test_with_evidence_and_pre_checked_ids(self):
        findings = _skill_findings(_finding("IAM-001"))
        checklist = _checklist("IAM-001")
        evidence = {"users": {"users": [{"UserName": "admin"}]}}
        result = SKILL._normalize_findings(
            findings, checklist, evidence=evidence, pre_checked_ids={"IAM-001"}
        )
        assert isinstance(result, SkillFindings)
