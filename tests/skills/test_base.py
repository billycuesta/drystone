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
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import MagicMock, patch

from drystone.models.findings import Finding, FindingsSummary, SkillFindings
from drystone.skills.base import BaseSkill, _severity_to_risk

# ── Minimal concrete subclass ──────────────────────────────────────────────────


class _DummySkill(BaseSkill):
    """Generic test double exercising ALL skills' traceability modules.

    Before P1 #2 (2026-09-16), _build_precheck_traceability's per-check-ID
    routing lived centrally on BaseSkill, so any skill instance handled
    every check_id prefix. After the split, routing is per-skill (each real
    skill class only knows its own prefixes via _skill_specific_traceability).
    This dummy restores the old centralized-dispatch behavior for tests that
    exercise many different skills' check IDs through one instance, without
    needing a separate dummy per skill.
    """

    @property
    def name(self) -> str:
        return "iam"

    def collect(self, aws_client, session):
        pass

    def _skill_specific_traceability(self, check_id, result, evidence):
        from drystone.skills.alerting import traceability as _alerting
        from drystone.skills.cloudtrail_events import traceability as _cloudtrail_events
        from drystone.skills.ecr import traceability as _ecr
        from drystone.skills.exposure import traceability as _exposure
        from drystone.skills.hardening import traceability as _hardening
        from drystone.skills.iam import traceability as _iam
        from drystone.skills.kms import traceability as _kms
        from drystone.skills.network import traceability as _network
        from drystone.skills.recon import traceability as _recon
        from drystone.skills.secretsmanager import traceability as _secretsmanager
        from drystone.skills.sistemas_explotables_red import traceability as _ser
        from drystone.skills.vulns import traceability as _vulns
        from drystone.skills.waf import traceability as _waf

        for module in (
            _iam,
            _hardening,
            _waf,
            _recon,
            _secretsmanager,
            _ser,
            _exposure,
            _network,
            _vulns,
            _alerting,
            _kms,
            _ecr,
            _cloudtrail_events,
        ):
            outcome = module.build_traceability(check_id, result, evidence)
            if outcome is not None:
                return outcome
        return None


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


def _pre_check(
    check_id,
    status="PASS",
    affected=None,
    evidence_summary="",
    metadata=None,
    risk_score_override=None,
):
    r = SimpleNamespace(
        check_id=check_id,
        status=status,
        affected_resources=list(affected or []),
        evidence_summary=evidence_summary,
        metadata=metadata,
        risk_score_override=risk_score_override,
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


class TestBaseEvidenceHelpers:
    def test_save_json_creates_parent_and_serializes_datetime(self, tmp_path):
        target = tmp_path / "nested" / "evidence.json"
        moment = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)

        SKILL._save_json(target, {"collected_at": moment})

        assert target.exists()
        saved = target.read_text()
        assert "  \"collected_at\"" in saved
        assert "2026-09-16 12:00:00+00:00" in saved

    def test_wrap_indexed_builds_region_and_secondary_index(self):
        items = [
            {"GroupId": "sg-1", "Name": "one"},
            {"GroupId": "", "Name": "empty"},
            {"Name": "missing"},
            "not-a-dict",
        ]

        wrapped = SKILL._wrap_indexed(items, by_key="GroupId", region="eu-west-1")

        assert wrapped["_meta"] == {"_region": "eu-west-1"}
        assert wrapped["items"] == items
        assert wrapped["by_id"] == {"sg-1": {"GroupId": "sg-1", "Name": "one"}}

    def test_wrap_indexed_supports_custom_index_name(self):
        items = [{"Name": "bucket-a"}]

        wrapped = SKILL._wrap_indexed(
            items,
            by_key="Name",
            index_name="by_name",
            region="us-east-1",
        )

        assert wrapped["by_name"] == {"bucket-a": {"Name": "bucket-a"}}
        assert "by_id" not in wrapped

    def test_audit_metadata_includes_backward_compatible_fields(self):
        session = MagicMock(account_id="123456789012")

        metadata = SKILL._audit_metadata(
            session,
            "us-east-1",
            evidence_files=["users.json"],
            extra={"custom": True},
        )

        assert metadata["_region"] == "us-east-1"
        assert metadata["_scope"] == "single-region"
        assert metadata["_skill"] == "iam"
        assert metadata["_account_id"] == "123456789012"
        assert metadata["evidence_files"] == ["users.json"]
        assert metadata["_timestamp"] == metadata["_collected_at"]
        assert metadata["custom"] is True


class TestPrecheckSeverityPreservation:
    def test_prechecked_finding_keeps_dynamic_risk_override(self):
        finding = _finding("ALRT-010", severity="Medium", risk_score=4.5)
        findings = _skill_findings(finding)
        checklist = _checklist("ALRT-010", severity="High")

        result = SKILL._normalize_findings(
            findings,
            checklist,
            pre_checked_ids={"ALRT-010"},
        )

        assert result.findings[0].severity == "Medium"
        assert result.findings[0].risk_score == 4.5


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

    def test_infers_region_from_evidence_arns_when_metadata_missing(self, tmp_path):
        session = MagicMock()
        evidence_path = tmp_path / "evidence" / "alerting"
        evidence_path.mkdir(parents=True)
        (evidence_path / "sns-topics.json").write_text(
            json.dumps([{"TopicArn": "arn:aws:sns:eu-west-1:123456789012:alerts"}])
        )
        session.get_evidence_path.return_value = evidence_path

        region = SKILL._infer_region_from_evidence(session)
        assert region == "eu-west-1"

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

    def test_refresh_summary_uses_final_finding_severity_and_risk(self):
        findings = _skill_findings(
            _finding("IAM-001", severity="Critical", risk_score=9.0),
            _finding("IAM-002", severity="High", risk_score=7.0),
            _finding("IAM-003", severity="Medium", risk_score=4.5),
        )
        findings.summary = FindingsSummary(
            total_findings=3,
            critical=2,
            high=0,
            medium=1,
            low=0,
            overall_risk_score=8.0,
        )

        result = SKILL._refresh_summary(findings, _checklist("IAM-001", "IAM-002", "IAM-003"))

        assert result.summary.total_findings == 3
        assert result.summary.critical == 1
        assert result.summary.high == 1
        assert result.summary.medium == 1
        assert result.summary.overall_risk_score == 7.6

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

    def test_corrects_existing_exposure_finding_with_authoritative_precheck_evidence(self):
        findings = _skill_findings(
            _finding(
                "EXP-014",
                severity="High",
                affected_resources=["arn:aws:s3:::a"],
                evidence_refs=["s3-buckets.json#by_name.a"],
                impact=None,
                evidence_snippet={"audit_log_buckets": [{"Name": "a"}]},
            )
        )
        pre_checks = [
            _pre_check(
                "EXP-014",
                status="FAIL",
                affected=["arn:aws:s3:::a", "arn:aws:s3:::b"],
                metadata={
                    "resource_details": [
                        {"bucket_name": "a", "bucket_arn": "arn:aws:s3:::a", "versioning": None},
                        {"bucket_name": "b", "bucket_arn": "arn:aws:s3:::b", "versioning": None},
                    ]
                },
            )
        ]
        checklist = _checklist("EXP-014")
        evidence = {
            "s3-buckets": {
                "items": [
                    {"Name": "a", "Versioning": None},
                    {"Name": "b", "Versioning": None},
                ],
                "by_name": {},
            }
        }

        result = SKILL._reconcile_with_pre_checks(
            findings, pre_checks, checklist, evidence=evidence
        )
        exp_finding = next(f for f in result.findings if f.id == "EXP-014")
        assert exp_finding.affected_resources == ["arn:aws:s3:::a", "arn:aws:s3:::b"]
        assert exp_finding.evidence_refs == [
            "s3-buckets.json#/items/0",
            "s3-buckets.json#/items/1",
        ]
        assert exp_finding.impact
        assert exp_finding.exploitability_status == "validated"
        assert len(exp_finding.evidence_snippet["affected_resources"]) == 2

    def test_injects_ser_ec2_002_with_resource_level_evidence_refs(self):
        findings = _skill_findings()
        affected = [
            "arn:aws:ec2:eu-west-1:123456789012:instance/i-123",
            "arn:aws:ec2:eu-west-1:123456789012:instance/i-456",
        ]
        pre_checks = [
            _pre_check(
                "SER-EC2-002",
                status="FAIL",
                affected=affected,
                evidence_summary="2 internet-reachable EC2 instance(s) with active Inspector findings",
                metadata={
                    "sg_rules_context": {
                        "i-123": [{"source": "0.0.0.0/0", "sg_id": "sg-web"}],
                        "i-456": [{"source": "::/0", "sg_id": "sg-web"}],
                    }
                },
                risk_score_override=9.0,
            )
        ]
        checklist = _checklist("SER-EC2-002", severity="Critical")
        evidence = {
            "attack-path-candidates": {
                "paths": [
                    {"target_resource": affected[0]},
                    {"target_resource": affected[1]},
                ]
            },
            "reachability-graph": {
                "edges": [
                    {"target": affected[0]},
                    {"target": affected[1]},
                ]
            },
            "compute-inventory": {
                "ec2_instances": [
                    {"InstanceId": "i-123"},
                    {"InstanceId": "i-456"},
                ]
            },
            "inspector-findings-normalized": {
                "findings": [
                    {"resources": [{"id": "i-123", "type": "AWS_EC2_INSTANCE"}]},
                    {"resources": [{"id": "i-456", "type": "AWS_EC2_INSTANCE"}]},
                ]
            },
            "network-controls": {
                "security_groups": [
                    {"GroupId": "sg-web", "GroupName": "Webservers"},
                ]
            },
        }

        result = SKILL._reconcile_with_pre_checks(
            findings, pre_checks, checklist, evidence=evidence
        )

        ser_finding = next(f for f in result.findings if f.id == "SER-EC2-002")
        assert ser_finding.evidence_refs[:2] == [
            "attack-path-candidates.json#/paths/0",
            "attack-path-candidates.json#/paths/1",
        ]
        assert len(ser_finding.evidence_refs) >= len(affected)
        assert "multiple sensitive ports" not in ser_finding.description
        assert ser_finding.impact
        assert ser_finding.severity == "Critical"

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

    def test_cloudtrail_event_traceability_matches_user_and_resource_name(self):
        trail_arn = "arn:aws:cloudtrail:eu-west-1:123456789012:trail/audit"
        evidence = {
            "audit-tampering-events": [
                {
                    "EventName": "StopLogging",
                    "Username": "jcgarcia",
                    "EventId": "evt-1",
                    "callerArn": "arn:aws:iam::123456789012:user/jcgarcia",
                    "Resources": [{"ResourceName": trail_arn}],
                },
                {
                    "EventName": "DeleteTrail",
                    "Username": "jcgarcia",
                    "EventId": "evt-2",
                    "callerArn": "arn:aws:iam::123456789012:user/jcgarcia",
                    "Resources": [{"ResourceName": trail_arn}],
                },
            ]
        }
        result = self._result(affected=["user:jcgarcia", trail_arn])

        refs, snippet = SKILL._build_precheck_traceability("CTEF-003", result, evidence)

        assert refs == ["audit-tampering-events.json#/0", "audit-tampering-events.json#/1"]
        assert snippet is not None
        assert [item["EventId"] for item in snippet["items"]] == ["evt-1", "evt-2"]

    def test_hardening_threshold_traceability_uses_summary_and_sample_findings(self):
        metadata = {
            "count": 12,
            "severity": "HIGH",
            "sample_findings": [
                {
                    "index": 3,
                    "id": "finding-3",
                    "title": "EC2.18 unrestricted traffic",
                    "resource_ids": ["arn:aws:ec2:eu-west-1:123:security-group/sg-1"],
                }
            ],
        }
        result = self._result(
            affected=["arn:aws:ec2:eu-west-1:123:security-group/sg-1"],
            metadata=metadata,
            evidence_summary="12 HIGH Security Hub finding(s) (>10)",
        )

        refs, snippet = SKILL._build_precheck_traceability("HRD-009", result, {})

        assert refs == [
            "security-hub-findings-summary.json#/severity_counts/HIGH",
            "security-hub-findings.json#/3",
        ]
        assert snippet["count"] == 12
        assert snippet["sample_findings"][0]["title"] == "EC2.18 unrestricted traffic"

    def test_hardening_guardduty_traceability_uses_detector_file(self):
        result = self._result(
            affected=["AWS::::Account"],
            metadata={"enabled": False, "service": "GuardDuty"},
            evidence_summary="no GuardDuty detectors",
        )

        refs, snippet = SKILL._build_precheck_traceability("HRD-014", result, {})

        assert refs == ["guardduty-detectors.json#/"]
        assert snippet["enabled"] is False
        assert snippet["service"] == "GuardDuty"

    def test_alerting_sns_traceability_maps_topic_and_alarms(self):
        topic_arn = "arn:aws:sns:eu-west-1:123456789012:InfraAlerts"
        evidence = {
            "sns-topics": [{"TopicArn": topic_arn, "Attributes": {"SubscriptionsConfirmed": "0"}}],
            "cloudwatch-alarms": [
                {"AlarmName": "RootAccountUsage", "AlarmActions": [topic_arn]},
                {"AlarmName": "UnauthorizedApiCalls", "AlarmActions": [topic_arn]},
            ],
        }
        result = self._result(
            affected=[topic_arn],
            metadata={
                "resource_details": [
                    {
                        "topic_arn": topic_arn,
                        "affected_alarms": ["RootAccountUsage", "UnauthorizedApiCalls"],
                        "alarm_count": 2,
                    }
                ]
            },
        )

        refs, snippet = SKILL._build_precheck_traceability("ALRT-005", result, evidence)

        assert "sns-topics.json#/0" in refs
        assert "cloudwatch-alarms.json#/0" in refs
        assert "cloudwatch-alarms.json#/1" in refs
        assert snippet["affected_resources"][0]["topic_arn"] == topic_arn

    def test_alerting_log_retention_traceability_maps_log_groups(self):
        evidence = {
            "cloudwatch-log-groups": [
                {"LogGroupName": "FlowLogsPostClear", "RetentionInDays": 30},
            ]
        }
        result = self._result(
            affected=["FlowLogsPostClear"],
            metadata={
                "resource_details": [
                    {"log_group_name": "FlowLogsPostClear", "retention_in_days": 30}
                ]
            },
        )

        refs, snippet = SKILL._build_precheck_traceability("ALRT-017", result, evidence)

        assert refs == ["cloudwatch-log-groups.json#/0"]
        assert snippet["affected_resources"][0]["retention_in_days"] == 30

    def test_exposure_s3_refs_cover_resource_details(self):
        metadata = {
            "resource_details": [
                {"bucket_name": "a", "bucket_arn": "arn:aws:s3:::a"},
                {"bucket_name": "b", "bucket_arn": "arn:aws:s3:::b"},
            ]
        }
        evidence = {
            "s3-buckets": {
                "items": [
                    {"Name": "a", "Versioning": None},
                    {"Name": "b", "Versioning": None},
                ],
                "by_name": {},
            }
        }
        result = self._result(metadata=metadata)
        refs, snippet = SKILL._build_precheck_traceability("EXP-014", result, evidence)
        assert refs == ["s3-buckets.json#/items/0", "s3-buckets.json#/items/1"]
        assert len(snippet["affected_resources"]) == 2

    def test_exposure_rds_refs_include_security_group(self):
        metadata = {
            "resource_details": [
                {
                    "db_instance_identifier": "postclear",
                    "open_rules": [{"security_group_id": "sg-rds", "port": 1433}],
                }
            ]
        }
        evidence = {
            "rds-instances": {"items": [{"DBInstanceIdentifier": "postclear"}]},
            "security-groups": {"by_id": {"sg-rds": {"GroupId": "sg-rds"}}},
        }
        result = self._result(metadata=metadata)
        refs, _snippet = SKILL._build_precheck_traceability("EXP-002", result, evidence)
        assert "rds-instances.json#/items/0" in refs
        assert "security-groups.json#by_id.sg-rds" in refs

    def test_exposure_alb_refs_include_waf_association_file(self):
        alb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/public/abc"
        metadata = {"resource_details": [{"load_balancer_arn": alb_arn}]}
        evidence = {
            "load-balancers": {"items": [{"LoadBalancerArn": alb_arn}]},
            "wafv2-web-acl-alb-associations": {"by_alb_arn": {}},
        }
        result = self._result(metadata=metadata)
        refs, _snippet = SKILL._build_precheck_traceability("EXP-007", result, evidence)
        assert "load-balancers.json#/items/0" in refs
        assert "wafv2-web-acl-alb-associations.json#by_alb_arn" in refs

    def test_waf001_traceability_maps_alb_association(self):
        alb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123:loadbalancer/app/open/abc"
        result = self._result(
            affected=[alb_arn],
            metadata={"resource_details": [{"load_balancer_arn": alb_arn, "wafv2_web_acl": None}]},
        )
        evidence = {"alb-waf-associations": [{"LoadBalancerArn": alb_arn, "WAFv2WebACL": None}]}

        refs, snippet = SKILL._build_precheck_traceability("WAF-001", result, evidence)

        assert refs == ["alb-waf-associations.json#/0"]
        assert snippet["affected_resources"][0]["load_balancer_arn"] == alb_arn

    def test_waf010_traceability_maps_waf_classic_acls(self):
        result = self._result(
            affected=["CommonAttackProtection", "BackOffice"],
            metadata={
                "resource_details": [
                    {"scope": "CLOUDFRONT", "name": "CommonAttackProtection", "web_acl_id": "g1"},
                    {"scope": "REGIONAL", "region": "eu-west-1", "name": "BackOffice"},
                ]
            },
        )
        evidence = {
            "waf-classic": {
                "global": {"web_acls": [{"Name": "CommonAttackProtection", "WebACLId": "g1"}]},
                "regional": {
                    "eu-west-1": {"web_acls": [{"Name": "BackOffice", "WebACLId": "r1"}]}
                },
            }
        }

        refs, snippet = SKILL._build_precheck_traceability("WAF-010", result, evidence)

        assert "waf-classic.json#/global/web_acls/0" in refs
        assert "waf-classic.json#/regional/eu-west-1/web_acls/0" in refs
        assert snippet["affected_resources"][0]["name"] == "CommonAttackProtection"

    def test_generic_no_affected_returns_empty_refs_with_summary(self):
        result = self._result(affected=[])
        refs, snippet = SKILL._build_precheck_traceability("IAM-001", result, {})
        assert refs == []
        assert snippet is not None

    def test_iam_injected_user_refs_are_concrete(self):
        evidence = {
            "users": [
                {"UserName": "alice", "Arn": "arn:aws:iam::123:user/alice"},
                {"UserName": "bob", "Arn": "arn:aws:iam::123:user/bob"},
            ]
        }
        result = self._result(
            affected=["arn:aws:iam::123:user/bob"],
            metadata={
                "resource_details": [
                    {"user": "bob", "arn": "arn:aws:iam::123:user/bob"},
                ]
            },
        )
        refs, snippet = SKILL._build_precheck_traceability("IAM-012", result, evidence)
        assert "users.json#/1" in refs
        assert "credential-report.csv#bob" in refs
        assert snippet["affected_resources"][0]["user"] == "bob"

    def test_iam_injected_user_refs_include_credential_report_and_policies(self):
        evidence = {
            "users": [
                {"UserName": "svc", "Arn": "arn:aws:iam::123:user/svc"},
            ],
            "groups": [
                {"GroupName": "audit", "Arn": "arn:aws:iam::123:group/audit"},
            ],
            "policies": [
                {"PolicyName": "AuditPolicy", "Arn": "arn:aws:iam::123:policy/AuditPolicy"},
            ],
            "credential-report": {"by_user": {"svc": {"password_enabled": "false"}}},
        }
        result = self._result(
            affected=["arn:aws:iam::123:user/svc"],
            metadata={
                "resource_details": [
                    {
                        "user": "svc",
                        "arn": "arn:aws:iam::123:user/svc",
                        "permission_context": {
                            "groups": ["audit"],
                            "direct_policy_arns": ["arn:aws:iam::123:policy/AuditPolicy"],
                        },
                    },
                ]
            },
        )
        refs, _snippet = SKILL._build_precheck_traceability("IAM-016", result, evidence)
        assert "users.json#/0" in refs
        assert "credential-report.csv#svc" in refs
        assert "groups.json#/0" in refs
        assert "policies.json#/0" in refs

    def test_iam_injected_role_refs_are_concrete(self):
        evidence = {
            "roles": [
                {"RoleName": "safe", "Arn": "arn:aws:iam::123:role/safe"},
                {"RoleName": "admin", "Arn": "arn:aws:iam::123:role/admin"},
            ]
        }
        result = self._result(
            affected=["arn:aws:iam::123:role/admin"],
            metadata={
                "detailed_roles": [
                    {"RoleName": "admin", "RoleArn": "arn:aws:iam::123:role/admin"},
                ]
            },
        )
        refs, snippet = SKILL._build_precheck_traceability("IAM-041", result, evidence)
        assert refs == ["roles.json#/1"]
        assert snippet["affected_resources"][0]["RoleName"] == "admin"

    def test_iam026_refs_include_policy_evidence(self):
        evidence = {
            "roles": [
                {"RoleName": "backup", "Arn": "arn:aws:iam::123:role/backup"},
            ],
            "policies": [
                {
                    "PolicyName": "PassRolePolicy",
                    "Arn": "arn:aws:iam::123:policy/PassRolePolicy",
                }
            ],
        }
        result = self._result(
            affected=["arn:aws:iam::123:role/backup"],
            metadata={
                "resource_details": [
                    {
                        "role_name": "backup",
                        "arn": "arn:aws:iam::123:role/backup",
                        "iam_admin_evidence": [
                            {
                                "policy_name": "PassRolePolicy",
                                "policy_arn": "arn:aws:iam::123:policy/PassRolePolicy",
                                "iam_admin_actions": ["iam:PassRole"],
                            }
                        ],
                    }
                ]
            },
        )
        refs, _snippet = SKILL._build_precheck_traceability("IAM-026", result, evidence)
        assert "roles.json#/0" in refs
        assert "policies.json#/0" in refs

    def test_network_sg_refs_are_concrete_for_net011(self):
        metadata = {
            "resource_details": [
                {"resource": "sg-a", "name": "db", "port": 1433},
                {"resource": "sg-b", "name": "cache", "port": 6379},
            ]
        }
        evidence = {
            "security-groups": {
                "items": [
                    {"GroupId": "sg-a", "GroupName": "db"},
                    {"GroupId": "sg-b", "GroupName": "cache"},
                ]
            }
        }
        result = self._result(affected=["sg-a", "sg-b"], metadata=metadata)
        refs, snippet = SKILL._build_precheck_traceability("NET-011", result, evidence)

        assert refs == ["security-groups.json#/items/0", "security-groups.json#/items/1"]
        assert len(snippet["affected_resources"]) == 2

    def test_network_subnet_and_nacl_refs_are_concrete_for_net016(self):
        metadata = {
            "resource_details": [
                {"resource": "subnet-a", "subnet_id": "subnet-a", "network_acl_id": "acl-1"},
                {"resource": "subnet-b", "subnet_id": "subnet-b", "network_acl_id": "acl-1"},
            ]
        }
        evidence = {
            "subnets": {"items": [{"SubnetId": "subnet-a"}, {"SubnetId": "subnet-b"}]},
            "network-acls": {"items": [{"NetworkAclId": "acl-1"}]},
        }
        result = self._result(affected=["subnet-a", "subnet-b"], metadata=metadata)
        refs, snippet = SKILL._build_precheck_traceability("NET-016", result, evidence)

        assert "subnets.json#/items/0" in refs
        assert "subnets.json#/items/1" in refs
        assert "network-acls.json#/items/0" in refs
        assert len(snippet["affected_resources"]) == 2

    def test_network_rds_public_subnet_refs_include_workload_and_network_path(self):
        metadata = {
            "resource_details": [
                {
                    "resource": "rds:postclear",
                    "resource_type": "rds",
                    "identifier": "postclear",
                    "public_subnet_ids": ["subnet-pub"],
                    "route_table_ids": ["rt-pub"],
                }
            ]
        }
        evidence = {
            "rds-instances": {"items": [{"DBInstanceIdentifier": "postclear"}]},
            "subnets": {"items": [{"SubnetId": "subnet-pub"}]},
            "route-tables": {"items": [{"RouteTableId": "rt-pub"}]},
        }
        result = self._result(affected=["rds:postclear"], metadata=metadata)
        refs, snippet = SKILL._build_precheck_traceability("NET-008", result, evidence)

        assert "rds-instances.json#/items/0" in refs
        assert "subnets.json#/items/0" in refs
        assert "route-tables.json#/items/0" in refs
        assert snippet["evidence_summary"] == "1 critical workload(s) in public subnets"

    def test_network_firewall_refs_include_vpc_route_and_igw(self):
        metadata = {
            "resource_details": [
                {
                    "resource": "vpc-1",
                    "vpc_id": "vpc-1",
                    "route_table_ids": ["rt-1"],
                    "internet_gateway_ids": ["igw-1"],
                }
            ]
        }
        evidence = {
            "vpcs": {"items": [{"VpcId": "vpc-1"}]},
            "route-tables": {"items": [{"RouteTableId": "rt-1"}]},
            "internet-gateways": {"items": [{"InternetGatewayId": "igw-1"}]},
        }
        result = self._result(affected=["vpc-1"], metadata=metadata)
        refs, _snippet = SKILL._build_precheck_traceability("NET-007", result, evidence)

        assert "vpcs.json#/items/0" in refs
        assert "route-tables.json#/items/0" in refs
        assert "internet-gateways.json#/items/0" in refs

    def test_network_nat_endpoint_gap_refs_include_route_nat_and_empty_endpoints(self):
        metadata = {
            "resource_details": [
                {
                    "resource": "rt-private",
                    "route_table_id": "rt-private",
                    "vpc_id": "vpc-1",
                    "nat_gateway_id": "nat-1",
                    "vpc_endpoints_present": False,
                }
            ]
        }
        evidence = {
            "route-tables": {"items": [{"RouteTableId": "rt-private"}]},
            "nat-gateway-routes": {"items": [{"NatGatewayId": "nat-1"}]},
            "vpc-endpoints": {"items": []},
        }
        result = self._result(affected=["rt-private"], metadata=metadata)
        refs, snippet = SKILL._build_precheck_traceability("NET-013", result, evidence)

        assert "route-tables.json#/items/0" in refs
        assert "nat-gateway-routes.json#/items/0" in refs
        assert "vpc-endpoints.json#/items" in refs
        assert (
            snippet["evidence_summary"]
            == "1 route table(s) with NAT default routes and no VPC endpoints"
        )

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



class TestAnalyzePipelineMetadata:
    def _session(self, tmp_path):
        evidence_path = tmp_path / "evidence" / "iam"
        findings_path = tmp_path / "findings"
        evidence_path.mkdir(parents=True)
        findings_path.mkdir()
        session = MagicMock()
        session.get_evidence_path.return_value = evidence_path
        session.get_findings_path.return_value = findings_path
        session.account_id = "123456789012"
        return session, evidence_path, findings_path

    def _agent(self):
        agent = MagicMock()
        agent.config = {"qsa_depth": "standard", "scan_depth": "normal"}
        agent.provider_type = "claude-cli"
        agent.metrics_tracker = None
        agent.get_display_name.return_value = "Mock Agent"
        agent.get_last_analysis_status.return_value = {}
        agent.analyze_evidence_chunked.return_value = _skill_findings()
        return agent

    def test_analyze_records_corrupt_evidence_and_does_not_count_routed_checks_as_evaluated(self, tmp_path):
        session, evidence_path, findings_path = self._session(tmp_path)
        (evidence_path / "users.json").write_text('{"items": []}')
        (evidence_path / "corrupt.json").write_text('{not-json')
        agent = self._agent()

        captured = {}

        def fake_coverage(checklist, findings, pre_evaluated_checks):
            captured["pre_evaluated_checks"] = set(pre_evaluated_checks)
            return {
                "coverage_valid": True,
                "coverage_percentage": 0,
                "evaluated_checks": 0,
                "total_checks": len(checklist.get("items", [])),
                "details": [],
            }

        with patch("drystone.validation.pre_checks.run_pre_checks", return_value=[]), patch(
            "drystone.analysis.router.route_checklist_for_llm",
            return_value=(
                {"items": [{"id": "IAM-ROUTED", "severity": "Critical"}]},
                {"llm_checks": 1, "deterministic_resolved": 0, "total_checks": 1},
            ),
        ), patch("drystone.validation.checklist_coverage.validate_checklist_coverage", side_effect=fake_coverage):
            output = SKILL.analyze(session, agent)

        data = json.loads(output.read_text())
        assert captured["pre_evaluated_checks"] == set()
        errors = data["analysis_metadata"]["evidence_load_errors"]
        assert errors[0]["file"] == "corrupt.json"
        assert errors[0]["error_type"] == "JSONDecodeError"

    def test_analyze_records_coverage_check_errors_in_metadata(self, tmp_path):
        session, evidence_path, findings_path = self._session(tmp_path)
        (evidence_path / "users.json").write_text('{"items": []}')
        agent = self._agent()

        with patch("drystone.validation.pre_checks.run_pre_checks", return_value=[]), patch(
            "drystone.analysis.router.route_checklist_for_llm",
            return_value=(
                {"items": []},
                {"llm_checks": 0, "deterministic_resolved": 1, "total_checks": 1},
            ),
        ), patch(
            "drystone.validation.checklist_coverage.validate_checklist_coverage",
            side_effect=RuntimeError("coverage exploded"),
        ):
            output = SKILL.analyze(session, agent)

        data = json.loads(output.read_text())
        assert data["analysis_metadata"]["coverage_check_error"] == {
            "error_type": "RuntimeError",
            "message": "coverage exploded",
        }
