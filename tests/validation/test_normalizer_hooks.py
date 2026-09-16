"""Focused tests for lazy findings normalizer hooks."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer
from drystone.validation.normalizer_hooks import (
    DefaultNormalizerHook,
    NormalizerContext,
    get_normalizer_hook,
)


def _finding(**overrides):
    data = {
        "id": "GEN-001",
        "severity": "Medium",
        "risk_score": 4.0,
        "title": "Test finding",
        "description": "Test finding description",
        "remediation": "Fix it",
        "affected_resources": ["resource-1"],
        "evidence_refs": ["evidence.json#item"],
    }
    data.update(overrides)
    return Finding(**data)


def test_lazy_registry_falls_back_for_skill_without_normalizer_module():
    context = NormalizerContext(skill_name="NO_SUCH_SKILL", checklist_map={}, evidence={})

    hook = get_normalizer_hook("NO_SUCH_SKILL", context)

    assert isinstance(hook, DefaultNormalizerHook)
    assert hook.remap_id("GEN-001", _finding()) == "GEN-001"
    assert hook.normalize_evidence_refs(["raw-ref"]) == ["raw-ref"]
    assert hook.validate_against_evidence("GEN-001", _finding()) is None


def test_exposure_hook_remaps_non_public_cross_account_bucket_policy():
    normalizer = FindingsNormalizer(
        checklist={
            "items": [
                {"id": "EXP-001", "severity": "Critical"},
                {"id": "EXP-015", "severity": "High"},
            ]
        },
        skill_name="exposure",
    )
    normalizer.evidence = {"_audit_metadata": {"_account_id": "111111111111"}}
    finding = _finding(
        id="EXP-001",
        evidence_snippet={
            "BucketPolicy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::222222222222:role/External"},
                    }
                ]
            }
        },
    )

    normalizer._sync_hook_context()

    assert normalizer._skill_hook.remap_id("EXP-001", finding) == "EXP-015"


def test_iam_hook_normalizes_credential_report_refs():
    normalizer = FindingsNormalizer(
        checklist={"items": [{"id": "IAM-001", "severity": "Critical"}]},
        skill_name="iam",
    )

    assert normalizer._normalize_evidence_refs(
        ["credential_report.json#root_account", "credential_report.csv#alice"]
    ) == ["credential-report.csv#<root_account>", "credential-report.csv#alice"]


def test_alerting_hook_sets_operational_impact_for_low_risk_metadata_findings():
    normalizer = FindingsNormalizer(
        checklist={"items": [{"id": "ALRT-018", "severity": "Low"}]},
        skill_name="alerting",
    )
    finding = _finding(id="ALRT-018", severity="Low", risk_score=2.0, impact=None)

    normalizer._ensure_impact(finding)

    assert finding.exploitability_status == "theoretical"
    assert "operational clarity" in finding.impact
