from pathlib import Path

from drystone.agent.cache import FindingsCache
from drystone.models.findings import Finding, FindingsSummary, SkillFindings


def _sample_findings() -> SkillFindings:
    return SkillFindings(
        skill="iam",
        findings=[
            Finding(
                id="IAM-001",
                severity="Critical",
                risk_score=9.1,
                title="Root without MFA",
                description="desc",
                remediation="remediate",
                cis_reference="1.5",
            )
        ],
        summary=FindingsSummary(total_findings=1, critical=1, high=0, medium=0, low=0),
        evidence_count=1,
    )


def test_cache_roundtrip(tmp_path: Path):
    cache = FindingsCache(cache_dir=tmp_path)
    key = cache.build_key(
        skill_name="iam",
        provider_type="claude-api",
        model="claude-opus-4-5-20251101",
        evidence={"users": [{"UserName": "root"}]},
        checklist={"version": "2.0", "items": [{"id": "IAM-001"}]},
        pre_checks=[],
    )

    expected = _sample_findings()
    cache.set(key, expected)
    loaded = cache.get(key)
    assert loaded is not None
    assert loaded.summary.total_findings == 1
    assert loaded.findings[0].id == "IAM-001"


def test_cache_key_changes_when_evidence_changes(tmp_path: Path):
    cache = FindingsCache(cache_dir=tmp_path)
    key_a = cache.build_key(
        skill_name="iam",
        provider_type="claude-api",
        model="claude-opus-4-5-20251101",
        evidence={"users": [{"UserName": "a"}]},
        checklist={"version": "2.0", "items": [{"id": "IAM-001"}]},
        pre_checks=[],
    )
    key_b = cache.build_key(
        skill_name="iam",
        provider_type="claude-api",
        model="claude-opus-4-5-20251101",
        evidence={"users": [{"UserName": "b"}]},
        checklist={"version": "2.0", "items": [{"id": "IAM-001"}]},
        pre_checks=[],
    )
    assert key_a != key_b
