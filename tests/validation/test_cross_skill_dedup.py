"""Tests for cross-skill deduplication of findings."""

from drystone.validation.cross_skill_dedup import (
    _quality_score,
    _resource_overlap,
    deduplicate_cross_skill,
)


def _make_finding(id, severity="High", resources=None, skill="iam", **kwargs):
    f = {
        "id": id,
        "severity": severity,
        "risk_score": 7.0,
        "title": f"Finding {id}",
        "description": f"Description for {id}",
        "skill": skill,
        "affected_resources": resources or [],
    }
    f.update(kwargs)
    return f


class TestResourceOverlap:
    def test_identical_sets(self):
        assert _resource_overlap({"a", "b"}, {"a", "b"}) == 1.0

    def test_no_overlap(self):
        assert _resource_overlap({"a"}, {"b"}) == 0.0

    def test_partial_overlap(self):
        assert _resource_overlap({"a", "b", "c"}, {"a", "b"}) == 1.0  # 2/min(3,2) = 1.0

    def test_empty_sets(self):
        assert _resource_overlap(set(), {"a"}) == 0.0


class TestQualityScore:
    def test_empty_finding(self):
        assert _quality_score({"id": "X-001"}) == 0

    def test_populated_finding(self):
        f = _make_finding(
            "IAM-001",
            impact="big impact",
            remediation="fix it",
            evidence_snippet={"key": "val"},
        )
        assert _quality_score(f) >= 3


class TestDeduplicateCrossSkill:
    def test_no_findings(self):
        assert deduplicate_cross_skill([]) == []

    def test_single_finding(self):
        f = [_make_finding("IAM-001")]
        assert deduplicate_cross_skill(f) == f

    def test_no_overlap_keeps_both(self):
        f1 = _make_finding("RECON-001", resources=["arn:aws:apigateway:us-east-1::/restapis/abc"])
        f2 = _make_finding("EXP-001", skill="exposure", resources=["arn:aws:s3:::other-bucket"])
        result = deduplicate_cross_skill([f1, f2])
        assert len(result) == 2

    def test_recon_exp_overlap_deduplicates(self):
        """RECON-* and EXP-* with same resources and severity → keep one."""
        resources = [
            "arn:aws:apigateway:us-east-1::/restapis/abc",
            "arn:aws:apigateway:us-east-1::/restapis/def",
        ]
        f1 = _make_finding("RECON-002", resources=resources, skill="recon")
        f2 = _make_finding(
            "EXP-006",
            resources=resources,
            skill="exposure",
            impact="detailed impact",
            remediation="fix",
        )
        result = deduplicate_cross_skill([f1, f2])
        assert len(result) == 1
        # Exposure has higher priority and more quality
        assert result[0]["id"] == "EXP-006"

    def test_different_severity_no_dedup(self):
        """Same resources but different severity → no dedup."""
        resources = ["arn:aws:s3:::bucket-1"]
        f1 = _make_finding("IAM-030", severity="Critical", resources=resources, skill="iam")
        f2 = _make_finding("EXP-015", severity="High", resources=resources, skill="exposure")
        result = deduplicate_cross_skill([f1, f2])
        assert len(result) == 2

    def test_non_matching_prefixes_no_dedup(self):
        """Prefixes not in CROSS_SKILL_DEDUP_RULES → no dedup."""
        resources = ["arn:aws:ec2:us-east-1::sg-123"]
        f1 = _make_finding("NET-001", resources=resources, skill="network")
        f2 = _make_finding("VULN-001", resources=resources, skill="vulns")
        result = deduplicate_cross_skill([f1, f2])
        assert len(result) == 2

    def test_sm_within_skill_dedup(self):
        """SM-* within-skill semantic dedup at 90% threshold."""
        resources = ["arn:aws:secretsmanager:us-east-1:123:secret/db-cred"]
        f1 = _make_finding("SM-001", resources=resources, skill="secretsmanager")
        f2 = _make_finding(
            "SM-002",
            resources=resources,
            skill="secretsmanager",
            impact="rotation gap",
        )
        result = deduplicate_cross_skill([f1, f2])
        assert len(result) == 1
