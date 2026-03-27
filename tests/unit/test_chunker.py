"""Tests for EvidenceChunker and FindingsAggregator."""

from datetime import datetime
from typing import Any, Dict, List

import pytest

from drystone.agent.chunker import EvidenceChunker, FindingsAggregator
from drystone.models.findings import Finding, FindingsSummary, SkillFindings

# ── helpers ───────────────────────────────────────────────────────────────────


def make_finding(
    id: str,
    severity: str = "High",
    risk_score: float = 7.0,
    evidence_refs: List[str] = None,
    evidence_snippet: Dict[str, Any] = None,
    affected_resources: List[str] = None,
) -> Finding:
    return Finding(
        id=id,
        severity=severity,
        risk_score=risk_score,
        title=f"Title {id}",
        description=f"Description {id}",
        remediation="Fix it",
        evidence_refs=evidence_refs or [],
        evidence_snippet=evidence_snippet,
        affected_resources=affected_resources or [],
    )


def make_skill_findings(findings: List[Finding]) -> SkillFindings:
    return SkillFindings(
        skill="iam",
        analyzed_at=datetime.utcnow(),
        evidence_count=1,
        checklist_version="1.0",
        findings=findings,
        summary=FindingsSummary(
            total_findings=len(findings),
            critical=0,
            high=len(findings),
            medium=0,
            low=0,
            overall_risk_score=7.0,
        ),
    )


def small_evidence(**kwargs) -> Dict[str, Any]:
    """Evidence that fits in a single chunk (small payload)."""
    return {k: [{"id": i} for i in range(3)] for k, _ in kwargs.items()} or {
        "users": [{"UserId": "U1"}, {"UserId": "U2"}]
    }


# ── EvidenceChunker.should_chunk ──────────────────────────────────────────────


class TestShouldChunk:
    def test_small_evidence_does_not_require_chunking(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=40000)
        evidence = {"users": [{"id": i} for i in range(5)]}
        assert chunker.should_chunk(evidence) is False

    def test_large_evidence_requires_chunking(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=10)
        evidence = {"users": [{"id": i, "data": "x" * 100} for i in range(20)]}
        assert chunker.should_chunk(evidence) is True

    def test_threshold_boundary(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=100)
        # json.dumps({"k": "..."}) adds 9 chars of overhead: {"k": " + "}
        # To get exactly 300 total chars (100 tokens) the value must be 291 chars
        json_overhead = len('{"k": ""}')  # 9
        value_for_100_tokens = "a" * (100 * 3 - json_overhead)  # 291 chars → 300 total
        value_for_101_tokens = "a" * (101 * 3 - json_overhead)  # 294 chars → 303 total
        assert chunker.should_chunk({"k": value_for_100_tokens}) is False
        assert chunker.should_chunk({"k": value_for_101_tokens}) is True


# ── EvidenceChunker: metadata key filtering ───────────────────────────────────


class TestMetadataKeyFiltering:
    """METADATA_KEYS entries must never appear in any chunk."""

    def test_account_aliases_excluded(self):
        chunker = EvidenceChunker()
        evidence = {
            "account-aliases": ["my-account"],
            "users": [{"UserId": "U1"}],
        }
        chunks = list(chunker.chunk_evidence(evidence))
        for chunk in chunks:
            assert "account-aliases" not in chunk.evidence

    def test_audit_metadata_excluded(self):
        chunker = EvidenceChunker()
        evidence = {
            "_audit_metadata": {"collected_at": "2026-01-01"},
            "roles": [{"RoleName": "Admin"}],
        }
        chunks = list(chunker.chunk_evidence(evidence))
        for chunk in chunks:
            assert "_audit_metadata" not in chunk.evidence

    def test_wafv2_managed_rule_groups_excluded(self):
        chunker = EvidenceChunker()
        evidence = {
            "wafv2-managed-rule-groups": [{"Name": "AWSManagedRulesCommonRuleSet"}],
            "web-acls": [{"Name": "my-acl"}],
        }
        chunks = list(chunker.chunk_evidence(evidence))
        for chunk in chunks:
            assert "wafv2-managed-rule-groups" not in chunk.evidence

    def test_underscore_prefixed_keys_excluded(self):
        chunker = EvidenceChunker()
        evidence = {
            "_internal": {"debug": True},
            "policies": [{"PolicyName": "ReadOnly"}],
        }
        chunks = list(chunker.chunk_evidence(evidence))
        for chunk in chunks:
            assert "_internal" not in chunk.evidence

    def test_only_metadata_keys_produces_no_chunks(self):
        chunker = EvidenceChunker()
        evidence = {
            "account-aliases": ["alias"],
            "_audit_metadata": {"ts": "2026-01-01"},
        }
        chunks = list(chunker.chunk_evidence(evidence))
        assert chunks == []


# ── EvidenceChunker: IAM small-file grouping ──────────────────────────────────


class TestIAMSmallFileGrouping:
    """Related IAM files should be emitted together in one chunk."""

    def test_users_credential_report_groups_together(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=40000)
        evidence = {
            "users": [{"UserId": "U1"}],
            "credential-report": [{"user": "root"}],
            "groups": [{"GroupName": "Admins"}],
        }
        chunks = list(chunker.chunk_evidence(evidence))
        # All three keys should appear in a single grouped chunk
        grouped = [c for c in chunks if "users" in c.evidence]
        assert len(grouped) == 1
        assert "credential-report" in grouped[0].evidence
        assert "groups" in grouped[0].evidence

    def test_password_policy_account_summary_groups_together(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=40000)
        evidence = {
            "password-policy": {"MinimumPasswordLength": 8},
            "account-summary": {"UsersQuota": 5000},
        }
        chunks = list(chunker.chunk_evidence(evidence))
        grouped = [c for c in chunks if "password-policy" in c.evidence]
        assert len(grouped) == 1
        assert "account-summary" in grouped[0].evidence

    def test_ungrouped_file_emitted_individually(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=40000)
        evidence = {"security-hub-findings": [{"Id": "finding-1"}]}
        chunks = list(chunker.chunk_evidence(evidence))
        assert len(chunks) == 1
        assert "security-hub-findings" in chunks[0].evidence

    def test_group_exceeding_max_tokens_not_grouped(self):
        # If the combined group is too large it should not be emitted as one chunk
        chunker = EvidenceChunker(max_tokens_per_chunk=5)
        evidence = {
            "users": [{"UserId": "U" * 50}],
            "credential-report": [{"user": "r" * 50}],
            "groups": [{"GroupName": "g" * 50}],
        }
        chunks = list(chunker.chunk_evidence(evidence))
        # The group was too big so each file is emitted individually
        for chunk in chunks:
            # No chunk should contain all three together
            has_all = (
                "users" in chunk.evidence
                and "credential-report" in chunk.evidence
                and "groups" in chunk.evidence
            )
            assert not has_all


# ── EvidenceChunker: large file chunking ──────────────────────────────────────


class TestLargeFileChunking:
    def test_large_list_split_into_multiple_chunks(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=10)
        # 50 items, each large enough to exceed max_tokens individually
        items = [{"id": i, "data": "x" * 50} for i in range(50)]
        evidence = {"roles": items}
        chunks = list(chunker.chunk_evidence(evidence))
        assert len(chunks) > 1

    def test_all_resources_preserved_across_chunks(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=10)
        items = [{"id": i} for i in range(30)]
        evidence = {"roles": items}
        chunks = list(chunker.chunk_evidence(evidence))
        recovered = []
        for chunk in chunks:
            recovered.extend(chunk.evidence["roles"])
        assert len(recovered) == 30
        assert {r["id"] for r in recovered} == set(range(30))

    def test_chunk_ids_are_sequential(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=10)
        items = [{"id": i, "data": "x" * 100} for i in range(30)]
        chunks = list(chunker.chunk_evidence({"roles": items}))
        ids = [c.chunk_id for c in chunks]
        assert ids == list(range(1, len(chunks) + 1))

    def test_total_chunks_consistent(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=10)
        items = [{"id": i, "data": "x" * 100} for i in range(30)]
        chunks = list(chunker.chunk_evidence({"roles": items}))
        total = chunks[0].total_chunks
        assert all(c.total_chunks == total for c in chunks)
        assert total == len(chunks)

    def test_resource_range_metadata_present(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=10)
        items = [{"id": i, "data": "x" * 100} for i in range(30)]
        chunks = list(chunker.chunk_evidence({"roles": items}))
        for chunk in chunks:
            assert "resource_range" in chunk.metadata

    def test_non_list_non_chunkable_data_returned_as_is(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=5)
        evidence = {"password-policy": {"MinimumPasswordLength": 8, "RequireSymbols": True}}
        chunks = list(chunker.chunk_evidence(evidence))
        assert len(chunks) == 1
        assert chunks[0].evidence["password-policy"]["MinimumPasswordLength"] == 8

    def test_dict_with_dominant_list_key_chunked(self):
        chunker = EvidenceChunker(max_tokens_per_chunk=10)
        items = [{"ep": i, "data": "x" * 50} for i in range(30)]
        evidence = {"api-endpoints": {"region": "us-east-1", "endpoints": items}}
        chunks = list(chunker.chunk_evidence(evidence))
        assert len(chunks) > 1
        # Base fields preserved in every chunk
        for chunk in chunks:
            assert chunk.evidence["api-endpoints"]["region"] == "us-east-1"


# ── EvidenceChunker._pick_dominant_list_key ───────────────────────────────────


class TestPickDominantListKey:
    def test_prefers_known_key_over_larger_unknown(self):
        chunker = EvidenceChunker()
        data = {
            "items": [1, 2, 3],
            "unknown_big": list(range(100)),
        }
        assert chunker._pick_dominant_list_key(data) == "items"

    def test_falls_back_to_largest_list(self):
        chunker = EvidenceChunker()
        data = {
            "aaa": [1, 2],
            "bbb": list(range(10)),
        }
        assert chunker._pick_dominant_list_key(data) == "bbb"

    def test_returns_empty_string_when_no_list(self):
        chunker = EvidenceChunker()
        data = {"key": "value", "num": 42}
        assert chunker._pick_dominant_list_key(data) == ""

    def test_ignores_empty_lists(self):
        chunker = EvidenceChunker()
        data = {"items": [], "other": [1, 2, 3]}
        # "items" is preferred but empty → should not be returned
        assert chunker._pick_dominant_list_key(data) == "other"


# ── FindingsAggregator ────────────────────────────────────────────────────────


class TestFindingsAggregator:
    def test_single_chunk_findings_preserved(self):
        agg = FindingsAggregator()
        findings = make_skill_findings([make_finding("IAM-001"), make_finding("IAM-002")])
        agg.add_findings(findings)
        result = agg.aggregate()
        assert result.summary.total_findings == 2
        assert {f.id for f in result.findings} == {"IAM-001", "IAM-002"}

    def test_duplicate_id_keeps_higher_risk_score(self):
        agg = FindingsAggregator()
        low = make_skill_findings([make_finding("IAM-001", risk_score=3.0)])
        high = make_skill_findings([make_finding("IAM-001", risk_score=9.0)])
        agg.add_findings(low)
        agg.add_findings(high)
        result = agg.aggregate()
        assert result.summary.total_findings == 1
        assert result.findings[0].risk_score == 9.0

    def test_duplicate_id_keeps_more_evidence_refs(self):
        agg = FindingsAggregator()
        sparse = make_skill_findings([make_finding("IAM-001", evidence_refs=["ref1"])])
        rich = make_skill_findings(
            [make_finding("IAM-001", evidence_refs=["ref1", "ref2", "ref3"])]
        )
        agg.add_findings(sparse)
        agg.add_findings(rich)
        result = agg.aggregate()
        assert len(result.findings[0].evidence_refs) == 3

    def test_duplicate_id_prefers_finding_with_snippet(self):
        agg = FindingsAggregator()
        no_snippet = make_skill_findings([make_finding("IAM-001")])
        with_snippet = make_skill_findings(
            [make_finding("IAM-001", evidence_snippet={"User": "root"})]
        )
        agg.add_findings(no_snippet)
        agg.add_findings(with_snippet)
        result = agg.aggregate()
        assert result.findings[0].evidence_snippet == {"User": "root"}

    def test_findings_from_multiple_chunks_merged(self):
        agg = FindingsAggregator()
        chunk1 = make_skill_findings([make_finding("IAM-001"), make_finding("IAM-002")])
        chunk2 = make_skill_findings([make_finding("IAM-003"), make_finding("IAM-004")])
        agg.add_findings(chunk1)
        agg.add_findings(chunk2)
        result = agg.aggregate()
        assert result.summary.total_findings == 4

    def test_empty_aggregation_returns_zero_findings(self):
        agg = FindingsAggregator()
        result = agg.aggregate()
        assert result.summary.total_findings == 0
        assert result.findings == []

    def test_severity_counts_in_summary(self):
        agg = FindingsAggregator()
        findings = make_skill_findings(
            [
                make_finding("F1", severity="Critical", risk_score=9.5),
                make_finding("F2", severity="Critical", risk_score=9.0),
                make_finding("F3", severity="High", risk_score=7.0),
                make_finding("F4", severity="Medium", risk_score=5.0),
                make_finding("F5", severity="Low", risk_score=2.0),
            ]
        )
        agg.add_findings(findings)
        result = agg.aggregate()
        assert result.summary.critical == 2
        assert result.summary.high == 1
        assert result.summary.medium == 1
        assert result.summary.low == 1

    def test_risk_score_is_weighted_average(self):
        agg = FindingsAggregator()
        findings = make_skill_findings(
            [
                make_finding("F1", risk_score=4.0),
                make_finding("F2", risk_score=6.0),
            ]
        )
        agg.add_findings(findings)
        result = agg.aggregate()
        assert result.summary.overall_risk_score == pytest.approx(5.0)
