"""Unit tests for the evidence chunking module."""

import pytest
from drystone.agent.chunker import EvidenceChunker, FindingsAggregator, EvidenceChunk
from drystone.models.findings import SkillFindings, FindingsSummary, Finding

# --- EvidenceChunker Tests ---

def test_should_chunk_false_for_small_evidence():
    """Test that should_chunk returns False for evidence below the token threshold."""
    chunker = EvidenceChunker(max_tokens_per_chunk=1000)
    small_evidence = {"users": [{"id": 1, "name": "test"}]} # Roughly 10 tokens
    assert not chunker.should_chunk(small_evidence)

def test_should_chunk_true_for_large_evidence():
    """Test that should_chunk returns True for evidence exceeding the token threshold."""
    chunker = EvidenceChunker(max_tokens_per_chunk=10)
    large_evidence = {"users": [{"id": i, "name": f"testuser_{i}"} for i in range(10)]} # > 10 tokens
    assert chunker.should_chunk(large_evidence)

def test_chunk_by_file_strategy():
    """Test the 'by_file' chunking strategy."""
    chunker = EvidenceChunker()
    evidence = {
        "users": [{"id": 1}],
        "roles": [{"id": "A"}, {"id": "B"}],
        "policies": [{"name": "p1"}]
    }
    chunks = list(chunker.chunk_evidence(evidence))

    assert len(chunks) == 3
    
    # Chunk 1
    assert chunks[0].chunk_id == 1
    assert chunks[0].total_chunks == 3
    assert chunks[0].evidence == {"users": [{"id": 1}]}
    assert chunks[0].metadata["source_file"] == "users"

    # Chunk 2
    assert chunks[1].chunk_id == 2
    assert chunks[1].total_chunks == 3
    assert chunks[1].evidence == {"roles": [{"id": "A"}, {"id": "B"}]}
    assert chunks[1].metadata["source_file"] == "roles"

    # Chunk 3
    assert chunks[2].chunk_id == 3
    assert chunks[2].total_chunks == 3
    assert chunks[2].evidence == {"policies": [{"name": "p1"}]}
    assert chunks[2].metadata["source_file"] == "policies"


# --- FindingsAggregator Tests ---

@pytest.fixture
def sample_findings_list():
    """Fixture with a list of SkillFindings objects for aggregation."""
    findings1 = SkillFindings(
        skill="iam",
        findings=[
            Finding(id="IAM-001", severity="Critical", risk_score=9.0, title="t1", description="d1", remediation="r1"),
            Finding(id="IAM-002", severity="High", risk_score=7.0, title="t2", description="d2", remediation="r2"),
        ],
        summary=FindingsSummary(total_findings=2, critical=1, high=1, medium=0, low=0, overall_risk_score=8.0),
        analyzed_at="2023-01-01T12:00:00Z",
        evidence_count=10,
        checklist_version="1.0"
    )
    findings2 = SkillFindings(
        skill="iam",
        findings=[
            Finding(id="IAM-001", severity="Critical", risk_score=9.0, title="t1", description="d1", remediation="r1"), # Duplicate
            Finding(id="IAM-003", severity="Medium", risk_score=5.0, title="t3", description="d3", remediation="r3"),
        ],
        summary=FindingsSummary(total_findings=2, critical=1, high=0, medium=1, low=0, overall_risk_score=7.0),
        analyzed_at="2023-01-01T12:01:00Z",
        evidence_count=5,
        checklist_version="1.0"
    )
    return [findings1, findings2]

def test_findings_aggregator_add_and_deduplicate(sample_findings_list):
    """Test that the aggregator adds findings and correctly de-duplicates by ID."""
    aggregator = FindingsAggregator()
    
    aggregator.add_findings(sample_findings_list[0])
    assert len(aggregator.all_findings) == 2
    assert aggregator.seen_ids == {"IAM-001", "IAM-002"}
    
    aggregator.add_findings(sample_findings_list[1])
    assert len(aggregator.all_findings) == 3 # IAM-001 was a duplicate
    assert aggregator.seen_ids == {"IAM-001", "IAM-002", "IAM-003"}
    
    # Check that the first instance of IAM-001 was kept
    assert aggregator.all_findings[0].id == "IAM-001"
    assert aggregator.all_findings[1].id == "IAM-002"
    assert aggregator.all_findings[2].id == "IAM-003"


def test_findings_aggregator_aggregate_summary(sample_findings_list):
    """Test the summary calculation in the aggregate method."""
    aggregator = FindingsAggregator()
    aggregator.add_findings(sample_findings_list[0])
    aggregator.add_findings(sample_findings_list[1])
    
    final_findings = aggregator.aggregate()

    assert isinstance(final_findings, SkillFindings)
    assert final_findings.summary.total_findings == 3
    assert final_findings.summary.critical == 1
    assert final_findings.summary.high == 1
    assert final_findings.summary.medium == 1
    assert final_findings.summary.low == 0
    
    # Expected risk score: (9.0 + 7.0 + 5.0) / 3 = 7.0
    assert final_findings.summary.overall_risk_score == pytest.approx(7.0)
