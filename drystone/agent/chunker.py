"""Evidence chunking for large AWS datasets."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterator, List

from drystone.models.findings import Finding, SkillFindings, FindingsSummary


@dataclass
class EvidenceChunk:
    """Single chunk of evidence for analysis."""
    chunk_id: int
    total_chunks: int
    evidence: Dict[str, Any]
    metadata: Dict[str, Any]  # Original file names, resource counts


class EvidenceChunker:
    """Chunks large evidence datasets for incremental Claude analysis."""

    def __init__(
        self,
        max_tokens_per_chunk: int = 40000,  # Conservative for 200K context
        chunk_strategy: str = "by_file"      # or "by_resource_count"
    ):
        self.max_tokens = max_tokens_per_chunk
        self.strategy = chunk_strategy

    def should_chunk(self, evidence: Dict[str, Any]) -> bool:
        """Check if evidence size requires chunking."""
        estimated_tokens = self._estimate_tokens(evidence)
        return estimated_tokens > self.max_tokens

    def chunk_evidence(
        self,
        evidence: Dict[str, Any]
    ) -> Iterator[EvidenceChunk]:
        """Split evidence into manageable chunks."""

        if self.strategy == "by_file":
            for filename, data in evidence.items():
                file_tokens = self._estimate_tokens({filename: data})

                if file_tokens > self.max_tokens:
                    # File too large → subdivide
                    yield from self._chunk_large_file(filename, data)
                else:
                    # File fits in one chunk
                    yield EvidenceChunk(
                        chunk_id=1,
                        total_chunks=1,
                        evidence={filename: data},
                        metadata={"source_file": filename}
                    )
        elif self.strategy == "by_resource_count":
            yield from self._chunk_by_resource(evidence) # Placeholder for now

    def _chunk_large_file(
        self,
        filename: str,
        data: Any,
        resources_per_chunk: int = 30
    ) -> Iterator[EvidenceChunk]:
        """Chunk large arrays into smaller chunks.

        For files exceeding max_tokens, subdivide by resource count.
        Example: inspector-findings.json with 475 findings → 16 chunks of 30 findings.

        Args:
            filename: Source file name
            data: File data (must be list)
            resources_per_chunk: Max resources per chunk (default: 30 for CLI)

        Yields:
            EvidenceChunk instances with subdivided data
        """
        if not isinstance(data, list):
            # Not a list → cannot chunk, return as-is
            yield EvidenceChunk(
                chunk_id=1,
                total_chunks=1,
                evidence={filename: data},
                metadata={"source_file": filename}
            )
            return

        total_resources = len(data)
        total_chunks = (total_resources + resources_per_chunk - 1) // resources_per_chunk

        for i in range(0, total_resources, resources_per_chunk):
            chunk_data = data[i:i + resources_per_chunk]
            chunk_id = i // resources_per_chunk + 1

            yield EvidenceChunk(
                chunk_id=chunk_id,
                total_chunks=total_chunks,
                evidence={filename: chunk_data},
                metadata={
                    "source_file": filename,
                    "resource_range": f"{i+1}-{i+len(chunk_data)}/{total_resources}",
                    "chunk_size_kb": len(json.dumps(chunk_data)) // 1024
                }
            )

    def _chunk_by_resource(
        self,
        evidence: Dict[str, Any],
        resources_per_chunk: int = 50
    ) -> Iterator[EvidenceChunk]:
        """Chunk by resource count - for very large files (e.g., 1000+ users).
        Implementation: split arrays in JSON files
        """
        pass # Placeholder for now

    def _estimate_tokens(self, evidence: Dict[str, Any]) -> int:
        """Estimate token count for evidence.

        Rule of thumb: 1 token ≈ 4 characters for English/JSON
        More conservative: 1 token ≈ 3 chars (for Spanish prompts)
        """
        json_str = json.dumps(evidence, ensure_ascii=False)
        return len(json_str) // 3  # Conservative estimation


class FindingsAggregator:
    """Aggregates findings from multiple chunked analyses."""

    def __init__(self):
        self.all_findings: List[Finding] = []
        self.seen_ids: set = set()

    def add_findings(self, findings: SkillFindings) -> None:
        """Add findings from a chunk analysis."""
        for finding in findings.findings:
            # De-duplicate by ID
            if finding.id not in self.seen_ids:
                self.all_findings.append(finding)
                self.seen_ids.add(finding.id)

    def aggregate(self) -> SkillFindings:
        """Combine all findings into final result."""
        # Calculate aggregated summary
        critical = sum(1 for f in self.all_findings if f.severity == "Critical")
        high = sum(1 for f in self.all_findings if f.severity == "High")
        medium = sum(1 for f in self.all_findings if f.severity == "Medium")
        low = sum(1 for f in self.all_findings if f.severity == "Low")

        # Risk score: weighted average
        risk_scores = [f.risk_score for f in self.all_findings if f.risk_score is not None]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

        return SkillFindings(
            findings=self.all_findings,
            summary=FindingsSummary(
                total_findings=len(self.all_findings),
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                overall_risk_score=avg_risk
            ),
            # Add other required fields for SkillFindings, e.g., skill, analyzed_at, etc.
            # For aggregation, we might need a way to pass these from the original context
            skill="aggregated", # Placeholder, ideally derived from original findings
            analyzed_at=datetime.utcnow().isoformat(),
            evidence_count=0, # This might need to be re-calculated or passed
            checklist_version="N/A" # This too
        )