"""Evidence chunking for large AWS datasets."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterator, cast

from drystone.models.findings import Finding, FindingsSummary, SkillFindings


@dataclass
class EvidenceChunk:
    """Single chunk of evidence for analysis."""

    chunk_id: int
    total_chunks: int
    evidence: Dict[str, Any]
    metadata: Dict[str, Any]  # Original file names, resource counts


class EvidenceChunker:
    """Chunks large evidence datasets for incremental Claude analysis."""

    # Evidence keys that are metadata/non-security and should be skipped during chunking.
    # These files don't contain security-relevant data and confuse the AI when sent standalone.
    METADATA_KEYS = frozenset({
        "account-aliases",
        "_audit_metadata",
    })

    def __init__(
        self,
        max_tokens_per_chunk: int = 40000,  # Conservative for 200K context
        chunk_strategy: str = "by_file",  # or "by_resource_count"
    ):
        self.max_tokens = max_tokens_per_chunk
        self.strategy = chunk_strategy

    def should_chunk(self, evidence: Dict[str, Any]) -> bool:
        """Check if evidence size requires chunking."""
        estimated_tokens = self._estimate_tokens(evidence)
        return estimated_tokens > self.max_tokens

    def chunk_evidence(self, evidence: Dict[str, Any]) -> Iterator[EvidenceChunk]:
        """Split evidence into manageable chunks.

        Skips metadata keys (account-aliases, _audit_metadata) that contain
        no security-relevant data and would confuse the AI when analyzed standalone.
        """

        if self.strategy == "by_file":
            for filename, data in evidence.items():
                # Skip metadata files that aren't security-relevant
                if filename in self.METADATA_KEYS or str(filename).startswith("_"):
                    continue

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
                        metadata={"source_file": filename},
                    )
        elif self.strategy == "by_resource_count":
            yield from self._chunk_by_resource(evidence)  # Placeholder for now

    def _chunk_large_file(
        self, filename: str, data: Any, resources_per_chunk: int = 15
    ) -> Iterator[EvidenceChunk]:
        """Chunk large arrays into smaller chunks.

        For files exceeding max_tokens, subdivide by resource count.
        Example: security-hub-findings.json with 500+ findings → more chunks of 15 findings each.

        Args:
            filename: Source file name
            data: File data (must be list)
            resources_per_chunk: Max resources per chunk (default: 15 for safety with models like Nova Lite)

        Yields:
            EvidenceChunk instances with subdivided data
        """
        # If the file is not a simple list, try to chunk a dominant list field
        # (common for dict-shaped evidence like {"items": [...]} or {"endpoints": [...]}).
        if not isinstance(data, list):
            if isinstance(data, dict):
                list_key = self._pick_dominant_list_key(data)
                if list_key:
                    base = {k: v for k, v in data.items() if k != list_key}
                    items = data.get(list_key)
                    if isinstance(items, list):
                        total_resources = len(items)
                        total_chunks = (
                            total_resources + resources_per_chunk - 1
                        ) // resources_per_chunk

                        for i in range(0, total_resources, resources_per_chunk):
                            chunk_items = items[i : i + resources_per_chunk]
                            chunk_id = i // resources_per_chunk + 1
                            yield EvidenceChunk(
                                chunk_id=chunk_id,
                                total_chunks=total_chunks,
                                evidence={filename: {**base, list_key: chunk_items}},
                                metadata={
                                    "source_file": filename,
                                    "resource_range": f"{i + 1}-{i + len(chunk_items)}/{total_resources}",
                                    "chunk_size_kb": len(json.dumps(chunk_items)) // 1024,
                                },
                            )
                        return

            # Not chunkable → return as-is
            yield EvidenceChunk(
                chunk_id=1,
                total_chunks=1,
                evidence={filename: data},
                metadata={"source_file": filename},
            )
            return

        total_resources = len(data)
        total_chunks = (total_resources + resources_per_chunk - 1) // resources_per_chunk

        for i in range(0, total_resources, resources_per_chunk):
            chunk_data = data[i : i + resources_per_chunk]
            chunk_id = i // resources_per_chunk + 1

            yield EvidenceChunk(
                chunk_id=chunk_id,
                total_chunks=total_chunks,
                evidence={filename: chunk_data},
                metadata={
                    "source_file": filename,
                    "resource_range": f"{i + 1}-{i + len(chunk_data)}/{total_resources}",
                    "chunk_size_kb": len(json.dumps(chunk_data)) // 1024,
                },
            )

    def _pick_dominant_list_key(self, data: Dict[str, Any]) -> str:
        """Pick a list-like field to chunk inside dict-shaped evidence.

        Prefer known keys first, otherwise pick the largest list by length.
        """
        preferred = [
            "items",
            "endpoints",
            "attachments",
            "route_tables",
            "transit_gateways",
            "services",
            "interfaces",
            "instances",
        ]

        for key in preferred:
            val = data.get(key)
            if isinstance(val, list) and len(val) > 0:
                return key

        best_key = ""
        best_len = 0
        for k, v in data.items():
            if isinstance(v, list) and len(v) > best_len:
                best_len = len(v)
                best_key = str(k)
        return best_key

    def _chunk_by_resource(
        self, evidence: Dict[str, Any], resources_per_chunk: int = 50
    ) -> Iterator[EvidenceChunk]:
        """Chunk by resource count - for very large files (e.g., 1000+ users).
        Implementation: split arrays in JSON files
        """
        return cast(Iterator[EvidenceChunk], iter(()))

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
        self._findings_by_id: Dict[str, Finding] = {}

    def _quality_score(self, finding: Finding) -> tuple:
        """Rank finding quality for deterministic deduplication.

        Preference order:
        1. Higher risk score
        2. More evidence references
        3. Presence of evidence snippet
        4. More affected resources
        """

        evidence_refs = len(finding.evidence_refs or [])
        has_snippet = 1 if finding.evidence_snippet else 0
        affected = len(finding.affected_resources or [])
        return (float(finding.risk_score or 0.0), evidence_refs, has_snippet, affected)

    def add_findings(self, findings: SkillFindings) -> None:
        """Add findings from a chunk analysis."""
        for finding in findings.findings:
            existing = self._findings_by_id.get(finding.id)
            if existing is None:
                self._findings_by_id[finding.id] = finding
                continue

            # Deterministic replacement: keep richer/higher-confidence finding.
            if self._quality_score(finding) > self._quality_score(existing):
                self._findings_by_id[finding.id] = finding

    def aggregate(self) -> SkillFindings:
        """Combine all findings into final result."""
        all_findings = list(self._findings_by_id.values())

        # Calculate aggregated summary
        critical = sum(1 for f in all_findings if f.severity == "Critical")
        high = sum(1 for f in all_findings if f.severity == "High")
        medium = sum(1 for f in all_findings if f.severity == "Medium")
        low = sum(1 for f in all_findings if f.severity == "Low")

        # Risk score: weighted average
        risk_scores = [f.risk_score for f in all_findings if f.risk_score is not None]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

        return SkillFindings(
            findings=all_findings,
            summary=FindingsSummary(
                total_findings=len(all_findings),
                critical=critical,
                high=high,
                medium=medium,
                low=low,
                overall_risk_score=avg_risk,
            ),
            # Add other required fields for SkillFindings, e.g., skill, analyzed_at, etc.
            # For aggregation, we might need a way to pass these from the original context
            skill="aggregated",  # Placeholder, ideally derived from original findings
            analyzed_at=datetime.utcnow(),
            evidence_count=0,  # This might need to be re-calculated or passed
            checklist_version="N/A",  # This too
        )
