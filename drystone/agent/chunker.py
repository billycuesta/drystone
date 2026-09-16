"""Evidence chunking for large AWS datasets."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterator, Optional, cast

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
    METADATA_KEYS = frozenset(
        {
            "account-aliases",
            "_audit_metadata",
            "wafv2-managed-rule-groups",  # AWS catalog data (available managed groups), not config state
        }
    )

    def __init__(
        self,
        max_tokens_per_chunk: int = 40000,  # Conservative for 200K context
        chunk_strategy: str = "by_file",  # or "by_resource_count"
    ):
        self.max_tokens = max_tokens_per_chunk
        self.strategy = chunk_strategy

    def should_chunk(self, evidence: Dict[str, Any]) -> bool:
        """Check if evidence size requires chunking."""
        # Some evidence types have high prompt-complexity even after token
        # distillation because every item carries nested policy/CVE semantics.
        # Force chunking so they cannot become one long-running Claude CLI call.
        for key, value in evidence.items():
            normalized = str(key).replace(".json", "").lower()
            if normalized in {"inspector-findings", "policies"}:
                if isinstance(value, list) and len(value) > 3:
                    return True
                if isinstance(value, dict):
                    items = value.get("items")
                    if isinstance(items, list) and len(items) > 3:
                        return True
                    for sub_value in value.values():
                        if isinstance(sub_value, dict) and isinstance(sub_value.get("items"), list):
                            if len(sub_value["items"]) > 3:
                                return True
        estimated_tokens = self._estimate_tokens(evidence)
        return estimated_tokens > self.max_tokens

    # Groups of related small files that provide better context when analyzed together.
    # Each group is sent as a single chunk if the combined size fits within max_tokens.
    # Files not listed here are sent individually (or subdivided if too large).
    _IAM_SMALL_FILE_GROUPS = [
        # User identity context: users + credential report + groups together give MFA/key context
        {"users", "credential-report", "groups"},
        # Account-level controls: password policy + account summary + SCPs
        {"password-policy", "account-summary", "effective-scps"},
        # Resource-based and cross-account trust context
        {"resource-based-policies", "assumeRole-chains"},
        # Instance profiles are lightweight and complement roles context
        {"instance-profiles"},
    ]

    def chunk_evidence(self, evidence: Dict[str, Any]) -> Iterator[EvidenceChunk]:
        """Split evidence into manageable chunks.

        Skips metadata keys (account-aliases, _audit_metadata) that contain
        no security-relevant data and would confuse the AI when analyzed standalone.

        Small related files are grouped together so the LLM has enough cross-file
        context to detect findings (e.g., users + credential-report + groups together
        for MFA and key rotation checks).
        """

        if self.strategy == "by_file":
            yield from self._chunk_by_file_grouped(evidence)
        elif self.strategy == "by_resource_count":
            yield from self._chunk_by_resource(evidence)  # Placeholder for now

    def _chunk_by_file_grouped(self, evidence: Dict[str, Any]) -> Iterator[EvidenceChunk]:
        """Chunk evidence grouping small related files for better LLM context."""
        # Collect security-relevant files (skip metadata)
        remaining: Dict[str, Any] = {
            k: v
            for k, v in evidence.items()
            if k not in self.METADATA_KEYS and not str(k).startswith("_")
        }

        emitted: set = set()

        # Emit grouped chunks first
        for group in self._IAM_SMALL_FILE_GROUPS:
            present = {k: remaining[k] for k in group if k in remaining}
            if not present:
                continue

            combined_tokens = self._estimate_tokens(present)
            if combined_tokens <= self.max_tokens:
                yield EvidenceChunk(
                    chunk_id=1,
                    total_chunks=1,
                    evidence=present,
                    metadata={"source_files": sorted(present.keys())},
                )
                emitted.update(present.keys())

        # Emit remaining files individually (or subdivided if large)
        for filename, data in remaining.items():
            if filename in emitted:
                continue
            file_tokens = self._estimate_tokens({filename: data})
            # The LLM prompt also includes the static XML template, full checklist,
            # and deterministic pre-check addendum. Split list-like evidence before
            # it reaches the nominal budget so a "single file" chunk does not still
            # become an oversized prompt.
            should_split = file_tokens > self.max_tokens
            if not should_split and file_tokens > int(self.max_tokens * 0.5):
                if isinstance(data, list):
                    should_split = True
                elif isinstance(data, dict) and self._pick_dominant_list_key(data):
                    should_split = True
            # Security Group evidence is deceptively expensive for the LLM: a modest
            # item count can contain many nested ingress/egress rules and long
            # descriptions. Split it proactively so Claude CLI does not spend the
            # full timeout on a single oversized SG prompt.
            if not should_split and filename == "security-groups" and isinstance(data, dict):
                list_key = self._pick_dominant_list_key(data)
                items = data.get(list_key) if list_key else None
                if isinstance(items, list) and len(items) > 8:
                    should_split = True
            if not should_split and filename in {"policies", "inspector-findings"}:
                if isinstance(data, list) and len(data) > 3:
                    should_split = True
                elif isinstance(data, dict):
                    list_key = self._pick_dominant_list_key(data)
                    items = data.get(list_key) if list_key else None
                    if isinstance(items, list) and len(items) > 3:
                        should_split = True
                    elif isinstance(items, dict) and isinstance(items.get("items"), list):
                        should_split = len(items["items"]) > 3

            if should_split:
                yield from self._chunk_large_file(filename, data)
            else:
                yield EvidenceChunk(
                    chunk_id=1,
                    total_chunks=1,
                    evidence={filename: data},
                    metadata={"source_file": filename},
                )

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
        if filename == "security-groups":
            resources_per_chunk = min(resources_per_chunk, 6)
        if filename == "policies":
            resources_per_chunk = min(resources_per_chunk, 4)
        if filename == "inspector-findings":
            resources_per_chunk = min(resources_per_chunk, 5)

        def _effective_chunk_size(items: list[Any], base: Optional[Dict[str, Any]] = None) -> int:
            """Choose a chunk size that leaves room for checklist/template context."""
            if not items:
                return resources_per_chunk

            # In chunked LLM calls the evidence is only part of the prompt. Keep
            # each evidence fragment well below the nominal budget so the static
            # XML template, checklist, and pre-check addendum do not push Claude
            # CLI into long-running prompts.
            target_tokens = max(1200, int(self.max_tokens * 0.35))
            sample = items[: min(len(items), 5)]
            sample_tokens = max(1, self._estimate_tokens({"items": sample}))
            avg_item_tokens = max(1, sample_tokens // max(1, len(sample)))
            base_tokens = self._estimate_tokens(base or {}) if base else 0
            available_tokens = max(1, target_tokens - base_tokens)
            dynamic_size = max(1, available_tokens // avg_item_tokens)
            return max(1, min(resources_per_chunk, dynamic_size))

        # If the file is not a simple list, try to chunk a dominant list field
        # (common for dict-shaped evidence like {"items": [...]} or {"endpoints": [...]}).
        if not isinstance(data, list):
            if isinstance(data, dict):
                list_key = self._pick_dominant_list_key(data)
                if list_key:
                    # Drop secondary indexes such as by_id/by_name while chunking.
                    # They duplicate the item list and can make every chunk nearly
                    # as large as the original file.
                    base = {
                        k: v
                        for k, v in data.items()
                        if k != list_key and not str(k).startswith("by_")
                    }
                    items_container = data.get(list_key)
                    items = items_container
                    list_wrapper: Dict[str, Any] | None = None
                    if isinstance(items_container, dict) and isinstance(items_container.get("items"), list):
                        list_wrapper = {k: v for k, v in items_container.items() if k != "items"}
                        items = items_container.get("items")
                    if isinstance(items, list):
                        resources_per_chunk = _effective_chunk_size(items, base)
                        total_resources = len(items)
                        total_chunks = (
                            total_resources + resources_per_chunk - 1
                        ) // resources_per_chunk

                        for i in range(0, total_resources, resources_per_chunk):
                            chunk_items = items[i : i + resources_per_chunk]
                            chunk_id = i // resources_per_chunk + 1
                            chunk_value: Any = chunk_items
                            if list_wrapper is not None:
                                chunk_value = {**list_wrapper, "items": chunk_items}
                            yield EvidenceChunk(
                                chunk_id=chunk_id,
                                total_chunks=total_chunks,
                                evidence={filename: {**base, list_key: chunk_value}},
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
        resources_per_chunk = _effective_chunk_size(data)
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
            "findings",
        ]

        for key in preferred:
            val = data.get(key)
            if isinstance(val, list) and len(val) > 0:
                return key
            if isinstance(val, dict) and isinstance(val.get("items"), list) and len(val["items"]) > 0:
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
