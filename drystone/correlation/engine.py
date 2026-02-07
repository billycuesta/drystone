"""
Correlation engine for cross-skill finding analysis.

GAPS RESOLVED:
- GAP-T1: ID generation (sequential + session prefix)
- GAP-T2: Account-level findings (no ARN)
- GAP-T3: Deduplication cache
- GAP-T4: One correlation per principal
- GAP-T6: risk_score fallback
- GAP-T8: Max 50 correlations per pattern
- GAP-P1: O(n) pattern matching via index
- GAP-P2: Resource index caching
- GAP-P3: 60s timeout
"""
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from collections import defaultdict

from drystone.models.findings import Finding
from drystone.correlation.models import CorrelatedFinding, SourceFindingRef
from drystone.correlation.patterns import PATTERN_METADATA

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Correlates findings across skills to identify compound risks."""

    # GAPS RESOLVED:
    # - GAP-T8: Limit correlations to prevent report bloat
    MAX_CORRELATIONS_PER_PATTERN = 50
    MAX_TOTAL_CORRELATIONS = 200

    # - GAP-P3: Timeout protection
    MAX_EXECUTION_TIME_SECONDS = 60

    def __init__(self, session_dir: Path):
        """Initialize correlation engine.

        Args:
            session_dir: Path to audit session directory
        """
        self.session_dir: Path = session_dir
        self.findings_dir: Path = session_dir / "findings"
        self.patterns: List[Dict[str, Any]] = PATTERN_METADATA

        # GAPS RESOLVED:
        # - GAP-T1: Counter for sequential IDs
        self._corr_counter: int = 0

        # - GAP-T3: Deduplication cache
        self._dedup_cache: Set[str] = set()

        # - GAP-P2: Resource index cache (reused across patterns)
        self._resource_index_cache: Optional[Dict[str, List[Finding]]] = None

    def run(self) -> Dict[str, Any]:
        """Execute correlation across all skills.

        GAPS RESOLVED:
        - GAP-P3: Timeout protection
        - GAP-D3: User feedback during execution

        Returns:
            {
                "total_correlations": int,
                "correlations": List[Dict],
                "patterns_applied": List[str],
                "execution_time_seconds": float,
                "errors": List[str]  # If any patterns failed
            }
        """
        start_time = time.time()
        errors = []

        try:
            logger.info("Starting cross-skill correlation analysis...")

            # Step 1: Load findings
            logger.info("Loading findings from session directory...")
            findings_by_skill = self._load_all_findings()

            if len(findings_by_skill) < 2:
                logger.info("Skipping correlation (< 2 skills executed)")
                return {
                    "total_correlations": 0,
                    "correlations": [],
                    "patterns_applied": [],
                    "execution_time_seconds": time.time() - start_time,
                    "skipped": True,
                    "reason": "Correlation requires at least 2 skills"
                }

            total_findings = sum(len(fs) for fs in findings_by_skill.values())
            logger.info(f"Loaded {total_findings} findings from {len(findings_by_skill)} skills")

            # Step 2: Build resource index (once, reused for all patterns)
            # GAPS RESOLVED: GAP-P1 (O(n) matching), GAP-P2 (caching)
            logger.info("Building resource index...")
            all_findings = [f for fs in findings_by_skill.values() for f in fs]
            self._resource_index_cache = self._build_resource_index(all_findings)
            logger.info(f"Indexed {len(self._resource_index_cache)} resources")

            # Step 3: Apply patterns
            correlations = []
            patterns_applied = []

            for pattern_meta in self.patterns:
                # Check if required skills were executed
                if not all(skill in findings_by_skill for skill in pattern_meta["skills_required"]):
                    logger.debug(f"Skipping pattern {pattern_meta['id']} (missing required skills)")
                    continue

                # Check timeout
                if time.time() - start_time > self.MAX_EXECUTION_TIME_SECONDS:
                    logger.warning(f"Correlation timeout ({self.MAX_EXECUTION_TIME_SECONDS}s), stopping")
                    errors.append(f"Timeout after {self.MAX_EXECUTION_TIME_SECONDS}s")
                    break

                try:
                    logger.info(f"Applying pattern: {pattern_meta['id']}...")

                    # Call pattern match function
                    match_function = pattern_meta["match_function"]
                    matches = match_function(findings_by_skill, self._resource_index_cache)

                    # GAPS RESOLVED: GAP-T8 (limit matches)
                    if len(matches) > self.MAX_CORRELATIONS_PER_PATTERN:
                        logger.warning(
                            f"Pattern {pattern_meta['id']} generated {len(matches)} matches, "
                            f"limiting to {self.MAX_CORRELATIONS_PER_PATTERN} highest-risk"
                        )
                        matches = self._prioritize_matches(matches, self.MAX_CORRELATIONS_PER_PATTERN)

                    # Generate correlated findings
                    for match_group in matches:
                        corr_finding = self._create_correlated_finding(pattern_meta, match_group)

                        if corr_finding:  # Not a duplicate
                            correlations.append(corr_finding)

                    if matches:
                        patterns_applied.append(pattern_meta["id"])
                        logger.info(f"Pattern {pattern_meta['id']}: {len(matches)} correlations")
                    else:
                        logger.debug(f"Pattern {pattern_meta['id']}: No matches")

                except Exception as e:
                    # GAPS RESOLVED: GAP-TS4 (error handling)
                    logger.error(f"Pattern {pattern_meta['id']} failed: {e}", exc_info=True)
                    errors.append(f"Pattern {pattern_meta['id']}: {str(e)}")

            # Step 4: Save results
            output = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "skills_analyzed": list(findings_by_skill.keys()),
                    "total_source_findings": total_findings,
                    "patterns_evaluated": len(self.patterns),
                    "patterns_matched": len(patterns_applied)
                },
                "correlations": [c.dict() for c in correlations],
                "total_correlations": len(correlations),
                "patterns_applied": patterns_applied,
                "execution_time_seconds": time.time() - start_time,
                "errors": errors if errors else None
            }

            # Save to file
            output_file = self.findings_dir / "correlated.json"
            with open(output_file, "w") as f:
                json.dump(output, f, indent=2, default=str)

            logger.info(
                f"✅ Correlation complete: {len(correlations)} compound risks identified "
                f"in {output['execution_time_seconds']:.1f}s"
            )

            return output

        except Exception as e:
            logger.error(f"Correlation engine failed: {e}", exc_info=True)
            return {
                "total_correlations": 0,
                "correlations": [],
                "patterns_applied": [],
                "execution_time_seconds": time.time() - start_time,
                "errors": [str(e)]
            }

    def _load_all_findings(self) -> Dict[str, List[Finding]]:
        """Load findings from all {skill}.json files.

        Returns:
            Dict mapping skill name to list of Finding objects.
        """
        findings = {}

        if not self.findings_dir.exists():
            logger.warning(f"Findings directory not found: {self.findings_dir}")
            return findings

        for skill_file in self.findings_dir.glob("*.json"):
            if skill_file.name == "correlated.json":
                continue  # Skip existing correlations

            skill_name = skill_file.stem

            try:
                with open(skill_file) as f:
                    data = json.load(f)

                    # Handle different file formats
                    if isinstance(data, dict) and "findings" in data:
                        # Format: {"findings": [...], "summary": {...}}
                        finding_dicts = data["findings"]
                    elif isinstance(data, list):
                        # Format: [...]
                        finding_dicts = data
                    else:
                        logger.warning(f"Unexpected format in {skill_file.name}")
                        continue

                    # Convert to Finding objects
                    findings[skill_name] = [Finding(**fd) for fd in finding_dicts]

                    logger.debug(f"Loaded {len(findings[skill_name])} findings from {skill_name}")

            except Exception as e:
                logger.error(f"Failed to load {skill_file.name}: {e}")

        return findings

    def _build_resource_index(self, all_findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Build ARN-to-findings index for fast lookup.

        GAPS RESOLVED:
        - GAP-T2: Account-level findings (no ARN)
        - GAP-P1: O(n) complexity

        Args:
            all_findings: Flat list of all findings

        Returns:
            Dict mapping resource identifier to findings.

            Keys:
            - ARNs: "arn:aws:iam::*:user/admin"
            - Account-level: "account:HRD" (for findings without ARNs)
            - Resource types: "type:iam:user" (for fast filtering)
        """
        resource_index = defaultdict(list)

        for finding in all_findings:
            # Strategy 1: Index by ARN
            if finding.affected_resources:
                for arn in finding.affected_resources:
                    if self._is_valid_arn(arn):
                        resource_index[arn].append(finding)

                        # OPTIMIZATION: Also index by resource type
                        resource_type = self._extract_resource_type(arn)
                        if resource_type:
                            resource_index[f"type:{resource_type}"].append(finding)
                    else:
                        # Malformed ARN
                        resource_index[f"malformed:{finding.id}"].append(finding)
            else:
                # Strategy 2: Account-level finding (no ARN)
                # Index by skill prefix
                skill_prefix = finding.id.split("-")[0]  # "HRD" from "HRD-001"
                resource_index[f"account:{skill_prefix}"].append(finding)

        return dict(resource_index)

    def _is_valid_arn(self, arn: str) -> bool:
        """Validate ARN format."""
        if not arn.startswith("arn:aws:"):
            return False

        parts = arn.split(":")
        return len(parts) >= 6

    def _extract_resource_type(self, arn: str) -> Optional[str]:
        """Extract resource type from ARN for indexing.

        Examples:
          arn:aws:iam::*:user/admin → "iam:user"
          arn:aws:ec2:*:*:security-group/sg-123 → "ec2:security-group"
        """
        if not arn.startswith("arn:aws:"):
            return None

        parts = arn.split(":")
        if len(parts) < 6:
            return None

        service = parts[2]  # iam, ec2, s3
        resource = parts[5].split("/")[0] if "/" in parts[5] else parts[5]

        return f"{service}:{resource}"

    def _prioritize_matches(self, matches: List[List[Finding]], limit: int) -> List[List[Finding]]:
        """Prioritize matches by cumulative risk score.

        GAPS RESOLVED:
        - GAP-T8: Prevent report bloat from too many correlations
        """
        # Calculate cumulative risk for each match
        matches_with_risk = [
            (match, sum(f.risk_score for f in match))
            for match in matches
        ]

        # Sort by risk (highest first)
        matches_with_risk.sort(key=lambda x: x[1], reverse=True)

        # Return top N
        return [match for match, _ in matches_with_risk[:limit]]

    def _create_correlated_finding(
        self,
        pattern_meta: Dict[str, Any],
        match_group: List[Finding]
    ) -> Optional[CorrelatedFinding]:
        """Create CorrelatedFinding from pattern match.

        GAPS RESOLVED:
        - GAP-T1: ID generation
        - GAP-T3: Deduplication
        - GAP-T6: risk_score fallback

        Returns:
            CorrelatedFinding or None if duplicate.
        """
        # GAPS RESOLVED: GAP-T3 (deduplication by source IDs)
        source_ids = sorted([f.id for f in match_group])
        dedup_key = "|".join(source_ids)

        if dedup_key in self._dedup_cache:
            logger.debug(f"Skipping duplicate correlation: {dedup_key}")
            return None

        self._dedup_cache.add(dedup_key)
        self._corr_counter += 1

        # GAPS RESOLVED: GAP-T1 (sequential ID with session prefix)
        session_id = self.session_dir.name
        session_prefix = session_id[:8] if len(session_id) >= 8 else "00000000"
        corr_id = f"CORR-{session_prefix}-{self._corr_counter:03d}"

        # Calculate compound risk
        # GAPS RESOLVED: GAP-T6 (fallback for missing risk_score)
        compound_risk = self._calculate_compound_risk(
            match_group,
            pattern_meta["amplification_factor"]
        )

        # Build source finding refs
        source_refs = []
        for finding in match_group:
            # Extract skill name from finding ID (IAM-001 → iam)
            skill = finding.id.split("-")[0].lower()

            source_refs.append(SourceFindingRef(
                id=finding.id,
                skill=skill,
                title=finding.title,
                severity=finding.severity,
                risk_score=finding.risk_score,
                contribution_weight=1.0 / len(match_group)
            ))

        # Collect affected resources
        affected_resources = list(set(
            arn
            for finding in match_group
            for arn in finding.affected_resources
        ))

        # Merge CIS references (convert to list if present)
        cis_refs = [
            finding.cis_reference
            for finding in match_group
            if finding.cis_reference
        ]
        if cis_refs:
            cis_refs = list(set(cis_refs))  # Deduplicate

        # Merge PCI DSS controls (convert to dict if needed)
        pci_dss = []
        for finding in match_group:
            if finding.pci_dss:
                for control in finding.pci_dss:
                    # Convert to dict if it's a Pydantic model
                    if hasattr(control, 'dict'):
                        pci_dss.append(control.dict())
                    elif isinstance(control, dict):
                        pci_dss.append(control)
                    else:
                        pci_dss.append({"control": str(control)})  # Fallback

        # Determine remediation priority
        remediation_priority = self._get_remediation_priority(compound_risk)

        return CorrelatedFinding(
            id=corr_id,
            pattern_id=pattern_meta["id"],
            severity=pattern_meta["severity"],
            compound_risk_score=compound_risk,
            title=pattern_meta["title_template"],
            description=pattern_meta["description_template"],
            attack_path=pattern_meta["attack_path_steps"],
            source_finding_ids=source_ids,
            source_findings=source_refs,
            affected_resources=affected_resources,
            remediation_priority=remediation_priority,
            remediation_steps=pattern_meta["remediation_template"],
            cis_reference=cis_refs if cis_refs else None,
            pci_dss=pci_dss if pci_dss else None
        )

    def _calculate_compound_risk(
        self,
        source_findings: List[Finding],
        amplification_factor: float
    ) -> float:
        """Calculate compound risk score.

        GAPS RESOLVED:
        - GAP-T6: Fallback if risk_score missing

        Formula:
            compound = avg(source_risks) × amplification_factor
            capped at 10.0
        """
        SEVERITY_FALLBACK = {
            "Critical": 9.0,
            "High": 7.0,
            "Medium": 5.0,
            "Low": 3.0
        }

        risks = []
        for finding in source_findings:
            # Try risk_score first
            if hasattr(finding, "risk_score") and finding.risk_score is not None:
                risks.append(finding.risk_score)
            else:
                # Fallback to severity mapping
                fallback = SEVERITY_FALLBACK.get(finding.severity, 5.0)
                risks.append(fallback)
                logger.warning(
                    f"Finding {finding.id} missing risk_score, using {fallback} "
                    f"from severity {finding.severity}"
                )

        if not risks:
            return 5.0  # Default: Medium

        # Compound = average × amplification (capped at 10.0)
        avg_risk = sum(risks) / len(risks)
        compound = min(avg_risk * amplification_factor, 10.0)

        return round(compound, 1)

    def _get_remediation_priority(self, risk_score: float) -> str:
        """Map risk score to remediation priority."""
        if risk_score >= 9.0:
            return "Immediate (0-7 days)"
        elif risk_score >= 7.0:
            return "High (8-30 days)"
        elif risk_score >= 5.0:
            return "Medium (31-90 days)"
        else:
            return "Low (90+ days)"
