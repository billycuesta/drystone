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
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from drystone.correlation.models import (
    CorrelatedFinding,
    CVSSScore,
    SourceFindingRef,
    ThreatContext,
)
from drystone.correlation.patterns import PATTERN_METADATA, PATTERN_REGISTRY
from drystone.models.findings import Finding

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
        self.network_graph: Optional[Dict[str, Any]] = None

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

            # Load evidence payloads for pentest enrichment and dynamic patterns.
            evidence_by_skill = self._load_all_evidence()

            if len(findings_by_skill) < 2:
                dynamic_candidates = PATTERN_REGISTRY.get_patterns_for_skills(
                    list(findings_by_skill.keys())
                )
                if not dynamic_candidates or not evidence_by_skill:
                    logger.info("Skipping correlation (< 2 skills executed)")
                    return {
                        "total_correlations": 0,
                        "correlations": [],
                        "patterns_applied": [],
                        "execution_time_seconds": time.time() - start_time,
                        "skipped": True,
                        "reason": "Correlation requires at least 2 skills",
                    }

            total_findings = sum(len(fs) for fs in findings_by_skill.values())
            logger.info(f"Loaded {total_findings} findings from {len(findings_by_skill)} skills")

            # Step 2: Build resource index (once, reused for all patterns)
            # GAPS RESOLVED: GAP-P1 (O(n) matching), GAP-P2 (caching)
            logger.info("Building resource index...")
            all_findings = [f for fs in findings_by_skill.values() for f in fs]
            self._resource_index_cache = self._build_resource_index(all_findings)
            logger.info(f"Indexed {len(self._resource_index_cache)} resources")

            self.network_graph = self.build_network_graph(evidence_by_skill)

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
                    logger.warning(
                        f"Correlation timeout ({self.MAX_EXECUTION_TIME_SECONDS}s), stopping"
                    )
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
                        matches = self._prioritize_matches(
                            matches, self.MAX_CORRELATIONS_PER_PATTERN
                        )

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

            # Step 3b: Apply dynamic pentest patterns (best-effort)
            dynamic_patterns = PATTERN_REGISTRY.get_patterns_for_skills(
                list(findings_by_skill.keys())
            )
            for pattern in dynamic_patterns:
                try:
                    if not pattern.matcher(
                        findings_by_skill, self._resource_index_cache, evidence_by_skill
                    ):
                        continue

                    # Resolve source findings: use source_finder if available (finding-based
                    # patterns), otherwise leave empty (evidence-based patterns).
                    source_findings_list: list = []
                    if pattern.source_finder is not None:
                        try:
                            source_findings_list = pattern.source_finder(
                                findings_by_skill, self._resource_index_cache, evidence_by_skill
                            ) or []
                        except Exception as _sf_err:
                            logger.warning(
                                f"source_finder for {pattern.id} failed: {_sf_err}"
                            )

                    source_ids = sorted({f.id for f in source_findings_list})
                    source_refs = [
                        SourceFindingRef(
                            id=f.id,
                            skill=f.id.split("-")[0].lower(),
                            title=f.title,
                            severity=f.severity,
                            risk_score=f.risk_score,
                            contribution_weight=1.0 / max(len(source_findings_list), 1),
                        )
                        for f in source_findings_list
                    ]
                    affected_resources = list(
                        {arn for f in source_findings_list for arn in f.affected_resources}
                    )

                    # Compound risk: use actual finding scores when available, fallback to formula.
                    if source_findings_list:
                        compound_risk = self._calculate_compound_risk(
                            source_findings_list, pattern.amplification_factor
                        )
                    else:
                        compound_risk = min(10.0, 6.5 * pattern.amplification_factor)

                    self._corr_counter += 1
                    session_id = self.session_dir.name
                    session_prefix = session_id[:8] if len(session_id) >= 8 else "00000000"
                    corr_id = f"CORR-{session_prefix}-{self._corr_counter:03d}"

                    synthetic = CorrelatedFinding(
                        id=corr_id,
                        pattern_id=pattern.id,
                        severity=pattern.severity,
                        compound_risk_score=compound_risk,
                        title=pattern.name,
                        description=pattern.description,
                        attack_path=pattern.attack_path_generator(evidence_by_skill),
                        source_finding_ids=source_ids,
                        source_findings=source_refs,
                        affected_resources=affected_resources,
                        remediation_priority=self._get_remediation_priority(compound_risk),
                        remediation_steps=pattern.remediation_generator(evidence_by_skill),
                        cis_reference=None,
                        pci_dss=None,
                    )
                    correlations.append(synthetic)
                    patterns_applied.append(pattern.id)
                except Exception as e:
                    errors.append(f"Dynamic pattern {pattern.id}: {e}")

            # Step 3c: Validate correlations (deterministic coherence checks)
            correlations = self._validate_correlations(correlations, findings_by_skill)

            # Step 4: Save results
            output = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "skills_analyzed": list(findings_by_skill.keys()),
                    "total_source_findings": total_findings,
                    "patterns_evaluated": len(self.patterns) + len(dynamic_patterns),
                    "patterns_matched": len(patterns_applied),
                },
                "correlations": [
                    self._enrich_correlation_for_pentest(c, evidence_by_skill) for c in correlations
                ],
                "total_correlations": len(correlations),
                "patterns_applied": patterns_applied,
                "execution_time_seconds": time.time() - start_time,
                "errors": errors if errors else None,
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
                "errors": [str(e)],
            }

    def _load_all_evidence(self) -> Dict[str, Any]:
        """Load evidence payloads by skill from session directory."""
        evidence_by_skill: Dict[str, Any] = {}
        evidence_root = self.session_dir / "evidence"
        if not evidence_root.exists():
            return evidence_by_skill

        for skill_dir in evidence_root.iterdir():
            if not skill_dir.is_dir():
                continue
            skill = skill_dir.name
            skill_evidence: Dict[str, Any] = {}
            for jf in skill_dir.glob("*.json"):
                try:
                    with open(jf) as f:
                        skill_evidence[jf.stem] = json.load(f)
                except Exception:
                    continue
            evidence_by_skill[skill] = skill_evidence
        return evidence_by_skill

    def build_network_graph(self, evidence_by_skill: Dict[str, Any]) -> Dict[str, Any]:
        """Build lightweight network graph used for blast-radius estimation."""
        graph = {"vpcs": {}, "routes": [], "tgw_connections": []}
        network_data = (
            evidence_by_skill.get("network", {}) if isinstance(evidence_by_skill, dict) else {}
        )
        vpcs = (
            ((network_data.get("vpcs") or {}).get("items") or [])
            if isinstance(network_data.get("vpcs"), dict)
            else []
        )
        route_tables = (
            ((network_data.get("route-tables") or {}).get("items") or [])
            if isinstance(network_data.get("route-tables"), dict)
            else []
        )
        tgw_topology = network_data.get("transit-gateway-topology") or {}

        for vpc in vpcs:
            if not isinstance(vpc, dict):
                continue
            vpc_id = vpc.get("VpcId")
            if isinstance(vpc_id, str):
                graph["vpcs"][vpc_id] = {
                    "CidrBlock": vpc.get("CidrBlock"),
                    "IsDefault": vpc.get("IsDefault"),
                }

        for rt in route_tables:
            if not isinstance(rt, dict):
                continue
            for route in rt.get("Routes", []) or []:
                if not isinstance(route, dict):
                    continue
                graph["routes"].append(
                    {
                        "Destination": route.get("DestinationCidrBlock")
                        or route.get("DestinationIpv6CidrBlock"),
                        "Target": route.get("GatewayId")
                        or route.get("NatGatewayId")
                        or route.get("TransitGatewayId"),
                        "VpcId": rt.get("VpcId"),
                    }
                )

        if isinstance(tgw_topology, dict):
            for attachment in tgw_topology.get("attachments", []) or []:
                if isinstance(attachment, dict):
                    graph["tgw_connections"].append(
                        {
                            "SourceVpc": attachment.get("ResourceId"),
                            "TransitGatewayId": attachment.get("TransitGatewayId"),
                            "State": attachment.get("State"),
                        }
                    )

        return graph

    def calculate_cvss_score(self, finding: CorrelatedFinding) -> CVSSScore:
        """Calculate simplified CVSS v3.1 mapping for correlation output."""
        sev = finding.severity
        mapping = {
            "Critical": {
                "AV": "N",
                "AC": "L",
                "PR": "N",
                "UI": "N",
                "S": "C",
                "C": "H",
                "I": "H",
                "A": "H",
            },
            "High": {
                "AV": "N",
                "AC": "L",
                "PR": "L",
                "UI": "N",
                "S": "U",
                "C": "H",
                "I": "L",
                "A": "N",
            },
            "Medium": {
                "AV": "A",
                "AC": "L",
                "PR": "L",
                "UI": "R",
                "S": "U",
                "C": "L",
                "I": "L",
                "A": "N",
            },
            "Low": {
                "AV": "L",
                "AC": "H",
                "PR": "H",
                "UI": "R",
                "S": "U",
                "C": "L",
                "I": "N",
                "A": "N",
            },
        }
        m = mapping.get(sev, mapping["Medium"])
        vector = f"CVSS:3.1/AV:{m['AV']}/AC:{m['AC']}/PR:{m['PR']}/UI:{m['UI']}/S:{m['S']}/C:{m['C']}/I:{m['I']}/A:{m['A']}"
        return CVSSScore(
            vector_string=vector,
            base_score=round(float(finding.compound_risk_score), 1),
            attack_vector="Network" if m["AV"] == "N" else "Adjacent",
            attack_complexity="Low" if m["AC"] == "L" else "High",
            privileges_required="None" if m["PR"] == "N" else "Low",
            user_interaction="None" if m["UI"] == "N" else "Required",
            scope="Changed" if m["S"] == "C" else "Unchanged",
            confidentiality_impact="High" if m["C"] == "H" else "Low",
            integrity_impact="High" if m["I"] == "H" else "Low",
            availability_impact="High" if m["A"] == "H" else "Low",
        )

    def map_to_mitre_attack(self, corr: CorrelatedFinding) -> ThreatContext:
        """Map correlation patterns to ATT&CK context."""
        dynamic = PATTERN_REGISTRY.get(corr.pattern_id)
        if dynamic is not None:
            return dynamic.threat_context

        mapping = {
            "iam_network_ssh_compromise": (["TA0001", "TA0004"], ["T1110", "T1078.004"]),
            "exposure_iam_data_exfiltration": (["TA0010"], ["T1537"]),
            "vulns_hardening_persistent_cve": (["TA0001", "TA0008"], ["T1190", "T1021"]),
            "iam_assume_role_privilege_escalation": (["TA0004"], ["T1078.004"]),
        }
        tactics, techniques = mapping.get(corr.pattern_id, ([], []))
        return ThreatContext(
            mitre_attack_tactics=tactics,
            mitre_attack_techniques=techniques,
            observed_in_wild=bool(tactics),
            exploit_maturity="Functional" if tactics else "Not Defined",
        )

    def calculate_blast_radius(self, corr: CorrelatedFinding) -> Dict[str, Any]:
        """Estimate blast radius from affected resources and network graph."""
        scope = (
            "Account-wide" if any(":iam::" in r for r in corr.affected_resources) else "VPC-local"
        )
        if any(r.startswith("arn:aws:s3:::") for r in corr.affected_resources):
            scope = "Cross-service"
        return {
            "scope": scope,
            "affected_resource_count": len(corr.affected_resources),
            "tgw_paths": len((self.network_graph or {}).get("tgw_connections", [])),
        }

    def _enrich_correlation_for_pentest(
        self, corr: CorrelatedFinding, evidence_by_skill: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Return correlation dict augmented with pentest context fields."""
        out = corr.dict()
        dynamic = PATTERN_REGISTRY.get(corr.pattern_id)
        out["cvss"] = self.calculate_cvss_score(corr).dict()
        out["threat_context"] = self.map_to_mitre_attack(corr).dict()
        if dynamic is not None:
            out["exploitability"] = dynamic.exploitability.dict()
        out["technical_impact"] = {
            "blast_radius": self.calculate_blast_radius(corr),
            "lateral_movement_paths": corr.attack_path,
        }
        return out

    def _validate_correlations(
        self,
        correlations: List[CorrelatedFinding],
        findings_by_skill: Dict[str, List[Finding]],
    ) -> List[CorrelatedFinding]:
        """Validate correlation coherence (deterministic).

        Rules:
        1. All source finding IDs must exist in actual findings
        2. At least 2 source findings required for a valid correlation
        3. Remove duplicates by pattern_id + source_finding_ids

        Args:
            correlations: List of correlated findings to validate
            findings_by_skill: Original findings by skill

        Returns:
            Filtered list of valid correlations
        """
        # Build set of all finding IDs
        all_finding_ids: Set[str] = set()
        for findings in findings_by_skill.values():
            for f in findings:
                all_finding_ids.add(f.id)

        valid = []
        seen_keys: Set[str] = set()

        for corr in correlations:
            # Rule 1: All source findings must exist
            source_ids = corr.source_finding_ids or []
            if source_ids and not all(sid in all_finding_ids for sid in source_ids):
                logger.debug(
                    f"Dropping correlation {corr.id}: missing source findings"
                )
                continue

            # Rule 2: At least 2 source findings (skip for dynamic patterns with empty sources)
            if source_ids and len(source_ids) < 2:
                logger.debug(
                    f"Dropping correlation {corr.id}: fewer than 2 source findings"
                )
                continue

            # Rule 3: Dedup by pattern + sources
            dedup_key = f"{corr.pattern_id}|{'|'.join(sorted(source_ids))}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            valid.append(corr)

        if len(valid) < len(correlations):
            logger.info(
                f"Correlation validation: {len(correlations)} → {len(valid)} "
                f"({len(correlations) - len(valid)} dropped)"
            )

        return valid

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
        matches_with_risk = [(match, sum(f.risk_score for f in match)) for match in matches]

        # Sort by risk (highest first)
        matches_with_risk.sort(key=lambda x: x[1], reverse=True)

        # Return top N
        return [match for match, _ in matches_with_risk[:limit]]

    def _create_correlated_finding(
        self, pattern_meta: Dict[str, Any], match_group: List[Finding]
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
            match_group, pattern_meta["amplification_factor"]
        )

        # Build source finding refs
        source_refs = []
        for finding in match_group:
            # Extract skill name from finding ID (IAM-001 → iam)
            skill = finding.id.split("-")[0].lower()

            source_refs.append(
                SourceFindingRef(
                    id=finding.id,
                    skill=skill,
                    title=finding.title,
                    severity=finding.severity,
                    risk_score=finding.risk_score,
                    contribution_weight=1.0 / len(match_group),
                )
            )

        # Collect affected resources
        affected_resources = list(
            set(arn for finding in match_group for arn in finding.affected_resources)
        )

        # Merge CIS references (convert to list if present)
        cis_refs = [finding.cis_reference for finding in match_group if finding.cis_reference]
        if cis_refs:
            cis_refs = list(set(cis_refs))  # Deduplicate

        # Merge PCI DSS controls (convert to dict if needed)
        pci_dss = []
        for finding in match_group:
            if finding.pci_dss:
                for control in finding.pci_dss:
                    # Convert to dict if it's a Pydantic model
                    if hasattr(control, "dict"):
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
            pci_dss=pci_dss if pci_dss else None,
        )

    def _calculate_compound_risk(
        self, source_findings: List[Finding], amplification_factor: float
    ) -> float:
        """Calculate compound risk score.

        GAPS RESOLVED:
        - GAP-T6: Fallback if risk_score missing

        Formula:
            compound = avg(source_risks) × amplification_factor
            capped at 10.0
        """
        severity_fallback = {"Critical": 9.0, "High": 7.0, "Medium": 5.0, "Low": 3.0}

        risks = []
        for finding in source_findings:
            # Try risk_score first
            if hasattr(finding, "risk_score") and finding.risk_score is not None:
                risks.append(finding.risk_score)
            else:
                # Fallback to severity mapping
                fallback = severity_fallback.get(finding.severity, 5.0)
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
