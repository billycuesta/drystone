"""Base skill interface for AWS security audits."""

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from drystone.cloud.aws.client import AWSClient
from drystone.storage.session import AuditSession

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient
    from drystone.models.findings import SkillFindings


def _severity_to_risk(severity: str) -> float:
    """Map severity to a representative risk score."""
    return {
        "Critical": 9.0,
        "High": 7.0,
        "Medium": 4.5,
        "Low": 2.0,
    }.get(severity, 5.0)


def _extract_resource_names(arns: list) -> list:
    """Extract human-readable names from ARNs or plain identifiers."""
    names = []
    for r in arns or []:
        if r.startswith("arn:") and "/" in r:
            names.append(r.split("/")[-1])
        elif r.startswith("arn:") and r.count(":") >= 5:
            names.append(r.split(":")[-1])
        else:
            names.append(r)
    return [n for n in names if n][:5]


def _format_resource_list(names: list) -> str:
    """Format a list of names as 'a, b and c'."""
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + f" and {names[-1]}"


class BaseSkill(ABC):
    """Abstract base class for Drystone security skills.

    Subclasses must implement:
        - name: Property returning skill identifier
        - collect(): Method to collect AWS data and save evidence
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Skill name identifier (e.g., 'iam', 'exposure').

        Returns:
            Unique skill name
        """
        pass

    @abstractmethod
    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect AWS data and save to evidence directory.

        Called by the orchestrator to:
            1. Query AWS APIs using aws_client
            2. Structure the raw data
            3. Save JSON files to session.get_evidence_path(self.name)

        Args:
            aws_client: Authenticated AWS client with credentials
            session: Current audit session for evidence storage

        Raises:
            Exception: If AWS API calls fail or evidence cannot be saved
        """
        pass

    def _save_json(self, filepath: Path, data: Any) -> None:
        """Save JSON evidence with stable formatting and datetime serialization."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _audit_metadata(
        self,
        session: AuditSession,
        region: str,
        *,
        scope: str = "single-region",
        evidence_files: Optional[List[str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build backward-compatible audit metadata for evidence collections."""
        timestamp = datetime.now(timezone.utc).isoformat()
        metadata: Dict[str, Any] = {
            "_region": region,
            "_timestamp": timestamp,
            "_collected_at": timestamp,
            "_scope": scope,
            "_skill": self.name,
            "evidence_files": list(evidence_files or []),
        }
        account_id = getattr(session, "account_id", None)
        if account_id:
            metadata["_account_id"] = account_id
        if extra:
            metadata.update(extra)
        return metadata

    def _wrap_indexed(
        self,
        items: List[Dict[str, Any]],
        *,
        by_key: str,
        index_name: str = "by_id",
        region: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Wrap list evidence with a stable secondary index for traceability."""
        index: Dict[str, Any] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            key = item.get(by_key)
            if isinstance(key, str) and key:
                index[key] = item

        wrapped: Dict[str, Any] = {"items": items, index_name: index}
        if region:
            wrapped["_meta"] = {"_region": region}
        if extra:
            wrapped.update(extra)
        return wrapped

    def _wrap_items(
        self,
        items: List[Dict[str, Any]],
        *,
        region: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Wrap list evidence in the common `items` shape."""
        wrapped: Dict[str, Any] = {"items": items}
        if region:
            wrapped["_meta"] = {"_region": region}
        if extra:
            wrapped.update(extra)
        return wrapped

    def _load_extra_evidence(self, evidence: Dict[str, Any], evidence_path: "Path") -> None:
        """Hook for subclasses to load non-JSON evidence (e.g. CSV, XML).

        Called after all *.json files have been loaded into *evidence*.
        Default implementation is a no-op.

        Args:
            evidence: Mutable dict populated with JSON evidence so far.
            evidence_path: Path to the skill's evidence directory.
        """
        pass

    def analyze(self, session: AuditSession, agent_client: "AgentClient") -> Path:
        """Analyze collected evidence using AI agent with chunking support.

        3-tier validation architecture:
        1. Read all evidence files + checklist
        2. Tier 1: Run deterministic pre-checks (binary PASS/FAIL/SKIP)
        3. Tier 2: Call AI agent (with pre-computed facts injected)
        4. Tier 3: Reconcile AI findings against pre-checks
        5. Normalize remaining findings (existing normalizer)
        6. Save findings + print summary
        """
        import json
        from pathlib import Path

        print("  Reading evidence files...")

        # 1. Read all evidence files
        evidence_path = session.get_evidence_path(self.name)
        evidence = {}
        evidence_load_errors = []

        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence directory not found: {evidence_path}")

        for json_file in evidence_path.glob("*.json"):
            try:
                with open(json_file) as f:
                    evidence[json_file.stem] = json.load(f)
            except Exception as exc:
                evidence_load_errors.append(
                    {
                        "file": json_file.name,
                        "error_type": type(exc).__name__,
                        "message": str(exc),
                    }
                )

        # Hook: subclasses may load additional non-JSON evidence (e.g. CSV files)
        self._load_extra_evidence(evidence, evidence_path)

        print(f"    Loaded {len(evidence)} evidence files")

        # 2. Read checklist
        checklist_path = Path(__file__).parent.parent / "skills" / self.name / "checklist.json"
        if not checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {checklist_path}")

        with open(checklist_path) as f:
            checklist = json.load(f)

        print(f"    Loaded {len(checklist['items'])} security checks")

        # 2a. Filter checklist by QSA depth (before any pipeline processing)
        qsa_depth = getattr(agent_client, "config", {}).get("qsa_depth", "standard")
        _depth_order = {"obvious": 0, "standard": 1, "deep": 2}
        _max_depth = _depth_order.get(qsa_depth, 1)
        original_count = len(checklist.get("items", []))
        checklist["items"] = [
            item
            for item in checklist.get("items", [])
            if _depth_order.get(item.get("qsa_visibility", "standard"), 1) <= _max_depth
        ]
        filtered_count = len(checklist.get("items", []))
        if filtered_count < original_count:
            print(
                f"    Filtered by QSA depth '{qsa_depth}': {original_count} → {filtered_count} checks"
            )

        # 2b. Tier 1: Run deterministic pre-checks
        from drystone.agent.budget import get_budget_policy
        from drystone.analysis.distiller import distill_evidence
        from drystone.analysis.router import route_checklist_for_llm
        from drystone.models.findings import FindingsSummary, SkillFindings
        from drystone.validation.confidence import compute_skill_confidence
        from drystone.validation.pre_checks import run_pre_checks

        pre_check_results = run_pre_checks(self.name, evidence, checklist)
        pass_ids = {r.check_id for r in pre_check_results if r.status == "PASS"}
        fail_ids = {r.check_id for r in pre_check_results if r.status == "FAIL"}
        skip_ids = {r.check_id for r in pre_check_results if r.status == "SKIP"}
        total_items = len(checklist.get("items", []))
        pending = total_items - len(pass_ids) - len(fail_ids) - len(skip_ids)
        print(
            f"  🔍 Pre-checks: {len(pass_ids)} PASS, {len(fail_ids)} FAIL, "
            f"{len(skip_ids)} SKIP, {pending} pending AI"
        )

        # P0 Router: exclude deterministic PASS/FAIL checks from LLM prompt
        routed_checklist, route_stats = route_checklist_for_llm(checklist, pass_ids, fail_ids)
        routed_ids = {
            str(it.get("id"))
            for it in (
                routed_checklist.get("items", []) if isinstance(routed_checklist, dict) else []
            )
            if isinstance(it, dict) and it.get("id")
        }
        print(
            f"  🧭 LLM routing: {route_stats['llm_checks']}/{route_stats['total_checks']} checks "
            f"(deterministic={route_stats['deterministic_resolved']})"
        )

        # P0 Distiller: compact oversized evidence before sending to LLM
        budget = get_budget_policy(
            getattr(agent_client, "provider_type", "claude-cli"),
            self.name,
            getattr(agent_client, "config", {}).get("scan_depth", "normal"),
        )
        distilled_evidence, distill_stats = distill_evidence(
            evidence,
            max_list_items=budget.distill_max_list_items,
        )
        if distill_stats["files_reduced"] > 0:
            print(
                f"  🧪 Evidence distilled: files={distill_stats['files_reduced']}, "
                f"items_removed={distill_stats['items_removed']}"
            )

        if getattr(agent_client, "metrics_tracker", None):
            try:
                agent_client.metrics_tracker.record_llm_budget(
                    self.name,
                    llm_checks=route_stats["llm_checks"],
                    deterministic_checks=route_stats["deterministic_resolved"],
                    distilled_files=distill_stats["files_reduced"],
                    items_removed=distill_stats["items_removed"],
                )
            except Exception:
                pass

        confidence = compute_skill_confidence(
            total_checks=route_stats["total_checks"],
            deterministic_checks=route_stats["deterministic_resolved"],
            llm_checks=route_stats["llm_checks"],
            partial_run=False,
        )
        llm_skipped = route_stats["llm_checks"] == 0
        if llm_skipped:
            print("  ⚡ LLM skipped: all checks resolved deterministically")

        if getattr(agent_client, "metrics_tracker", None):
            try:
                agent_client.metrics_tracker.record_skill_quality(
                    self.name,
                    confidence_score=float(confidence["score"]),
                    confidence_level=str(confidence["level"]),
                    llm_skipped=llm_skipped,
                )
            except Exception:
                pass

        # 3. Tier 2: Call AI agent (with pre-computed facts injected)
        provider_name = agent_client.get_display_name()
        print(f"  Analyzing with {provider_name}...")
        llm_fallback_used = False
        effective_confidence = confidence
        if llm_skipped:
            findings = SkillFindings(
                skill=self.name,
                findings=[],
                summary=FindingsSummary(
                    total_findings=0,
                    critical=0,
                    high=0,
                    medium=0,
                    low=0,
                    overall_risk_score=0.0,
                ),
                evidence_count=len(evidence),
                checklist_version=str(checklist.get("version", "1.0")),
            )
        else:
            try:
                findings = agent_client.analyze_evidence_chunked(
                    skill_name=self.name,
                    evidence=distilled_evidence,
                    checklist=routed_checklist,
                    pre_checks=pre_check_results,
                )
            except Exception as ai_error:
                import logging as _logging

                from drystone.validation.confidence import compute_skill_confidence

                llm_fallback_used = True
                effective_confidence = compute_skill_confidence(
                    total_checks=route_stats["total_checks"],
                    deterministic_checks=route_stats["deterministic_resolved"],
                    llm_checks=0,
                    partial_run=True,
                )
                _logging.getLogger(__name__).warning(
                    f"AI analysis failed for {self.name}: {ai_error}. "
                    f"Falling back to pre-check results only."
                )
                print(
                    f"  ⚠️  AI analysis failed ({type(ai_error).__name__}). Using pre-check results."
                )
                findings = SkillFindings(
                    skill=self.name,
                    findings=[],
                    summary=FindingsSummary(
                        total_findings=0,
                        critical=0,
                        high=0,
                        medium=0,
                        low=0,
                        overall_risk_score=0.0,
                    ),
                    evidence_count=len(evidence),
                    checklist_version=str(checklist.get("version", "1.0")),
                )
                if getattr(agent_client, "metrics_tracker", None):
                    try:
                        agent_client.metrics_tracker.record_skill_quality(
                            self.name,
                            confidence_score=float(effective_confidence["score"]),
                            confidence_level=str(effective_confidence["level"]),
                            llm_skipped=True,
                            llm_fallback_used=True,
                        )
                        agent_client.metrics_tracker.record_llm_budget(
                            self.name,
                            llm_checks=0,
                            deterministic_checks=route_stats["deterministic_resolved"],
                            distilled_files=distill_stats["files_reduced"],
                            items_removed=distill_stats["items_removed"],
                        )
                    except Exception:
                        pass

        chunk_status = agent_client.get_last_analysis_status(self.name) or {}
        chunk_partial = bool(chunk_status.get("partial_results", False))
        if chunk_partial and not llm_fallback_used:
            from drystone.validation.confidence import compute_skill_confidence

            effective_confidence = compute_skill_confidence(
                total_checks=route_stats["total_checks"],
                deterministic_checks=route_stats["deterministic_resolved"],
                llm_checks=route_stats["llm_checks"],
                partial_run=True,
            )
            if getattr(agent_client, "metrics_tracker", None):
                try:
                    agent_client.metrics_tracker.record_skill_quality(
                        self.name,
                        confidence_score=float(effective_confidence["score"]),
                        confidence_level=str(effective_confidence["level"]),
                        llm_skipped=llm_skipped,
                        llm_fallback_used=False,
                        partial_results=True,
                        partial_reason="one_or_more_llm_chunks_failed",
                        failed_chunks=int(chunk_status.get("failed_chunks") or 0),
                        total_chunks=int(chunk_status.get("total_chunks") or 0),
                    )
                except Exception:
                    pass

        # 3b. Tag LLM findings with exploitability_status before reconciliation
        for f in findings.findings:
            if f.exploitability_status is None:
                f.exploitability_status = "probable" if f.evidence_snippet else "theoretical"

        # 4. Tier 3: Reconcile AI findings against pre-checks
        if pre_check_results:
            findings = self._reconcile_with_pre_checks(
                findings, pre_check_results, checklist, evidence=evidence
            )

        # 5. Normalize findings (reduce variance; skip pre-checked IDs)
        print("  Normalizing findings...")
        pre_checked_ids = pass_ids | fail_ids
        findings = self._normalize_findings(
            findings, checklist, evidence=evidence, pre_checked_ids=pre_checked_ids
        )

        # Normalization/report assembly must not be allowed to erase deterministic
        # pre-check evidence. Re-apply authoritative FAIL pre-check data after
        # normalization so injected findings keep impact text and resource-level refs.
        if pre_check_results:
            findings = self._reconcile_with_pre_checks(
                findings, pre_check_results, checklist, evidence=evidence
            )
            self._validate_final_precheck_findings(findings, fail_ids)
            findings = self._refresh_summary(findings, checklist)

        # 5b. Check checklist coverage (log missing criticals)
        try:
            from drystone.validation.checklist_coverage import validate_checklist_coverage

            coverage = validate_checklist_coverage(
                checklist,
                [f.model_dump(mode="json") for f in findings.findings],
                pre_evaluated_checks=pre_checked_ids,
            )
            if not coverage["coverage_valid"]:
                missing_criticals = [
                    d
                    for d in coverage["details"]
                    if not d["evaluated"] and d["check_severity"] == "Critical"
                ]
                if missing_criticals:
                    import logging

                    _logger = logging.getLogger(__name__)
                    for m in missing_criticals:
                        _logger.warning(
                            f"Missing Critical check: {m['check_id']} - {m['check_title']}"
                        )
            print(
                f"  📋 Checklist coverage: {coverage['coverage_percentage']:.0f}% "
                f"({coverage['evaluated_checks']}/{coverage['total_checks']})"
            )
        except Exception as exc:
            coverage_check_error = {
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        else:
            coverage_check_error = None

        # 6. Save findings
        findings_dir = session.get_findings_path()
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / f"{self.name}.json"

        findings.skill = self.name
        findings.evidence_count = len(evidence)
        findings.checklist_version = str(checklist.get("version", "1.0"))
        findings_payload = findings.model_dump(mode="json")
        findings_payload["analysis_metadata"] = {
            "confidence_score": float(effective_confidence["score"]),
            "confidence_level": str(effective_confidence["level"]),
            "llm_skipped": llm_skipped or llm_fallback_used,
            "llm_fallback_used": llm_fallback_used,
            "partial_results": chunk_partial or llm_fallback_used,
            "partial_reason": (
                "llm_fallback_used"
                if llm_fallback_used
                else "one_or_more_llm_chunks_failed" if chunk_partial else ""
            ),
            "failed_chunks": int(chunk_status.get("failed_chunks") or 0),
            "total_chunks": int(chunk_status.get("total_chunks") or 0),
            "failed_chunk_details": chunk_status.get("failed_chunk_details") or [],
            "llm_checks": 0 if llm_fallback_used else route_stats["llm_checks"],
            "llm_checks_attempted": route_stats["llm_checks"],
            "llm_routed_checks": sorted(routed_ids),
            "deterministic_checks": route_stats["deterministic_resolved"],
            "total_checks": route_stats["total_checks"],
            "evidence_load_errors": evidence_load_errors,
        }
        if coverage_check_error:
            findings_payload["analysis_metadata"]["coverage_check_error"] = coverage_check_error
        findings_payload = self._inject_validation_commands(findings_payload, session)

        with open(findings_path, "w") as f:
            json.dump(findings_payload, f, indent=2, default=str)

        # 7. Print summary
        print("\n✅ Analysis complete:")
        print(f"   Total findings: {findings.summary.total_findings}")
        print(f"   Critical: {findings.summary.critical}")
        print(f"   High: {findings.summary.high}")
        print(f"   Medium: {findings.summary.medium}")
        print(f"   Low: {findings.summary.low}")
        print(f"   Overall Risk: {findings.summary.overall_risk_score:.1f}/10")

        return findings_path

    def _refresh_summary(
        self, findings: "SkillFindings", checklist: Dict[str, Any]
    ) -> "SkillFindings":
        """Recompute summary after final deterministic reconciliation."""
        from drystone.validation.findings_normalizer import FindingsNormalizer

        findings.summary = FindingsNormalizer(checklist, skill_name=self.name).recalculate_summary(
            findings.findings
        )
        return findings

    def _inject_validation_commands(
        self, payload: Dict[str, Any], session: AuditSession
    ) -> Dict[str, Any]:
        """Attach reproducible AWS CLI validation commands to findings.

        This augments findings at persistence time so all report formatters can render
        the same command set without format-specific inference.
        """
        from drystone.reports.validation_commands import suggest_aws_cli_commands

        region = self._infer_region_from_evidence(session)
        account_id = getattr(session, "account_id", "") or "<account-id>"

        for finding in payload.get("findings", []):
            existing = finding.get("validation_commands")
            if isinstance(existing, list) and any(str(c).strip() for c in existing):
                continue

            refs = finding.get("evidence_refs", [])
            if not isinstance(refs, list):
                refs = []

            commands = suggest_aws_cli_commands(
                skill=self.name,
                evidence_refs=[str(ref) for ref in refs],
                region=region,
                account_id=str(account_id),
                finding_id=str(finding.get("id", "")),
                affected_resources=[str(r) for r in (finding.get("affected_resources") or [])],
            )
            if commands:
                finding["validation_commands"] = commands

        return payload

    def _infer_region_from_evidence(self, session: AuditSession) -> str:
        evidence_path = session.get_evidence_path(self.name)
        metadata_path = evidence_path / "_audit_metadata.json"
        if metadata_path.exists():
            try:
                import json

                with open(metadata_path) as f:
                    meta = json.load(f)
                region = str(meta.get("_region", "")).strip()
                if region:
                    return region
            except Exception:
                pass
        try:
            import json
            import re

            arn_region_re = re.compile(r"arn:aws:[^:]+:([a-z]{2}-[a-z]+-\d):\d{12}:")
            for json_file in sorted(evidence_path.glob("*.json")):
                with open(json_file) as f:
                    text = json.dumps(json.load(f), default=str)
                match = arn_region_re.search(text)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return "us-east-1"

    def _reconcile_with_pre_checks(
        self,
        findings: "SkillFindings",
        pre_checks: list,
        checklist: Dict[str, Any],
        evidence: Optional[Dict[str, Any]] = None,
    ) -> "SkillFindings":
        """Reconcile AI findings against pre-computed verdicts (Tier 3).

        Rules:
        1. REJECT findings that contradict a PASS pre-check
        2. INJECT findings for FAIL pre-checks that AI missed
        """
        import logging

        from drystone.models.findings import Finding

        _logger = logging.getLogger(__name__)
        pass_ids = {r.check_id for r in pre_checks if r.status == "PASS"}
        fail_results = {r.check_id: r for r in pre_checks if r.status == "FAIL"}

        # Rule 1: Reject findings contradicting PASS
        before = len(findings.findings)
        findings.findings = [f for f in findings.findings if f.id not in pass_ids]
        rejected = before - len(findings.findings)
        if rejected:
            _logger.info(
                f"Pre-check reconciliation: rejected {rejected} findings contradicting PASS"
            )

        # Rule 2: Inject findings for missed FAILs
        existing_ids = {f.id for f in findings.findings}
        checklist_map = {item["id"]: item for item in checklist.get("items", []) if "id" in item}

        injected = 0
        for check_id, result in fail_results.items():
            if check_id not in existing_ids:
                item = checklist_map.get(check_id)
                if item:
                    evidence_refs, evidence_snippet = self._build_precheck_traceability(
                        check_id=check_id,
                        result=result,
                        evidence=evidence or {},
                    )
                    # Merge structured metadata (e.g. cve_details, attack_path) into snippet
                    if getattr(result, "metadata", None):
                        if evidence_snippet is None:
                            evidence_snippet = {}
                        evidence_snippet.update(result.metadata)
                    # Build narrative description for the injected finding.
                    checklist_desc = (item.get("description") or "").strip()
                    evidence_line = (result.evidence_summary or "").strip()

                    from drystone.validation.pre_checks import (
                        PRE_CHECK_ANALOGIES,
                        PRE_CHECK_DESCRIPTIONS,
                        PRE_CHECK_IMPACTS,
                        PRE_CHECK_REMEDIATIONS,
                    )

                    template = PRE_CHECK_DESCRIPTIONS.get(check_id)
                    if template:
                        resource_names = _extract_resource_names(result.affected_resources)
                        resources_str = _format_resource_list(resource_names) or evidence_line
                        result_metadata = getattr(result, "metadata", None) or {}
                        count = int(result_metadata.get("count") or len(result.affected_resources) or 1)
                        precheck_description = template.format(
                            resources=resources_str,
                            count=count,
                            service=self.name.upper(),
                        )
                    else:
                        # Programmatic fallback: narrative opening + checklist context
                        skill_upper = self.name.upper()
                        resource_names = _extract_resource_names(result.affected_resources)
                        resources_str = _format_resource_list(resource_names)
                        if evidence_line:
                            p1 = (
                                f"During the analysis of the {skill_upper} service, it was "
                                f"identified that {evidence_line.rstrip('.')}."
                            )
                            if resources_str:
                                p2 = (
                                    f"Specifically, the following resources are affected: "
                                    f"{resources_str}. {checklist_desc}".strip()
                                )
                            else:
                                p2 = checklist_desc
                        else:
                            p1 = (
                                f"During the analysis of the {skill_upper} service, "
                                f"{checklist_desc}"
                            )
                            p2 = ""
                        precheck_description = f"{p1}\n\n{p2}".strip()

                    analogy = PRE_CHECK_ANALOGIES.get(check_id)

                    base_risk = _severity_to_risk(item.get("severity", "Medium"))
                    effective_risk = (
                        result.risk_score_override
                        if result.risk_score_override is not None
                        else base_risk
                    )
                    effective_severity = item.get("severity", "Medium")
                    if result.risk_score_override is not None:
                        if result.risk_score_override >= 9.0:
                            effective_severity = "Critical"
                        elif result.risk_score_override >= 7.0:
                            effective_severity = "High"
                        elif result.risk_score_override >= 4.0:
                            effective_severity = "Medium"
                        else:
                            effective_severity = "Low"

                    finding = Finding(
                        id=check_id,
                        severity=effective_severity,
                        risk_score=effective_risk,
                        title=item.get("title", check_id),
                        description=precheck_description,
                        remediation=PRE_CHECK_REMEDIATIONS.get(check_id)
                        or item.get("remediation", "See checklist for remediation steps."),
                        affected_resources=result.affected_resources,
                        evidence_refs=evidence_refs,
                        evidence_snippet=evidence_snippet,
                        cis_reference=item.get("cis_reference") or item.get("cis_id"),
                        exploitability_status="validated",
                        impact=PRE_CHECK_IMPACTS.get(check_id),
                        security_analogy=analogy,
                    )
                    findings.findings.append(finding)
                    injected += 1

        if injected:
            _logger.info(f"Pre-check reconciliation: injected {injected} findings for missed FAILs")

        # Rule 2b: Correct existing LLM/deterministic findings using authoritative pre-check data.
        # Some checks are generated deterministically and should not keep older/minimal evidence
        # shapes if the pre-check has richer resource-level metadata.
        _resource_authoritative_checks = {
            "EXP-002",
            "EXP-007",
            "EXP-013",
            "EXP-014",
            "EXP-015",
            "EXP-024",
            "NET-001",
            "NET-003",
            "NET-007",
            "NET-008",
            "NET-009",
            "NET-010",
            "NET-011",
            "NET-013",
            "NET-016",
            "NET-022",
            "NET-025",
            "NET-027",
            "VULN-004",
            "VULN-008",
            "VULN-010",
            "VULN-011",
            "ALRT-002",
            "ALRT-005",
            "ALRT-007",
            "ALRT-010",
            "ALRT-017",
            "HRD-004",
            "HRD-005",
            "HRD-009",
            "HRD-010",
            "HRD-012",
            "HRD-014",
            "SER-EC2-002",
            "WAF-001",
            "WAF-004",
            "WAF-006",
            "WAF-010",
        }
        corrected = 0
        from drystone.validation.pre_checks import PRE_CHECK_IMPACTS

        for check_id, result in fail_results.items():
            if check_id not in _resource_authoritative_checks:
                continue
            if check_id not in existing_ids or not result.affected_resources:
                continue
            for f in findings.findings:
                if f.id == check_id:
                    evidence_refs, evidence_snippet = self._build_precheck_traceability(
                        check_id=check_id,
                        result=result,
                        evidence=evidence or {},
                    )
                    if getattr(result, "metadata", None):
                        if evidence_snippet is None:
                            evidence_snippet = {}
                        evidence_snippet.update(result.metadata)
                    f.affected_resources = list(result.affected_resources)
                    if evidence_refs:
                        f.evidence_refs = evidence_refs
                    if evidence_snippet:
                        f.evidence_snippet = evidence_snippet
                    if PRE_CHECK_IMPACTS.get(check_id):
                        f.impact = PRE_CHECK_IMPACTS[check_id]
                    if getattr(result, "risk_score_override", None) is not None:
                        f.risk_score = result.risk_score_override
                        if result.risk_score_override >= 9.0:
                            f.severity = "Critical"
                        elif result.risk_score_override >= 7.0:
                            f.severity = "High"
                        elif result.risk_score_override >= 4.0:
                            f.severity = "Medium"
                        else:
                            f.severity = "Low"
                    f.exploitability_status = "validated"
                    _logger.debug(
                        f"Pre-check reconciliation: corrected authoritative evidence for {check_id}"
                    )
                    corrected += 1
                    break

        if corrected:
            _logger.info(
                f"Pre-check reconciliation: corrected authoritative evidence on {corrected} finding(s)"
            )

        # Rule 2c: Escalate risk_score / severity on EXISTING LLM findings when the
        # pre-check has a risk_score_override that exceeds the LLM's assessment.
        # This handles the case where the AI correctly detected the finding but
        # under-calibrated the severity (e.g. CVSS 9.8 NETWORK CVE on internet-exposed EC2
        # reported as High 7.2 instead of Critical 9.0).
        escalated = 0
        for check_id, result in fail_results.items():
            if getattr(result, "risk_score_override", None) is None:
                continue
            if check_id not in existing_ids:
                continue  # not present — handled by Rule 2 injection above
            for f in findings.findings:
                if f.id == check_id:
                    current_risk = float(f.risk_score or 0.0)
                    if current_risk < result.risk_score_override:
                        f.risk_score = result.risk_score_override
                        if result.risk_score_override >= 9.0:
                            f.severity = "Critical"
                        elif result.risk_score_override >= 7.0 and f.severity not in ("Critical",):
                            f.severity = "High"
                        _logger.debug(
                            "Pre-check reconciliation: escalated %s from risk=%.1f (%s) "
                            "to risk=%.1f (%s) via risk_score_override",
                            check_id,
                            current_risk,
                            f.severity,
                            result.risk_score_override,
                            f.severity,
                        )
                        escalated += 1
                    break

        if escalated:
            _logger.info(
                f"Pre-check reconciliation: escalated severity on {escalated} finding(s) via risk_score_override"
            )

        return findings

    def _validate_final_precheck_findings(
        self,
        findings: "SkillFindings",
        fail_ids: set[str],
    ) -> None:
        """Block client-facing output if deterministic High/Critical findings are incomplete."""
        issues: List[str] = []
        one_ref_per_resource_checks = {
            "EXP-002",
            "EXP-004",
            "EXP-007",
            "EXP-013",
            "EXP-014",
            "EXP-024",
            "NET-001",
            "NET-003",
            "NET-007",
            "NET-008",
            "NET-009",
            "NET-010",
            "NET-011",
            "NET-013",
                "NET-016",
                "NET-022",
                "NET-025",
                "NET-027",
                "SER-EC2-002",
            }
        for finding in findings.findings:
            if finding.id not in fail_ids:
                continue
            severity = str(finding.severity or "").lower()
            if severity not in {"high", "critical"}:
                continue
            if not str(finding.impact or "").strip():
                issues.append(f"{finding.id} {severity} deterministic finding has empty impact")
            affected = list(finding.affected_resources or [])
            refs = list(finding.evidence_refs or [])
            if finding.id in one_ref_per_resource_checks and affected and len(refs) < len(affected):
                issues.append(
                    f"{finding.id} deterministic finding has {len(affected)} affected "
                    f"resource(s) but only {len(refs)} evidence ref(s)"
                )
        if issues:
            raise ValueError("Final deterministic finding QA failed: " + "; ".join(issues))

    def _skill_specific_traceability(
        self,
        check_id: str,
        result: Any,
        evidence: Dict[str, Any],
    ) -> Optional["tuple[List[str], Optional[Dict[str, Any]]]"]:
        """Override in subclasses that need check-ID-specific traceability.

        Returns None by default, meaning "no override" -- the caller falls
        back to the generic evidence-matching heuristic. See
        skills/{skill}/traceability.py for the 12 skills with overrides
        (P1 #2, 2026-09-16 -- split out of a single 1136-line god-method).
        """
        return None

    def _build_precheck_traceability(
        self,
        check_id: str,
        result: Any,
        evidence: Dict[str, Any],
    ) -> tuple[List[str], Optional[Dict[str, Any]]]:
        """Attach best-effort refs/snippet for injected pre-check findings."""
        override = self._skill_specific_traceability(check_id, result, evidence)
        if override is not None:
            return override

        from drystone.skills._traceability_helpers import generic_traceability

        return generic_traceability(result, evidence)

    def _normalize_findings(
        self,
        findings: "SkillFindings",
        checklist: Dict[str, Any],
        evidence: Any = None,
        pre_checked_ids: Any = None,
    ) -> "SkillFindings":
        """Normalize findings to reduce variance between AI models.

        This method is inherited by ALL skills (IAM, Exposure, Network, Vulns).
        Reduces variance by:
        1. Normalizing IDs (remove sub-IDs like IAM-008-001 → IAM-008)
        2. Filtering false positives (DISREGARD markers, invalid IDs)
        3. Validating against evidence (detect contradictions) — skipped for pre-checked IDs
        4. Resolving mutually exclusive findings (anti-duplicates)
        5. Calibrating severities against checklist constraints
        6. Recalculating summary statistics

        Args:
            findings: Raw findings from AI model
            checklist: Security checklist for this skill
            evidence: AWS evidence data for validation (optional)
            pre_checked_ids: Set of check IDs already resolved by Tier 1 pre-checks.
                           Evidence validation is skipped for these IDs.

        Returns:
            SkillFindings with normalized findings and updated summary
        """
        from drystone.validation.findings_normalizer import FindingsNormalizer

        # Create normalizer for this skill
        normalizer = FindingsNormalizer(checklist, skill_name=self.name)

        # Optionally pass evidence for validation
        if evidence:
            normalizer.evidence = evidence

        # Pass pre-checked IDs to skip redundant evidence validation
        if pre_checked_ids:
            normalizer._pre_checked_ids = pre_checked_ids

        # Normalize findings
        findings.findings = normalizer.normalize(findings.findings)

        # Resolve mutually exclusive findings (anti-duplicates)
        findings.findings = normalizer._resolve_mutual_exclusions(findings.findings)

        # Recalculate summary after all filtering
        findings.summary = normalizer.recalculate_summary(findings.findings)

        return findings
