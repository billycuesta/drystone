"""Base skill interface for AWS security audits."""

from abc import ABC, abstractmethod
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

        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence directory not found: {evidence_path}")

        for json_file in evidence_path.glob("*.json"):
            try:
                with open(json_file) as f:
                    evidence[json_file.stem] = json.load(f)
            except Exception:
                pass

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
                pre_evaluated_checks=pre_checked_ids | routed_ids,
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
        except Exception:
            pass  # Coverage check is best-effort

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
            "deterministic_checks": route_stats["deterministic_resolved"],
            "total_checks": route_stats["total_checks"],
        }
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

    def _build_precheck_traceability(
        self,
        check_id: str,
        result: Any,
        evidence: Dict[str, Any],
    ) -> tuple[List[str], Optional[Dict[str, Any]]]:
        """Attach best-effort refs/snippet for injected pre-check findings."""

        def _resource_matches(obj: Dict[str, Any], affected: set[str]) -> bool:
            if not affected:
                return False
            candidates = [
                str(obj.get("Arn") or ""),
                str(obj.get("ARN") or ""),
                str(obj.get("RepositoryArn") or ""),
                str(obj.get("RoleArn") or ""),
                str(obj.get("UserArn") or ""),
                str(obj.get("KeyArn") or ""),
                str(obj.get("LoadBalancerArn") or ""),
                str(obj.get("DBInstanceIdentifier") or ""),
                str(obj.get("GroupId") or ""),
                str(obj.get("BucketName") or ""),
                str(obj.get("VpcId") or ""),
                str(obj.get("Id") or ""),
                str(obj.get("Name") or ""),
                str(obj.get("RepositoryName") or ""),
                str(obj.get("ResourceName") or ""),
                str(obj.get("Username") or ""),
                str(obj.get("callerArn") or ""),
                str(obj.get("EventId") or ""),
            ]
            for resource in obj.get("Resources") or []:
                if isinstance(resource, dict):
                    candidates.append(str(resource.get("ResourceName") or ""))
            for c in candidates:
                if not c:
                    continue
                if c in affected:
                    return True
                for a in affected:
                    if c and c in a:
                        return True
            return False

        def _generic_traceability() -> tuple[List[str], Optional[Dict[str, Any]]]:
            affected = set(str(r) for r in (getattr(result, "affected_resources", []) or []))
            refs: List[str] = []
            snippets: List[Dict[str, Any]] = []

            for file_key, doc in (evidence or {}).items():
                if not isinstance(file_key, str) or file_key.startswith("_"):
                    continue

                # Common envelope: {"<collection>": [..]}
                if isinstance(doc, dict):
                    for coll_key in (
                        "items",
                        "repositories",
                        "users",
                        "roles",
                        "vpcs",
                        "security_groups",
                        "securityGroups",
                        "subnets",
                        "policies",
                        "keys",
                        "findings",
                    ):
                        items = doc.get(coll_key)
                        if not isinstance(items, list):
                            continue
                        for idx, item in enumerate(items):
                            if not isinstance(item, dict):
                                continue
                            if _resource_matches(item, affected):
                                refs.append(f"{file_key}.json#/{coll_key}/{idx}")
                                snippets.append(item)
                                if len(snippets) >= 3:
                                    return refs[:10], {"items": snippets}

                    # Single object fallback
                    if _resource_matches(doc, affected):
                        refs.append(f"{file_key}.json#/")
                        snippets.append(doc)
                        if len(snippets) >= 3:
                            return refs[:10], {"items": snippets}

                elif isinstance(doc, list):
                    for idx, item in enumerate(doc):
                        if not isinstance(item, dict):
                            continue
                        if _resource_matches(item, affected):
                            refs.append(f"{file_key}.json#/{idx}")
                            snippets.append(item)
                            if len(snippets) >= 3:
                                return refs[:10], {"items": snippets}

            if refs and snippets:
                return refs[:10], {"items": snippets[:10]}

            if affected:
                return [], {
                    "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                    "affected_resources": list(affected)[:10],
                }

            return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}

        def _list_from_evidence(key: str) -> List[Dict[str, Any]]:
            doc = (evidence or {}).get(key)
            if isinstance(doc, list):
                return [item for item in doc if isinstance(item, dict)]
            if isinstance(doc, dict):
                items = doc.get(key)
                if isinstance(items, list):
                    return [item for item in items if isinstance(item, dict)]
                singular = key[:-1] if key.endswith("s") else key
                items = doc.get(singular)
                if isinstance(items, list):
                    return [item for item in items if isinstance(item, dict)]
            return []

        def _refs_for_resources(
            key: str,
            resources: List[str],
            name_fields: tuple[str, ...],
        ) -> tuple[List[str], List[Dict[str, Any]]]:
            affected = {str(r) for r in resources or []}
            refs: List[str] = []
            matched: List[Dict[str, Any]] = []
            doc = (evidence or {}).get(key)
            items = _list_from_evidence(key)
            pointer_prefix = f"{key}.json#/"
            if isinstance(doc, dict) and isinstance(doc.get(key), list):
                pointer_prefix = f"{key}.json#/{key}/"

            for idx, item in enumerate(items):
                candidates = {str(item.get("Arn") or item.get("ARN") or "")}
                for field_name in name_fields:
                    val = item.get(field_name)
                    if val:
                        candidates.add(str(val))
                if not candidates & affected:
                    if not any(c and any(c in a for a in affected) for c in candidates):
                        continue
                refs.append(f"{pointer_prefix}{idx}")
                matched.append(item)
            return refs[:10], matched[:10]

        def _dedupe_refs(refs: List[str]) -> List[str]:
            seen: set[str] = set()
            out: List[str] = []
            for ref in refs:
                if not ref or ref in seen:
                    continue
                seen.add(ref)
                out.append(ref)
            return out

        def _iam_policy_refs(details: List[Dict[str, Any]]) -> List[str]:
            policy_ids: set[str] = set()

            def _collect(obj: Any) -> None:
                if isinstance(obj, dict):
                    for key, val in obj.items():
                        if key in {"policy_arn", "PolicyArn"} and val:
                            policy_ids.add(str(val))
                        elif key in {"policy_name", "PolicyName"} and val:
                            policy_ids.add(str(val))
                        elif key in {
                            "policy_arns",
                            "PolicyArns",
                            "direct_policy_arns",
                            "group_policy_arns",
                        } and isinstance(val, list):
                            policy_ids.update(str(item) for item in val if item)
                        else:
                            _collect(val)
                elif isinstance(obj, list):
                    for item in obj:
                        _collect(item)

            _collect(details)
            refs: List[str] = []
            for idx, policy in enumerate(_list_from_evidence("policies")):
                candidates = {
                    str(policy.get("Arn") or ""),
                    str(policy.get("PolicyArn") or ""),
                    str(policy.get("PolicyName") or ""),
                }
                if candidates & policy_ids:
                    refs.append(f"policies.json#/{idx}")
            return refs

        def _iam_group_refs(details: List[Dict[str, Any]]) -> List[str]:
            group_names: set[str] = set()
            for detail in details:
                context = detail.get("permission_context") if isinstance(detail, dict) else None
                if isinstance(context, dict):
                    group_names.update(str(g) for g in (context.get("groups") or []) if g)
                for group in detail.get("groups") or [] if isinstance(detail, dict) else []:
                    if isinstance(group, str):
                        group_names.add(group)
            refs: List[str] = []
            for idx, group in enumerate(_list_from_evidence("groups")):
                if str(group.get("GroupName") or "") in group_names:
                    refs.append(f"groups.json#/{idx}")
            return refs

        def _iam_credential_refs(details: List[Dict[str, Any]]) -> List[str]:
            return [
                f"credential-report.csv#{d.get('user')}"
                for d in details
                if isinstance(d, dict) and d.get("user")
            ]

        def _cloudtrail_event_refs() -> tuple[List[str], Optional[Dict[str, Any]]]:
            target_event_names = {"StopLogging", "DeleteTrail", "UpdateTrail"}
            refs: List[str] = []
            events: List[Dict[str, Any]] = []
            seen_event_ids: set[str] = set()

            def _add_event(key: str, idx: int, event: Dict[str, Any]) -> None:
                event_name = str(event.get("EventName") or "")
                if event_name not in target_event_names:
                    return
                refs.append(f"{key}.json#/{idx}")
                event_id = str(event.get("EventId") or f"{key}:{idx}")
                if event_id in seen_event_ids:
                    return
                seen_event_ids.add(event_id)
                events.append(event)

            for idx, event in enumerate(_list_from_evidence("audit-tampering-events")):
                _add_event("audit-tampering-events", idx, event)

            for key in ("stop-logging-events", "delete-trail-events", "update-trail-events"):
                for idx, event in enumerate(_list_from_evidence(key)):
                    _add_event(key, idx, event)

            if not refs:
                return _generic_traceability()

            return _dedupe_refs(refs), {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                "affected_resources": list(getattr(result, "affected_resources", []) or [])[:10],
                "items": events[:10],
            }

        def _indexed_ref_for(
            key: str,
            predicate: Any,
            preferred_index: str = "items",
        ) -> Optional[str]:
            doc = (evidence or {}).get(key)
            if isinstance(doc, dict):
                if preferred_index and isinstance(doc.get(preferred_index), list):
                    for idx, item in enumerate(doc[preferred_index]):
                        if isinstance(item, dict) and predicate(item):
                            return f"{key}.json#/{preferred_index}/{idx}"
                if isinstance(doc.get("items"), list):
                    for idx, item in enumerate(doc["items"]):
                        if isinstance(item, dict) and predicate(item):
                            return f"{key}.json#/items/{idx}"
                for map_name in ("by_name", "by_id", "by_alb_arn"):
                    mapping = doc.get(map_name)
                    if not isinstance(mapping, dict):
                        continue
                    for map_key, item in mapping.items():
                        value = item if isinstance(item, dict) else {"value": item}
                        if predicate(value):
                            return f"{key}.json#{map_name}.{map_key}"
            elif isinstance(doc, list):
                for idx, item in enumerate(doc):
                    if isinstance(item, dict) and predicate(item):
                        return f"{key}.json#/{idx}"
            return None

        if check_id == "CTEF-003":
            return _cloudtrail_event_refs()

        def _hardening_traceability() -> tuple[List[str], Optional[Dict[str, Any]]]:
            metadata = getattr(result, "metadata", None) or {}
            refs: List[str] = []
            snippet: Dict[str, Any] = {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail")
            }

            if check_id == "HRD-004":
                refs.append("security-hub-findings-summary.json#/compliance_status_counts")
                snippet.update(
                    {
                        "compliance_score": metadata.get("compliance_score"),
                        "passed": metadata.get("passed"),
                        "failed": metadata.get("failed"),
                        "warning": metadata.get("warning"),
                    }
                )
            elif check_id in {"HRD-005", "HRD-009", "HRD-012"}:
                severity = str(metadata.get("severity") or "").upper()
                sample_findings = [
                    item for item in (metadata.get("sample_findings") or []) if isinstance(item, dict)
                ]
                if severity:
                    refs.append(f"security-hub-findings-summary.json#/severity_counts/{severity}")
                for sample in sample_findings:
                    idx = sample.get("index")
                    if isinstance(idx, int):
                        refs.append(f"security-hub-findings.json#/{idx}")
                snippet.update(
                    {
                        "count": metadata.get("count"),
                        "severity": severity,
                        "sample_findings": sample_findings[:5],
                    }
                )
            elif check_id == "HRD-010":
                refs.append("config-conformance-packs.json#/")
                snippet.update({"conformance_pack_count": metadata.get("conformance_pack_count", 0)})
            elif check_id == "HRD-014":
                refs.append("guardduty-detectors.json#/")
                snippet.update({"enabled": metadata.get("enabled", False), "service": "GuardDuty"})
            else:
                return _generic_traceability()

            affected_resources = list(getattr(result, "affected_resources", []) or [])
            if affected_resources:
                snippet["affected_resources"] = affected_resources[:10]
            return _dedupe_refs(refs), snippet

        if check_id.startswith("HRD-"):
            return _hardening_traceability()

        def _waf_traceability() -> tuple[List[str], Optional[Dict[str, Any]]]:
            resource_details = [
                item
                for item in ((getattr(result, "metadata", None) or {}).get("resource_details") or [])
                if isinstance(item, dict)
            ]
            affected_resources = list(getattr(result, "affected_resources", []) or [])
            refs: List[str] = []

            if check_id == "WAF-001":
                for detail in resource_details:
                    alb_arn = str(detail.get("load_balancer_arn") or "")
                    ref = _indexed_ref_for(
                        "alb-waf-associations",
                        lambda item, alb_arn=alb_arn: str(item.get("LoadBalancerArn") or "")
                        == alb_arn,
                    )
                    if ref:
                        refs.append(ref)
                if refs:
                    return _dedupe_refs(refs), {
                        "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                        "affected_resources": resource_details or affected_resources,
                    }
                return _generic_traceability()

            if check_id in {"WAF-004", "WAF-006"}:
                for detail in resource_details:
                    web_acl_arn = str(detail.get("web_acl_arn") or "")
                    ref = _indexed_ref_for(
                        "wafv2-web-acls",
                        lambda item, web_acl_arn=web_acl_arn: str(item.get("ARN") or "")
                        == web_acl_arn,
                    )
                    if ref:
                        refs.append(ref)
                if refs:
                    return _dedupe_refs(refs), {
                        "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                        "affected_resources": resource_details or affected_resources,
                    }
                return _generic_traceability()

            if check_id == "WAF-010":
                classic = (evidence or {}).get("waf-classic") or {}
                names = {str(d.get("name") or "") for d in resource_details if d.get("name")}

                global_acls = ((classic.get("global") or {}).get("web_acls") or [])
                for idx, acl in enumerate(global_acls):
                    if isinstance(acl, dict) and str(acl.get("Name") or "") in names:
                        refs.append(f"waf-classic.json#/global/web_acls/{idx}")

                regional = classic.get("regional") or {}
                if isinstance(regional, dict):
                    for region, region_data in regional.items():
                        web_acls = (region_data or {}).get("web_acls") or []
                        for idx, acl in enumerate(web_acls):
                            if isinstance(acl, dict) and str(acl.get("Name") or "") in names:
                                refs.append(f"waf-classic.json#/regional/{region}/web_acls/{idx}")

                if refs:
                    return _dedupe_refs(refs), {
                        "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                        "affected_resources": resource_details or affected_resources,
                    }
                return _generic_traceability()

            return _generic_traceability()

        if check_id.startswith("WAF-"):
            return _waf_traceability()

        def _recon_traceability() -> tuple[List[str], Optional[Dict[str, Any]]]:
            affected_resources = [str(r) for r in (getattr(result, "affected_resources", []) or [])]
            refs: List[str] = []

            if check_id == "RECON-007":
                affected = set(affected_resources)
                lb_doc = (evidence or {}).get("load-balancer-dns") or {}
                for idx, lb in enumerate(lb_doc.get("load_balancers") or []):
                    if not isinstance(lb, dict):
                        continue
                    dns_name = str(lb.get("DNSName") or "")
                    name = str(lb.get("Name") or "")
                    if dns_name in affected or name in affected:
                        refs.append(f"load-balancer-dns.json#/load_balancers/{idx}")
            elif check_id == "RECON-010":
                affected = set(affected_resources)
                eps_doc = (evidence or {}).get("public-endpoints") or {}
                for idx, gw in enumerate(eps_doc.get("nat_gateway_ips") or []):
                    if isinstance(gw, dict) and str(gw.get("PublicIp") or "") in affected:
                        refs.append(f"public-endpoints.json#/nat_gateway_ips/{idx}")
            elif check_id == "RECON-016":
                affected = set(affected_resources)
                eps_doc = (evidence or {}).get("public-endpoints") or {}
                for idx, eip in enumerate(eps_doc.get("elastic_ips") or []):
                    if isinstance(eip, dict) and str(eip.get("PublicIp") or "") in affected:
                        refs.append(f"public-endpoints.json#/elastic_ips/{idx}")
            elif check_id == "RECON-004":
                r53_doc = (evidence or {}).get("route53-zones") or {}
                for zone_idx, zone in enumerate(r53_doc.get("zones") or []):
                    if not isinstance(zone, dict):
                        continue
                    zone_name = str(zone.get("Name") or "")
                    for rec_idx, rec in enumerate(zone.get("Records") or []):
                        if not isinstance(rec, dict):
                            continue
                        marker = f"{rec.get('Name')} ({rec.get('Type')}) in {zone_name}"
                        if marker in affected_resources:
                            refs.append(f"route53-zones.json#/zones/{zone_idx}/Records/{rec_idx}")
            elif check_id == "RECON-008":
                if isinstance((evidence or {}).get("attack-surface-score"), dict):
                    refs.append("attack-surface-score.json#/")

            if not refs:
                return _generic_traceability()

            return _dedupe_refs(refs)[:50], {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                "affected_resources": affected_resources[:10],
                "metadata": getattr(result, "metadata", None) or {},
            }

        if check_id.startswith("RECON-"):
            return _recon_traceability()

        if check_id == "SM-012":
            refs = []
            if isinstance((evidence or {}).get("cloudwatch_alarms"), dict):
                refs.append("cloudwatch_alarms.json#/regions")
            if isinstance((evidence or {}).get("eventbridge_rules"), dict):
                refs.append("eventbridge_rules.json#/regions")
            if refs:
                return _dedupe_refs(refs), {
                    "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                    "affected_resources": list(getattr(result, "affected_resources", []) or []),
                }
            return _generic_traceability()

        def _ser_ec2_002_traceability() -> tuple[List[str], Optional[Dict[str, Any]]]:
            affected_resources = [str(r) for r in (getattr(result, "affected_resources", []) or [])]
            affected_instance_ids = {
                resource.split(":instance/")[-1] if ":instance/" in resource else resource
                for resource in affected_resources
            }
            refs: List[str] = []

            paths_doc = (evidence or {}).get("attack-path-candidates") or {}
            for idx, path in enumerate(paths_doc.get("paths") or []):
                if not isinstance(path, dict):
                    continue
                target = str(path.get("target_resource") or "")
                target_iid = target.split(":instance/")[-1] if ":instance/" in target else target
                if target in affected_resources or target_iid in affected_instance_ids:
                    refs.append(f"attack-path-candidates.json#/paths/{idx}")

            reach_doc = (evidence or {}).get("reachability-graph") or {}
            for idx, edge in enumerate(reach_doc.get("edges") or []):
                if not isinstance(edge, dict):
                    continue
                target = str(edge.get("target") or edge.get("target_resource") or "")
                target_iid = target.split(":instance/")[-1] if ":instance/" in target else target
                if target in affected_resources or target_iid in affected_instance_ids:
                    refs.append(f"reachability-graph.json#/edges/{idx}")

            compute_doc = (evidence or {}).get("compute-inventory") or {}
            for idx, instance in enumerate(compute_doc.get("ec2_instances") or []):
                if not isinstance(instance, dict):
                    continue
                iid = str(instance.get("InstanceId") or "")
                arn = str(instance.get("Arn") or instance.get("InstanceArn") or "")
                if iid in affected_instance_ids or arn in affected_resources:
                    refs.append(f"compute-inventory.json#/ec2_instances/{idx}")

            inspector_doc = (evidence or {}).get("inspector-findings-normalized") or {}
            for idx, finding in enumerate(inspector_doc.get("findings") or []):
                if not isinstance(finding, dict):
                    continue
                resource_ids = []
                for resource in finding.get("resources") or []:
                    if isinstance(resource, dict):
                        rid = str(resource.get("id") or "")
                        resource_ids.append(rid.split(":instance/")[-1] if ":instance/" in rid else rid)
                if affected_instance_ids.intersection(resource_ids):
                    refs.append(f"inspector-findings-normalized.json#/findings/{idx}")

            metadata = getattr(result, "metadata", None) or {}
            sg_ids: set[str] = set()
            for rules in (metadata.get("sg_rules_context") or {}).values():
                if not isinstance(rules, list):
                    continue
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    source = str(rule.get("source") or "")
                    if source in {"0.0.0.0/0", "::/0"} and rule.get("sg_id"):
                        sg_ids.add(str(rule.get("sg_id")))

            network_doc = (evidence or {}).get("network-controls") or {}
            for idx, sg in enumerate(network_doc.get("security_groups") or []):
                if isinstance(sg, dict) and str(sg.get("GroupId") or "") in sg_ids:
                    refs.append(f"network-controls.json#/security_groups/{idx}")

            if not refs:
                return _generic_traceability()

            return _dedupe_refs(refs), {
                "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                "affected_resources": affected_resources[:10],
            }

        if check_id == "SER-EC2-002":
            return _ser_ec2_002_traceability()

        def _s3_refs(details: List[Dict[str, Any]]) -> List[str]:
            refs: List[str] = []
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                bucket = str(detail.get("bucket_name") or "")
                if not bucket:
                    arn = str(detail.get("bucket_arn") or "")
                    bucket = arn.rsplit(":::", 1)[-1] if ":::" in arn else ""
                if not bucket:
                    continue
                ref = _indexed_ref_for(
                    "s3-buckets",
                    lambda item, bucket=bucket: str(item.get("Name") or "") == bucket,
                )
                if ref:
                    refs.append(ref)
            return refs

        def _sg_refs_from_details(details: List[Dict[str, Any]]) -> List[str]:
            refs: List[str] = []
            for detail in details:
                if not isinstance(detail, dict):
                    continue
                sg_ids = []
                if detail.get("security_group_id"):
                    sg_ids.append(str(detail.get("security_group_id")))
                for rule in detail.get("open_rules") or []:
                    if isinstance(rule, dict) and rule.get("security_group_id"):
                        sg_ids.append(str(rule.get("security_group_id")))
                for sg_id in sg_ids:
                    ref = _indexed_ref_for(
                        "security-groups",
                        lambda item, sg_id=sg_id: str(item.get("GroupId") or "") == sg_id,
                    )
                    if ref:
                        refs.append(ref)
            return refs

        if check_id in {
            "EXP-002",
            "EXP-004",
            "EXP-007",
            "EXP-013",
            "EXP-014",
            "EXP-015",
            "EXP-024",
        }:
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if resource_details:
                refs: List[str] = []
                if check_id == "EXP-002":
                    for detail in resource_details:
                        db_id = str(detail.get("db_instance_identifier") or "")
                        ref = _indexed_ref_for(
                            "rds-instances",
                            lambda item, db_id=db_id: str(item.get("DBInstanceIdentifier") or "")
                            == db_id,
                        )
                        if ref:
                            refs.append(ref)
                    refs.extend(_sg_refs_from_details(resource_details))
                elif check_id == "EXP-004":
                    for detail in resource_details:
                        instance_id = str(detail.get("instance_id") or "")
                        for key in ("ec2-instances", "instances", "ec2_instances"):
                            ref = _indexed_ref_for(
                                key,
                                lambda item, instance_id=instance_id: str(
                                    item.get("InstanceId") or item.get("id") or ""
                                )
                                == instance_id,
                            )
                            if ref:
                                refs.append(ref)
                                break
                    refs.extend(_sg_refs_from_details(resource_details))
                elif check_id == "EXP-007":
                    for detail in resource_details:
                        lb_arn = str(detail.get("load_balancer_arn") or "")
                        ref = _indexed_ref_for(
                            "load-balancers",
                            lambda item, lb_arn=lb_arn: str(item.get("LoadBalancerArn") or "")
                            == lb_arn,
                        )
                        if ref:
                            refs.append(ref)
                        refs.append("wafv2-web-acl-alb-associations.json#by_alb_arn")
                elif check_id in {"EXP-013", "EXP-014", "EXP-015", "EXP-024"}:
                    refs.extend(_s3_refs(resource_details))

                summaries = {
                    "EXP-002": f"{len(resource_details)} public RDS instance(s) with internet-open DB ports",
                    "EXP-004": f"{len(resource_details)} EC2 management/DB exposure(s) open to the internet",
                    "EXP-007": f"{len(resource_details)} internet-facing ALB(s) without WAF",
                    "EXP-013": f"{len(resource_details)} S3 bucket(s) without SecureTransport deny",
                    "EXP-014": f"{len(resource_details)} S3 bucket(s) without versioning",
                    "EXP-015": f"{len(resource_details)} S3 policy statement(s) with ineffective public/cross-account conditions",
                    "EXP-024": f"{len(resource_details)} audit/log S3 bucket(s) without customer-managed KMS",
                }
                return (
                    _dedupe_refs(refs)[:30],
                    {
                        "evidence_summary": summaries[check_id],
                        "affected_resources": resource_details,
                    },
                )

        if check_id in {"IAM-002", "IAM-004", "IAM-012", "IAM-014", "IAM-015", "IAM-016"}:
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if resource_details:
                refs, _matched = _refs_for_resources(
                    "users",
                    [str(d.get("arn") or d.get("user") or "") for d in resource_details],
                    ("UserName",),
                )
                if check_id in {"IAM-002", "IAM-012", "IAM-016"}:
                    refs.extend(_iam_credential_refs(resource_details))
                if check_id in {"IAM-002", "IAM-004", "IAM-015", "IAM-016"}:
                    refs.extend(_iam_group_refs(resource_details))
                    refs.extend(_iam_policy_refs(resource_details))
                summaries = {
                    "IAM-002": f"{len(resource_details)} user(s) without MFA on console or active access-key identities",
                    "IAM-004": f"{len(resource_details)} user(s) with access keys older than 90 days",
                    "IAM-012": f"{len(resource_details)} inactive user(s) (>90 days without activity)",
                    "IAM-014": f"{len(resource_details)} user(s) with multiple active access keys",
                    "IAM-015": f"{len(resource_details)} user(s) with direct policy attachments outside groups",
                    "IAM-016": f"{len(resource_details)} IAM user(s) with service-account-like credential patterns",
                }
                return (
                    _dedupe_refs(refs)[:20],
                    {
                        "evidence_summary": summaries[check_id],
                        "affected_resources": resource_details,
                    },
                )

        if check_id in {"IAM-007", "IAM-026", "IAM-041"}:
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if check_id == "IAM-041":
                resource_details = (getattr(result, "metadata", None) or {}).get("detailed_roles")
            if resource_details:
                refs, _matched = _refs_for_resources(
                    "roles",
                    [
                        str(
                            d.get("arn")
                            or d.get("RoleArn")
                            or d.get("role_arn")
                            or d.get("role_name")
                            or d.get("RoleName")
                            or ""
                        )
                        for d in resource_details
                        if isinstance(d, dict)
                    ],
                    ("RoleName",),
                )
                if check_id == "IAM-026":
                    refs.extend(_iam_policy_refs(resource_details))
                summaries = {
                    "IAM-007": f"{len(resource_details)} role(s) with inline policies",
                    "IAM-026": f"{len(resource_details)} role(s) without permissions boundaries",
                    "IAM-041": f"{len(resource_details)} role(s) with AdministratorAccess/PowerUserAccess",
                }
                return (
                    _dedupe_refs(refs)[:20],
                    {
                        "evidence_summary": summaries[check_id],
                        "affected_resources": resource_details,
                    },
                )

        if check_id in {
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
        }:
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if resource_details:
                refs: List[str] = []

                def _add_ref(key: str, field: str, value: Any) -> None:
                    value_str = str(value or "")
                    if not value_str:
                        return
                    ref = _indexed_ref_for(
                        key,
                        lambda item, field=field, value_str=value_str: str(item.get(field) or "")
                        == value_str,
                    )
                    if ref:
                        refs.append(ref)

                for detail in resource_details:
                    if not isinstance(detail, dict):
                        continue
                    if check_id in {"NET-001", "NET-009", "NET-011", "NET-027"}:
                        sg_id = detail.get("security_group_id") or detail.get("resource")
                        _add_ref("security-groups", "GroupId", sg_id)
                    elif check_id in {"NET-003", "NET-010"}:
                        _add_ref(
                            "network-acls",
                            "NetworkAclId",
                            detail.get("network_acl_id") or detail.get("resource"),
                        )
                    elif check_id == "NET-013":
                        _add_ref(
                            "route-tables",
                            "RouteTableId",
                            detail.get("route_table_id") or detail.get("resource"),
                        )
                        _add_ref("nat-gateway-routes", "NatGatewayId", detail.get("nat_gateway_id"))
                        refs.append("vpc-endpoints.json#/items")
                    elif check_id in {"NET-016", "NET-022", "NET-025"}:
                        _add_ref(
                            "subnets", "SubnetId", detail.get("subnet_id") or detail.get("resource")
                        )
                        _add_ref("network-acls", "NetworkAclId", detail.get("network_acl_id"))
                        _add_ref("route-tables", "RouteTableId", detail.get("route_table_id"))
                    elif check_id == "NET-007":
                        _add_ref("vpcs", "VpcId", detail.get("vpc_id") or detail.get("resource"))
                        for route_table_id in detail.get("route_table_ids") or []:
                            _add_ref("route-tables", "RouteTableId", route_table_id)
                        for igw_id in detail.get("internet_gateway_ids") or []:
                            _add_ref("internet-gateways", "InternetGatewayId", igw_id)
                    elif check_id == "NET-008":
                        if detail.get("resource_type") == "rds":
                            _add_ref(
                                "rds-instances", "DBInstanceIdentifier", detail.get("identifier")
                            )
                        elif detail.get("resource_type") == "lambda":
                            _add_ref("lambda-functions", "FunctionName", detail.get("identifier"))
                        for subnet_id in detail.get("public_subnet_ids") or []:
                            _add_ref("subnets", "SubnetId", subnet_id)
                        for route_table_id in detail.get("route_table_ids") or []:
                            _add_ref("route-tables", "RouteTableId", route_table_id)

                summaries = {
                    "NET-001": f"{len(resource_details)} SG rule(s) exposing sensitive ports to the internet",
                    "NET-003": f"{len(resource_details)} NACL(s) with allow-all inbound internet rules",
                    "NET-007": f"{len(resource_details)} internet-facing VPC(s) without Network Firewall evidence",
                    "NET-008": f"{len(resource_details)} critical workload(s) in public subnets",
                    "NET-009": f"{len(resource_details)} SG rule(s) with overly broad CIDR to non-web ports",
                    "NET-010": f"{len(resource_details)} default NACL(s) with allow-all internet rules",
                    "NET-011": f"{len(resource_details)} SG(s) with critical rules missing description",
                    "NET-013": f"{len(resource_details)} route table(s) with NAT default routes and no VPC endpoints",
                    "NET-016": f"{len(resource_details)} subnet(s) associated with default NACLs",
                    "NET-022": f"{len(resource_details)} public subnet(s) with IGW route",
                    "NET-025": f"{len(resource_details)} subnet(s) missing classification tags",
                    "NET-027": f"{len(resource_details)} Security Group(s) missing tags",
                }
                return (
                    _dedupe_refs(refs)[:50],
                    {
                        "evidence_summary": summaries[check_id],
                        "affected_resources": resource_details,
                    },
                )

        if check_id == "EXP-003":
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if resource_details:
                return (
                    ["security-groups.json"],
                    {
                        "evidence_summary": f"{len(resource_details)} SG(s) with SSH/RDP open to 0.0.0.0/0 or ::/0",
                        "affected_resources": resource_details,
                    },
                )

        if check_id in {
            "VULN-002",
            "VULN-004",
            "VULN-008",
            "VULN-010",
            "VULN-011",
            "VULN-009",
            "VULN-023",
            "VULN-024",
        }:
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if resource_details:
                evidence_files = {
                    "VULN-002": "inspector-findings.json",
                    "VULN-004": "inspector-findings.json",
                    "VULN-008": "inspector-findings.json",
                    "VULN-010": "inspector-findings.json",
                    "VULN-011": "ecr-image-scans.json",
                    "VULN-009": "inspector-findings.json",
                    "VULN-023": "ec2-user-data.json",
                    "VULN-024": "lambda-environment-variables.json",
                }
                summaries = {
                    "VULN-002": f"{len(resource_details)} CRITICAL active Inspector finding(s)",
                    "VULN-004": f"{len(resource_details)} ACTIVE Inspector finding(s) with exploitAvailable=YES",
                    "VULN-008": f"{len(resource_details)} ACTIVE HIGH Inspector finding(s) requiring remediation tracking",
                    "VULN-010": f"{len(resource_details)} ACTIVE HIGH/CRITICAL Inspector finding(s) on EC2 service instances",
                    "VULN-011": f"{len(resource_details)} ECR scan configuration item(s) explicitly disabled",
                    "VULN-009": f"{len(resource_details)} resource(s) with 3+ active CVEs",
                    "VULN-023": f"{len(resource_details)} instance(s) with secret-like user-data",
                    "VULN-024": f"{len(resource_details)} Lambda function(s) with sensitive env keys",
                }
                detail_refs: List[str] = []
                for detail in resource_details:
                    if not isinstance(detail, dict):
                        continue
                    if detail.get("evidence_ref"):
                        detail_refs.append(str(detail.get("evidence_ref")))
                    for ref in detail.get("evidence_refs") or []:
                        detail_refs.append(str(ref))
                return (
                    _dedupe_refs(detail_refs or [evidence_files[check_id]])[:50],
                    {
                        "evidence_summary": summaries[check_id],
                        "affected_resources": resource_details,
                    },
                )

        if check_id == "ALRT-005":
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if resource_details:
                refs: List[str] = []
                for detail in resource_details:
                    if not isinstance(detail, dict):
                        continue
                    topic_arn = str(detail.get("topic_arn") or "")
                    if topic_arn:
                        topic_ref = _indexed_ref_for(
                            "sns-topics",
                            lambda item, topic_arn=topic_arn: str(item.get("TopicArn") or "")
                            == topic_arn,
                        )
                        if topic_ref:
                            refs.append(topic_ref)
                        for alarm_name in detail.get("affected_alarms") or []:
                            alarm_ref = _indexed_ref_for(
                                "cloudwatch-alarms",
                                lambda item, alarm_name=str(alarm_name): str(
                                    item.get("AlarmName") or ""
                                )
                                == alarm_name,
                            )
                            if alarm_ref:
                                refs.append(alarm_ref)
                return (
                    _dedupe_refs(refs or ["sns-topics.json"])[:50],
                    {
                        "evidence_summary": (
                            f"{len(resource_details)} SNS topic(s) with no confirmed subscriptions"
                        ),
                        "affected_resources": resource_details,
                    },
                )

        if check_id in {"ALRT-002", "ALRT-007", "ALRT-010", "ALRT-017"}:
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            refs: List[str] = []
            if check_id == "ALRT-002":
                refs.extend(["eventbridge-rules.json", "cloudwatch-metric-filters.json"])
            elif check_id == "ALRT-007":
                refs.append("cloudwatch-metric-filters.json")
            elif check_id == "ALRT-010":
                for alarm_name in getattr(result, "affected_resources", []) or []:
                    alarm_ref = _indexed_ref_for(
                        "cloudwatch-alarms",
                        lambda item, alarm_name=str(alarm_name): str(item.get("AlarmName") or "")
                        == alarm_name,
                    )
                    if alarm_ref:
                        refs.append(alarm_ref)
                if not refs:
                    refs.append("cloudwatch-alarms.json")
            elif check_id == "ALRT-017":
                for log_group_name in getattr(result, "affected_resources", []) or []:
                    lg_ref = _indexed_ref_for(
                        "cloudwatch-log-groups",
                        lambda item, log_group_name=str(log_group_name): str(
                            item.get("LogGroupName") or ""
                        )
                        == log_group_name,
                    )
                    if lg_ref:
                        refs.append(lg_ref)
                if not refs:
                    refs.append("cloudwatch-log-groups.json")

            return (
                _dedupe_refs(refs)[:50],
                {
                    "evidence_summary": getattr(result, "evidence_summary", "pre-check fail"),
                    "affected_resources": resource_details
                    or list(getattr(result, "affected_resources", []) or []),
                },
            )

        if check_id == "KMS-002":
            resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
            if resource_details:
                return (
                    ["kms-grants.json"],
                    {
                        "evidence_summary": (
                            f"{len(resource_details)} unexpected sensitive KMS grant(s)"
                        ),
                        "affected_resources": resource_details,
                    },
                )

        if check_id == "SER-LMB-002":
            front_doc = evidence.get("front-doors", {})
            routes = front_doc.get("api_gateway_routes", []) if isinstance(front_doc, dict) else []
            affected = set(str(r) for r in (getattr(result, "affected_resources", []) or []))
            matched = []
            for route in routes:
                if not isinstance(route, dict):
                    continue
                api_id = str(route.get("ApiId") or "")
                method = str(route.get("Method") or "")
                path = str(route.get("Path") or "")
                key = f"{api_id} {method} {path}".strip()
                ws_key = f"{api_id} (WebSocket API: $connect unauthenticated)"
                if key in affected or ws_key in affected or api_id in affected:
                    matched.append(
                        {
                            "ApiId": route.get("ApiId"),
                            "ApiType": route.get("ApiType"),
                            "Method": route.get("Method"),
                            "Path": route.get("Path"),
                            "AuthorizationType": route.get("AuthorizationType"),
                            "ApiKeyRequired": route.get("ApiKeyRequired"),
                        }
                    )
            if matched:
                return (
                    ["front-doors.json#/api_gateway_routes"],
                    {"api_gateway_routes": matched},
                )
            # Fallback: return all unauth routes from evidence
            unauth_routes = [
                r
                for r in routes
                if isinstance(r, dict)
                and str(r.get("AuthorizationType") or "").upper() in ("NONE", "")
                and str(r.get("Method") or "").upper() not in ("OPTIONS", "$DISCONNECT", "$DEFAULT")
            ]
            if unauth_routes:
                return (
                    ["front-doors.json#/api_gateway_routes"],
                    {
                        "api_gateway_routes": [
                            {
                                "ApiId": r.get("ApiId"),
                                "ApiType": r.get("ApiType"),
                                "Method": r.get("Method"),
                                "Path": r.get("Path"),
                                "AuthorizationType": r.get("AuthorizationType"),
                            }
                            for r in unauth_routes[:5]
                        ]
                    },
                )
            return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}

        if check_id in {"ECR-002", "ECR-005", "ECR-006"}:
            repos_doc = evidence.get("repositories")
            repos = repos_doc.get("repositories") if isinstance(repos_doc, dict) else None
            if not isinstance(repos, list):
                return [], {
                    "evidence_summary": getattr(result, "evidence_summary", "pre-check fail")
                }

            affected = set(str(r) for r in (getattr(result, "affected_resources", []) or []))

            matched = []
            refs: List[str] = []
            for idx, repo in enumerate(repos):
                if not isinstance(repo, dict):
                    continue
                arn = str(repo.get("RepositoryArn") or "")
                name = str(repo.get("RepositoryName") or "")
                name_like = f"repository/{name}" if name else ""
                if affected and arn not in affected and (name_like not in affected):
                    continue

                refs.append(f"repositories.json#/repositories/{idx}")
                if check_id == "ECR-002":
                    matched.append(
                        {
                            "RepositoryName": repo.get("RepositoryName"),
                            "RepositoryArn": repo.get("RepositoryArn"),
                            "ImageTagMutability": repo.get("ImageTagMutability"),
                        }
                    )
                elif check_id == "ECR-005":
                    matched.append(
                        {
                            "RepositoryName": repo.get("RepositoryName"),
                            "RepositoryArn": repo.get("RepositoryArn"),
                            "EncryptionType": repo.get("EncryptionType"),
                            "KmsKey": repo.get("KmsKey"),
                        }
                    )
                elif check_id == "ECR-006":
                    matched.append(
                        {
                            "RepositoryName": repo.get("RepositoryName"),
                            "RepositoryArn": repo.get("RepositoryArn"),
                            "HasLifecyclePolicy": repo.get("HasLifecyclePolicy"),
                            "LifecyclePolicy": repo.get("LifecyclePolicy"),
                        }
                    )

            if refs and matched:
                snippet = {"repositories": matched[:10]}
                return refs[:10], snippet

            return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}

        if check_id not in {"KMS-002", "KMS-007"}:
            return _generic_traceability()

        grants_doc = evidence.get("kms-grants")
        items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
        if not isinstance(items, list):
            return [], None

        def _is_sensitive(grant: Dict[str, Any]) -> bool:
            ops = grant.get("Operations")
            if not isinstance(ops, list):
                return False
            ops_norm = {str(o) for o in ops if o is not None}
            return "Decrypt" in ops_norm or any(o.startswith("GenerateDataKey") for o in ops_norm)

        def _is_expected(grant: Dict[str, Any]) -> bool:
            cons = grant.get("Constraints")
            if not isinstance(cons, dict):
                return False
            has_ctx = bool(
                cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset")
            )
            grantee = str(grant.get("GranteePrincipal") or "")
            issuing = str(grant.get("IssuingAccount") or "")
            serviceish = (
                grantee.endswith(".amazonaws.com")
                or (":assumed-role/" in grantee and "arn:aws:sts::" in grantee)
                or issuing.endswith(".amazonaws.com")
            )
            return has_ctx and serviceish

        for idx, grant in enumerate(items):
            if not isinstance(grant, dict):
                continue
            if check_id == "KMS-002":
                if not _is_sensitive(grant):
                    continue
                if _is_expected(grant):
                    continue
            elif check_id == "KMS-007":
                ops = grant.get("Operations")
                if not isinstance(ops, list):
                    continue
                if "CreateGrant" not in {str(o) for o in ops if o is not None}:
                    continue
                if _is_expected(grant):
                    continue

            ref = f"kms-grants.json#items.{idx}"
            snippet = {
                "GrantId": grant.get("GrantId"),
                "KeyId": grant.get("KeyId"),
                "GranteePrincipal": grant.get("GranteePrincipal"),
                "Operations": grant.get("Operations"),
                "Constraints": grant.get("Constraints"),
            }
            return [ref], snippet

        # fallback to generic traceability for other KMS pre-check fails
        return _generic_traceability()

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
