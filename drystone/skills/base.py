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
        from typing import List, Set

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

        print(f"    Loaded {len(evidence)} evidence files")

        # 2. Read checklist
        checklist_path = Path(__file__).parent.parent / "skills" / self.name / "checklist.json"
        if not checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {checklist_path}")

        with open(checklist_path) as f:
            checklist = json.load(f)

        print(f"    Loaded {len(checklist['items'])} security checks")

        # 2b. Tier 1: Run deterministic pre-checks
        from drystone.analysis.distiller import distill_evidence
        from drystone.analysis.router import route_checklist_for_llm
        from drystone.agent.budget import get_budget_policy
        from drystone.models.findings import FindingsSummary, SkillFindings
        from drystone.validation.pre_checks import run_pre_checks
        from drystone.validation.confidence import compute_skill_confidence

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
        print(
            f"  🧭 LLM routing: {route_stats['llm_checks']}/{route_stats['total_checks']} checks "
            f"(deterministic={route_stats['deterministic_resolved']})"
        )

        # P0 Distiller: compact oversized evidence before sending to LLM
        budget = get_budget_policy(getattr(agent_client, "provider_type", "claude-cli"), self.name)
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
            findings = agent_client.analyze_evidence_chunked(
                skill_name=self.name,
                evidence=distilled_evidence,
                checklist=routed_checklist,
                pre_checks=pre_check_results,
            )

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

        # 5b. Check checklist coverage (log missing criticals)
        try:
            from drystone.validation.checklist_coverage import validate_checklist_coverage

            coverage = validate_checklist_coverage(
                checklist,
                [f.model_dump(mode="json") for f in findings.findings],
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

        findings_payload = findings.model_dump(mode="json")
        findings_payload["analysis_metadata"] = {
            "confidence_score": float(confidence["score"]),
            "confidence_level": str(confidence["level"]),
            "llm_skipped": llm_skipped,
            "llm_checks": route_stats["llm_checks"],
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
                    finding = Finding(
                        id=check_id,
                        severity=item.get("severity", "Medium"),
                        risk_score=_severity_to_risk(item.get("severity", "Medium")),
                        title=item.get("title", check_id),
                        description=f"Pre-check determined: {result.evidence_summary}",
                        remediation=item.get("remediation", "See checklist for remediation steps."),
                        affected_resources=result.affected_resources,
                        evidence_refs=evidence_refs,
                        evidence_snippet=evidence_snippet,
                        cis_reference=item.get("cis_reference") or item.get("cis_id"),
                    )
                    findings.findings.append(finding)
                    injected += 1

        if injected:
            _logger.info(f"Pre-check reconciliation: injected {injected} findings for missed FAILs")

        return findings

    def _build_precheck_traceability(
        self,
        check_id: str,
        result: Any,
        evidence: Dict[str, Any],
    ) -> tuple[List[str], Optional[Dict[str, Any]]]:
        """Attach best-effort refs/snippet for injected pre-check findings."""
        if check_id not in {"KMS-002", "KMS-007"}:
            return [], None

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

        # fallback to pre-check summary only
        return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}

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
