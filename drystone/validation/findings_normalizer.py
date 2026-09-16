"""Post-processing normalizer for AI-generated findings.

Reduces variance between different AI models by:
1. Normalizing finding IDs (IAM-008-001 → IAM-008)
2. Calibrating severities against checklist constraints
3. Filtering false positives and duplicates
4. Validating findings against evidence (evidence-based filtering)
5. Resolving mutually exclusive findings (anti-duplicates)
6. Recalculating risk scores with consistent formula

SKILL-AGNOSTIC: Works with any skill (IAM, Exposure, Network, Vulns).
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, cast

from drystone.models.findings import Finding, FindingsSummary, PCIDSSControl
from drystone.validation.normalizer_hooks import NormalizerContext, get_normalizer_hook

logger = logging.getLogger(__name__)


Severity = Literal["Critical", "High", "Medium", "Low"]


def _kms_grant_is_sensitive(grant: Dict[str, Any]) -> bool:
    ops = grant.get("Operations")
    if not isinstance(ops, list):
        return False
    ops_norm = {str(o) for o in ops if o is not None}
    return "Decrypt" in ops_norm or any(o.startswith("GenerateDataKey") for o in ops_norm)


def _kms_grant_has_context_constraints(grant: Dict[str, Any]) -> bool:
    cons = grant.get("Constraints")
    if not isinstance(cons, dict):
        return False
    return bool(cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset"))


def _kms_grant_is_service_managed(grant: Dict[str, Any]) -> bool:
    grantee = str(grant.get("GranteePrincipal") or "")
    issuing = str(grant.get("IssuingAccount") or "")
    if grantee.endswith(".amazonaws.com"):
        return True
    if ":assumed-role/" in grantee and "arn:aws:sts::" in grantee:
        return True
    if issuing.endswith(".amazonaws.com"):
        return True
    return False


def _principal_has_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws_p = principal.get("AWS")
        if aws_p == "*":
            return True
        if isinstance(aws_p, list) and any(p == "*" for p in aws_p):
            return True
    return False


class FindingsNormalizer:
    """Normalizes findings from different AI models to ensure consistency.

    Reduces variance by enforcing:
    - Simple ID format: SKILL-XXX (no sub-IDs like IAM-008-001)
    - Severity ranges: Critical 8.5-10, High 6.0-8.4, Medium 3.0-5.9, Low 1.0-2.9
    - Checklist constraints: Only valid IDs, no false positives, max 1 per item
    - Risk score calibration: Aligned with severity ranges

    Works for any skill by using skill name + checklist ID mapping.

    Example:
        >>> normalizer = FindingsNormalizer(
        ...     checklist={"items": [{"id": "IAM-001", "severity": "Critical"}]},
        ...     skill_name="iam"
        ... )
        >>> normalized = normalizer.normalize(raw_findings)
        >>> summary = normalizer.recalculate_summary(normalized)
    """

    # Severity ranges (risk_score bounds)
    SEVERITY_RANGES = {
        "Critical": (8.5, 10.0),
        "High": (6.0, 8.4),
        "Medium": (3.0, 5.9),
        "Low": (1.0, 2.9),
    }

    # Mutually exclusive findings pairs: (ID1, ID2) → resolution strategy
    # Strategy: "keep_specific" (keep more specific/detailed finding)
    #           "keep_higher" (keep higher severity finding)
    MUTUAL_EXCLUSIONS = {
        # Hardening: Config state
        ("HRD-001", "HRD-006"): "keep_specific",  # Config: disabled vs partial
        # Hardening: Security Hub state
        ("HRD-002", "HRD-003"): "keep_specific",  # Hub: disabled vs no standards
        # Hardening: Compliance score ranges (overlapping ranges)
        ("HRD-004", "HRD-008"): "keep_higher",  # Compliance: <50% vs 50-70%
        ("HRD-008", "HRD-011"): "keep_higher",  # Compliance: 50-70% vs 70-85%
        ("HRD-004", "HRD-011"): "keep_higher",  # Compliance: <50% vs 70-85%
        ("HRD-004", "HRD-015"): "keep_higher",  # Compliance: <50% vs 85-95%
        ("HRD-008", "HRD-015"): "keep_higher",  # Compliance: 50-70% vs 85-95%
        ("HRD-011", "HRD-015"): "keep_higher",  # Compliance: 70-85% vs 85-95%
        # IAM: User state
        ("IAM-003", "IAM-004"): "keep_specific",  # Inactive user vs no MFA
        ("IAM-005", "IAM-007"): "keep_specific",  # No rotation vs old keys
        ("IAM-008", "IAM-009"): "keep_specific",  # Weak policy vs no policy
        # IAM: Root account
        ("IAM-001", "IAM-002"): "keep_higher",  # No MFA vs partial MFA
        # KMS: grant broadness vs persistence-specific finding
        ("KMS-002", "KMS-007"): "keep_specific",
        # Alerting: CloudTrail state
        ("ALR-001", "ALR-003"): "keep_specific",  # Disabled vs no logs
        ("ALR-003", "ALR-005"): "keep_specific",  # No logs vs no alarms
    }

    def __init__(self, checklist: Dict[str, Any], skill_name: str):
        """Initialize normalizer with checklist reference.

        Args:
            checklist: Security checklist for this skill (from checklist.json)
                      Must have 'items' array with id/severity fields
            skill_name: Skill identifier (e.g., 'iam', 'exposure', 'network', 'vulns')

        Raises:
            ValueError: If checklist format invalid or skill_name not provided
        """
        if not checklist or "items" not in checklist:
            raise ValueError("Checklist must have 'items' array")

        self.checklist = checklist
        self.skill_name = skill_name.upper()  # IAM, EXPOSURE, NETWORK, VULNS
        self.evidence: Optional[Dict[str, Any]] = None  # Optional evidence for validation
        self._pre_checked_ids: set = set()  # IDs already resolved by Tier 1 pre-checks

        # Build mapping: {ID → checklist item}
        # Example: {"IAM-001": {...}, "IAM-007": {...}, ...}
        self.checklist_map = {item["id"]: item for item in checklist["items"] if "id" in item}
        self._hook_context = NormalizerContext(
            skill_name=self.skill_name,
            checklist_map=self.checklist_map,
            evidence=self.evidence,
        )
        self._skill_hook = get_normalizer_hook(self.skill_name, self._hook_context)

    def _sync_hook_context(self) -> None:
        """Keep lazy skill hooks aligned with mutable normalizer state."""
        self._hook_context.evidence = self.evidence

    def normalize(self, findings: List[Finding]) -> List[Finding]:
        """Normalize all findings to reduce variance.

        Steps:
        1. Normalize each finding ID (remove sub-IDs)
        2. Skip duplicates (keep first occurrence of normalized ID)
        3. Skip false positives (e.g., "DISREGARD THIS FINDING")
        4. Skip findings that contradict evidence (if evidence provided)
        5. Calibrate severity against checklist constraints
        6. Return normalized list

        Args:
            findings: Raw findings from AI model

        Returns:
            Normalized findings list with:
            - Simple IDs (SKILL-XXX format)
            - Valid severities from checklist
            - Risk scores in correct ranges
            - No false positives or duplicates

        Example:
            >>> findings = [Finding(id="IAM-008-001", severity="High", ...)]
            >>> normalized = normalizer.normalize(findings)
            >>> normalized[0].id  # Returns "IAM-008"
        """
        logger.debug(f"Normalizing {len(findings)} findings...")
        normalized = []
        seen_ids = set()

        for finding in findings:
            # 1. Normalize ID (remove sub-IDs)
            normalized_id = self._normalize_id(finding.id)

            self._sync_hook_context()
            normalized_id = self._skill_hook.remap_id(normalized_id, finding)

            # 2. Skip duplicates
            if normalized_id in seen_ids:
                logger.debug(f"  ⏭️  Skipped duplicate: {finding.id} → {normalized_id}")
                continue
            seen_ids.add(normalized_id)

            # 3. Skip false positives
            if self._is_false_positive(finding):
                logger.debug(
                    f"  ❌ Rejected false positive: {finding.id} (severity: {finding.severity})"
                )
                continue

            # 4. Validate against evidence (if available)
            if self.evidence and not self._validate_against_evidence(normalized_id, finding):
                logger.warning(
                    f"  ❌ Rejected {normalized_id} - contradicts evidence (severity: {finding.severity})"
                )
                continue

            # 5. Calibrate severity. Pre-check findings may carry evidence-derived
            # risk_score_override values that intentionally differ from the static
            # checklist severity, so preserve them.
            if normalized_id in self._pre_checked_ids:
                severity = cast(Severity, finding.severity)
                risk_score = finding.risk_score
            else:
                severity, risk_score = self._calibrate_severity(
                    normalized_id, finding.severity, finding.risk_score
                )

            severity, risk_score = self._apply_contextual_severity_adjustments(
                normalized_id, finding, severity, risk_score
            )

            # Update finding in-place
            finding.id = normalized_id
            finding.severity = severity
            finding.risk_score = risk_score

            # Ensure impact is populated (fallback from severity template)
            self._ensure_impact(finding)

            # Keep model-provided title to preserve report language alignment.

            # Patch obviously incorrect account IDs in affected resource ARNs using audit metadata.
            # This avoids reports listing placeholder ARNs like 123456789012.
            if self.evidence and isinstance(self.evidence.get("_audit_metadata"), dict):
                meta = cast(Dict[str, Any], self.evidence.get("_audit_metadata") or {})
                audit_account = meta.get("_account_id")
                audit_region = meta.get("_region")
                if isinstance(audit_account, str) and audit_account.isdigit():
                    patched = []
                    for r in finding.affected_resources or []:
                        if not isinstance(r, str):
                            patched.append(r)
                            continue

                        # Fix malformed EC2 ARNs sometimes emitted by the model, e.g.
                        # arn:aws:ec2:us-east-1:vpc/subnet-xxxx
                        if (
                            isinstance(audit_region, str)
                            and r.startswith("arn:aws:ec2:")
                            and ":vpc/" in r
                            and len(r.split(":")) == 5
                        ):
                            p5 = r.split(":")
                            region = p5[3]
                            suffix = p5[4]
                            if suffix.startswith("vpc/"):
                                resid = suffix.split("/", 1)[1]
                                if resid.startswith("subnet-"):
                                    r = f"arn:aws:ec2:{region}:{audit_account}:subnet/{resid}"
                                elif resid.startswith("rtb-"):
                                    r = f"arn:aws:ec2:{region}:{audit_account}:route-table/{resid}"
                                elif resid.startswith("vpc-"):
                                    r = f"arn:aws:ec2:{region}:{audit_account}:vpc/{resid}"
                                elif resid.startswith("acl-"):
                                    r = f"arn:aws:ec2:{region}:{audit_account}:network-acl/{resid}"

                        if r.startswith("arn:aws:"):
                            parts = r.split(":")
                            # arn:partition:service:region:account:...
                            if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                                parts[4] = audit_account
                                r = ":".join(parts)
                        patched.append(r)
                    finding.affected_resources = patched

            # Normalize evidence references into resolvable JSON pointers when possible.
            # This is especially important for skills where evidence is stored as structured
            # JSON documents and the model may output shorthand anchors.
            finding.evidence_refs = self._normalize_evidence_refs(finding.evidence_refs)

            # Verify finding has minimum evidence quality requirements.
            if self.evidence:
                verified, reason = self._verify_finding(normalized_id, finding)
                if not verified:
                    logger.warning(f"  ❌ Rejected {normalized_id} - unverified: {reason}")
                    continue

            # Align PCI DSS mappings with checklist source of truth.
            # The agent sometimes emits incorrect control IDs for a given finding ID.
            self._align_pci_dss_controls(normalized_id, finding)

            # Strip LLM-injected meta-keys from evidence_snippet (e.g. "Note", "note").
            # The AI sometimes appends explanatory notes that don't belong in the snippet.
            if isinstance(finding.evidence_snippet, dict):
                finding.evidence_snippet = {
                    k: v
                    for k, v in finding.evidence_snippet.items()
                    if k.lower() not in ("note", "notes", "_note", "_notes")
                }

            logger.debug(f"  ✅ Accepted: {normalized_id} | {severity} | risk={risk_score:.1f}")
            normalized.append(finding)

        # Fallback: populate security_analogy from PRE_CHECK_ANALOGIES for findings
        # that the LLM didn't provide an analogy for but have a known pre-check analogy.
        from drystone.validation.pre_checks import PRE_CHECK_ANALOGIES

        for finding in normalized:
            if not finding.security_analogy:
                fallback = PRE_CHECK_ANALOGIES.get(finding.id)
                if fallback:
                    finding.security_analogy = fallback
                    logger.debug(f"  🔄 Analogy fallback applied for {finding.id}")

        return normalized

    def _verify_finding(self, finding_id: str, finding: Finding) -> Tuple[bool, Optional[str]]:
        """Verify finding is backed by usable evidence.

        This is a generic safety net complementary to skill-specific evidence gates.
        """

        refs = finding.evidence_refs or []

        # If refs are missing or too coarse, try to infer stable refs from evidence
        # + affected resources. This keeps high/critical findings traceable enough
        # for the final reporting QA gate.
        if finding.severity in {"Critical", "High"} and self.evidence:
            inferred = self._infer_evidence_refs(finding)
            if inferred:
                merged = list(refs)
                for ref in inferred:
                    if ref not in merged:
                        merged.append(ref)
                finding.evidence_refs = merged
                refs = merged

        # Critical findings must be backed by something usable: evidence_refs, evidence_snippet,
        # or directly discoverable signal in loaded evidence.
        if finding.severity == "Critical" and not refs:
            # IAM findings must be traceable to specific evidence locations.
            # For other skills we allow evidence_snippet/evidence-content-based verification.
            # Exception: pre-check confirmed findings (in _pre_checked_ids) are already
            # verified against real evidence deterministically — no refs needed.
            if self.skill_name in {"IAM"} and finding_id not in self._pre_checked_ids:
                return False, "missing evidence_refs for critical finding"

        # Rule 2: references should resolve to known evidence keys/files
        for ref in refs:
            if not isinstance(ref, str):
                continue
            if not self._resolve_evidence_ref(ref):
                return False, f"unresolved evidence ref: {ref}"

        # Rule 3: critical findings require stronger evidence signal.
        # Skip for findings already confirmed deterministically by Tier-1 pre-checks
        # (_pre_checked_ids) — those have been verified against real evidence and
        # don't need a heuristic signal check.
        if (
            finding.severity == "Critical"
            and finding_id not in self._pre_checked_ids
            and self.skill_name not in {"HARDENING"}
            and not self._has_critical_evidence(finding)
        ):
            return False, "critical severity without critical evidence"

        # Rule 4: if affected resources are provided, at least one should exist in evidence.
        # Exception: pre-check verified findings use deterministic ARNs (e.g. execute-api:*)
        # that may not appear verbatim in raw evidence files but are still valid.
        resources = finding.affected_resources or []
        if (
            finding.severity == "Critical"
            and resources
            and finding_id not in self._pre_checked_ids
            and not self._resources_exist_in_evidence(resources)
        ):
            return False, "critical finding has affected_resources not found in evidence"

        return True, None

    def _apply_contextual_severity_adjustments(
        self,
        finding_id: str,
        finding: Finding,
        severity: Severity,
        risk_score: float,
    ) -> Tuple[Severity, float]:
        """Apply evidence-based severity adjustments for nuanced scenarios."""
        self._sync_hook_context()
        adjusted = self._skill_hook.adjust_severity(finding_id, finding, severity, risk_score)
        if adjusted is not None:
            return cast(Severity, adjusted[0]), adjusted[1]

        return severity, risk_score

    def _kms_001_is_managed_default_pattern(self, finding: Finding) -> bool:
        if not self.evidence:
            return False

        refs = finding.evidence_refs or []
        if not refs:
            return False

        ev = cast(Dict[str, Any], self.evidence)
        keys_doc = ev.get("kms-keys")
        key_items = keys_doc.get("items") if isinstance(keys_doc, dict) else []
        keyman_by_id: Dict[str, str] = {}
        if isinstance(key_items, list):
            for it in key_items:
                if not isinstance(it, dict):
                    continue
                kid = str(it.get("KeyId") or "")
                meta = it.get("Metadata") if isinstance(it.get("Metadata"), dict) else {}
                km = str(meta.get("KeyManager") or "")
                if kid:
                    keyman_by_id[kid] = km

        pol_doc = ev.get("kms-key-policies")
        pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else []
        idx_to_policy: Dict[int, Dict[str, Any]] = {}
        if isinstance(pol_items, list):
            for i, it in enumerate(pol_items):
                if isinstance(it, dict):
                    idx_to_policy[i] = it

        seen_any = False
        for ref in refs:
            if not isinstance(ref, str) or not ref.startswith("kms-key-policies.json#items."):
                continue
            try:
                idx = int(ref.split("#items.", 1)[1])
            except Exception:
                continue
            rec = idx_to_policy.get(idx)
            if not isinstance(rec, dict):
                continue
            seen_any = True
            key_id = str(rec.get("KeyId") or "")
            if keyman_by_id.get(key_id, "").upper() != "AWS":
                return False

            policy = rec.get("Policy")
            if not isinstance(policy, dict):
                return False
            stmts = policy.get("Statement")
            stmt_list = (
                stmts if isinstance(stmts, list) else [stmts] if isinstance(stmts, dict) else []
            )

            wildcard_stmt_ok = False
            for st in stmt_list:
                if not isinstance(st, dict):
                    continue
                if str(st.get("Effect") or "").upper() != "ALLOW":
                    continue
                if not _principal_has_wildcard(st.get("Principal")):
                    continue
                cond = st.get("Condition") if isinstance(st.get("Condition"), dict) else {}
                if not isinstance(cond, dict):
                    continue
                s_eq = (
                    cond.get("StringEquals") if isinstance(cond.get("StringEquals"), dict) else {}
                )
                s_like = cond.get("StringLike") if isinstance(cond.get("StringLike"), dict) else {}
                has_caller = isinstance(s_eq, dict) and bool(s_eq.get("kms:CallerAccount"))
                via = None
                if isinstance(s_eq, dict):
                    via = s_eq.get("kms:ViaService")
                if via is None and isinstance(s_like, dict):
                    via = s_like.get("kms:ViaService")
                has_via = bool(via)
                if has_caller and has_via:
                    wildcard_stmt_ok = True
                    break

            if not wildcard_stmt_ok:
                return False

        return seen_any

    def _infer_evidence_refs(self, finding: Finding) -> List[str]:
        """Best-effort evidence_refs inference for common resource types.

        Keep this conservative: only add refs when we can confidently point to evidence.
        """

        if not isinstance(self.evidence, dict):
            return []

        evidence = cast(Dict[str, Any], self.evidence)

        resources = [r for r in (finding.affected_resources or []) if isinstance(r, str)]
        if not resources:
            return []

        refs: List[str] = []

        def _find_in_items(doc_key: str, match_key: str, match_val: str) -> Optional[int]:
            doc = evidence.get(doc_key)
            if not isinstance(doc, dict):
                return None
            items = doc.get("items")
            if not isinstance(items, list):
                return None
            for idx, it in enumerate(items):
                if isinstance(it, dict) and it.get(match_key) == match_val:
                    return idx
            return None

        for r in resources:
            # Security Group ARN
            if ":security-group/" in r:
                sg_id = r.split(":security-group/", 1)[1]
                sg_doc = evidence.get("security-groups")
                if isinstance(sg_doc, dict):
                    by_id = sg_doc.get("by_id")
                    if isinstance(by_id, dict) and sg_id in by_id:
                        refs.append(f"security-groups.json#by_id.{sg_id}")
                        continue
                idx = _find_in_items("security-groups", "GroupId", sg_id)
                if isinstance(idx, int):
                    refs.append(f"security-groups.json#/items/{idx}")
                    continue

            # RDS instance ARN
            if ":db:" in r and r.startswith("arn:aws:rds:"):
                db_id = r.split(":db:", 1)[1]
                idx = _find_in_items("rds-instances", "DBInstanceIdentifier", db_id)
                if isinstance(idx, int):
                    refs.append(f"rds-instances.json#/items/{idx}")
                    continue

            # ELBv2 ARN
            if r.startswith("arn:aws:elasticloadbalancing:") and ":loadbalancer/" in r:
                lb_doc = evidence.get("load-balancers")
                if isinstance(lb_doc, dict):
                    by_id = lb_doc.get("by_id")
                    if isinstance(by_id, dict) and r in by_id:
                        refs.append(f"load-balancers.json#by_id.{r}")
                        continue
                idx = _find_in_items("load-balancers", "LoadBalancerArn", r)
                if isinstance(idx, int):
                    refs.append(f"load-balancers.json#/items/{idx}")
                    continue

            # IAM role / instance profile ARN.
            if r.startswith("arn:aws:iam::") and (":role/" in r or ":instance-profile/" in r):
                profile_doc = evidence.get("instance-profiles")
                profiles = []
                if isinstance(profile_doc, dict):
                    profiles = profile_doc.get("instance_profiles") or []
                if isinstance(profiles, list):
                    matched_profile = False
                    for idx, profile in enumerate(profiles):
                        if not isinstance(profile, dict):
                            continue
                        if ":instance-profile/" in r and str(profile.get("Arn") or "") == r:
                            refs.append(f"instance-profiles.json#/instance_profiles/{idx}")
                            matched_profile = True
                            break
                        for role_idx, role in enumerate(profile.get("Roles") or []):
                            if isinstance(role, dict) and str(role.get("Arn") or "") == r:
                                refs.append(
                                    f"instance-profiles.json#/instance_profiles/{idx}/Roles/{role_idx}"
                                )
                                matched_profile = True
                                break
                        else:
                            continue
                        break
                    if matched_profile:
                        continue

        # Deduplicate but preserve order
        out: List[str] = []
        for ref in refs:
            if ref not in out:
                out.append(ref)
        return out

    def _resolve_evidence_ref(self, ref: str) -> bool:
        """Check whether evidence reference points to available evidence payload."""

        if not isinstance(self.evidence, dict):
            return True

        file_ref = ref.split("#", 1)[0].strip()
        if not file_ref:
            return False

        filename = Path(file_ref).name
        stem = Path(filename).stem

        # Fail-open when the referenced evidence file is not present in loaded evidence.
        # This avoids false rejections for tests/chunks where only partial evidence is loaded.
        if (
            filename not in self.evidence
            and stem not in self.evidence
            and file_ref not in self.evidence
        ):
            return True

        return file_ref in self.evidence or filename in self.evidence or stem in self.evidence

    def _has_critical_evidence(self, finding: Finding) -> bool:
        """Heuristic critical-evidence check for severity verification."""

        snippet = finding.evidence_snippet or {}
        text = json.dumps(snippet, default=str).lower()

        # Obvious strong indicators.
        if "root" in text and ("accesskey" in text or "mfa" in text):
            return True
        if "0.0.0.0/0" in text and ("22" in text or "ssh" in text):
            return True
        if '"principal"' in text and ('": "*"' in text or '":"*"' in text):
            return True
        # Wildcard action/resource in policy is also strong signal (IAM policy admin).
        if '"action"' in text and '"*"' in text:
            return True
        if "httptokens" in text and "optional" in text:
            return True
        if "critical" in text:
            return True

        # Also accept if referenced evidence files are clearly critical-oriented.
        refs = " ".join([str(r).lower() for r in (finding.evidence_refs or [])])
        for token in ("root", "guardduty", "inspector", "public", "exfiltration"):
            if token in refs:
                return True

        # Evidence-backed signal without snippet/refs:
        # - Some validators use minimal findings without evidence_refs but provide evidence payloads.
        # - Allow these when we can detect strong indicators directly in evidence.
        if isinstance(self.evidence, dict):
            evidence_text = json.dumps(self.evidence, default=str).lower()
            if '"principal"' in evidence_text and '"*"' in evidence_text:
                return True
            if "0.0.0.0/0" in evidence_text or "::/0" in evidence_text:
                return True
            if "internet-facing" in evidence_text:
                return True
            if "publiclyaccessible" in evidence_text and "true" in evidence_text:
                return True
            if "ispublic" in evidence_text and "true" in evidence_text:
                return True

        return False

    def _resources_exist_in_evidence(self, resources: List[str]) -> bool:
        """Check if at least one affected resource can be found in loaded evidence."""

        if not isinstance(self.evidence, dict) or not resources:
            return True

        evidence_blob = json.dumps(self.evidence, default=str)

        def _candidates(r: str) -> List[str]:
            out = [r]
            if ":security-group/" in r:
                out.append(r.split(":security-group/", 1)[1])
            if ":subnet/" in r:
                out.append(r.split(":subnet/", 1)[1])
            if ":route-table/" in r:
                out.append(r.split(":route-table/", 1)[1])
            if ":vpc/" in r:
                out.append(r.split(":vpc/", 1)[1])
            if ":db:" in r:
                out.append(r.split(":db:", 1)[1])
            if ":loadbalancer/" in r:
                out.append(r.split(":loadbalancer/", 1)[1])
            if "/" in r:
                out.append(r.rsplit("/", 1)[1])
            return [x for x in out if isinstance(x, str) and x]

        for resource in resources:
            if not isinstance(resource, str) or not resource:
                continue
            for cand in _candidates(resource):
                if cand in evidence_blob:
                    return True

        return False

    def _align_pci_dss_controls(self, finding_id: str, finding: Finding) -> None:
        """Ensure finding.pci_dss matches the checklist mapping for this finding ID.

        For compliance reporting, the checklist is the source of truth for which
        PCI DSS controls a check maps to. We keep the agent-provided reason when
        it matches a checklist control; otherwise we fall back to the checklist reason.
        """

        item = self.checklist_map.get(finding_id)
        if not item:
            return

        allowed = item.get("pci_dss") or []
        if not isinstance(allowed, list) or not allowed:
            # Checklist does not map this check to PCI; drop any model-emitted mapping.
            finding.pci_dss = []
            return

        existing: Dict[str, PCIDSSControl] = {}
        for c in finding.pci_dss or []:
            # Be defensive: in some tests/edge-cases this may be a dict.
            if isinstance(c, dict):
                cid = c.get("control")
                reason = c.get("reason")
                if isinstance(cid, str) and cid:
                    existing[cid] = PCIDSSControl(control=cid, reason=str(reason or ""))
                continue

            try:
                if c.control:
                    existing[c.control] = c
            except Exception:
                continue

        new_controls: List[PCIDSSControl] = []
        for pci in allowed:
            if not isinstance(pci, dict):
                continue
            cid = pci.get("control")
            if not isinstance(cid, str) or not cid:
                continue

            reason = None
            if cid in existing and getattr(existing[cid], "reason", None):
                reason = existing[cid].reason
            if not reason:
                reason = pci.get("reason") or "Control mapping found in checklist."

            new_controls.append(PCIDSSControl(control=cid, reason=reason))

        finding.pci_dss = new_controls

    def _remap_exposure_id(self, finding_id: str, finding: Finding) -> str:
        """Remap Exposure finding IDs when content matches a different checklist item.

        - EXP-001 is strictly "public S3 bucket". If the finding is actually about
          cross-account bucket policy access (non-public), remap to EXP-015.
        """

        if finding_id != "EXP-001":
            return finding_id

        if not self.evidence:
            return finding_id

        meta = self.evidence.get("_audit_metadata")
        audit_account = None
        if isinstance(meta, dict):
            audit_account = meta.get("_account_id")
        if isinstance(audit_account, str):
            audit_account = audit_account.strip()

        snippet = finding.evidence_snippet
        if not isinstance(snippet, dict):
            return finding_id

        sn = cast(Dict[str, Any], snippet)
        policy = sn.get("BucketPolicy")
        if not isinstance(policy, dict):
            return finding_id

        # If it's truly public, keep EXP-001.
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict):
                continue
            if st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                return finding_id

        # Otherwise, detect cross-account IAM principals.
        principals: List[str] = []
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict):
                continue
            if st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if not isinstance(principal, dict):
                continue
            aws_p = principal.get("AWS")
            if isinstance(aws_p, str):
                principals.append(aws_p)
            elif isinstance(aws_p, list):
                principals.extend([p for p in aws_p if isinstance(p, str)])

        iam_principals = [p for p in principals if p.startswith("arn:aws:iam::")]
        if not iam_principals:
            return finding_id

        if isinstance(audit_account, str) and audit_account.isdigit():
            for p in iam_principals:
                parts = p.split(":")
                # arn:aws:iam::<acct>:...
                if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                    return "EXP-015"

        # If we can't confirm account id, still remap: it's non-public bucket policy exposure.
        return "EXP-015"

    def _remap_network_id(self, finding_id: str, finding: Finding) -> str:
        """Remap Network finding IDs based on evidence.

        NET-004 is specifically about *sensitive resources* in subnets that have
        0.0.0.0/0 -> IGW routing. If we can only confirm the subnet is public but
        cannot confirm sensitive resources in that subnet, remap to NET-022.
        """

        if finding_id != "NET-004":
            return finding_id

        if not self.evidence:
            return finding_id

        if "NET-022" not in self.checklist_map:
            return finding_id

        route_tables = self.evidence.get("route-tables")
        enis = self.evidence.get("network-interfaces")
        sgs = self.evidence.get("security-groups")

        # Route tables with 0.0.0.0/0 -> igw-* define "public" routing.
        rt_items: List[Dict[str, Any]] = []
        if isinstance(route_tables, dict) and isinstance(route_tables.get("items"), list):
            rt_items = cast(List[Dict[str, Any]], route_tables.get("items") or [])
        elif isinstance(route_tables, list):
            rt_items = cast(List[Dict[str, Any]], route_tables)

        public_subnets: List[str] = []
        for rt in rt_items:
            if not isinstance(rt, dict):
                continue
            routes = rt.get("Routes", []) or []
            if not isinstance(routes, list):
                continue
            has_igw_default = False
            for r in routes:
                if not isinstance(r, dict):
                    continue
                if r.get("DestinationCidrBlock") != "0.0.0.0/0":
                    continue
                gw = r.get("GatewayId")
                if isinstance(gw, str) and gw.startswith("igw-"):
                    has_igw_default = True
                    break
            if not has_igw_default:
                continue

            assocs = rt.get("Associations", []) or []
            if not isinstance(assocs, list):
                continue
            for a in assocs:
                if isinstance(a, dict):
                    sid = a.get("SubnetId")
                    if isinstance(sid, str) and sid.startswith("subnet-"):
                        public_subnets.append(sid)
                elif isinstance(a, str) and a.startswith("subnet-"):
                    public_subnets.append(a)

        public_subnets = sorted(set(public_subnets))
        if not public_subnets:
            return finding_id

        eni_items: List[Dict[str, Any]] = []
        if isinstance(enis, dict) and isinstance(enis.get("items"), list):
            eni_items = cast(List[Dict[str, Any]], enis.get("items") or [])
        elif isinstance(enis, list):
            eni_items = cast(List[Dict[str, Any]], enis)

        sg_by_id: Dict[str, Dict[str, Any]] = {}
        if isinstance(sgs, dict) and isinstance(sgs.get("by_id"), dict):
            sg_by_id = cast(Dict[str, Dict[str, Any]], sgs.get("by_id") or {})

        sensitive_markers = (
            "rds",
            "db",
            "database",
            "postgres",
            "mysql",
            "mariadb",
            "mongo",
            "redis",
            "elasticache",
        )

        def _is_sensitive_eni(eni: Dict[str, Any]) -> bool:
            desc = (eni.get("Description") or "").lower()
            if any(m in desc for m in sensitive_markers):
                return True
            for g in eni.get("Groups", []) or []:
                if not isinstance(g, dict):
                    continue
                gid = g.get("GroupId")
                if not isinstance(gid, str):
                    continue
                sg = sg_by_id.get(gid) or {}
                name = (sg.get("GroupName") or "").lower()
                if any(m in name for m in sensitive_markers):
                    return True
            return False

        for eni in eni_items:
            if not isinstance(eni, dict):
                continue
            sid = eni.get("SubnetId")
            if sid not in public_subnets:
                continue
            if _is_sensitive_eni(eni):
                return finding_id

        # No sensitive indicators found in public subnets; downgrade scenario to NET-022.
        return "NET-022"

    def _normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        """Normalize evidence_refs to resolvable JSON pointers.

        (Implementation note)
        This method includes skill-specific normalization for:
        - Secrets Manager (SECRETSMANAGER)
        - ECR (ECR)
        """
        if not refs:
            return refs

        self._sync_hook_context()
        return self._skill_hook.normalize_evidence_refs(refs)

    def _normalize_evidence_refs_alerting(
        self, refs: List[str], evidence: Dict[str, Any]
    ) -> List[str]:
        """Normalize Alerting evidence refs such as 'cloudwatch-metric-filters'."""
        normalized: List[str] = []
        evidence_keys = {str(k) for k in evidence.keys()}
        for ref in refs:
            rr = str(ref).strip()
            if not rr:
                continue
            base, sep, suffix = rr.partition("#")
            if not base.endswith(".json") and base in evidence_keys:
                base = f"{base}.json"
            normalized.append(f"{base}{sep}{suffix}" if sep else base)
        return normalized

    def _normalize_evidence_refs_hardening(self, refs: List[str]) -> List[str]:
        """Normalize Hardening evidence refs for consistent report traceability."""

        out: List[str] = []
        for r in refs:
            if not isinstance(r, str):
                continue

            rr = r.strip()
            if rr.startswith("security-hub-findings#"):
                rr = rr.replace("security-hub-findings#", "security-hub-findings.json#", 1)
            if rr.startswith("security-hub-findings-summary#"):
                rr = rr.replace(
                    "security-hub-findings-summary#",
                    "security-hub-findings-summary.json#",
                    1,
                )
            if rr.startswith("security-hub-enabled-standards#"):
                rr = rr.replace(
                    "security-hub-enabled-standards#",
                    "security-hub-enabled-standards.json#",
                    1,
                )

            out.append(rr)

        return out

    def _normalize_evidence_refs_kms(self, refs: List[str], evidence: Dict[str, Any]) -> List[str]:
        """Normalize KMS refs like #<keyid>/#KeyId=<id>/#<grantid> to items.<idx>."""
        out: List[str] = []

        pol_doc = evidence.get("kms-key-policies")
        pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else []
        keyid_to_idx: Dict[str, int] = {}
        if isinstance(pol_items, list):
            for i, it in enumerate(pol_items):
                if isinstance(it, dict):
                    kid = str(it.get("KeyId") or "").strip()
                    if kid:
                        keyid_to_idx[kid] = i

        grants_doc = evidence.get("kms-grants")
        grant_items = grants_doc.get("items") if isinstance(grants_doc, dict) else []
        grantid_to_idx: Dict[str, int] = {}
        if isinstance(grant_items, list):
            for i, it in enumerate(grant_items):
                if isinstance(it, dict):
                    gid = str(it.get("GrantId") or "").strip()
                    if gid:
                        grantid_to_idx[gid] = i

        for r in refs:
            if not isinstance(r, str):
                continue
            rr = r.strip()

            if rr.startswith("kms-key-policies.json#"):
                anchor = rr.split("#", 1)[1]
                if anchor.startswith("items."):
                    out.append(rr)
                    continue

                key_id = anchor
                if anchor.startswith("KeyId="):
                    key_id = anchor.split("=", 1)[1]

                idx = keyid_to_idx.get(key_id)
                if idx is not None:
                    out.append(f"kms-key-policies.json#items.{idx}")
                else:
                    out.append(rr)
                continue

            if rr.startswith("kms-grants.json#"):
                anchor = rr.split("#", 1)[1]
                if anchor.startswith("items."):
                    out.append(rr)
                    continue
                idx = grantid_to_idx.get(anchor)
                if idx is not None:
                    out.append(f"kms-grants.json#items.{idx}")
                else:
                    out.append(rr)
                continue

            out.append(rr)

        return out

    def _normalize_evidence_refs_network(
        self, refs: List[str], evidence: Dict[str, Any]
    ) -> List[str]:
        """Normalize Network evidence references to indexed documents."""

        # Best-effort resolve SG and VPC anchors to by_id.
        out: List[str] = []
        sg_id: Optional[str] = None

        for r in refs:
            if not isinstance(r, str):
                continue
            rr = r.strip()

            if rr.startswith("security-groups.json#"):
                anchor = rr.split("#", 1)[1]

                if not sg_id and anchor.startswith("sg-"):
                    sg_id = anchor

                # Already normalized
                if anchor.startswith("by_id."):
                    out.append(rr)
                    continue

                # sg-xxxx anchor
                if anchor.startswith("sg-"):
                    doc = evidence.get("security-groups")
                    if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                        if anchor in (doc.get("by_id") or {}):
                            out.append(f"security-groups.json#by_id.{anchor}")
                            continue
                    out.append(rr)
                    continue

                # IngressRules[0] style anchor: attach to inferred SG if possible
                if anchor.startswith("IngressRules") and sg_id:
                    out.append(f"security-groups.json#by_id.{sg_id}.{anchor}")
                    continue

                out.append(rr)
                continue

            if rr.startswith("vpcs.json#"):
                anchor = rr.split("#", 1)[1]
                if anchor.startswith("by_id."):
                    out.append(rr)
                    continue
                # Keep original; evidence-based validation uses by_id anyway.
                out.append(rr)
                continue

            out.append(rr)

        return out

    def _normalize_evidence_refs_exposure(
        self, refs: List[str], evidence: Dict[str, Any]
    ) -> List[str]:
        """Normalize Exposure evidence references to indexed documents.

        Exposure evidence is stored as indexed documents of the form:
        - {"items": [...], "by_id": {...}} or for S3: {"items": [...], "by_name": {...}}

        The model often emits anchors like:
        - security-groups.json#sg-123
        - s3-buckets.json#my-bucket
        - rds-instances.json#db-identifier

        This method rewrites them to stable anchors:
        - security-groups.json#by_id.sg-123
        - s3-buckets.json#by_name.my-bucket
        - rds-instances.json#by_id.db-identifier
        """

        def _rewrite(doc_key: str, filename: str, anchor: str, *, map_key: str) -> str:
            # Only rewrite if evidence has the expected index.
            doc = evidence.get(doc_key)
            if not isinstance(doc, dict):
                return f"{filename}#{anchor}"
            idx = doc.get(map_key)
            if not isinstance(idx, dict):
                return f"{filename}#{anchor}"
            if anchor not in idx:
                return f"{filename}#{anchor}"
            return f"{filename}#{map_key}.{anchor}"

        out: List[str] = []
        for r in refs:
            if not isinstance(r, str):
                continue
            if "#" not in r:
                rr = r.strip()
                # The model sometimes emits index-only refs like "by_name.bucket".
                if rr.startswith("by_name."):
                    out.append(f"s3-buckets.json#{rr}")
                    continue
                if rr.startswith("by_id."):
                    key = rr.split(".", 1)[1] if "." in rr else ""
                    # Try to resolve which evidence doc owns this id.
                    if key:
                        for doc_key, file_name in [
                            ("security-groups", "security-groups.json"),
                            ("rds-instances", "rds-instances.json"),
                            ("rds-snapshots", "rds-snapshots.json"),
                            ("ami-images", "ami-images.json"),
                            ("cloudfront-distributions", "cloudfront-distributions.json"),
                            ("load-balancers", "load-balancers.json"),
                        ]:
                            doc = evidence.get(doc_key)
                            if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                                if key in (doc.get("by_id") or {}):
                                    out.append(f"{file_name}#{rr}")
                                    break
                        else:
                            out.append(rr)
                        continue

                out.append(r)
                continue

            filename, anchor = r.split("#", 1)
            # Normalize common filename variants
            filename = filename.strip()
            anchor = anchor.strip()

            # If already using indexed anchors, keep as-is.
            if anchor.startswith("by_name.") or anchor.startswith("by_id."):
                out.append(f"{filename}#{anchor}")
                continue

            if filename == "security-groups.json":
                out.append(_rewrite("security-groups", filename, anchor, map_key="by_id"))
                continue
            if filename == "rds-instances.json":
                out.append(_rewrite("rds-instances", filename, anchor, map_key="by_id"))
                continue
            if filename == "rds-snapshots.json":
                out.append(_rewrite("rds-snapshots", filename, anchor, map_key="by_id"))
                continue
            if filename == "ami-images.json":
                out.append(_rewrite("ami-images", filename, anchor, map_key="by_id"))
                continue
            if filename == "cloudfront-distributions.json":
                out.append(_rewrite("cloudfront-distributions", filename, anchor, map_key="by_id"))
                continue
            if filename == "load-balancers.json":
                out.append(_rewrite("load-balancers", filename, anchor, map_key="by_id"))
                continue
            if filename == "s3-buckets.json":
                out.append(_rewrite("s3-buckets", filename, anchor, map_key="by_name"))
                continue

            out.append(r)

        return out

    def _normalize_evidence_refs_iam(self, refs: List[str]) -> List[str]:
        """Normalize IAM evidence references.

        Currently focuses on credential report references. The model often emits
        `credential-report.json#...` even though the collector stores it as CSV.
        """

        out: List[str] = []
        for r in refs:
            if not isinstance(r, str):
                continue

            rr = r
            # Normalize credential report filename
            rr = rr.replace("credential-report.json", "credential-report.csv")
            rr = rr.replace("credential_report.json", "credential-report.csv")
            rr = rr.replace("credential_report.csv", "credential-report.csv")

            # Normalize common root anchor
            rr = rr.replace("#root_account", "#<root_account>")
            out.append(rr)

        return out

    def _normalize_evidence_refs_secretsmanager(
        self, refs: List[str], evidence: Dict[str, Any]
    ) -> List[str]:
        # Build name -> index mapping for secrets.json
        secrets_doc = evidence.get("secrets")
        name_to_idx: Dict[str, int] = {}
        if isinstance(secrets_doc, dict):
            secrets_list = secrets_doc.get("secrets", [])
            if isinstance(secrets_list, list):
                for i, s in enumerate(secrets_list):
                    if isinstance(s, dict) and s.get("Name") and s.get("Error") is None:
                        n = str(s.get("Name"))
                        if n not in name_to_idx:
                            name_to_idx[n] = i

        cw_regions: Dict[str, Any] = {}
        cw_doc = evidence.get("cloudwatch_alarms")
        if isinstance(cw_doc, dict):
            cw_regions = cast(Dict[str, Any], cw_doc.get("regions", {}) or {})

        eb_regions: Dict[str, Any] = {}
        eb_doc = evidence.get("eventbridge_rules")
        if isinstance(eb_doc, dict):
            eb_regions = cast(Dict[str, Any], eb_doc.get("regions", {}) or {})

        out: List[str] = []
        for ref in refs:
            if not isinstance(ref, str) or "#" not in ref:
                out.append(ref)
                continue

            file_part, frag = ref.split("#", 1)
            file_name = file_part.strip()
            frag = frag.strip()

            # Already a JSON pointer
            if frag.startswith("/"):
                out.append(ref)
                continue

            lowered = file_name.lower()

            if lowered.endswith("secrets.json"):
                if frag in name_to_idx:
                    out.append(f"{file_name}#/secrets/{name_to_idx[frag]}")
                elif frag in {
                    "all_secrets",
                    "encryption_key_ids",
                    "replication_status",
                    "resource_policies",
                    "rotation_analysis",
                    "tags",
                }:
                    out.append(f"{file_name}#/secrets")
                else:
                    out.append(ref)
                continue

            if lowered.endswith("cloudwatch_alarms.json"):
                if isinstance(cw_regions, dict) and frag in cw_regions:
                    out.append(f"{file_name}#/regions/{frag}")
                else:
                    out.append(ref)
                continue

            if lowered.endswith("eventbridge_rules.json"):
                if isinstance(eb_regions, dict) and frag in eb_regions:
                    out.append(f"{file_name}#/regions/{frag}")
                else:
                    out.append(ref)
                continue

            out.append(ref)

        return out

    def _normalize_evidence_refs_ecr(self, refs: List[str], evidence: Dict[str, Any]) -> List[str]:
        repos_doc = evidence.get("repositories")
        name_to_idx: Dict[str, int] = {}
        if isinstance(repos_doc, dict):
            repos_list = repos_doc.get("repositories", [])
            if isinstance(repos_list, list):
                for i, r in enumerate(repos_list):
                    if isinstance(r, dict) and r.get("RepositoryName"):
                        n = str(r.get("RepositoryName"))
                        if n not in name_to_idx:
                            name_to_idx[n] = i

        out: List[str] = []
        for ref in refs:
            if not isinstance(ref, str) or "#" not in ref:
                out.append(ref)
                continue

            file_part, frag = ref.split("#", 1)
            file_name = file_part.strip()
            frag = frag.strip()

            if frag.startswith("/"):
                out.append(ref)
                continue

            lowered = file_name.lower()

            if lowered.endswith("repositories.json"):
                if frag in name_to_idx:
                    out.append(f"{file_name}#/repositories/{name_to_idx[frag]}")
                elif frag in {"all_repositories", "repositories"}:
                    out.append(f"{file_name}#/repositories")
                else:
                    out.append(ref)
                continue

            if lowered.endswith("registry.json"):
                if frag in {"registry", "registry_policy", "registry_scanning"}:
                    out.append(f"{file_name}#/{frag}")
                else:
                    out.append(ref)
                continue

            out.append(ref)

        return out

    def _normalize_id(self, finding_id: str) -> str:
        """Normalize finding ID to simple format (SKILL-XXX).

        Removes sub-IDs and standardizes format.

        Args:
            finding_id: Original ID from AI model (may include sub-IDs)

        Returns:
            Normalized ID in format SKILL-XXX

        Examples:
            "IAM-008-001" → "IAM-008"
            "EXP-005-002" → "EXP-005"
            "NET-012" → "NET-012" (unchanged)
            "VULN-003-sub" → "VULN-003"
        """
        # Pattern: SKILL-XXX (skill prefix + 3 digits)
        # Matches: IAM-001, EXP-005, NET-012, VULN-003, etc
        match = re.match(r"([A-Z]+-\d{3})", finding_id)
        if match:
            return match.group(1)

        # Fallback: return as-is (will be caught as invalid later)
        return finding_id

    def _is_false_positive(self, finding: Finding) -> bool:
        """Detect false positive findings that should be filtered.

        Checks for:
        1. "DISREGARD" markers in title or description
        2. Invalid IDs (not in checklist)

        Args:
            finding: Finding to check

        Returns:
            True if false positive (should be filtered), False otherwise

        Examples:
            >>> Finding(title="DISREGARD THIS FINDING - ERROR") → True
            >>> Finding(id="IAM-999") → True (not in checklist)
            >>> Finding(id="IAM-001", title="Root account without MFA") → False
        """
        title_u = (finding.title or "").upper()
        desc_u = (finding.description or "").upper()
        rem_u = (finding.remediation or "").upper()

        # Check for "DISREGARD" markers (common model variants)
        if (
            "DISREGARD" in title_u
            or "DISREGARD" in desc_u
            or "DISREGARD" in rem_u
            or "DISREGARDED" in title_u
            or "DISREGARDED" in desc_u
            or "DISREGARDED" in rem_u
            or "IGNORE THIS FINDING" in title_u
            or "IGNORE THIS FINDING" in desc_u
            or "IGNORE THIS FINDING" in rem_u
        ):
            return True

        # Reject "no finding" placeholders (model was incentivized to fill min findings).
        # These are not actionable security issues and degrade report quality.
        if (
            "NO FINDING" in title_u
            or "NO FINDING" in desc_u
            or "NO ACTION NEEDED" in title_u
            or "NO ACTION NEEDED" in desc_u
            or "NO ACTION NEEDED" in rem_u
            or "CORRECTLY CONFIGURED" in desc_u
            or "CORRECTLY IMPLEMENTED" in desc_u
        ):
            return True

        # Heuristic: if a finding has no affected resources and no evidence references/snippet,
        # treat it as low-quality/non-actionable and filter it out.
        # (We keep this conservative by requiring ALL to be empty.)
        if (
            not (finding.affected_resources or [])
            and not (finding.evidence_refs or [])
            and not (getattr(finding, "evidence_snippet", None))
        ):
            return True

        # Check for invalid IDs (not in checklist)
        normalized_id = self._normalize_id(finding.id)
        if normalized_id not in self.checklist_map:
            return True

        return False

    # Severity-based impact templates used when the LLM returns no impact.
    _IMPACT_TEMPLATES = {
        "Critical": (
            "Exploitation of this vulnerability can lead to full compromise of the affected "
            "resource(s). An attacker who exploits {title} gains a high-privilege foothold "
            "that enables lateral movement, data exfiltration, or service disruption.\n\n"
            "The business impact includes potential regulatory violations, data breach "
            "notification obligations, and loss of customer trust."
        ),
        "High": (
            "If exploited, an attacker could leverage {title} to escalate privileges or "
            "access sensitive data beyond their authorized scope.\n\n"
            "Depending on the environment, this could result in unauthorized access to "
            "production systems or customer data."
        ),
        "Medium": (
            "This finding ({title}) represents a security gap that could be chained with "
            "other vulnerabilities to increase attack impact.\n\n"
            "While not directly exploitable for full compromise, it weakens the overall "
            "security posture and should be remediated in the medium term."
        ),
        "Low": (
            "This finding ({title}) represents a minor security improvement opportunity.\n\n"
            "The direct risk is limited, but addressing it contributes to defense-in-depth "
            "and reduces the attack surface."
        ),
    }

    def _ensure_impact(self, finding: Finding) -> None:
        """Populate impact field if missing, using severity-based template."""
        self._sync_hook_context()
        if self._skill_hook.ensure_impact(finding):
            return
        if finding.impact:
            return
        template = self._IMPACT_TEMPLATES.get(finding.severity, self._IMPACT_TEMPLATES["Medium"])
        finding.impact = template.format(title=finding.title.lower())

    def _align_severity_to_score(
        self, severity: Severity, risk_score: float
    ) -> Tuple[Severity, float]:
        """Ensure severity label and risk_score are mutually consistent.

        If the risk_score falls outside the expected range for the severity,
        the severity label is adjusted to match the score (score is truth).
        """
        for sev_label, (low, high) in self.SEVERITY_RANGES.items():
            if low <= risk_score <= high:
                return cast(Severity, sev_label), risk_score
        # Fallback: if score is out of all ranges (e.g., 0.0), keep as-is
        return severity, risk_score

    def _calibrate_severity(
        self, finding_id: str, current_severity: str, current_risk_score: float
    ) -> Tuple[Severity, float]:
        """Calibrate severity against checklist constraints.

        Uses checklist as source of truth for severity mapping.
        If AI model assigned wrong severity, corrects it to match checklist.
        Ensures risk_score is within valid range for severity level.

        Args:
            finding_id: Normalized finding ID (SKILL-XXX)
            current_severity: Severity from AI model (Critical/High/Medium/Low)
            current_risk_score: Risk score from AI model (0.0-10.0)

        Returns:
            Tuple of (calibrated_severity, calibrated_risk_score)

        Logic:
        1. If ID not in checklist: return current values (will be filtered by _is_false_positive)
        2. If severity doesn't match checklist: use checklist severity + middle of range
        3. If severity matches: clamp risk_score to severity range
        4. Use middle of range as default when recalibrating

        Examples:
            >>> calibrate("IAM-007", "High", 7.5)  # Checklist says Medium
            → ("Medium", 4.45)  # Middle of 3.0-5.9 range

            >>> calibrate("IAM-001", "Critical", 9.2)  # Matches checklist
            → ("Critical", 9.2)  # Within 8.5-10.0, unchanged
        """
        # Get expected severity from checklist
        if finding_id not in self.checklist_map:
            # Not in checklist: ensure severity label matches risk_score range
            return self._align_severity_to_score(
                cast(Severity, current_severity), current_risk_score
            )

        expected_severity = cast(Severity, self.checklist_map[finding_id]["severity"])

        # If AI model used wrong severity, correct it
        if current_severity != expected_severity:
            # Recalculate risk_score to match expected severity
            min_score, max_score = self.SEVERITY_RANGES[expected_severity]

            # Use middle of range as default
            calibrated_score = (min_score + max_score) / 2

            return expected_severity, calibrated_score

        # Severity matches checklist, but ensure risk_score is in valid range
        min_score, max_score = self.SEVERITY_RANGES[expected_severity]

        if current_risk_score < min_score:
            return expected_severity, min_score
        elif current_risk_score > max_score:
            return expected_severity, max_score

        return expected_severity, current_risk_score

    def _validate_against_evidence(self, finding_id: str, finding: Finding) -> bool:
        """Validate finding against evidence through the skill-owned normalizer hook."""
        if not self.evidence:
            return True

        if finding_id in self._pre_checked_ids:
            return True

        self._sync_hook_context()
        hook_result = self._skill_hook.validate_against_evidence(finding_id, finding)
        if hook_result is not None:
            return hook_result

        return True

    def _resolve_mutual_exclusions(self, findings: List[Finding]) -> List[Finding]:
        """Resolve mutually exclusive findings.

        If both findings in an exclusion pair are present, keep only one
        according to the resolution strategy (keep_specific or keep_higher).

        Args:
            findings: List of findings that may contain exclusive pairs

        Returns:
            Findings list with exclusions resolved (no conflicting pairs)

        Example:
            If both HRD-001 (disabled) and HRD-006 (partial) present:
            Keep HRD-006 (more specific)
        """
        findings_dict = {f.id: f for f in findings}
        to_remove = set()

        for (id1, id2), strategy in self.MUTUAL_EXCLUSIONS.items():
            if id1 in findings_dict and id2 in findings_dict:
                # Both present - resolve conflict
                f1, f2 = findings_dict[id1], findings_dict[id2]

                if strategy == "keep_specific":
                    # Keep the more specific finding (higher ID number = more detailed)
                    id1_num = int(id1.split("-")[1])
                    id2_num = int(id2.split("-")[1])
                    to_remove_id = id1 if id1_num < id2_num else id2
                    kept_id = id2 if to_remove_id == id1 else id1
                    logger.info(
                        f"Mutual exclusion resolved: {id1} vs {id2} → kept {kept_id} (more specific)"
                    )
                    to_remove.add(to_remove_id)

                elif strategy == "keep_higher":
                    # Keep higher severity
                    to_remove_id = id1 if f1.risk_score < f2.risk_score else id2
                    kept_id = id2 if to_remove_id == id1 else id1
                    logger.info(
                        f"Mutual exclusion resolved: {id1} vs {id2} → kept {kept_id} (higher severity: {max(f1.risk_score, f2.risk_score)})"
                    )
                    to_remove.add(to_remove_id)

        return [f for f in findings if f.id not in to_remove]

    def recalculate_summary(self, findings: List[Finding]) -> FindingsSummary:
        """Recalculate summary statistics after normalization.

        Counts findings by severity and calculates overall_risk_score
        using weighted average formula (same as original scoring).

        Args:
            findings: Normalized findings list

        Returns:
            FindingsSummary with updated totals and overall_risk_score

        Formula for overall_risk_score:
            weighted_sum = Σ(risk_score × weight)
            total_weight = Σ(weight)
            overall = weighted_sum / total_weight

        where weights are:
            - Critical: 3.0
            - High: 2.0
            - Medium: 1.0
            - Low: 0.5

        Example:
            >>> findings = [Critical(9.5), High(7.0), Medium(4.0)]
            >>> summary = normalizer.recalculate_summary(findings)
            >>> summary.overall_risk_score  # ≈ 7.0
        """
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "Critical")
        high = sum(1 for f in findings if f.severity == "High")
        medium = sum(1 for f in findings if f.severity == "Medium")
        low = sum(1 for f in findings if f.severity == "Low")

        # Overall risk score = weighted average
        # Critical: 3x weight, High: 2x, Medium: 1x, Low: 0.5x
        if total == 0:
            overall_risk = 0.0
        else:
            weights = {
                "Critical": 3.0,
                "High": 2.0,
                "Medium": 1.0,
                "Low": 0.5,
            }

            weighted_sum = sum(f.risk_score * weights[f.severity] for f in findings)
            total_weight = sum(weights[f.severity] for f in findings)

            # Round to 1 decimal place
            overall_risk = round(weighted_sum / total_weight, 1)

        return FindingsSummary(
            total_findings=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            overall_risk_score=overall_risk,
        )


__all__ = ["FindingsNormalizer", "logger"]
