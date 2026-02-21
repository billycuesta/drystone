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

import fnmatch
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, cast

from drystone.models.findings import Finding, FindingsSummary, PCIDSSControl

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

            # Exposure: remap IDs when the model uses the wrong check ID.
            if self.skill_name == "EXPOSURE":
                normalized_id = self._remap_exposure_id(normalized_id, finding)

            # Network: remap IDs when evidence indicates a different scenario.
            if self.skill_name == "NETWORK":
                normalized_id = self._remap_network_id(normalized_id, finding)

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

            # 5. Calibrate severity
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

        return normalized

    def _verify_finding(self, finding_id: str, finding: Finding) -> Tuple[bool, Optional[str]]:
        """Verify finding is backed by usable evidence.

        This is a generic safety net complementary to skill-specific evidence gates.
        """

        refs = finding.evidence_refs or []

        # If the model omitted evidence_refs, try to infer stable refs from evidence + affected resources.
        # This prevents false rejections in high-signal deterministic cases (e.g., SG open to world).
        if finding.severity == "Critical" and not refs and self.evidence:
            inferred = self._infer_evidence_refs(finding)
            if inferred:
                finding.evidence_refs = inferred
                refs = inferred

        # Critical findings must be backed by something usable: evidence_refs, evidence_snippet,
        # or directly discoverable signal in loaded evidence.
        if finding.severity == "Critical" and not refs:
            # IAM findings must be traceable to specific evidence locations.
            # For other skills we allow evidence_snippet/evidence-content-based verification.
            if self.skill_name in {"IAM"}:
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

        # Rule 4: if affected resources are provided, at least one should exist in evidence
        resources = finding.affected_resources or []
        if (
            finding.severity == "Critical"
            and resources
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
        if finding_id == "KMS-001" and self._kms_001_is_managed_default_pattern(finding):
            # Keep signal but avoid over-severity for common AWS-managed policy defaults.
            return "High", 7.2

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

        if not self.evidence:
            return refs

        evidence = cast(Dict[str, Any], self.evidence)
        if self.skill_name == "SECRETSMANAGER":
            return self._normalize_evidence_refs_secretsmanager(refs, evidence)
        if self.skill_name == "ECR":
            return self._normalize_evidence_refs_ecr(refs, evidence)
        if self.skill_name == "IAM":
            return self._normalize_evidence_refs_iam(refs)
        if self.skill_name == "EXPOSURE":
            return self._normalize_evidence_refs_exposure(refs, evidence)
        if self.skill_name == "NETWORK":
            return self._normalize_evidence_refs_network(refs, evidence)
        if self.skill_name == "HARDENING":
            return self._normalize_evidence_refs_hardening(refs)
        if self.skill_name == "KMS":
            return self._normalize_evidence_refs_kms(refs, evidence)

        return refs

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
            # Invalid ID: return current values (will be filtered)
            return cast(Severity, current_severity), current_risk_score

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
        """Validate finding against actual evidence to detect false positives.

        Checks if finding contradicts explicit evidence about service state.
        Returns False (reject) if evidence clearly shows finding is incorrect.

        For finding IDs that were already resolved by Tier 1 pre-checks
        (stored in self._pre_checked_ids), validation is skipped because
        reconciliation was already handled by _reconcile_with_pre_checks().

        Args:
            finding_id: Normalized finding ID (e.g., "HRD-002")
            finding: Finding object to validate

        Returns:
            True if finding is valid, False if contradicts evidence (should be filtered)
        """
        if not self.evidence:
            return True  # No evidence to validate against

        # Skip validation for IDs already resolved by Tier 1 pre-checks
        if finding_id in self._pre_checked_ids:
            return True

        # Vulns: strict evidence reconciliation to avoid contradictory findings.
        if self.skill_name == "VULNS":
            return self._validate_vulns_finding(finding_id, finding)

        # WAF: Applicability gating (avoid false positives when there is no in-scope surface)
        # Evidence keys come from BaseSkill.analyze(), using json_file.stem.
        if finding_id in {
            "WAF-001",
            "WAF-002",
            "WAF-003",
            "WAF-004",
            "WAF-005",
            "WAF-006",
            "WAF-007",
            "WAF-008",
            "WAF-009",
            "WAF-010",
            "WAF-011",
            "WAF-012",
            "WAF-013",
            "WAF-014",
            "WAF-015",
            "WAF-016",
        }:
            albs = self.evidence.get("alb-waf-associations", None)
            dists = self.evidence.get("cloudfront-distributions", None)
            web_acls = self.evidence.get("wafv2-web-acls", None)
            ip_sets = self.evidence.get("wafv2-ip-sets", None)
            api_entrypoints = self.evidence.get("api-entrypoints-waf-associations", None)
            coll_status = self.evidence.get("waf-collection-status", None)

            # If collection status indicates failures, treat coverage/config findings as unverifiable.
            # Allow ONLY WAF-013 to surface the evidence-quality gap.
            if isinstance(coll_status, dict):
                has_failure = False
                try:
                    if (coll_status.get("cloudfront") or {}).get("ok") is False:
                        has_failure = True
                    if ((coll_status.get("wafv2") or {}).get("CLOUDFRONT") or {}).get(
                        "ok"
                    ) is False:
                        has_failure = True
                    for _, r in (
                        ((coll_status.get("wafv2") or {}).get("REGIONAL") or {})
                        .get("regions", {})
                        .items()
                    ):
                        if isinstance(r, dict) and r.get("ok") is False:
                            has_failure = True
                            break
                    for _, r in (coll_status.get("alb") or {}).get("regions", {}).items():
                        if isinstance(r, dict) and r.get("ok") is False:
                            has_failure = True
                            break
                    for _, r in (coll_status.get("api_entrypoints") or {}).items():
                        if isinstance(r, dict) and r.get("ok") is False:
                            has_failure = True
                            break
                    if (coll_status.get("waf_classic") or {}).get("ok") is False:
                        has_failure = True
                except Exception:
                    # If status parsing fails, don't hard-reject.
                    has_failure = False

                if has_failure and finding_id != "WAF-013":
                    logger.warning(
                        f"Rejected {finding_id} - WAF collection status indicates failures; only WAF-013 is valid."
                    )
                    return False

                if (not has_failure) and finding_id == "WAF-013":
                    logger.warning(
                        f"Rejected {finding_id} - No collection failures detected in waf-collection-status."
                    )
                    return False

            # WAF-001 only makes sense if we detected at least one internet-facing ALB in-scope.
            if finding_id == "WAF-001" and isinstance(albs, list) and len(albs) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No internet-facing ALBs detected (alb-waf-associations is empty)."
                )
                return False

            # WAF-002 only makes sense if we detected at least one CloudFront distribution in-scope.
            if finding_id == "WAF-002" and isinstance(dists, list) and len(dists) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No CloudFront distributions detected (cloudfront-distributions is empty)."
                )
                return False

            # WAF-003..WAF-008 relate to Web ACL configuration; if we have no Web ACLs,
            # these checks are N/A (coverage should be reported via WAF-001/WAF-002 only).
            if finding_id in {"WAF-003", "WAF-004", "WAF-005", "WAF-006", "WAF-007", "WAF-008"}:
                if isinstance(web_acls, list) and len(web_acls) == 0:
                    logger.warning(
                        f"Rejected {finding_id} - No WAFv2 Web ACLs detected (wafv2-web-acls is empty)."
                    )
                    return False

            # WAF-009 only makes sense if IP sets exist.
            if finding_id == "WAF-009" and isinstance(ip_sets, list) and len(ip_sets) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No WAFv2 IP sets detected (wafv2-ip-sets is empty)."
                )
                return False

            # WAF-014..WAF-016 only make sense if we detected any WAF-supported API entry points.
            if finding_id in {"WAF-014", "WAF-015", "WAF-016"}:
                if isinstance(api_entrypoints, list) and len(api_entrypoints) == 0:
                    logger.warning(
                        f"Rejected {finding_id} - No API entry points detected (api-entrypoints-waf-associations is empty)."
                    )
                    return False

        # Security Hub false positive detection
        if finding_id == "HRD-002":
            hub_status = self.evidence.get("security-hub-status", {})
            # If HubArn exists and is not empty, Security Hub IS enabled
            if hub_status.get("HubArn"):
                logger.warning(
                    f"Rejected {finding_id} - Security Hub IS enabled (HubArn present). "
                    f"Evidence: HubArn={hub_status.get('HubArn')}"
                )
                return False  # False positive: Hub is actually enabled

        # Security Hub standards check (HRD-003, HRD-007) - only valid if Hub is enabled
        if finding_id in ["HRD-003", "HRD-007"]:
            hub_status = self.evidence.get("security-hub-status", {})
            # These findings only make sense if Security Hub is enabled
            if not hub_status.get("HubArn"):
                logger.warning(
                    f"Rejected {finding_id} - Security Hub is NOT enabled. "
                    f"Cannot evaluate Hub-specific findings without enabled Hub."
                )
                return False  # Can't evaluate if Hub is disabled

        # HRD-003: "0 standards enabled" must be rejected when standards are present.
        if finding_id == "HRD-003":
            enabled_standards = self.evidence.get("security-hub-enabled-standards", [])
            if isinstance(enabled_standards, list):
                ready_or_enabled = 0
                for std in enabled_standards:
                    if not isinstance(std, dict):
                        continue
                    status = str(std.get("Status") or "").upper()
                    controls = std.get("ControlsSummary") or {}
                    enabled_controls = 0
                    if isinstance(controls, dict):
                        enabled_controls = int(controls.get("enabled") or 0)
                    if status in {"READY", "ENABLED"} or enabled_controls > 0:
                        ready_or_enabled += 1

                if ready_or_enabled > 0:
                    logger.warning(
                        f"Rejected {finding_id} - Security Hub has {ready_or_enabled} enabled/ready standards."
                    )
                    return False

        # AWS Config false positive detection
        if finding_id == "HRD-001":
            config_recorders = self.evidence.get("config-recorders", {})
            recorders = config_recorders.get("ConfigurationRecorders", [])
            # If recorders array has items, Config IS enabled (at least partially)
            if len(recorders) > 0:
                logger.warning(
                    f"Rejected {finding_id} - Config IS enabled ({len(recorders)} recorders). "
                    f"Should be HRD-006 instead."
                )
                return False  # False positive: Config is actually enabled

        # AWS Config enabled check (HRD-006) - only valid if Config is partially enabled
        if finding_id == "HRD-006":
            config_recorders = self.evidence.get("config-recorders", {})
            recorders = config_recorders.get("ConfigurationRecorders", [])
            # This finding only makes sense if Config is enabled but incomplete
            if len(recorders) == 0:
                logger.warning(
                    f"Rejected {finding_id} - Config is NOT enabled (no recorders). "
                    f"Should be HRD-001 instead."
                )
                return False  # False positive: Config is disabled, not partial

            recorder_status_doc = self.evidence.get("config-recorder-status", {})
            status_items = (
                recorder_status_doc.get("ConfigurationRecordersStatus", [])
                if isinstance(recorder_status_doc, dict)
                else []
            )
            recording_ok = False
            if isinstance(status_items, list) and status_items:
                for s in status_items:
                    if isinstance(s, dict) and s.get("recording") is True:
                        recording_ok = True
                        break

            channels_doc = self.evidence.get("config-delivery-channels", {})
            channels = (
                channels_doc.get("DeliveryChannels", []) if isinstance(channels_doc, dict) else []
            )
            channel_ok = False
            if isinstance(channels, list) and channels:
                for c in channels:
                    if isinstance(c, dict) and c.get("s3BucketName"):
                        channel_ok = True
                        break

            if recording_ok and channel_ok:
                logger.warning(
                    f"Rejected {finding_id} - Config recorder is recording and delivery channel is configured."
                )
                return False

        # GuardDuty validation (HRD-009, HRD-014)
        if finding_id in ["HRD-009", "HRD-014"]:
            gd_detectors = self.evidence.get("guardduty-detectors", [])
            # These findings only make sense if GuardDuty is enabled
            if not gd_detectors or len(gd_detectors) == 0:
                logger.warning(
                    f"Rejected {finding_id} - GuardDuty is NOT enabled. "
                    f"Cannot evaluate GuardDuty-specific findings."
                )
                return False

        # Hardening threshold checks must use global Security Hub summary, not chunk-local snippets.
        if finding_id in {"HRD-005", "HRD-009", "HRD-012", "HRD-016", "HRD-004"}:
            sev_counts, comp_counts = self._get_hardening_securityhub_counts()

            if finding_id == "HRD-005" and sev_counts.get("CRITICAL", 0) <= 0:
                logger.warning(
                    f"Rejected {finding_id} - global CRITICAL count is {sev_counts.get('CRITICAL', 0)}."
                )
                return False

            if finding_id == "HRD-009" and sev_counts.get("HIGH", 0) <= 10:
                logger.warning(
                    f"Rejected {finding_id} - global HIGH count is {sev_counts.get('HIGH', 0)} (requires >10)."
                )
                return False

            if finding_id == "HRD-012" and sev_counts.get("MEDIUM", 0) <= 20:
                logger.warning(
                    f"Rejected {finding_id} - global MEDIUM count is {sev_counts.get('MEDIUM', 0)} (requires >20)."
                )
                return False

            if finding_id == "HRD-016" and sev_counts.get("LOW", 0) <= 0:
                logger.warning(
                    f"Rejected {finding_id} - global LOW count is {sev_counts.get('LOW', 0)} (requires >0)."
                )
                return False

            if finding_id == "HRD-004":
                passed = int(comp_counts.get("PASSED", 0) or 0)
                failed = int(comp_counts.get("FAILED", 0) or 0)
                warning = int(comp_counts.get("WARNING", 0) or 0)
                denom = passed + failed + warning
                if denom > 0:
                    compliance_score = (passed / denom) * 100.0
                    if compliance_score >= 50.0:
                        logger.warning(
                            f"Rejected {finding_id} - computed compliance score is {compliance_score:.1f}% (requires <50%)."
                        )
                        return False

            if self._hardening_threshold_narrative_contradicts_evidence(
                finding_id, finding, sev_counts
            ):
                logger.warning(
                    f"Rejected {finding_id} - finding narrative/snippet contradicts threshold criteria."
                )
                return False

        if finding_id == "HRD-017":
            if not self._hardening_has_tagging_evidence(finding):
                logger.warning(
                    f"Rejected {finding_id} - no tagging evidence available for account-wide tag consistency assessment."
                )
                return False

        if finding_id == "HRD-013":
            has_outdated = self._hardening_has_outdated_enabled_standards()
            refs = finding.evidence_refs or []
            has_standards_ref = any(
                isinstance(r, str) and "security-hub-enabled-standards" in r for r in refs
            )

            if not has_outdated:
                logger.warning(
                    f"Rejected {finding_id} - no outdated enabled Security Hub standards detected."
                )
                return False
            if not has_standards_ref:
                logger.warning(
                    f"Rejected {finding_id} - missing security-hub-enabled-standards evidence refs."
                )
                return False

        # Hardening: reject findings that use non-resolvable Security Hub evidence refs.
        if finding_id.startswith("HRD-"):
            if not self._hardening_refs_resolve_to_securityhub(finding):
                logger.warning(
                    f"Rejected {finding_id} - unresolved security-hub-findings.json evidence refs."
                )
                return False

        # IAM: Root account MFA
        if finding_id == "IAM-001":
            account_summary = self.evidence.get("account-summary", {})
            mfa_enabled = None
            if isinstance(account_summary, dict):
                # Collector may store either the raw API shape (SummaryMap.AccountMFAEnabled)
                # or a flattened test fixture shape (AccountMFAEnabled).
                if "AccountMFAEnabled" in account_summary:
                    mfa_enabled = account_summary.get("AccountMFAEnabled")
                else:
                    summary_map = account_summary.get("SummaryMap")
                    if isinstance(summary_map, dict):
                        mfa_enabled = summary_map.get("AccountMFAEnabled")

            if mfa_enabled in {1, True, "1", "true", "True"}:
                logger.warning(
                    f"Rejected {finding_id} - Root account MFA IS enabled. "
                    f"Evidence: AccountMFAEnabled={mfa_enabled}"
                )
                return False  # Root MFA IS enabled

            # Secondary source of truth: credential report CSV (if present)
            cred = self.evidence.get("credential-report")
            if isinstance(cred, dict):
                by_user = cred.get("by_user")
                if isinstance(by_user, dict):
                    root_row = by_user.get("<root_account>")
                    if isinstance(root_row, dict):
                        mfa_active = root_row.get("mfa_active")
                        if mfa_active in {"true", "True", True, "1", 1}:
                            logger.warning(
                                f"Rejected {finding_id} - Root account MFA IS enabled (credential report). "
                                f"Evidence: mfa_active={mfa_active}"
                            )
                            return False

        # IAM: Root account access keys
        if finding_id == "IAM-009":
            account_summary = self.evidence.get("account-summary", {})
            access_keys_present = None
            if isinstance(account_summary, dict):
                if "AccountAccessKeysPresent" in account_summary:
                    access_keys_present = account_summary.get("AccountAccessKeysPresent")
                else:
                    summary_map = account_summary.get("SummaryMap")
                    if isinstance(summary_map, dict):
                        access_keys_present = summary_map.get("AccountAccessKeysPresent")

            # 0 means no root access keys present.
            if access_keys_present in {0, False, "0", "false", "False"}:
                logger.warning(
                    f"Rejected {finding_id} - Root access keys are NOT present. "
                    f"Evidence: AccountAccessKeysPresent={access_keys_present}"
                )
                return False

            # Secondary source of truth: credential report CSV (if present)
            cred = self.evidence.get("credential-report")
            if isinstance(cred, dict):
                by_user = cred.get("by_user")
                if isinstance(by_user, dict):
                    root_row = by_user.get("<root_account>")
                    if isinstance(root_row, dict):
                        k1 = root_row.get("access_key_1_active")
                        k2 = root_row.get("access_key_2_active")
                        if k1 in {"false", "False", False, "0", 0} and k2 in {
                            "false",
                            "False",
                            False,
                            "0",
                            0,
                        }:
                            logger.warning(
                                f"Rejected {finding_id} - Root access keys are NOT active (credential report). "
                                f"Evidence: access_key_1_active={k1}, access_key_2_active={k2}"
                            )
                            return False

        # IAM: Inactive users
        if finding_id == "IAM-003":
            users = self.evidence.get("users", [])
            inactive = [
                u for u in users if not u.get("PasswordLastUsed") and not u.get("AccessKeys")
            ]
            if len(inactive) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No inactive users found. "
                    f"Evidence: {len(users)} users, all have activity."
                )
                return False  # No inactive users found

        # IAM: Inactive users (IAM-012)
        # The model sometimes flags root as "inactive" due to old console usage.
        # Root account should be used minimally; this is expected and not a finding.
        if finding_id == "IAM-012":
            is_root = False
            for arn in finding.affected_resources or []:
                if isinstance(arn, str) and arn.endswith(":root"):
                    is_root = True
                    break

            snippet = finding.evidence_snippet
            if not is_root and isinstance(snippet, dict):
                sn = cast(Dict[str, Any], snippet)
                if sn.get("user") == "<root_account>" or sn.get("arn", "").endswith(":root"):
                    is_root = True

            if is_root:
                logger.warning(
                    f"Rejected {finding_id} - Root account inactivity is expected; not actionable."
                )
                return False

        # IAM: Old access keys (> 90 days)
        if finding_id == "IAM-007":
            users = self.evidence.get("users", [])
            old_keys = []
            for user in users:
                for key in user.get("AccessKeys", []):
                    create_date = key.get("CreateDate")
                    if isinstance(create_date, str):
                        try:
                            create_date = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                        except (ValueError, TypeError):
                            continue
                    if create_date and isinstance(create_date, datetime):
                        age_days = (datetime.now(create_date.tzinfo) - create_date).days
                        if age_days > 90:
                            old_keys.append(key)
            if len(old_keys) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No old access keys found (>90 days). "
                    f"All keys are recent or missing CreateDate."
                )
                return False  # No old keys found

        # Alerting: CloudTrail disabled
        if finding_id == "ALR-001":
            trails = self.evidence.get("cloudtrail-trails", [])
            if len(trails) > 0:
                logger.warning(
                    f"Rejected {finding_id} - CloudTrail IS enabled ({len(trails)} trails). "
                    f"Should be ALR-003 (no logs) or ALR-005+ (other issues)."
                )
                return False  # CloudTrail IS enabled (should be ALR-003 or ALR-005+)

        # Alerting: CloudTrail logs disabled (ALR-003 only valid if Trail exists)
        if finding_id == "ALR-003":
            trails = self.evidence.get("cloudtrail-trails", [])
            if len(trails) == 0:
                logger.warning(
                    f"Rejected {finding_id} - CloudTrail is NOT enabled (no trails). "
                    f"Should be ALR-001 instead."
                )
                return False  # Can't have "no logs" if trail doesn't exist

        # Exposure: validate internet-exposure checks against explicit evidence
        if finding_id.startswith("EXP-"):

            def _items(doc: Any) -> List[Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("items"), list):
                    return cast(List[Dict[str, Any]], doc.get("items") or [])
                if isinstance(doc, list):
                    return cast(List[Dict[str, Any]], doc)
                return []

            def _index(doc: Any, key_field: str) -> Dict[str, Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                    return cast(Dict[str, Dict[str, Any]], doc.get("by_id") or {})
                idx: Dict[str, Dict[str, Any]] = {}
                for it in _items(doc):
                    if not isinstance(it, dict):
                        continue
                    k = it.get(key_field)
                    if isinstance(k, str) and k:
                        idx[k] = it
                return idx

            def _sg_has_open_cidr(sg: Dict[str, Any], *, port: int, cidr: str) -> bool:
                for perm in sg.get("IngressRules", []) or []:
                    if not isinstance(perm, dict):
                        continue
                    proto = perm.get("IpProtocol")
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")

                    port_match = False
                    if proto == "-1":
                        port_match = True
                    elif proto == "tcp" and isinstance(from_p, int) and isinstance(to_p, int):
                        port_match = from_p <= port <= to_p

                    if not port_match:
                        continue

                    for r in perm.get("IpRanges", []) or []:
                        if isinstance(r, dict) and r.get("CidrIp") == cidr:
                            return True
                    for r in perm.get("Ipv6Ranges", []) or []:
                        if isinstance(r, dict) and r.get("CidrIpv6") == cidr:
                            return True

                return False

            # EXP-002: RDS/DB publicly accessible from internet
            if finding_id == "EXP-002":
                rds_doc = self.evidence.get("rds-instances")
                sg_doc = self.evidence.get("security-groups")
                rds_items = _items(rds_doc)
                sgs_by_id = _index(sg_doc, "GroupId")

                public_insts = [
                    i
                    for i in rds_items
                    if isinstance(i, dict) and i.get("PubliclyAccessible") is True
                ]
                if not public_insts:
                    logger.warning(
                        f"Rejected {finding_id} - No RDS instances with PubliclyAccessible=true in evidence."
                    )
                    return False

                has_internet_sg = False
                for inst in public_insts:
                    for vsg in inst.get("VpcSecurityGroups", []) or []:
                        if not isinstance(vsg, dict):
                            continue
                        sg_id = vsg.get("VpcSecurityGroupId")
                        if not isinstance(sg_id, str):
                            continue
                        sg = sgs_by_id.get(sg_id)
                        if not isinstance(sg, dict):
                            continue
                        # Any TCP/all-protocol ingress from 0.0.0.0/0 or ::/0 is sufficient.
                        if _sg_has_open_cidr(sg, port=5432, cidr="0.0.0.0/0") or _sg_has_open_cidr(
                            sg, port=5432, cidr="::/0"
                        ):
                            has_internet_sg = True
                            break
                    if has_internet_sg:
                        break

                if not has_internet_sg:
                    logger.warning(
                        f"Rejected {finding_id} - No RDS-attached security group with internet ingress (0.0.0.0/0 or ::/0) found."
                    )
                    return False

            # EXP-001: Public S3 bucket exposure
            if finding_id == "EXP-001":
                s3_doc = self.evidence.get("s3-buckets")
                items = _items(s3_doc)
                if not items:
                    logger.warning(
                        f"Rejected {finding_id} - Missing s3-buckets evidence; cannot verify."
                    )
                    return False

                affected_buckets = [
                    r.replace("arn:aws:s3:::", "")
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:s3:::")
                ]
                if not affected_buckets:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any S3 bucket ARN."
                    )
                    return False

                def _is_public_acl(grants: Any) -> bool:
                    if not isinstance(grants, list):
                        return False
                    for g in grants:
                        if not isinstance(g, dict):
                            continue
                        gr = g.get("Grantee")
                        if not isinstance(gr, dict):
                            continue
                        if gr.get("Type") != "Group":
                            continue
                        uri = gr.get("URI")
                        if not isinstance(uri, str):
                            continue
                        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                            return True
                    return False

                def _has_public_policy(policy: Any) -> bool:
                    if not isinstance(policy, dict):
                        return False
                    for st in policy.get("Statement", []) or []:
                        if not isinstance(st, dict):
                            continue
                        if st.get("Effect") != "Allow":
                            continue
                        principal = st.get("Principal")
                        if principal != "*" and not (
                            isinstance(principal, dict) and principal.get("AWS") == "*"
                        ):
                            continue
                        act = st.get("Action")
                        actions = [act] if isinstance(act, str) else (act or [])
                        if (
                            "s3:*" in actions
                            or "s3:GetObject" in actions
                            or "s3:ListBucket" in actions
                        ):
                            return True
                    return False

                public = False
                for bn in affected_buckets:
                    # Prefer indexed by_name if present
                    b = None
                    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
                        b = (s3_doc.get("by_name") or {}).get(bn)
                    if not isinstance(b, dict):
                        b = next(
                            (x for x in items if isinstance(x, dict) and x.get("Name") == bn), None
                        )
                    if not isinstance(b, dict):
                        continue
                    if _is_public_acl(b.get("ACL")) or _has_public_policy(b.get("BucketPolicy")):
                        public = True
                        break

                if not public:
                    logger.warning(
                        f"Rejected {finding_id} - No public ACL/policy evidence found for referenced buckets."
                    )
                    return False

            # EXP-015: S3 cross-account bucket policy access
            if finding_id == "EXP-015":
                meta = self.evidence.get("_audit_metadata")
                audit_account = None
                if isinstance(meta, dict):
                    audit_account = meta.get("_account_id")

                # Require at least one affected cross-account IAM principal.
                principals = [
                    r
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:iam::")
                ]
                if not principals:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any IAM principal ARN."
                    )
                    return False

                if isinstance(audit_account, str) and audit_account.isdigit():
                    is_cross = False
                    for p in principals:
                        parts = p.split(":")
                        if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                            is_cross = True
                            break
                    if not is_cross:
                        logger.warning(
                            f"Rejected {finding_id} - No cross-account IAM principal detected in affected_resources."
                        )
                        return False

            # EXP-003: SSH/RDP open to 0.0.0.0/0
            if finding_id == "EXP-003":
                sg_doc = self.evidence.get("security-groups")
                sgs_by_id = _index(sg_doc, "GroupId")

                sg_id = None
                for r in finding.affected_resources or []:
                    if not isinstance(r, str):
                        continue
                    if "/sg-" in r:
                        sg_id = r.split("/", 1)[1]
                        break
                    if r.startswith("sg-"):
                        sg_id = r
                        break

                if not sg_id or sg_id not in sgs_by_id:
                    logger.warning(
                        f"Rejected {finding_id} - Cannot resolve security group id from affected_resources."
                    )
                    return False

                sg = sgs_by_id.get(sg_id) or {}
                ssh_open = _sg_has_open_cidr(sg, port=22, cidr="0.0.0.0/0") or _sg_has_open_cidr(
                    sg, port=22, cidr="::/0"
                )
                rdp_open = _sg_has_open_cidr(sg, port=3389, cidr="0.0.0.0/0") or _sg_has_open_cidr(
                    sg, port=3389, cidr="::/0"
                )
                if not (ssh_open or rdp_open):
                    logger.warning(
                        f"Rejected {finding_id} - Security group does not expose SSH/RDP to 0.0.0.0/0 or ::/0."
                    )
                    return False

            # EXP-007: Internet-facing ALB/NLB without WAF association
            if finding_id == "EXP-007":
                lbs_doc = self.evidence.get("load-balancers")
                assoc_doc = self.evidence.get("wafv2-web-acl-alb-associations")
                if not isinstance(lbs_doc, dict) or not isinstance(assoc_doc, dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing load-balancers or wafv2 association evidence; cannot verify."
                    )
                    return False

                lbs = _items(lbs_doc)
                by_alb = assoc_doc.get("by_alb_arn")
                if not isinstance(by_alb, dict):
                    by_alb = {}

                internet_albs = [
                    lb
                    for lb in lbs
                    if isinstance(lb, dict)
                    and lb.get("Type") == "application"
                    and lb.get("Scheme") == "internet-facing"
                    and isinstance(lb.get("LoadBalancerArn"), str)
                ]

                if not internet_albs:
                    logger.warning(
                        f"Rejected {finding_id} - No internet-facing ALBs detected in evidence."
                    )
                    return False

                # Require the finding to identify at least one ALB ARN.
                affected_albs = [
                    r
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:elasticloadbalancing:")
                ]
                if not affected_albs:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference a specific ALB/NLB ARN."
                    )
                    return False

                valid_gap = False
                internet_arn_set = {lb.get("LoadBalancerArn") for lb in internet_albs}
                for alb_arn in affected_albs:
                    if alb_arn not in internet_arn_set:
                        continue
                    if not (by_alb.get(alb_arn) or []):
                        valid_gap = True
                        break

                if not valid_gap:
                    logger.warning(
                        f"Rejected {finding_id} - All referenced ALBs appear to have WAF association or are not internet-facing."
                    )
                    return False

            # EXP-010: obsolete TLS policies on internet-facing ALB
            if finding_id == "EXP-010":
                lbs_doc = self.evidence.get("load-balancers")
                lis_doc = self.evidence.get("load-balancer-listeners")
                if not isinstance(lbs_doc, dict) or not isinstance(lis_doc, dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing ELBv2 evidence (load-balancers/load-balancer-listeners)."
                    )
                    return False

                lbs = _items(lbs_doc)
                scheme_by_arn = {
                    lb.get("LoadBalancerArn"): lb.get("Scheme")
                    for lb in lbs
                    if isinstance(lb, dict) and isinstance(lb.get("LoadBalancerArn"), str)
                }
                listeners = _items(lis_doc)

                old = False
                for li in listeners:
                    if not isinstance(li, dict):
                        continue
                    if li.get("Protocol") != "HTTPS":
                        continue
                    lb_arn = li.get("LoadBalancerArn")
                    if (
                        not isinstance(lb_arn, str)
                        or scheme_by_arn.get(lb_arn) != "internet-facing"
                    ):
                        continue
                    pol = li.get("SslPolicy")
                    if not isinstance(pol, str) or not pol:
                        continue
                    if (
                        "TLS-1-0" in pol
                        or "TLS-1-1" in pol
                        or pol in {"ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08"}
                    ):
                        old = True
                        break

                if not old:
                    logger.warning(
                        f"Rejected {finding_id} - No HTTPS listeners with obsolete TLS policy detected for internet-facing ALBs."
                    )
                    return False

            # EXP-013: S3 TLS enforcement missing
            if finding_id == "EXP-013":
                s3_doc = self.evidence.get("s3-buckets")
                if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing indexed s3-buckets evidence; cannot verify."
                    )
                    return False

                by_name = cast(Dict[str, Any], s3_doc.get("by_name") or {})
                affected = [
                    r.replace("arn:aws:s3:::", "")
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:s3:::")
                ]
                if not affected:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any S3 bucket ARN."
                    )
                    return False

                def _has_securetransport_deny(policy: Any) -> bool:
                    if not isinstance(policy, dict):
                        return False
                    for st in policy.get("Statement", []) or []:
                        if not isinstance(st, dict):
                            continue
                        if st.get("Effect") != "Deny":
                            continue
                        cond = st.get("Condition")
                        if not isinstance(cond, dict):
                            continue
                        b = cond.get("Bool")
                        if isinstance(b, dict) and b.get("aws:SecureTransport") == "false":
                            return True
                    return False

                missing = False
                for bn in affected:
                    b = by_name.get(bn)
                    if not isinstance(b, dict):
                        continue
                    if not _has_securetransport_deny(b.get("BucketPolicy")):
                        missing = True
                        break

                if not missing:
                    logger.warning(
                        f"Rejected {finding_id} - All referenced buckets already enforce aws:SecureTransport in policy."
                    )
                    return False

            # EXP-014: S3 audit/log buckets without versioning
            if finding_id == "EXP-014":
                s3_doc = self.evidence.get("s3-buckets")
                if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing indexed s3-buckets evidence; cannot verify."
                    )
                    return False

                by_name = cast(Dict[str, Any], s3_doc.get("by_name") or {})
                affected = [
                    r.replace("arn:aws:s3:::", "")
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:s3:::")
                ]
                if not affected:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any S3 bucket ARN."
                    )
                    return False

                needs = False
                for bn in affected:
                    b = by_name.get(bn)
                    if not isinstance(b, dict):
                        continue
                    if (b.get("Versioning") or "") != "Enabled":
                        needs = True
                        break
                if not needs:
                    logger.warning(
                        f"Rejected {finding_id} - All referenced buckets already have versioning enabled."
                    )
                    return False

            # EXP-011: public object listing
            if finding_id == "EXP-011":
                s3_doc = self.evidence.get("s3-buckets")
                items = _items(s3_doc)
                found_public_list = False
                for b in items:
                    if not isinstance(b, dict):
                        continue
                    policy = b.get("BucketPolicy")
                    if not isinstance(policy, dict):
                        continue
                    for st in policy.get("Statement", []) or []:
                        if not isinstance(st, dict):
                            continue
                        if st.get("Effect") != "Allow":
                            continue
                        principal = st.get("Principal")
                        if principal != "*" and not (
                            isinstance(principal, dict) and principal.get("AWS") == "*"
                        ):
                            continue
                        act = st.get("Action")
                        actions = [act] if isinstance(act, str) else (act or [])
                        if "s3:ListBucket" not in actions:
                            continue
                        found_public_list = True
                        break
                    if found_public_list:
                        break
                if not found_public_list:
                    logger.warning(
                        f"Rejected {finding_id} - No public s3:ListBucket permissions found in bucket policies."
                    )
                    return False

        # Network: evidence-based validation for common false positives
        if finding_id.startswith("NET-"):

            def _items(doc: Any) -> List[Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("items"), list):
                    return cast(List[Dict[str, Any]], doc.get("items") or [])
                if isinstance(doc, list):
                    return cast(List[Dict[str, Any]], doc)
                return []

            def _by_id(doc: Any, key: str) -> Dict[str, Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                    return cast(Dict[str, Dict[str, Any]], doc.get("by_id") or {})
                idx: Dict[str, Dict[str, Any]] = {}
                for it in _items(doc):
                    if not isinstance(it, dict):
                        continue
                    k = it.get(key)
                    if isinstance(k, str) and k:
                        idx[k] = it
                return idx

            def _perm_allows_world(perm: Dict[str, Any], *, port: int) -> bool:
                proto = perm.get("IpProtocol")
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")

                port_match = False
                if proto == "-1":
                    port_match = True
                elif proto == "tcp" and isinstance(from_p, int) and isinstance(to_p, int):
                    port_match = from_p <= port <= to_p

                if not port_match:
                    return False

                for r in perm.get("IpRanges", []) or []:
                    if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
                        return True
                for r in perm.get("Ipv6Ranges", []) or []:
                    if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
                        return True

                return False

            # NET-001: Sensitive ports exposed to world
            if finding_id == "NET-001":
                sg_doc = self.evidence.get("security-groups")
                sgs = _by_id(sg_doc, "GroupId")

                sg_id = None
                snippet = finding.evidence_snippet
                if isinstance(snippet, dict):
                    sg_id = cast(Dict[str, Any], snippet).get("GroupId")

                if not sg_id:
                    for arn in finding.affected_resources or []:
                        if not isinstance(arn, str):
                            continue
                        marker = ":security-group/"
                        if marker in arn:
                            sg_id = arn.split(marker, 1)[1]
                            break

                if not (isinstance(sg_id, str) and sg_id.startswith("sg-")):
                    logger.warning(
                        f"Rejected {finding_id} - Cannot resolve security group id from evidence/affected_resources."
                    )
                    return False

                sg = sgs.get(sg_id)
                if not isinstance(sg, dict):
                    logger.warning(
                        f"Rejected {finding_id} - Security group '{sg_id}' not found in evidence."
                    )
                    return False

                sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379]
                exposed = False
                for perm in sg.get("IngressRules", []) or []:
                    if not isinstance(perm, dict):
                        continue
                    for p in sensitive_ports:
                        if _perm_allows_world(perm, port=p):
                            exposed = True
                            break
                    if exposed:
                        break

                if not exposed:
                    logger.warning(
                        f"Rejected {finding_id} - No 0.0.0.0/0 or ::/0 ingress detected for sensitive ports in '{sg_id}'."
                    )
                    return False

            # NET-018: VPC missing Flow Logs
            if finding_id == "NET-018":
                vpc_doc = self.evidence.get("vpcs")
                vpcs = _by_id(vpc_doc, "VpcId")
                vpc_id = None
                for arn in finding.affected_resources or []:
                    if not isinstance(arn, str):
                        continue
                    if arn.startswith("vpc-"):
                        vpc_id = arn
                        break
                    marker = ":vpc/"
                    if marker in arn:
                        vpc_id = arn.split(marker, 1)[1]
                        break
                if not vpc_id and isinstance(finding.evidence_snippet, dict):
                    sn = cast(Dict[str, Any], finding.evidence_snippet)
                    vpc_id = sn.get("VpcId") or sn.get("vpc_id")

                if isinstance(vpc_id, str) and vpc_id.startswith("vpc-"):
                    v = vpcs.get(vpc_id)
                    flow_logs = []
                    if isinstance(v, dict):
                        flow_logs = v.get("FlowLogs", []) or []

                    if isinstance(flow_logs, list) and any(
                        isinstance(fl, dict) and (fl.get("FlowLogStatus") in {"ACTIVE", "active"})
                        for fl in flow_logs
                    ):
                        logger.warning(
                            f"Rejected {finding_id} - Flow Logs are enabled and ACTIVE for {vpc_id}."
                        )
                        return False

            # NET-011: Missing descriptions on critical rules
            if finding_id == "NET-011":
                sg_doc = self.evidence.get("security-groups")
                sgs = _by_id(sg_doc, "GroupId")

                sg_ids: List[str] = []
                for arn in finding.affected_resources or []:
                    if not isinstance(arn, str):
                        continue
                    marker = ":security-group/"
                    if marker in arn:
                        sg_ids.append(arn.split(marker, 1)[1])

                # If none in affected_resources, try evidence refs.
                for ref in finding.evidence_refs or []:
                    if not isinstance(ref, str):
                        continue
                    if "security-groups.json#by_id." in ref:
                        sg_ids.append(
                            ref.split("security-groups.json#by_id.", 1)[1].split(".", 1)[0]
                        )
                    elif "security-groups.json#" in ref and "sg-" in ref:
                        sg_ids.append(ref.split("#", 1)[1].split(".", 1)[0])

                sg_ids = sorted({s for s in sg_ids if isinstance(s, str) and s.startswith("sg-")})
                if not sg_ids:
                    # Can't validate; don't hard-reject.
                    return True

                crit_ports = {22, 3389, 3306, 5432, 6379, 1433, 27017, 8080}

                def _perm_matches_critical(perm: Dict[str, Any]) -> bool:
                    proto = perm.get("IpProtocol")
                    if proto == "-1":
                        return True
                    if proto != "tcp":
                        return False
                    fp = perm.get("FromPort")
                    tp = perm.get("ToPort")
                    if not isinstance(fp, int) or not isinstance(tp, int):
                        return False
                    return any(fp <= p <= tp for p in crit_ports)

                def _has_missing_desc(perm: Dict[str, Any]) -> bool:
                    for r in perm.get("IpRanges", []) or []:
                        if not isinstance(r, dict):
                            continue
                        if not r.get("Description"):
                            return True
                    for r in perm.get("Ipv6Ranges", []) or []:
                        if not isinstance(r, dict):
                            continue
                        if not r.get("Description"):
                            return True
                    for r in perm.get("UserIdGroupPairs", []) or []:
                        if not isinstance(r, dict):
                            continue
                        if not r.get("Description"):
                            return True
                    return False

                found_gap = False
                for sg_id in sg_ids:
                    sg = sgs.get(sg_id)
                    if not isinstance(sg, dict):
                        continue
                    for perm in (sg.get("IngressRules", []) or []) + (
                        sg.get("EgressRules", []) or []
                    ):
                        if not isinstance(perm, dict):
                            continue
                        if not _perm_matches_critical(perm):
                            continue
                        if _has_missing_desc(perm):
                            found_gap = True
                            break
                    if found_gap:
                        break

                if not found_gap:
                    logger.warning(
                        f"Rejected {finding_id} - No critical SG rules with missing descriptions found in referenced security groups."
                    )
                    return False

            # NET-008: Critical workloads deployed in public subnets
            if finding_id == "NET-008":
                route_tables = self.evidence.get("route-tables")

                rt_items: List[Dict[str, Any]] = []
                if isinstance(route_tables, dict) and isinstance(route_tables.get("items"), list):
                    rt_items = cast(List[Dict[str, Any]], route_tables.get("items") or [])
                elif isinstance(route_tables, list):
                    rt_items = cast(List[Dict[str, Any]], route_tables)

                # Build set of public subnets (0.0.0.0/0 -> igw-*)
                public_subnets: set[str] = set()
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
                    for a in rt.get("Associations", []) or []:
                        if isinstance(a, dict) and isinstance(a.get("SubnetId"), str):
                            sid = a.get("SubnetId")
                            if isinstance(sid, str) and sid:
                                public_subnets.add(sid)
                        elif isinstance(a, str) and a.startswith("subnet-"):
                            public_subnets.add(a)

                if not public_subnets:
                    logger.warning(
                        f"Rejected {finding_id} - No public subnets detected from route tables (IGW default route)."
                    )
                    return False

                # Extract subnet ids referenced by the finding (from affected_resources and snippet)
                referenced: set[str] = set()
                for r in finding.affected_resources or []:
                    if isinstance(r, str) and ":subnet/" in r:
                        referenced.add(r.split(":subnet/", 1)[1])
                    elif isinstance(r, str) and r.startswith("subnet-"):
                        referenced.add(r)
                snippet = finding.evidence_snippet
                if isinstance(snippet, dict):
                    sid = cast(Dict[str, Any], snippet).get("SubnetId")
                    if isinstance(sid, str) and sid.startswith("subnet-"):
                        referenced.add(sid)

                if referenced and not (referenced & public_subnets):
                    logger.warning(
                        f"Rejected {finding_id} - Referenced subnets are not public per route-table IGW routing evidence."
                    )
                    return False

                # If finding doesn't reference subnets, at least require that some public subnet has ENIs
                # that look like critical workloads, otherwise it's too speculative.
                if not referenced:
                    eni_doc = self.evidence.get("network-interfaces")
                    eni_items: List[Dict[str, Any]] = []
                    if isinstance(eni_doc, dict) and isinstance(eni_doc.get("items"), list):
                        eni_items = cast(List[Dict[str, Any]], eni_doc.get("items") or [])
                    elif isinstance(eni_doc, list):
                        eni_items = cast(List[Dict[str, Any]], eni_doc)

                    found = False
                    for eni in eni_items:
                        if not isinstance(eni, dict):
                            continue
                        sid = eni.get("SubnetId")
                        if sid not in public_subnets:
                            continue
                        desc = str(eni.get("Description") or "").lower()
                        if any(
                            x in desc for x in ["rds", "elasticache", "opensearch", "redis", "db"]
                        ):
                            found = True
                            break
                    if not found:
                        logger.warning(
                            f"Rejected {finding_id} - No critical workload indicators found in public subnets."
                        )
                        return False

                # NET-008 gating ends here.

        # Secrets Manager: Public wildcard resource policy (SM-001)
        # Only valid when evidence contains at least one statement with Principal == "*".
        if finding_id == "SM-001":
            secrets_doc = self.evidence.get("secrets", {})
            secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

            has_wildcard = False
            for s in secrets_list if isinstance(secrets_list, list) else []:
                if not isinstance(s, dict):
                    continue
                policy = s.get("ResourcePolicy")
                if not isinstance(policy, dict):
                    continue
                for st in policy.get("Statement", []) or []:
                    if not isinstance(st, dict):
                        continue
                    principal = st.get("Principal", {})
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        has_wildcard = True
                        break
                if has_wildcard:
                    break

            if not has_wildcard:
                logger.warning(
                    f"Rejected {finding_id} - No wildcard Principal '*' found in Secrets Manager resource policies."
                )
                return False

        # Secrets Manager: Rotation interval > 90 days (SM-003)
        # Only valid when rotation is enabled AND AutomaticallyAfterDays > 90 for at least one secret.
        if finding_id == "SM-003":
            secrets_doc = self.evidence.get("secrets", {})
            secrets_list = secrets_doc.get("secrets", []) if isinstance(secrets_doc, dict) else []

            has_over_90 = False
            for s in secrets_list if isinstance(secrets_list, list) else []:
                if not isinstance(s, dict):
                    continue
                if not s.get("RotationEnabled"):
                    continue
                rules = s.get("RotationRules")
                if not isinstance(rules, dict):
                    continue
                days = rules.get("AutomaticallyAfterDays")
                try:
                    if days is not None and int(days) > 90:
                        has_over_90 = True
                        break
                except (ValueError, TypeError):
                    continue

            if not has_over_90:
                logger.warning(
                    f"Rejected {finding_id} - No secrets with RotationEnabled=true and AutomaticallyAfterDays>90 found."
                )
                return False

        # ECR: Public wildcard principals (ECR-001)
        # Only valid when at least one repository policy explicitly allows wildcard principals.
        if finding_id == "ECR-001":
            repos_doc = self.evidence.get("repositories")
            if not isinstance(repos_doc, dict):
                repos_doc = {}
            repos_list = repos_doc.get("repositories", [])

            has_wildcard = False
            for r in repos_list if isinstance(repos_list, list) else []:
                if not isinstance(r, dict):
                    continue
                policy = r.get("Policy")
                if not isinstance(policy, dict):
                    continue
                for st in policy.get("Statement", []) or []:
                    if not isinstance(st, dict) or st.get("Effect") != "Allow":
                        continue
                    principal = st.get("Principal")
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        has_wildcard = True
                        break
                if has_wildcard:
                    break

            if not has_wildcard:
                logger.warning(
                    f"Rejected {finding_id} - No wildcard Principal '*' found in ECR repository policies."
                )
                return False

        # ECR: Image scanning on push should be enabled (ECR-003)
        # Guard against false positives when registry scanning is ENHANCED and already covers the repo.
        # In ENHANCED mode (Inspector integration), vulnerability scanning can be continuous at the
        # registry level, so per-repo scanOnPush=false is not necessarily a security gap.
        if finding_id == "ECR-003":
            reg_doc = self.evidence.get("registry")
            reg_scanning = None
            if isinstance(reg_doc, dict):
                reg_scanning = reg_doc.get("registry_scanning")

            scan_cfg = None
            if isinstance(reg_scanning, dict):
                scan_cfg = reg_scanning.get("scanningConfiguration")

            if isinstance(scan_cfg, dict) and scan_cfg.get("scanType") == "ENHANCED":
                repo_name: Optional[str] = None
                snippet = finding.evidence_snippet
                if isinstance(snippet, dict):
                    snippet_d = cast(Dict[str, Any], snippet)
                    repo_name = snippet_d.get("RepositoryName")

                if not repo_name:
                    for arn in finding.affected_resources or []:
                        if not isinstance(arn, str):
                            continue
                        marker = ":repository/"
                        if marker in arn:
                            # Repository names can include slashes; keep the full suffix.
                            repo_name = arn.split(marker, 1)[1]
                            break

                def _repo_filter_matches(repo: str, rf: Dict[str, Any]) -> bool:
                    pattern = rf.get("filter")
                    ftype = rf.get("filterType")
                    if not isinstance(pattern, str):
                        return False
                    if pattern == "*":
                        return True
                    if ftype == "PREFIX_MATCH":
                        return repo.startswith(pattern)
                    # Default to wildcard semantics (AWS uses WILDCARD in evidence)
                    return fnmatch.fnmatchcase(repo, pattern)

                if repo_name:
                    rules = scan_cfg.get("rules")
                    if isinstance(rules, list):
                        for rule in rules:
                            if not isinstance(rule, dict):
                                continue
                            freq = rule.get("scanFrequency")
                            if freq not in {"CONTINUOUS_SCAN", "SCAN_ON_PUSH"}:
                                continue

                            repo_filters = rule.get("repositoryFilters")
                            # Conservative: if filters are missing/invalid, we can't conclude coverage.
                            if not isinstance(repo_filters, list) or not repo_filters:
                                continue

                            if any(
                                isinstance(rf, dict) and _repo_filter_matches(repo_name, rf)
                                for rf in repo_filters
                            ):
                                logger.warning(
                                    f"Rejected {finding_id} - Registry ENHANCED scanning ({freq}) covers repository '{repo_name}'."
                                )
                                return False

        # ECR: Cross-account repository access review (ECR-007)
        # Only valid when there is explicit cross-account principal(s) present.
        if finding_id == "ECR-007":
            repos_doc = self.evidence.get("repositories", {})
            repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []

            # Determine current account from registry evidence or repository ARN.
            current_account: Optional[str] = None
            reg_doc = self.evidence.get("registry")
            if isinstance(reg_doc, dict):
                reg = reg_doc.get("registry")
                if isinstance(reg, dict) and reg.get("registryId"):
                    current_account = str(reg.get("registryId"))

            if not current_account and isinstance(repos_list, list):
                for r in repos_list:
                    if isinstance(r, dict) and r.get("RepositoryArn"):
                        arn = str(r.get("RepositoryArn"))
                        parts = arn.split(":")
                        if len(parts) > 4:
                            current_account = parts[4]
                            break

            def _extract_accounts(principal_aws: Any) -> List[str]:
                out: List[str] = []
                if isinstance(principal_aws, str):
                    out.append(principal_aws)
                elif isinstance(principal_aws, list):
                    out.extend([str(x) for x in principal_aws if x is not None])
                return out

            has_cross_account = False
            for r in repos_list if isinstance(repos_list, list) else []:
                if not isinstance(r, dict):
                    continue
                policy = r.get("Policy")
                if not isinstance(policy, dict):
                    continue
                for st in policy.get("Statement", []) or []:
                    if not isinstance(st, dict) or st.get("Effect") != "Allow":
                        continue
                    principal = st.get("Principal")
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        # Wildcard implies cross-account risk as well.
                        has_cross_account = True
                        break
                    if isinstance(principal, dict) and "AWS" in principal:
                        for aws_p in _extract_accounts(principal.get("AWS")):
                            if current_account and current_account in aws_p:
                                continue
                            # Capture numeric account IDs or ARNs for other accounts.
                            if aws_p.isdigit() and (
                                not current_account or aws_p != current_account
                            ):
                                has_cross_account = True
                                break
                            if aws_p.startswith("arn:aws:iam::"):
                                # arn:aws:iam::<acct>:role/name
                                acct = aws_p.split(":")[4] if len(aws_p.split(":")) > 4 else ""
                                if acct and (not current_account or acct != current_account):
                                    has_cross_account = True
                                    break
                    if has_cross_account:
                        break
                if has_cross_account:
                    break

            if not has_cross_account:
                logger.warning(
                    f"Rejected {finding_id} - No explicit cross-account principals found in repository policies."
                )
                return False

        # ECR: Registry scanning configuration should be defined (ECR-004)
        # Reject if evidence shows we could not collect registry scanning configuration.
        if finding_id == "ECR-004":
            reg_doc = self.evidence.get("registry")
            if isinstance(reg_doc, dict):
                reg_scanning = reg_doc.get("registry_scanning")
                if isinstance(reg_scanning, dict) and reg_scanning.get("error"):
                    logger.warning(
                        f"Rejected {finding_id} - registry scanning evidence has error: {reg_scanning.get('error')}"
                    )
                    return False
            # If missing entirely, also reject (insufficient evidence)
            else:
                return False

        # KMS: Key policy wildcard/broad principals (KMS-001)
        # Reject when we cannot find any Allow statement with a wildcard principal.
        if finding_id == "KMS-001":
            pol_doc = self.evidence.get("kms-key-policies")
            items = None
            if isinstance(pol_doc, dict):
                items = pol_doc.get("items")

            if not isinstance(items, list) or not items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            def _principal_has_wildcard(p: Any) -> bool:
                if p == "*":
                    return True
                if isinstance(p, str):
                    return p.strip() == "*"
                if isinstance(p, list):
                    return any(_principal_has_wildcard(x) for x in p)
                if isinstance(p, dict):
                    # Typical shapes: {"AWS": "*"} or {"AWS": ["arn:...", "*"]}
                    for v in p.values():
                        if _principal_has_wildcard(v):
                            return True
                return False

            has_wildcard = False
            for rec in items:
                if not isinstance(rec, dict):
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    # Unparseable policy (raw string) can't be validated; keep scanning.
                    continue
                stmts = policy.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []

                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    if str(st.get("Effect") or "").upper() != "ALLOW":
                        continue
                    if _principal_has_wildcard(st.get("Principal")):
                        has_wildcard = True
                        break
                if has_wildcard:
                    break

            if not has_wildcard:
                logger.warning(
                    f"Rejected {finding_id} - no wildcard/broad principals found in kms-key-policies."
                )
                return False

        # KMS: Grants allow decrypt or data key generation (KMS-002)
        # Reject when we cannot find any grant with Decrypt/GenerateDataKey operations.
        if finding_id == "KMS-002":
            grants_doc = self.evidence.get("kms-grants")
            items = None
            if isinstance(grants_doc, dict):
                items = grants_doc.get("items")

            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-grants evidence items.")
                return False

            has_sensitive_grant = False
            for g in items:
                if not isinstance(g, dict):
                    continue
                if not _kms_grant_is_sensitive(g):
                    continue

                # Ignore expected service-managed grants with context constraints.
                if _kms_grant_is_service_managed(g) and _kms_grant_has_context_constraints(g):
                    continue

                has_sensitive_grant = True
                break

            if not has_sensitive_grant:
                logger.warning(
                    f"Rejected {finding_id} - no grants with Decrypt/GenerateDataKey operations found in kms-grants."
                )
                return False

        # KMS: Policy allows administrative modification or grant creation (KMS-003)
        # Accept only when key policy explicitly allows kms:PutKeyPolicy/kms:CreateGrant/kms:*.
        if finding_id == "KMS-003":
            pol_doc = self.evidence.get("kms-key-policies")
            items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            def _actions(st: Dict[str, Any]) -> List[str]:
                a = st.get("Action")
                if isinstance(a, str):
                    return [a]
                if isinstance(a, list):
                    return [str(x) for x in a if x is not None]
                return []

            has_admin = False
            for rec in items:
                if not isinstance(rec, dict):
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    continue
                stmts = policy.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []

                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    if str(st.get("Effect") or "").upper() != "ALLOW":
                        continue
                    for act in _actions(st):
                        act_l = str(act).lower()
                        if act_l in {"kms:putkeypolicy", "kms:creategrant", "kms:*"}:
                            has_admin = True
                            break
                    if has_admin:
                        break
                if has_admin:
                    break

            if not has_admin:
                logger.warning(
                    f"Rejected {finding_id} - no kms:PutKeyPolicy/kms:CreateGrant permissions found in key policies."
                )
                return False

        # KMS: Rotation disabled for customer-managed keys (KMS-004)
        if finding_id == "KMS-004":
            keys_doc = self.evidence.get("kms-keys")
            items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-keys evidence items.")
                return False

            has_rotation_disabled = False
            for k in items:
                if not isinstance(k, dict):
                    continue
                meta = k.get("Metadata")
                if isinstance(meta, dict):
                    if str(meta.get("KeyManager") or "").upper() not in {"CUSTOMER"}:
                        continue
                # Collector stores KeyRotationEnabled at top-level when available.
                rot = k.get("KeyRotationEnabled")
                if rot is False or rot in {"false", "False", 0, "0"}:
                    has_rotation_disabled = True
                    break

            if not has_rotation_disabled:
                logger.warning(
                    f"Rejected {finding_id} - no customer-managed keys with KeyRotationEnabled=false found in evidence."
                )
                return False

        # KMS: Policies allow destructive key availability actions (KMS-005)
        if finding_id == "KMS-005":
            pol_doc = self.evidence.get("kms-key-policies")
            items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            destructive = {
                "kms:disablekey",
                "kms:schedulekeydeletion",
                "kms:deleteimportedkeymaterial",
                "kms:deletealias",
                "kms:updatealias",
                "kms:*",
            }

            has_destructive = False
            for rec in items:
                if not isinstance(rec, dict):
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    continue
                stmts = policy.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []

                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    if str(st.get("Effect") or "").upper() != "ALLOW":
                        continue
                    a = st.get("Action")
                    acts: List[str]
                    if isinstance(a, str):
                        acts = [a]
                    elif isinstance(a, list):
                        acts = [str(x) for x in a if x is not None]
                    else:
                        acts = []
                    if any(str(act).lower() in destructive for act in acts):
                        has_destructive = True
                        break
                if has_destructive:
                    break

            if not has_destructive:
                logger.warning(
                    f"Rejected {finding_id} - no destructive KMS actions found in key policies."
                )
                return False

        # KMS: Imported key material deletion risk (KMS-006)
        if finding_id == "KMS-006":
            keys_doc = self.evidence.get("kms-keys")
            key_items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
            pol_doc = self.evidence.get("kms-key-policies")
            pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
            if not isinstance(key_items, list) or not key_items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-keys evidence items.")
                return False
            if not isinstance(pol_items, list) or not pol_items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            external_ids = set()
            for k in key_items:
                if not isinstance(k, dict):
                    continue
                meta = k.get("Metadata") if isinstance(k.get("Metadata"), dict) else {}
                if str(meta.get("Origin") or "").upper() == "EXTERNAL":
                    key_id = str(meta.get("KeyId") or k.get("KeyId") or "")
                    if key_id:
                        external_ids.add(key_id)

            if not external_ids:
                logger.warning(f"Rejected {finding_id} - no EXTERNAL origin keys found.")
                return False

            has_risk = False
            for rec in pol_items:
                if not isinstance(rec, dict):
                    continue
                key_id = str(rec.get("KeyId") or "")
                if key_id not in external_ids:
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    continue
                stmts = policy.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []
                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    if str(st.get("Effect") or "").upper() != "ALLOW":
                        continue
                    a = st.get("Action")
                    acts: List[str]
                    if isinstance(a, str):
                        acts = [a]
                    elif isinstance(a, list):
                        acts = [str(x) for x in a if x is not None]
                    else:
                        acts = []
                    if any(
                        str(act).lower() in {"kms:deleteimportedkeymaterial", "kms:*"}
                        for act in acts
                    ):
                        has_risk = True
                        break
                if has_risk:
                    break

            if not has_risk:
                logger.warning(
                    f"Rejected {finding_id} - no DeleteImportedKeyMaterial permission found for EXTERNAL keys."
                )
                return False

        # KMS: grant persistence via CreateGrant delegation (KMS-007)
        if finding_id == "KMS-007":
            grants_doc = self.evidence.get("kms-grants")
            items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-grants evidence items.")
                return False

            has_unconstrained_create_grant = False
            for g in items:
                if not isinstance(g, dict):
                    continue
                ops = g.get("Operations")
                if not isinstance(ops, list):
                    continue
                ops_norm = {str(o) for o in ops if o is not None}
                if "CreateGrant" not in ops_norm:
                    continue
                cons = g.get("Constraints")
                has_ctx = isinstance(cons, dict) and bool(
                    cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset")
                )
                if has_ctx:
                    continue
                has_unconstrained_create_grant = True
                break

            if not has_unconstrained_create_grant:
                logger.warning(
                    f"Rejected {finding_id} - no unconstrained CreateGrant delegation found in grants evidence."
                )
                return False

        # Messaging: DLQ/Redrive config presence (MSG-002)
        # Reject when no queues have RedrivePolicy/RedriveAllowPolicy configured.
        if finding_id == "MSG-002":
            q_doc = self.evidence.get("sqs-queues")
            items = None
            if isinstance(q_doc, dict):
                items = q_doc.get("items")

            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty sqs-queues evidence items.")
                return False

            has_redrive = False
            for q in items:
                if not isinstance(q, dict):
                    continue
                if q.get("RedrivePolicy") or q.get("RedriveAllowPolicy"):
                    has_redrive = True
                    break

            if not has_redrive:
                logger.warning(
                    f"Rejected {finding_id} - no redrive configuration present in sqs-queues evidence."
                )
                return False

        # Messaging: OrgID condition present in SQS queue policy (MSG-001)
        if finding_id == "MSG-001":
            q_doc = self.evidence.get("sqs-queues")
            items = q_doc.get("items") if isinstance(q_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty sqs-queues evidence items.")
                return False

            has_orgid = False
            for q in items:
                if not isinstance(q, dict):
                    continue
                pol = q.get("Policy")
                if not isinstance(pol, dict):
                    continue
                stmts = pol.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []
                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    cond = st.get("Condition")
                    if not isinstance(cond, dict):
                        continue
                    cond_text = json.dumps(cond, default=str)
                    if "aws:PrincipalOrgID" in cond_text or "aws:PrincipalOrgId" in cond_text:
                        has_orgid = True
                        break
                if has_orgid:
                    break

            if not has_orgid:
                logger.warning(
                    f"Rejected {finding_id} - no aws:PrincipalOrgID condition found in SQS queue policies."
                )
                return False

        # Messaging: SNS->SQS injection condition missing (MSG-003)
        # Accept only when a queue policy allows SendMessage from SNS without SourceArn/SourceAccount.
        if finding_id == "MSG-003":
            q_doc = self.evidence.get("sqs-queues")
            items = q_doc.get("items") if isinstance(q_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty sqs-queues evidence items.")
                return False

            def _action_includes_send(action: Any) -> bool:
                if isinstance(action, str):
                    return action.lower() in {"sqs:sendmessage", "sqs:*", "*"}
                if isinstance(action, list):
                    return any(_action_includes_send(a) for a in action)
                return False

            def _principal_is_sns(principal: Any) -> bool:
                if isinstance(principal, dict):
                    svc = principal.get("Service")
                    if isinstance(svc, str) and svc.lower() == "sns.amazonaws.com":
                        return True
                    if isinstance(svc, list) and any(
                        isinstance(x, str) and x.lower() == "sns.amazonaws.com" for x in svc
                    ):
                        return True
                return False

            has_injection = False
            for q in items:
                if not isinstance(q, dict):
                    continue
                pol = q.get("Policy")
                if not isinstance(pol, dict):
                    continue
                stmts = pol.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []

                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    if str(st.get("Effect") or "").upper() != "ALLOW":
                        continue
                    if not _action_includes_send(st.get("Action")):
                        continue
                    if not _principal_is_sns(st.get("Principal")):
                        continue
                    cond = st.get("Condition")
                    cond_text = json.dumps(cond, default=str) if isinstance(cond, dict) else ""
                    if "aws:SourceArn" not in cond_text and "aws:SourceAccount" not in cond_text:
                        has_injection = True
                        break
                if has_injection:
                    break

            if not has_injection:
                logger.warning(
                    f"Rejected {finding_id} - no SNS->SQS SendMessage allow without SourceArn/SourceAccount found in evidence."
                )
                return False

        # Messaging: Message move task risk only applies when DLQs exist (MSG-004)
        if finding_id == "MSG-004":
            q_doc = self.evidence.get("sqs-queues")
            items = q_doc.get("items") if isinstance(q_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty sqs-queues evidence items.")
                return False

            has_dlq = False
            for q in items:
                if isinstance(q, dict) and q.get("RedrivePolicy"):
                    has_dlq = True
                    break

            if not has_dlq:
                logger.warning(
                    f"Rejected {finding_id} - no DLQ/RedrivePolicy configured; message move tasks are not applicable."
                )
                return False

        # CICD: Source credentials exist (CICD-001)
        if finding_id == "CICD-001":
            sc_doc = self.evidence.get("codebuild-source-credentials")
            items = None
            if isinstance(sc_doc, dict):
                items = sc_doc.get("items")

            if not isinstance(items, list) or len(items) == 0:
                logger.warning(
                    f"Rejected {finding_id} - no CodeBuild source credentials present in evidence."
                )
                return False

        # CICD: Insecure SSL or proxy-style config exists (CICD-002)
        if finding_id == "CICD-002":
            proj_doc = self.evidence.get("codebuild-projects")
            items = None
            if isinstance(proj_doc, dict):
                items = proj_doc.get("items")

            if not isinstance(items, list) or not items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty codebuild-projects evidence items."
                )
                return False

            has_risk = False
            for p in items:
                if not isinstance(p, dict):
                    continue
                source_raw = p.get("source")
                source: Dict[str, Any] = source_raw if isinstance(source_raw, dict) else {}
                if source.get("insecureSsl") is True:
                    has_risk = True
                    break

                env_raw = p.get("environment")
                env: Dict[str, Any] = env_raw if isinstance(env_raw, dict) else {}
                evs = env.get("environmentVariables")
                if isinstance(evs, list):
                    for ev in evs:
                        if isinstance(ev, dict) and ev.get("looks_like_proxy") is True:
                            has_risk = True
                            break
                if has_risk:
                    break

            if not has_risk:
                logger.warning(
                    f"Rejected {finding_id} - no insecureSsl/proxy indicators found in codebuild-projects evidence."
                )
                return False

        # Compute: EKS public endpoint exists (COMP-EKS-001)
        if finding_id == "COMP-EKS-001":
            eks_doc = self.evidence.get("eks-inventory")
            clusters = None
            if isinstance(eks_doc, dict):
                clusters = eks_doc.get("clusters")

            if not isinstance(clusters, list) or not clusters:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty eks-inventory clusters evidence."
                )
                return False

            has_public = False
            for c in clusters:
                if not isinstance(c, dict):
                    continue
                vpc_cfg = c.get("resourcesVpcConfig")
                if isinstance(vpc_cfg, dict) and vpc_cfg.get("endpointPublicAccess") is True:
                    has_public = True
                    break

            if not has_public:
                logger.warning(
                    f"Rejected {finding_id} - no clusters with endpointPublicAccess=true found in eks-inventory."
                )
                return False

        # Compute: EKS control plane logging not fully enabled (COMP-EKS-002)
        if finding_id == "COMP-EKS-002":
            eks_doc = self.evidence.get("eks-inventory")
            clusters = eks_doc.get("clusters") if isinstance(eks_doc, dict) else None
            if not isinstance(clusters, list) or not clusters:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty eks-inventory clusters evidence."
                )
                return False

            required = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
            has_gap = False
            for c in clusters:
                if not isinstance(c, dict):
                    continue
                logging_cfg = c.get("logging")
                if not isinstance(logging_cfg, dict):
                    has_gap = True
                    break
                cl = logging_cfg.get("clusterLogging")
                if not isinstance(cl, list):
                    has_gap = True
                    break
                enabled_types = set()
                for entry in cl:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("enabled") is not True:
                        continue
                    types = entry.get("types")
                    if isinstance(types, list):
                        for t in types:
                            if isinstance(t, str):
                                enabled_types.add(t)

                if not required.issubset(enabled_types):
                    has_gap = True
                    break

            if not has_gap:
                logger.warning(
                    f"Rejected {finding_id} - all required EKS control plane log types are enabled per eks-inventory."
                )
                return False

        # Compute: Scheduled EventBridge rules target ECS RunTask (COMP-ECS-001)
        if finding_id == "COMP-ECS-001":
            ev_doc = self.evidence.get("eventbridge-rules")
            rules = None
            if isinstance(ev_doc, dict):
                rules = ev_doc.get("rules")

            if not isinstance(rules, list) or not rules:
                logger.warning(f"Rejected {finding_id} - missing/empty eventbridge-rules evidence.")
                return False

            has_scheduled_ecs = False
            for r in rules:
                if not isinstance(r, dict):
                    continue
                if not r.get("ScheduleExpression"):
                    continue
                targets = r.get("Targets")
                if not isinstance(targets, list) or not targets:
                    continue
                for t in targets:
                    if not isinstance(t, dict):
                        continue
                    if t.get("EcsParameters"):
                        has_scheduled_ecs = True
                        break
                    arn = str(t.get("Arn") or "")
                    if ":ecs:" in arn:
                        has_scheduled_ecs = True
                        break
                if has_scheduled_ecs:
                    break

            if not has_scheduled_ecs:
                logger.warning(
                    f"Rejected {finding_id} - no scheduled EventBridge rule with ECS targets found in eventbridge-rules."
                )
                return False

        # Compute: ECS task definitions drift/unexpected containers (COMP-ECS-002)
        # Accept only when evidence shows suspicious image pinning patterns.
        if finding_id == "COMP-ECS-002":
            ecs_doc = self.evidence.get("ecs-inventory")
            tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
            if not isinstance(tdefs, list) or not tdefs:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty ecs-inventory task_definitions evidence."
                )
                return False

            def _image_suspicious(img: str) -> bool:
                img_l = img.lower()
                if "@sha256:" in img_l:
                    return False
                if img_l.endswith(":latest") or ":latest" in img_l:
                    return True
                for reg in ("docker.io/", "ghcr.io/", "quay.io/"):
                    if reg in img_l:
                        return True
                return False

            has_suspicious = False
            for td in tdefs:
                if not isinstance(td, dict):
                    continue
                cds = td.get("containerDefinitions")
                if not isinstance(cds, list):
                    continue
                for cd in cds:
                    if not isinstance(cd, dict):
                        continue
                    img = cd.get("image")
                    if isinstance(img, str) and _image_suspicious(img):
                        has_suspicious = True
                        break
                if has_suspicious:
                    break

            if not has_suspicious:
                logger.warning(
                    f"Rejected {finding_id} - no suspicious container image patterns found in task definitions."
                )
                return False

        # Compute: ECS workloads lack centralized logging (COMP-ECS-003)
        if finding_id == "COMP-ECS-003":
            ecs_doc = self.evidence.get("ecs-inventory")
            tdefs = ecs_doc.get("task_definitions") if isinstance(ecs_doc, dict) else None
            if not isinstance(tdefs, list) or not tdefs:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty ecs-inventory task_definitions evidence."
                )
                return False

            has_logging_gap = False
            for td in tdefs:
                if not isinstance(td, dict):
                    continue
                cds = td.get("containerDefinitions")
                if not isinstance(cds, list):
                    continue
                for cd in cds:
                    if not isinstance(cd, dict):
                        continue
                    log_cfg = cd.get("logConfiguration")
                    if not isinstance(log_cfg, dict):
                        has_logging_gap = True
                        break
                    if str(log_cfg.get("logDriver") or "").lower() != "awslogs":
                        has_logging_gap = True
                        break
                if has_logging_gap:
                    break

            if not has_logging_gap:
                logger.warning(
                    f"Rejected {finding_id} - all containers appear to have awslogs configuration."
                )
                return False

        # Compute: ECS task roles overly permissive (COMP-ECS-004)
        # We cannot determine role policy scope from this skill; require explicit wildcard evidence_snippet.
        if finding_id == "COMP-ECS-004":
            snippet_text = json.dumps(finding.evidence_snippet or {}, default=str).lower()
            if '"action"' in snippet_text and ('"*"' in snippet_text or "iam:*" in snippet_text):
                return True
            logger.warning(
                f"Rejected {finding_id} - insufficient evidence of overly permissive IAM actions for ECS roles."
            )
            return False

        # ------------------------------
        # IAM evidence-based validations
        # ------------------------------

        # IAM: No policy should have full administrative permissions (*:*) (IAM-008)
        # Accept only when at least one policy statement contains wildcard Action ('*' or 'iam:*')
        # AND is not strictly resource-scoped.
        if finding_id == "IAM-008":
            pols = self.evidence.get("policies")
            if not isinstance(pols, list) or not pols:
                logger.warning(f"Rejected {finding_id} - missing/empty policies evidence.")
                return False

            def _iam_actions(action: Any) -> List[str]:
                if isinstance(action, str):
                    return [action]
                if isinstance(action, list):
                    return [str(a) for a in action if a is not None]
                return []

            def _iam_resources(res: Any) -> List[str]:
                if isinstance(res, str):
                    return [res]
                if isinstance(res, list):
                    return [str(r) for r in res if r is not None]
                return []

            has_admin = False
            for p in pols:
                if not isinstance(p, dict):
                    continue
                doc = p.get("PolicyDocument")
                if not isinstance(doc, dict):
                    continue
                stmts = doc.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []

                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    if str(st.get("Effect") or "").upper() != "ALLOW":
                        continue
                    acts = [a.lower() for a in _iam_actions(st.get("Action"))]
                    if "*" not in acts and "iam:*" not in acts:
                        continue

                    # If action is wildcard, resource scoping matters. '*' resource is high risk.
                    res_list = _iam_resources(st.get("Resource"))
                    if not res_list:
                        # Missing resource is effectively broad.
                        has_admin = True
                        break
                    if any(r == "*" for r in res_list):
                        has_admin = True
                        break

                if has_admin:
                    break

            if not has_admin:
                logger.warning(
                    f"Rejected {finding_id} - no Allow statements with wildcard Action+Resource found in policies evidence."
                )
                return False

        # IAM: Role trust policies should not allow public access (*) (IAM-011)
        # Accept only when at least one trust policy contains wildcard principal.
        if finding_id == "IAM-011":
            roles = self.evidence.get("roles")
            if not isinstance(roles, list) or not roles:
                logger.warning(f"Rejected {finding_id} - missing/empty roles evidence.")
                return False

            def _principal_is_wildcard(principal: Any) -> bool:
                if principal == "*":
                    return True
                if isinstance(principal, dict):
                    aws = principal.get("AWS")
                    if aws == "*":
                        return True
                    if isinstance(aws, list) and any(x == "*" for x in aws):
                        return True
                return False

            has_public_trust = False
            for r in roles:
                if not isinstance(r, dict):
                    continue
                trust = r.get("AssumeRolePolicyDocument")
                if not isinstance(trust, dict):
                    continue
                stmts = trust.get("Statement")
                stmt_list: List[Any]
                if isinstance(stmts, list):
                    stmt_list = stmts
                elif isinstance(stmts, dict):
                    stmt_list = [stmts]
                else:
                    stmt_list = []
                for st in stmt_list:
                    if not isinstance(st, dict):
                        continue
                    if str(st.get("Effect") or "").upper() != "ALLOW":
                        continue
                    if _principal_is_wildcard(st.get("Principal")):
                        has_public_trust = True
                        break
                if has_public_trust:
                    break

            if not has_public_trust:
                logger.warning(
                    f"Rejected {finding_id} - no wildcard Principal '*' found in role trust policies."
                )
                return False

        # IAM: Access keys should be rotated every 90 days (IAM-004)
        # Accept only when at least one ACTIVE access key is older than 90 days.
        if finding_id == "IAM-004":
            users = self.evidence.get("users")
            if not isinstance(users, list) or not users:
                logger.warning(f"Rejected {finding_id} - missing/empty users evidence.")
                return False

            now = datetime.now(timezone.utc)
            has_old_active = False
            for u in users:
                if not isinstance(u, dict):
                    continue
                for k in u.get("AccessKeys", []) or []:
                    if not isinstance(k, dict):
                        continue
                    if str(k.get("Status") or "").lower() != "active":
                        continue
                    cd = k.get("CreateDate")
                    if not isinstance(cd, str) or not cd:
                        continue
                    try:
                        created = datetime.fromisoformat(cd.replace("Z", "+00:00"))
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=timezone.utc)
                    except Exception:
                        continue
                    age_days = (now - created).days
                    if age_days > 90:
                        has_old_active = True
                        break
                if has_old_active:
                    break

            if not has_old_active:
                logger.warning(
                    f"Rejected {finding_id} - no active access keys older than 90 days found in users evidence."
                )
                return False

        # IAM: Users should not have multiple active access keys (IAM-014)
        # Accept only when at least one user has >=2 ACTIVE keys.
        if finding_id == "IAM-014":
            users = self.evidence.get("users")
            if not isinstance(users, list) or not users:
                # Fallback to credential report when users.json is not available.
                cred = self.evidence.get("credential-report")
                by_user = cred.get("by_user") if isinstance(cred, dict) else None
                if not isinstance(by_user, dict) or not by_user:
                    # Fail-open: when only partial evidence is loaded (unit tests/chunks),
                    # we cannot safely validate multi-key state.
                    logger.warning(
                        f"Accepted {finding_id} - users evidence missing and credential-report by_user unavailable (fail-open)."
                    )
                    return True

                def _is_true(v: Any) -> bool:
                    if isinstance(v, bool):
                        return v
                    if isinstance(v, str):
                        return v.strip().lower() in {"true", "yes", "1"}
                    if isinstance(v, int):
                        return v == 1
                    return False

                has_multi_active = False
                for _, row in by_user.items():
                    if not isinstance(row, dict):
                        continue
                    if _is_true(row.get("access_key_1_active")) and _is_true(
                        row.get("access_key_2_active")
                    ):
                        has_multi_active = True
                        break

                if not has_multi_active:
                    logger.warning(
                        f"Rejected {finding_id} - credential report shows no users with two active keys."
                    )
                    return False

                return True

            has_multi_active = False
            for u in users:
                if not isinstance(u, dict):
                    continue
                keys = u.get("AccessKeys")
                if not isinstance(keys, list):
                    continue
                active = [
                    k
                    for k in keys
                    if isinstance(k, dict) and str(k.get("Status") or "").lower() == "active"
                ]
                if len(active) >= 2:
                    has_multi_active = True
                    break

            if not has_multi_active:
                logger.warning(
                    f"Rejected {finding_id} - no users with >=2 active access keys found in users evidence."
                )
                return False

        # IAM: Users should not exist without group assignment (IAM-020)
        # Accept only when at least one user has Groups empty.
        if finding_id == "IAM-020":
            users = self.evidence.get("users")
            if not isinstance(users, list) or not users:
                logger.warning(f"Rejected {finding_id} - missing/empty users evidence.")
                return False

            has_user_without_group = False
            for u in users:
                if not isinstance(u, dict):
                    continue
                groups = u.get("Groups")
                if isinstance(groups, list) and len(groups) == 0:
                    has_user_without_group = True
                    break

            if not has_user_without_group:
                logger.warning(
                    f"Rejected {finding_id} - no users with empty Groups[] found in users evidence."
                )
                return False

        return True  # Finding is valid against evidence

    def _get_hardening_securityhub_counts(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """Return global Security Hub severity/compliance counts for hardening validations."""

        sev_counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "OTHER": 0,
        }
        comp_counts: Dict[str, int] = {
            "PASSED": 0,
            "FAILED": 0,
            "WARNING": 0,
            "NOT_AVAILABLE": 0,
            "OTHER": 0,
        }

        summary = self.evidence.get("security-hub-findings-summary") if self.evidence else None
        if isinstance(summary, dict):
            sc = summary.get("severity_counts")
            if isinstance(sc, dict):
                for k in sev_counts:
                    sev_counts[k] = int(sc.get(k, 0) or 0)

            cc = summary.get("compliance_status_counts")
            if isinstance(cc, dict):
                for k in comp_counts:
                    comp_counts[k] = int(cc.get(k, 0) or 0)

        # Fallback: derive from raw findings when summary is unavailable.
        if sum(sev_counts.values()) == 0:
            findings = self.evidence.get("security-hub-findings") if self.evidence else None
            if isinstance(findings, list):
                for f in findings:
                    if not isinstance(f, dict):
                        continue

                    sev = str(((f.get("Severity") or {}).get("Label") or "")).upper()
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                    elif sev:
                        sev_counts["OTHER"] += 1

                    comp = str(((f.get("Compliance") or {}).get("Status") or "")).upper()
                    if comp in comp_counts:
                        comp_counts[comp] += 1
                    elif comp:
                        comp_counts["OTHER"] += 1

        return sev_counts, comp_counts

    def _hardening_refs_resolve_to_securityhub(self, finding: Finding) -> bool:
        """Validate that Security Hub refs point to actually present evidence records."""

        refs = finding.evidence_refs or []
        sh_refs = [
            r for r in refs if isinstance(r, str) and r.startswith("security-hub-findings.json#")
        ]
        if not sh_refs:
            return True

        findings = self.evidence.get("security-hub-findings") if self.evidence else None
        if not isinstance(findings, list) or not findings:
            # If we can't validate due missing evidence, fail-open.
            return True

        unresolved: List[str] = []
        for r in sh_refs:
            frag = r.split("#", 1)[1].strip() if "#" in r else ""
            if not frag:
                continue

            if frag in {"metadata", "ResourceCount"}:
                unresolved.append(frag)
                continue

            token = frag
            if " (" in token and token.endswith("findings)"):
                token = token.split(" (", 1)[0]

            matched = False
            for rec in findings:
                if not isinstance(rec, dict):
                    continue
                rec_id = str(rec.get("Id") or "")
                rec_gen = str(rec.get("GeneratorId") or "")
                rec_title = str(rec.get("Title") or "")

                if "/finding/" in token:
                    finding_tail = token.split("/finding/", 1)[1]
                    if finding_tail and finding_tail in rec_id:
                        matched = True
                        break
                else:
                    if token and (token in rec_id or token in rec_gen or token in rec_title):
                        matched = True
                        break

            if not matched:
                unresolved.append(frag)

        if unresolved:
            logger.warning(
                f"Unresolved Security Hub refs: {unresolved[:3]} (total={len(unresolved)})"
            )
            return False

        return True

    def _hardening_threshold_narrative_contradicts_evidence(
        self, finding_id: str, finding: Finding, sev_counts: Dict[str, int]
    ) -> bool:
        """Reject threshold findings when their own narrative contradicts required thresholds."""

        if finding_id not in {"HRD-009", "HRD-012"}:
            return False

        text = " ".join(
            [
                str(finding.title or ""),
                str(finding.description or ""),
                json.dumps(finding.evidence_snippet or {}, default=str),
            ]
        ).lower()

        if finding_id == "HRD-009":
            # Explicitly saying <=10 HIGH is contradictory with ">10" rule.
            if "high_severity_count" in text:
                m = re.search(r"high_severity_count\D*(\d+)", text)
                if m and int(m.group(1)) <= 10:
                    return True

            for m in re.finditer(r"(\d+)\s+high", text):
                if int(m.group(1)) <= 10:
                    return True

            if "below the >10 threshold" in text or "below >10 threshold" in text:
                return True

            # Sanity: global evidence itself must satisfy threshold.
            return int(sev_counts.get("HIGH", 0)) <= 10

        if finding_id == "HRD-012":
            if "medium_severity_findings" in text:
                m = re.search(r"medium_severity_findings\D*(\d+)", text)
                if m and int(m.group(1)) <= 20:
                    return True

            for m in re.finditer(r"(\d+)\s+medium", text):
                if int(m.group(1)) <= 20:
                    return True

            if "below the >20 threshold" in text or "below >20 threshold" in text:
                return True

            return int(sev_counts.get("MEDIUM", 0)) <= 20

        return False

    def _hardening_has_tagging_evidence(self, finding: Finding) -> bool:
        """Return True only when evidence includes real tagging data."""

        refs = [r for r in (finding.evidence_refs or []) if isinstance(r, str)]
        if refs and all("password-policy.json" in r for r in refs):
            return False

        if not isinstance(self.evidence, dict):
            return False

        for key, value in self.evidence.items():
            key_l = str(key).lower()
            if "tag" not in key_l:
                continue

            if isinstance(value, list) and len(value) > 0:
                return True
            if isinstance(value, dict):
                # Conservative: require non-metadata, non-empty payload.
                payload_keys = [k for k in value.keys() if k != "ResponseMetadata"]
                if payload_keys:
                    return True

        return False

    def _hardening_has_outdated_enabled_standards(self) -> bool:
        """Detect outdated Security Hub standard versions from enabled standards evidence."""

        standards = self.evidence.get("security-hub-enabled-standards") if self.evidence else None
        if not isinstance(standards, list):
            return False

        for s in standards:
            if not isinstance(s, dict):
                continue
            arn = str(s.get("StandardsArn") or "")
            arn_l = arn.lower()

            # Explicit known legacy versions that should be considered outdated.
            if "pci-dss" in arn_l and "/v/3.2.1" in arn_l:
                return True
            if "cis-aws-foundations-benchmark" in arn_l and "/v/1.2.0" in arn_l:
                return True

        return False

    def _validate_vulns_finding(self, finding_id: str, finding: Finding) -> bool:
        """Validate vulns findings against concrete Inspector/RDS evidence.

        This prevents high-impact false positives in chunked analyses where a single
        chunk may not include all evidence files.
        """

        if not isinstance(self.evidence, dict):
            return True

        inspector_raw = self.evidence.get("inspector-findings")
        inspector_findings: List[Dict[str, Any]] = []
        if isinstance(inspector_raw, list):
            inspector_findings = [f for f in inspector_raw if isinstance(f, dict)]

        active_findings = [
            f for f in inspector_findings if str(f.get("status", "")).upper() == "ACTIVE"
        ]

        if finding_id == "VULN-001":
            # "Inspector disabled" contradicts any collected Inspector findings.
            if inspector_findings:
                logger.warning(
                    "Rejected VULN-001 - inspector-findings.json contains findings; "
                    "Inspector is active in this account/region."
                )
                return False

        if finding_id == "VULN-002":
            # "Critical unremediated" requires at least one ACTIVE CRITICAL finding.
            has_active_critical = any(
                str(f.get("severity", "")).upper() == "CRITICAL" for f in active_findings
            )
            if not has_active_critical:
                logger.warning(
                    "Rejected VULN-002 - no ACTIVE CRITICAL findings in inspector-findings evidence."
                )
                return False

        if finding_id == "VULN-009":
            # Accumulation risk requires multiple ACTIVE HIGH/CRITICAL CVEs in same resource.
            per_resource: Dict[str, int] = {}
            for f in active_findings:
                sev = str(f.get("severity", "")).upper()
                if sev not in {"CRITICAL", "HIGH"}:
                    continue
                for r in f.get("resources", []) or []:
                    if not isinstance(r, dict):
                        continue
                    rid = r.get("id")
                    if isinstance(rid, str) and rid:
                        per_resource[rid] = per_resource.get(rid, 0) + 1

            if not per_resource or max(per_resource.values()) < 3:
                logger.warning(
                    "Rejected VULN-009 - no resource has >=3 ACTIVE HIGH/CRITICAL findings."
                )
                return False

        if finding_id == "VULN-014":
            # "Unpatched >30 days" needs explicit age evidence, not only upgrade availability.
            if not self._has_vuln_age_evidence_gt_30_days(finding):
                logger.warning("Rejected VULN-014 - missing explicit age evidence (>30 days).")
                return False

        return True

    def _has_vuln_age_evidence_gt_30_days(self, finding: Finding) -> bool:
        """Return True when finding contains explicit aging evidence >30 days."""

        snippet = finding.evidence_snippet
        if isinstance(snippet, dict):
            stack: List[Any] = [snippet]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    for k, v in node.items():
                        key = str(k).lower()

                        if isinstance(v, (int, float)):
                            if (
                                any(tok in key for tok in ("day", "age", "stale", "open"))
                                and v > 30
                            ):
                                return True

                        if isinstance(v, str):
                            value_lower = v.lower()
                            if ("30+" in value_lower) or (">30" in value_lower):
                                return True
                            if any(tok in key for tok in ("day", "age", "stale", "open")):
                                digits = re.findall(r"\d+", value_lower)
                                if digits and int(digits[0]) > 30:
                                    return True

                        if isinstance(v, (dict, list)):
                            stack.append(v)
                elif isinstance(node, list):
                    for item in node:
                        if isinstance(item, (dict, list)):
                            stack.append(item)
                        elif isinstance(item, str):
                            il = item.lower()
                            if "30+" in il or ">30" in il:
                                return True

        # Also accept explicit reference to timestamp-based aging evidence.
        refs = finding.evidence_refs or []
        for ref in refs:
            if not isinstance(ref, str):
                continue
            rl = ref.lower()
            if any(
                tok in rl for tok in ("firstobservedat", "lastobservedat", "days_open", "age_days")
            ):
                return True

        return False

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
