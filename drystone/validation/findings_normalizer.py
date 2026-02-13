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

import re
import logging
import fnmatch
from typing import List, Dict, Any, Tuple, Optional, Literal, cast

from drystone.models.findings import Finding, FindingsSummary, PCIDSSControl

logger = logging.getLogger(__name__)


Severity = Literal["Critical", "High", "Medium", "Low"]


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
        # IAM: User state
        ("IAM-003", "IAM-004"): "keep_specific",  # Inactive user vs no MFA
        ("IAM-005", "IAM-007"): "keep_specific",  # No rotation vs old keys
        ("IAM-008", "IAM-009"): "keep_specific",  # Weak policy vs no policy
        # IAM: Root account
        ("IAM-001", "IAM-002"): "keep_higher",  # No MFA vs partial MFA
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

            # Update finding in-place
            finding.id = normalized_id
            finding.severity = severity
            finding.risk_score = risk_score

            # Enforce checklist title for language consistency.
            item = self.checklist_map.get(normalized_id)
            if isinstance(item, dict) and isinstance(item.get("title"), str) and item.get("title"):
                finding.title = str(item.get("title"))

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

            # Align PCI DSS mappings with checklist source of truth.
            # The agent sometimes emits incorrect control IDs for a given finding ID.
            self._align_pci_dss_controls(normalized_id, finding)

            logger.debug(f"  ✅ Accepted: {normalized_id} | {severity} | risk={risk_score:.1f}")
            normalized.append(finding)

        return normalized

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

        return refs

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

        Args:
            finding_id: Normalized finding ID (e.g., "HRD-002")
            finding: Finding object to validate

        Returns:
            True if finding is valid, False if contradicts evidence (should be filtered)

        Examples:
            - HRD-002 "Security Hub disabled" is FALSE if HubArn exists in evidence → return False
            - HRD-001 "Config disabled" is FALSE if ConfigurationRecorders > 0 → return False
            - HRD-003 "No standards enabled" is FALSE if Security Hub not enabled → return False
        """
        if not self.evidence:
            return True  # No evidence to validate against

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
            from datetime import datetime, timedelta

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

        return True  # Finding is valid against evidence

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
