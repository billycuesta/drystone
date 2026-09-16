"""Vulnerability-specific findings normalization hooks."""

import logging
import re
from typing import Any, Dict, List, Optional

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    pass


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("VULN"):
            return None
        return self._validate_vulns_finding(finding_id, finding)

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

        if finding_id == "VULN-003":
            # Publicly accessible vulnerable resources require explicit reachability evidence;
            # active EC2 Inspector findings alone only prove vulnerable instances.
            public_ids: set = set()
            for key in ("public-vulnerability-paths", "internet-reachable-vulnerabilities"):
                doc = self.evidence.get(key)
                items = (
                    doc.get("items")
                    if isinstance(doc, dict)
                    else doc if isinstance(doc, list) else []
                )
                for item in items or []:
                    if not isinstance(item, dict):
                        continue
                    rid = (
                        item.get("InstanceId") or item.get("instance_id") or item.get("resource_id")
                    )
                    if isinstance(rid, str) and rid:
                        public_ids.add(rid)

            for key in ("ec2-instances", "instances"):
                doc = self.evidence.get(key)
                items = (
                    doc.get("items")
                    if isinstance(doc, dict)
                    else doc if isinstance(doc, list) else []
                )
                for item in items or []:
                    if not isinstance(item, dict):
                        continue
                    rid = str(item.get("InstanceId") or "")
                    if not rid:
                        continue
                    if (
                        item.get("PublicIpAddress")
                        or item.get("PublicIp")
                        or item.get("PubliclyReachable") is True
                    ):
                        public_ids.add(rid)

            if not public_ids:
                logger.warning(
                    "Rejected VULN-003 - no public reachability evidence for vulnerable resources."
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

        if finding_id == "VULN-011":
            # Empty ECR image findings are ambiguous; disabled scanning needs config proof.
            has_ecr_finding = any(
                any(
                    isinstance(r, dict) and r.get("type") == "AWS_ECR_CONTAINER_IMAGE"
                    for r in (f.get("resources") or [])
                )
                for f in inspector_findings
            )
            if has_ecr_finding:
                logger.warning(
                    "Rejected VULN-011 - ECR image findings exist, so scanning is not proven disabled."
                )
                return False

            config_proves_disabled = False
            for key in ("ecr-scanning-config", "scanning-config", "registry"):
                doc = self.evidence.get(key)
                if not isinstance(doc, dict):
                    continue
                scan_type = str(doc.get("scanType") or doc.get("ScanType") or "").upper()
                rules = doc.get("rules") or doc.get("Rules") or []
                if scan_type in {"BASIC", "NONE", "DISABLED"} or rules == []:
                    config_proves_disabled = True
                    break
            if not config_proves_disabled:
                logger.warning(
                    "Rejected VULN-011 - no ECR scan configuration evidence proving disabled scanning."
                )
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



def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
