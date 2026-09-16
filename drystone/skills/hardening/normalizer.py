"""Hardening-specific findings normalization hooks."""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
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


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("HRD-"):
            return None

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

        # GuardDuty validation (HRD-014)
        if finding_id == "HRD-014":
            gd_detectors = self.evidence.get("guardduty-detectors", [])
            detector_ids: List[Any] = []
            if isinstance(gd_detectors, dict):
                detector_ids = gd_detectors.get("DetectorIds") or []
            elif isinstance(gd_detectors, list):
                detector_ids = gd_detectors
            if not detector_ids:
                logger.warning(
                    f"Accepted {finding_id} - GuardDuty is not enabled and no detectors were found."
                )

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

        return True

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


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
