"""Secrets Manager-specific findings normalization hooks."""

import logging
from typing import Any, Dict, List, Optional, cast

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return refs

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


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("SM-"):
            return None

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

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
