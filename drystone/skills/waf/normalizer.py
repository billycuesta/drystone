"""WAF-specific findings normalization hooks."""

import logging
from typing import Optional

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    pass


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("WAF-"):
            return None

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

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
