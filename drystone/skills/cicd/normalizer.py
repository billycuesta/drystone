"""CI/CD-specific findings normalization hooks."""

import logging
from typing import Any, Dict, Optional

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    pass


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("CICD-"):
            return None

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

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
