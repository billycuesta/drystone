"""Compute-specific findings normalization hooks."""

import json
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

        if not finding_id.startswith("COMP-"):
            return None

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

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
