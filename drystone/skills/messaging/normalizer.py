"""Messaging-specific findings normalization hooks."""

import json
import logging
from typing import Any, List, Optional

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    pass


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("MSG-"):
            return None

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

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
