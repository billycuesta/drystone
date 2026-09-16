"""IAM (IAM-*) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import (
    dedupe_refs,
    list_from_evidence,
    refs_for_resources,
)


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id in {"IAM-002", "IAM-004", "IAM-012", "IAM-014", "IAM-015", "IAM-016"}:
        resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
        if resource_details:
            refs, _matched = refs_for_resources(
                evidence,
                "users",
                [str(d.get("arn") or d.get("user") or "") for d in resource_details],
                ("UserName",),
            )
            if check_id in {"IAM-002", "IAM-012", "IAM-016"}:
                refs.extend(_iam_credential_refs(resource_details))
            if check_id in {"IAM-002", "IAM-004", "IAM-015", "IAM-016"}:
                refs.extend(_iam_group_refs(evidence, resource_details))
                refs.extend(_iam_policy_refs(evidence, resource_details))
            summaries = {
                "IAM-002": f"{len(resource_details)} user(s) without MFA on console or active access-key identities",
                "IAM-004": f"{len(resource_details)} user(s) with access keys older than 90 days",
                "IAM-012": f"{len(resource_details)} inactive user(s) (>90 days without activity)",
                "IAM-014": f"{len(resource_details)} user(s) with multiple active access keys",
                "IAM-015": f"{len(resource_details)} user(s) with direct policy attachments outside groups",
                "IAM-016": f"{len(resource_details)} IAM user(s) with service-account-like credential patterns",
            }
            return (
                dedupe_refs(refs)[:20],
                {
                    "evidence_summary": summaries[check_id],
                    "affected_resources": resource_details,
                },
            )

    if check_id in {"IAM-007", "IAM-026", "IAM-041"}:
        resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
        if check_id == "IAM-041":
            resource_details = (getattr(result, "metadata", None) or {}).get("detailed_roles")
        if resource_details:
            refs, _matched = refs_for_resources(
                evidence,
                "roles",
                [
                    str(
                        d.get("arn")
                        or d.get("RoleArn")
                        or d.get("role_arn")
                        or d.get("role_name")
                        or d.get("RoleName")
                        or ""
                    )
                    for d in resource_details
                    if isinstance(d, dict)
                ],
                ("RoleName",),
            )
            if check_id == "IAM-026":
                refs.extend(_iam_policy_refs(evidence, resource_details))
            summaries = {
                "IAM-007": f"{len(resource_details)} role(s) with inline policies",
                "IAM-026": f"{len(resource_details)} role(s) without permissions boundaries",
                "IAM-041": f"{len(resource_details)} role(s) with AdministratorAccess/PowerUserAccess",
            }
            return (
                dedupe_refs(refs)[:20],
                {
                    "evidence_summary": summaries[check_id],
                    "affected_resources": resource_details,
                },
            )

    return None


def _iam_policy_refs(evidence: Dict[str, Any], details: List[Dict[str, Any]]) -> List[str]:
    policy_ids: set = set()

    def _collect(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key in {"policy_arn", "PolicyArn"} and val:
                    policy_ids.add(str(val))
                elif key in {"policy_name", "PolicyName"} and val:
                    policy_ids.add(str(val))
                elif key in {
                    "policy_arns",
                    "PolicyArns",
                    "direct_policy_arns",
                    "group_policy_arns",
                } and isinstance(val, list):
                    policy_ids.update(str(item) for item in val if item)
                else:
                    _collect(val)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item)

    _collect(details)
    refs: List[str] = []
    for idx, policy in enumerate(list_from_evidence(evidence, "policies")):
        candidates = {
            str(policy.get("Arn") or ""),
            str(policy.get("PolicyArn") or ""),
            str(policy.get("PolicyName") or ""),
        }
        if candidates & policy_ids:
            refs.append(f"policies.json#/{idx}")
    return refs


def _iam_group_refs(evidence: Dict[str, Any], details: List[Dict[str, Any]]) -> List[str]:
    group_names: set = set()
    for detail in details:
        context = detail.get("permission_context") if isinstance(detail, dict) else None
        if isinstance(context, dict):
            group_names.update(str(g) for g in (context.get("groups") or []) if g)
        for group in detail.get("groups") or [] if isinstance(detail, dict) else []:
            if isinstance(group, str):
                group_names.add(group)
    refs: List[str] = []
    for idx, group in enumerate(list_from_evidence(evidence, "groups")):
        if str(group.get("GroupName") or "") in group_names:
            refs.append(f"groups.json#/{idx}")
    return refs


def _iam_credential_refs(details: List[Dict[str, Any]]) -> List[str]:
    return [
        f"credential-report.csv#{d.get('user')}"
        for d in details
        if isinstance(d, dict) and d.get("user")
    ]
