"""Evidence distillation to reduce prompt/token size."""

import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

FILE_ALLOWLIST_FIELDS = {
    "vpcs": {"VpcId", "CidrBlock", "State", "IsDefault", "Tags"},
    "security-groups": {
        "GroupId",
        "GroupName",
        "VpcId",
        "Description",
        "IpPermissions",
        "IpPermissionsEgress",
    },
    "route-tables": {"RouteTableId", "VpcId", "Routes", "Associations", "Tags"},
    "subnets": {"SubnetId", "VpcId", "CidrBlock", "AvailabilityZone", "MapPublicIpOnLaunch"},
    "roles": {
        "Arn",
        "RoleName",
        "AssumeRolePolicyDocument",
        "AttachedPolicies",  # actual field name (was wrongly "AttachedManagedPolicies")
        "InlinePolicies",
        "Path",
    },
    "policies": {
        "Arn",
        "PolicyName",
        "DefaultVersionId",
        "AttachmentCount",
        "IsAttachable",
        "PolicyDocument",  # policy content needed for LLM checks (IAM-007, -008, etc.)
    },
    "inspector-findings": {
        "findingArn",
        "status",
        "severity",
        "title",
        "description",
        "resources",
        "inspectorScore",
        "fixAvailable",
        "exploitAvailable",
        "remediation",
        "packageVulnerabilityDetails",
    },
}


def _normalize_file_key(key: str) -> str:
    return str(key).replace(".json", "").lower()


def _prune_dict_fields(resource: Dict[str, Any], file_key: str) -> Dict[str, Any]:
    allow = FILE_ALLOWLIST_FIELDS.get(file_key)
    if not allow:
        return resource
    out = {k: v for k, v in resource.items() if k in allow}
    if len(out) == 0:
        logger.warning(
            "distiller: allowlist for %r matched none of this resource's fields "
            "(%s) -- distillation had no effect, keeping the resource unpruned. "
            "This usually means the resource's real field names drifted from "
            "FILE_ALLOWLIST_FIELDS[%r].",
            file_key,
            sorted(resource.keys()),
            file_key,
        )
        return resource
    if file_key == "inspector-findings":
        out = _compact_inspector_finding(out)
    return out


def _truncate_text(value: Any, max_chars: int = 240) -> Any:
    if not isinstance(value, str):
        return value
    if len(value) <= max_chars:
        return value
    return value[:max_chars].rstrip() + "..."


def _compact_inspector_finding(item: Dict[str, Any]) -> Dict[str, Any]:
    """Keep Inspector findings small enough for LLM triage prompts.

    Deterministic pre-checks still receive full raw evidence before distillation.
    The LLM only needs compact fields to reason about residual checklist items.
    """
    compact = dict(item)
    if "description" in compact:
        compact["description"] = _truncate_text(compact.get("description"), 240)

    remediation = compact.get("remediation")
    if isinstance(remediation, dict):
        compact["remediation"] = {
            "recommendation": _truncate_text(remediation.get("recommendation"), 240),
            "url": remediation.get("url"),
        }

    details = compact.get("packageVulnerabilityDetails")
    if isinstance(details, dict):
        packages = details.get("vulnerablePackages") or []
        compact_packages = []
        if isinstance(packages, list):
            for pkg in packages[:3]:
                if not isinstance(pkg, dict):
                    continue
                compact_packages.append(
                    {
                        "name": pkg.get("name"),
                        "version": pkg.get("version"),
                        "fixedInVersion": pkg.get("fixedInVersion"),
                        "packageManager": pkg.get("packageManager"),
                    }
                )
        compact["packageVulnerabilityDetails"] = {
            "vulnerabilityId": details.get("vulnerabilityId"),
            "source": details.get("source"),
            "vulnerablePackages": compact_packages,
            "cvss": (details.get("cvss") or [])[:1] if isinstance(details.get("cvss"), list) else [],
        }

    resources = compact.get("resources")
    if isinstance(resources, list):
        compact["resources"] = [
            {
                "id": res.get("id"),
                "type": res.get("type"),
            }
            for res in resources[:2]
            if isinstance(res, dict)
        ]

    return compact


def _prune_list_items(items: List[Any], file_key: str, keep_count: int) -> List[Any]:
    source_items = items
    if file_key == "inspector-findings":
        def _inspector_rank(item: Any) -> tuple:
            if not isinstance(item, dict):
                return (9, 9, 9)
            status_rank = 0 if str(item.get("status", "")).upper() == "ACTIVE" else 1
            sev = str(item.get("severity", "")).upper()
            severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)
            exploit_rank = 0 if str(item.get("exploitAvailable", "")).upper() == "YES" else 1
            return (status_rank, severity_rank, exploit_rank)

        source_items = sorted(items, key=_inspector_rank)

    trimmed = source_items[:keep_count]
    pruned: List[Any] = []
    for item in trimmed:
        if isinstance(item, dict):
            pruned.append(_prune_dict_fields(item, file_key))
        else:
            pruned.append(item)
    return pruned


def distill_evidence(
    evidence: Dict[str, Any], max_list_items: int = 25
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Create a compact evidence view while keeping traceability.

    Rules:
    - Keep metadata keys untouched.
    - For long lists, keep first N elements and attach summary metadata.
    - For dicts containing long lists, apply same truncation recursively (1 level).
    """
    distilled: Dict[str, Any] = {}
    files_reduced = 0
    items_removed = 0

    for key, value in evidence.items():
        file_key = _normalize_file_key(str(key))
        if str(key).startswith("_"):
            distilled[key] = value
            continue

        if isinstance(value, list):
            if len(value) > max_list_items:
                files_reduced += 1
                items_removed += len(value) - max_list_items
                distilled[key] = {
                    "_distilled": True,
                    "_original_count": len(value),
                    "_kept_count": max_list_items,
                    "items": _prune_list_items(value, file_key, max_list_items),
                }
            else:
                distilled[key] = _prune_list_items(value, file_key, len(value))
            continue

        if isinstance(value, dict):
            compact = dict(value)
            changed = False
            for sub_key, sub_value in list(compact.items()):
                if isinstance(sub_value, list) and len(sub_value) > max_list_items:
                    changed = True
                    files_reduced += 1
                    items_removed += len(sub_value) - max_list_items
                    compact[sub_key] = {
                        "_distilled": True,
                        "_original_count": len(sub_value),
                        "_kept_count": max_list_items,
                        "items": _prune_list_items(sub_value, file_key, max_list_items),
                    }
                elif isinstance(sub_value, list):
                    compact[sub_key] = _prune_list_items(sub_value, file_key, len(sub_value))
            distilled[key] = compact if changed else value
            continue

        distilled[key] = value

    stats = {
        "files_reduced": files_reduced,
        "items_removed": items_removed,
    }
    return distilled, stats
