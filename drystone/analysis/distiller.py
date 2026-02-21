"""Evidence distillation to reduce prompt/token size."""

from typing import Any, Dict, List, Tuple


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
        "AttachedPolicies",   # actual field name (was wrongly "AttachedManagedPolicies")
        "InlinePolicies",
        "Path",
    },
    "policies": {
        "Arn",
        "PolicyName",
        "DefaultVersionId",
        "AttachmentCount",
        "IsAttachable",
        "PolicyDocument",     # policy content needed for LLM checks (IAM-007, -008, etc.)
    },
    "inspector-findings": {
        "findingArn",
        "severity",
        "title",
        "description",
        "resource",
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
        return resource
    return out


def _prune_list_items(items: List[Any], file_key: str, keep_count: int) -> List[Any]:
    trimmed = items[:keep_count]
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
