"""KMS (KMS-002, KMS-007) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
Note the original had two stages for KMS-002: a cheap early return when
`resource_details` is present, falling through to detailed grant matching
(shared with KMS-007) otherwise.
"""

from typing import Any, Dict, List, Optional

from drystone.skills._traceability_helpers import generic_traceability


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id not in {"KMS-002", "KMS-007"}:
        return None

    if check_id == "KMS-002":
        resource_details = (getattr(result, "metadata", None) or {}).get("resource_details")
        if resource_details:
            return (
                ["kms-grants.json"],
                {
                    "evidence_summary": (
                        f"{len(resource_details)} unexpected sensitive KMS grant(s)"
                    ),
                    "affected_resources": resource_details,
                },
            )

    grants_doc = evidence.get("kms-grants")
    items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
    if not isinstance(items, list):
        return [], None

    def _is_sensitive(grant: Dict[str, Any]) -> bool:
        ops = grant.get("Operations")
        if not isinstance(ops, list):
            return False
        ops_norm = {str(o) for o in ops if o is not None}
        return "Decrypt" in ops_norm or any(o.startswith("GenerateDataKey") for o in ops_norm)

    def _is_expected(grant: Dict[str, Any]) -> bool:
        cons = grant.get("Constraints")
        if not isinstance(cons, dict):
            return False
        has_ctx = bool(cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset"))
        grantee = str(grant.get("GranteePrincipal") or "")
        issuing = str(grant.get("IssuingAccount") or "")
        serviceish = (
            grantee.endswith(".amazonaws.com")
            or (":assumed-role/" in grantee and "arn:aws:sts::" in grantee)
            or issuing.endswith(".amazonaws.com")
        )
        return has_ctx and serviceish

    for idx, grant in enumerate(items):
        if not isinstance(grant, dict):
            continue
        if check_id == "KMS-002":
            if not _is_sensitive(grant):
                continue
            if _is_expected(grant):
                continue
        elif check_id == "KMS-007":
            ops = grant.get("Operations")
            if not isinstance(ops, list):
                continue
            if "CreateGrant" not in {str(o) for o in ops if o is not None}:
                continue
            if _is_expected(grant):
                continue

        ref = f"kms-grants.json#items.{idx}"
        snippet = {
            "GrantId": grant.get("GrantId"),
            "KeyId": grant.get("KeyId"),
            "GranteePrincipal": grant.get("GranteePrincipal"),
            "Operations": grant.get("Operations"),
            "Constraints": grant.get("Constraints"),
        }
        return [ref], snippet

    # fallback to generic traceability for other KMS pre-check fails
    return generic_traceability(result, evidence)
