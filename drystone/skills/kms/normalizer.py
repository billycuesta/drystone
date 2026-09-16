"""KMS-specific findings normalization hooks."""

import logging
from typing import Any, Dict, List, Optional

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import _principal_has_wildcard
from drystone.validation.normalizer_hooks import (
    DefaultNormalizerHook,
    NormalizerContext,
    SeverityAdjustment,
)

logger = logging.getLogger(__name__)


def _kms_grant_is_sensitive(grant: Dict[str, Any]) -> bool:
    ops = grant.get("Operations")
    if not isinstance(ops, list):
        return False
    ops_norm = {str(o) for o in ops if o is not None}
    return "Decrypt" in ops_norm or any(o.startswith("GenerateDataKey") for o in ops_norm)


def _kms_grant_has_context_constraints(grant: Dict[str, Any]) -> bool:
    cons = grant.get("Constraints")
    if not isinstance(cons, dict):
        return False
    return bool(cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset"))


def _kms_grant_is_service_managed(grant: Dict[str, Any]) -> bool:
    grantee = str(grant.get("GranteePrincipal") or "")
    issuing = str(grant.get("IssuingAccount") or "")
    if grantee.endswith(".amazonaws.com"):
        return True
    if ":assumed-role/" in grantee and "arn:aws:sts::" in grantee:
        return True
    if issuing.endswith(".amazonaws.com"):
        return True
    return False


class SkillNormalizerHook(DefaultNormalizerHook):
    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return refs

        out: List[str] = []

        pol_doc = evidence.get("kms-key-policies")
        pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else []
        keyid_to_idx: Dict[str, int] = {}
        if isinstance(pol_items, list):
            for i, it in enumerate(pol_items):
                if isinstance(it, dict):
                    kid = str(it.get("KeyId") or "").strip()
                    if kid:
                        keyid_to_idx[kid] = i

        grants_doc = evidence.get("kms-grants")
        grant_items = grants_doc.get("items") if isinstance(grants_doc, dict) else []
        grantid_to_idx: Dict[str, int] = {}
        if isinstance(grant_items, list):
            for i, it in enumerate(grant_items):
                if isinstance(it, dict):
                    gid = str(it.get("GrantId") or "").strip()
                    if gid:
                        grantid_to_idx[gid] = i

        for r in refs:
            if not isinstance(r, str):
                continue
            rr = r.strip()

            if rr.startswith("kms-key-policies.json#"):
                anchor = rr.split("#", 1)[1]
                if anchor.startswith("items."):
                    out.append(rr)
                    continue

                key_id = anchor
                if anchor.startswith("KeyId="):
                    key_id = anchor.split("=", 1)[1]

                idx = keyid_to_idx.get(key_id)
                if idx is not None:
                    out.append(f"kms-key-policies.json#items.{idx}")
                else:
                    out.append(rr)
                continue

            if rr.startswith("kms-grants.json#"):
                anchor = rr.split("#", 1)[1]
                if anchor.startswith("items."):
                    out.append(rr)
                    continue
                idx = grantid_to_idx.get(anchor)
                if idx is not None:
                    out.append(f"kms-grants.json#items.{idx}")
                else:
                    out.append(rr)
                continue

            out.append(rr)

        return out

    def adjust_severity(
        self, finding_id: str, finding: Finding, severity: str, risk_score: float
    ) -> Optional[SeverityAdjustment]:
        if finding_id == "KMS-001" and self._kms_001_is_managed_default_pattern(finding):
            return "High", 7.2
        return None

    def _kms_001_is_managed_default_pattern(self, finding: Finding) -> bool:
        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return False

        refs = finding.evidence_refs or []
        if not refs:
            return False

        keys_doc = evidence.get("kms-keys")
        key_items = keys_doc.get("items") if isinstance(keys_doc, dict) else []
        keyman_by_id: Dict[str, str] = {}
        if isinstance(key_items, list):
            for it in key_items:
                if not isinstance(it, dict):
                    continue
                kid = str(it.get("KeyId") or "")
                meta = it.get("Metadata") if isinstance(it.get("Metadata"), dict) else {}
                km = str(meta.get("KeyManager") or "")
                if kid:
                    keyman_by_id[kid] = km

        pol_doc = evidence.get("kms-key-policies")
        pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else []
        idx_to_policy: Dict[int, Dict[str, Any]] = {}
        if isinstance(pol_items, list):
            for i, it in enumerate(pol_items):
                if isinstance(it, dict):
                    idx_to_policy[i] = it

        seen_any = False
        for ref in refs:
            if not isinstance(ref, str) or not ref.startswith("kms-key-policies.json#items."):
                continue
            try:
                idx = int(ref.split("#items.", 1)[1])
            except Exception:
                continue
            rec = idx_to_policy.get(idx)
            if not isinstance(rec, dict):
                continue
            seen_any = True
            key_id = str(rec.get("KeyId") or "")
            if keyman_by_id.get(key_id, "").upper() != "AWS":
                return False

            policy = rec.get("Policy")
            if not isinstance(policy, dict):
                return False
            stmts = policy.get("Statement")
            stmt_list = stmts if isinstance(stmts, list) else [stmts] if isinstance(stmts, dict) else []

            wildcard_stmt_ok = False
            for st in stmt_list:
                if not isinstance(st, dict):
                    continue
                if str(st.get("Effect") or "").upper() != "ALLOW":
                    continue
                if not _principal_has_wildcard(st.get("Principal")):
                    continue
                cond = st.get("Condition") if isinstance(st.get("Condition"), dict) else {}
                if not isinstance(cond, dict):
                    continue
                s_eq = cond.get("StringEquals") if isinstance(cond.get("StringEquals"), dict) else {}
                s_like = cond.get("StringLike") if isinstance(cond.get("StringLike"), dict) else {}
                has_caller = isinstance(s_eq, dict) and bool(s_eq.get("kms:CallerAccount"))
                via = None
                if isinstance(s_eq, dict):
                    via = s_eq.get("kms:ViaService")
                if via is None and isinstance(s_like, dict):
                    via = s_like.get("kms:ViaService")
                has_via = bool(via)
                if has_caller and has_via:
                    wildcard_stmt_ok = True
                    break

            if not wildcard_stmt_ok:
                return False

        return seen_any


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("KMS-"):
            return None

        # KMS: Key policy wildcard/broad principals (KMS-001)
        # Reject when we cannot find any Allow statement with a wildcard principal.
        if finding_id == "KMS-001":
            pol_doc = self.evidence.get("kms-key-policies")
            items = None
            if isinstance(pol_doc, dict):
                items = pol_doc.get("items")

            if not isinstance(items, list) or not items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            def _principal_has_wildcard(p: Any) -> bool:
                if p == "*":
                    return True
                if isinstance(p, str):
                    return p.strip() == "*"
                if isinstance(p, list):
                    return any(_principal_has_wildcard(x) for x in p)
                if isinstance(p, dict):
                    # Typical shapes: {"AWS": "*"} or {"AWS": ["arn:...", "*"]}
                    for v in p.values():
                        if _principal_has_wildcard(v):
                            return True
                return False

            has_wildcard = False
            for rec in items:
                if not isinstance(rec, dict):
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    # Unparseable policy (raw string) can't be validated; keep scanning.
                    continue
                stmts = policy.get("Statement")
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
                    if _principal_has_wildcard(st.get("Principal")):
                        has_wildcard = True
                        break
                if has_wildcard:
                    break

            if not has_wildcard:
                logger.warning(
                    f"Rejected {finding_id} - no wildcard/broad principals found in kms-key-policies."
                )
                return False

        # KMS: Grants allow decrypt or data key generation (KMS-002)
        # Reject when we cannot find any grant with Decrypt/GenerateDataKey operations.
        if finding_id == "KMS-002":
            grants_doc = self.evidence.get("kms-grants")
            items = None
            if isinstance(grants_doc, dict):
                items = grants_doc.get("items")

            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-grants evidence items.")
                return False

            has_sensitive_grant = False
            for g in items:
                if not isinstance(g, dict):
                    continue
                if not _kms_grant_is_sensitive(g):
                    continue

                # Ignore expected service-managed grants with context constraints.
                if _kms_grant_is_service_managed(g) and _kms_grant_has_context_constraints(g):
                    continue

                has_sensitive_grant = True
                break

            if not has_sensitive_grant:
                logger.warning(
                    f"Rejected {finding_id} - no grants with Decrypt/GenerateDataKey operations found in kms-grants."
                )
                return False

        # KMS: Policy allows administrative modification or grant creation (KMS-003)
        # Accept only when key policy explicitly allows kms:PutKeyPolicy/kms:CreateGrant/kms:*.
        if finding_id == "KMS-003":
            pol_doc = self.evidence.get("kms-key-policies")
            items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            def _actions(st: Dict[str, Any]) -> List[str]:
                a = st.get("Action")
                if isinstance(a, str):
                    return [a]
                if isinstance(a, list):
                    return [str(x) for x in a if x is not None]
                return []

            has_admin = False
            for rec in items:
                if not isinstance(rec, dict):
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    continue
                stmts = policy.get("Statement")
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
                    for act in _actions(st):
                        act_l = str(act).lower()
                        if act_l in {"kms:putkeypolicy", "kms:creategrant", "kms:*"}:
                            has_admin = True
                            break
                    if has_admin:
                        break
                if has_admin:
                    break

            if not has_admin:
                logger.warning(
                    f"Rejected {finding_id} - no kms:PutKeyPolicy/kms:CreateGrant permissions found in key policies."
                )
                return False

        # KMS: Rotation disabled for customer-managed keys (KMS-004)
        if finding_id == "KMS-004":
            keys_doc = self.evidence.get("kms-keys")
            items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-keys evidence items.")
                return False

            has_rotation_disabled = False
            for k in items:
                if not isinstance(k, dict):
                    continue
                meta = k.get("Metadata")
                if isinstance(meta, dict):
                    if str(meta.get("KeyManager") or "").upper() not in {"CUSTOMER"}:
                        continue
                # Collector stores KeyRotationEnabled at top-level when available.
                rot = k.get("KeyRotationEnabled")
                if rot is False or rot in {"false", "False", 0, "0"}:
                    has_rotation_disabled = True
                    break

            if not has_rotation_disabled:
                logger.warning(
                    f"Rejected {finding_id} - no customer-managed keys with KeyRotationEnabled=false found in evidence."
                )
                return False

        # KMS: Policies allow destructive key availability actions (KMS-005)
        if finding_id == "KMS-005":
            pol_doc = self.evidence.get("kms-key-policies")
            items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            destructive = {
                "kms:disablekey",
                "kms:schedulekeydeletion",
                "kms:deleteimportedkeymaterial",
                "kms:deletealias",
                "kms:updatealias",
                "kms:*",
            }

            has_destructive = False
            for rec in items:
                if not isinstance(rec, dict):
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    continue
                stmts = policy.get("Statement")
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
                    a = st.get("Action")
                    acts: List[str]
                    if isinstance(a, str):
                        acts = [a]
                    elif isinstance(a, list):
                        acts = [str(x) for x in a if x is not None]
                    else:
                        acts = []
                    if any(str(act).lower() in destructive for act in acts):
                        has_destructive = True
                        break
                if has_destructive:
                    break

            if not has_destructive:
                logger.warning(
                    f"Rejected {finding_id} - no destructive KMS actions found in key policies."
                )
                return False

        # KMS: Imported key material deletion risk (KMS-006)
        if finding_id == "KMS-006":
            keys_doc = self.evidence.get("kms-keys")
            key_items = keys_doc.get("items") if isinstance(keys_doc, dict) else None
            pol_doc = self.evidence.get("kms-key-policies")
            pol_items = pol_doc.get("items") if isinstance(pol_doc, dict) else None
            if not isinstance(key_items, list) or not key_items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-keys evidence items.")
                return False
            if not isinstance(pol_items, list) or not pol_items:
                logger.warning(
                    f"Rejected {finding_id} - missing/empty kms-key-policies evidence items."
                )
                return False

            external_ids = set()
            for k in key_items:
                if not isinstance(k, dict):
                    continue
                meta = k.get("Metadata") if isinstance(k.get("Metadata"), dict) else {}
                if str(meta.get("Origin") or "").upper() == "EXTERNAL":
                    key_id = str(meta.get("KeyId") or k.get("KeyId") or "")
                    if key_id:
                        external_ids.add(key_id)

            if not external_ids:
                logger.warning(f"Rejected {finding_id} - no EXTERNAL origin keys found.")
                return False

            has_risk = False
            for rec in pol_items:
                if not isinstance(rec, dict):
                    continue
                key_id = str(rec.get("KeyId") or "")
                if key_id not in external_ids:
                    continue
                policy = rec.get("Policy")
                if not isinstance(policy, dict):
                    continue
                stmts = policy.get("Statement")
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
                    a = st.get("Action")
                    acts: List[str]
                    if isinstance(a, str):
                        acts = [a]
                    elif isinstance(a, list):
                        acts = [str(x) for x in a if x is not None]
                    else:
                        acts = []
                    if any(
                        str(act).lower() in {"kms:deleteimportedkeymaterial", "kms:*"}
                        for act in acts
                    ):
                        has_risk = True
                        break
                if has_risk:
                    break

            if not has_risk:
                logger.warning(
                    f"Rejected {finding_id} - no DeleteImportedKeyMaterial permission found for EXTERNAL keys."
                )
                return False

        # KMS: grant persistence via CreateGrant delegation (KMS-007)
        if finding_id == "KMS-007":
            grants_doc = self.evidence.get("kms-grants")
            items = grants_doc.get("items") if isinstance(grants_doc, dict) else None
            if not isinstance(items, list) or not items:
                logger.warning(f"Rejected {finding_id} - missing/empty kms-grants evidence items.")
                return False

            has_unconstrained_create_grant = False
            for g in items:
                if not isinstance(g, dict):
                    continue
                ops = g.get("Operations")
                if not isinstance(ops, list):
                    continue
                ops_norm = {str(o) for o in ops if o is not None}
                if "CreateGrant" not in ops_norm:
                    continue
                cons = g.get("Constraints")
                has_ctx = isinstance(cons, dict) and bool(
                    cons.get("EncryptionContextEquals") or cons.get("EncryptionContextSubset")
                )
                if has_ctx:
                    continue
                has_unconstrained_create_grant = True
                break

            if not has_unconstrained_create_grant:
                logger.warning(
                    f"Rejected {finding_id} - no unconstrained CreateGrant delegation found in grants evidence."
                )

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
