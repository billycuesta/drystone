"""IAM-specific findings normalization hooks."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, cast

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        out: List[str] = []
        for r in refs:
            if not isinstance(r, str):
                continue
            rr = r
            rr = rr.replace("credential-report.json", "credential-report.csv")
            rr = rr.replace("credential_report.json", "credential-report.csv")
            rr = rr.replace("credential_report.csv", "credential-report.csv")
            rr = rr.replace("#root_account", "#<root_account>")
            out.append(rr)
        return out


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("IAM-"):
            return None

        # IAM: Root account MFA
        if finding_id == "IAM-001":
            account_summary = self.evidence.get("account-summary", {})
            mfa_enabled = None
            if isinstance(account_summary, dict):
                # Collector may store either the raw API shape (SummaryMap.AccountMFAEnabled)
                # or a flattened test fixture shape (AccountMFAEnabled).
                if "AccountMFAEnabled" in account_summary:
                    mfa_enabled = account_summary.get("AccountMFAEnabled")
                else:
                    summary_map = account_summary.get("SummaryMap")
                    if isinstance(summary_map, dict):
                        mfa_enabled = summary_map.get("AccountMFAEnabled")

            if mfa_enabled in {1, True, "1", "true", "True"}:
                logger.warning(
                    f"Rejected {finding_id} - Root account MFA IS enabled. "
                    f"Evidence: AccountMFAEnabled={mfa_enabled}"
                )
                return False  # Root MFA IS enabled

            # Secondary source of truth: credential report CSV (if present)
            cred = self.evidence.get("credential-report")
            if isinstance(cred, dict):
                by_user = cred.get("by_user")
                if isinstance(by_user, dict):
                    root_row = by_user.get("<root_account>")
                    if isinstance(root_row, dict):
                        mfa_active = root_row.get("mfa_active")
                        if mfa_active in {"true", "True", True, "1", 1}:
                            logger.warning(
                                f"Rejected {finding_id} - Root account MFA IS enabled (credential report). "
                                f"Evidence: mfa_active={mfa_active}"
                            )
                            return False

        # IAM: Root account access keys
        if finding_id == "IAM-009":
            account_summary = self.evidence.get("account-summary", {})
            access_keys_present = None
            if isinstance(account_summary, dict):
                if "AccountAccessKeysPresent" in account_summary:
                    access_keys_present = account_summary.get("AccountAccessKeysPresent")
                else:
                    summary_map = account_summary.get("SummaryMap")
                    if isinstance(summary_map, dict):
                        access_keys_present = summary_map.get("AccountAccessKeysPresent")

            # 0 means no root access keys present.
            if access_keys_present in {0, False, "0", "false", "False"}:
                logger.warning(
                    f"Rejected {finding_id} - Root access keys are NOT present. "
                    f"Evidence: AccountAccessKeysPresent={access_keys_present}"
                )
                return False

            # Secondary source of truth: credential report CSV (if present)
            cred = self.evidence.get("credential-report")
            if isinstance(cred, dict):
                by_user = cred.get("by_user")
                if isinstance(by_user, dict):
                    root_row = by_user.get("<root_account>")
                    if isinstance(root_row, dict):
                        k1 = root_row.get("access_key_1_active")
                        k2 = root_row.get("access_key_2_active")
                        if k1 in {"false", "False", False, "0", 0} and k2 in {
                            "false",
                            "False",
                            False,
                            "0",
                            0,
                        }:
                            logger.warning(
                                f"Rejected {finding_id} - Root access keys are NOT active (credential report). "
                                f"Evidence: access_key_1_active={k1}, access_key_2_active={k2}"
                            )
                            return False

        # IAM: Inactive users
        if finding_id == "IAM-003":
            users = self.evidence.get("users", [])
            inactive = [
                u for u in users if not u.get("PasswordLastUsed") and not u.get("AccessKeys")
            ]
            if len(inactive) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No inactive users found. "
                    f"Evidence: {len(users)} users, all have activity."
                )
                return False  # No inactive users found

        # IAM: Inactive users (IAM-012)
        # The model sometimes flags root as "inactive" due to old console usage.
        # Root account should be used minimally; this is expected and not a finding.
        if finding_id == "IAM-012":
            is_root = False
            for arn in finding.affected_resources or []:
                if isinstance(arn, str) and arn.endswith(":root"):
                    is_root = True
                    break

            snippet = finding.evidence_snippet
            if not is_root and isinstance(snippet, dict):
                sn = cast(Dict[str, Any], snippet)
                if sn.get("user") == "<root_account>" or sn.get("arn", "").endswith(":root"):
                    is_root = True

            if is_root:
                logger.warning(
                    f"Rejected {finding_id} - Root account inactivity is expected; not actionable."
                )
                return False

        # IAM: Old access keys (> 90 days)
        if finding_id == "IAM-007":
            users = self.evidence.get("users", [])
            old_keys = []
            for user in users:
                for key in user.get("AccessKeys", []):
                    create_date = key.get("CreateDate")
                    if isinstance(create_date, str):
                        try:
                            create_date = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                        except (ValueError, TypeError):
                            continue
                    if create_date and isinstance(create_date, datetime):
                        age_days = (datetime.now(create_date.tzinfo) - create_date).days
                        if age_days > 90:
                            old_keys.append(key)
            if len(old_keys) == 0:
                logger.warning(
                    f"Rejected {finding_id} - No old access keys found (>90 days). "
                    f"All keys are recent or missing CreateDate."
                )
                return False

        # IAM evidence-based validations
        # ------------------------------

        # IAM: No policy should have full administrative permissions (*:*) (IAM-008)
        # Accept only when at least one policy statement contains wildcard Action ('*' or 'iam:*')
        # AND is not strictly resource-scoped.
        if finding_id == "IAM-008":
            pols = self.evidence.get("policies")
            if not isinstance(pols, list) or not pols:
                logger.warning(f"Rejected {finding_id} - missing/empty policies evidence.")
                return False

            def _iam_actions(action: Any) -> List[str]:
                if isinstance(action, str):
                    return [action]
                if isinstance(action, list):
                    return [str(a) for a in action if a is not None]
                return []

            def _iam_resources(res: Any) -> List[str]:
                if isinstance(res, str):
                    return [res]
                if isinstance(res, list):
                    return [str(r) for r in res if r is not None]
                return []

            has_admin = False
            for p in pols:
                if not isinstance(p, dict):
                    continue
                doc = p.get("PolicyDocument")
                if not isinstance(doc, dict):
                    continue
                stmts = doc.get("Statement")
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
                    acts = [a.lower() for a in _iam_actions(st.get("Action"))]
                    if "*" not in acts and "iam:*" not in acts:
                        continue

                    # If action is wildcard, resource scoping matters. '*' resource is high risk.
                    res_list = _iam_resources(st.get("Resource"))
                    if not res_list:
                        # Missing resource is effectively broad.
                        has_admin = True
                        break
                    if any(r == "*" for r in res_list):
                        has_admin = True
                        break

                if has_admin:
                    break

            if not has_admin:
                logger.warning(
                    f"Rejected {finding_id} - no Allow statements with wildcard Action+Resource found in policies evidence."
                )
                return False

        # IAM: Role trust policies should not allow public access (*) (IAM-011)
        # Accept only when at least one trust policy contains wildcard principal.
        if finding_id == "IAM-011":
            roles = self.evidence.get("roles")
            if not isinstance(roles, list) or not roles:
                logger.warning(f"Rejected {finding_id} - missing/empty roles evidence.")
                return False

            def _principal_is_wildcard(principal: Any) -> bool:
                if principal == "*":
                    return True
                if isinstance(principal, dict):
                    aws = principal.get("AWS")
                    if aws == "*":
                        return True
                    if isinstance(aws, list) and any(x == "*" for x in aws):
                        return True
                return False

            has_public_trust = False
            for r in roles:
                if not isinstance(r, dict):
                    continue
                trust = r.get("AssumeRolePolicyDocument")
                if not isinstance(trust, dict):
                    continue
                stmts = trust.get("Statement")
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
                    if _principal_is_wildcard(st.get("Principal")):
                        has_public_trust = True
                        break
                if has_public_trust:
                    break

            if not has_public_trust:
                logger.warning(
                    f"Rejected {finding_id} - no wildcard Principal '*' found in role trust policies."
                )
                return False

        # IAM: Access keys should be rotated every 90 days (IAM-004)
        # Accept only when at least one ACTIVE access key is older than 90 days.
        if finding_id == "IAM-004":
            users = self.evidence.get("users")
            if not isinstance(users, list) or not users:
                logger.warning(f"Rejected {finding_id} - missing/empty users evidence.")
                return False

            now = datetime.now(timezone.utc)
            has_old_active = False
            for u in users:
                if not isinstance(u, dict):
                    continue
                for k in u.get("AccessKeys", []) or []:
                    if not isinstance(k, dict):
                        continue
                    if str(k.get("Status") or "").lower() != "active":
                        continue
                    cd = k.get("CreateDate")
                    if not isinstance(cd, str) or not cd:
                        continue
                    try:
                        created = datetime.fromisoformat(cd.replace("Z", "+00:00"))
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=timezone.utc)
                    except Exception:
                        continue
                    age_days = (now - created).days
                    if age_days > 90:
                        has_old_active = True
                        break
                if has_old_active:
                    break

            if not has_old_active:
                logger.warning(
                    f"Rejected {finding_id} - no active access keys older than 90 days found in users evidence."
                )
                return False

        # IAM: Users should not have multiple active access keys (IAM-014)
        # Accept only when at least one user has >=2 ACTIVE keys.
        if finding_id == "IAM-014":
            users = self.evidence.get("users")
            if not isinstance(users, list) or not users:
                # Fallback to credential report when users.json is not available.
                cred = self.evidence.get("credential-report")
                by_user = cred.get("by_user") if isinstance(cred, dict) else None
                if not isinstance(by_user, dict) or not by_user:
                    # Fail-open: when only partial evidence is loaded (unit tests/chunks),
                    # we cannot safely validate multi-key state.
                    logger.warning(
                        f"Accepted {finding_id} - users evidence missing and credential-report by_user unavailable (fail-open)."
                    )
                    return True

                def _is_true(v: Any) -> bool:
                    if isinstance(v, bool):
                        return v
                    if isinstance(v, str):
                        return v.strip().lower() in {"true", "yes", "1"}
                    if isinstance(v, int):
                        return v == 1
                    return False

                has_multi_active = False
                for _, row in by_user.items():
                    if not isinstance(row, dict):
                        continue
                    if _is_true(row.get("access_key_1_active")) and _is_true(
                        row.get("access_key_2_active")
                    ):
                        has_multi_active = True
                        break

                if not has_multi_active:
                    logger.warning(
                        f"Rejected {finding_id} - credential report shows no users with two active keys."
                    )
                    return False

                return True

            has_multi_active = False
            for u in users:
                if not isinstance(u, dict):
                    continue
                keys = u.get("AccessKeys")
                if not isinstance(keys, list):
                    continue
                active = [
                    k
                    for k in keys
                    if isinstance(k, dict) and str(k.get("Status") or "").lower() == "active"
                ]
                if len(active) >= 2:
                    has_multi_active = True
                    break

            if not has_multi_active:
                logger.warning(
                    f"Rejected {finding_id} - no users with >=2 active access keys found in users evidence."
                )
                return False

        # IAM: Users should not exist without group assignment (IAM-020)
        # Accept only when at least one user has Groups empty.
        if finding_id == "IAM-020":
            users = self.evidence.get("users")
            if not isinstance(users, list) or not users:
                logger.warning(f"Rejected {finding_id} - missing/empty users evidence.")
                return False

            has_user_without_group = False
            for u in users:
                if not isinstance(u, dict):
                    continue
                groups = u.get("Groups")
                if isinstance(groups, list) and len(groups) == 0:
                    has_user_without_group = True
                    break

            if not has_user_without_group:
                logger.warning(
                    f"Rejected {finding_id} - no users with empty Groups[] found in users evidence."
                )
                return False


        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
