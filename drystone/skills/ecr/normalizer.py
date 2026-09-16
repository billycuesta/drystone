"""ECR-specific findings normalization hooks."""

import fnmatch
import logging
from typing import Any, Dict, List, Optional, cast

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return refs

        repos_doc = evidence.get("repositories")
        name_to_idx: Dict[str, int] = {}
        if isinstance(repos_doc, dict):
            repos_list = repos_doc.get("repositories", [])
            if isinstance(repos_list, list):
                for i, r in enumerate(repos_list):
                    if isinstance(r, dict) and r.get("RepositoryName"):
                        n = str(r.get("RepositoryName"))
                        if n not in name_to_idx:
                            name_to_idx[n] = i

        out: List[str] = []
        for ref in refs:
            if not isinstance(ref, str) or "#" not in ref:
                out.append(ref)
                continue

            file_part, frag = ref.split("#", 1)
            file_name = file_part.strip()
            frag = frag.strip()

            if frag.startswith("/"):
                out.append(ref)
                continue

            lowered = file_name.lower()

            if lowered.endswith("repositories.json"):
                if frag in name_to_idx:
                    out.append(f"{file_name}#/repositories/{name_to_idx[frag]}")
                elif frag in {"all_repositories", "repositories"}:
                    out.append(f"{file_name}#/repositories")
                else:
                    out.append(ref)
                continue

            if lowered.endswith("registry.json"):
                if frag in {"registry", "registry_policy", "registry_scanning"}:
                    out.append(f"{file_name}#/{frag}")
                else:
                    out.append(ref)
                continue

            out.append(ref)

        return out


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("ECR-"):
            return None

        # ECR: Public wildcard principals (ECR-001)
        # Only valid when at least one repository policy explicitly allows wildcard principals.
        if finding_id == "ECR-001":
            repos_doc = self.evidence.get("repositories")
            if not isinstance(repos_doc, dict):
                repos_doc = {}
            repos_list = repos_doc.get("repositories", [])

            has_wildcard = False
            for r in repos_list if isinstance(repos_list, list) else []:
                if not isinstance(r, dict):
                    continue
                policy = r.get("Policy")
                if not isinstance(policy, dict):
                    continue
                for st in policy.get("Statement", []) or []:
                    if not isinstance(st, dict) or st.get("Effect") != "Allow":
                        continue
                    principal = st.get("Principal")
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        has_wildcard = True
                        break
                if has_wildcard:
                    break

            if not has_wildcard:
                logger.warning(
                    f"Rejected {finding_id} - No wildcard Principal '*' found in ECR repository policies."
                )
                return False

        # ECR: Image scanning on push should be enabled (ECR-003)
        # Guard against false positives when registry scanning is ENHANCED and already covers the repo.
        # In ENHANCED mode (Inspector integration), vulnerability scanning can be continuous at the
        # registry level, so per-repo scanOnPush=false is not necessarily a security gap.
        if finding_id == "ECR-003":
            reg_doc = self.evidence.get("registry")
            reg_scanning = None
            if isinstance(reg_doc, dict):
                reg_scanning = reg_doc.get("registry_scanning")

            scan_cfg = None
            if isinstance(reg_scanning, dict):
                scan_cfg = reg_scanning.get("scanningConfiguration")

            if isinstance(scan_cfg, dict) and scan_cfg.get("scanType") == "ENHANCED":
                repo_name: Optional[str] = None
                snippet = finding.evidence_snippet
                if isinstance(snippet, dict):
                    snippet_d = cast(Dict[str, Any], snippet)
                    repo_name = snippet_d.get("RepositoryName")

                if not repo_name:
                    for arn in finding.affected_resources or []:
                        if not isinstance(arn, str):
                            continue
                        marker = ":repository/"
                        if marker in arn:
                            # Repository names can include slashes; keep the full suffix.
                            repo_name = arn.split(marker, 1)[1]
                            break

                def _repo_filter_matches(repo: str, rf: Dict[str, Any]) -> bool:
                    pattern = rf.get("filter")
                    ftype = rf.get("filterType")
                    if not isinstance(pattern, str):
                        return False
                    if pattern == "*":
                        return True
                    if ftype == "PREFIX_MATCH":
                        return repo.startswith(pattern)
                    # Default to wildcard semantics (AWS uses WILDCARD in evidence)
                    return fnmatch.fnmatchcase(repo, pattern)

                if repo_name:
                    rules = scan_cfg.get("rules")
                    if isinstance(rules, list):
                        for rule in rules:
                            if not isinstance(rule, dict):
                                continue
                            freq = rule.get("scanFrequency")
                            if freq not in {"CONTINUOUS_SCAN", "SCAN_ON_PUSH"}:
                                continue

                            repo_filters = rule.get("repositoryFilters")
                            # Conservative: if filters are missing/invalid, we can't conclude coverage.
                            if not isinstance(repo_filters, list) or not repo_filters:
                                continue

                            if any(
                                isinstance(rf, dict) and _repo_filter_matches(repo_name, rf)
                                for rf in repo_filters
                            ):
                                logger.warning(
                                    f"Rejected {finding_id} - Registry ENHANCED scanning ({freq}) covers repository '{repo_name}'."
                                )
                                return False

        # ECR: Cross-account repository access review (ECR-007)
        # Only valid when there is explicit cross-account principal(s) present.
        if finding_id == "ECR-007":
            repos_doc = self.evidence.get("repositories", {})
            repos_list = repos_doc.get("repositories", []) if isinstance(repos_doc, dict) else []

            # Determine current account from registry evidence or repository ARN.
            current_account: Optional[str] = None
            reg_doc = self.evidence.get("registry")
            if isinstance(reg_doc, dict):
                reg = reg_doc.get("registry")
                if isinstance(reg, dict) and reg.get("registryId"):
                    current_account = str(reg.get("registryId"))

            if not current_account and isinstance(repos_list, list):
                for r in repos_list:
                    if isinstance(r, dict) and r.get("RepositoryArn"):
                        arn = str(r.get("RepositoryArn"))
                        parts = arn.split(":")
                        if len(parts) > 4:
                            current_account = parts[4]
                            break

            def _extract_accounts(principal_aws: Any) -> List[str]:
                out: List[str] = []
                if isinstance(principal_aws, str):
                    out.append(principal_aws)
                elif isinstance(principal_aws, list):
                    out.extend([str(x) for x in principal_aws if x is not None])
                return out

            has_cross_account = False
            for r in repos_list if isinstance(repos_list, list) else []:
                if not isinstance(r, dict):
                    continue
                policy = r.get("Policy")
                if not isinstance(policy, dict):
                    continue
                for st in policy.get("Statement", []) or []:
                    if not isinstance(st, dict) or st.get("Effect") != "Allow":
                        continue
                    principal = st.get("Principal")
                    if principal == "*" or (
                        isinstance(principal, dict) and principal.get("AWS") == "*"
                    ):
                        # Wildcard implies cross-account risk as well.
                        has_cross_account = True
                        break
                    if isinstance(principal, dict) and "AWS" in principal:
                        for aws_p in _extract_accounts(principal.get("AWS")):
                            if current_account and current_account in aws_p:
                                continue
                            # Capture numeric account IDs or ARNs for other accounts.
                            if aws_p.isdigit() and (
                                not current_account or aws_p != current_account
                            ):
                                has_cross_account = True
                                break
                            if aws_p.startswith("arn:aws:iam::"):
                                # arn:aws:iam::<acct>:role/name
                                acct = aws_p.split(":")[4] if len(aws_p.split(":")) > 4 else ""
                                if acct and (not current_account or acct != current_account):
                                    has_cross_account = True
                                    break
                    if has_cross_account:
                        break
                if has_cross_account:
                    break

            if not has_cross_account:
                logger.warning(
                    f"Rejected {finding_id} - No explicit cross-account principals found in repository policies."
                )
                return False

        # ECR: Registry scanning configuration should be defined (ECR-004)
        # Reject if evidence shows we could not collect registry scanning configuration.
        if finding_id == "ECR-004":
            reg_doc = self.evidence.get("registry")
            if isinstance(reg_doc, dict):
                reg_scanning = reg_doc.get("registry_scanning")
                if isinstance(reg_scanning, dict) and reg_scanning.get("error"):
                    logger.warning(
                        f"Rejected {finding_id} - registry scanning evidence has error: {reg_scanning.get('error')}"
                    )
                    return False
            # If missing entirely, also reject (insufficient evidence)
            else:
                logger.warning(
                    f"Rejected {finding_id} - missing registry evidence; cannot verify registry scanning configuration."
                )
                return False

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
