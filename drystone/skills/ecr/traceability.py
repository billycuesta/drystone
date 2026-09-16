"""ECR (ECR-002, ECR-005, ECR-006) pre-check traceability.

Extracted verbatim from BaseSkill._build_precheck_traceability (P1 #2, 2026-09-16).
"""

from typing import Any, Dict, List, Optional


def build_traceability(
    check_id: str, result: Any, evidence: Dict[str, Any]
) -> "Optional[tuple[List[str], Optional[Dict[str, Any]]]]":
    if check_id not in {"ECR-002", "ECR-005", "ECR-006"}:
        return None

    repos_doc = evidence.get("repositories")
    repos = repos_doc.get("repositories") if isinstance(repos_doc, dict) else None
    if not isinstance(repos, list):
        return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}

    affected = set(str(r) for r in (getattr(result, "affected_resources", []) or []))

    matched = []
    refs: List[str] = []
    for idx, repo in enumerate(repos):
        if not isinstance(repo, dict):
            continue
        arn = str(repo.get("RepositoryArn") or "")
        name = str(repo.get("RepositoryName") or "")
        name_like = f"repository/{name}" if name else ""
        if affected and arn not in affected and (name_like not in affected):
            continue

        refs.append(f"repositories.json#/repositories/{idx}")
        if check_id == "ECR-002":
            matched.append(
                {
                    "RepositoryName": repo.get("RepositoryName"),
                    "RepositoryArn": repo.get("RepositoryArn"),
                    "ImageTagMutability": repo.get("ImageTagMutability"),
                }
            )
        elif check_id == "ECR-005":
            matched.append(
                {
                    "RepositoryName": repo.get("RepositoryName"),
                    "RepositoryArn": repo.get("RepositoryArn"),
                    "EncryptionType": repo.get("EncryptionType"),
                    "KmsKey": repo.get("KmsKey"),
                }
            )
        elif check_id == "ECR-006":
            matched.append(
                {
                    "RepositoryName": repo.get("RepositoryName"),
                    "RepositoryArn": repo.get("RepositoryArn"),
                    "HasLifecyclePolicy": repo.get("HasLifecyclePolicy"),
                    "LifecyclePolicy": repo.get("LifecyclePolicy"),
                }
            )

    if refs and matched:
        snippet = {"repositories": matched[:10]}
        return refs[:10], snippet

    return [], {"evidence_summary": getattr(result, "evidence_summary", "pre-check fail")}
