"""ECR security audit skill.

Collects evidence about Amazon ECR repositories and registry configuration.
Focus: access control, immutability, scanning, encryption, and lifecycle hygiene.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession


class ECRSkill(BaseSkill):
    """Amazon ECR security audit."""

    @property
    def name(self) -> str:
        return "ecr"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        """Collect ECR evidence for the configured region."""
        region = aws_client.region_name
        print(f"  🔍 Scanning ECR in region: {region}...")

        evidence_path = session.get_evidence_path(self.name)
        evidence_path.mkdir(parents=True, exist_ok=True)

        # Session (use same creds as the audit)
        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
        }
        if getattr(aws_client, "session_token", None):
            client_kwargs["aws_session_token"] = aws_client.session_token

        session_obj = boto3.Session(**client_kwargs)
        ecr = session_obj.client("ecr", region_name=region)

        collection_status: Dict[str, Any] = {
            "region": region,
            "ok": True,
            "errors": {},
        }

        # === Registry-level configuration ===
        registry: Dict[str, Any] = {
            "region": region,
            "registry": {},
            "registry_policy": None,
            "registry_scanning": None,
        }

        try:
            registry["registry"] = ecr.describe_registry()
        except Exception as e:
            collection_status["ok"] = False
            collection_status["errors"]["describe_registry"] = str(e)
            registry["registry"] = {"error": str(e)}

        try:
            rp = ecr.get_registry_policy()
            # policyText is a JSON string
            registry["registry_policy"] = {
                "registryId": rp.get("registryId"),
                "policyText": json.loads(rp.get("policyText", "{}")),
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            if code not in {"RegistryPolicyNotFoundException", "AccessDeniedException"}:
                collection_status["ok"] = False
            collection_status["errors"]["get_registry_policy"] = code
            registry["registry_policy"] = {"error": code}
        except Exception as e:
            collection_status["ok"] = False
            collection_status["errors"]["get_registry_policy"] = str(e)
            registry["registry_policy"] = {"error": str(e)}

        try:
            # boto3/botocore expose this as either:
            # - get_registry_scanning_configuration (Operation: GetRegistryScanningConfiguration)
            # - describe_registry_scanning_configuration (older docs, not always present in SDK)
            if hasattr(ecr, "describe_registry_scanning_configuration"):
                registry["registry_scanning"] = ecr.describe_registry_scanning_configuration()
            elif hasattr(ecr, "get_registry_scanning_configuration"):
                registry["registry_scanning"] = ecr.get_registry_scanning_configuration()
            else:
                code = "UnsupportedOperationInSDK"
                collection_status["errors"]["registry_scanning_configuration"] = code
                registry["registry_scanning"] = {"error": code}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            collection_status["errors"]["registry_scanning_configuration"] = code
            registry["registry_scanning"] = {"error": code}
        except AttributeError:
            code = "UnsupportedOperationInSDK"
            collection_status["errors"]["registry_scanning_configuration"] = code
            registry["registry_scanning"] = {"error": code}
        except Exception as e:
            collection_status["errors"]["registry_scanning_configuration"] = str(e)
            registry["registry_scanning"] = {"error": str(e)}

        # === Repository-level evidence ===
        repositories: List[Dict[str, Any]] = []
        try:
            paginator = ecr.get_paginator("describe_repositories")
            for page in paginator.paginate():
                for repo in page.get("repositories", []) or []:
                    repo_name = repo.get("repositoryName")
                    repo_arn = repo.get("repositoryArn")

                    policy_obj: Optional[Dict[str, Any]] = None
                    lifecycle_obj: Optional[Dict[str, Any]] = None
                    tags: List[Dict[str, Any]] = []

                    # Repo policy (may not exist)
                    is_public = False
                    try:
                        pr = ecr.get_repository_policy(repositoryName=repo_name)
                        policy_obj = json.loads(pr.get("policyText", "{}"))
                        is_public = self._policy_allows_public(policy_obj)
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "Unknown")
                        if code != "RepositoryPolicyNotFoundException":
                            collection_status["errors"].setdefault("repo_policy_errors", []).append(
                                {"repository": repo_name, "error": code}
                            )
                    except Exception as e:
                        collection_status["errors"].setdefault("repo_policy_errors", []).append(
                            {"repository": repo_name, "error": str(e)}
                        )

                    # Lifecycle policy (may not exist)
                    has_lifecycle = False
                    try:
                        lr = ecr.get_lifecycle_policy(repositoryName=repo_name)
                        lifecycle_obj = json.loads(lr.get("lifecyclePolicyText", "{}"))
                        has_lifecycle = True
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "Unknown")
                        if code != "LifecyclePolicyNotFoundException":
                            collection_status["errors"].setdefault(
                                "lifecycle_policy_errors", []
                            ).append({"repository": repo_name, "error": code})
                    except Exception as e:
                        collection_status["errors"].setdefault(
                            "lifecycle_policy_errors", []
                        ).append({"repository": repo_name, "error": str(e)})

                    # Tags (optional)
                    try:
                        if repo_arn:
                            tr = ecr.list_tags_for_resource(resourceArn=repo_arn)
                            tags = tr.get("tags", []) or []
                    except Exception:
                        tags = []

                    repositories.append(
                        {
                            "Region": region,
                            "RepositoryName": repo_name,
                            "RepositoryArn": repo_arn,
                            "CreatedAt": str(repo.get("createdAt", "")),
                            "ImageTagMutability": repo.get("imageTagMutability"),
                            "ScanOnPush": (
                                (repo.get("imageScanningConfiguration") or {}).get(
                                    "scanOnPush", False
                                )
                            ),
                            "EncryptionType": (
                                (repo.get("encryptionConfiguration") or {}).get("encryptionType")
                            ),
                            "KmsKey": ((repo.get("encryptionConfiguration") or {}).get("kmsKey")),
                            "Policy": policy_obj,
                            "IsPublic": is_public,
                            "LifecyclePolicy": lifecycle_obj,
                            "HasLifecyclePolicy": has_lifecycle,
                            "Tags": tags,
                        }
                    )

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            collection_status["ok"] = False
            collection_status["errors"]["describe_repositories"] = code
        except Exception as e:
            collection_status["ok"] = False
            collection_status["errors"]["describe_repositories"] = str(e)

        # === AUDIT METADATA ===
        audit_metadata = {
            "_region": region,
            "_timestamp": datetime.utcnow().isoformat() + "Z",
            "_scope": "single-region",
            "_skill": self.name,
        }

        self._save_json(evidence_path / "_audit_metadata.json", audit_metadata)
        self._save_json(evidence_path / "registry.json", registry)
        self._save_json(evidence_path / "repositories.json", {"repositories": repositories})
        self._save_json(evidence_path / "ecr-collection-status.json", collection_status)

        print(f"  ✅ Found {len(repositories)} repositories")

    def _policy_allows_public(self, policy: Optional[Dict[str, Any]]) -> bool:
        """Return True if a resource policy allows wildcard principals."""
        if not isinstance(policy, dict):
            return False
        for stmt in policy.get("Statement", []) or []:
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            if principal == "*":
                return True
            if isinstance(principal, dict) and principal.get("AWS") == "*":
                return True
        return False

    def _save_json(self, filepath: Path, data: Any) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["ECRSkill"]
