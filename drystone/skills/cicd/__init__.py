"""CI/CD security audit skill (CodeBuild-focused).

Collects evidence about AWS CodeBuild projects and configured source credentials.

Focus: token leakage paths (source credentials), insecure SSL, and proxy-based
interception configurations (HackTricks Cloud AWS).
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

logger = get_logger(__name__)


class CICDSkill(BaseSkill):
    @property
    def name(self) -> str:
        return "cicd"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        region = aws_client.region_name
        print(f"  🔍 Scanning CI/CD (CodeBuild) in region: {region}...")

        evidence_path = session.get_evidence_path(self.name)
        evidence_path.mkdir(parents=True, exist_ok=True)

        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
        }
        if getattr(aws_client, "session_token", None):
            client_kwargs["aws_session_token"] = aws_client.session_token

        session_obj = boto3.Session(**client_kwargs)
        codebuild = session_obj.client("codebuild", region_name=region)

        metadata = {
            "_collected_at": datetime.utcnow().isoformat() + "Z",
            "_region": region,
            "_skill": self.name,
        }
        self._save_json(evidence_path / "_audit_metadata.json", metadata)

        projects, proj_errors = self._collect_codebuild_projects(codebuild)
        self._save_json(
            evidence_path / "codebuild-projects.json",
            {"items": projects, "errors": proj_errors},
        )

        creds, cred_errors = self._collect_source_credentials(codebuild)
        self._save_json(
            evidence_path / "codebuild-source-credentials.json",
            {"items": creds, "errors": cred_errors},
        )

        ok = not (proj_errors or cred_errors)
        logger.info(
            "CI/CD collection complete",
            extra={
                "region": region,
                "projects": len(projects),
                "source_credentials": len(creds),
                "ok": ok,
            },
        )

    def _collect_codebuild_projects(self, codebuild) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}

        try:
            paginator = codebuild.get_paginator("list_projects")
            names: List[str] = []
            for page in paginator.paginate():
                names.extend(page.get("projects", []) or [])

            # Batch get details (max 100 per call)
            for i in range(0, len(names), 100):
                batch = names[i : i + 100]
                if not batch:
                    continue
                try:
                    resp = codebuild.batch_get_projects(names=batch)
                    for p in resp.get("projects", []) or []:
                        items.append(self._minimize_project(p))
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    errors[f"batch_get_projects:{i}"] = code

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            errors["list_projects"] = code
        except Exception as e:
            errors["list_projects"] = str(e)

        return items, errors

    def _collect_source_credentials(self, codebuild) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}

        try:
            resp = codebuild.list_source_credentials()
            for sc in resp.get("sourceCredentialsInfos", []) or []:
                if not isinstance(sc, dict):
                    continue
                # Intentionally do NOT retrieve token material.
                items.append(
                    {
                        "arn": sc.get("arn"),
                        "serverType": sc.get("serverType"),
                        "authType": sc.get("authType"),
                        "resource": sc.get("resource"),
                        "createdAt": str(sc.get("createdAt", "")),
                    }
                )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            errors["list_source_credentials"] = code
        except Exception as e:
            errors["list_source_credentials"] = str(e)

        return items, errors

    def _minimize_project(self, p: Dict[str, Any]) -> Dict[str, Any]:
        source = p.get("source") if isinstance(p.get("source"), dict) else {}
        env = p.get("environment") if isinstance(p.get("environment"), dict) else {}
        svc_role = p.get("serviceRole")

        env_vars = (
            env.get("environmentVariables")
            if isinstance(env.get("environmentVariables"), list)
            else []
        )
        env_vars_min = []
        for ev in env_vars:
            if not isinstance(ev, dict):
                continue
            name = ev.get("name")
            val = ev.get("value")
            # Do not persist full values that may contain secrets; keep only key and simple risk flags.
            env_vars_min.append(
                {
                    "name": name,
                    "type": ev.get("type"),
                    "has_value": bool(val),
                    "looks_like_proxy": isinstance(val, str)
                    and ("proxy" in str(name).lower() or "proxy" in val.lower()),
                }
            )

        return {
            "name": p.get("name"),
            "arn": p.get("arn"),
            "serviceRole": svc_role,
            "source": {
                "type": source.get("type"),
                "location": source.get("location"),
                "auth": source.get("auth"),
                "insecureSsl": source.get("insecureSsl"),
            },
            "environment": {
                "image": env.get("image"),
                "computeType": env.get("computeType"),
                "privilegedMode": env.get("privilegedMode"),
                "imagePullCredentialsType": env.get("imagePullCredentialsType"),
                "environmentVariables": env_vars_min,
            },
            "artifacts": p.get("artifacts", {}),
        }

    def _save_json(self, filepath: Path, data: Any) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
