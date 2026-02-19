"""KMS security audit skill.

Collects evidence about AWS KMS keys, key policies, and grants.
Focus: key policy exposure, grant abuse, and privesc/persistence potential.
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


class KMSSkill(BaseSkill):
    """AWS KMS audit skill."""

    @property
    def name(self) -> str:
        return "kms"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        region = aws_client.region_name
        print(f"  🔍 Scanning KMS in region: {region}...")

        evidence_path = session.get_evidence_path(self.name)
        evidence_path.mkdir(parents=True, exist_ok=True)

        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
        }
        if getattr(aws_client, "session_token", None):
            client_kwargs["aws_session_token"] = aws_client.session_token

        session_obj = boto3.Session(**client_kwargs)
        kms = session_obj.client("kms", region_name=region)

        metadata = {
            "_collected_at": datetime.utcnow().isoformat() + "Z",
            "_region": region,
            "_skill": self.name,
        }
        self._save_json(evidence_path / "_audit_metadata.json", metadata)

        keys, key_errors = self._collect_keys(kms)
        self._save_json(evidence_path / "kms-keys.json", {"items": keys, "errors": key_errors})

        policies, policy_errors = self._collect_key_policies(kms, keys)
        self._save_json(
            evidence_path / "kms-key-policies.json",
            {"items": policies, "errors": policy_errors},
        )

        grants, grant_errors = self._collect_grants(kms, keys)
        self._save_json(
            evidence_path / "kms-grants.json",
            {"items": grants, "errors": grant_errors},
        )

        aliases, alias_errors = self._collect_aliases(kms)
        self._save_json(
            evidence_path / "kms-aliases.json",
            {"items": aliases, "errors": alias_errors},
        )

        custom_stores, custom_store_errors = self._collect_custom_key_stores(kms)
        self._save_json(
            evidence_path / "kms-custom-key-stores.json",
            {"items": custom_stores, "errors": custom_store_errors},
        )

        ok = not (
            key_errors or policy_errors or grant_errors or alias_errors or custom_store_errors
        )
        logger.info(
            "KMS collection complete",
            extra={
                "region": region,
                "keys": len(keys),
                "policies": len(policies),
                "grants": len(grants),
                "aliases": len(aliases),
                "custom_key_stores": len(custom_stores),
                "ok": ok,
            },
        )

    def _collect_keys(self, kms) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        keys: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for k in page.get("Keys", []) or []:
                    key_id = k.get("KeyId")
                    if not key_id:
                        continue
                    try:
                        desc = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                        rotation_enabled = None
                        try:
                            rotation_enabled = kms.get_key_rotation_status(KeyId=key_id).get(
                                "KeyRotationEnabled"
                            )
                        except ClientError as e:
                            # Not all keys support rotation; keep as metadata.
                            code_rot = e.response.get("Error", {}).get("Code", "Unknown")
                            errors[f"get_key_rotation_status:{key_id}"] = code_rot

                        keys.append(
                            {
                                "KeyId": key_id,
                                "KeyArn": k.get("KeyArn"),
                                "Metadata": desc,
                                "KeyRotationEnabled": rotation_enabled,
                            }
                        )
                    except ClientError as e:
                        code = e.response.get("Error", {}).get("Code", "Unknown")
                        errors[f"describe_key:{key_id}"] = code
                        keys.append(
                            {
                                "KeyId": key_id,
                                "KeyArn": k.get("KeyArn"),
                                "Metadata": {"error": code},
                                "KeyRotationEnabled": None,
                            }
                        )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            errors["list_keys"] = code
        except Exception as e:
            errors["list_keys"] = str(e)
        return keys, errors

    def _collect_key_policies(
        self, kms, keys: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}

        for k in keys:
            key_id = k.get("KeyId")
            if not key_id:
                continue

            policy_names: List[str] = []
            try:
                resp = kms.list_key_policies(KeyId=key_id)
                policy_names = resp.get("PolicyNames", []) or []
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                errors[f"list_key_policies:{key_id}"] = code
                continue

            for policy_name in policy_names:
                try:
                    p = kms.get_key_policy(KeyId=key_id, PolicyName=policy_name).get("Policy", "")
                    policy_obj: Any
                    try:
                        policy_obj = json.loads(p) if p else {}
                    except Exception:
                        policy_obj = {"raw": p}
                    items.append(
                        {
                            "KeyId": key_id,
                            "PolicyName": policy_name,
                            "Policy": policy_obj,
                        }
                    )
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "Unknown")
                    errors[f"get_key_policy:{key_id}:{policy_name}"] = code

        return items, errors

    def _collect_grants(
        self, kms, keys: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}

        for k in keys:
            key_id = k.get("KeyId")
            if not key_id:
                continue
            try:
                paginator = kms.get_paginator("list_grants")
                for page in paginator.paginate(KeyId=key_id):
                    for g in page.get("Grants", []) or []:
                        items.append({"KeyId": key_id, **g})
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                # AccessDenied is common; keep as error but don't crash.
                errors[f"list_grants:{key_id}"] = code
            except Exception as e:
                errors[f"list_grants:{key_id}"] = str(e)

        return items, errors

    def _save_json(self, filepath: Path, data: Any) -> None:
        """Save JSON evidence to disk."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _collect_aliases(self, kms) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}
        try:
            paginator = kms.get_paginator("list_aliases")
            for page in paginator.paginate():
                for a in page.get("Aliases", []) or []:
                    items.append(a)
        except ClientError as e:
            errors["list_aliases"] = e.response.get("Error", {}).get("Code", "Unknown")
        except Exception as e:
            errors["list_aliases"] = str(e)
        return items, errors

    def _collect_custom_key_stores(self, kms) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        items: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}
        try:
            paginator = kms.get_paginator("describe_custom_key_stores")
            for page in paginator.paginate():
                for cks in page.get("CustomKeyStores", []) or []:
                    items.append(cks)
        except ClientError as e:
            errors["describe_custom_key_stores"] = e.response.get("Error", {}).get(
                "Code", "Unknown"
            )
        except Exception as e:
            errors["describe_custom_key_stores"] = str(e)
        return items, errors
