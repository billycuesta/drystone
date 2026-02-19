"""Compute security audit skill (ECS/EKS/EC2/Lambda).

Collects evidence about:
- ECS: clusters, services, task definitions, and running tasks (labels)
- EventBridge: rules/targets relevant for ECS scheduled execution
- EKS: clusters and nodegroups (endpoint exposure + logging posture)
- EC2: metadata posture + user-data risk indicators
- Lambda: function URLs + execution role policy posture

Goal: enable pentest-oriented correlations around persistence and workload
attack surface without performing active exploitation.
"""

from __future__ import annotations

import base64
import json
import re
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


class ComputeSkill(BaseSkill):
    @property
    def name(self) -> str:
        return "compute"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        region = aws_client.region_name
        print(f"  🔍 Scanning Compute (ECS/EKS) in region: {region}...")

        evidence_path = session.get_evidence_path(self.name)
        evidence_path.mkdir(parents=True, exist_ok=True)

        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
        }
        if getattr(aws_client, "session_token", None):
            client_kwargs["aws_session_token"] = aws_client.session_token

        session_obj = boto3.Session(**client_kwargs)
        ecs = session_obj.client("ecs", region_name=region)
        eks = session_obj.client("eks", region_name=region)
        events = session_obj.client("events", region_name=region)

        metadata = {
            "_collected_at": datetime.utcnow().isoformat() + "Z",
            "_region": region,
            "_skill": self.name,
        }
        self._save_json(evidence_path / "_audit_metadata.json", metadata)

        ecs_out, ecs_errors = self._collect_ecs(ecs)
        self._save_json(evidence_path / "ecs-inventory.json", ecs_out)
        self._save_json(evidence_path / "ecs-errors.json", ecs_errors)

        ev_out, ev_errors = self._collect_eventbridge(events)
        self._save_json(evidence_path / "eventbridge-rules.json", ev_out)
        self._save_json(evidence_path / "eventbridge-errors.json", ev_errors)

        eks_out, eks_errors = self._collect_eks(eks)
        self._save_json(evidence_path / "eks-inventory.json", eks_out)
        self._save_json(evidence_path / "eks-errors.json", eks_errors)

        ec2_out, ec2_errors = self._collect_ec2(session_obj.client("ec2", region_name=region))
        self._save_json(evidence_path / "ec2-inventory.json", ec2_out)
        self._save_json(evidence_path / "ec2-errors.json", ec2_errors)

        lambda_out, lambda_errors = self._collect_lambda(
            session_obj.client("lambda", region_name=region),
            session_obj.client("iam", region_name=region),
        )
        self._save_json(evidence_path / "lambda-inventory.json", lambda_out)
        self._save_json(evidence_path / "lambda-errors.json", lambda_errors)

        ok = not (ecs_errors or ev_errors or eks_errors or ec2_errors or lambda_errors)
        logger.info(
            "Compute collection complete",
            extra={
                "region": region,
                "ecs_clusters": len(ecs_out.get("clusters", [])),
                "eks_clusters": len(eks_out.get("clusters", [])),
                "ec2_instances": len(ec2_out.get("instances", [])),
                "lambda_functions": len(lambda_out.get("functions", [])),
                "ok": ok,
            },
        )

    def _scan_for_secrets(self, text: str) -> Dict[str, bool]:
        patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws(.{0,20})?(secret|access).{0,10}[=:]\s*[A-Za-z0-9/+=]{30,}",
            "password": r"(?i)password\s*[=:]\s*[^\s\"']+",
            "api_key": r"(?i)api[_-]?key\s*[=:]\s*[^\s\"']+",
            "token": r"(?i)(token|secret)\s*[=:]\s*[^\s\"']+",
        }
        return {name: bool(re.search(pattern, text)) for name, pattern in patterns.items()}

    def _collect_ec2(self, ec2) -> Tuple[Dict[str, Any], Dict[str, str]]:
        out: Dict[str, Any] = {"instances": []}
        errors: Dict[str, str] = {}

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []) or []:
                    for instance in reservation.get("Instances", []) or []:
                        iid = instance.get("InstanceId")
                        if not iid:
                            continue
                        item: Dict[str, Any] = {
                            "InstanceId": iid,
                            "State": (instance.get("State") or {}).get("Name"),
                            "IamInstanceProfile": instance.get("IamInstanceProfile"),
                            "MetadataOptions": instance.get("MetadataOptions") or {},
                            "SecurityGroups": instance.get("SecurityGroups", []),
                        }

                        try:
                            attr = ec2.describe_instance_attribute(
                                InstanceId=iid, Attribute="userData"
                            )
                            raw = ((attr or {}).get("UserData") or {}).get("Value")
                            decoded = ""
                            if raw:
                                try:
                                    decoded = base64.b64decode(raw).decode(
                                        "utf-8", errors="replace"
                                    )
                                except Exception:
                                    decoded = str(raw)
                            item["UserData"] = decoded
                            item["ContainsSecrets"] = (
                                self._scan_for_secrets(decoded) if decoded else {}
                            )
                            ldec = decoded.lower() if decoded else ""
                            item["HasRemoteBootstrap"] = "curl " in ldec or "wget " in ldec
                        except Exception as e:
                            errors[f"describe_instance_attribute:{iid}"] = str(e)

                        out["instances"].append(item)
        except ClientError as e:
            errors["describe_instances"] = e.response.get("Error", {}).get("Code", "Unknown")
        except Exception as e:
            errors["describe_instances"] = str(e)

        return out, errors

    def _collect_lambda(self, lam, iam) -> Tuple[Dict[str, Any], Dict[str, str]]:
        out: Dict[str, Any] = {"functions": []}
        errors: Dict[str, str] = {}

        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []) or []:
                    fn_name = fn.get("FunctionName")
                    if not fn_name:
                        continue
                    role_arn = fn.get("Role")
                    role_name = (
                        role_arn.split("/")[-1]
                        if isinstance(role_arn, str) and "/" in role_arn
                        else None
                    )
                    item: Dict[str, Any] = {
                        "FunctionName": fn_name,
                        "FunctionArn": fn.get("FunctionArn"),
                        "Role": role_arn,
                    }

                    try:
                        cfg = lam.get_function_url_config(FunctionName=fn_name)
                        item["FunctionUrl"] = cfg.get("FunctionUrl")
                        item["AuthType"] = cfg.get("AuthType")
                    except ClientError:
                        item["FunctionUrl"] = None
                        item["AuthType"] = None
                    except Exception as e:
                        errors[f"get_function_url_config:{fn_name}"] = str(e)

                    attached = []
                    if role_name:
                        try:
                            attached = iam.list_attached_role_policies(RoleName=role_name).get(
                                "AttachedPolicies", []
                            )
                        except Exception as e:
                            errors[f"list_attached_role_policies:{role_name}"] = str(e)

                    item["AttachedPolicies"] = attached
                    out["functions"].append(item)
        except ClientError as e:
            errors["list_functions"] = e.response.get("Error", {}).get("Code", "Unknown")
        except Exception as e:
            errors["list_functions"] = str(e)

        return out, errors

    def _collect_ecs(self, ecs) -> Tuple[Dict[str, Any], Dict[str, str]]:
        out: Dict[str, Any] = {"clusters": [], "services": [], "tasks": [], "task_definitions": []}
        errors: Dict[str, str] = {}

        cluster_arns: List[str] = []
        try:
            paginator = ecs.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_arns.extend(page.get("clusterArns", []) or [])
        except ClientError as e:
            errors["list_clusters"] = e.response.get("Error", {}).get("Code", "Unknown")
            return out, errors
        except Exception as e:
            errors["list_clusters"] = str(e)
            return out, errors

        if cluster_arns:
            try:
                desc = ecs.describe_clusters(clusters=cluster_arns).get("clusters", []) or []
                out["clusters"] = desc
            except Exception as e:
                errors["describe_clusters"] = str(e)

        # Services + tasks per cluster (labels)
        for c_arn in cluster_arns:
            # Services
            try:
                svc_arns: List[str] = []
                p = ecs.get_paginator("list_services")
                for page in p.paginate(cluster=c_arn):
                    svc_arns.extend(page.get("serviceArns", []) or [])

                for i in range(0, len(svc_arns), 10):
                    batch = svc_arns[i : i + 10]
                    if not batch:
                        continue
                    resp = ecs.describe_services(cluster=c_arn, services=batch)
                    out["services"].extend(resp.get("services", []) or [])
            except ClientError as e:
                errors[f"list/describe_services:{c_arn}"] = e.response.get("Error", {}).get(
                    "Code", "Unknown"
                )
            except Exception as e:
                errors[f"list/describe_services:{c_arn}"] = str(e)

            # Tasks (labels)
            try:
                task_arns: List[str] = []
                p = ecs.get_paginator("list_tasks")
                for page in p.paginate(cluster=c_arn, desiredStatus="RUNNING"):
                    task_arns.extend(page.get("taskArns", []) or [])

                for i in range(0, len(task_arns), 100):
                    batch = task_arns[i : i + 100]
                    if not batch:
                        continue
                    resp = ecs.describe_tasks(cluster=c_arn, tasks=batch)
                    out["tasks"].extend(resp.get("tasks", []) or [])
            except ClientError as e:
                errors[f"list/describe_tasks:{c_arn}"] = e.response.get("Error", {}).get(
                    "Code", "Unknown"
                )
            except Exception as e:
                errors[f"list/describe_tasks:{c_arn}"] = str(e)

        # Task definitions (best-effort, potentially large)
        try:
            td_arns: List[str] = []
            p = ecs.get_paginator("list_task_definitions")
            for page in p.paginate(sort="DESC"):
                td_arns.extend(page.get("taskDefinitionArns", []) or [])

            # Cap to avoid massive evidence; keep most recent 100.
            td_arns = td_arns[:100]
            for td_arn in td_arns:
                try:
                    resp = ecs.describe_task_definition(taskDefinition=td_arn)
                    out["task_definitions"].append(resp.get("taskDefinition", {}))
                except Exception as e:
                    errors[f"describe_task_definition:{td_arn}"] = str(e)
        except ClientError as e:
            errors["list_task_definitions"] = e.response.get("Error", {}).get("Code", "Unknown")
        except Exception as e:
            errors["list_task_definitions"] = str(e)

        return out, errors

    def _collect_eventbridge(self, events) -> Tuple[Dict[str, Any], Dict[str, str]]:
        out: Dict[str, Any] = {"rules": []}
        errors: Dict[str, str] = {}

        # Collect all rules; tag ECS-related targets in post-processing via targets listing.
        try:
            p = events.get_paginator("list_rules")
            for page in p.paginate():
                out["rules"].extend(page.get("Rules", []) or [])
        except ClientError as e:
            errors["list_rules"] = e.response.get("Error", {}).get("Code", "Unknown")
            return out, errors
        except Exception as e:
            errors["list_rules"] = str(e)
            return out, errors

        # Attach targets for each rule (capped)
        for rule in out["rules"][:200]:
            name = rule.get("Name")
            if not name:
                continue
            try:
                targets = events.list_targets_by_rule(Rule=name).get("Targets", []) or []
                rule["Targets"] = targets
            except ClientError as e:
                errors[f"list_targets_by_rule:{name}"] = e.response.get("Error", {}).get(
                    "Code", "Unknown"
                )
            except Exception as e:
                errors[f"list_targets_by_rule:{name}"] = str(e)

        return out, errors

    def _collect_eks(self, eks) -> Tuple[Dict[str, Any], Dict[str, str]]:
        out: Dict[str, Any] = {"clusters": [], "nodegroups": []}
        errors: Dict[str, str] = {}

        clusters: List[str] = []
        try:
            p = eks.get_paginator("list_clusters")
            for page in p.paginate():
                clusters.extend(page.get("clusters", []) or [])
        except ClientError as e:
            errors["list_clusters"] = e.response.get("Error", {}).get("Code", "Unknown")
            return out, errors
        except Exception as e:
            errors["list_clusters"] = str(e)
            return out, errors

        for name in clusters:
            try:
                c = eks.describe_cluster(name=name).get("cluster", {})
                out["clusters"].append(c)
            except ClientError as e:
                errors[f"describe_cluster:{name}"] = e.response.get("Error", {}).get(
                    "Code", "Unknown"
                )
            except Exception as e:
                errors[f"describe_cluster:{name}"] = str(e)

            # Nodegroups
            try:
                ngs: List[str] = []
                p = eks.get_paginator("list_nodegroups")
                for page in p.paginate(clusterName=name):
                    ngs.extend(page.get("nodegroups", []) or [])
                for ng in ngs:
                    try:
                        d = eks.describe_nodegroup(clusterName=name, nodegroupName=ng).get(
                            "nodegroup", {}
                        )
                        out["nodegroups"].append(d)
                    except Exception as e:
                        errors[f"describe_nodegroup:{name}:{ng}"] = str(e)
            except ClientError as e:
                errors[f"list_nodegroups:{name}"] = e.response.get("Error", {}).get(
                    "Code", "Unknown"
                )
            except Exception as e:
                errors[f"list_nodegroups:{name}"] = str(e)

        return out, errors

    def _save_json(self, filepath: Path, data: Any) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
