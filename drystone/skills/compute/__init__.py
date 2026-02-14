"""Compute security audit skill (ECS/EKS first).

Collects evidence about:
- ECS: clusters, services, task definitions, and running tasks (labels)
- EventBridge: rules/targets relevant for ECS scheduled execution
- EKS: clusters and nodegroups (endpoint exposure + logging posture)

Goal: enable pentest-oriented correlations around persistence and workload
attack surface without performing active exploitation.
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

        ok = not (ecs_errors or ev_errors or eks_errors)
        logger.info(
            "Compute collection complete",
            extra={
                "region": region,
                "ecs_clusters": len(ecs_out.get("clusters", [])),
                "eks_clusters": len(eks_out.get("clusters", [])),
                "ok": ok,
            },
        )

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
