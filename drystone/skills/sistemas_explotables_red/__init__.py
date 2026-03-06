"""Sistemas explotables por red skill.

Passive pentest-oriented collection that correlates exposure and exploitability
signals for compute assets (EC2/ECS/Lambda/RDS) without active scanning.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession


class SistemasExplotablesRedSkill(BaseSkill):
    @property
    def name(self) -> str:
        return "sistemas_explotables_red"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        region = aws_client.region_name
        evidence_path = session.get_evidence_path(self.name)

        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": region,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        ec2 = boto3.client("ec2", **client_kwargs)
        elbv2 = boto3.client("elbv2", **client_kwargs)
        lam = boto3.client("lambda", **client_kwargs)
        apigw = boto3.client("apigateway", **client_kwargs)
        apigw2 = boto3.client("apigatewayv2", **client_kwargs)
        ecs = boto3.client("ecs", **client_kwargs)
        rds = boto3.client("rds", **client_kwargs)

        metadata = {
            "_region": region,
            "_timestamp": datetime.now(timezone.utc).isoformat(),
            "_scope": "single-region",
            "_skill": self.name,
            "_account_id": session.account_id,
            "evidence_files": [],
        }

        def _save(filename: str, data: Any) -> None:
            filepath = evidence_path / filename
            self._save_json(filepath, data)
            metadata["evidence_files"].append(filename)

        # compute-inventory.json
        compute_inventory: Dict[str, Any] = {
            "ec2_instances": [],
            "ecs_services": [],
            "lambda_functions": [],
            "rds_instances": [],
        }

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []) or []:
                    for inst in reservation.get("Instances", []) or []:
                        if not isinstance(inst, dict):
                            continue
                        compute_inventory["ec2_instances"].append(
                            {
                                "InstanceId": inst.get("InstanceId"),
                                "VpcId": inst.get("VpcId"),
                                "SubnetId": inst.get("SubnetId"),
                                "State": (inst.get("State") or {}).get("Name"),
                                "PublicIpAddress": inst.get("PublicIpAddress"),
                                "SecurityGroups": inst.get("SecurityGroups", []),
                                "IamInstanceProfile": inst.get("IamInstanceProfile"),
                                "Tags": inst.get("Tags", []),
                            }
                        )
        except Exception:
            pass

        try:
            cluster_arns = ecs.list_clusters().get("clusterArns", []) or []
            for cluster_arn in cluster_arns:
                service_arns = ecs.list_services(cluster=cluster_arn).get("serviceArns", []) or []
                for i in range(0, len(service_arns), 10):
                    chunk = service_arns[i : i + 10]
                    if not chunk:
                        continue
                    services = ecs.describe_services(cluster=cluster_arn, services=chunk).get(
                        "services", []
                    )
                    for svc in services:
                        compute_inventory["ecs_services"].append(
                            {
                                "ClusterArn": cluster_arn,
                                "ServiceArn": svc.get("serviceArn"),
                                "ServiceName": svc.get("serviceName"),
                                "LoadBalancers": svc.get("loadBalancers", []),
                                "NetworkConfiguration": svc.get("networkConfiguration", {}),
                            }
                        )
        except Exception:
            pass

        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []) or []:
                    if not isinstance(fn, dict):
                        continue
                    compute_inventory["lambda_functions"].append(
                        {
                            "FunctionName": fn.get("FunctionName"),
                            "FunctionArn": fn.get("FunctionArn"),
                            "Role": fn.get("Role"),
                            "VpcConfig": fn.get("VpcConfig", {}),
                        }
                    )
        except Exception:
            pass

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []) or []:
                    if not isinstance(db, dict):
                        continue
                    compute_inventory["rds_instances"].append(
                        {
                            "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                            "DBInstanceArn": db.get("DBInstanceArn"),
                            "Engine": db.get("Engine"),
                            "Endpoint": db.get("Endpoint", {}),
                            "PubliclyAccessible": db.get("PubliclyAccessible"),
                            "VpcSecurityGroups": db.get("VpcSecurityGroups", []),
                        }
                    )
        except Exception:
            pass

        _save("compute-inventory.json", compute_inventory)

        # network-controls.json
        network_controls: Dict[str, Any] = {
            "security_groups": [],
            "route_tables": [],
            "network_acls": [],
        }
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                network_controls["security_groups"].extend(page.get("SecurityGroups", []))
        except Exception:
            pass
        try:
            paginator = ec2.get_paginator("describe_route_tables")
            for page in paginator.paginate():
                network_controls["route_tables"].extend(page.get("RouteTables", []))
        except Exception:
            pass
        try:
            paginator = ec2.get_paginator("describe_network_acls")
            for page in paginator.paginate():
                network_controls["network_acls"].extend(page.get("NetworkAcls", []))
        except Exception:
            pass
        _save("network-controls.json", network_controls)

        # front-doors.json
        front_doors: Dict[str, Any] = {
            "load_balancers": [],
            "listeners": [],
            "target_groups": [],
            "lambda_function_urls": [],
            "api_gateway_routes": [],
        }

        lb_arns: List[str] = []
        try:
            marker = None
            while True:
                kwargs = {"PageSize": 400}
                if marker:
                    kwargs["Marker"] = marker
                resp = elbv2.describe_load_balancers(**kwargs)
                lbs = resp.get("LoadBalancers", []) or []
                front_doors["load_balancers"].extend(lbs)
                for lb in lbs:
                    if not isinstance(lb, dict):
                        continue
                    lb_arn = lb.get("LoadBalancerArn")
                    if isinstance(lb_arn, str) and lb_arn:
                        lb_arns.append(lb_arn)
                marker = resp.get("NextMarker")
                if not marker:
                    break
        except Exception:
            pass

        for lb_arn in lb_arns:
            try:
                listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
                for li in listeners:
                    if not isinstance(li, dict):
                        continue
                    li["LoadBalancerArn"] = lb_arn
                    front_doors["listeners"].append(li)
            except Exception:
                continue

            try:
                tgs = elbv2.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
                for tg in tgs:
                    if not isinstance(tg, dict):
                        continue
                    tg["LoadBalancerArn"] = lb_arn
                    front_doors["target_groups"].append(tg)
            except Exception:
                continue

        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []) or []:
                    fn_name = fn.get("FunctionName") if isinstance(fn, dict) else None
                    if not fn_name:
                        continue
                    try:
                        cfg = lam.get_function_url_config(FunctionName=fn_name)
                        front_doors["lambda_function_urls"].append(
                            {
                                "FunctionName": fn_name,
                                "FunctionArn": fn.get("FunctionArn"),
                                "FunctionUrl": cfg.get("FunctionUrl"),
                                "AuthType": cfg.get("AuthType"),
                            }
                        )
                    except ClientError:
                        continue
        except Exception:
            pass

        try:
            rest_apis = apigw.get_rest_apis().get("items", []) or []
            for api in rest_apis:
                api_id = api.get("id") if isinstance(api, dict) else None
                if not api_id:
                    continue
                resources = apigw.get_resources(restApiId=api_id).get("items", []) or []
                for res in resources:
                    methods = res.get("resourceMethods") if isinstance(res, dict) else None
                    if not isinstance(methods, dict):
                        continue
                    for method in methods.keys():
                        try:
                            m = apigw.get_method(
                                restApiId=api_id, resourceId=res.get("id"), httpMethod=method
                            )
                        except ClientError:
                            continue
                        front_doors["api_gateway_routes"].append(
                            {
                                "ApiType": "REST",
                                "ApiId": api_id,
                                "Path": res.get("path"),
                                "Method": method,
                                "AuthorizationType": m.get("authorizationType"),
                                "ApiKeyRequired": bool(m.get("apiKeyRequired")),
                            }
                        )
        except Exception:
            pass

        try:
            apis2 = apigw2.get_apis().get("Items", []) or []
            for api in apis2:
                api_id = api.get("ApiId") if isinstance(api, dict) else None
                if not api_id:
                    continue
                routes = apigw2.get_routes(ApiId=api_id).get("Items", []) or []
                for route in routes:
                    if not isinstance(route, dict):
                        continue
                    route_key = str(route.get("RouteKey") or "")
                    method = route_key.split(" ")[0] if " " in route_key else route_key
                    path = route_key.split(" ", 1)[1] if " " in route_key else ""
                    front_doors["api_gateway_routes"].append(
                        {
                            "ApiType": "HTTP",
                            "ApiId": api_id,
                            "Path": path,
                            "Method": method,
                            "AuthorizationType": route.get("AuthorizationType"),
                            "ApiKeyRequired": False,
                        }
                    )
        except Exception:
            pass

        _save("front-doors.json", front_doors)

        inspector_doc = self._collect_inspector_findings(client_kwargs)
        _save("inspector-findings-normalized.json", inspector_doc)

        account_id = session.account_id or "*"
        reachability_doc, service_hyp_doc = self._build_reachability(
            front_doors=front_doors,
            compute_inventory=compute_inventory,
            region=region,
            account_id=account_id,
        )
        reachability_doc["_meta"] = {"region": region}
        _save("reachability-graph.json", reachability_doc)
        _save("port-service-hypothesis.json", service_hyp_doc)

        attack_paths = self._build_attack_paths(
            reachability_doc=reachability_doc,
            inspector_doc=inspector_doc,
            compute_inventory=compute_inventory,
            region=region,
            account_id=account_id,
        )
        _save("attack-path-candidates.json", {"paths": attack_paths})

        _save("_audit_metadata.json", metadata)

    def _save_json(self, filepath: Path, data: Any) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _collect_inspector_findings(self, client_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        try:
            inspector = boto3.client("inspector2", **client_kwargs)
            token = None
            while True:
                kwargs: Dict[str, Any] = {"maxResults": 100}
                if token:
                    kwargs["nextToken"] = token
                resp = inspector.list_findings(**kwargs)
                batch = resp.get("findings", []) or []
                for f in batch:
                    if not isinstance(f, dict):
                        continue
                    sev = str(f.get("severity") or "").upper()
                    status = str(f.get("status") or "").upper()
                    if sev not in counts or status != "ACTIVE":
                        continue
                    resources = []
                    for r in f.get("resources", []) or []:
                        if not isinstance(r, dict):
                            continue
                        resources.append(
                            {
                                "id": r.get("id"),
                                "type": r.get("type"),
                            }
                        )
                    findings.append(
                        {
                            "findingArn": f.get("findingArn"),
                            "severity": sev,
                            "status": status,
                            "title": f.get("title"),
                            "resources": resources,
                        }
                    )
                    counts[sev] += 1

                token = resp.get("nextToken")
                if not token:
                    break
        except Exception:
            pass

        return {
            "findings": findings,
            "summary": {
                "critical": counts["CRITICAL"],
                "high": counts["HIGH"],
                "medium": counts["MEDIUM"],
                "low": counts["LOW"],
                "total": sum(counts.values()),
            },
        }

    def _build_reachability(
        self,
        front_doors: Dict[str, Any],
        compute_inventory: Dict[str, Any],
        region: str = "*",
        account_id: str = "*",
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        hypotheses: List[Dict[str, Any]] = []

        for inst in compute_inventory.get("ec2_instances", []) or []:
            if not isinstance(inst, dict) or not inst.get("PublicIpAddress"):
                continue
            iid = str(inst.get("InstanceId") or "")
            if not iid:
                continue
            arn = f"arn:aws:ec2:{region}:{account_id}:instance/{iid}"
            edges.append(
                {
                    "source": "internet",
                    "target": arn,
                    "protocol": "tcp",
                    "port": "unknown",
                    "path_type": "public-ip",
                    "confidence": 0.9,
                }
            )

        for f_url in front_doors.get("lambda_function_urls", []) or []:
            if not isinstance(f_url, dict):
                continue
            if str(f_url.get("AuthType") or "").upper() != "NONE":
                continue
            target = str(f_url.get("FunctionArn") or "")
            if not target:
                continue
            edges.append(
                {
                    "source": "internet",
                    "target": target,
                    "protocol": "https",
                    "port": 443,
                    "path_type": "lambda-url",
                    "confidence": 0.95,
                }
            )

        for db in compute_inventory.get("rds_instances", []) or []:
            if not isinstance(db, dict) or not db.get("PubliclyAccessible"):
                continue
            target = str(db.get("DBInstanceArn") or "")
            if not target:
                continue
            edges.append(
                {
                    "source": "internet",
                    "target": target,
                    "protocol": "tcp",
                    "port": "engine-default",
                    "path_type": "public-rds",
                    "confidence": 0.85,
                }
            )

        internet_facing_lbs: set[str] = set()
        for lb in front_doors.get("load_balancers", []) or []:
            if not isinstance(lb, dict):
                continue
            if str(lb.get("Scheme") or "") != "internet-facing":
                continue
            lb_arn = str(lb.get("LoadBalancerArn") or "")
            if not lb_arn:
                continue
            internet_facing_lbs.add(lb_arn)
            edges.append(
                {
                    "source": "internet",
                    "target": lb_arn,
                    "protocol": "tcp",
                    "port": "listener",
                    "path_type": "lb-front-door",
                    "confidence": 0.88,
                }
            )

        tg_to_lb: Dict[str, str] = {}
        for tg in front_doors.get("target_groups", []) or []:
            if not isinstance(tg, dict):
                continue
            tg_arn = str(tg.get("TargetGroupArn") or "")
            lb_arn = str(tg.get("LoadBalancerArn") or "")
            if tg_arn and lb_arn:
                tg_to_lb[tg_arn] = lb_arn

        for svc in compute_inventory.get("ecs_services", []) or []:
            if not isinstance(svc, dict):
                continue
            service_arn = str(svc.get("ServiceArn") or "")
            if not service_arn:
                continue

            load_balancers = svc.get("LoadBalancers", []) or []
            if not isinstance(load_balancers, list):
                continue
            for lb_ref in load_balancers:
                if not isinstance(lb_ref, dict):
                    continue
                tg_arn = str(lb_ref.get("targetGroupArn") or "")
                if not tg_arn:
                    continue
                lb_arn = tg_to_lb.get(tg_arn, "")
                if not lb_arn or lb_arn not in internet_facing_lbs:
                    continue
                edges.append(
                    {
                        "source": lb_arn,
                        "target": service_arn,
                        "protocol": "tcp",
                        "port": "target-group",
                        "path_type": "alb->ecs-service",
                        "confidence": 0.8,
                    }
                )

        for li in front_doors.get("listeners", []) or []:
            if not isinstance(li, dict):
                continue
            proto = str(li.get("Protocol") or "")
            if proto:
                hypotheses.append(
                    {
                        "path_type": "lb-front-door",
                        "protocol": proto.lower(),
                        "port": li.get("Port"),
                        "service_hypothesis": "web-service",
                    }
                )

        return {"_meta": {"region": "unknown"}, "edges": edges}, {"items": hypotheses}

    def _build_attack_paths(
        self,
        reachability_doc: Dict[str, Any],
        inspector_doc: Dict[str, Any],
        compute_inventory: Dict[str, Any],
        region: str = "*",
        account_id: str = "*",
    ) -> List[Dict[str, Any]]:
        role_resources = set()
        for inst in compute_inventory.get("ec2_instances", []) or []:
            if not isinstance(inst, dict):
                continue
            profile = inst.get("IamInstanceProfile")
            if isinstance(profile, dict) and profile.get("Arn"):
                iid = str(inst.get("InstanceId") or "")
                if iid:
                    role_resources.add(f"arn:aws:ec2:{region}:{account_id}:instance/{iid}")

        for fn in compute_inventory.get("lambda_functions", []) or []:
            if not isinstance(fn, dict):
                continue
            if fn.get("Role") and fn.get("FunctionArn"):
                role_resources.add(str(fn.get("FunctionArn")))

        role_resource_keys: Set[str] = set()
        for rr in role_resources:
            role_resource_keys |= self._resource_keys(rr)
            role_resource_keys.add(self._canonical_resource_key(rr))

        inspector_severity_hits: Dict[str, Dict[str, int]] = {}
        internet_reachability_hits: Dict[str, int] = {}

        for f_idx, f in enumerate(inspector_doc.get("findings", []) or []):
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity") or "").upper()
            title = str(f.get("title") or "").lower()
            for r in f.get("resources", []) or []:
                if not isinstance(r, dict):
                    continue
                rid = str(r.get("id") or "")
                if not rid:
                    continue
                key = self._canonical_resource_key(rid)
                inspector_severity_hits.setdefault(key, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0})
                if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
                    inspector_severity_hits[key][sev] = inspector_severity_hits[key].get(sev, 0) + 1
                if "reachable from an internet gateway" in title:
                    internet_reachability_hits[key] = internet_reachability_hits.get(key, 0) + 1

        paths: List[Dict[str, Any]] = []
        edges = reachability_doc.get("edges", []) or []
        for idx, edge in enumerate(edges, start=1):
            if not isinstance(edge, dict):
                continue
            target = str(edge.get("target") or "")
            if not target:
                continue
            reachability = float(edge.get("confidence") or 0.5)
            target_keys = self._resource_keys(target)
            target_keys.add(self._canonical_resource_key(target))

            crit_hits = sum(
                inspector_severity_hits.get(k, {}).get("CRITICAL", 0) for k in target_keys
            )
            high_hits = sum(inspector_severity_hits.get(k, {}).get("HIGH", 0) for k in target_keys)
            med_hits = sum(inspector_severity_hits.get(k, {}).get("MEDIUM", 0) for k in target_keys)
            internet_reach_hits = sum(internet_reachability_hits.get(k, 0) for k in target_keys)

            if crit_hits >= 1:
                vulnerability = 0.95
            elif high_hits >= 2:
                vulnerability = 0.85
            elif high_hits == 1:
                vulnerability = 0.75
            elif med_hits >= 3:
                vulnerability = 0.6
            elif med_hits >= 1:
                vulnerability = 0.45
            else:
                vulnerability = 0.2

            if internet_reach_hits > 0 and vulnerability < 0.55:
                vulnerability = 0.55

            blast = 0.8 if any(k in role_resource_keys for k in target_keys) else 0.3
            overall = round((0.45 * reachability) + (0.35 * vulnerability) + (0.20 * blast), 2)

            required_conditions = []
            if (crit_hits + high_hits + med_hits) == 0:
                required_conditions.append("known_vulnerability_not_confirmed")
            if not any(k in role_resource_keys for k in target_keys):
                required_conditions.append("high_blast_radius_not_confirmed")

            paths.append(
                {
                    "id": f"AP-SER-{idx:03d}",
                    "severity": self._overall_score_to_severity(overall),
                    "entry_point": "internet",
                    "pivot_resource": edge.get("source"),
                    "target_resource": target,
                    "reachability_score": round(reachability, 2),
                    "vulnerability_score": vulnerability,
                    "blast_radius_score": blast,
                    "overall_score": overall,
                    "inspector_signal": {
                        "critical": crit_hits,
                        "high": high_hits,
                        "medium": med_hits,
                        "internet_reachability_findings": internet_reach_hits,
                    },
                    "required_conditions": required_conditions,
                    "evidence_refs": [f"reachability-graph.json#edges[{idx - 1}]"],
                }
            )

        return paths

    def _overall_score_to_severity(self, score: float) -> str:
        """Map overall_score (0-1) to severity label using agreed thresholds."""
        if score >= 0.75:
            return "Critical"
        if score >= 0.55:
            return "High"
        if score >= 0.35:
            return "Medium"
        return "Low"

    def _resource_keys(self, resource_id: str) -> Set[str]:
        rid = str(resource_id or "").strip()
        if not rid:
            return set()

        keys: Set[str] = {rid}
        if ":instance/" in rid:
            keys.add(rid.split(":instance/")[-1])
        if rid.startswith("i-"):
            keys.add(f"arn:aws:ec2:*:*:instance/{rid}")
        return keys

    def _canonical_resource_key(self, resource_id: str) -> str:
        rid = str(resource_id or "").strip()
        if ":instance/" in rid:
            return rid.split(":instance/")[-1]
        return rid


__all__ = ["SistemasExplotablesRedSkill"]
