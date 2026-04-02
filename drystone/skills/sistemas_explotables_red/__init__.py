"""Sistemas explotables por red skill.

Passive pentest-oriented collection that correlates exposure and exploitability
signals for compute assets (EC2/ECS/Lambda/RDS) without active scanning.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession

logger = logging.getLogger(__name__)


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

        # CVE Intelligence: enrich Inspector findings with NVD/GitHub data
        cve_intel = self._collect_cve_intelligence(
            inspector_doc=inspector_doc,
            network_controls=network_controls,
            compute_inventory=compute_inventory,
        )
        _save("cve-intelligence.json", cve_intel)

        _save("_audit_metadata.json", metadata)

    # Port → service name mapping for attack path narrative
    _PORT_SERVICE_MAP: Dict[int, str] = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL",
        1433: "MSSQL",
        5601: "Kibana",
        9200: "Elasticsearch",
        6379: "Redis",
        27017: "MongoDB",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }

    # ── Exploit source clients ───────────────────────────────────

    _CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    _EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    _EXPLOITDB_MAX_SIZE = 15 * 1024 * 1024  # 15 MB guard
    _POC_DOMAINS = {"github.com", "exploit-db.com", "packetstormsecurity.com"}

    def _fetch_cisa_kev(self) -> Dict[str, Dict[str, Any]]:
        """Fetch CISA Known Exploited Vulnerabilities catalog.

        Returns dict keyed by CVE ID with fields: date_added, vendor, product,
        ransomware_use.  Cached in self._kev_cache after first call.
        """
        if hasattr(self, "_kev_cache"):
            return self._kev_cache
        try:
            req = urllib.request.Request(
                self._CISA_KEV_URL,
                headers={"User-Agent": "drystone-security-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())
            lookup: Dict[str, Dict[str, Any]] = {}
            for entry in body.get("vulnerabilities", []):
                if not isinstance(entry, dict):
                    continue
                cve_id = str(entry.get("cveID") or "")
                if cve_id:
                    lookup[cve_id] = {
                        "date_added": entry.get("dateAdded", ""),
                        "vendor": entry.get("vendorProject", ""),
                        "product": entry.get("product", ""),
                        "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
                    }
            self._kev_cache = lookup
            return lookup
        except Exception as exc:
            logger.warning("CISA KEV fetch failed: %s", exc)
            self._kev_cache: Dict[str, Dict[str, Any]] = {}
            return self._kev_cache

    def _fetch_exploitdb_index(self, cve_ids: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Fetch Exploit-DB CSV index and return matches for given CVE IDs.

        Returns dict keyed by CVE ID with fields: id, type, platform, description.
        CVE IDs are found in the ``codes`` column (`;`-separated values).
        Cached in self._edb_cache after first call.
        """
        if hasattr(self, "_edb_cache"):
            return {cve: self._edb_cache[cve] for cve in cve_ids if cve in self._edb_cache}
        try:
            req = urllib.request.Request(
                self._EXPLOITDB_CSV_URL,
                headers={"User-Agent": "drystone-security-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read(self._EXPLOITDB_MAX_SIZE + 1)
                if len(raw) > self._EXPLOITDB_MAX_SIZE:
                    logger.warning("Exploit-DB CSV exceeds %d bytes, skipping", self._EXPLOITDB_MAX_SIZE)
                    self._edb_cache: Dict[str, Dict[str, Any]] = {}
                    return self._edb_cache
                text = raw.decode("utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            full_index: Dict[str, Dict[str, Any]] = {}
            for row in reader:
                codes_raw = str(row.get("codes") or "")
                if not codes_raw:
                    continue
                codes = [c.strip() for c in codes_raw.split(";") if c.strip().upper().startswith("CVE-")]
                if not codes:
                    continue
                entry = {
                    "id": int(row.get("id") or 0),
                    "type": str(row.get("type") or ""),
                    "platform": str(row.get("platform") or ""),
                    "description": str(row.get("description") or "")[:200],
                }
                for code in codes:
                    code_upper = code.upper()
                    if code_upper not in full_index:
                        full_index[code_upper] = entry
            self._edb_cache = full_index
            return {cve: full_index[cve] for cve in cve_ids if cve in full_index}
        except Exception as exc:
            logger.warning("Exploit-DB CSV fetch failed: %s", exc)
            self._edb_cache: Dict[str, Dict[str, Any]] = {}
            return self._edb_cache

    # ── CVE Intelligence ─────────────────────────────────────────

    def _collect_cve_intelligence(
        self,
        inspector_doc: Dict[str, Any],
        network_controls: Dict[str, Any],
        compute_inventory: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Enrich Inspector CVE findings with NVD API data and open-port analysis.

        Queries NVD API v2 for CVSS scores and vector strings.
        Correlates open ports from security groups with CVE attack vectors.
        Generates per-instance attack path narratives with MITRE ATT&CK techniques.
        All network calls are best-effort: errors are logged but never fail the audit.
        """
        enrichment_errors: List[str] = []
        instances_intel: Dict[str, Any] = {}

        # 1. Build instance_id → list of {id, package, severity} from Inspector findings
        instance_cves_raw: Dict[str, List[Dict[str, str]]] = {}
        for finding in inspector_doc.get("findings", []) or []:
            if not isinstance(finding, dict):
                continue
            title = str(finding.get("title") or "")
            sev = str(finding.get("severity") or "").upper()
            for r in finding.get("resources", []) or []:
                if not isinstance(r, dict) or r.get("type") != "AWS_EC2_INSTANCE":
                    continue
                rid = str(r.get("id") or "")
                if not rid:
                    continue
                iid = rid.split(":instance/")[-1] if ":instance/" in rid else rid
                # Extract CVE/GHSA ID and package from title: "CVE-XXXX (pkg)"
                cve_id = ""
                package = ""
                if title.upper().startswith("CVE-") or title.upper().startswith("GHSA-"):
                    parts = title.split(" ", 1)
                    cve_id = parts[0]
                    if len(parts) > 1:
                        # "CVE-XXX cryptography 41.0.4..." → package is second word
                        pkg_parts = parts[1].strip().split()
                        package = pkg_parts[0] if pkg_parts else ""
                else:
                    cve_id = title[:80]  # fallback: truncated title
                instance_cves_raw.setdefault(iid, [])
                if cve_id and not any(e["id"] == cve_id for e in instance_cves_raw[iid]):
                    instance_cves_raw[iid].append(
                        {"id": cve_id, "package": package, "severity": sev}
                    )

        # 2. Build SG → open internet-exposed ports mapping AND full ingress rules
        sg_open_ports: Dict[str, List[int]] = {}
        sg_all_rules: Dict[str, Dict[str, Any]] = {}  # sgid → {name, rules}
        for sg in network_controls.get("security_groups", []) or []:
            if not isinstance(sg, dict):
                continue
            sgid = str(sg.get("GroupId") or "")
            if not sgid:
                continue
            sg_name = str(sg.get("GroupName") or sgid)
            ports: List[int] = []
            all_rules: List[Dict[str, Any]] = []
            for perm in sg.get("IpPermissions", []) or []:
                if not isinstance(perm, dict):
                    continue
                from_port = int(perm.get("FromPort", 0) or 0)
                to_port = int(perm.get("ToPort", 65535) or 65535)
                proto = str(perm.get("IpProtocol", "") or "")
                proto_str = "all" if proto == "-1" else proto
                port_str = (
                    "all"
                    if proto == "-1"
                    else (str(from_port) if from_port == to_port else f"{from_port}-{to_port}")
                )
                ranges = perm.get("IpRanges", []) or []
                ipv6_ranges = perm.get("Ipv6Ranges", []) or []
                for r in ranges:
                    cidr = str(r.get("CidrIp") or "")
                    if cidr:
                        all_rules.append(
                            {
                                "port": port_str,
                                "protocol": proto_str,
                                "source": cidr,
                                "type": "cidr",
                            }
                        )
                for r in ipv6_ranges:
                    cidr = str(r.get("CidrIpv6") or "")
                    if cidr:
                        all_rules.append(
                            {
                                "port": port_str,
                                "protocol": proto_str,
                                "source": cidr,
                                "type": "cidr_ipv6",
                            }
                        )
                for r in perm.get("UserIdGroupPairs", []) or []:
                    ref_id = str(r.get("GroupId") or "")
                    if ref_id:
                        all_rules.append(
                            {
                                "port": port_str,
                                "protocol": proto_str,
                                "source": ref_id,
                                "type": "security_group",
                            }
                        )
                # Determine if internet-accessible for sg_open_ports
                is_internet = any(str(r.get("CidrIp", "")).startswith("0.") for r in ranges) or any(
                    str(r.get("CidrIpv6", "")).startswith("::/") for r in ipv6_ranges
                )
                if is_internet:
                    if proto == "-1":
                        ports.extend([22, 80, 443, 3389])
                    elif proto in ("tcp", "udp"):
                        for p in range(from_port, min(to_port + 1, from_port + 100)):
                            if p in self._PORT_SERVICE_MAP or from_port == to_port:
                                ports.append(from_port)
                                break
            if ports:
                sg_open_ports[sgid] = sorted(set(ports))
            if all_rules:
                sg_all_rules[sgid] = {"name": sg_name, "rules": all_rules[:25]}

        # 3. Build instance_id → open internet-exposed ports, all SG rules, and IAM role
        instance_open_ports: Dict[str, List[Dict[str, Any]]] = {}
        instance_sg_rules: Dict[str, List[Dict[str, Any]]] = {}  # iid → flat rule list
        instance_roles: Dict[str, str] = {}  # iid → role name
        for inst in compute_inventory.get("ec2_instances", []) or []:
            if not isinstance(inst, dict) or not inst.get("PublicIpAddress"):
                continue
            iid = str(inst.get("InstanceId") or "")
            if not iid:
                continue
            open_ports: List[Dict[str, Any]] = []
            inst_rules: List[Dict[str, Any]] = []
            for sg_ref in inst.get("SecurityGroups", []) or []:
                sgid = str(sg_ref.get("GroupId") or "") if isinstance(sg_ref, dict) else ""
                for port in sg_open_ports.get(sgid, []):
                    svc = self._PORT_SERVICE_MAP.get(port, "Unknown")
                    open_ports.append(
                        {"port": port, "protocol": "tcp", "service": svc, "internet_exposed": True}
                    )
                sg_data = sg_all_rules.get(sgid, {})
                for rule in sg_data.get("rules", [])[:20]:
                    inst_rules.append({**rule, "sg_id": sgid, "sg_name": sg_data.get("name", sgid)})
            instance_open_ports[iid] = open_ports
            if inst_rules:
                instance_sg_rules[iid] = inst_rules[:30]
            # Extract IAM role name from instance profile ARN
            profile = inst.get("IamInstanceProfile")
            if isinstance(profile, dict):
                arn = str(profile.get("Arn") or "")
                role_name = arn.split("/")[-1] if "/" in arn else ""
                if role_name:
                    instance_roles[iid] = role_name

        # 4. Collect unique CVE IDs (cap at 20) and query exploit sources + NVD
        all_cve_ids: List[str] = []
        for cves in instance_cves_raw.values():
            for e in cves:
                if e["id"] not in all_cve_ids and len(all_cve_ids) < 20:
                    all_cve_ids.append(e["id"])

        cve_id_set = {c.upper() for c in all_cve_ids if c.upper().startswith("CVE-")}

        # 4a. Fetch CISA KEV and Exploit-DB catalogs (before NVD loop)
        kev_lookup: Dict[str, Dict[str, Any]] = {}
        edb_lookup: Dict[str, Dict[str, Any]] = {}
        if cve_id_set:
            try:
                kev_lookup = self._fetch_cisa_kev()
            except Exception as exc:
                enrichment_errors.append(f"CISA KEV fetch failed: {exc}")
            try:
                edb_lookup = self._fetch_exploitdb_index(cve_id_set)
            except Exception as exc:
                enrichment_errors.append(f"Exploit-DB fetch failed: {exc}")

        # 4b. Query NVD API per CVE and extract PoC URLs from references
        nvd_cache: Dict[str, Dict[str, Any]] = {}
        for cve_id in all_cve_ids:
            if not cve_id.upper().startswith("CVE-"):
                continue
            try:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "drystone-security-audit/1.0"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read().decode())
                vulns = body.get("vulnerabilities", [])
                if not vulns:
                    continue
                cve_data = vulns[0].get("cve", {})
                metrics = cve_data.get("metrics", {})
                cvss_score: Optional[float] = None
                cvss_vector = ""
                # Prefer v3.1, fallback to v3.0, v2
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list and isinstance(metric_list, list):
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_vector = str(cvss_data.get("vectorString", ""))
                        break
                descriptions_list = cve_data.get("descriptions", [])
                cve_description = next(
                    (
                        d.get("value", "")
                        for d in descriptions_list
                        if isinstance(d, dict) and d.get("lang") == "en"
                    ),
                    "",
                )
                # Extract PoC/exploit URLs from NVD references
                poc_urls: List[str] = []
                seen_urls: Set[str] = set()
                for ref in cve_data.get("references", []):
                    if not isinstance(ref, dict):
                        continue
                    ref_url = str(ref.get("url") or "")
                    if not ref_url or ref_url in seen_urls:
                        continue
                    tags = ref.get("tags", []) or []
                    is_exploit_tag = any("Exploit" in str(t) for t in tags)
                    is_poc_domain = any(d in ref_url for d in self._POC_DOMAINS)
                    if is_exploit_tag or is_poc_domain:
                        poc_urls.append(ref_url)
                        seen_urls.add(ref_url)
                nvd_cache[cve_id] = {
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "description": cve_description[:600] if cve_description else "",
                    "poc_urls": poc_urls,
                }
            except Exception as e:
                enrichment_errors.append(f"NVD lookup failed for {cve_id}: {e}")

        # 5. Build per-instance intel with enriched CVEs and attack path
        for iid, raw_cves in instance_cves_raw.items():
            open_ports = instance_open_ports.get(iid, [])
            open_port_nums = [p["port"] for p in open_ports]

            enriched_cves: List[Dict[str, Any]] = []
            for entry in raw_cves:
                cve_id = entry["id"]
                nvd = nvd_cache.get(cve_id, {})
                vector = str(nvd.get("cvss_vector", "") or "")
                # Inspector Network Reachability findings are inherently network-accessible;
                # skip CVSS-based inference and mark them as exploitable from the internet.
                if "reachable from an internet gateway" in cve_id.lower():
                    attack_vector = "NETWORK"
                    exploitable = True
                else:
                    attack_vector = (
                        "NETWORK" if "AV:N" in vector else ("LOCAL" if "AV:L" in vector else "")
                    )
                    exploitable = attack_vector == "NETWORK" and len(open_port_nums) > 0
                # Build exploit_intel from external sources
                cve_upper = cve_id.upper()
                kev_entry = kev_lookup.get(cve_upper)
                edb_entry = edb_lookup.get(cve_upper)
                nvd_poc_urls = nvd.get("poc_urls", [])

                has_public_exploit = bool(kev_entry or edb_entry or nvd_poc_urls)
                sources_checked = ["cisa_kev", "exploit_db", "nvd_references"]

                # Build human-readable summary
                summary_parts: List[str] = []
                if kev_entry:
                    summary_parts.append("Listed in CISA KEV (actively exploited in wild)")
                if edb_entry:
                    eid = edb_entry.get("id", "?")
                    etype = edb_entry.get("type", "unknown")
                    summary_parts.append(f"{etype.capitalize()} exploit on Exploit-DB #{eid}")
                if nvd_poc_urls:
                    summary_parts.append(f"{len(nvd_poc_urls)} PoC URL(s) in NVD references")
                if not summary_parts:
                    summary_parts.append("No public exploit found in checked sources")

                exploit_intel: Dict[str, Any] = {
                    "has_public_exploit": has_public_exploit,
                    "cisa_kev": {
                        "listed": bool(kev_entry),
                        "date_added": kev_entry.get("date_added", "") if kev_entry else "",
                        "ransomware_use": kev_entry.get("ransomware_use", "") if kev_entry else "",
                    },
                    "exploit_db": {
                        "id": edb_entry.get("id") if edb_entry else None,
                        "type": edb_entry.get("type", "") if edb_entry else "",
                        "platform": edb_entry.get("platform", "") if edb_entry else "",
                    },
                    "poc_urls": nvd_poc_urls[:10],
                    "sources_checked": sources_checked,
                    "summary": ". ".join(summary_parts) + ".",
                }

                enriched_cves.append(
                    {
                        "id": cve_id,
                        "package": entry.get("package", ""),
                        "inspector_severity": entry.get("severity", ""),
                        "cvss_score": nvd.get("cvss_score"),
                        "cvss_vector": vector or None,
                        "description": nvd.get("description", ""),
                        "attack_vector": attack_vector or "UNKNOWN",
                        "exploitable_from_internet": exploitable,
                        "relevant_open_ports": open_port_nums[:5],
                        "exploit_intel": exploit_intel,
                    }
                )

            attack_path = self._build_instance_attack_path(iid, enriched_cves, open_ports)

            instances_intel[iid] = {
                "open_ports": open_ports,
                "sg_rules": instance_sg_rules.get(iid, []),
                "iam_role": instance_roles.get(iid, ""),
                "cves": enriched_cves,
                "attack_path": attack_path,
            }

        return {
            "instances": instances_intel,
            "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
            "enrichment_errors": enrichment_errors,
        }

    def _build_instance_attack_path(
        self,
        iid: str,
        cves: List[Dict[str, Any]],
        open_ports: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate a MITRE ATT&CK-mapped attack path for an EC2 instance."""
        if not open_ports and not cves:
            return {}

        steps: List[Dict[str, Any]] = []
        step_num = 1

        # Step 1: Initial access via open port
        if open_ports:
            port_info = open_ports[0]
            port = port_info.get("port", "?")
            svc = port_info.get("service", "Unknown")
            steps.append(
                {
                    "step": step_num,
                    "action": f"Reach port {port}/TCP from internet (SG allows 0.0.0.0/0) — {svc}",
                    "technique": "T1595.001",
                }
            )
            step_num += 1

        # Step 2: Exploit network-reachable CVE
        network_cves = [c for c in cves if c.get("exploitable_from_internet")]
        if network_cves:
            top_cve = network_cves[0]
            cve_id = top_cve.get("id", "CVE-unknown")
            pkg = top_cve.get("package", "")
            pkg_str = f" in {pkg}" if pkg else ""
            steps.append(
                {
                    "step": step_num,
                    "action": f"Exploit {cve_id}{pkg_str} via network-accessible service",
                    "technique": "T1190",
                }
            )
            step_num += 1

        # Step 3: Code execution
        steps.append(
            {
                "step": step_num,
                "action": "Achieve code execution or denial of service on target service",
                "technique": "T1059",
            }
        )
        step_num += 1

        # Step 4: IMDS credential theft
        steps.append(
            {
                "step": step_num,
                "action": "Query EC2 Instance Metadata Service (IMDS) for IAM role credentials",
                "technique": "T1552.005",
            }
        )
        step_num += 1

        # Step 5: Lateral movement
        steps.append(
            {
                "step": step_num,
                "action": "Use harvested role credentials for lateral movement or data exfiltration",
                "technique": "T1078.004",
            }
        )

        narrative = (
            f"Instance {iid} is reachable from the internet"
            + (f" on port {open_ports[0]['port']}/{open_ports[0]['service']}" if open_ports else "")
            + (f" and has {len(network_cves)} network-exploitable CVE(s)" if network_cves else "")
            + ". An attacker can exploit vulnerabilities to gain initial access, "
            "then escalate via IMDS credential theft."
        )

        return {"narrative": narrative, "steps": steps}

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
