"""Post-processor for network skill to add ASCII topology diagram.

Generates a high-level network topology overview based on collected evidence:
- VPCs and CIDR blocks
- Public vs private subnets (based on route tables with 0.0.0.0/0 -> IGW)
- Key resource indicators inferred from ENIs (EC2/Lambda/RDS/NATGW/VPCE)

The diagram is injected into findings["architecture"]["flow_diagram"],
so both Markdown and PCI DSS formatters can render it.
"""

import json
from typing import Any, Dict, List, Optional

from drystone.storage.session import AuditSession


class NetworkPostProcessor:
    def __init__(self, session: AuditSession):
        self.session = session
        self.evidence_path = session.get_evidence_path("network")

    def process(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        evidence = self._load_evidence()
        analysis = self._analyze(evidence)
        diagram = self._generate_diagram(analysis)
        gaps = self._critical_gaps(analysis)

        findings["architecture"] = {
            "flow_diagram": diagram,
            "components_detected": analysis,
            "critical_gaps": gaps,
        }
        return findings

    def _load_evidence(self) -> Dict[str, Any]:
        files = {
            "audit_metadata": "_audit_metadata.json",
            "vpcs": "vpcs.json",
            "subnets": "subnets.json",
            "route_tables": "route-tables.json",
            "igws": "internet-gateways.json",
            "enis": "network-interfaces.json",
            "vpc_endpoints": "vpc-endpoints.json",
            "ec2_instances": "ec2-instances.json",
            "rds_instances": "rds-instances.json",
            "lambda_functions": "lambda-functions.json",
        }

        out: Dict[str, Any] = {}
        for key, filename in files.items():
            fp = self.evidence_path / filename
            if not fp.exists():
                continue
            try:
                with open(fp) as f:
                    out[key] = json.load(f)
            except Exception:
                out[key] = None
        return out

    def _items(self, doc: Any) -> List[Dict[str, Any]]:
        if isinstance(doc, dict) and isinstance(doc.get("items"), list):
            return [x for x in doc.get("items") or [] if isinstance(x, dict)]
        if isinstance(doc, list):
            return [x for x in doc if isinstance(x, dict)]
        return []

    def _analyze(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        meta = evidence.get("audit_metadata") or {}
        region = "unknown"
        account_id = "unknown"
        if isinstance(meta, dict):
            region = meta.get("_region") or region
            account_id = meta.get("_account_id") or account_id

        vpcs = self._items(evidence.get("vpcs"))
        subnets = self._items(evidence.get("subnets"))
        route_tables = self._items(evidence.get("route_tables"))
        igws = self._items(evidence.get("igws"))
        enis = self._items(evidence.get("enis"))
        vpc_endpoints = self._items(evidence.get("vpc_endpoints"))
        ec2_instances = self._items(evidence.get("ec2_instances"))
        rds_instances = self._items(evidence.get("rds_instances"))
        lambda_functions = self._items(evidence.get("lambda_functions"))

        # IGW attachments: igw -> vpc
        igw_by_vpc: Dict[str, List[str]] = {}
        for igw in igws:
            igw_id = igw.get("InternetGatewayId")
            for att in igw.get("Attachments", []) or []:
                if not isinstance(att, dict):
                    continue
                vpc_id = att.get("VpcId")
                if isinstance(vpc_id, str) and isinstance(igw_id, str):
                    igw_by_vpc.setdefault(vpc_id, []).append(igw_id)

        # Route table -> associated subnets and public-ness
        public_subnets: Dict[str, List[str]] = {}
        rt_public: Dict[str, bool] = {}
        rt_by_subnet: Dict[str, str] = {}

        for rt in route_tables:
            rt_id = rt.get("RouteTableId")
            vpc_id = rt.get("VpcId")
            if not isinstance(rt_id, str) or not isinstance(vpc_id, str):
                continue

            has_igw_default = False
            for r in rt.get("Routes", []) or []:
                if not isinstance(r, dict):
                    continue
                if r.get("DestinationCidrBlock") != "0.0.0.0/0":
                    continue
                gw = r.get("GatewayId")
                if isinstance(gw, str) and gw.startswith("igw-"):
                    has_igw_default = True
                    break
            rt_public[rt_id] = has_igw_default

            for a in rt.get("Associations", []) or []:
                sid = None
                if isinstance(a, dict):
                    sid = a.get("SubnetId")
                elif isinstance(a, str):
                    sid = a
                if isinstance(sid, str) and sid.startswith("subnet-"):
                    rt_by_subnet[sid] = rt_id
                    if has_igw_default:
                        public_subnets.setdefault(vpc_id, []).append(sid)

        # Subnet classification per VPC
        subnets_by_vpc: Dict[str, List[Dict[str, Any]]] = {}
        for sn in subnets:
            vpc_id = sn.get("VpcId")
            if isinstance(vpc_id, str):
                subnets_by_vpc.setdefault(vpc_id, []).append(sn)

        # ENI classification
        eni_by_subnet: Dict[str, List[Dict[str, Any]]] = {}
        for eni in enis:
            sid = eni.get("SubnetId")
            if isinstance(sid, str) and sid.startswith("subnet-"):
                eni_by_subnet.setdefault(sid, []).append(eni)

        def classify_eni(eni: Dict[str, Any]) -> str:
            itype = str(eni.get("InterfaceType") or "").lower()
            desc = str(eni.get("Description") or "").lower()
            att = eni.get("Attachment") or {}
            inst = None
            if isinstance(att, dict):
                inst = att.get("InstanceId")

            if itype == "lambda" or "lambda" in desc:
                return "Lambda"
            if itype == "nat_gateway" or "nat gateway" in desc:
                return "NATGW"
            if itype == "vpc_endpoint" or "vpc endpoint" in desc:
                return "VPCE"
            if "rdsnetworkinterface" in desc or "rds" in desc:
                return "RDS"
            if isinstance(inst, str) and inst.startswith("i-"):
                return "EC2"
            return "Other"

        def summarize_subnet(sn: Dict[str, Any]) -> Dict[str, Any]:
            sid = sn.get("SubnetId")
            sid_s = sid if isinstance(sid, str) else "unknown"
            cidr = sn.get("CidrBlock")
            az = sn.get("AvailabilityZone")
            map_pub = sn.get("MapPublicIpOnLaunch")

            rt_id = rt_by_subnet.get(sid_s)
            is_public = bool(rt_id and rt_public.get(rt_id) is True)

            enis_here = eni_by_subnet.get(sid_s, [])
            types: Dict[str, int] = {}
            public_ips = 0
            for e in enis_here:
                types[classify_eni(e)] = types.get(classify_eni(e), 0) + 1
                if e.get("PublicIp"):
                    public_ips += 1

            return {
                "subnet_id": sid_s,
                "cidr": cidr,
                "az": az,
                "map_public_ip": map_pub,
                "route_table_id": rt_id,
                "is_public": is_public,
                "eni_total": len(enis_here),
                "eni_public_ip_total": public_ips,
                "eni_types": types,
                "resource_names": {},
            }

        # Resource name maps by subnet
        def _tag_name(tags: Any) -> Optional[str]:
            if not isinstance(tags, list):
                return None
            for t in tags:
                if not isinstance(t, dict):
                    continue
                if t.get("Key") == "Name" and isinstance(t.get("Value"), str) and t.get("Value"):
                    return t.get("Value")
            return None

        ec2_by_subnet: Dict[str, List[str]] = {}
        for inst in ec2_instances:
            sid = inst.get("SubnetId")
            iid = inst.get("InstanceId")
            if not (isinstance(sid, str) and sid.startswith("subnet-")):
                continue
            name = _tag_name(inst.get("Tags"))
            label = name or (iid if isinstance(iid, str) else None)
            if label:
                ec2_by_subnet.setdefault(sid, []).append(label)

        rds_by_subnet: Dict[str, List[str]] = {}
        for db in rds_instances:
            dbid = db.get("DBInstanceIdentifier")
            if not isinstance(dbid, str):
                continue
            for sid in db.get("SubnetIds", []) or []:
                if isinstance(sid, str) and sid.startswith("subnet-"):
                    rds_by_subnet.setdefault(sid, []).append(dbid)

        lambda_by_subnet: Dict[str, List[str]] = {}
        for fn in lambda_functions:
            name = fn.get("FunctionName")
            if not isinstance(name, str):
                continue
            for sid in fn.get("SubnetIds", []) or []:
                if isinstance(sid, str) and sid.startswith("subnet-"):
                    lambda_by_subnet.setdefault(sid, []).append(name)

        vpc_summaries: List[Dict[str, Any]] = []
        for v in vpcs:
            vpc_id = v.get("VpcId")
            if not isinstance(vpc_id, str):
                continue

            cidr = v.get("CidrBlock")
            flow_logs = v.get("FlowLogs", []) or []
            flow_active = any(
                isinstance(fl, dict) and fl.get("FlowLogStatus") == "ACTIVE" for fl in flow_logs
            )

            subs = subnets_by_vpc.get(vpc_id, [])
            subs_summ = []
            for sn in subs:
                s = summarize_subnet(sn)
                sid = s.get("subnet_id")
                if isinstance(sid, str):
                    s["resource_names"] = {
                        "EC2": sorted(set(ec2_by_subnet.get(sid, []))),
                        "Lambda": sorted(set(lambda_by_subnet.get(sid, []))),
                        "RDS": sorted(set(rds_by_subnet.get(sid, []))),
                    }
                subs_summ.append(s)
            pub = [s for s in subs_summ if s.get("is_public")]
            priv = [s for s in subs_summ if not s.get("is_public")]

            vpce_count = len([e for e in vpc_endpoints if e.get("VpcId") == vpc_id])

            vpc_summaries.append(
                {
                    "vpc_id": vpc_id,
                    "cidr": cidr,
                    "igw_ids": sorted(set(igw_by_vpc.get(vpc_id, []))),
                    "flow_logs_active": flow_active,
                    "subnets_public": sorted(pub, key=lambda x: str(x.get("subnet_id") or "")),
                    "subnets_private": sorted(priv, key=lambda x: str(x.get("subnet_id") or "")),
                    "vpc_endpoints_total": vpce_count,
                }
            )

        return {
            "region": region,
            "account_id": account_id,
            "vpcs_total": len(vpc_summaries),
            "vpcs": vpc_summaries,
        }

    def _critical_gaps(self, a: Dict[str, Any]) -> List[str]:
        gaps: List[str] = []
        for v in a.get("vpcs", []) or []:
            vpc_id = v.get("vpc_id")
            pubs = v.get("subnets_public") or []
            if pubs:
                # If any ENI in a public subnet has a public IP, call out.
                if any((s.get("eni_public_ip_total") or 0) > 0 for s in pubs):
                    gaps.append(
                        f"VPC {vpc_id}: public subnet(s) contain ENIs with public IPs (validate no sensitive workloads)"
                    )
        return gaps

    def _box(self, title: str) -> List[str]:
        w = 73
        t = title[: w - 4]
        top = "┌" + "─" * (w - 2) + "┐"
        mid = "│ " + t.ljust(w - 4) + " │"
        bot = "└" + "─" * (w - 2) + "┘"
        return [top, mid, bot]

    def _generate_diagram(self, a: Dict[str, Any]) -> str:
        region = a.get("region") or "unknown"
        vpcs = a.get("vpcs") or []

        lines: List[str] = []
        lines.extend(self._box(f"AWS NETWORK TOPOLOGY (region: {region})"))
        lines.append("")

        if not vpcs:
            lines.append("No VPCs detected in evidence.")
            return "\n".join(lines)

        # Keep diagram readable: show up to 3 VPCs.
        for v in vpcs[:3]:
            vpc_id = v.get("vpc_id")
            cidr = v.get("cidr")
            igws = v.get("igw_ids") or []
            flow = "yes" if v.get("flow_logs_active") else "no"
            vpce_total = v.get("vpc_endpoints_total") or 0

            lines.append(f"VPC {vpc_id} ({cidr})")
            lines.append(
                f"  IGW: {', '.join(igws) if igws else 'none'} | FlowLogs: {flow} | VPCE: {vpce_total}"
            )

            pubs = v.get("subnets_public") or []
            privs = v.get("subnets_private") or []

            def fmt_sub(s: Dict[str, Any]) -> str:
                sid = s.get("subnet_id")
                cidr = s.get("cidr")
                az = s.get("az")
                eni_total = s.get("eni_total")
                types = s.get("eni_types") or {}
                typ_str = ", ".join(
                    [f"{k}:{types[k]}" for k in sorted(types.keys()) if types.get(k)]
                )
                pub_ip = s.get("eni_public_ip_total") or 0
                pub_ip_s = f" public_ip:{pub_ip}" if pub_ip else ""
                return f"    - {sid} {cidr} {az} enis:{eni_total}{pub_ip_s} [{typ_str}]"

            def fmt_names(s: Dict[str, Any]) -> List[str]:
                rn = s.get("resource_names") or {}
                if not isinstance(rn, dict):
                    return []

                def _fmt(label: str, names: Any) -> Optional[str]:
                    if not isinstance(names, list) or not names:
                        return None
                    # Keep diagram readable: show first 2 names
                    shown = [str(x) for x in names[:2]]
                    extra = len(names) - len(shown)
                    suffix = f" (+{extra} more)" if extra > 0 else ""
                    return f"      {label}: {', '.join(shown)}{suffix}"

                out = []
                for label in ["EC2", "Lambda", "RDS"]:
                    line = _fmt(label, rn.get(label))
                    if line:
                        out.append(line)
                return out

            lines.append("  Public subnets:")
            if pubs:
                for s in pubs[:5]:
                    lines.append(fmt_sub(s))
                    lines.extend(fmt_names(s))
            else:
                lines.append("    - none")

            lines.append("  Private subnets:")
            if privs:
                for s in privs[:5]:
                    lines.append(fmt_sub(s))
                    lines.extend(fmt_names(s))
            else:
                lines.append("    - none")

            lines.append("")

        if len(vpcs) > 3:
            lines.append(f"(Diagram truncated: {len(vpcs) - 3} additional VPC(s) not shown)")

        return "\n".join(lines).rstrip()
