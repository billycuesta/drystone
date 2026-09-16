"""Network-specific findings normalization hooks."""

import logging
from typing import Any, Dict, List, Optional, cast

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    def remap_id(self, finding_id: str, finding: Finding) -> str:
        if finding_id != "NET-004":
            return finding_id

        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return finding_id

        if "NET-022" not in self.context.checklist_map:
            return finding_id

        route_tables = evidence.get("route-tables")
        enis = evidence.get("network-interfaces")
        sgs = evidence.get("security-groups")

        rt_items: List[Dict[str, Any]] = []
        if isinstance(route_tables, dict) and isinstance(route_tables.get("items"), list):
            rt_items = cast(List[Dict[str, Any]], route_tables.get("items") or [])
        elif isinstance(route_tables, list):
            rt_items = cast(List[Dict[str, Any]], route_tables)

        public_subnets: List[str] = []
        for rt in rt_items:
            if not isinstance(rt, dict):
                continue
            routes = rt.get("Routes", []) or []
            if not isinstance(routes, list):
                continue
            has_igw_default = False
            for r in routes:
                if not isinstance(r, dict):
                    continue
                if r.get("DestinationCidrBlock") != "0.0.0.0/0":
                    continue
                gw = r.get("GatewayId")
                if isinstance(gw, str) and gw.startswith("igw-"):
                    has_igw_default = True
                    break
            if not has_igw_default:
                continue

            assocs = rt.get("Associations", []) or []
            if not isinstance(assocs, list):
                continue
            for a in assocs:
                if isinstance(a, dict):
                    sid = a.get("SubnetId")
                    if isinstance(sid, str) and sid.startswith("subnet-"):
                        public_subnets.append(sid)
                elif isinstance(a, str) and a.startswith("subnet-"):
                    public_subnets.append(a)

        public_subnets = sorted(set(public_subnets))
        if not public_subnets:
            return finding_id

        eni_items: List[Dict[str, Any]] = []
        if isinstance(enis, dict) and isinstance(enis.get("items"), list):
            eni_items = cast(List[Dict[str, Any]], enis.get("items") or [])
        elif isinstance(enis, list):
            eni_items = cast(List[Dict[str, Any]], enis)

        sg_by_id: Dict[str, Dict[str, Any]] = {}
        if isinstance(sgs, dict) and isinstance(sgs.get("by_id"), dict):
            sg_by_id = cast(Dict[str, Dict[str, Any]], sgs.get("by_id") or {})

        sensitive_markers = (
            "rds",
            "db",
            "database",
            "postgres",
            "mysql",
            "mariadb",
            "mongo",
            "redis",
            "elasticache",
        )

        def _is_sensitive_eni(eni: Dict[str, Any]) -> bool:
            desc = (eni.get("Description") or "").lower()
            if any(m in desc for m in sensitive_markers):
                return True
            for g in eni.get("Groups", []) or []:
                if not isinstance(g, dict):
                    continue
                gid = g.get("GroupId")
                if not isinstance(gid, str):
                    continue
                sg = sg_by_id.get(gid) or {}
                name = (sg.get("GroupName") or "").lower()
                if any(m in name for m in sensitive_markers):
                    return True
            return False

        for eni in eni_items:
            if not isinstance(eni, dict):
                continue
            sid = eni.get("SubnetId")
            if sid not in public_subnets:
                continue
            if _is_sensitive_eni(eni):
                return finding_id

        return "NET-022"

    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return refs

        out: List[str] = []
        sg_id: Optional[str] = None

        for r in refs:
            if not isinstance(r, str):
                continue
            rr = r.strip()

            if rr.startswith("security-groups.json#"):
                anchor = rr.split("#", 1)[1]

                if not sg_id and anchor.startswith("sg-"):
                    sg_id = anchor

                if anchor.startswith("by_id."):
                    out.append(rr)
                    continue

                if anchor.startswith("sg-"):
                    doc = evidence.get("security-groups")
                    if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                        if anchor in (doc.get("by_id") or {}):
                            out.append(f"security-groups.json#by_id.{anchor}")
                            continue
                    out.append(rr)
                    continue

                if anchor.startswith("IngressRules") and sg_id:
                    out.append(f"security-groups.json#by_id.{sg_id}.{anchor}")
                    continue

                out.append(rr)
                continue

            if rr.startswith("vpcs.json#"):
                anchor = rr.split("#", 1)[1]
                if anchor.startswith("by_id."):
                    out.append(rr)
                    continue
                out.append(rr)
                continue

            out.append(rr)

        return out

    def ensure_impact(self, finding: Finding) -> bool:
        if finding.id != "NET-024":
            return False
        impact = str(finding.impact or "")
        if (
            "Compliance auditors flagging" not in impact
            and "prior to attestation" not in impact
            and "cardholder data" not in impact.lower()
        ):
            return False
        finding.impact = (
            "Inconsistent security group naming weakens ownership, triage, and "
            "change-control workflows. Operators may struggle to identify which "
            "team owns a rule set, whether a group is temporary, or whether an "
            "exception is still required.\n\n"
            "The business impact is slower incident response and less reliable "
            "inventory governance. This is an operational control gap; it should "
            "not be presented as proven data exposure or a guaranteed audit outcome "
            "unless separate evidence establishes that scope."
        )
        return True


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("NET-"):
            return None

        # Network: evidence-based validation for common false positives
        if finding_id.startswith("NET-"):

            def _items(doc: Any) -> List[Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("items"), list):
                    return cast(List[Dict[str, Any]], doc.get("items") or [])
                if isinstance(doc, list):
                    return cast(List[Dict[str, Any]], doc)
                return []

            def _by_id(doc: Any, key: str) -> Dict[str, Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                    return cast(Dict[str, Dict[str, Any]], doc.get("by_id") or {})
                idx: Dict[str, Dict[str, Any]] = {}
                for it in _items(doc):
                    if not isinstance(it, dict):
                        continue
                    k = it.get(key)
                    if isinstance(k, str) and k:
                        idx[k] = it
                return idx

            def _perm_allows_world(perm: Dict[str, Any], *, port: int) -> bool:
                proto = perm.get("IpProtocol")
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")

                port_match = False
                if proto == "-1":
                    port_match = True
                elif proto == "tcp" and isinstance(from_p, int) and isinstance(to_p, int):
                    port_match = from_p <= port <= to_p

                if not port_match:
                    return False

                for r in perm.get("IpRanges", []) or []:
                    if isinstance(r, dict) and r.get("CidrIp") == "0.0.0.0/0":
                        return True
                for r in perm.get("Ipv6Ranges", []) or []:
                    if isinstance(r, dict) and r.get("CidrIpv6") == "::/0":
                        return True

                return False

            # NET-001: Sensitive ports exposed to world
            if finding_id == "NET-001":
                sg_doc = self.evidence.get("security-groups")
                sgs = _by_id(sg_doc, "GroupId")

                sg_id = None
                snippet = finding.evidence_snippet
                if isinstance(snippet, dict):
                    sg_id = cast(Dict[str, Any], snippet).get("GroupId")

                if not sg_id:
                    for arn in finding.affected_resources or []:
                        if not isinstance(arn, str):
                            continue
                        marker = ":security-group/"
                        if marker in arn:
                            sg_id = arn.split(marker, 1)[1]
                            break

                if not (isinstance(sg_id, str) and sg_id.startswith("sg-")):
                    logger.warning(
                        f"Rejected {finding_id} - Cannot resolve security group id from evidence/affected_resources."
                    )
                    return False

                sg = sgs.get(sg_id)
                if not isinstance(sg, dict):
                    logger.warning(
                        f"Rejected {finding_id} - Security group '{sg_id}' not found in evidence."
                    )
                    return False

                sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017, 6379]
                exposed = False
                for perm in sg.get("IngressRules", []) or []:
                    if not isinstance(perm, dict):
                        continue
                    for p in sensitive_ports:
                        if _perm_allows_world(perm, port=p):
                            exposed = True
                            break
                    if exposed:
                        break

                if not exposed:
                    logger.warning(
                        f"Rejected {finding_id} - No 0.0.0.0/0 or ::/0 ingress detected for sensitive ports in '{sg_id}'."
                    )
                    return False

            # NET-018: VPC missing Flow Logs
            if finding_id == "NET-018":
                vpc_doc = self.evidence.get("vpcs")
                vpcs = _by_id(vpc_doc, "VpcId")
                vpc_id = None
                for arn in finding.affected_resources or []:
                    if not isinstance(arn, str):
                        continue
                    if arn.startswith("vpc-"):
                        vpc_id = arn
                        break
                    marker = ":vpc/"
                    if marker in arn:
                        vpc_id = arn.split(marker, 1)[1]
                        break
                if not vpc_id and isinstance(finding.evidence_snippet, dict):
                    sn = cast(Dict[str, Any], finding.evidence_snippet)
                    vpc_id = sn.get("VpcId") or sn.get("vpc_id")

                if isinstance(vpc_id, str) and vpc_id.startswith("vpc-"):
                    v = vpcs.get(vpc_id)
                    flow_logs = []
                    if isinstance(v, dict):
                        flow_logs = v.get("FlowLogs", []) or []

                    if isinstance(flow_logs, list) and any(
                        isinstance(fl, dict) and (fl.get("FlowLogStatus") in {"ACTIVE", "active"})
                        for fl in flow_logs
                    ):
                        logger.warning(
                            f"Rejected {finding_id} - Flow Logs are enabled and ACTIVE for {vpc_id}."
                        )
                        return False

            # NET-011: Missing descriptions on critical rules
            if finding_id == "NET-011":
                sg_doc = self.evidence.get("security-groups")
                sgs = _by_id(sg_doc, "GroupId")

                sg_ids: List[str] = []
                for arn in finding.affected_resources or []:
                    if not isinstance(arn, str):
                        continue
                    marker = ":security-group/"
                    if marker in arn:
                        sg_ids.append(arn.split(marker, 1)[1])

                # If none in affected_resources, try evidence refs.
                for ref in finding.evidence_refs or []:
                    if not isinstance(ref, str):
                        continue
                    if "security-groups.json#by_id." in ref:
                        sg_ids.append(
                            ref.split("security-groups.json#by_id.", 1)[1].split(".", 1)[0]
                        )
                    elif "security-groups.json#" in ref and "sg-" in ref:
                        sg_ids.append(ref.split("#", 1)[1].split(".", 1)[0])

                sg_ids = sorted({s for s in sg_ids if isinstance(s, str) and s.startswith("sg-")})
                if not sg_ids:
                    # Can't validate; don't hard-reject.
                    return True

                crit_ports = {22, 3389, 3306, 5432, 6379, 1433, 27017, 8080}

                def _perm_matches_critical(perm: Dict[str, Any]) -> bool:
                    proto = perm.get("IpProtocol")
                    if proto == "-1":
                        return True
                    if proto != "tcp":
                        return False
                    fp = perm.get("FromPort")
                    tp = perm.get("ToPort")
                    if not isinstance(fp, int) or not isinstance(tp, int):
                        return False
                    return any(fp <= p <= tp for p in crit_ports)

                def _has_missing_desc(perm: Dict[str, Any]) -> bool:
                    for r in perm.get("IpRanges", []) or []:
                        if not isinstance(r, dict):
                            continue
                        if not r.get("Description"):
                            return True
                    for r in perm.get("Ipv6Ranges", []) or []:
                        if not isinstance(r, dict):
                            continue
                        if not r.get("Description"):
                            return True
                    for r in perm.get("UserIdGroupPairs", []) or []:
                        if not isinstance(r, dict):
                            continue
                        if not r.get("Description"):
                            return True
                    return False

                found_gap = False
                for sg_id in sg_ids:
                    sg = sgs.get(sg_id)
                    if not isinstance(sg, dict):
                        continue
                    for perm in (sg.get("IngressRules", []) or []) + (
                        sg.get("EgressRules", []) or []
                    ):
                        if not isinstance(perm, dict):
                            continue
                        if not _perm_matches_critical(perm):
                            continue
                        if _has_missing_desc(perm):
                            found_gap = True
                            break
                    if found_gap:
                        break

                if not found_gap:
                    logger.warning(
                        f"Rejected {finding_id} - No critical SG rules with missing descriptions found in referenced security groups."
                    )
                    return False

            # NET-008: Critical workloads deployed in public subnets
            if finding_id == "NET-008":
                route_tables = self.evidence.get("route-tables")

                rt_items: List[Dict[str, Any]] = []
                if isinstance(route_tables, dict) and isinstance(route_tables.get("items"), list):
                    rt_items = cast(List[Dict[str, Any]], route_tables.get("items") or [])
                elif isinstance(route_tables, list):
                    rt_items = cast(List[Dict[str, Any]], route_tables)

                # Build set of public subnets (0.0.0.0/0 -> igw-*)
                public_subnets: set[str] = set()
                for rt in rt_items:
                    if not isinstance(rt, dict):
                        continue
                    routes = rt.get("Routes", []) or []
                    if not isinstance(routes, list):
                        continue
                    has_igw_default = False
                    for r in routes:
                        if not isinstance(r, dict):
                            continue
                        if r.get("DestinationCidrBlock") != "0.0.0.0/0":
                            continue
                        gw = r.get("GatewayId")
                        if isinstance(gw, str) and gw.startswith("igw-"):
                            has_igw_default = True
                            break
                    if not has_igw_default:
                        continue
                    for a in rt.get("Associations", []) or []:
                        if isinstance(a, dict) and isinstance(a.get("SubnetId"), str):
                            sid = a.get("SubnetId")
                            if isinstance(sid, str) and sid:
                                public_subnets.add(sid)
                        elif isinstance(a, str) and a.startswith("subnet-"):
                            public_subnets.add(a)

                if not public_subnets:
                    logger.warning(
                        f"Rejected {finding_id} - No public subnets detected from route tables (IGW default route)."
                    )
                    return False

                # Extract subnet ids referenced by the finding (from affected_resources and snippet)
                referenced: set[str] = set()
                for r in finding.affected_resources or []:
                    if isinstance(r, str) and ":subnet/" in r:
                        referenced.add(r.split(":subnet/", 1)[1])
                    elif isinstance(r, str) and r.startswith("subnet-"):
                        referenced.add(r)
                snippet = finding.evidence_snippet
                if isinstance(snippet, dict):
                    sid = cast(Dict[str, Any], snippet).get("SubnetId")
                    if isinstance(sid, str) and sid.startswith("subnet-"):
                        referenced.add(sid)

                if referenced and not (referenced & public_subnets):
                    logger.warning(
                        f"Rejected {finding_id} - Referenced subnets are not public per route-table IGW routing evidence."
                    )
                    return False

                # If finding doesn't reference subnets, at least require that some public subnet has ENIs
                # that look like critical workloads, otherwise it's too speculative.
                if not referenced:
                    eni_doc = self.evidence.get("network-interfaces")
                    eni_items: List[Dict[str, Any]] = []
                    if isinstance(eni_doc, dict) and isinstance(eni_doc.get("items"), list):
                        eni_items = cast(List[Dict[str, Any]], eni_doc.get("items") or [])
                    elif isinstance(eni_doc, list):
                        eni_items = cast(List[Dict[str, Any]], eni_doc)

                    found = False
                    for eni in eni_items:
                        if not isinstance(eni, dict):
                            continue
                        sid = eni.get("SubnetId")
                        if sid not in public_subnets:
                            continue
                        desc = str(eni.get("Description") or "").lower()
                        if any(
                            x in desc for x in ["rds", "elasticache", "opensearch", "redis", "db"]
                        ):
                            found = True
                            break
                    if not found:
                        logger.warning(
                            f"Rejected {finding_id} - No critical workload indicators found in public subnets."
                        )
                        return False


        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
