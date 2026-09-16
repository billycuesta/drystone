"""Exposure-specific findings normalization hooks."""

import logging
from typing import Any, Dict, List, Optional, cast

from drystone.models.findings import Finding
from drystone.validation.normalizer_hooks import DefaultNormalizerHook, NormalizerContext

logger = logging.getLogger(__name__)


class SkillNormalizerHook(DefaultNormalizerHook):
    def remap_id(self, finding_id: str, finding: Finding) -> str:
        if finding_id != "EXP-001":
            return finding_id

        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return finding_id

        meta = evidence.get("_audit_metadata")
        audit_account = None
        if isinstance(meta, dict):
            audit_account = meta.get("_account_id")
        if isinstance(audit_account, str):
            audit_account = audit_account.strip()

        snippet = finding.evidence_snippet
        if not isinstance(snippet, dict):
            return finding_id

        sn = cast(Dict[str, Any], snippet)
        policy = sn.get("BucketPolicy")
        if not isinstance(policy, dict):
            return finding_id

        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict):
                continue
            if st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                return finding_id

        principals: List[str] = []
        for st in policy.get("Statement", []) or []:
            if not isinstance(st, dict):
                continue
            if st.get("Effect") != "Allow":
                continue
            principal = st.get("Principal")
            if not isinstance(principal, dict):
                continue
            aws_p = principal.get("AWS")
            if isinstance(aws_p, str):
                principals.append(aws_p)
            elif isinstance(aws_p, list):
                principals.extend([p for p in aws_p if isinstance(p, str)])

        iam_principals = [p for p in principals if p.startswith("arn:aws:iam::")]
        if not iam_principals:
            return finding_id

        if isinstance(audit_account, str) and audit_account.isdigit():
            for p in iam_principals:
                parts = p.split(":")
                if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                    return "EXP-015"

        return "EXP-015"

    def normalize_evidence_refs(self, refs: List[str]) -> List[str]:
        evidence = self.context.evidence
        if not isinstance(evidence, dict):
            return refs

        def _rewrite(doc_key: str, filename: str, anchor: str, *, map_key: str) -> str:
            doc = evidence.get(doc_key)
            if not isinstance(doc, dict):
                return f"{filename}#{anchor}"
            idx = doc.get(map_key)
            if not isinstance(idx, dict):
                return f"{filename}#{anchor}"
            if anchor not in idx:
                return f"{filename}#{anchor}"
            return f"{filename}#{map_key}.{anchor}"

        out: List[str] = []
        for r in refs:
            if not isinstance(r, str):
                continue
            if "#" not in r:
                rr = r.strip()
                if rr.startswith("by_name."):
                    out.append(f"s3-buckets.json#{rr}")
                    continue
                if rr.startswith("by_id."):
                    key = rr.split(".", 1)[1] if "." in rr else ""
                    if key:
                        for doc_key, file_name in [
                            ("security-groups", "security-groups.json"),
                            ("rds-instances", "rds-instances.json"),
                            ("rds-snapshots", "rds-snapshots.json"),
                            ("ami-images", "ami-images.json"),
                            ("cloudfront-distributions", "cloudfront-distributions.json"),
                            ("load-balancers", "load-balancers.json"),
                        ]:
                            doc = evidence.get(doc_key)
                            if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                                if key in (doc.get("by_id") or {}):
                                    out.append(f"{file_name}#{rr}")
                                    break
                        else:
                            out.append(rr)
                        continue

                out.append(r)
                continue

            filename, anchor = r.split("#", 1)
            filename = filename.strip()
            anchor = anchor.strip()

            if anchor.startswith("by_name.") or anchor.startswith("by_id."):
                out.append(f"{filename}#{anchor}")
                continue

            if filename == "security-groups.json":
                out.append(_rewrite("security-groups", filename, anchor, map_key="by_id"))
                continue
            if filename == "rds-instances.json":
                out.append(_rewrite("rds-instances", filename, anchor, map_key="by_id"))
                continue
            if filename == "rds-snapshots.json":
                out.append(_rewrite("rds-snapshots", filename, anchor, map_key="by_id"))
                continue
            if filename == "ami-images.json":
                out.append(_rewrite("ami-images", filename, anchor, map_key="by_id"))
                continue
            if filename == "cloudfront-distributions.json":
                out.append(_rewrite("cloudfront-distributions", filename, anchor, map_key="by_id"))
                continue
            if filename == "load-balancers.json":
                out.append(_rewrite("load-balancers", filename, anchor, map_key="by_id"))
                continue
            if filename == "s3-buckets.json":
                out.append(_rewrite("s3-buckets", filename, anchor, map_key="by_name"))
                continue

            out.append(r)

        return out


    def validate_against_evidence(self, finding_id: str, finding: Finding) -> Optional[bool]:
        if not isinstance(self.evidence, dict):
            return None

        if not finding_id.startswith("EXP-"):
            return None

        # Exposure: validate internet-exposure checks against explicit evidence
        if finding_id.startswith("EXP-"):

            def _items(doc: Any) -> List[Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("items"), list):
                    return cast(List[Dict[str, Any]], doc.get("items") or [])
                if isinstance(doc, list):
                    return cast(List[Dict[str, Any]], doc)
                return []

            def _index(doc: Any, key_field: str) -> Dict[str, Dict[str, Any]]:
                if isinstance(doc, dict) and isinstance(doc.get("by_id"), dict):
                    return cast(Dict[str, Dict[str, Any]], doc.get("by_id") or {})
                idx: Dict[str, Dict[str, Any]] = {}
                for it in _items(doc):
                    if not isinstance(it, dict):
                        continue
                    k = it.get(key_field)
                    if isinstance(k, str) and k:
                        idx[k] = it
                return idx

            def _sg_has_open_cidr(sg: Dict[str, Any], *, port: int, cidr: str) -> bool:
                for perm in sg.get("IngressRules", []) or []:
                    if not isinstance(perm, dict):
                        continue
                    proto = perm.get("IpProtocol")
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")

                    port_match = False
                    if proto == "-1":
                        port_match = True
                    elif proto == "tcp" and isinstance(from_p, int) and isinstance(to_p, int):
                        port_match = from_p <= port <= to_p

                    if not port_match:
                        continue

                    for r in perm.get("IpRanges", []) or []:
                        if isinstance(r, dict) and r.get("CidrIp") == cidr:
                            return True
                    for r in perm.get("Ipv6Ranges", []) or []:
                        if isinstance(r, dict) and r.get("CidrIpv6") == cidr:
                            return True

                return False

            # EXP-002: RDS/DB publicly accessible from internet
            if finding_id == "EXP-002":
                rds_doc = self.evidence.get("rds-instances")
                sg_doc = self.evidence.get("security-groups")
                rds_items = _items(rds_doc)
                sgs_by_id = _index(sg_doc, "GroupId")

                public_insts = [
                    i
                    for i in rds_items
                    if isinstance(i, dict) and i.get("PubliclyAccessible") is True
                ]
                if not public_insts:
                    logger.warning(
                        f"Rejected {finding_id} - No RDS instances with PubliclyAccessible=true in evidence."
                    )
                    return False

                has_internet_sg = False
                for inst in public_insts:
                    for vsg in inst.get("VpcSecurityGroups", []) or []:
                        if not isinstance(vsg, dict):
                            continue
                        sg_id = vsg.get("VpcSecurityGroupId")
                        if not isinstance(sg_id, str):
                            continue
                        sg = sgs_by_id.get(sg_id)
                        if not isinstance(sg, dict):
                            continue
                        # Any TCP/all-protocol ingress from 0.0.0.0/0 or ::/0 is sufficient.
                        if _sg_has_open_cidr(sg, port=5432, cidr="0.0.0.0/0") or _sg_has_open_cidr(
                            sg, port=5432, cidr="::/0"
                        ):
                            has_internet_sg = True
                            break
                    if has_internet_sg:
                        break

                if not has_internet_sg:
                    logger.warning(
                        f"Rejected {finding_id} - No RDS-attached security group with internet ingress (0.0.0.0/0 or ::/0) found."
                    )
                    return False

            # EXP-001: Public S3 bucket exposure
            if finding_id == "EXP-001":
                s3_doc = self.evidence.get("s3-buckets")
                items = _items(s3_doc)
                if not items:
                    logger.warning(
                        f"Rejected {finding_id} - Missing s3-buckets evidence; cannot verify."
                    )
                    return False

                affected_buckets = [
                    r.replace("arn:aws:s3:::", "")
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:s3:::")
                ]
                if not affected_buckets:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any S3 bucket ARN."
                    )
                    return False

                def _is_public_acl(grants: Any) -> bool:
                    if not isinstance(grants, list):
                        return False
                    for g in grants:
                        if not isinstance(g, dict):
                            continue
                        gr = g.get("Grantee")
                        if not isinstance(gr, dict):
                            continue
                        if gr.get("Type") != "Group":
                            continue
                        uri = gr.get("URI")
                        if not isinstance(uri, str):
                            continue
                        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                            return True
                    return False

                def _has_public_policy(policy: Any) -> bool:
                    if not isinstance(policy, dict):
                        return False
                    for st in policy.get("Statement", []) or []:
                        if not isinstance(st, dict):
                            continue
                        if st.get("Effect") != "Allow":
                            continue
                        principal = st.get("Principal")
                        if principal != "*" and not (
                            isinstance(principal, dict) and principal.get("AWS") == "*"
                        ):
                            continue
                        act = st.get("Action")
                        actions = [act] if isinstance(act, str) else (act or [])
                        if (
                            "s3:*" in actions
                            or "s3:GetObject" in actions
                            or "s3:ListBucket" in actions
                        ):
                            return True
                    return False

                public = False
                for bn in affected_buckets:
                    # Prefer indexed by_name if present
                    b = None
                    if isinstance(s3_doc, dict) and isinstance(s3_doc.get("by_name"), dict):
                        b = (s3_doc.get("by_name") or {}).get(bn)
                    if not isinstance(b, dict):
                        b = next(
                            (x for x in items if isinstance(x, dict) and x.get("Name") == bn), None
                        )
                    if not isinstance(b, dict):
                        continue
                    if _is_public_acl(b.get("ACL")) or _has_public_policy(b.get("BucketPolicy")):
                        public = True
                        break

                if not public:
                    logger.warning(
                        f"Rejected {finding_id} - No public ACL/policy evidence found for referenced buckets."
                    )
                    return False

            # EXP-015: S3 cross-account bucket policy access
            if finding_id == "EXP-015":
                meta = self.evidence.get("_audit_metadata")
                audit_account = None
                if isinstance(meta, dict):
                    audit_account = meta.get("_account_id")

                # Require at least one affected cross-account IAM principal.
                principals = [
                    r
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:iam::")
                ]
                if not principals:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any IAM principal ARN."
                    )
                    return False

                if isinstance(audit_account, str) and audit_account.isdigit():
                    is_cross = False
                    for p in principals:
                        parts = p.split(":")
                        if len(parts) > 4 and parts[4].isdigit() and parts[4] != audit_account:
                            is_cross = True
                            break
                    if not is_cross:
                        logger.warning(
                            f"Rejected {finding_id} - No cross-account IAM principal detected in affected_resources."
                        )
                        return False

            # EXP-003: SSH/RDP open to 0.0.0.0/0
            if finding_id == "EXP-003":
                sg_doc = self.evidence.get("security-groups")
                sgs_by_id = _index(sg_doc, "GroupId")

                sg_id = None
                for r in finding.affected_resources or []:
                    if not isinstance(r, str):
                        continue
                    if "/sg-" in r:
                        sg_id = r.split("/", 1)[1]
                        break
                    if r.startswith("sg-"):
                        sg_id = r
                        break

                if not sg_id or sg_id not in sgs_by_id:
                    logger.warning(
                        f"Rejected {finding_id} - Cannot resolve security group id from affected_resources."
                    )
                    return False

                sg = sgs_by_id.get(sg_id) or {}
                ssh_open = _sg_has_open_cidr(sg, port=22, cidr="0.0.0.0/0") or _sg_has_open_cidr(
                    sg, port=22, cidr="::/0"
                )
                rdp_open = _sg_has_open_cidr(sg, port=3389, cidr="0.0.0.0/0") or _sg_has_open_cidr(
                    sg, port=3389, cidr="::/0"
                )
                if not (ssh_open or rdp_open):
                    logger.warning(
                        f"Rejected {finding_id} - Security group does not expose SSH/RDP to 0.0.0.0/0 or ::/0."
                    )
                    return False

            # EXP-007: Internet-facing ALB/NLB without WAF association
            if finding_id == "EXP-007":
                lbs_doc = self.evidence.get("load-balancers")
                assoc_doc = self.evidence.get("wafv2-web-acl-alb-associations")
                if not isinstance(lbs_doc, dict) or not isinstance(assoc_doc, dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing load-balancers or wafv2 association evidence; cannot verify."
                    )
                    return False

                lbs = _items(lbs_doc)
                by_alb = assoc_doc.get("by_alb_arn")
                if not isinstance(by_alb, dict):
                    by_alb = {}

                internet_albs = [
                    lb
                    for lb in lbs
                    if isinstance(lb, dict)
                    and lb.get("Type") == "application"
                    and lb.get("Scheme") == "internet-facing"
                    and isinstance(lb.get("LoadBalancerArn"), str)
                ]

                if not internet_albs:
                    logger.warning(
                        f"Rejected {finding_id} - No internet-facing ALBs detected in evidence."
                    )
                    return False

                # Require the finding to identify at least one ALB ARN.
                affected_albs = [
                    r
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:elasticloadbalancing:")
                ]
                if not affected_albs:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference a specific ALB/NLB ARN."
                    )
                    return False

                valid_gap = False
                internet_arn_set = {lb.get("LoadBalancerArn") for lb in internet_albs}
                for alb_arn in affected_albs:
                    if alb_arn not in internet_arn_set:
                        continue
                    if not (by_alb.get(alb_arn) or []):
                        valid_gap = True
                        break

                if not valid_gap:
                    logger.warning(
                        f"Rejected {finding_id} - All referenced ALBs appear to have WAF association or are not internet-facing."
                    )
                    return False

            # EXP-010: obsolete TLS policies on internet-facing ALB
            if finding_id == "EXP-010":
                lbs_doc = self.evidence.get("load-balancers")
                lis_doc = self.evidence.get("load-balancer-listeners")
                if not isinstance(lbs_doc, dict) or not isinstance(lis_doc, dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing ELBv2 evidence (load-balancers/load-balancer-listeners)."
                    )
                    return False

                lbs = _items(lbs_doc)
                scheme_by_arn = {
                    lb.get("LoadBalancerArn"): lb.get("Scheme")
                    for lb in lbs
                    if isinstance(lb, dict) and isinstance(lb.get("LoadBalancerArn"), str)
                }
                listeners = _items(lis_doc)

                old = False
                for li in listeners:
                    if not isinstance(li, dict):
                        continue
                    if li.get("Protocol") != "HTTPS":
                        continue
                    lb_arn = li.get("LoadBalancerArn")
                    if (
                        not isinstance(lb_arn, str)
                        or scheme_by_arn.get(lb_arn) != "internet-facing"
                    ):
                        continue
                    pol = li.get("SslPolicy")
                    if not isinstance(pol, str) or not pol:
                        continue
                    if (
                        "TLS-1-0" in pol
                        or "TLS-1-1" in pol
                        or pol in {"ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08"}
                    ):
                        old = True
                        break

                if not old:
                    logger.warning(
                        f"Rejected {finding_id} - No HTTPS listeners with obsolete TLS policy detected for internet-facing ALBs."
                    )
                    return False

            # EXP-013: S3 TLS enforcement missing
            if finding_id == "EXP-013":
                s3_doc = self.evidence.get("s3-buckets")
                if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing indexed s3-buckets evidence; cannot verify."
                    )
                    return False

                by_name = cast(Dict[str, Any], s3_doc.get("by_name") or {})
                affected = [
                    r.replace("arn:aws:s3:::", "")
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:s3:::")
                ]
                if not affected:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any S3 bucket ARN."
                    )
                    return False

                def _has_securetransport_deny(policy: Any) -> bool:
                    if not isinstance(policy, dict):
                        return False
                    for st in policy.get("Statement", []) or []:
                        if not isinstance(st, dict):
                            continue
                        if st.get("Effect") != "Deny":
                            continue
                        cond = st.get("Condition")
                        if not isinstance(cond, dict):
                            continue
                        b = cond.get("Bool")
                        if isinstance(b, dict) and b.get("aws:SecureTransport") == "false":
                            return True
                    return False

                missing = False
                for bn in affected:
                    b = by_name.get(bn)
                    if not isinstance(b, dict):
                        continue
                    if not _has_securetransport_deny(b.get("BucketPolicy")):
                        missing = True
                        break

                if not missing:
                    logger.warning(
                        f"Rejected {finding_id} - All referenced buckets already enforce aws:SecureTransport in policy."
                    )
                    return False

            # EXP-014: S3 audit/log buckets without versioning
            if finding_id == "EXP-014":
                s3_doc = self.evidence.get("s3-buckets")
                if not isinstance(s3_doc, dict) or not isinstance(s3_doc.get("by_name"), dict):
                    logger.warning(
                        f"Rejected {finding_id} - Missing indexed s3-buckets evidence; cannot verify."
                    )
                    return False

                by_name = cast(Dict[str, Any], s3_doc.get("by_name") or {})
                affected = [
                    r.replace("arn:aws:s3:::", "")
                    for r in (finding.affected_resources or [])
                    if isinstance(r, str) and r.startswith("arn:aws:s3:::")
                ]
                if not affected:
                    logger.warning(
                        f"Rejected {finding_id} - Finding does not reference any S3 bucket ARN."
                    )
                    return False

                needs = False
                for bn in affected:
                    b = by_name.get(bn)
                    if not isinstance(b, dict):
                        continue
                    if (b.get("Versioning") or "") != "Enabled":
                        needs = True
                        break
                if not needs:
                    logger.warning(
                        f"Rejected {finding_id} - All referenced buckets already have versioning enabled."
                    )
                    return False

            # EXP-011: public object listing
            if finding_id == "EXP-011":
                s3_doc = self.evidence.get("s3-buckets")
                items = _items(s3_doc)
                found_public_list = False
                for b in items:
                    if not isinstance(b, dict):
                        continue
                    policy = b.get("BucketPolicy")
                    if not isinstance(policy, dict):
                        continue
                    for st in policy.get("Statement", []) or []:
                        if not isinstance(st, dict):
                            continue
                        if st.get("Effect") != "Allow":
                            continue
                        principal = st.get("Principal")
                        if principal != "*" and not (
                            isinstance(principal, dict) and principal.get("AWS") == "*"
                        ):
                            continue
                        act = st.get("Action")
                        actions = [act] if isinstance(act, str) else (act or [])
                        if "s3:ListBucket" not in actions:
                            continue
                        found_public_list = True
                        break
                    if found_public_list:
                        break
                if not found_public_list:
                    logger.warning(
                        f"Rejected {finding_id} - No public s3:ListBucket permissions found in bucket policies."
                    )

        return True


def get_normalizer_hook(context: NormalizerContext) -> SkillNormalizerHook:
    return SkillNormalizerHook(context)
