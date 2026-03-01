"""Post-processor for WAF skill to add architecture diagram.

Generates an ASCII flow diagram that visualizes what the WAF protects
(CloudFront and/or internet-facing ALBs) based on collected evidence.
"""

import json
from typing import Any, Dict, List

from drystone.storage.session import AuditSession


class WAFPostProcessor:
    """Post-processor for WAF skill to add architecture diagram."""

    def __init__(self, session: AuditSession):
        self.session = session
        self.evidence_path = session.get_evidence_path("waf")

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
            "cloudfront_distributions": "cloudfront-distributions.json",
            "alb_waf_associations": "alb-waf-associations.json",
            "wafv2_web_acls": "wafv2-web-acls.json",
            "api_entrypoints": "api-entrypoints-waf-associations.json",
            "collection_status": "waf-collection-status.json",
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

    def _analyze(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        meta = evidence.get("audit_metadata") or {}
        region = meta.get("_region") or "unknown"

        dists = evidence.get("cloudfront_distributions") or []
        albs = evidence.get("alb_waf_associations") or []
        acls = evidence.get("wafv2_web_acls") or []
        apis = evidence.get("api_entrypoints") or []
        status = evidence.get("collection_status") or {}

        cf_total = len(dists) if isinstance(dists, list) else 0
        cf_protected = 0
        for d in dists if isinstance(dists, list) else []:
            web_acl = d.get("WebACLId")
            if isinstance(web_acl, str) and web_acl.strip():
                cf_protected += 1

        alb_total = len(albs) if isinstance(albs, list) else 0
        alb_protected = 0
        alb_errors = 0
        for a in albs if isinstance(albs, list) else []:
            waf_acl = a.get("WAFv2WebACL")
            if isinstance(waf_acl, dict) and waf_acl.get("ARN"):
                alb_protected += 1
            elif isinstance(waf_acl, dict) and waf_acl.get("error"):
                alb_errors += 1

        waf_acl_total = len(acls) if isinstance(acls, list) else 0
        waf_acl_logging_enabled = 0
        log_destinations: List[str] = []
        for acl in acls if isinstance(acls, list) else []:
            logging_cfg = (acl or {}).get("Logging") or {}
            if isinstance(logging_cfg, dict) and logging_cfg.get("enabled") is True:
                waf_acl_logging_enabled += 1
                for dest in logging_cfg.get("LogDestinationConfigs", []) or []:
                    if isinstance(dest, str) and dest:
                        log_destinations.append(dest)

        # Deduplicate destinations (keep stable order)
        seen = set()
        uniq_destinations = []
        for d in log_destinations:
            if d in seen:
                continue
            seen.add(d)
            uniq_destinations.append(d)

        api_total = len(apis) if isinstance(apis, list) else 0
        api_protected = 0
        api_errors = 0
        svc_counts: Dict[str, Dict[str, int]] = {}
        for e in apis if isinstance(apis, list) else []:
            svc = str(e.get("Service") or "unknown")
            svc_counts.setdefault(svc, {"total": 0, "protected": 0})
            svc_counts[svc]["total"] += 1

            waf_acl = e.get("WAFv2WebACL")
            if isinstance(waf_acl, dict) and waf_acl.get("ARN"):
                api_protected += 1
                svc_counts[svc]["protected"] += 1
            elif isinstance(waf_acl, dict) and waf_acl.get("error"):
                api_errors += 1

        return {
            "region": region,
            "collection_status": status,
            "cloudfront_distributions_total": cf_total,
            "cloudfront_distributions_protected": cf_protected,
            "alb_internet_facing_total": alb_total,
            "alb_internet_facing_protected": alb_protected,
            "alb_association_errors": alb_errors,
            "api_entrypoints_total": api_total,
            "api_entrypoints_protected": api_protected,
            "api_entrypoints_errors": api_errors,
            "api_entrypoints_by_service": svc_counts,
            "wafv2_web_acls_total": waf_acl_total,
            "wafv2_web_acls_logging_enabled": waf_acl_logging_enabled,
            "waf_log_destinations": uniq_destinations,
        }

    def _critical_gaps(self, a: Dict[str, Any]) -> List[str]:
        gaps: List[str] = []

        alb_total = int(a.get("alb_internet_facing_total") or 0)
        alb_prot = int(a.get("alb_internet_facing_protected") or 0)
        cf_total = int(a.get("cloudfront_distributions_total") or 0)
        cf_prot = int(a.get("cloudfront_distributions_protected") or 0)

        if alb_total > 0 and alb_prot == 0:
            gaps.append("No internet-facing ALBs are protected by WAF")
        if cf_total > 0 and cf_prot == 0:
            gaps.append("No CloudFront distributions are protected by WAF")

        api_total = int(a.get("api_entrypoints_total") or 0)
        api_prot = int(a.get("api_entrypoints_protected") or 0)
        if api_total > 0 and api_prot == 0:
            gaps.append(
                "No public API entry points are protected by WAF (API Gateway/AppSync/Cognito)"
            )

        return gaps

    def _short_dest(self, arn: str) -> str:
        # Keep the diagram readable.
        if len(arn) <= 70:
            return arn
        return arn[:32] + "..." + arn[-28:]

    def _generate_diagram(self, a: Dict[str, Any]) -> str:
        region = a.get("region") or "unknown"
        coll_status = a.get("collection_status") or {}

        cf_total = int(a.get("cloudfront_distributions_total") or 0)
        cf_prot = int(a.get("cloudfront_distributions_protected") or 0)
        alb_total = int(a.get("alb_internet_facing_total") or 0)
        alb_prot = int(a.get("alb_internet_facing_protected") or 0)
        alb_errors = int(a.get("alb_association_errors") or 0)
        api_total = int(a.get("api_entrypoints_total") or 0)
        api_prot = int(a.get("api_entrypoints_protected") or 0)
        api_errors = int(a.get("api_entrypoints_errors") or 0)
        waf_acl_total = int(a.get("wafv2_web_acls_total") or 0)
        waf_log_on = int(a.get("wafv2_web_acls_logging_enabled") or 0)
        destinations = a.get("waf_log_destinations") or []

        svc_counts = a.get("api_entrypoints_by_service") or {}
        api_service_parts = []
        for svc, counts in sorted(svc_counts.items()):
            total = int((counts or {}).get("total") or 0)
            if total > 0:
                api_service_parts.append(f"{svc}={total}")
        api_services_line = ", ".join(api_service_parts) if api_service_parts else "none"

        def coverage_icon(total: int, protected: int) -> str:
            if total <= 0:
                return "➖"
            if protected <= 0:
                return "❌"
            if protected < total:
                return "⚠️"
            return "✅"

        cf_icon = coverage_icon(cf_total, cf_prot)
        alb_icon = coverage_icon(alb_total, alb_prot)
        api_icon = coverage_icon(api_total, api_prot)
        log_icon = coverage_icon(waf_acl_total, waf_log_on)

        lines: List[str] = []
        lines.append("WAF TRAFFIC FLOW (STEP-BY-STEP)")
        lines.append("────────────────────────────────────────────────────────────────")
        lines.append(f"Region in scope: {region}")
        lines.append("")
        lines.append("1) Client traffic arrives from the Internet")
        lines.append("           │")
        lines.append("           v")
        lines.append("2) Entry point receives traffic WITH WAF attached at that entry point")
        lines.append("   (CloudFront distribution, internet-facing ALB, or API endpoint)")
        lines.append(f"   - CloudFront distributions: {cf_total}")
        lines.append(f"   - Internet-facing ALBs:    {alb_total}")
        lines.append(f"   - Public API entrypoints:  {api_total} ({api_services_line})")
        lines.append("           │")
        lines.append("           v")
        lines.append("3) AWS WAF evaluates the request before backend access")
        lines.append("   - Result: BLOCKED or ALLOWED")
        lines.append("           │")
        lines.append("           v")
        lines.append("4) If ALLOWED, traffic is forwarded to platform services")
        lines.append("   - CloudFront -> configured origins (ALB/API/static) [if used]")
        lines.append("   - ALB -> target groups -> backend services [if used]")
        lines.append("   - API Gateway/AppSync/Cognito -> backend integrations [if used]")
        lines.append("           │")
        lines.append("           v")
        lines.append("5) Backend processes request and returns response")
        lines.append("           │")
        lines.append("           v")
        lines.append("6) WAF metrics/logs are recorded (CloudWatch / Firehose / S3)")
        lines.append("")
        lines.append("OBSERVED COVERAGE")
        lines.append(f"  {cf_icon} CloudFront protected: {cf_prot}/{cf_total}")
        lines.append(
            f"  {alb_icon} ALB protected:        {alb_prot}/{alb_total} (assoc errors: {alb_errors})"
        )
        lines.append(
            f"  {api_icon} API protected:        {api_prot}/{api_total} (assoc errors: {api_errors})"
        )
        lines.append(f"  {log_icon} WAF logging enabled:  {waf_log_on}/{waf_acl_total}")

        if isinstance(coll_status, dict):
            try:
                has_failure = False
                if (coll_status.get("cloudfront") or {}).get("ok") is False:
                    has_failure = True
                if ((coll_status.get("wafv2") or {}).get("CLOUDFRONT") or {}).get("ok") is False:
                    has_failure = True
                for _, r in (
                    ((coll_status.get("wafv2") or {}).get("REGIONAL") or {})
                    .get("regions", {})
                    .items()
                ):
                    if isinstance(r, dict) and r.get("ok") is False:
                        has_failure = True
                        break
                if has_failure:
                    lines.append("")
                    lines.append("EVIDENCE WARNING")
                    lines.append(
                        "  - Some API calls failed during collection; missing resources may be UNVERIFIED."
                    )
            except Exception:
                pass

        if destinations:
            lines.append("")
            lines.append("LOG DESTINATIONS (observed)")
            for d in destinations[:5]:
                lines.append(f"  - {self._short_dest(d)}")
            if len(destinations) > 5:
                lines.append(f"  - ... ({len(destinations) - 5} more)")

        lines.append("")
        lines.append("LEGEND: ✅ full | ⚠️ partial | ❌ missing | ➖ n/a")

        return "\n".join(lines).strip()
