# ruff: noqa
"""Recon deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# RECON PRE-CHECKS
# ============================================================================


@_register("recon")
def check_recon_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-001: DNS wildcard records exposing internal services."""
    route53 = evidence.get("route53-zones")
    if not isinstance(route53, dict):
        return PreCheckResult("RECON-001", "SKIP", "no route53-zones evidence", [])

    wildcard_count = int(route53.get("wildcard_record_count", 0) or 0)
    if wildcard_count == 0:
        return PreCheckResult("RECON-001", "PASS", "no DNS wildcard records found", [])

    # Collect wildcard record names
    wildcards = []
    for zone in route53.get("zones", []):
        if not isinstance(zone, dict):
            continue
        for rec in zone.get("Records", []):
            if not isinstance(rec, dict):
                continue
            name = str(rec.get("Name", ""))
            if name.startswith("*."):
                wildcards.append(f"{name} ({rec.get('Type', '?')}) in {zone.get('Name', '?')}")

    return PreCheckResult(
        "RECON-001",
        "FAIL",
        f"{wildcard_count} DNS wildcard records expose internal service naming",
        wildcards[:10],
    )


@_register("recon")
def check_recon_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-002: API Gateway stages without authentication in production."""
    apigw = evidence.get("api-gateway-stages")
    if not isinstance(apigw, dict):
        return PreCheckResult("RECON-002", "SKIP", "no api-gateway-stages evidence", [])

    total_apis = int(apigw.get("total_apis", 0) or 0)
    if total_apis == 0:
        return PreCheckResult("RECON-002", "SKIP", "no API Gateway APIs configured", [])

    unauth_stages = int(apigw.get("unauthenticated_stages", 0) or 0)
    if unauth_stages == 0:
        return PreCheckResult("RECON-002", "PASS", "all API Gateway stages have authentication", [])

    # Collect unauthenticated stage/route identifiers for the finding
    unauth_urls = []
    for api in apigw.get("apis", []):
        if not isinstance(api, dict):
            continue
        api_type = api.get("Type", "")
        if api_type == "REST":
            # REST APIs: use pre-collected UnauthenticatedRoutes (non-OPTIONS methods)
            for route in api.get("UnauthenticatedRoutes", []):
                unauth_urls.append(str(route))
        else:
            # HTTP APIs (v2): auth is at stage/route level
            for stage in api.get("Stages", []):
                if not isinstance(stage, dict):
                    continue
                auth = stage.get("DefaultRouteAuthorizationType")
                if auth in {"NONE", None}:
                    url = (
                        stage.get("InvokeURL")
                        or f"{api.get('Id', '?')}:{stage.get('StageName', '?')}"
                    )
                    unauth_urls.append(url)

    # Build human-readable summary
    rest_unauth = sum(
        int(a.get("UnauthenticatedRouteCount", 0) or 0)
        for a in apigw.get("apis", [])
        if isinstance(a, dict) and a.get("Type") == "REST"
    )
    http_unauth = unauth_stages - sum(
        1
        for a in apigw.get("apis", [])
        if isinstance(a, dict)
        and a.get("Type") == "REST"
        and int(a.get("UnauthenticatedRouteCount", 0) or 0) > 0
    )
    parts = []
    if rest_unauth > 0:
        parts.append(f"{rest_unauth} REST API route(s) without auth")
    if http_unauth > 0:
        parts.append(f"{http_unauth} HTTP API stage(s) without auth")
    summary = (
        "; ".join(parts)
        if parts
        else f"{unauth_stages} API Gateway stage(s) without authentication"
    )

    return PreCheckResult(
        "RECON-002",
        "FAIL",
        summary,
        unauth_urls[:10],
    )


@_register("recon")
def check_recon_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-003: Elastic IPs assigned to instances (public IP inventory)."""
    public_eps = evidence.get("public-endpoints")
    if not isinstance(public_eps, dict):
        return PreCheckResult("RECON-003", "SKIP", "no public-endpoints evidence", [])

    eip_count = int(public_eps.get("elastic_ip_count", 0) or 0)
    if eip_count == 0:
        return PreCheckResult("RECON-003", "PASS", "no Elastic IPs allocated", [])

    # Collect EIPs attached to instances (those are the risky ones)
    instance_eips = [
        str(eip.get("PublicIp", ""))
        for eip in public_eps.get("elastic_ips", [])
        if isinstance(eip, dict) and eip.get("AssociatedWithInstance")
    ]

    if not instance_eips:
        return PreCheckResult(
            "RECON-003", "PASS", f"{eip_count} EIP(s) allocated but none attached to instances", []
        )

    # Build enriched evidence snippet with SG rules chain
    enriched_eips = []
    for eip in public_eps.get("elastic_ips", []):
        if isinstance(eip, dict) and eip.get("AssociatedWithInstance"):
            enriched_eips.append(
                {
                    "PublicIp": eip.get("PublicIp"),
                    "InstanceId": eip.get("InstanceId"),
                    "InstanceName": eip.get("InstanceName", "unknown"),
                    "PermissiveSGRules": eip.get("PermissiveSGRules", []),
                }
            )

    return PreCheckResult(
        "RECON-003",
        "FAIL",
        f"{len(instance_eips)}/{eip_count} Elastic IPs attached to EC2 instances (public IPs)",
        instance_eips[:10],
        metadata={"elastic_ips_with_sg_rules": enriched_eips[:5]},  # max 5 for readability
    )


@_register("recon")
def check_recon_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-005: Lambda Function URLs publicly accessible without authentication."""
    lambda_urls = evidence.get("lambda-urls")
    if not isinstance(lambda_urls, dict):
        return PreCheckResult("RECON-005", "SKIP", "no lambda-urls evidence", [])

    total = int(lambda_urls.get("total_function_urls", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-005", "SKIP", "no Lambda Function URLs configured", [])

    public = int(lambda_urls.get("public_function_urls", 0) or 0)
    if public == 0:
        return PreCheckResult(
            "RECON-005", "PASS", f"all {total} Lambda Function URLs require authentication", []
        )

    public_fn_urls = [
        str(u.get("FunctionUrl") or u.get("FunctionName", "unknown"))
        for u in lambda_urls.get("urls", [])
        if isinstance(u, dict) and u.get("IsPublic")
    ]

    return PreCheckResult(
        "RECON-005",
        "FAIL",
        f"{public}/{total} Lambda Function URLs are publicly accessible (AuthType=NONE)",
        public_fn_urls[:10],
    )


@_register("recon")
def check_recon_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-007: Internet-facing Load Balancers without WAF."""
    lb_data = evidence.get("load-balancer-dns")
    if not isinstance(lb_data, dict):
        return PreCheckResult("RECON-007", "SKIP", "no load-balancer-dns evidence", [])

    total_lbs = int(lb_data.get("total_load_balancers", 0) or 0)
    if total_lbs == 0:
        return PreCheckResult("RECON-007", "SKIP", "no load balancers configured", [])

    public_lbs = int(lb_data.get("public_load_balancers", 0) or 0)
    if public_lbs == 0:
        return PreCheckResult("RECON-007", "PASS", "no internet-facing load balancers", [])

    no_waf = int(lb_data.get("public_without_waf", 0) or 0)
    if no_waf == 0:
        return PreCheckResult(
            "RECON-007", "PASS", "all internet-facing load balancers have WAF attached", []
        )

    no_waf_dns = [
        str(lb.get("DNSName") or lb.get("Name", "unknown"))
        for lb in lb_data.get("load_balancers", [])
        if isinstance(lb, dict) and lb.get("IsPublic") and not lb.get("WafWebAclArn")
    ]

    return PreCheckResult(
        "RECON-007",
        "FAIL",
        f"{no_waf}/{public_lbs} internet-facing load balancers without WAF",
        no_waf_dns[:10],
    )


@_register("recon")
def check_recon_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-011: HTTP (non-HTTPS) listeners on public Load Balancers."""
    lb_data = evidence.get("load-balancer-dns")
    if not isinstance(lb_data, dict):
        return PreCheckResult("RECON-011", "SKIP", "no load-balancer-dns evidence", [])

    if int(lb_data.get("public_load_balancers", 0) or 0) == 0:
        return PreCheckResult("RECON-011", "SKIP", "no internet-facing load balancers", [])

    http_only_lbs = []
    for lb in lb_data.get("load_balancers", []):
        if not isinstance(lb, dict) or not lb.get("IsPublic"):
            continue
        # Only ALBs have HTTP protocol (NLBs use TCP)
        if lb.get("Type") != "application":
            continue
        has_https = False
        has_http = False
        for lst in lb.get("Listeners", []):
            if not isinstance(lst, dict):
                continue
            proto = str(lst.get("Protocol", "")).upper()
            if proto == "HTTPS":
                has_https = True
            elif proto == "HTTP":
                has_http = True
        # Flag if HTTP listener exists but no HTTPS (no redirect)
        if has_http and not has_https:
            http_only_lbs.append(str(lb.get("DNSName") or lb.get("Name", "unknown")))

    if not http_only_lbs:
        return PreCheckResult(
            "RECON-011", "PASS", "no internet-facing ALBs with HTTP-only listeners", []
        )
    return PreCheckResult(
        "RECON-011",
        "FAIL",
        f"{len(http_only_lbs)} internet-facing ALB(s) with HTTP listeners and no HTTPS",
        http_only_lbs[:10],
    )


@_register("recon")
def check_recon_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-015: Attack surface score is HIGH or CRITICAL."""
    score_doc = evidence.get("attack-surface-score")
    if not isinstance(score_doc, dict):
        return PreCheckResult("RECON-015", "SKIP", "no attack-surface-score evidence", [])

    score = float(score_doc.get("score", 0.0) or 0.0)
    rating = str(score_doc.get("rating", "LOW"))

    if score < 5.0:
        return PreCheckResult(
            "RECON-015",
            "PASS",
            f"attack surface score {score:.1f}/10 ({rating}) — within acceptable range",
            [],
        )

    # Collect contributing factors as resources
    factors = [
        f"{f.get('factor', '?')}: {f.get('count', 0)} ({f.get('contribution', 0.0):.1f} pts)"
        for f in score_doc.get("factors", [])
        if isinstance(f, dict)
    ]

    return PreCheckResult(
        "RECON-015",
        "FAIL",
        f"attack surface score {score:.1f}/10 ({rating}) — broad external exposure",
        factors[:10],
    )


@_register("recon")
def check_recon_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-006: CloudFront distributions without logging enabled."""
    cf = evidence.get("cloudfront-origins")
    if not isinstance(cf, dict):
        return PreCheckResult("RECON-006", "SKIP", "no cloudfront-origins evidence", [])

    total = int(cf.get("total_distributions", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-006", "SKIP", "no CloudFront distributions", [])

    no_log = int(cf.get("distributions_without_logging", 0) or 0)
    if no_log == 0:
        return PreCheckResult(
            "RECON-006", "PASS", "all CloudFront distributions have logging enabled", []
        )

    no_log_ids = [
        str(d.get("DomainName") or d.get("Id", "unknown"))
        for d in cf.get("distributions", [])
        if isinstance(d, dict) and not d.get("LoggingEnabled")
    ]

    return PreCheckResult(
        "RECON-006",
        "FAIL",
        f"{no_log}/{total} CloudFront distributions without access logging",
        no_log_ids[:10],
    )


@_register("recon")
def check_recon_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-008: Large external attack surface (many entry points)."""
    score_doc = evidence.get("attack-surface-score")
    if not isinstance(score_doc, dict):
        return PreCheckResult("RECON-008", "SKIP", "no attack-surface-score evidence", [])

    total_apis = int(score_doc.get("total_public_apis", 0) or 0)
    lbs = int(score_doc.get("public_load_balancers", 0) or 0)
    lambdas = int(score_doc.get("public_lambda_urls", 0) or 0)
    eips = int(score_doc.get("elastic_ips", 0) or 0)
    cf = int(score_doc.get("cloudfront_distributions", 0) or 0)
    total_entry_points = total_apis + lbs + lambdas + eips + cf

    if total_entry_points > 10:
        return PreCheckResult(
            "RECON-008",
            "FAIL",
            f"{total_entry_points} internet-facing entry points detected (APIs={total_apis}, LBs={lbs}, Lambda={lambdas}, EIPs={eips}, CF={cf})",
            [],
            metadata={
                "total_entry_points": total_entry_points,
                "factors": score_doc.get("factors", []),
            },
        )
    return PreCheckResult(
        "RECON-008",
        "PASS",
        f"{total_entry_points} entry points — within acceptable threshold (≤10)",
        [],
    )


@_register("recon")
def check_recon_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-009: REST API Gateway stages without access logging."""
    apigw = evidence.get("api-gateway-stages")
    if not isinstance(apigw, dict):
        return PreCheckResult("RECON-009", "SKIP", "no api-gateway-stages evidence", [])

    total_apis = int(apigw.get("total_apis", 0) or 0)
    if total_apis == 0:
        return PreCheckResult("RECON-009", "SKIP", "no API Gateway APIs configured", [])

    no_log_stages = []
    for api in apigw.get("apis", []):
        if not isinstance(api, dict):
            continue
        for stage in api.get("Stages", []):
            if not isinstance(stage, dict):
                continue
            if not stage.get("AccessLogEnabled"):
                url = (
                    stage.get("InvokeURL") or f"{api.get('Id', '?')}:{stage.get('StageName', '?')}"
                )
                no_log_stages.append(url)

    if not no_log_stages:
        return PreCheckResult(
            "RECON-009", "PASS", "all API Gateway stages have access logging enabled", []
        )

    return PreCheckResult(
        "RECON-009",
        "FAIL",
        f"{len(no_log_stages)} API Gateway stage(s) without access logging",
        no_log_stages[:10],
    )


@_register("recon")
def check_recon_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-010: NAT Gateway IPs add to public IP inventory."""
    public_eps = evidence.get("public-endpoints")
    if not isinstance(public_eps, dict):
        return PreCheckResult("RECON-010", "SKIP", "no public-endpoints evidence", [])

    nat_count = int(public_eps.get("nat_gateway_ip_count", 0) or 0)
    if nat_count == 0:
        return PreCheckResult("RECON-010", "PASS", "no NAT Gateway IPs detected", [])

    nat_ips = [
        str(gw.get("PublicIp", ""))
        for gw in public_eps.get("nat_gateway_ips", [])
        if isinstance(gw, dict)
    ]

    return PreCheckResult(
        "RECON-010",
        "FAIL",
        f"{nat_count} NAT Gateway public IP(s) — document and whitelist at third-party vendors",
        nat_ips[:10],
    )


@_register("recon")
def check_recon_012(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-012: CloudFront distributions without WAF."""
    cf = evidence.get("cloudfront-origins")
    if not isinstance(cf, dict):
        return PreCheckResult("RECON-012", "SKIP", "no cloudfront-origins evidence", [])

    total = int(cf.get("total_distributions", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-012", "SKIP", "no CloudFront distributions", [])

    no_waf = [
        str(d.get("DomainName") or d.get("Id", "unknown"))
        for d in cf.get("distributions", [])
        if isinstance(d, dict) and not d.get("WebAclId")
    ]

    if not no_waf:
        return PreCheckResult(
            "RECON-012", "PASS", "all CloudFront distributions have WAF associated", []
        )

    return PreCheckResult(
        "RECON-012",
        "FAIL",
        f"{len(no_waf)}/{total} CloudFront distributions without WAF",
        no_waf[:10],
    )


@_register("recon")
def check_recon_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-013: Public Route53 zone count exceeds threshold (broad DNS footprint)."""
    r53 = evidence.get("route53-zones")
    if not isinstance(r53, dict):
        return PreCheckResult("RECON-013", "SKIP", "no route53-zones evidence", [])

    public_zones = int(r53.get("public_zones", 0) or 0)
    if public_zones > 5:
        zone_names = [
            z.get("Name", "unknown")
            for z in r53.get("zones", [])
            if isinstance(z, dict) and not z.get("IsPrivate")
        ]
        return PreCheckResult(
            "RECON-013",
            "FAIL",
            f"{public_zones} public hosted zones — broad DNS footprint (threshold: 5)",
            zone_names[:10],
        )
    return PreCheckResult(
        "RECON-013",
        "PASS",
        f"{public_zones} public hosted zones — within acceptable threshold (≤5)",
        [],
    )


@_register("recon")
def check_recon_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-014: API Gateway has more than 5 unauthenticated endpoints."""
    apigw = evidence.get("api-gateway-stages")
    if not isinstance(apigw, dict):
        return PreCheckResult("RECON-014", "SKIP", "no api-gateway-stages evidence", [])

    unauth = int(apigw.get("unauthenticated_stages", 0) or 0)
    if unauth > 5:
        return PreCheckResult(
            "RECON-014",
            "FAIL",
            f"{unauth} API Gateway stages without authentication (threshold: 5)",
            [],
        )
    return PreCheckResult(
        "RECON-014",
        "PASS",
        f"{unauth} unauthenticated API Gateway stages — within threshold (≤5)",
        [],
    )


@_register("recon")
def check_recon_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-016: Unassociated Elastic IPs (not attached to any instance or NAT Gateway)."""
    public_eps = evidence.get("public-endpoints")
    if not isinstance(public_eps, dict):
        return PreCheckResult("RECON-016", "SKIP", "no public-endpoints evidence", [])

    eips = public_eps.get("elastic_ips", [])
    if not eips:
        return PreCheckResult("RECON-016", "PASS", "no Elastic IPs allocated", [])

    # Build set of NAT GW IPs — those are "associated" even if not attached to an EC2 instance
    nat_gw_ips = {
        str(gw.get("PublicIp", ""))
        for gw in public_eps.get("nat_gateway_ips", [])
        if isinstance(gw, dict)
    }

    # Truly unassociated: not attached to instance AND no ENI (NAT GW EIPs have an ENI)
    truly_unused = [
        str(eip.get("PublicIp", ""))
        for eip in eips
        if isinstance(eip, dict)
        and not eip.get("AssociatedWithInstance")
        and not eip.get("NetworkInterfaceId")  # NAT GW EIPs always have an ENI
        and str(eip.get("PublicIp", "")) not in nat_gw_ips
    ]

    if not truly_unused:
        return PreCheckResult(
            "RECON-016",
            "PASS",
            f"{len(eips)} EIP(s) — all associated with EC2 instances or NAT Gateways",
            [],
        )

    return PreCheckResult(
        "RECON-016",
        "FAIL",
        f"{len(truly_unused)} Elastic IP(s) not attached to any instance or NAT Gateway",
        truly_unused[:10],
    )


@_register("recon")
def check_recon_017(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-017: Load Balancer exposes non-standard high-risk ports."""
    lb_data = evidence.get("load-balancer-dns")
    if not isinstance(lb_data, dict):
        return PreCheckResult("RECON-017", "SKIP", "no load-balancer-dns evidence", [])

    public_lbs = int(lb_data.get("public_load_balancers", 0) or 0)
    if public_lbs == 0:
        return PreCheckResult("RECON-017", "SKIP", "no internet-facing load balancers", [])

    high_risk_ports = {3306, 5432, 27017, 1521, 8443, 8080}
    risky = []
    for lb in lb_data.get("load_balancers", []):
        if not isinstance(lb, dict) or not lb.get("IsPublic"):
            continue
        for listener in lb.get("Listeners", []):
            if not isinstance(listener, dict):
                continue
            port = int(listener.get("Port", 0) or 0)
            if port in high_risk_ports:
                risky.append(f"{lb.get('DNSName', '?')}:{port}")

    if risky:
        return PreCheckResult(
            "RECON-017",
            "FAIL",
            f"{len(risky)} high-risk port(s) exposed on internet-facing LBs",
            risky[:10],
        )
    return PreCheckResult(
        "RECON-017",
        "PASS",
        "no high-risk ports exposed on internet-facing load balancers",
        [],
    )


@_register("recon")
def check_recon_018(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-018: Lambda Function URLs with CORS allowing all origins."""
    lambda_urls = evidence.get("lambda-urls")
    if not isinstance(lambda_urls, dict):
        return PreCheckResult("RECON-018", "SKIP", "no lambda-urls evidence", [])

    total = int(lambda_urls.get("total_function_urls", 0) or 0)
    if total == 0:
        return PreCheckResult("RECON-018", "SKIP", "no Lambda Function URLs configured", [])

    wildcard_cors = [
        str(u.get("FunctionUrl", u.get("FunctionName", "unknown")))
        for u in lambda_urls.get("urls", [])
        if isinstance(u, dict) and "*" in (u.get("Cors") or {}).get("AllowOrigins", [])
    ]

    if wildcard_cors:
        return PreCheckResult(
            "RECON-018",
            "FAIL",
            f"{len(wildcard_cors)} Lambda Function URL(s) with CORS AllowOrigins=['*']",
            wildcard_cors[:10],
        )
    return PreCheckResult(
        "RECON-018",
        "PASS",
        "no Lambda Function URLs with wildcard CORS origins",
        [],
    )


@_register("recon")
def check_recon_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-004: Route53 public zones with records revealing internal architecture."""
    r53 = evidence.get("route53-zones")
    if not isinstance(r53, dict):
        return PreCheckResult("RECON-004", "SKIP", "no route53-zones evidence", [])

    public_zones = int(r53.get("public_zones", 0) or 0)
    if public_zones == 0:
        return PreCheckResult("RECON-004", "PASS", "no public Route53 zones", [])

    # Count DNS records in public zones — any public zone with records reveals architecture
    revealing_records = []
    for zone in r53.get("zones", []):
        if not isinstance(zone, dict) or zone.get("IsPrivate"):
            continue
        zone_name = zone.get("Name", "?")
        for rec in zone.get("Records", []):
            if not isinstance(rec, dict):
                continue
            rec_type = str(rec.get("Type", ""))
            rec_name = str(rec.get("Name", ""))
            # A, AAAA, CNAME, MX records in public zones reveal service endpoints
            if rec_type in {"A", "AAAA", "CNAME", "MX"}:
                revealing_records.append(f"{rec_name} ({rec_type}) in {zone_name}")

    if revealing_records:
        # Build enriched snippet with zone details and sensitivity analysis
        enriched_zones = []
        for zone in r53.get("zones", []):
            if not isinstance(zone, dict) or zone.get("IsPrivate"):
                continue
            enriched_zones.append(
                {
                    "HostedZoneId": zone.get("Id"),
                    "ZoneName": zone.get("Name"),
                    "IsPrivate": zone.get("IsPrivate", False),
                    "RecordCount": zone.get("RecordCount", 0),
                    "SensitivityAnalysis": zone.get("SensitivityAnalysis", {}),
                    "ExposedRecords": [
                        {"Name": r["Name"], "Type": r["Type"]} for r in zone.get("Records", [])[:5]
                    ],
                }
            )

        return PreCheckResult(
            "RECON-004",
            "FAIL",
            f"{len(revealing_records)} DNS record(s) in public zones reveal service endpoints",
            revealing_records[:10],
            metadata={"public_dns_zones": enriched_zones[:5]},
        )

    return PreCheckResult(
        "RECON-004",
        "PASS",
        f"{public_zones} public zone(s) present but no revealing A/AAAA/CNAME/MX records found",
        [],
    )


@_register("recon")
def check_recon_019(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-019: Public DNS zones with sensitive keywords expose architecture."""
    r53 = evidence.get("route53-zones")
    if not isinstance(r53, dict):
        return PreCheckResult("RECON-019", "SKIP", "no route53-zones evidence", [])

    critical_zones = []
    for zone in r53.get("zones", []):
        if not isinstance(zone, dict) or zone.get("IsPrivate"):
            continue
        analysis = zone.get("SensitivityAnalysis", {})
        if analysis.get("SeverityBump") in ("critical", "high"):
            critical_zones.append(
                {
                    "ZoneName": zone.get("Name"),
                    "Keywords": analysis.get("SensitiveKeywords"),
                    "GeoPatterns": analysis.get("GeoEnvPatterns"),
                    "IsPrivate": False,
                }
            )

    if critical_zones:
        return PreCheckResult(
            "RECON-019",
            "FAIL",
            f"{len(critical_zones)} public DNS zone(s) with sensitive keywords (pci/admin/internal/prod/dev)",
            [z["ZoneName"] for z in critical_zones][:10],
            metadata={"sensitive_public_zones": critical_zones[:5]},
        )

    return PreCheckResult(
        "RECON-019",
        "PASS",
        "no public zones with sensitive keywords detected",
        [],
    )


@_register("recon")
def check_recon_020(evidence: Dict[str, Any]) -> PreCheckResult:
    """RECON-020: No public entry points detected (minimal attack surface)."""
    score_doc = evidence.get("attack-surface-score")
    if not isinstance(score_doc, dict):
        return PreCheckResult("RECON-020", "SKIP", "no attack-surface-score evidence", [])

    score = float(score_doc.get("score", 0.0) or 0.0)
    rating = str(score_doc.get("rating", ""))
    total_apis = int(score_doc.get("total_public_apis", 0) or 0)
    public_lbs = int(score_doc.get("public_load_balancers", 0) or 0)
    public_lambdas = int(score_doc.get("public_lambda_urls", 0) or 0)
    unauth_stages = int(score_doc.get("unauthenticated_api_stages", 0) or 0)

    # LOW rating with no unauthenticated entry points = PASS (minimal external exposure)
    if rating == "LOW" and unauth_stages == 0 and public_lbs == 0 and public_lambdas == 0:
        return PreCheckResult(
            "RECON-020",
            "PASS",
            f"attack surface score {score:.1f}/10 ({rating}) — minimal external exposure confirmed",
            [],
        )

    # If score is HIGH/CRITICAL, this check does not apply (RECON-015 handles that)
    if score >= 5.0:
        return PreCheckResult(
            "RECON-020",
            "SKIP",
            f"attack surface score {score:.1f}/10 ({rating}) — RECON-015 applies instead",
            [],
        )

    # Medium exposure — not minimal but not high either
    return PreCheckResult(
        "RECON-020",
        "PASS",
        f"attack surface score {score:.1f}/10 ({rating}) — {total_apis} API(s), {public_lbs} public LB(s), {public_lambdas} public Lambda URL(s)",
        [],
    )


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
