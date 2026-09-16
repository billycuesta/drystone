# ruff: noqa
"""Waf deterministic pre-checks."""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .core import PreCheckResult, _register
from .helpers import *
from .metadata import *

logger = logging.getLogger(__name__)


# WAF PRE-CHECKS
# ============================================================================


def _waf_collection_has_failures(evidence: Dict[str, Any]) -> bool:
    """Check if WAF collection status indicates failures."""
    coll_status = evidence.get("waf-collection-status")
    if not isinstance(coll_status, dict):
        return False
    try:
        if (coll_status.get("cloudfront") or {}).get("ok") is False:
            return True
        if ((coll_status.get("wafv2") or {}).get("CLOUDFRONT") or {}).get("ok") is False:
            return True
        for _, r in (
            ((coll_status.get("wafv2") or {}).get("REGIONAL") or {}).get("regions", {}).items()
        ):
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        for _, r in (coll_status.get("alb") or {}).get("regions", {}).items():
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        for _, r in (coll_status.get("api_entrypoints") or {}).items():
            if isinstance(r, dict) and r.get("ok") is False:
                return True
        if (coll_status.get("waf_classic") or {}).get("ok") is False:
            return True
    except Exception:
        return False
    return False


def _waf_classic_alb_associations(evidence: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return ALB ARNs associated with WAF Classic Web ACLs."""
    classic = evidence.get("waf-classic") or {}
    if not isinstance(classic, dict):
        return {}

    associations: Dict[str, Dict[str, Any]] = {}
    regional = classic.get("regional") or {}
    if not isinstance(regional, dict):
        return associations

    for region_data in regional.values():
        if not isinstance(region_data, dict):
            continue
        for assoc in region_data.get("alb_associations") or []:
            if not isinstance(assoc, dict):
                continue
            arn = str(assoc.get("LoadBalancerArn") or "")
            if not arn:
                continue
            web_acl = assoc.get("WebACL")
            if isinstance(web_acl, dict) and (web_acl.get("WebACLId") or web_acl.get("Name")):
                associations[arn] = assoc
    return associations


@_register("waf")
def check_waf_001(evidence: Dict[str, Any]) -> PreCheckResult:
    """Internet-facing ALBs should have WAF protection."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-001", "SKIP", "WAF collection failures (WAF-013)", [])
    albs = evidence.get("alb-waf-associations")
    if not isinstance(albs, list) or len(albs) == 0:
        return PreCheckResult("WAF-001", "PASS", "no internet-facing ALBs detected", [])
    classic_alb_associations = _waf_classic_alb_associations(evidence)
    unprotected: List[str] = []
    resource_details: List[Dict[str, Any]] = []
    for alb in albs:
        if not isinstance(alb, dict):
            continue
        arn = str(alb.get("LoadBalancerArn") or alb.get("LoadBalancerName") or "unknown")
        wafv2_acl = alb.get("WAFv2WebACL")
        has_wafv2 = isinstance(wafv2_acl, dict) and wafv2_acl.get("ARN") and not wafv2_acl.get(
            "error"
        )
        has_classic = arn in classic_alb_associations
        if has_wafv2 or has_classic:
            continue
        unprotected.append(arn)
        resource_details.append(
            {
                "load_balancer_arn": arn,
                "dns_name": alb.get("DNSName"),
                "region": alb.get("Region"),
                "scheme": alb.get("Scheme"),
                "wafv2_web_acl": wafv2_acl,
                "waf_classic_web_acl": None,
            }
        )
    if unprotected:
        return PreCheckResult(
            "WAF-001",
            "FAIL",
            f"{len(unprotected)} internet-facing ALB(s) without WAFv2 or WAF Classic protection",
            unprotected[:5],
            metadata={
                "resource_details": resource_details,
                "waf_classic_protected_albs": sorted(classic_alb_associations.keys()),
            },
        )
    return PreCheckResult("WAF-001", "PASS", "all internet-facing ALBs are WAF-protected", [])


@_register("waf")
def check_waf_002(evidence: Dict[str, Any]) -> PreCheckResult:
    """CloudFront distributions should have WAF protection."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-002", "SKIP", "WAF collection failures (WAF-013)", [])
    dists = evidence.get("cloudfront-distributions")
    if not isinstance(dists, list) or len(dists) == 0:
        return PreCheckResult("WAF-002", "PASS", "no CloudFront distributions detected", [])
    # Full deterministic check: WebACLId must be non-empty
    unprotected = [
        d.get("DomainName") or d.get("Id", "unknown") for d in dists if not d.get("WebACLId")
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-002",
            "FAIL",
            f"{len(unprotected)} CloudFront distribution(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-002", "PASS", "all CloudFront distributions are WAF-protected", [])


@_register("waf")
def check_waf_003(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAFv2 Web ACL logging should be enabled."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-003", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-003", "PASS", "no Web ACLs (N/A)", [])
    not_logging = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not (acl.get("Logging") or {}).get("enabled", False)
    ]
    if not_logging:
        return PreCheckResult(
            "WAF-003",
            "FAIL",
            f"{len(not_logging)} Web ACL(s) without logging enabled",
            not_logging[:5],
        )
    return PreCheckResult("WAF-003", "PASS", "all Web ACLs have logging enabled", [])


@_register("waf")
def check_waf_004(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF logging RedactedFields should cover sensitive headers."""
    _sensitive_headers = {"cookie", "x-api-key", "authorization", "x-auth-token"}
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-004", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-004", "PASS", "no Web ACLs (N/A)", [])
    incomplete: list = []
    all_missing: set = set()
    resource_details: List[Dict[str, Any]] = []
    for acl in web_acls:
        logging_cfg = acl.get("Logging") or {}
        if not logging_cfg.get("enabled", False):
            continue  # WAF-003 covers disabled logging
        redacted = {
            (r.get("SingleHeader") or {}).get("Name", "").lower()
            for r in (logging_cfg.get("RedactedFields") or [])
        }
        missing = _sensitive_headers - redacted
        if missing:
            all_missing |= missing
            arn = acl.get("ARN") or acl.get("Name", "unknown")
            incomplete.append(arn)
            resource_details.append(
                {
                    "web_acl_arn": arn,
                    "name": acl.get("Name"),
                    "logging_enabled": True,
                    "redacted_fields": logging_cfg.get("RedactedFields") or [],
                    "missing_redactions": sorted(missing),
                }
            )
    if incomplete:
        missing_str = "/".join(sorted(all_missing))
        return PreCheckResult(
            "WAF-004",
            "FAIL",
            f"{len(incomplete)} Web ACL(s) with incomplete log redaction (missing: {missing_str})",
            incomplete[:5],
            metadata={"resource_details": resource_details},
        )
    return PreCheckResult("WAF-004", "PASS", "all Web ACLs have complete log redaction", [])


@_register("waf")
def check_waf_005(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACL VisibilityConfig should have SampledRequestsEnabled=true."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-005", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-005", "PASS", "no Web ACLs (N/A)", [])
    failing = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not (acl.get("WebACL") or {})
        .get("VisibilityConfig", {})
        .get("SampledRequestsEnabled", True)
    ]
    if failing:
        return PreCheckResult(
            "WAF-005",
            "FAIL",
            f"{len(failing)} Web ACL(s) with SampledRequestsEnabled=false",
            failing[:5],
        )
    return PreCheckResult("WAF-005", "PASS", "all Web ACLs have sampled requests enabled", [])


_WAF_BASELINE_MANAGED_RULES = {
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
}


@_register("waf")
def check_waf_006(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs should include at least one baseline AWS Managed Rule group."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-006", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-006", "PASS", "no Web ACLs (N/A)", [])
    missing_baseline = []
    resource_details: List[Dict[str, Any]] = []
    for acl in web_acls:
        rules = (acl.get("WebACL") or {}).get("Rules", [])
        used_managed = {
            str((r.get("Statement") or {}).get("ManagedRuleGroupStatement", {}).get("Name", ""))
            for r in rules
        }
        used_aws_baseline = used_managed & _WAF_BASELINE_MANAGED_RULES
        if not used_aws_baseline:
            arn = acl.get("ARN") or acl.get("Name", "unknown")
            missing_baseline.append(arn)
            managed_groups = [
                {
                    "vendor": (r.get("Statement") or {})
                    .get("ManagedRuleGroupStatement", {})
                    .get("VendorName"),
                    "name": (r.get("Statement") or {})
                    .get("ManagedRuleGroupStatement", {})
                    .get("Name"),
                }
                for r in rules
                if (r.get("Statement") or {}).get("ManagedRuleGroupStatement")
            ]
            resource_details.append(
                {
                    "web_acl_arn": arn,
                    "name": acl.get("Name"),
                    "managed_rule_groups": managed_groups,
                    "missing_aws_baseline_rule_groups": sorted(_WAF_BASELINE_MANAGED_RULES),
                }
            )
    if missing_baseline:
        return PreCheckResult(
            "WAF-006",
            "FAIL",
            f"{len(missing_baseline)} Web ACL(s) lack baseline AWS Managed Rules",
            missing_baseline[:5],
            metadata={"resource_details": resource_details},
        )
    return PreCheckResult("WAF-006", "PASS", "all Web ACLs have baseline managed rules", [])


@_register("waf")
def check_waf_007(evidence: Dict[str, Any]) -> PreCheckResult:
    """Managed rule groups should not be overridden to Count-only mode in production."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-007", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-007", "PASS", "no Web ACLs (N/A)", [])
    count_only: list = []
    for acl in web_acls:
        rules = (acl.get("WebACL") or {}).get("Rules", [])
        for rule in rules:
            override = rule.get("OverrideAction") or {}
            if "Count" in override:
                count_only.append(f"{acl.get('Name', 'unknown')}/{rule.get('Name', 'unknown')}")
    if count_only:
        return PreCheckResult(
            "WAF-007",
            "FAIL",
            f"{len(count_only)} managed rule group(s) in Count-only mode",
            count_only[:5],
        )
    return PreCheckResult("WAF-007", "PASS", "no managed rule groups in Count-only mode", [])


@_register("waf")
def check_waf_008(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs should include at least one rate-based rule to limit abuse."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-008", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-008", "PASS", "no Web ACLs (N/A)", [])
    no_rate_rules = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not any(
            "RateBasedStatement" in (r.get("Statement") or {})
            for r in (acl.get("WebACL") or {}).get("Rules", [])
        )
    ]
    if no_rate_rules:
        return PreCheckResult(
            "WAF-008",
            "FAIL",
            f"{len(no_rate_rules)} Web ACL(s) without rate-based rules",
            no_rate_rules[:5],
        )
    return PreCheckResult("WAF-008", "PASS", "all Web ACLs have rate-based rules", [])


@_register("waf")
def check_waf_009(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF IP sets should not contain overly broad CIDRs (0.0.0.0/0 or ::/0)."""
    _broad_cidrs = {"0.0.0.0/0", "::/0"}
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-009", "SKIP", "WAF collection failures", [])
    ip_sets = evidence.get("wafv2-ip-sets")
    if not isinstance(ip_sets, list) or len(ip_sets) == 0:
        return PreCheckResult("WAF-009", "PASS", "no WAFv2 IP sets", [])
    broad = [
        ip_set.get("Name", "unknown")
        for ip_set in ip_sets
        if _broad_cidrs & set(ip_set.get("Addresses", []))
    ]
    if broad:
        return PreCheckResult(
            "WAF-009",
            "FAIL",
            f"{len(broad)} IP set(s) with broad CIDRs (0.0.0.0/0 or ::/0)",
            broad[:5],
        )
    return PreCheckResult("WAF-009", "PASS", "no IP sets with broad CIDRs", [])


@_register("waf")
def check_waf_010(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF Classic Web ACLs should be migrated to WAFv2."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-010", "SKIP", "WAF collection failures", [])
    classic = evidence.get("waf-classic") or {}
    global_acls = (classic.get("global") or {}).get("web_acls", [])
    regional_acls: list = []
    for region_data in (classic.get("regional") or {}).values():
        regional_acls.extend((region_data or {}).get("web_acls", []))
    total = len(global_acls) + len(regional_acls)
    if total > 0:
        resource_details = [
            {"scope": "CLOUDFRONT", "name": a.get("Name", "unknown"), "web_acl_id": a.get("WebACLId")}
            for a in global_acls
            if isinstance(a, dict)
        ]
        for region, region_data in (classic.get("regional") or {}).items():
            for acl in (region_data or {}).get("web_acls", []):
                if isinstance(acl, dict):
                    resource_details.append(
                        {
                            "scope": "REGIONAL",
                            "region": region,
                            "name": acl.get("Name", "unknown"),
                            "web_acl_id": acl.get("WebACLId"),
                        }
                    )
        names = [d.get("name", "unknown") for d in resource_details]
        return PreCheckResult(
            "WAF-010",
            "FAIL",
            f"{total} WAF Classic Web ACL(s) detected; migrate to WAFv2",
            names[:5],
            metadata={"resource_details": resource_details},
        )
    return PreCheckResult("WAF-010", "PASS", "no WAF Classic Web ACLs detected", [])


@_register("waf")
def check_waf_011(evidence: Dict[str, Any]) -> PreCheckResult:
    """Web ACLs with no associated resources should be reviewed for cleanup."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-011", "SKIP", "WAF collection failures", [])
    web_acls = evidence.get("wafv2-web-acls")
    if not isinstance(web_acls, list) or len(web_acls) == 0:
        return PreCheckResult("WAF-011", "PASS", "no Web ACLs (N/A)", [])
    unassociated = [
        acl.get("ARN") or acl.get("Name", "unknown")
        for acl in web_acls
        if not acl.get("AssociatedResourceArns")
    ]
    if unassociated:
        return PreCheckResult(
            "WAF-011",
            "FAIL",
            f"{len(unassociated)} Web ACL(s) with no associated resources",
            unassociated[:5],
        )
    return PreCheckResult("WAF-011", "PASS", "all Web ACLs have associated resources", [])


@_register("waf")
def check_waf_013(evidence: Dict[str, Any]) -> PreCheckResult:
    """WAF collection status indicates failures or unverifiable associations."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-013", "FAIL", "WAF collection has failures", [])
    # Detect HTTP API entries where GetWebACLForResource returned WAFInvalidParameterException.
    # This is an AWS SDK limitation: HTTP API V2 ARNs are not supported by that API call.
    # These endpoints have UNKNOWN WAF protection status and should be noted.
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if isinstance(api_eps, list):
        http_api_errors = [
            f"{e.get('Name', 'unknown')}/{e.get('Stage', '')}"
            for e in api_eps
            if e.get("ApiType") == "HTTP"
            and isinstance(e.get("WAFv2WebACL"), dict)
            and "error" in e["WAFv2WebACL"]
        ]
        if http_api_errors:
            return PreCheckResult(
                "WAF-013",
                "FAIL",
                f"WAF status unverifiable for {len(http_api_errors)} HTTP API stage(s) "
                f"(AWS GetWebACLForResource does not support HTTP API V2 ARN format): "
                f"{', '.join(http_api_errors[:3])}",
                http_api_errors[:5],
            )
    return PreCheckResult("WAF-013", "PASS", "no WAF collection failures", [])


@_register("waf")
def check_waf_014(evidence: Dict[str, Any]) -> PreCheckResult:
    """API Gateway REST stages should be protected by AWS WAF."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-014", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-014", "SKIP", "no api-entrypoints evidence", [])
    # Only evaluate REST APIs (HTTP APIs return WAFInvalidParameterException — AWS limitation)
    rest_entries = [
        e for e in api_eps if e.get("Service") == "apigateway" and e.get("ApiType") == "REST"
    ]
    if not rest_entries:
        return PreCheckResult("WAF-014", "PASS", "no API Gateway REST stages detected", [])
    unprotected = [
        f"{e.get('Name', 'unknown')}/{e.get('Stage', '')}"
        for e in rest_entries
        if not isinstance(e.get("WAFv2WebACL"), dict) or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-014",
            "FAIL",
            f"{len(unprotected)} API Gateway REST stage(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-014", "PASS", "all API Gateway REST stages are WAF-protected", [])


@_register("waf")
def check_waf_015(evidence: Dict[str, Any]) -> PreCheckResult:
    """AppSync GraphQL APIs should be protected by AWS WAF."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-015", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-015", "SKIP", "no api-entrypoints evidence", [])
    appsync_entries = [e for e in api_eps if e.get("Service") == "appsync"]
    if not appsync_entries:
        return PreCheckResult("WAF-015", "PASS", "no AppSync APIs detected (N/A)", [])
    unprotected = [
        e.get("Name", e.get("ApiId", "unknown"))
        for e in appsync_entries
        if not isinstance(e.get("WAFv2WebACL"), dict) or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-015",
            "FAIL",
            f"{len(unprotected)} AppSync API(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-015", "PASS", "all AppSync APIs are WAF-protected", [])


@_register("waf")
def check_waf_016(evidence: Dict[str, Any]) -> PreCheckResult:
    """Cognito User Pools should be protected by AWS WAF when publicly exposed."""
    if _waf_collection_has_failures(evidence):
        return PreCheckResult("WAF-016", "SKIP", "WAF collection failures", [])
    api_eps = evidence.get("api-entrypoints-waf-associations")
    if not isinstance(api_eps, list):
        return PreCheckResult("WAF-016", "SKIP", "no api-entrypoints evidence", [])
    cognito_entries = [e for e in api_eps if e.get("Service") == "cognito"]
    if not cognito_entries:
        return PreCheckResult("WAF-016", "PASS", "no Cognito User Pools detected (N/A)", [])
    unprotected = [
        e.get("Name", e.get("ApiId", "unknown"))
        for e in cognito_entries
        if not isinstance(e.get("WAFv2WebACL"), dict) or "error" in (e.get("WAFv2WebACL") or {})
    ]
    if unprotected:
        return PreCheckResult(
            "WAF-016",
            "FAIL",
            f"{len(unprotected)} Cognito User Pool(s) without WAF protection",
            unprotected[:5],
        )
    return PreCheckResult("WAF-016", "PASS", "all Cognito User Pools are WAF-protected", [])


# ============================================================================

__all__ = [name for name in globals() if name.startswith("check_")]
