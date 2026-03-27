"""WAF security skill for AWS audit.

Collects AWS WAF (WAFv2 + legacy WAF Classic) configuration and associations to
support security and compliance analysis (e.g., PCI DSS 6.4.2).
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

logger = get_logger(__name__)


class WAFSkill(BaseSkill):
    """WAF audit skill - analyzes AWS WAF posture and coverage."""

    @property
    def name(self) -> str:
        return "waf"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect AWS WAF evidence.

        Coverage:
            - WAFv2 Web ACLs (CLOUDFRONT global + REGIONAL across regions)
            - WAFv2 IP sets, rule groups, regex pattern sets
            - Associations for CloudFront + internet-facing ALBs
            - Associations for other WAF-supported entry points (API Gateway, AppSync, Cognito)
            - WAF Classic (inventory + CloudFront/ALB association mapping best-effort)
        """

        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        evidence_path = session.get_evidence_path(self.name)

        # Track collection quality to avoid ambiguous "empty means missing" conclusions.
        collection_status: Dict[str, Any] = {
            "region": aws_client.region_name,
            "wafv2_global_region": "us-east-1",
            "cloudfront": {"ok": True, "error": None, "count": 0},
            "wafv2": {
                "CLOUDFRONT": {"ok": True, "error": None, "count": 0},
                "REGIONAL": {"regions": {}},
            },
            "alb": {"regions": {}},
            "api_entrypoints": {
                "apigateway_rest": {"ok": True, "error": None, "count": 0},
                "apigateway_http": {"ok": True, "error": None, "count": 0},
                "appsync": {"ok": True, "error": None, "count": 0},
                "cognito_user_pools": {"ok": True, "error": None, "count": 0},
            },
            "waf_classic": {"ok": True, "error": None},
        }

        # Drystone wizard config is single-region; keep REGIONAL scope aligned
        # with the selected region for consistency across skills.
        regions = [aws_client.region_name or client_kwargs.get("region_name") or "us-east-1"]

        # CloudFront (global) resources are managed via WAFv2 in us-east-1.
        wafv2_global_region = "us-east-1"

        # Collect CloudFront distributions (needed to map WebACLId -> dist ARN).
        cloudfront_dists, cf_error = self._collect_cloudfront_distributions(client_kwargs)
        if cf_error:
            collection_status["cloudfront"].update({"ok": False, "error": cf_error})
        collection_status["cloudfront"]["count"] = len(cloudfront_dists)
        self._save_json(evidence_path / "cloudfront-distributions.json", cloudfront_dists)

        # Build mapping for WAFv2 CloudFront associations.
        cf_wafv2_map = self._cloudfront_wafv2_association_map(cloudfront_dists)
        cf_classic_map = self._cloudfront_classic_association_map(cloudfront_dists)
        self._save_json(evidence_path / "cloudfront-wafv2-associations.json", cf_wafv2_map)
        self._save_json(evidence_path / "cloudfront-classic-associations.json", cf_classic_map)

        # === WAFv2 WEB ACLS ===
        print("  Collecting WAFv2 Web ACLs...")
        wafv2_web_acls: List[Dict[str, Any]] = []

        # 1) Global (CLOUDFRONT)
        cf_acls, cf_acl_error = self._collect_wafv2_web_acls_for_scope(
            client_kwargs={**client_kwargs, "region_name": wafv2_global_region},
            scope="CLOUDFRONT",
            region_name=wafv2_global_region,
            association_map=cf_wafv2_map,
        )
        if cf_acl_error:
            collection_status["wafv2"]["CLOUDFRONT"].update({"ok": False, "error": cf_acl_error})
        collection_status["wafv2"]["CLOUDFRONT"]["count"] = len(cf_acls)
        wafv2_web_acls.extend(cf_acls)

        # 2) Regional (REGIONAL) across regions
        for region in regions:
            reg_acls, reg_acl_error = self._collect_wafv2_web_acls_for_scope(
                client_kwargs={**client_kwargs, "region_name": region},
                scope="REGIONAL",
                region_name=region,
                association_map=None,
            )
            collection_status["wafv2"]["REGIONAL"]["regions"].setdefault(
                region,
                {
                    "ok": True,
                    "error": None,
                    "count": 0,
                },
            )
            if reg_acl_error:
                collection_status["wafv2"]["REGIONAL"]["regions"][region].update(
                    {"ok": False, "error": reg_acl_error}
                )
            collection_status["wafv2"]["REGIONAL"]["regions"][region]["count"] = len(reg_acls)
            wafv2_web_acls.extend(reg_acls)

        self._save_json(evidence_path / "wafv2-web-acls.json", wafv2_web_acls)

        # === WAFv2 SUPPORTING OBJECTS ===
        print("  Collecting WAFv2 IP sets / rule groups / regex pattern sets...")
        wafv2_ip_sets: List[Dict[str, Any]] = []
        wafv2_rule_groups: List[Dict[str, Any]] = []
        wafv2_regex_pattern_sets: List[Dict[str, Any]] = []
        wafv2_managed_rule_groups: Dict[str, Any] = {"global": None, "regional": {}}

        # Global (CLOUDFRONT)
        ip_global, ip_global_err = self._collect_wafv2_ip_sets(
            {**client_kwargs, "region_name": wafv2_global_region}, scope="CLOUDFRONT"
        )
        rg_global, rg_global_err = self._collect_wafv2_rule_groups(
            {**client_kwargs, "region_name": wafv2_global_region}, scope="CLOUDFRONT"
        )
        rx_global, rx_global_err = self._collect_wafv2_regex_pattern_sets(
            {**client_kwargs, "region_name": wafv2_global_region}, scope="CLOUDFRONT"
        )
        # Track global supporting object status in the same bucket as CLOUDFRONT ACLs.
        if ip_global_err or rg_global_err or rx_global_err:
            # Preserve the first error to keep the status concise.
            first_err = ip_global_err or rg_global_err or rx_global_err
            if not collection_status["wafv2"]["CLOUDFRONT"].get("error"):
                collection_status["wafv2"]["CLOUDFRONT"].update({"ok": False, "error": first_err})
        wafv2_ip_sets.extend(ip_global)
        wafv2_rule_groups.extend(rg_global)
        wafv2_regex_pattern_sets.extend(rx_global)
        wafv2_managed_rule_groups["global"] = self._collect_wafv2_managed_rule_groups(
            {**client_kwargs, "region_name": wafv2_global_region}, scope="CLOUDFRONT"
        )

        # Regional
        for region in regions:
            regional_kwargs = {**client_kwargs, "region_name": region}
            ip_reg, ip_reg_err = self._collect_wafv2_ip_sets(regional_kwargs, scope="REGIONAL")
            rg_reg, rg_reg_err = self._collect_wafv2_rule_groups(regional_kwargs, scope="REGIONAL")
            rx_reg, rx_reg_err = self._collect_wafv2_regex_pattern_sets(
                regional_kwargs, scope="REGIONAL"
            )

            # Track errors for the region (even if list_web_acls succeeded).
            collection_status["wafv2"]["REGIONAL"]["regions"].setdefault(
                region,
                {
                    "ok": True,
                    "error": None,
                    "count": 0,
                },
            )
            if ip_reg_err or rg_reg_err or rx_reg_err:
                first_err = ip_reg_err or rg_reg_err or rx_reg_err
                if not collection_status["wafv2"]["REGIONAL"]["regions"][region].get("error"):
                    collection_status["wafv2"]["REGIONAL"]["regions"][region].update(
                        {"ok": False, "error": first_err}
                    )

            wafv2_ip_sets.extend(ip_reg)
            wafv2_rule_groups.extend(rg_reg)
            wafv2_regex_pattern_sets.extend(rx_reg)
            wafv2_managed_rule_groups["regional"][region] = self._collect_wafv2_managed_rule_groups(
                regional_kwargs, scope="REGIONAL"
            )

        self._save_json(evidence_path / "wafv2-ip-sets.json", wafv2_ip_sets)
        self._save_json(evidence_path / "wafv2-rule-groups.json", wafv2_rule_groups)
        self._save_json(evidence_path / "wafv2-regex-pattern-sets.json", wafv2_regex_pattern_sets)
        self._save_json(evidence_path / "wafv2-managed-rule-groups.json", wafv2_managed_rule_groups)

        # === ALB ASSOCIATIONS (internet-facing) ===
        print("  Collecting internet-facing ALB -> WAF associations...")
        alb_assoc, alb_errs = self._collect_alb_waf_associations(client_kwargs, regions)
        for region in regions:
            collection_status["alb"]["regions"].setdefault(
                region, {"ok": True, "error": None, "count": 0}
            )
        for region, err in alb_errs.items():
            collection_status["alb"]["regions"].setdefault(
                region, {"ok": True, "error": None, "count": 0}
            )
            collection_status["alb"]["regions"][region].update({"ok": False, "error": err})
        # Count ALBs observed in-scope per region.
        for region in regions:
            collection_status["alb"]["regions"][region]["count"] = len(
                [a for a in alb_assoc if a.get("Region") == region]
            )
        self._save_json(evidence_path / "alb-waf-associations.json", alb_assoc)

        # === OTHER WAF-SUPPORTED ENTRY POINTS ===
        print("  Collecting API entry points -> WAF associations...")
        api_entrypoints, api_status = self._collect_api_entrypoints_waf_associations(
            client_kwargs=client_kwargs,
            regions=regions,
            account_id=session.account_id,
        )
        self._save_json(evidence_path / "api-entrypoints-waf-associations.json", api_entrypoints)
        # Merge api_status into collection_status.api_entrypoints
        for k, v in api_status.items():
            if k in collection_status["api_entrypoints"]:
                collection_status["api_entrypoints"][k].update(v)

        # === WAF CLASSIC INVENTORY (best-effort) ===
        print("  Collecting WAF Classic inventory (legacy)...")
        waf_classic, classic_error = self._collect_waf_classic_inventory(
            client_kwargs, regions, cf_classic_map
        )
        if classic_error:
            collection_status["waf_classic"].update({"ok": False, "error": classic_error})
        self._save_json(evidence_path / "waf-classic.json", waf_classic)

        # Persist collection quality metadata (used to gate analysis and avoid false positives).
        self._save_json(evidence_path / "waf-collection-status.json", collection_status)

        # === AUDIT METADATA ===
        audit_metadata = {
            "_region": aws_client.region_name,
            "_timestamp": datetime.now().isoformat(),
            "_scope": "single-region",
            "_skill": self.name,
            "regions_scanned": regions,
            "includes_cloudfront_global": True,
            "includes_waf_classic": True,
        }
        self._save_json(evidence_path / "_audit_metadata.json", audit_metadata)

        print("\n✅ WAF collection complete")

    # -----------------
    # Helpers
    # -----------------

    def _save_json(self, filepath: Path, data: Any) -> None:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _get_regions(self, client_kwargs: Dict[str, Any]) -> List[str]:
        """Legacy helper (not used by default).

        Drystone audits are single-region. This returns the configured region.
        """
        region = client_kwargs.get("region_name")
        return [region] if region else ["us-east-1"]

    def _collect_cloudfront_distributions(
        self, client_kwargs: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        dists: List[Dict[str, Any]] = []
        try:
            cf = boto3.client(
                "cloudfront", **{k: v for k, v in client_kwargs.items() if k != "region_name"}
            )
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                for dist in page.get("DistributionList", {}).get("Items", []) or []:
                    dists.append(
                        {
                            "Id": dist.get("Id"),
                            "ARN": dist.get("ARN"),
                            "DomainName": dist.get("DomainName"),
                            "Enabled": dist.get("Enabled"),
                            "Status": dist.get("Status"),
                            "WebACLId": dist.get("WebACLId"),
                            "Origins": dist.get("Origins"),
                            "DefaultCacheBehavior": dist.get("DefaultCacheBehavior"),
                            "Aliases": dist.get("Aliases"),
                        }
                    )
        except Exception as e:
            logger.warning(f"Could not list CloudFront distributions: {e}")
            return dists, str(e)
        return dists, None

    def _cloudfront_wafv2_association_map(
        self, cloudfront_dists: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        mapping: Dict[str, List[str]] = {}
        for dist in cloudfront_dists:
            web_acl = dist.get("WebACLId") or ""
            if isinstance(web_acl, str) and web_acl.startswith("arn:aws:wafv2"):
                arn = dist.get("ARN")
                if isinstance(arn, str) and arn:
                    mapping.setdefault(web_acl, []).append(arn)
        # Remove nulls
        for k in list(mapping.keys()):
            mapping[k] = [v for v in mapping[k] if v]
        return mapping

    def _cloudfront_classic_association_map(
        self, cloudfront_dists: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        mapping: Dict[str, List[str]] = {}
        for dist in cloudfront_dists:
            web_acl = dist.get("WebACLId") or ""
            # Classic uses short id, sometimes with a path.
            if isinstance(web_acl, str) and web_acl and not web_acl.startswith("arn:aws:wafv2"):
                acl_id = web_acl.split("/")[-1]
                arn = dist.get("ARN")
                if isinstance(arn, str) and arn:
                    mapping.setdefault(acl_id, []).append(arn)
        for k in list(mapping.keys()):
            mapping[k] = [v for v in mapping[k] if v]
        return mapping

    def _collect_wafv2_web_acls_for_scope(
        self,
        client_kwargs: Dict[str, Any],
        scope: str,
        region_name: str,
        association_map: Optional[Dict[str, List[str]]],
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        out: List[Dict[str, Any]] = []
        try:
            waf = boto3.client("wafv2", **client_kwargs)
            # boto3 does not always expose paginators for WAFv2 list_* calls.
            # Use manual pagination via NextMarker.
            marker: Optional[str] = None
            while True:
                params: Dict[str, Any] = {"Scope": scope, "Limit": 100}
                if marker:
                    params["NextMarker"] = marker
                page = waf.list_web_acls(**params)

                for summary in page.get("WebACLs", []) or []:
                    acl_arn = summary.get("ARN")
                    acl_id = summary.get("Id")
                    acl_name = summary.get("Name")

                    acl_detail: Dict[str, Any] = {
                        "Name": acl_name,
                        "Id": acl_id,
                        "ARN": acl_arn,
                        "Scope": scope,
                        "Region": "Global" if scope == "CLOUDFRONT" else region_name,
                        "Description": summary.get("Description"),
                        "LockToken": None,
                        "WebACL": None,
                        "Logging": None,
                        "AssociatedResourceArns": [],
                        "CloudWatchRuleMetrics": None,
                    }

                    # Web ACL config
                    try:
                        resp = waf.get_web_acl(Name=acl_name, Scope=scope, Id=acl_id)
                        acl_detail["LockToken"] = resp.get("LockToken")
                        acl_detail["WebACL"] = resp.get("WebACL")
                    except ClientError as e:
                        acl_detail["WebACL"] = {"error": str(e)}

                    # Logging config
                    acl_detail["Logging"] = self._get_wafv2_logging_configuration(waf, acl_arn)

                    # Associated resources (best-effort)
                    associated: List[str] = []
                    try:
                        if acl_arn:
                            resp = waf.list_resources_for_web_acl(WebACLArn=acl_arn)
                            associated.extend(resp.get("ResourceArns", []) or [])
                    except ClientError:
                        pass

                    # CloudFront associations are not always returned consistently; augment via CloudFront inventory.
                    if association_map and acl_arn:
                        associated.extend(association_map.get(acl_arn, []) or [])

                    acl_detail["AssociatedResourceArns"] = sorted(
                        list({a for a in associated if a})
                    )

                    # CloudWatch rule metrics (best-effort)
                    try:
                        web_acl = acl_detail.get("WebACL") or {}
                        rule_names = []
                        for rule in web_acl.get("Rules") or []:
                            rn = rule.get("Name")
                            if rn:
                                rule_names.append(rn)
                        acl_detail["CloudWatchRuleMetrics"] = self._get_wafv2_rule_metrics(
                            client_kwargs=client_kwargs,
                            scope=scope,
                            region_name=region_name,
                            web_acl_name=acl_name,
                            rule_names=rule_names,
                        )
                    except Exception:
                        acl_detail["CloudWatchRuleMetrics"] = None

                    out.append(acl_detail)

                marker = page.get("NextMarker")
                if not marker:
                    break

        except Exception as e:
            logger.warning(
                f"Could not list WAFv2 Web ACLs for scope={scope} region={region_name}: {e}"
            )
            return out, str(e)
        return out, None

    def _get_wafv2_logging_configuration(
        self, waf_client, web_acl_arn: Optional[str]
    ) -> Dict[str, Any]:
        if not web_acl_arn:
            return {"enabled": False, "reason": "missing_arn"}
        try:
            resp = waf_client.get_logging_configuration(ResourceArn=web_acl_arn)
            cfg = resp.get("LoggingConfiguration") or {}
            return {
                "enabled": True,
                "LogDestinationConfigs": cfg.get("LogDestinationConfigs", []),
                "RedactedFields": cfg.get("RedactedFields", []),
                "LoggingFilter": cfg.get("LoggingFilter"),
            }
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            # Logging config is absent for most Web ACLs; treat as disabled.
            if code in {"WAFNonexistentItemException", "WAFEntityMigrationException"}:
                return {"enabled": False, "reason": code}
            return {"enabled": False, "reason": code or "error", "error": str(e)}
        except Exception as e:
            return {"enabled": False, "reason": "error", "error": str(e)}

    def _get_wafv2_rule_metrics(
        self,
        client_kwargs: Dict[str, Any],
        scope: str,
        region_name: str,
        web_acl_name: str,
        rule_names: List[str],
    ) -> Dict[str, Any]:
        """Collect basic BlockedRequests metrics for WebACL and its rules.

        Best-effort only. CloudWatch dimensions differ between REGIONAL and CLOUDFRONT.
        """

        # CloudFront WAF metrics are queried via CloudWatch in us-east-1.
        cw_region = "us-east-1" if scope == "CLOUDFRONT" else region_name
        cw = boto3.client("cloudwatch", **{**client_kwargs, "region_name": cw_region})

        start = datetime.utcnow() - timedelta(days=7)
        end = datetime.utcnow()
        period = 86400

        def _query(rule_dimension_value: str) -> int:
            dims = [
                {"Name": "WebACL", "Value": web_acl_name},
                {"Name": "Rule", "Value": rule_dimension_value},
            ]
            # Some accounts/metrics expect a Region dimension.
            if scope == "CLOUDFRONT":
                dims.append({"Name": "Region", "Value": "Global"})
            else:
                dims.append({"Name": "Region", "Value": region_name})

            resp = cw.get_metric_statistics(
                Namespace="AWS/WAFV2",
                MetricName="BlockedRequests",
                Dimensions=dims,
                StartTime=start,
                EndTime=end,
                Period=period,
                Statistics=["Sum"],
            )
            points = resp.get("Datapoints", []) or []
            return int(sum((p.get("Sum") or 0) for p in points))

        metrics: Dict[str, Any] = {"time_window_days": 7, "blocked_requests": {}}

        # Query overall (ALL) and default action.
        for key in ["ALL", "Default_Action"]:
            try:
                metrics["blocked_requests"][key] = _query(key)
            except Exception:
                metrics["blocked_requests"][key] = None

        # Query each rule (limit to avoid excessive calls)
        max_rules = 25
        for rn in rule_names[:max_rules]:
            try:
                metrics["blocked_requests"][rn] = _query(rn)
            except Exception:
                metrics["blocked_requests"][rn] = None

        if len(rule_names) > max_rules:
            metrics["truncated_rules"] = len(rule_names) - max_rules

        return metrics

    def _collect_wafv2_ip_sets(
        self, client_kwargs: Dict[str, Any], scope: str
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        out: List[Dict[str, Any]] = []
        try:
            waf = boto3.client("wafv2", **client_kwargs)
            marker: Optional[str] = None
            while True:
                params: Dict[str, Any] = {"Scope": scope, "Limit": 100}
                if marker:
                    params["NextMarker"] = marker
                page = waf.list_ip_sets(**params)

                for s in page.get("IPSets", []) or []:
                    try:
                        detail = waf.get_ip_set(Name=s["Name"], Scope=scope, Id=s["Id"]).get(
                            "IPSet"
                        )
                        out.append(
                            {
                                "Name": detail.get("Name"),
                                "Id": detail.get("Id"),
                                "ARN": detail.get("ARN"),
                                "Scope": scope,
                                "Region": (
                                    "Global"
                                    if scope == "CLOUDFRONT"
                                    else client_kwargs.get("region_name")
                                ),
                                "Description": detail.get("Description"),
                                "IPAddressVersion": detail.get("IPAddressVersion"),
                                "Addresses": detail.get("Addresses", []),
                                "AddressCount": len(detail.get("Addresses", []) or []),
                            }
                        )
                    except Exception as e:
                        out.append(
                            {
                                "Name": s.get("Name"),
                                "Id": s.get("Id"),
                                "Scope": scope,
                                "error": str(e),
                            }
                        )

                marker = page.get("NextMarker")
                if not marker:
                    break
        except Exception as e:
            logger.warning(f"Could not collect WAFv2 IP sets for scope={scope}: {e}")
            return out, str(e)
        return out, None

    def _collect_wafv2_rule_groups(
        self, client_kwargs: Dict[str, Any], scope: str
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        out: List[Dict[str, Any]] = []
        try:
            waf = boto3.client("wafv2", **client_kwargs)
            marker: Optional[str] = None
            while True:
                params: Dict[str, Any] = {"Scope": scope, "Limit": 100}
                if marker:
                    params["NextMarker"] = marker
                page = waf.list_rule_groups(**params)

                for rg in page.get("RuleGroups", []) or []:
                    try:
                        detail = waf.get_rule_group(Name=rg["Name"], Scope=scope, Id=rg["Id"]).get(
                            "RuleGroup"
                        )
                        out.append(
                            {
                                "Name": detail.get("Name"),
                                "Id": detail.get("Id"),
                                "ARN": detail.get("ARN"),
                                "Scope": scope,
                                "Region": (
                                    "Global"
                                    if scope == "CLOUDFRONT"
                                    else client_kwargs.get("region_name")
                                ),
                                "Capacity": detail.get("Capacity"),
                                "Description": detail.get("Description"),
                                "Rules": detail.get("Rules"),
                                "VisibilityConfig": detail.get("VisibilityConfig"),
                            }
                        )
                    except Exception as e:
                        out.append(
                            {
                                "Name": rg.get("Name"),
                                "Id": rg.get("Id"),
                                "Scope": scope,
                                "error": str(e),
                            }
                        )

                marker = page.get("NextMarker")
                if not marker:
                    break
        except Exception as e:
            logger.warning(f"Could not collect WAFv2 rule groups for scope={scope}: {e}")
            return out, str(e)
        return out, None

    def _collect_wafv2_regex_pattern_sets(
        self, client_kwargs: Dict[str, Any], scope: str
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        out: List[Dict[str, Any]] = []
        try:
            waf = boto3.client("wafv2", **client_kwargs)
            marker: Optional[str] = None
            while True:
                params: Dict[str, Any] = {"Scope": scope, "Limit": 100}
                if marker:
                    params["NextMarker"] = marker
                page = waf.list_regex_pattern_sets(**params)

                for s in page.get("RegexPatternSets", []) or []:
                    try:
                        detail = waf.get_regex_pattern_set(
                            Name=s["Name"], Scope=scope, Id=s["Id"]
                        ).get("RegexPatternSet")
                        out.append(
                            {
                                "Name": detail.get("Name"),
                                "Id": detail.get("Id"),
                                "ARN": detail.get("ARN"),
                                "Scope": scope,
                                "Region": (
                                    "Global"
                                    if scope == "CLOUDFRONT"
                                    else client_kwargs.get("region_name")
                                ),
                                "Description": detail.get("Description"),
                                "RegularExpressionList": detail.get("RegularExpressionList", []),
                            }
                        )
                    except Exception as e:
                        out.append(
                            {
                                "Name": s.get("Name"),
                                "Id": s.get("Id"),
                                "Scope": scope,
                                "error": str(e),
                            }
                        )

                marker = page.get("NextMarker")
                if not marker:
                    break
        except Exception as e:
            logger.warning(f"Could not collect WAFv2 regex pattern sets for scope={scope}: {e}")
            return out, str(e)
        return out, None

    def _collect_wafv2_managed_rule_groups(
        self, client_kwargs: Dict[str, Any], scope: str
    ) -> Dict[str, Any]:
        """Collect catalog of available managed rule groups (best-effort)."""
        try:
            waf = boto3.client("wafv2", **client_kwargs)
            resp = waf.list_available_managed_rule_groups(Scope=scope)
            return {
                "Scope": scope,
                "Region": "Global" if scope == "CLOUDFRONT" else client_kwargs.get("region_name"),
                "ManagedRuleGroups": resp.get("ManagedRuleGroups", []),
            }
        except Exception as e:
            return {
                "Scope": scope,
                "Region": "Global" if scope == "CLOUDFRONT" else client_kwargs.get("region_name"),
                "error": str(e),
            }

    def _collect_alb_waf_associations(
        self, client_kwargs: Dict[str, Any], regions: List[str]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        out: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}
        for region in regions:
            try:
                elb = boto3.client("elbv2", **{**client_kwargs, "region_name": region})
                waf = boto3.client("wafv2", **{**client_kwargs, "region_name": region})
                paginator = elb.get_paginator("describe_load_balancers")
                for page in paginator.paginate():
                    for lb in page.get("LoadBalancers", []) or []:
                        if lb.get("Type") != "application":
                            continue
                        if lb.get("Scheme") != "internet-facing":
                            continue

                        lb_arn = lb.get("LoadBalancerArn")
                        assoc: Dict[str, Any] = {
                            "Region": region,
                            "LoadBalancerArn": lb_arn,
                            "DNSName": lb.get("DNSName"),
                            "Scheme": lb.get("Scheme"),
                            "Type": lb.get("Type"),
                            "State": lb.get("State"),
                            "VpcId": lb.get("VpcId"),
                            "IpAddressType": lb.get("IpAddressType"),
                            "WAFv2WebACL": None,
                        }

                        try:
                            if lb_arn:
                                resp = waf.get_web_acl_for_resource(ResourceArn=lb_arn)
                                assoc["WAFv2WebACL"] = resp.get("WebACL")
                        except ClientError as e:
                            code = e.response.get("Error", {}).get("Code")
                            assoc["WAFv2WebACL"] = {"error": code or "error", "message": str(e)}

                        out.append(assoc)
            except Exception as e:
                logger.warning(f"Could not collect ALB associations in region {region}: {e}")
                errors[region] = str(e)
        return out, errors

    def _collect_waf_classic_inventory(
        self,
        client_kwargs: Dict[str, Any],
        regions: List[str],
        cloudfront_classic_assoc: Dict[str, List[str]],
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        inventory: Dict[str, Any] = {
            "global": {"web_acls": []},
            "regional": {},
            "cloudfront_associations": cloudfront_classic_assoc,
        }

        first_error: Optional[str] = None

        # Global WAF Classic for CloudFront (service is available via us-east-1)
        try:
            waf_global = boto3.client("waf", **{**client_kwargs, "region_name": "us-east-1"})
            web_acls: List[Dict[str, Any]] = []
            marker: Optional[str] = None
            while True:
                params: Dict[str, Any] = {"Limit": 100}
                if marker:
                    params["NextMarker"] = marker
                page = waf_global.list_web_acls(**params)
                for acl in page.get("WebACLs", []) or []:
                    acl_id = acl.get("WebACLId")
                    web_acls.append(
                        {
                            "Name": acl.get("Name"),
                            "WebACLId": acl_id,
                            "AssociatedCloudFrontDistributions": cloudfront_classic_assoc.get(
                                acl_id, []
                            ),
                        }
                    )

                marker = page.get("NextMarker")
                if not marker:
                    break
            inventory["global"]["web_acls"] = web_acls
        except Exception as e:
            inventory["global"]["error"] = str(e)
            first_error = first_error or str(e)

        # Regional WAF Classic
        for region in regions:
            try:
                waf_regional = boto3.client(
                    "waf-regional", **{**client_kwargs, "region_name": region}
                )
                web_acls: List[Dict[str, Any]] = []
                marker: Optional[str] = None
                while True:
                    params: Dict[str, Any] = {"Limit": 100}
                    if marker:
                        params["NextMarker"] = marker
                    page = waf_regional.list_web_acls(**params)
                    for acl in page.get("WebACLs", []) or []:
                        web_acls.append({"Name": acl.get("Name"), "WebACLId": acl.get("WebACLId")})

                    marker = page.get("NextMarker")
                    if not marker:
                        break

                inventory["regional"][region] = {"web_acls": web_acls}

                # Best-effort: map ALB associations (classic)
                try:
                    elb = boto3.client("elbv2", **{**client_kwargs, "region_name": region})
                    paginator_lb = elb.get_paginator("describe_load_balancers")
                    assoc_list: List[Dict[str, Any]] = []
                    for page_lb in paginator_lb.paginate():
                        for lb in page_lb.get("LoadBalancers", []) or []:
                            if (
                                lb.get("Type") != "application"
                                or lb.get("Scheme") != "internet-facing"
                            ):
                                continue
                            lb_arn = lb.get("LoadBalancerArn")
                            entry: Dict[str, Any] = {
                                "LoadBalancerArn": lb_arn,
                                "DNSName": lb.get("DNSName"),
                                "WebACL": None,
                            }
                            try:
                                resp = waf_regional.get_web_acl_for_resource(ResourceArn=lb_arn)
                                entry["WebACL"] = resp.get("WebACLSummary")
                            except Exception as e:
                                entry["WebACL"] = {"error": str(e)}
                            assoc_list.append(entry)
                    inventory["regional"][region]["alb_associations"] = assoc_list
                except Exception:
                    inventory["regional"][region]["alb_associations"] = []

            except Exception as e:
                inventory["regional"][region] = {"error": str(e), "web_acls": []}
                first_error = first_error or str(e)

        return inventory, first_error

    def _collect_api_entrypoints_waf_associations(
        self,
        client_kwargs: Dict[str, Any],
        regions: List[str],
        account_id: str,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        """Collect WAF associations for WAF-supported API entry points.

        This expands the skill beyond ALB/CloudFront and reduces false positives by
        explicitly inventorying additional in-scope entry points.
        """

        out: List[Dict[str, Any]] = []
        status: Dict[str, Dict[str, Any]] = {
            "apigateway_rest": {"ok": True, "error": None, "count": 0},
            "apigateway_http": {"ok": True, "error": None, "count": 0},
            "appsync": {"ok": True, "error": None, "count": 0},
            "cognito_user_pools": {"ok": True, "error": None, "count": 0},
        }

        for region in regions:
            try:
                waf = boto3.client("wafv2", **{**client_kwargs, "region_name": region})
            except Exception as e:
                # If we cannot create the WAFv2 client, we cannot evaluate any associations.
                err = str(e)
                for k in status.keys():
                    status[k].update({"ok": False, "error": err})
                continue

            # === API Gateway (REST) ===
            try:
                apigw = boto3.client("apigateway", **{**client_kwargs, "region_name": region})
                paginator = apigw.get_paginator("get_rest_apis")
                for page in paginator.paginate(limit=500):
                    for api in page.get("items", []) or []:
                        endpoint_types = (api.get("endpointConfiguration") or {}).get("types") or []
                        # Exclude private APIs (not internet-facing).
                        if "PRIVATE" in endpoint_types:
                            continue

                        api_id = api.get("id")
                        if not api_id:
                            continue

                        stages = apigw.get_stages(restApiId=api_id).get("item", []) or []
                        for st in stages:
                            stage_name = st.get("stageName")
                            if not stage_name:
                                continue

                            stage_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}/stages/{stage_name}"
                            entry: Dict[str, Any] = {
                                "Service": "apigateway",
                                "ApiType": "REST",
                                "Region": region,
                                "ApiId": api_id,
                                "Name": api.get("name"),
                                "Stage": stage_name,
                                "EndpointTypes": endpoint_types,
                                "ResourceArn": stage_arn,
                                "WAFv2WebACL": None,
                            }
                            try:
                                resp = waf.get_web_acl_for_resource(ResourceArn=stage_arn)
                                entry["WAFv2WebACL"] = resp.get("WebACL")
                            except ClientError as e:
                                code = e.response.get("Error", {}).get("Code")
                                entry["WAFv2WebACL"] = {"error": code or "error", "message": str(e)}
                            out.append(entry)
            except Exception as e:
                status["apigateway_rest"].update({"ok": False, "error": str(e)})

            # === API Gateway v2 (HTTP/WebSocket) ===
            try:
                apigwv2 = boto3.client("apigatewayv2", **{**client_kwargs, "region_name": region})
                paginator = apigwv2.get_paginator("get_apis")
                for page in paginator.paginate(MaxResults="500"):
                    for api in page.get("Items", []) or []:
                        api_id = api.get("ApiId")
                        if not api_id:
                            continue

                        stages = apigwv2.get_stages(ApiId=api_id).get("Items", []) or []
                        for st in stages:
                            stage_name = st.get("StageName")
                            if not stage_name:
                                continue

                            stage_arn = (
                                f"arn:aws:apigateway:{region}::/apis/{api_id}/stages/{stage_name}"
                            )
                            entry = {
                                "Service": "apigateway",
                                "ApiType": api.get("ProtocolType"),
                                "Region": region,
                                "ApiId": api_id,
                                "Name": api.get("Name"),
                                "Stage": stage_name,
                                "ResourceArn": stage_arn,
                                "DisableExecuteApiEndpoint": api.get("DisableExecuteApiEndpoint"),
                                "ApiEndpoint": api.get("ApiEndpoint"),
                                "WAFv2WebACL": None,
                            }
                            try:
                                resp = waf.get_web_acl_for_resource(ResourceArn=stage_arn)
                                entry["WAFv2WebACL"] = resp.get("WebACL")
                            except ClientError as e:
                                code = e.response.get("Error", {}).get("Code")
                                entry["WAFv2WebACL"] = {"error": code or "error", "message": str(e)}
                            out.append(entry)
            except Exception as e:
                status["apigateway_http"].update({"ok": False, "error": str(e)})

            # === AppSync ===
            try:
                appsync = boto3.client("appsync", **{**client_kwargs, "region_name": region})
                paginator = appsync.get_paginator("list_graphql_apis")
                for page in paginator.paginate(maxResults=25):
                    for api in page.get("graphqlApis", []) or []:
                        api_id = api.get("apiId")
                        arn = api.get("arn") or (
                            f"arn:aws:appsync:{region}:{account_id}:apis/{api_id}"
                            if api_id
                            else None
                        )
                        if not arn:
                            continue
                        entry = {
                            "Service": "appsync",
                            "Region": region,
                            "ApiId": api_id,
                            "Name": api.get("name"),
                            "AuthenticationType": api.get("authenticationType"),
                            "ResourceArn": arn,
                            "WAFv2WebACL": None,
                        }
                        try:
                            resp = waf.get_web_acl_for_resource(ResourceArn=arn)
                            entry["WAFv2WebACL"] = resp.get("WebACL")
                        except ClientError as e:
                            code = e.response.get("Error", {}).get("Code")
                            entry["WAFv2WebACL"] = {"error": code or "error", "message": str(e)}
                        out.append(entry)
            except Exception as e:
                status["appsync"].update({"ok": False, "error": str(e)})

            # === Cognito User Pools ===
            try:
                cognito = boto3.client("cognito-idp", **{**client_kwargs, "region_name": region})
                paginator = cognito.get_paginator("list_user_pools")
                for page in paginator.paginate(MaxResults=60):
                    for up in page.get("UserPools", []) or []:
                        up_id = up.get("Id")
                        if not up_id:
                            continue
                        arn = f"arn:aws:cognito-idp:{region}:{account_id}:userpool/{up_id}"
                        entry = {
                            "Service": "cognito-idp",
                            "Region": region,
                            "UserPoolId": up_id,
                            "Name": up.get("Name"),
                            "ResourceArn": arn,
                            "WAFv2WebACL": None,
                        }
                        try:
                            resp = waf.get_web_acl_for_resource(ResourceArn=arn)
                            entry["WAFv2WebACL"] = resp.get("WebACL")
                        except ClientError as e:
                            code = e.response.get("Error", {}).get("Code")
                            entry["WAFv2WebACL"] = {"error": code or "error", "message": str(e)}
                        out.append(entry)
            except Exception as e:
                status["cognito_user_pools"].update({"ok": False, "error": str(e)})

        # Fill counts
        status["apigateway_rest"]["count"] = len(
            [e for e in out if e.get("Service") == "apigateway" and e.get("ApiType") == "REST"]
        )
        status["apigateway_http"]["count"] = len(
            [e for e in out if e.get("Service") == "apigateway" and e.get("ApiType") != "REST"]
        )
        status["appsync"]["count"] = len([e for e in out if e.get("Service") == "appsync"])
        status["cognito_user_pools"]["count"] = len(
            [e for e in out if e.get("Service") == "cognito-idp"]
        )

        return out, status


__all__ = ["WAFSkill"]
