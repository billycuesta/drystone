"""Reconnaissance skill for AWS attack surface mapping."""

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient

logger = get_logger(__name__)


class ReconSkill(BaseSkill):
    """Reconnaissance skill — maps external attack surface before analysis.

    Collects all publicly reachable entry points: Route53 DNS, API Gateway
    endpoints, Lambda Function URLs, Load Balancers, Elastic IPs, CloudFront
    distributions. Produces an attack-surface-score.json summary used by
    the correlation engine and pentest report.
    """

    @property
    def name(self) -> str:
        return "recon"

    def collect(self, aws_client: AWSClient, session: AuditSession) -> None:
        """Collect external attack surface data.

        Evidence files written:
            route53-zones.json            Hosted zones + public A/CNAME/MX records
            api-gateway-stages.json       REST + HTTP API stages and routes
            lambda-urls.json              Function URLs (public/auth)
            load-balancer-dns.json        ALB/NLB DNS names + listeners
            public-endpoints.json         Elastic IPs + NAT Gateway IPs
            cloudfront-origins.json       CloudFront distributions + origins
            attack-surface-score.json     Aggregated scoring summary
        """
        client_kwargs: Dict[str, Any] = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        evidence_path = session.get_evidence_path(self.name)

        # === ROUTE 53 ===
        print("  Collecting Route53 hosted zones and records...")
        route53_data = self._collect_route53(client_kwargs)
        self._save_json(evidence_path / "route53-zones.json", route53_data)

        # === API GATEWAY (REST + HTTP v2) ===
        print("  Collecting API Gateway stages...")
        apigw_data = self._collect_api_gateway(client_kwargs)
        self._save_json(evidence_path / "api-gateway-stages.json", apigw_data)

        # === LAMBDA FUNCTION URLS ===
        print("  Collecting Lambda Function URLs...")
        lambda_urls = self._collect_lambda_urls(client_kwargs)
        self._save_json(evidence_path / "lambda-urls.json", lambda_urls)

        # === LOAD BALANCERS ===
        print("  Collecting Load Balancer DNS names...")
        lb_data = self._collect_load_balancers(client_kwargs)
        self._save_json(evidence_path / "load-balancer-dns.json", lb_data)

        # === PUBLIC ENDPOINTS (Elastic IPs + NAT GW) ===
        print("  Collecting public endpoints (Elastic IPs, NAT Gateways)...")
        public_eps = self._collect_public_endpoints(client_kwargs)
        self._save_json(evidence_path / "public-endpoints.json", public_eps)

        # === CLOUDFRONT DISTRIBUTIONS ===
        print("  Collecting CloudFront distributions...")
        cf_data = self._collect_cloudfront(client_kwargs)
        self._save_json(evidence_path / "cloudfront-origins.json", cf_data)

        # === ATTACK SURFACE SCORE ===
        score = self._compute_attack_surface_score(
            route53_data, apigw_data, lambda_urls, lb_data, public_eps, cf_data
        )
        self._save_json(evidence_path / "attack-surface-score.json", score)

        print(
            f"\n✅ Recon collection complete — "
            f"attack surface score: {score.get('score', 0.0):.1f}/10 "
            f"({score.get('rating', 'UNKNOWN')})"
        )

    # -------------------------------------------------------------------------
    # ROUTE 53
    # -------------------------------------------------------------------------

    def _collect_route53(self, client_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Collect hosted zones and public DNS records."""
        r53 = boto3.client(
            "route53", **{k: v for k, v in client_kwargs.items() if k != "region_name"}
        )
        zones: List[Dict[str, Any]] = []
        try:
            paginator = r53.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page.get("HostedZones", []):
                    zone_id = zone.get("Id", "").split("/")[-1]
                    is_private = zone.get("Config", {}).get("PrivateZone", False)
                    zone_entry: Dict[str, Any] = {
                        "Id": zone_id,
                        "Name": zone.get("Name"),
                        "IsPrivate": is_private,
                        "RecordCount": zone.get("ResourceRecordSetCount", 0),
                        "Records": [],
                    }
                    # Only enumerate public zones for attack surface
                    if not is_private:
                        try:
                            rec_paginator = r53.get_paginator("list_resource_record_sets")
                            for rec_page in rec_paginator.paginate(HostedZoneId=zone_id):
                                for rec in rec_page.get("ResourceRecordSets", []):
                                    rec_type = rec.get("Type", "")
                                    # Focus on record types relevant to attack surface
                                    if rec_type in {"A", "AAAA", "CNAME", "MX", "NS", "TXT"}:
                                        entry = {
                                            "Name": rec.get("Name"),
                                            "Type": rec_type,
                                        }
                                        # Include values (IPs, targets)
                                        rr = rec.get("ResourceRecords", [])
                                        if rr:
                                            entry["Values"] = [
                                                r.get("Value") for r in rr if r.get("Value")
                                            ]
                                        # Alias records (CloudFront, ALB, etc.)
                                        alias = rec.get("AliasTarget")
                                        if alias:
                                            entry["AliasTarget"] = alias.get("DNSName")
                                        zone_entry["Records"].append(entry)
                        except ClientError as e:
                            logger.warning(f"Could not list records for zone {zone_id}: {e}")
                    zones.append(zone_entry)
        except ClientError as e:
            logger.error(f"Could not list hosted zones: {e}")

        # Enrich zones with semantic analysis
        import re

        for zone in zones:
            zone["SensitivityAnalysis"] = self._classify_dns_sensitivity(
                zone_name=zone.get("Name", ""), records=zone.get("Records", [])
            )

        public_zones = [z for z in zones if not z.get("IsPrivate")]
        wildcard_records = [
            r
            for z in public_zones
            for r in z.get("Records", [])
            if str(r.get("Name", "")).startswith("*")
        ]
        return {
            "total_zones": len(zones),
            "public_zones": len(public_zones),
            "private_zones": len(zones) - len(public_zones),
            "wildcard_record_count": len(wildcard_records),
            "zones": zones,
        }

    # -------------------------------------------------------------------------
    # API GATEWAY
    # -------------------------------------------------------------------------

    def _collect_api_gateway(self, client_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Collect REST (v1) and HTTP (v2) API Gateway stages."""
        apis: List[Dict[str, Any]] = []

        # REST APIs (v1)
        try:
            apigw = boto3.client("apigateway", **client_kwargs)
            paginator = apigw.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    api_id = api.get("id")
                    api_entry: Dict[str, Any] = {
                        "Id": api_id,
                        "Name": api.get("name"),
                        "Type": "REST",
                        "EndpointType": api.get("endpointConfiguration", {}).get("types", []),
                        "Stages": [],
                    }
                    try:
                        stages = apigw.get_stages(restApiId=api_id)
                        for stage in stages.get("item", []):
                            stage_entry = {
                                "StageName": stage.get("stageName"),
                                "InvokeURL": f"https://{api_id}.execute-api.{client_kwargs.get('region_name')}.amazonaws.com/{stage.get('stageName')}",
                                "CacheClusterEnabled": stage.get("cacheClusterEnabled", False),
                                "AccessLogEnabled": bool(stage.get("accessLogSettings")),
                                "WebAclArn": stage.get("webAclArn"),
                                "DefaultRouteAuthorizationType": None,  # REST doesn't have single auth
                            }
                            api_entry["Stages"].append(stage_entry)
                    except ClientError as e:
                        logger.warning(f"Could not get stages for REST API {api_id}: {e}")
                    # Collect REST API resource/method-level auth to detect unauth routes.
                    # OPTIONS methods are excluded (CORS preflight — not a real auth gap).
                    try:
                        resources_resp = apigw.get_resources(restApiId=api_id, embed=["methods"])
                        unauth_rest_routes: List[Dict[str, Any]] = []
                        for resource in resources_resp.get("items", []):
                            path = resource.get("path", "")
                            for method, method_cfg in (
                                resource.get("resourceMethods") or {}
                            ).items():
                                if method.upper() == "OPTIONS":
                                    continue
                                auth_type = method_cfg.get("authorizationType", "NONE")
                                if auth_type in {"NONE", None}:
                                    unauth_rest_routes.append(
                                        f"{api_id}/{method}/{path.lstrip('/')}"
                                    )
                        api_entry["UnauthenticatedRouteCount"] = len(unauth_rest_routes)
                        api_entry["UnauthenticatedRoutes"] = unauth_rest_routes[:20]
                    except ClientError as e:
                        logger.warning(f"Could not get resources for REST API {api_id}: {e}")
                    apis.append(api_entry)
        except ClientError as e:
            logger.warning(f"Could not list REST APIs: {e}")

        # HTTP APIs (v2)
        try:
            apigw2 = boto3.client("apigatewayv2", **client_kwargs)
            paginator = apigw2.get_paginator("get_apis")
            for page in paginator.paginate():
                for api in page.get("Items", []):
                    api_id = api.get("ApiId")
                    api_entry = {
                        "Id": api_id,
                        "Name": api.get("Name"),
                        "Type": "HTTP",
                        "ProtocolType": api.get("ProtocolType"),
                        "Stages": [],
                    }
                    try:
                        stages_resp = apigw2.get_stages(ApiId=api_id)
                        for stage in stages_resp.get("Items", []):
                            stage_name = stage.get("StageName", "$default")
                            invoke_url = f"https://{api_id}.execute-api.{client_kwargs.get('region_name')}.amazonaws.com"
                            if stage_name != "$default":
                                invoke_url += f"/{stage_name}"
                            stage_entry = {
                                "StageName": stage_name,
                                "InvokeURL": invoke_url,
                                "AutoDeploy": stage.get("AutoDeploy", False),
                                "AccessLogEnabled": bool(stage.get("AccessLogSettings")),
                                "DefaultRouteAuthorizationType": None,
                            }
                            # Try to get default route auth type
                            try:
                                routes = apigw2.get_routes(ApiId=api_id)
                                default_auths = [
                                    r.get("AuthorizationType", "NONE")
                                    for r in routes.get("Items", [])
                                    if r.get("RouteKey", "").startswith("$default")
                                ]
                                if default_auths:
                                    stage_entry["DefaultRouteAuthorizationType"] = default_auths[0]
                                # Count unauthenticated routes
                                unauth_routes = [
                                    r
                                    for r in routes.get("Items", [])
                                    if r.get("AuthorizationType") in {"NONE", None}
                                ]
                                stage_entry["UnauthenticatedRouteCount"] = len(unauth_routes)
                                stage_entry["TotalRouteCount"] = len(routes.get("Items", []))
                            except ClientError:
                                pass
                            api_entry["Stages"].append(stage_entry)
                    except ClientError as e:
                        logger.warning(f"Could not get stages for HTTP API {api_id}: {e}")
                    apis.append(api_entry)
        except ClientError as e:
            logger.warning(f"Could not list HTTP APIs: {e}")

        total_stages = sum(len(a.get("Stages", [])) for a in apis)
        # For HTTP APIs (v2): count stages where DefaultRouteAuthorizationType is NONE/null.
        # For REST APIs (v1): auth is method-level; count REST APIs with ≥1 unauth non-OPTIONS
        # route as "unauthenticated" (one entry per API, not per stage, to avoid double-counting).
        unauth_stages = sum(
            1
            for a in apis
            for s in a.get("Stages", [])
            if a.get("Type") != "REST" and s.get("DefaultRouteAuthorizationType") in {"NONE", None}
        )
        # Add REST APIs that have at least one unauthenticated non-OPTIONS route
        rest_unauth_apis = sum(
            1
            for a in apis
            if a.get("Type") == "REST" and int(a.get("UnauthenticatedRouteCount", 0) or 0) > 0
        )
        unauth_stages += rest_unauth_apis
        return {
            "total_apis": len(apis),
            "total_stages": total_stages,
            "unauthenticated_stages": unauth_stages,
            "apis": apis,
        }

    # -------------------------------------------------------------------------
    # LAMBDA FUNCTION URLS
    # -------------------------------------------------------------------------

    def _collect_lambda_urls(self, client_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Collect Lambda Function URLs (public and authenticated)."""
        lam = boto3.client("lambda", **client_kwargs)
        urls: List[Dict[str, Any]] = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    fn_name = fn.get("FunctionName")
                    if not fn_name:
                        continue
                    try:
                        url_config = lam.get_function_url_config(FunctionName=fn_name)
                        auth_type = url_config.get("AuthType", "UNKNOWN")
                        urls.append(
                            {
                                "FunctionName": fn_name,
                                "FunctionArn": fn.get("FunctionArn"),
                                "FunctionUrl": url_config.get("FunctionUrl"),
                                "AuthType": auth_type,
                                "IsPublic": auth_type == "NONE",
                                "Cors": url_config.get("Cors"),
                            }
                        )
                    except ClientError as e:
                        # ResourceNotFoundException → no URL configured, skip
                        if "ResourceNotFoundException" not in str(e):
                            logger.debug(f"Could not get URL config for {fn_name}: {e}")
        except ClientError as e:
            logger.error(f"Could not list Lambda functions: {e}")

        public_urls = [u for u in urls if u.get("IsPublic")]
        return {
            "total_function_urls": len(urls),
            "public_function_urls": len(public_urls),
            "urls": urls,
        }

    # -------------------------------------------------------------------------
    # LOAD BALANCERS
    # -------------------------------------------------------------------------

    def _collect_load_balancers(self, client_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Collect ALB/NLB DNS names and listener config."""
        elbv2 = boto3.client("elbv2", **client_kwargs)
        lbs: List[Dict[str, Any]] = []
        try:
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    arn = lb.get("LoadBalancerArn")
                    lb_entry: Dict[str, Any] = {
                        "Name": lb.get("LoadBalancerName"),
                        "DNSName": lb.get("DNSName"),
                        "Scheme": lb.get("Scheme"),  # internet-facing | internal
                        "Type": lb.get("Type"),  # application | network
                        "IsPublic": lb.get("Scheme") == "internet-facing",
                        "VpcId": lb.get("VpcId"),
                        "Listeners": [],
                        "WafWebAclArn": None,
                    }
                    # Get listeners
                    try:
                        listeners = elbv2.describe_listeners(LoadBalancerArn=arn)
                        for lst in listeners.get("Listeners", []):
                            lb_entry["Listeners"].append(
                                {
                                    "Port": lst.get("Port"),
                                    "Protocol": lst.get("Protocol"),
                                    "SslPolicy": lst.get("SslPolicy"),
                                }
                            )
                    except ClientError as e:
                        logger.warning(f"Could not get listeners for {arn}: {e}")
                    # Check WAF association
                    try:
                        waf = boto3.client("wafv2", **client_kwargs)
                        waf_acl = waf.get_web_acl_for_resource(ResourceArn=arn)
                        lb_entry["WafWebAclArn"] = (
                            waf_acl.get("WebACL", {}).get("ARN") if waf_acl.get("WebACL") else None
                        )
                    except ClientError:
                        pass  # WAF not associated or no permission
                    lbs.append(lb_entry)
        except ClientError as e:
            logger.error(f"Could not list load balancers: {e}")

        public_lbs = [lb for lb in lbs if lb.get("IsPublic")]
        public_no_waf = [lb for lb in public_lbs if not lb.get("WafWebAclArn")]
        return {
            "total_load_balancers": len(lbs),
            "public_load_balancers": len(public_lbs),
            "public_without_waf": len(public_no_waf),
            "load_balancers": lbs,
        }

    # -------------------------------------------------------------------------
    # PUBLIC ENDPOINTS (Elastic IPs + NAT GW)
    # -------------------------------------------------------------------------

    def _collect_public_endpoints(self, client_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Collect Elastic IPs and NAT Gateway public IPs."""
        ec2 = boto3.client("ec2", **client_kwargs)
        elastic_ips: List[Dict[str, Any]] = []
        nat_gw_ips: List[Dict[str, Any]] = []

        # Elastic IPs
        try:
            addresses = ec2.describe_addresses()
            for addr in addresses.get("Addresses", []):
                elastic_ips.append(
                    {
                        "PublicIp": addr.get("PublicIp"),
                        "AllocationId": addr.get("AllocationId"),
                        "AssociatedWithInstance": bool(addr.get("InstanceId")),
                        "InstanceId": addr.get("InstanceId"),
                        "NetworkInterfaceId": addr.get("NetworkInterfaceId"),
                        "Domain": addr.get("Domain"),
                    }
                )
        except ClientError as e:
            logger.error(f"Could not list Elastic IPs: {e}")

        # NAT Gateways
        try:
            paginator = ec2.get_paginator("describe_nat_gateways")
            for page in paginator.paginate(Filters=[{"Name": "state", "Values": ["available"]}]):
                for ngw in page.get("NatGateways", []):
                    for addr in ngw.get("NatGatewayAddresses", []):
                        if addr.get("PublicIp"):
                            nat_gw_ips.append(
                                {
                                    "NatGatewayId": ngw.get("NatGatewayId"),
                                    "PublicIp": addr.get("PublicIp"),
                                    "VpcId": ngw.get("VpcId"),
                                    "SubnetId": ngw.get("SubnetId"),
                                }
                            )
        except ClientError as e:
            logger.error(f"Could not list NAT Gateways: {e}")

        # Enrich EIPs with instance names and permissive SG rules
        enriched_eips = []
        for eip in elastic_ips:
            enriched = self._enrich_eip_with_sg_rules(eip, ec2)
            enriched_eips.append(enriched)

        return {
            "elastic_ip_count": len(enriched_eips),
            "nat_gateway_ip_count": len(nat_gw_ips),
            "total_public_ip_count": len(enriched_eips) + len(nat_gw_ips),
            "elastic_ips": enriched_eips,
            "nat_gateway_ips": nat_gw_ips,
        }

    def _enrich_eip_with_sg_rules(self, eip: Dict[str, Any], ec2_client) -> Dict[str, Any]:
        """Expand EIP entry with instance name and permissive SG rules."""
        instance_id = eip.get("InstanceId")
        if not instance_id:
            return eip  # EIP not attached to instance

        try:
            # Get instance name tag
            resp = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = resp["Reservations"][0]["Instances"][0]
            name_tag = next(
                (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), instance_id
            )
            sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

            # Get SG rules (only ingress, only permissive ones: 0.0.0.0/0 or ::/0)
            sgs = ec2_client.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
            permissive_rules = []
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    cidr_ranges = rule.get("IpRanges", []) + rule.get("Ipv6Ranges", [])
                    for cidr in cidr_ranges:
                        if (
                            cidr.get("CidrIp") in ("0.0.0.0/0", "::/0")
                            or cidr.get("CidrIpv6") == "::/0"
                        ):
                            permissive_rules.append(
                                {
                                    "SecurityGroupId": sg["GroupId"],
                                    "SecurityGroupName": sg["GroupName"],
                                    "Protocol": rule.get("IpProtocol", "-1"),
                                    "FromPort": rule.get("FromPort"),
                                    "ToPort": rule.get("ToPort"),
                                    "Cidr": cidr.get("CidrIp") or cidr.get("CidrIpv6"),
                                }
                            )

            eip["InstanceName"] = name_tag
            eip["PermissiveSGRules"] = permissive_rules  # list of culpable rules
        except Exception:
            pass  # degraded mode: EIP without enrichment

        return eip

    def _classify_dns_sensitivity(self, zone_name: str, records: list) -> dict:
        """Return sensitivity classification for a public DNS zone."""
        import re

        SENSITIVE_KEYWORDS = {
            "critical": ["pci", "cardholder", "payment", "cde"],
            "high": ["admin", "internal", "mgmt", "management", "prod", "production"],
            "medium": ["db", "database", "stage", "staging", "dev", "vpn", "bastion"],
        }

        GEO_ENV_PATTERNS = [
            r"\b(pci|prod)\.(mx|co|br|ar|cl)\b",  # pci.mx.ejemplo.com
            r"\b(internal|db)\.(us|eu|ap)-\w+\b",  # internal.us-east.ejemplo.com
        ]

        name_lower = zone_name.lower()

        # Keyword detection
        matched_keywords = []
        severity_bump = None
        for sev, kws in SENSITIVE_KEYWORDS.items():
            for kw in kws:
                if kw in name_lower:
                    matched_keywords.append(kw)
                    if severity_bump is None:
                        severity_bump = sev

        # Geographic/environment pattern detection
        geo_matches = []
        for pattern in GEO_ENV_PATTERNS:
            if re.search(pattern, name_lower):
                geo_matches.append(pattern)

        # Record-level analysis
        sensitive_records = [
            r
            for r in records
            if any(
                kw in r.get("Name", "").lower() for kws in SENSITIVE_KEYWORDS.values() for kw in kws
            )
        ]

        return {
            "SensitiveKeywords": matched_keywords,
            "SeverityBump": severity_bump,  # None, "medium", "high", "critical"
            "GeoEnvPatterns": geo_matches,
            "SensitiveRecordCount": len(sensitive_records),
        }

    # -------------------------------------------------------------------------
    # CLOUDFRONT
    # -------------------------------------------------------------------------

    def _collect_cloudfront(self, client_kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Collect CloudFront distributions and their origins."""
        # CloudFront is global — use us-east-1
        cf_kwargs = {k: v for k, v in client_kwargs.items()}
        cf_kwargs["region_name"] = "us-east-1"
        cf = boto3.client("cloudfront", **cf_kwargs)
        distributions: List[Dict[str, Any]] = []
        try:
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                dist_list = page.get("DistributionList", {}).get("Items", []) or []
                for dist in dist_list:
                    origins = []
                    for origin in dist.get("Origins", {}).get("Items", []) or []:
                        origins.append(
                            {
                                "Id": origin.get("Id"),
                                "DomainName": origin.get("DomainName"),
                                "S3OriginPath": origin.get("S3OriginConfig", {}).get(
                                    "OriginAccessIdentity"
                                ),
                            }
                        )
                    logging_enabled = bool(
                        dist.get("DistributionConfig", {}).get("Logging", {}).get("Enabled")
                    )
                    distributions.append(
                        {
                            "Id": dist.get("Id"),
                            "DomainName": dist.get("DomainName"),
                            "Aliases": dist.get("Aliases", {}).get("Items", []) or [],
                            "Status": dist.get("Status"),
                            "Enabled": dist.get("Enabled", False),
                            "Origins": origins,
                            "LoggingEnabled": logging_enabled,
                            "WebAclId": dist.get("WebACLId") or None,
                        }
                    )
        except ClientError as e:
            logger.warning(f"Could not list CloudFront distributions: {e}")

        no_logging = [d for d in distributions if not d.get("LoggingEnabled")]
        return {
            "total_distributions": len(distributions),
            "distributions_without_logging": len(no_logging),
            "distributions": distributions,
        }

    # -------------------------------------------------------------------------
    # ATTACK SURFACE SCORE
    # -------------------------------------------------------------------------

    def _compute_attack_surface_score(
        self,
        route53: Dict[str, Any],
        apigw: Dict[str, Any],
        lambda_urls: Dict[str, Any],
        lbs: Dict[str, Any],
        public_eps: Dict[str, Any],
        cf: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compute a 0-10 attack surface score from collected evidence."""
        score = 0.0
        factors: List[Dict[str, Any]] = []

        # Public API Gateway stages (each unauth = +1.2, capped at 3.0)
        unauth = apigw.get("unauthenticated_stages", 0)
        if unauth > 0:
            contrib = min(3.0, unauth * 1.2)
            score += contrib
            factors.append(
                {
                    "factor": "API Gateway unauthenticated stages",
                    "count": unauth,
                    "contribution": round(contrib, 2),
                }
            )

        # Public Lambda URLs (+1.5 each, capped at 3.0)
        pub_lambdas = lambda_urls.get("public_function_urls", 0)
        if pub_lambdas > 0:
            contrib = min(3.0, pub_lambdas * 1.5)
            score += contrib
            factors.append(
                {
                    "factor": "Public Lambda Function URLs",
                    "count": pub_lambdas,
                    "contribution": round(contrib, 2),
                }
            )

        # Public load balancers without WAF (+0.8 each, capped at 2.0)
        pub_no_waf = lbs.get("public_without_waf", 0)
        if pub_no_waf > 0:
            contrib = min(2.0, pub_no_waf * 0.8)
            score += contrib
            factors.append(
                {
                    "factor": "Internet-facing Load Balancers without WAF",
                    "count": pub_no_waf,
                    "contribution": round(contrib, 2),
                }
            )

        # Elastic IPs (+0.3 each, capped at 1.5)
        eips = public_eps.get("elastic_ip_count", 0)
        if eips > 0:
            contrib = min(1.5, eips * 0.3)
            score += contrib
            factors.append(
                {
                    "factor": "Elastic IPs",
                    "count": eips,
                    "contribution": round(contrib, 2),
                }
            )

        # DNS wildcard records (+0.5 each, capped at 1.5)
        wildcards = route53.get("wildcard_record_count", 0)
        if wildcards > 0:
            contrib = min(1.5, wildcards * 0.5)
            score += contrib
            factors.append(
                {
                    "factor": "DNS wildcard records",
                    "count": wildcards,
                    "contribution": round(contrib, 2),
                }
            )

        score = min(10.0, round(score, 2))
        if score >= 7.0:
            rating = "CRITICAL"
        elif score >= 5.0:
            rating = "HIGH"
        elif score >= 3.0:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return {
            "score": score,
            "rating": rating,
            "total_public_apis": apigw.get("total_stages", 0),
            "unauthenticated_api_stages": unauth,
            "public_lambda_urls": pub_lambdas,
            "public_load_balancers": lbs.get("public_load_balancers", 0),
            "public_lbs_without_waf": pub_no_waf,
            "elastic_ips": eips,
            "nat_gateway_ips": public_eps.get("nat_gateway_ip_count", 0),
            "dns_wildcard_records": wildcards,
            "cloudfront_distributions": cf.get("total_distributions", 0),
            "factors": factors,
        }

    def _save_json(self, filepath: Path, data: Any) -> None:
        """Save data to JSON file."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["ReconSkill"]
