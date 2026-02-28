"""Tests for the ReconSkill collector and recon pre-checks."""

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from drystone.skills.recon import ReconSkill
from drystone.validation.pre_checks import run_pre_checks


# ============================================================================
# Collector tests
# ============================================================================


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        yield from self._pages


class _DummyEC2Client:
    def describe_addresses(self):
        return {
            "Addresses": [
                {"PublicIp": "1.2.3.4", "AllocationId": "eipalloc-aaa", "InstanceId": "i-001"},
                {"PublicIp": "5.6.7.8", "AllocationId": "eipalloc-bbb"},  # unassociated
            ]
        }

    def get_paginator(self, op):
        if op == "describe_nat_gateways":
            return _DummyPaginator(
                [
                    {
                        "NatGateways": [
                            {
                                "NatGatewayId": "nat-001",
                                "VpcId": "vpc-001",
                                "SubnetId": "subnet-001",
                                "NatGatewayAddresses": [{"PublicIp": "10.0.0.1"}],
                            }
                        ]
                    }
                ]
            )
        return _DummyPaginator([{}])

    def __getattr__(self, _name):
        def _fn(*_args, **_kwargs):
            return {}
        return _fn


class _DummyR53Client:
    def get_paginator(self, op):
        if op == "list_hosted_zones":
            return _DummyPaginator(
                [
                    {
                        "HostedZones": [
                            {
                                "Id": "/hostedzone/Z001",
                                "Name": "example.com.",
                                "Config": {"PrivateZone": False},
                                "ResourceRecordSetCount": 5,
                            }
                        ]
                    }
                ]
            )
        if op == "list_resource_record_sets":
            return _DummyPaginator(
                [
                    {
                        "ResourceRecordSets": [
                            {"Name": "*.example.com.", "Type": "A", "ResourceRecords": [{"Value": "1.2.3.4"}]},
                            {"Name": "www.example.com.", "Type": "A", "ResourceRecords": [{"Value": "1.2.3.4"}]},
                        ]
                    }
                ]
            )
        return _DummyPaginator([{}])


class _DummyAPIGWClient:
    def get_paginator(self, op):
        if op == "get_rest_apis":
            return _DummyPaginator(
                [{"items": [{"id": "abc123", "name": "MyAPI", "endpointConfiguration": {"types": ["REGIONAL"]}}]}]
            )
        return _DummyPaginator([{}])

    def get_stages(self, **_kwargs):
        return {
            "item": [{"stageName": "prod", "cacheClusterEnabled": False, "webAclArn": None}]
        }


class _DummyAPIGW2Client:
    def get_paginator(self, op):
        return _DummyPaginator([{"Items": []}])

    def get_stages(self, **_kwargs):
        return {"Items": []}

    def get_routes(self, **_kwargs):
        return {"Items": []}


class _DummyLambdaClient:
    def get_paginator(self, op):
        return _DummyPaginator([
            {"Functions": [
                {"FunctionName": "fn-public", "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn-public"},
                {"FunctionName": "fn-private", "FunctionArn": "arn:aws:lambda:us-east-1:123:function:fn-private"},
            ]}
        ])

    def get_function_url_config(self, FunctionName=""):
        if FunctionName == "fn-public":
            return {"AuthType": "NONE", "FunctionUrl": "https://fn-public.lambda-url.us-east-1.on.aws/"}
        from botocore.exceptions import ClientError
        raise ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}},
            "GetFunctionUrlConfig",
        )


class _DummyELBv2Client:
    def get_paginator(self, op):
        return _DummyPaginator([
            {"LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb-public",
                    "LoadBalancerName": "alb-public",
                    "DNSName": "alb-public.us-east-1.elb.amazonaws.com",
                    "Scheme": "internet-facing",
                    "Type": "application",
                    "VpcId": "vpc-001",
                }
            ]}
        ])

    def describe_listeners(self, LoadBalancerArn=""):
        return {"Listeners": [{"Port": 443, "Protocol": "HTTPS", "SslPolicy": "ELBSecurityPolicy-2016-08"}]}


class _DummyWAFClient:
    def get_web_acl_for_resource(self, ResourceArn=""):
        return {}  # No WAF


class _DummyCFClient:
    def get_paginator(self, op):
        return _DummyPaginator([{"DistributionList": {"Items": []}}])


def _make_boto_client(service_name, **_kwargs):
    """Return appropriate dummy client for service."""
    if service_name == "ec2":
        return _DummyEC2Client()
    if service_name == "route53":
        return _DummyR53Client()
    if service_name == "apigateway":
        return _DummyAPIGWClient()
    if service_name == "apigatewayv2":
        return _DummyAPIGW2Client()
    if service_name == "lambda":
        return _DummyLambdaClient()
    if service_name == "elbv2":
        return _DummyELBv2Client()
    if service_name == "wafv2":
        return _DummyWAFClient()
    if service_name == "cloudfront":
        return _DummyCFClient()
    m = MagicMock()
    return m


def test_recon_collect_writes_all_evidence_files(tmp_path: Path):
    """ReconSkill.collect() must write all 7 expected evidence files."""
    aws_client = Mock()
    aws_client.access_key_id = "AKIA0000000000000000"
    aws_client.secret_access_key = "x" * 40
    aws_client.region_name = "us-east-1"
    aws_client.session_token = None

    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    session.account_id = "123456789012"

    saved = []
    skill = ReconSkill()

    def _record(path, _data):
        saved.append(path.name)

    with patch("boto3.client", side_effect=_make_boto_client):
        with patch.object(skill, "_save_json", side_effect=_record):
            skill.collect(aws_client, session)

    expected = {
        "route53-zones.json",
        "api-gateway-stages.json",
        "lambda-urls.json",
        "load-balancer-dns.json",
        "public-endpoints.json",
        "cloudfront-origins.json",
        "attack-surface-score.json",
    }
    assert expected.issubset(set(saved)), f"Missing files: {expected - set(saved)}"


def test_recon_skill_name():
    assert ReconSkill().name == "recon"


def test_recon_collect_detects_public_lambda_url(tmp_path: Path):
    """ReconSkill must record public Lambda URLs (AuthType=NONE)."""
    aws_client = Mock()
    aws_client.access_key_id = "AKIA0000000000000000"
    aws_client.secret_access_key = "x" * 40
    aws_client.region_name = "us-east-1"
    aws_client.session_token = None

    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    session.account_id = "123456789012"

    saved_data = {}
    skill = ReconSkill()

    def _record(path, data):
        saved_data[path.name] = data

    with patch("boto3.client", side_effect=_make_boto_client):
        with patch.object(skill, "_save_json", side_effect=_record):
            skill.collect(aws_client, session)

    lambda_doc = saved_data.get("lambda-urls.json", {})
    assert lambda_doc.get("total_function_urls", 0) == 1
    assert lambda_doc.get("public_function_urls", 0) == 1
    urls = lambda_doc.get("urls", [])
    assert any(u.get("IsPublic") for u in urls)


def test_recon_attack_surface_score_computed(tmp_path: Path):
    """attack-surface-score.json must contain valid score structure."""
    aws_client = Mock()
    aws_client.access_key_id = "AKIA0000000000000000"
    aws_client.secret_access_key = "x" * 40
    aws_client.region_name = "us-east-1"
    aws_client.session_token = None

    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    session.account_id = "123456789012"

    saved_data = {}
    skill = ReconSkill()

    def _record(path, data):
        saved_data[path.name] = data

    with patch("boto3.client", side_effect=_make_boto_client):
        with patch.object(skill, "_save_json", side_effect=_record):
            skill.collect(aws_client, session)

    score_doc = saved_data.get("attack-surface-score.json", {})
    assert "score" in score_doc
    assert "rating" in score_doc
    assert score_doc["rating"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0.0 <= float(score_doc["score"]) <= 10.0


# ============================================================================
# Pre-check tests
# ============================================================================


def _base_evidence() -> dict:
    """Minimal evidence with no findings (all PASS/SKIP)."""
    return {
        "route53-zones": {
            "total_zones": 1,
            "public_zones": 1,
            "wildcard_record_count": 0,
            "zones": [{"Id": "Z001", "Name": "example.com.", "IsPrivate": False, "Records": []}],
        },
        "api-gateway-stages": {
            "total_apis": 1,
            "total_stages": 1,
            "unauthenticated_stages": 0,
            "apis": [{"Id": "abc123", "Name": "API", "Type": "REST", "Stages": [
                {"StageName": "prod", "DefaultRouteAuthorizationType": "AWS_IAM"}
            ]}],
        },
        "lambda-urls": {
            "total_function_urls": 0,
            "public_function_urls": 0,
            "urls": [],
        },
        "load-balancer-dns": {
            "total_load_balancers": 0,
            "public_load_balancers": 0,
            "public_without_waf": 0,
            "load_balancers": [],
        },
        "public-endpoints": {
            "elastic_ip_count": 0,
            "nat_gateway_ip_count": 0,
            "total_public_ip_count": 0,
            "elastic_ips": [],
            "nat_gateway_ips": [],
        },
        "cloudfront-origins": {
            "total_distributions": 0,
            "distributions_without_logging": 0,
            "distributions": [],
        },
        "attack-surface-score": {
            "score": 1.5,
            "rating": "LOW",
            "factors": [],
        },
    }


class TestReconPreCheckRECON001:
    """RECON-001: DNS wildcard records."""

    def test_pass_no_wildcards(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r001 = next((r for r in results if r.check_id == "RECON-001"), None)
        assert r001 is not None
        assert r001.status == "PASS"

    def test_fail_with_wildcard(self):
        ev = _base_evidence()
        ev["route53-zones"]["wildcard_record_count"] = 1
        ev["route53-zones"]["zones"][0]["Records"] = [
            {"Name": "*.example.com.", "Type": "A", "Values": ["1.2.3.4"]}
        ]
        results = run_pre_checks("recon", ev, {})
        r001 = next((r for r in results if r.check_id == "RECON-001"), None)
        assert r001 is not None
        assert r001.status == "FAIL"
        assert "*.example.com." in r001.affected_resources[0]

    def test_skip_no_evidence(self):
        ev = {}
        results = run_pre_checks("recon", ev, {})
        r001 = next((r for r in results if r.check_id == "RECON-001"), None)
        assert r001 is not None
        assert r001.status == "SKIP"


class TestReconPreCheckRECON002:
    """RECON-002: API Gateway unauthenticated stages."""

    def test_pass_all_authenticated(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r002 = next((r for r in results if r.check_id == "RECON-002"), None)
        assert r002 is not None
        assert r002.status == "PASS"

    def test_fail_unauth_stage(self):
        ev = _base_evidence()
        ev["api-gateway-stages"]["unauthenticated_stages"] = 1
        ev["api-gateway-stages"]["apis"][0]["Stages"][0]["DefaultRouteAuthorizationType"] = "NONE"
        ev["api-gateway-stages"]["apis"][0]["Stages"][0]["InvokeURL"] = "https://abc.execute-api.us-east-1.amazonaws.com/prod"
        results = run_pre_checks("recon", ev, {})
        r002 = next((r for r in results if r.check_id == "RECON-002"), None)
        assert r002 is not None
        assert r002.status == "FAIL"

    def test_skip_no_apis(self):
        ev = _base_evidence()
        ev["api-gateway-stages"]["total_apis"] = 0
        results = run_pre_checks("recon", ev, {})
        r002 = next((r for r in results if r.check_id == "RECON-002"), None)
        assert r002 is not None
        assert r002.status == "SKIP"


class TestReconPreCheckRECON003:
    """RECON-003: Elastic IPs attached to instances."""

    def test_pass_no_eips(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r003 = next((r for r in results if r.check_id == "RECON-003"), None)
        assert r003 is not None
        assert r003.status == "PASS"

    def test_fail_eip_with_instance(self):
        ev = _base_evidence()
        ev["public-endpoints"]["elastic_ip_count"] = 1
        ev["public-endpoints"]["elastic_ips"] = [
            {"PublicIp": "1.2.3.4", "AllocationId": "eipalloc-001", "AssociatedWithInstance": True, "InstanceId": "i-001"}
        ]
        results = run_pre_checks("recon", ev, {})
        r003 = next((r for r in results if r.check_id == "RECON-003"), None)
        assert r003 is not None
        assert r003.status == "FAIL"
        assert "1.2.3.4" in r003.affected_resources

    def test_pass_eip_unassociated(self):
        ev = _base_evidence()
        ev["public-endpoints"]["elastic_ip_count"] = 1
        ev["public-endpoints"]["elastic_ips"] = [
            {"PublicIp": "1.2.3.4", "AllocationId": "eipalloc-001", "AssociatedWithInstance": False}
        ]
        results = run_pre_checks("recon", ev, {})
        r003 = next((r for r in results if r.check_id == "RECON-003"), None)
        assert r003 is not None
        assert r003.status == "PASS"


class TestReconPreCheckRECON005:
    """RECON-005: Lambda public Function URLs."""

    def test_skip_no_urls(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r005 = next((r for r in results if r.check_id == "RECON-005"), None)
        assert r005 is not None
        assert r005.status == "SKIP"

    def test_fail_public_lambda_url(self):
        ev = _base_evidence()
        ev["lambda-urls"] = {
            "total_function_urls": 1,
            "public_function_urls": 1,
            "urls": [
                {
                    "FunctionName": "fn-public",
                    "FunctionUrl": "https://fn-public.lambda-url.us-east-1.on.aws/",
                    "AuthType": "NONE",
                    "IsPublic": True,
                }
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r005 = next((r for r in results if r.check_id == "RECON-005"), None)
        assert r005 is not None
        assert r005.status == "FAIL"

    def test_pass_authenticated_lambda_url(self):
        ev = _base_evidence()
        ev["lambda-urls"] = {
            "total_function_urls": 1,
            "public_function_urls": 0,
            "urls": [
                {
                    "FunctionName": "fn-private",
                    "FunctionUrl": "https://fn-private.lambda-url.us-east-1.on.aws/",
                    "AuthType": "AWS_IAM",
                    "IsPublic": False,
                }
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r005 = next((r for r in results if r.check_id == "RECON-005"), None)
        assert r005 is not None
        assert r005.status == "PASS"


class TestReconPreCheckRECON007:
    """RECON-007: Internet-facing LBs without WAF."""

    def test_skip_no_lbs(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r007 = next((r for r in results if r.check_id == "RECON-007"), None)
        assert r007 is not None
        assert r007.status == "SKIP"

    def test_fail_lb_without_waf(self):
        ev = _base_evidence()
        ev["load-balancer-dns"] = {
            "total_load_balancers": 1,
            "public_load_balancers": 1,
            "public_without_waf": 1,
            "load_balancers": [
                {
                    "Name": "alb-public",
                    "DNSName": "alb-public.us-east-1.elb.amazonaws.com",
                    "IsPublic": True,
                    "Type": "application",
                    "WafWebAclArn": None,
                    "Listeners": [{"Port": 443, "Protocol": "HTTPS"}],
                }
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r007 = next((r for r in results if r.check_id == "RECON-007"), None)
        assert r007 is not None
        assert r007.status == "FAIL"

    def test_pass_lb_with_waf(self):
        ev = _base_evidence()
        ev["load-balancer-dns"] = {
            "total_load_balancers": 1,
            "public_load_balancers": 1,
            "public_without_waf": 0,
            "load_balancers": [
                {
                    "Name": "alb-waf",
                    "DNSName": "alb-waf.us-east-1.elb.amazonaws.com",
                    "IsPublic": True,
                    "Type": "application",
                    "WafWebAclArn": "arn:aws:wafv2:us-east-1:123:regional/webacl/MyACL/abc",
                    "Listeners": [{"Port": 443, "Protocol": "HTTPS"}],
                }
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r007 = next((r for r in results if r.check_id == "RECON-007"), None)
        assert r007 is not None
        assert r007.status == "PASS"


class TestReconPreCheckRECON015:
    """RECON-015: Attack surface score HIGH/CRITICAL."""

    def test_pass_low_score(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r015 = next((r for r in results if r.check_id == "RECON-015"), None)
        assert r015 is not None
        assert r015.status == "PASS"

    def test_fail_high_score(self):
        ev = _base_evidence()
        ev["attack-surface-score"] = {
            "score": 7.5,
            "rating": "CRITICAL",
            "factors": [
                {"factor": "Public Lambda URLs", "count": 3, "contribution": 3.0},
                {"factor": "API GW unauth", "count": 2, "contribution": 2.4},
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r015 = next((r for r in results if r.check_id == "RECON-015"), None)
        assert r015 is not None
        assert r015.status == "FAIL"
        assert "7.5" in r015.evidence_summary

    def test_skip_no_score_doc(self):
        ev = {}
        results = run_pre_checks("recon", ev, {})
        r015 = next((r for r in results if r.check_id == "RECON-015"), None)
        assert r015 is not None
        assert r015.status == "SKIP"


class TestReconPreCheckRECON006:
    """RECON-006: CloudFront distributions without logging."""

    def test_skip_no_distributions(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r006 = next((r for r in results if r.check_id == "RECON-006"), None)
        assert r006 is not None
        assert r006.status == "SKIP"

    def test_fail_cf_no_logging(self):
        ev = _base_evidence()
        ev["cloudfront-origins"] = {
            "total_distributions": 1,
            "distributions_without_logging": 1,
            "distributions": [
                {"Id": "E1234", "DomainName": "d1234.cloudfront.net", "LoggingEnabled": False}
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r006 = next((r for r in results if r.check_id == "RECON-006"), None)
        assert r006 is not None
        assert r006.status == "FAIL"


class TestReconPreCheckRECON011:
    """RECON-011: HTTP-only listeners on internet-facing ALBs."""

    def test_skip_no_lbs(self):
        ev = _base_evidence()
        results = run_pre_checks("recon", ev, {})
        r011 = next((r for r in results if r.check_id == "RECON-011"), None)
        assert r011 is not None
        assert r011.status == "SKIP"

    def test_fail_http_only(self):
        ev = _base_evidence()
        ev["load-balancer-dns"] = {
            "total_load_balancers": 1,
            "public_load_balancers": 1,
            "public_without_waf": 0,
            "load_balancers": [
                {
                    "Name": "alb-http",
                    "DNSName": "alb-http.us-east-1.elb.amazonaws.com",
                    "IsPublic": True,
                    "Type": "application",
                    "WafWebAclArn": None,
                    "Listeners": [{"Port": 80, "Protocol": "HTTP"}],
                }
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r011 = next((r for r in results if r.check_id == "RECON-011"), None)
        assert r011 is not None
        assert r011.status == "FAIL"

    def test_pass_https_listener(self):
        ev = _base_evidence()
        ev["load-balancer-dns"] = {
            "total_load_balancers": 1,
            "public_load_balancers": 1,
            "public_without_waf": 0,
            "load_balancers": [
                {
                    "Name": "alb-https",
                    "DNSName": "alb-https.us-east-1.elb.amazonaws.com",
                    "IsPublic": True,
                    "Type": "application",
                    "WafWebAclArn": "arn:aws:wafv2:us-east-1:123:regional/webacl/X",
                    "Listeners": [
                        {"Port": 80, "Protocol": "HTTP"},
                        {"Port": 443, "Protocol": "HTTPS"},
                    ],
                }
            ],
        }
        results = run_pre_checks("recon", ev, {})
        r011 = next((r for r in results if r.check_id == "RECON-011"), None)
        assert r011 is not None
        assert r011.status == "PASS"
