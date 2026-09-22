import json
from unittest.mock import Mock, patch

from drystone.models.findings import FindingsSummary, SkillFindings
from drystone.skills.exposure import ExposureSkill
from drystone.storage.session import AuditSession


class _PaginatedApiGatewayV1:
    def __init__(self):
        self.rest_api_calls = []
        self.resource_calls = []

    def get_rest_apis(self, **kwargs):
        self.rest_api_calls.append(kwargs)
        if kwargs.get("position"):
            return {"items": [{"id": "rest-api-2", "name": "second"}]}
        return {
            "items": [{"id": "rest-api-1", "name": "first"}],
            "position": "rest-page-2",
        }

    def get_stages(self, **_kwargs):
        return {"item": []}

    def get_resources(self, **kwargs):
        self.resource_calls.append(kwargs)
        if kwargs.get("restApiId") == "rest-api-1" and not kwargs.get("position"):
            return {
                "items": [
                    {
                        "id": "resource-1",
                        "path": "/one",
                        "resourceMethods": {"GET": {}},
                    }
                ],
                "position": "resource-page-2",
            }
        if kwargs.get("restApiId") == "rest-api-1":
            return {
                "items": [
                    {
                        "id": "resource-2",
                        "path": "/two",
                        "resourceMethods": {"GET": {}},
                    }
                ]
            }
        return {"items": []}

    def get_method(self, **_kwargs):
        return {"authorizationType": "NONE", "apiKeyRequired": False}


class _PaginatedApiGatewayV2:
    def __init__(self):
        self.route_calls = []

    def get_apis(self):
        return {"Items": [{"ApiId": "http-api-1", "Name": "http"}]}

    def get_stages(self, **_kwargs):
        return {"Items": []}

    def get_routes(self, **kwargs):
        self.route_calls.append(kwargs)
        if kwargs.get("NextToken"):
            return {"Items": [{"RouteKey": "POST /second"}]}
        return {"Items": [{"RouteKey": "GET /first"}], "NextToken": "route-page-2"}


def _run_api_gateway_collection(tmp_path, apigw, apigw2):
    aws_client = Mock()
    aws_client.region_name = "us-east-1"
    aws_client.client_kwargs.return_value = {"region_name": "us-east-1"}
    session = Mock(spec=AuditSession)
    session.account_id = "123456789012"
    session.get_evidence_path.return_value = tmp_path / "evidence"

    def client_factory(service, **_kwargs):
        if service == "apigateway":
            return apigw
        if service == "apigatewayv2":
            return apigw2
        raise RuntimeError(f"No fixture for {service}")

    with patch("drystone.skills.exposure.boto3.client", side_effect=client_factory):
        ExposureSkill().collect(aws_client, session)
    return tmp_path / "evidence"


def test_exposure_paginates_api_gateway_apis_resources_and_routes(tmp_path):
    apigw = _PaginatedApiGatewayV1()
    apigw2 = _PaginatedApiGatewayV2()

    evidence_dir = _run_api_gateway_collection(tmp_path, apigw, apigw2)

    stages = json.loads((evidence_dir / "api-gateway-stages.json").read_text())
    routes = json.loads((evidence_dir / "api-gateway-routes.json").read_text())
    paths = {route["Path"] for route in routes["items"]}

    assert [call.get("position") for call in apigw.rest_api_calls] == [None, "rest-page-2"]
    assert {call.get("position") for call in apigw.resource_calls} == {None, "resource-page-2"}
    assert [call.get("NextToken") for call in apigw2.route_calls] == [None, "route-page-2"]
    assert stages["items"] == []
    assert {"/one", "/two", "/first", "/second"} == paths


def test_exposure_analyze_adds_deterministic_s3_findings(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True)
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)

    # Minimal evidence to trigger deterministic EXP-013/014/015
    (evidence_dir / "_audit_metadata.json").write_text(
        json.dumps({"_region": "us-east-1", "_account_id": "111111111111"})
    )
    (evidence_dir / "s3-buckets.json").write_text(
        json.dumps(
            {
                "_meta": {"_region": "us-east-1"},
                "items": [],
                "by_name": {
                    "tulotero-pci-prod-logs-backup": {
                        "Name": "tulotero-pci-prod-logs-backup",
                        "BucketPolicy": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
                                    "Action": ["s3:PutObject"],
                                    "Resource": "arn:aws:s3:::tulotero-pci-prod-logs-backup/*",
                                }
                            ]
                        },
                        "Versioning": None,
                    },
                    "payments-prod-na-tl-access-logs": {
                        "Name": "payments-prod-na-tl-access-logs",
                        "BucketPolicy": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                                    "Action": "s3:PutObject",
                                    "Resource": "arn:aws:s3:::payments-prod-na-tl-access-logs/*",
                                }
                            ]
                        },
                        "Versioning": None,
                    },
                },
            }
        )
    )

    # Other evidence files expected by prompt are optional for deterministic.
    for name in [
        "rds-instances.json",
        "ami-images.json",
        "security-groups.json",
        "cloudfront-distributions.json",
        "load-balancers.json",
        "load-balancer-listeners.json",
        "wafv2-web-acls.json",
        "wafv2-web-acl-alb-associations.json",
    ]:
        (evidence_dir / name).write_text(json.dumps({"items": [], "by_id": {}, "_meta": {}}))

    session = Mock(spec=AuditSession)
    session.account_id = "111111111111"
    session.get_evidence_path.return_value = evidence_dir
    session.get_findings_path.return_value = findings_dir

    agent = Mock()
    agent.get_display_name.return_value = "TestAgent"
    agent.get_last_analysis_status.return_value = {}
    agent.analyze_evidence_chunked.return_value = SkillFindings(
        skill="exposure",
        findings=[],
        summary=FindingsSummary(
            total_findings=0, critical=0, high=0, medium=0, low=0, overall_risk_score=0.0
        ),
        evidence_count=0,
        checklist_version="1.0",
    )

    skill = ExposureSkill()
    out_path = skill.analyze(session, agent)

    data = json.loads(out_path.read_text())
    ids = {f["id"] for f in data["findings"]}
    assert "EXP-013" in ids
    assert "EXP-014" in ids
    assert "EXP-015" in ids
