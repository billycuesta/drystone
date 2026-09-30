import json
from unittest.mock import MagicMock, Mock, patch

from drystone.models.findings import FindingsSummary, SkillFindings
from drystone.skills.exposure import ExposureSkill
from drystone.storage.session import AuditSession


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


def _make_generic_apigw2_peer_client_factory(dummy_apigw2):
    """Build a boto3.client(name, **kw) stub: apigatewayv2 -> dummy, else a
    generic MagicMock stubbed just enough for unrelated collect() sections
    to terminate their pagination loops instead of raising into their
    (already-tested) individual except blocks."""

    def _make_client(name, **_kwargs):
        if name == "apigatewayv2":
            return dummy_apigw2
        m = MagicMock()
        m.get_paginator.return_value.paginate.return_value = []
        m.list_buckets.return_value = {"Buckets": []}
        m.describe_db_instances.return_value = {"DBInstances": []}
        m.describe_images.return_value = {"Images": []}
        m.describe_security_groups.return_value = {"SecurityGroups": []}
        m.list_distributions.return_value = {"DistributionList": {"Items": []}}
        # Pre-existing pagination loops (ELBv2, WAFv2) must terminate too,
        # otherwise a plain MagicMock NextMarker never becomes falsy.
        m.describe_load_balancers.return_value = {"LoadBalancers": []}
        m.list_web_acls.return_value = {"WebACLs": []}
        return m

    return _make_client


def test_apigw2_get_apis_pagination_accumulates(tmp_path):
    """Ensure apigatewayv2.get_apis() paginated responses are fully accumulated."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True)

    session = Mock(spec=AuditSession)
    session.account_id = "111111111111"
    session.get_evidence_path.return_value = evidence_dir

    aws_client = MagicMock()
    aws_client.client_kwargs.return_value = {}
    aws_client.region_name = "us-east-1"

    saved = {}

    def _record(path, data):
        saved[path.name] = data

    class DummyAPIGW2:
        def __init__(self):
            self._calls = 0

        def get_apis(self, **kwargs):
            # First page has a NextToken; second page is the last one.
            if self._calls == 0:
                self._calls += 1
                return {"Items": [{"ApiId": "a1", "Name": "API-One"}], "NextToken": "t1"}
            return {"Items": [{"ApiId": "a2", "Name": "API-Two"}], "NextToken": None}

        def get_routes(self, **kwargs):
            return {"Items": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}]}

        def get_stages(self, **kwargs):
            return {"Items": [{"StageName": "prod", "DeploymentId": "d1"}]}

    skill = ExposureSkill()

    with patch(
        "boto3.client", side_effect=_make_generic_apigw2_peer_client_factory(DummyAPIGW2())
    ):
        with patch.object(skill, "_save_json", side_effect=_record):
            skill.collect(aws_client, session)

    # api-gateway-stages.json should contain stages for both APIs (a1 and a2)
    stages = saved.get("api-gateway-stages.json", {}).get("items", [])
    api_ids = {s.get("ApiId") for s in stages}
    assert "a1" in api_ids and "a2" in api_ids


def test_apigw2_get_apis_pagination_failure_records_partial_collection(tmp_path):
    """A page-fetch failure mid-pagination must be recorded, not silently dropped."""
    from botocore.exceptions import ClientError

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(parents=True)

    session = Mock(spec=AuditSession)
    session.account_id = "111111111111"
    session.get_evidence_path.return_value = evidence_dir

    aws_client = MagicMock()
    aws_client.client_kwargs.return_value = {}
    aws_client.region_name = "us-east-1"

    saved = {}

    def _record(path, data):
        saved[path.name] = data

    class FlakyAPIGW2:
        def __init__(self):
            self._calls = 0

        def get_apis(self, **kwargs):
            if self._calls == 0:
                self._calls += 1
                return {"Items": [{"ApiId": "a1", "Name": "API-One"}], "NextToken": "t1"}
            raise ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
                "GetApis",
            )

        def get_routes(self, **kwargs):
            return {"Items": [{"RouteKey": "GET /", "AuthorizationType": "NONE"}]}

        def get_stages(self, **kwargs):
            return {"Items": [{"StageName": "prod", "DeploymentId": "d1"}]}

    skill = ExposureSkill()

    with patch(
        "boto3.client", side_effect=_make_generic_apigw2_peer_client_factory(FlakyAPIGW2())
    ):
        with patch.object(skill, "_save_json", side_effect=_record):
            skill.collect(aws_client, session)

    # Page 1's API must still be recorded even though page 2 failed.
    stages = saved.get("api-gateway-stages.json", {}).get("items", [])
    assert {s.get("ApiId") for s in stages} == {"a1"}

    status = saved.get("exposure-collection-status.json", {})
    components = status.get("components", {})
    assert components.get("api-gateway-stages", {}).get("ok") is False
    assert components.get("api-gateway-stages", {}).get("reason_code") == "partial_collection"
