"""Tests for ExposureSkill.collect() collection-status recording.

Strategy:
- boto3.client is dispatched by service name; every service not explicitly
  overridden for a test falls back to `_DummyClient()` (same pattern as
  tests/skills/test_exposure_pentest.py): any method call returns `{}` and
  any paginator yields one empty page, so every section's happy path
  degrades to "collected, zero items" without needing to hand-craft every
  AWS API response shape.
- Targeted overrides inject failures for specific tests (list-call failure
  -> collection_failed; per-item sub-call failure while the list call
  succeeded -> partial_collection).
"""

import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from drystone.skills.exposure import ExposureSkill

# ── Generic empty-response client (mirrors test_exposure_pentest.py) ────────


class _DummyPaginator:
    def paginate(self, **_kwargs):
        yield {}


class _DummyClient:
    def get_paginator(self, _op):
        return _DummyPaginator()

    def __getattr__(self, _name):
        def _fn(*_args, **_kwargs):
            return {}

        return _fn


def _make_paginator(*pages):
    pag = MagicMock()
    pag.paginate.return_value = iter(pages)
    return pag


def _make_aws_client(access_key="AKID", secret="SECRET", region="us-east-1", token=None):
    client = MagicMock()
    client.access_key_id = access_key
    client.secret_access_key = secret
    client.region_name = region
    client.session_token = token

    def _client_kwargs(region_name=None):
        kwargs = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret,
            "region_name": region_name or region,
        }
        if token:
            kwargs["aws_session_token"] = token
        return kwargs

    client.client_kwargs.side_effect = _client_kwargs
    return client


def _make_session(tmp_path, skill_name="exposure", account_id="123456789012"):
    session = MagicMock()
    evidence_path = tmp_path / "evidence" / skill_name
    evidence_path.mkdir(parents=True)
    session.get_evidence_path.return_value = evidence_path
    session.account_id = account_id
    return session, evidence_path


_ALL_SERVICES = (
    "s3",
    "rds",
    "ec2",
    "cloudfront",
    "elbv2",
    "wafv2",
    "lambda",
    "apigateway",
    "apigatewayv2",
    "ecs",
    "eks",
    "opensearch",
    "es",
    "sqs",
    "sns",
    "secretsmanager",
    "ecr",
)


def _boto3_factory(**overrides):
    """Dispatch factory: returns the appropriate mock client by service name.
    Every service not explicitly overridden gets a fresh `_DummyClient()`."""
    clients = {name: _DummyClient() for name in _ALL_SERVICES}
    clients.update(overrides)

    def _factory(service, **kwargs):
        return clients[service]

    return _factory


COMPONENT_NAMES = (
    "s3-buckets",
    "rds-instances",
    "ami-images",
    "security-groups",
    "cloudfront-distributions",
    "load-balancers",
    "wafv2-web-acls",
    "lambda-function-urls",
    "api-gateway-stages",
    "ecs-eks-ingress",
    "elasticsearch-domains",
    "resource-based-policies",
)


def _skill():
    return ExposureSkill()


def _load_status(evidence_path):
    return json.loads((evidence_path / "exposure-collection-status.json").read_text())


# ── Happy path ────────────────────────────────────────────────────────────


def test_all_components_ok_on_happy_path(tmp_path):
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)

    with patch("boto3.client", side_effect=_boto3_factory()):
        _skill().collect(aws_client, session)

    status = _load_status(evidence_path)
    assert status["_schema"] == "drystone.collection_status.v1"
    assert status["_skill"] == "exposure"
    assert status["ok"] is True
    components = status["components"]
    for name in COMPONENT_NAMES:
        assert components[name] == {"ok": True}, f"{name}: {components.get(name)}"


def test_evidence_key_is_exposure_collection_status_stem(tmp_path):
    """Confirms the evidence dict key pre-checks will see once loaded by
    BaseSkill.analyze() (json_file.stem, per drystone/skills/base.py)."""
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)

    with patch("boto3.client", side_effect=_boto3_factory()):
        _skill().collect(aws_client, session)

    evidence: dict = {}
    for json_file in evidence_path.glob("*.json"):
        evidence[json_file.stem] = json.loads(json_file.read_text())

    assert "exposure-collection-status" in evidence
    assert evidence["exposure-collection-status"]["_skill"] == "exposure"


# ── Collection failures (list call itself fails) ────────────────────────


def test_s3_list_buckets_failure_is_collection_failed(tmp_path):
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)
    s3 = MagicMock()
    s3.list_buckets.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "ListBuckets"
    )

    with patch("boto3.client", side_effect=_boto3_factory(s3=s3)):
        _skill().collect(aws_client, session)

    status = _load_status(evidence_path)
    assert status["ok"] is False
    component = status["components"]["s3-buckets"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component["error_code"] == "AccessDenied"
    assert "not authorized" in component["error"]


def test_ec2_describe_security_groups_failure_is_collection_failed(tmp_path):
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)
    ec2 = MagicMock()
    ec2.describe_images.return_value = {"Images": []}
    ec2.describe_security_groups.side_effect = Exception("boom")

    with patch("boto3.client", side_effect=_boto3_factory(ec2=ec2)):
        _skill().collect(aws_client, session)

    status = _load_status(evidence_path)
    component = status["components"]["security-groups"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"


# ── Partial collection (per-item sub-calls fail after a successful list) ──


def test_s3_bucket_policy_unreadable_is_partial_collection(tmp_path):
    """list_buckets succeeds (2 buckets); get_bucket_policy fails for one
    bucket with a real error (not the expected "no policy" 404) -- the list
    call succeeded, so this is a coverage gap, matching the
    PLAN_VALIDATION_WARN.md example verbatim ("some bucket policies
    unreadable")."""
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)
    s3 = MagicMock()
    s3.list_buckets.return_value = {
        "Buckets": [{"Name": "bucket-a"}, {"Name": "bucket-b"}]
    }
    s3.get_bucket_acl.return_value = {"Grants": []}
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}

    def _get_public_access_block(Bucket):  # noqa: N803 (boto3 kwarg casing)
        raise ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "none"}},
            "GetPublicAccessBlock",
        )

    def _get_bucket_policy(Bucket):  # noqa: N803
        if Bucket == "bucket-b":
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "cannot read policy"}},
                "GetBucketPolicy",
            )
        raise ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "none"}}, "GetBucketPolicy"
        )

    def _get_bucket_encryption(Bucket):  # noqa: N803
        raise ClientError(
            {
                "Error": {
                    "Code": "ServerSideEncryptionConfigurationNotFoundError",
                    "Message": "none",
                }
            },
            "GetBucketEncryption",
        )

    s3.get_public_access_block.side_effect = _get_public_access_block
    s3.get_bucket_policy.side_effect = _get_bucket_policy
    s3.get_bucket_encryption.side_effect = _get_bucket_encryption

    with patch("boto3.client", side_effect=_boto3_factory(s3=s3)):
        _skill().collect(aws_client, session)

    status = _load_status(evidence_path)
    component = status["components"]["s3-buckets"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
    assert "1" in component["error"]

    data = json.loads((evidence_path / "s3-buckets.json").read_text())
    assert len(data["items"]) == 2


def test_s3_expected_absence_codes_do_not_mark_partial(tmp_path):
    """The common "no policy / no public access block / no custom
    encryption" 404s are a legitimate resource state, not a collection
    failure -- they must not flip s3-buckets to partial_collection."""
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "bucket-a"}]}
    s3.get_bucket_acl.return_value = {"Grants": []}
    s3.get_bucket_versioning.return_value = {"Status": None}
    s3.get_public_access_block.side_effect = ClientError(
        {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "none"}},
        "GetPublicAccessBlock",
    )
    s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "none"}}, "GetBucketPolicy"
    )
    s3.get_bucket_encryption.side_effect = ClientError(
        {
            "Error": {
                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                "Message": "none",
            }
        },
        "GetBucketEncryption",
    )

    with patch("boto3.client", side_effect=_boto3_factory(s3=s3)):
        _skill().collect(aws_client, session)

    status = _load_status(evidence_path)
    assert status["components"]["s3-buckets"] == {"ok": True}


def test_load_balancer_listeners_failure_is_partial_collection(tmp_path):
    """describe_load_balancers succeeds (1 LB) but describe_listeners fails
    for it: the list call succeeded, so this is a coverage gap."""
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)
    elbv2 = MagicMock()
    elbv2.describe_load_balancers.return_value = {
        "LoadBalancers": [
            {
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/lb1/abc",
                "LoadBalancerName": "lb1",
                "DNSName": "lb1.example.com",
                "Scheme": "internet-facing",
                "Type": "application",
                "VpcId": "vpc-1",
                "SecurityGroups": [],
                "AvailabilityZones": [],
            }
        ]
    }
    elbv2.describe_listeners.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "cannot read listeners"}},
        "DescribeListeners",
    )

    with patch("boto3.client", side_effect=_boto3_factory(elbv2=elbv2)):
        _skill().collect(aws_client, session)

    status = _load_status(evidence_path)
    component = status["components"]["load-balancers"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
    data = json.loads((evidence_path / "load-balancers.json").read_text())
    assert len(data["items"]) == 1


def test_resource_based_policies_partial_failure(tmp_path):
    """SQS's list_queues succeeds but SNS's list_topics (a different
    resource type collected independently in the same section) fails:
    a coverage gap in one sub-collector, not a total section failure."""
    aws_client = _make_aws_client()
    session, evidence_path = _make_session(tmp_path)
    sqs = MagicMock()
    sqs.list_queues.return_value = {"QueueUrls": []}
    sns = MagicMock()
    sns.get_paginator.side_effect = Exception("sns unavailable")

    with patch("boto3.client", side_effect=_boto3_factory(sqs=sqs, sns=sns)):
        _skill().collect(aws_client, session)

    status = _load_status(evidence_path)
    component = status["components"]["resource-based-policies"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
