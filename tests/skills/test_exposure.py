import json
from unittest.mock import Mock, patch

from drystone.models.findings import FindingsSummary, SkillFindings
from drystone.skills.exposure import ExposureSkill
from drystone.storage.session import AuditSession


class _DummyCloudFrontClient:
    def list_distributions(self):
        return {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "E123ABC",
                        "ARN": "arn:aws:cloudfront::111111111111:distribution/E123ABC",
                        "DomainName": "d123.example.cloudfront.net",
                        "Enabled": True,
                    }
                ]
            }
        }


class _DummyShieldClient:
    def __init__(self, state: str):
        self.state = state
        self.list_protections_calls = []

    def describe_subscription_state(self):
        return {"SubscriptionState": self.state}

    def list_protections(self, **kwargs):
        self.list_protections_calls.append(kwargs)
        if kwargs.get("NextToken"):
            return {"Protections": []}
        return {
            "Protections": [
                {
                    "ResourceArn": "arn:aws:cloudfront::111111111111:distribution/E123ABC"
                }
            ],
            "NextToken": "page-2",
        }


def _make_exposure_collection_fixtures(tmp_path, shield_state):
    aws_client = Mock()
    aws_client.region_name = "eu-west-1"
    aws_client.client_kwargs.return_value = {
        "aws_access_key_id": "AKID",
        "aws_secret_access_key": "SECRET",
        "region_name": "eu-west-1",
    }
    session = Mock(spec=AuditSession)
    session.account_id = "111111111111"
    session.get_evidence_path.return_value = tmp_path / "evidence"
    shield_client = _DummyShieldClient(shield_state)

    def client_factory(service_name, **kwargs):
        if service_name == "cloudfront":
            return _DummyCloudFrontClient()
        if service_name == "shield":
            assert kwargs["region_name"] == "us-east-1"
            return shield_client
        raise RuntimeError(f"No fixture for {service_name}")

    return aws_client, session, shield_client, client_factory


def test_exposure_collects_active_shield_protections(tmp_path):
    aws_client, session, shield_client, client_factory = _make_exposure_collection_fixtures(
        tmp_path, "ACTIVE"
    )

    with patch("drystone.skills.exposure.boto3.client", side_effect=client_factory):
        ExposureSkill().collect(aws_client, session)

    evidence = json.loads(
        (tmp_path / "evidence" / "shield-protection-status.json").read_text()
    )
    assert evidence == {
        "subscription_state": "ACTIVE",
        "protected_resource_arns": [
            "arn:aws:cloudfront::111111111111:distribution/E123ABC"
        ],
    }
    assert shield_client.list_protections_calls == [{}, {"NextToken": "page-2"}]


def test_exposure_collects_inactive_shield_without_listing_protections(tmp_path):
    aws_client, session, shield_client, client_factory = _make_exposure_collection_fixtures(
        tmp_path, "INACTIVE"
    )

    with patch("drystone.skills.exposure.boto3.client", side_effect=client_factory):
        ExposureSkill().collect(aws_client, session)

    evidence = json.loads(
        (tmp_path / "evidence" / "shield-protection-status.json").read_text()
    )
    assert evidence == {"subscription_state": "INACTIVE", "protected_resource_arns": []}
    assert shield_client.list_protections_calls == []


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
