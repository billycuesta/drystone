import json
from unittest.mock import Mock

from drystone.skills.exposure import ExposureSkill
from drystone.models.findings import SkillFindings, FindingsSummary
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
        "rds-snapshots.json",
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
