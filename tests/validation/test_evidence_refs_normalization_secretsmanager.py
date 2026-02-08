"""Tests for evidence_refs normalization (Secrets Manager)."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer


SECRETSMANAGER_CHECKLIST = {
    "skill": "secretsmanager",
    "items": [
        {"id": "SM-002", "severity": "High"},
        {"id": "SM-012", "severity": "Medium"},
    ],
}


def test_secretsmanager_evidence_refs_converted_to_json_pointers():
    normalizer = FindingsNormalizer(SECRETSMANAGER_CHECKLIST, "secretsmanager")
    normalizer.evidence = {
        "secrets": {
            "secrets": [
                {"Name": "db_user", "ARN": "arn:...", "Region": "us-east-1"},
                {"Name": "ids_master_password", "ARN": "arn:...", "Region": "us-east-1"},
            ]
        },
        "cloudwatch_alarms": {"regions": {"us-east-1": {"alarm_count": 1, "likely_relevant": []}}},
        "eventbridge_rules": {
            "regions": {"us-east-1": {"relevant_rule_count": 0, "relevant_rules": []}}
        },
    }

    f = Finding(
        id="SM-012",
        severity="Medium",
        risk_score=4.0,
        title="Rotation alerting missing",
        description="No alerts",
        evidence_refs=[
            "secrets.json#db_user",
            "secrets.json#all_secrets",
            "cloudwatch_alarms.json#us-east-1",
            "eventbridge_rules.json#us-east-1",
            "secrets.json#/secrets/1",  # already normalized
        ],
        remediation="Fix",
    )

    out = normalizer.normalize([f])
    assert len(out) == 1
    assert out[0].evidence_refs == [
        "secrets.json#/secrets/0",
        "secrets.json#/secrets",
        "cloudwatch_alarms.json#/regions/us-east-1",
        "eventbridge_rules.json#/regions/us-east-1",
        "secrets.json#/secrets/1",
    ]
