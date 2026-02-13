"""Evidence-based validation tests for Secrets Manager findings."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer


SECRETSMANAGER_CHECKLIST = {
    "skill": "secretsmanager",
    "items": [
        {"id": "SM-001", "severity": "Critical"},
        {"id": "SM-002", "severity": "High"},
        {"id": "SM-003", "severity": "High"},
    ],
}


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid,
        severity="High",
        risk_score=7.0,
        title=f"{fid} title",
        description=f"{fid} description",
        evidence_refs=["secrets.json#db_user"],
        remediation="Fix",
        cis_reference="N/A",
    )


def test_sm_001_rejected_when_no_wildcard_principal_present():
    normalizer = FindingsNormalizer(SECRETSMANAGER_CHECKLIST, "secretsmanager")
    normalizer.evidence = {
        "secrets": {
            "secrets": [
                {"Name": "db_user", "ResourcePolicy": {}},
                {"Name": "ids_master_password", "ResourcePolicy": None},
            ]
        }
    }

    out = normalizer.normalize([_finding("SM-001")])
    assert out == []


def test_sm_001_accepted_when_wildcard_principal_present():
    normalizer = FindingsNormalizer(SECRETSMANAGER_CHECKLIST, "secretsmanager")
    normalizer.evidence = {
        "secrets": {
            "secrets": [
                {
                    "Name": "db_user",
                    "ResourcePolicy": {
                        "Statement": [{"Principal": "*", "Action": "secretsmanager:GetSecretValue"}]
                    },
                }
            ]
        }
    }

    out = normalizer.normalize([_finding("SM-001")])
    assert len(out) == 1
    assert out[0].id == "SM-001"


def test_sm_003_rejected_when_rotation_disabled_or_no_interval_over_90():
    normalizer = FindingsNormalizer(SECRETSMANAGER_CHECKLIST, "secretsmanager")
    normalizer.evidence = {
        "secrets": {
            "secrets": [
                {"Name": "db_user", "RotationEnabled": False, "RotationRules": {}},
                {"Name": "ids_master_password", "RotationEnabled": True, "RotationRules": {}},
                {
                    "Name": "redis_auth_token",
                    "RotationEnabled": True,
                    "RotationRules": {"AutomaticallyAfterDays": 30},
                },
            ]
        }
    }

    out = normalizer.normalize([_finding("SM-003")])
    assert out == []


def test_sm_003_accepted_when_interval_over_90_exists():
    normalizer = FindingsNormalizer(SECRETSMANAGER_CHECKLIST, "secretsmanager")
    normalizer.evidence = {
        "secrets": {
            "secrets": [
                {
                    "Name": "db_user",
                    "RotationEnabled": True,
                    "RotationRules": {"AutomaticallyAfterDays": 120},
                }
            ]
        }
    }

    out = normalizer.normalize([_finding("SM-003")])
    assert len(out) == 1
    assert out[0].id == "SM-003"
