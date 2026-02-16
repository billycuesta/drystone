"""Evidence-based validation tests for IAM findings to reduce false positives."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer


IAM_CHECKLIST = {
    "skill": "iam",
    "items": [
        {"id": "IAM-008", "severity": "Critical"},
        {"id": "IAM-011", "severity": "Critical"},
        {"id": "IAM-004", "severity": "Critical"},
        {"id": "IAM-014", "severity": "High"},
        {"id": "IAM-020", "severity": "Medium"},
    ],
}


def _finding(fid: str, severity: str) -> Finding:
    return Finding(
        id=fid,
        severity=severity,  # type: ignore[arg-type]
        risk_score=7.0,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=["policies.json#/0"],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_iam_008_rejected_when_no_wildcard_admin_policy():
    n = FindingsNormalizer(IAM_CHECKLIST, "iam")
    n.evidence = {
        "policies": [
            {
                "PolicyName": "ScopedKMS",
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["kms:Decrypt"],
                            "Resource": "arn:aws:kms:us-east-1:111:key/abc",
                        }
                    ]
                },
            }
        ]
    }

    out = n.normalize([_finding("IAM-008", "Critical")])
    assert out == []


def test_iam_008_accepted_when_wildcard_action_and_resource_present():
    n = FindingsNormalizer(IAM_CHECKLIST, "iam")
    n.evidence = {
        "policies": [
            {
                "PolicyName": "Admin",
                "PolicyDocument": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                },
            }
        ]
    }

    f = _finding("IAM-008", "Critical")
    f.evidence_snippet = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "IAM-008"


def test_iam_011_rejected_when_trust_not_public():
    n = FindingsNormalizer(IAM_CHECKLIST, "iam")
    n.evidence = {
        "roles": [
            {
                "RoleName": "X",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::222:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            }
        ]
    }
    f = _finding("IAM-011", "Critical")
    f.evidence_refs = ["roles.json#/0"]
    out = n.normalize([f])
    assert out == []


def test_iam_011_accepted_when_public_trust_present():
    n = FindingsNormalizer(IAM_CHECKLIST, "iam")
    n.evidence = {
        "roles": [
            {
                "RoleName": "X",
                "AssumeRolePolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            }
        ]
    }
    f = _finding("IAM-011", "Critical")
    f.evidence_refs = ["roles.json#/0"]
    out = n.normalize([f])
    assert len(out) == 1


def test_iam_014_rejected_when_only_one_active_key():
    n = FindingsNormalizer(IAM_CHECKLIST, "iam")
    n.evidence = {
        "users": [
            {
                "UserName": "u",
                "Groups": [],
                "AccessKeys": [
                    {
                        "AccessKeyId": "A",
                        "Status": "Active",
                        "CreateDate": "2026-01-01 00:00:00+00:00",
                    },
                    {
                        "AccessKeyId": "B",
                        "Status": "Inactive",
                        "CreateDate": "2026-01-02 00:00:00+00:00",
                    },
                ],
            }
        ]
    }
    f = _finding("IAM-014", "High")
    f.evidence_refs = ["users.json#/0"]
    out = n.normalize([f])
    assert out == []


def test_iam_020_accepted_when_user_has_no_groups():
    n = FindingsNormalizer(IAM_CHECKLIST, "iam")
    n.evidence = {
        "users": [
            {"UserName": "u", "Groups": [], "AccessKeys": []},
        ]
    }
    f = _finding("IAM-020", "Medium")
    f.evidence_refs = ["users.json#/0"]
    out = n.normalize([f])
    assert len(out) == 1
