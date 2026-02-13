"""Evidence-based validation tests for ECR findings."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer


ECR_CHECKLIST = {
    "skill": "ecr",
    "items": [
        {"id": "ECR-001", "severity": "Critical"},
        {"id": "ECR-003", "severity": "High"},
        {"id": "ECR-004", "severity": "Medium"},
        {"id": "ECR-007", "severity": "High"},
    ],
}


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid,
        severity="High",
        risk_score=7.0,
        title=f"{fid} title",
        description=f"{fid} description",
        evidence_refs=["repositories.json#repositories"],
        remediation="Fix",
        cis_reference="N/A",
    )


def test_ecr_001_rejected_when_no_wildcard_principal_present():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "repositories": {
            "repositories": [
                {"RepositoryName": "a", "Policy": None},
                {"RepositoryName": "b", "Policy": {}},
            ]
        }
    }

    out = normalizer.normalize([_finding("ECR-001")])
    assert out == []


def test_ecr_001_accepted_when_wildcard_principal_present():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "repositories": {
            "repositories": [
                {
                    "RepositoryName": "a",
                    "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
                }
            ]
        }
    }

    out = normalizer.normalize([_finding("ECR-001")])
    assert len(out) == 1
    assert out[0].id == "ECR-001"


def test_ecr_007_rejected_when_no_policy_or_no_cross_account_principals():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "registry": {"registry": {"registryId": "111111111111"}},
        "repositories": {
            "repositories": [
                {
                    "RepositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/a",
                    "Policy": None,
                },
                {
                    "RepositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/b",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111111111111:role/x"},
                            }
                        ]
                    },
                },
            ]
        },
    }

    out = normalizer.normalize([_finding("ECR-007")])
    assert out == []


def test_ecr_007_accepted_when_cross_account_principal_present():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "registry": {"registry": {"registryId": "111111111111"}},
        "repositories": {
            "repositories": [
                {
                    "RepositoryArn": "arn:aws:ecr:us-east-1:111111111111:repository/a",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::222222222222:role/y"},
                            }
                        ]
                    },
                }
            ]
        },
    }

    out = normalizer.normalize([_finding("ECR-007")])
    assert len(out) == 1
    assert out[0].id == "ECR-007"


def test_ecr_004_rejected_when_registry_scanning_has_error():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "registry": {"registry_scanning": {"error": "UnsupportedOperationInSDK"}},
        "repositories": {"repositories": []},
    }

    out = normalizer.normalize([_finding("ECR-004")])
    assert out == []


def test_ecr_003_rejected_when_enhanced_registry_scanning_covers_repo():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "registry": {
            "registry_scanning": {
                "scanningConfiguration": {
                    "scanType": "ENHANCED",
                    "rules": [
                        {
                            "scanFrequency": "CONTINUOUS_SCAN",
                            "repositoryFilters": [{"filter": "*", "filterType": "WILDCARD"}],
                        }
                    ],
                }
            }
        },
        "repositories": {"repositories": [{"RepositoryName": "mtr", "ScanOnPush": False}]},
    }

    f = _finding("ECR-003")
    f.evidence_snippet = {"RepositoryName": "mtr", "ScanOnPush": False}
    f.affected_resources = ["arn:aws:ecr:us-east-1:111111111111:repository/mtr"]
    out = normalizer.normalize([f])
    assert out == []


def test_ecr_003_accepted_when_enhanced_registry_scanning_does_not_cover_repo():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "registry": {
            "registry_scanning": {
                "scanningConfiguration": {
                    "scanType": "ENHANCED",
                    "rules": [
                        {
                            "scanFrequency": "CONTINUOUS_SCAN",
                            "repositoryFilters": [{"filter": "cards", "filterType": "WILDCARD"}],
                        }
                    ],
                }
            }
        },
        "repositories": {"repositories": [{"RepositoryName": "mtr", "ScanOnPush": False}]},
    }

    f = _finding("ECR-003")
    f.evidence_snippet = {"RepositoryName": "mtr", "ScanOnPush": False}
    out = normalizer.normalize([f])
    assert len(out) == 1
    assert out[0].id == "ECR-003"
