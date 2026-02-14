"""Tests for evidence_refs normalization (ECR)."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

ECR_CHECKLIST = {
    "skill": "ecr",
    "items": [
        {"id": "ECR-001", "severity": "Critical"},
    ],
}


def test_ecr_evidence_refs_converted_to_json_pointers():
    normalizer = FindingsNormalizer(ECR_CHECKLIST, "ecr")
    normalizer.evidence = {
        "repositories": {
            "repositories": [
                {"RepositoryName": "repo-a", "RepositoryArn": "arn:..."},
                {
                    "RepositoryName": "repo-b",
                    "RepositoryArn": "arn:...",
                    "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
                },
            ]
        },
        "registry": {"registry": {}, "registry_policy": None, "registry_scanning": None},
    }

    f = Finding(
        id="ECR-001",
        severity="Critical",
        risk_score=9.5,
        title="Public repo",
        description="Policy allows wildcard",
        evidence_refs=[
            "repositories.json#repo-b",
            "repositories.json#all_repositories",
            "registry.json#registry_scanning",
            "repositories.json#/repositories/0",
        ],
        remediation="Fix",
        cis_reference="N/A",
    )

    out = normalizer.normalize([f])
    assert len(out) == 1
    assert out[0].evidence_refs == [
        "repositories.json#/repositories/1",
        "repositories.json#/repositories",
        "registry.json#/registry_scanning",
        "repositories.json#/repositories/0",
    ]
