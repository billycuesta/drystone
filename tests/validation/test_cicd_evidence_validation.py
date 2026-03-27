"""Evidence-based validation tests for CICD findings."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

CICD_CHECKLIST = {
    "skill": "cicd",
    "items": [
        {"id": "CICD-001", "severity": "High"},
        {"id": "CICD-002", "severity": "High"},
    ],
}


def _finding(fid: str) -> Finding:
    ref = "codebuild-projects.json#/items/0"
    if fid == "CICD-001":
        ref = "codebuild-source-credentials.json#/items/0"
    return Finding(
        id=fid,
        severity="High",
        risk_score=7.4,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=[ref],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_cicd_001_rejected_when_no_source_credentials():
    n = FindingsNormalizer(CICD_CHECKLIST, "cicd")
    n.evidence = {"codebuild-source-credentials": {"items": []}}
    out = n.normalize([_finding("CICD-001")])
    assert out == []


def test_cicd_001_accepted_when_source_credentials_present():
    n = FindingsNormalizer(CICD_CHECKLIST, "cicd")
    n.evidence = {
        "codebuild-source-credentials": {
            "items": [
                {
                    "arn": "arn:aws:codebuild:us-east-1:111:source-credential/abc",
                    "serverType": "GITHUB",
                    "authType": "PERSONAL_ACCESS_TOKEN",
                }
            ]
        }
    }
    out = n.normalize([_finding("CICD-001")])
    assert len(out) == 1
    assert out[0].id == "CICD-001"


def test_cicd_002_rejected_when_no_insecure_ssl_or_proxy_indicator():
    n = FindingsNormalizer(CICD_CHECKLIST, "cicd")
    n.evidence = {
        "codebuild-projects": {
            "items": [
                {
                    "name": "p1",
                    "source": {"insecureSsl": False},
                    "environment": {
                        "environmentVariables": [{"name": "HTTPS_PROXY", "looks_like_proxy": False}]
                    },
                }
            ]
        }
    }

    out = n.normalize([_finding("CICD-002")])
    assert out == []


def test_cicd_002_accepted_when_insecure_ssl_present():
    n = FindingsNormalizer(CICD_CHECKLIST, "cicd")
    n.evidence = {
        "codebuild-projects": {
            "items": [
                {
                    "name": "p1",
                    "source": {"insecureSsl": True},
                    "environment": {"environmentVariables": []},
                }
            ]
        }
    }

    out = n.normalize([_finding("CICD-002")])
    assert len(out) == 1
    assert out[0].id == "CICD-002"
