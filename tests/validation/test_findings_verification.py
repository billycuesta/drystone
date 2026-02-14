"""Tests for generic finding verification layer."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

CHECKLIST = {
    "skill": "iam",
    "items": [
        {"id": "IAM-001", "severity": "Critical", "title": "Root MFA disabled"},
        {"id": "IAM-002", "severity": "High", "title": "Overly permissive policy"},
    ],
}


def test_verification_rejects_missing_evidence_refs():
    n = FindingsNormalizer(CHECKLIST, "iam")
    n.evidence = {"users": [{"UserName": "root", "MfaActive": False}]}
    finding = Finding(
        id="IAM-001",
        severity="Critical",
        risk_score=9.0,
        title="x",
        description="x",
        evidence_refs=[],
        evidence_snippet={"UserName": "root", "MfaActive": False},
        affected_resources=["root"],
        remediation="x",
        cis_reference="1.5",
    )

    out = n.normalize([finding])
    assert out == []


def test_verification_rejects_critical_without_critical_evidence():
    n = FindingsNormalizer(CHECKLIST, "iam")
    n.evidence = {"users": [{"UserName": "alice"}]}
    finding = Finding(
        id="IAM-001",
        severity="Critical",
        risk_score=9.0,
        title="x",
        description="x",
        evidence_refs=["users.json#0"],
        evidence_snippet={"UserName": "alice"},
        affected_resources=["alice"],
        remediation="x",
        cis_reference="1.5",
    )

    out = n.normalize([finding])
    assert out == []


def test_verification_accepts_well_formed_finding():
    n = FindingsNormalizer(CHECKLIST, "iam")
    n.evidence = {"users": [{"UserName": "root", "AccessKeys": ["AKIA..."]}]}
    finding = Finding(
        id="IAM-001",
        severity="Critical",
        risk_score=9.0,
        title="x",
        description="x",
        evidence_refs=["users.json#root"],
        evidence_snippet={"UserName": "root", "AccessKeys": ["AKIA..."]},
        affected_resources=["root"],
        remediation="x",
        cis_reference="1.5",
    )

    out = n.normalize([finding])
    assert len(out) == 1
    assert out[0].id == "IAM-001"
