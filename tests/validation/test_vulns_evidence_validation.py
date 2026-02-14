"""Evidence-based validation tests for vulns findings."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

VULNS_CHECKLIST = {
    "skill": "vulns",
    "items": [
        {"id": "VULN-001", "severity": "Critical"},
        {"id": "VULN-002", "severity": "Critical"},
        {"id": "VULN-009", "severity": "High"},
        {"id": "VULN-014", "severity": "High"},
    ],
}


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid,
        severity="High",
        risk_score=7.0,
        title=f"{fid} title",
        description=f"{fid} description",
        evidence_refs=["inspector-findings.json#sample"],
        remediation="Fix",
        cis_reference="N/A",
    )


def test_vuln_001_rejected_when_inspector_findings_exist():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {
        "inspector-findings": [
            {"severity": "HIGH", "status": "ACTIVE", "resources": [{"id": "r1"}]}
        ]
    }

    out = normalizer.normalize([_finding("VULN-001")])
    assert out == []


def test_vuln_001_accepted_when_inspector_findings_missing_or_empty():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {"inspector-findings": []}

    out = normalizer.normalize([_finding("VULN-001")])
    assert len(out) == 1
    assert out[0].id == "VULN-001"


def test_vuln_002_rejected_without_active_critical_findings():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {
        "inspector-findings": [
            {"severity": "HIGH", "status": "ACTIVE", "resources": [{"id": "r1"}]},
            {"severity": "CRITICAL", "status": "CLOSED", "resources": [{"id": "r2"}]},
        ]
    }

    out = normalizer.normalize([_finding("VULN-002")])
    assert out == []


def test_vuln_002_accepted_with_active_critical_findings():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {
        "inspector-findings": [
            {"severity": "CRITICAL", "status": "ACTIVE", "resources": [{"id": "r1"}]}
        ]
    }

    out = normalizer.normalize([_finding("VULN-002")])
    assert len(out) == 1
    assert out[0].id == "VULN-002"


def test_vuln_009_requires_accumulation_in_same_resource():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {
        "inspector-findings": [
            {"severity": "HIGH", "status": "ACTIVE", "resources": [{"id": "r1"}]},
            {"severity": "HIGH", "status": "ACTIVE", "resources": [{"id": "r2"}]},
        ]
    }

    out = normalizer.normalize([_finding("VULN-009")])
    assert out == []


def test_vuln_009_accepted_with_three_or_more_same_resource_findings():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {
        "inspector-findings": [
            {"severity": "HIGH", "status": "ACTIVE", "resources": [{"id": "r1"}]},
            {"severity": "HIGH", "status": "ACTIVE", "resources": [{"id": "r1"}]},
            {"severity": "CRITICAL", "status": "ACTIVE", "resources": [{"id": "r1"}]},
        ]
    }

    out = normalizer.normalize([_finding("VULN-009")])
    assert len(out) == 1
    assert out[0].id == "VULN-009"


def test_vuln_014_rejected_without_explicit_age_evidence():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {"rds-patch-info": [{"DBInstanceIdentifier": "cardsdb-co"}]}

    out = normalizer.normalize([_finding("VULN-014")])
    assert out == []


def test_vuln_014_accepted_with_age_evidence_gt_30_days():
    normalizer = FindingsNormalizer(VULNS_CHECKLIST, "vulns")
    normalizer.evidence = {"rds-patch-info": [{"DBInstanceIdentifier": "cardsdb-co"}]}

    finding = _finding("VULN-014")
    finding.evidence_snippet = {"patch_age_days": 45}
    out = normalizer.normalize([finding])
    assert len(out) == 1
    assert out[0].id == "VULN-014"
