"""Evidence-based validation tests for hardening findings."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

HARDENING_CHECKLIST = {
    "skill": "hardening",
    "items": [
        {"id": "HRD-003", "severity": "Critical"},
        {"id": "HRD-004", "severity": "Critical"},
        {"id": "HRD-006", "severity": "High"},
        {"id": "HRD-009", "severity": "High"},
        {"id": "HRD-012", "severity": "Medium"},
        {"id": "HRD-013", "severity": "Medium"},
        {"id": "HRD-016", "severity": "Low"},
        {"id": "HRD-017", "severity": "Low"},
        {"id": "HRD-011", "severity": "Medium"},
    ],
}


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid,
        severity="High",
        risk_score=7.0,
        title=f"{fid} title",
        description=f"{fid} description",
        evidence_refs=["security-hub-findings#sample"],
        evidence_snippet={"sample": True},
        remediation="Fix",
        cis_reference="N/A",
    )


def test_hrd_003_rejected_when_standards_are_enabled():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-status": {"HubArn": "arn:aws:securityhub:us-east-1:111111111111:hub/default"},
        "security-hub-enabled-standards": [{"Status": "READY", "ControlsSummary": {"enabled": 42}}],
    }

    out = normalizer.normalize([_finding("HRD-003")])
    assert out == []


def test_hrd_003_accepted_when_hub_enabled_but_no_standards_enabled():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-status": {"HubArn": "arn:aws:securityhub:us-east-1:111111111111:hub/default"},
        "security-hub-enabled-standards": [],
    }

    out = normalizer.normalize([_finding("HRD-003")])
    assert len(out) == 1
    assert out[0].id == "HRD-003"


def test_hrd_006_rejected_when_config_fully_operational():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "config-recorders": {"ConfigurationRecorders": [{"name": "default"}]},
        "config-recorder-status": {"ConfigurationRecordersStatus": [{"recording": True}]},
        "config-delivery-channels": {"DeliveryChannels": [{"s3BucketName": "cfg-bucket"}]},
    }

    out = normalizer.normalize([_finding("HRD-006")])
    assert out == []


def test_hrd_006_accepted_when_config_incomplete_no_delivery_channel():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "config-recorders": {"ConfigurationRecorders": [{"name": "default"}]},
        "config-recorder-status": {"ConfigurationRecordersStatus": [{"recording": True}]},
        "config-delivery-channels": {"DeliveryChannels": []},
    }

    out = normalizer.normalize([_finding("HRD-006")])
    assert len(out) == 1
    assert out[0].id == "HRD-006"


def test_hrd_score_bands_mutually_exclusive():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    findings = [_finding("HRD-004"), _finding("HRD-011")]
    normalized = normalizer.normalize(findings)
    resolved = normalizer._resolve_mutual_exclusions(normalized)

    assert len(resolved) == 1
    assert resolved[0].id == "HRD-004"


def test_hardening_evidence_refs_are_normalized_to_json_files():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {"_audit_metadata": {"_region": "us-east-1"}}
    finding = _finding("HRD-011")
    finding.evidence_refs = [
        "security-hub-findings#APIGateway.8",
        "security-hub-findings-summary#severity_counts",
    ]

    out = normalizer.normalize([finding])
    assert len(out) == 1
    refs = out[0].evidence_refs
    assert refs[0] == "security-hub-findings.json#APIGateway.8"
    assert refs[1] == "security-hub-findings-summary.json#severity_counts"


def test_hrd_009_rejected_when_global_high_count_not_above_threshold():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-findings-summary": {
            "severity_counts": {"CRITICAL": 0, "HIGH": 10, "MEDIUM": 50, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 0, "FAILED": 10, "WARNING": 0},
        }
    }

    finding = _finding("HRD-009")
    finding.evidence_refs = []
    out = normalizer.normalize([finding])
    assert out == []


def test_hrd_012_accepted_when_global_medium_count_above_threshold():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-findings-summary": {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 21, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 0, "FAILED": 21, "WARNING": 0},
        }
    }

    finding = _finding("HRD-012")
    finding.evidence_refs = []
    finding.evidence_snippet = {"MEDIUM": 21}
    out = normalizer.normalize([finding])
    assert len(out) == 1
    assert out[0].id == "HRD-012"


def test_hardening_rejects_unresolvable_security_hub_refs():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-findings": [
            {
                "Id": "arn:aws:securityhub:us-east-1:111111111111:security-control/GuardDuty.7/finding/abcd",
                "GeneratorId": "security-control/GuardDuty.7",
                "Title": "GuardDuty EKS Runtime Monitoring should be enabled",
            }
        ]
    }

    finding = _finding("HRD-009")
    finding.evidence_refs = ["security-hub-findings.json#metadata"]
    out = normalizer.normalize([finding])
    assert out == []


def test_hrd_016_rejected_when_global_low_count_is_zero():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-findings-summary": {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 0, "FAILED": 0, "WARNING": 0},
        }
    }

    finding = _finding("HRD-016")
    finding.severity = "Low"
    finding.risk_score = 2.5
    finding.evidence_refs = []
    finding.evidence_snippet = {"total_low": 0}
    out = normalizer.normalize([finding])
    assert out == []


def test_hrd_012_rejected_when_narrative_says_below_threshold():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-findings-summary": {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 135, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 0, "FAILED": 115, "WARNING": 0},
        }
    }

    finding = _finding("HRD-012")
    finding.evidence_refs = []
    finding.description = "There are 15 medium findings, below the >20 threshold."
    out = normalizer.normalize([finding])
    assert out == []


def test_hrd_017_rejected_without_tagging_evidence():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "password-policy": {"PasswordPolicy": {"MinimumPasswordLength": 14}},
    }

    finding = _finding("HRD-017")
    finding.severity = "Low"
    finding.risk_score = 1.5
    finding.evidence_refs = ["password-policy.json"]
    out = normalizer.normalize([finding])
    assert out == []


def test_hrd_013_rejected_when_no_standard_refs():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-enabled-standards": [
            {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"}
        ]
    }

    finding = _finding("HRD-013")
    finding.description = "Standards appear outdated"
    finding.evidence_refs = ["config-compliance.json#rule-a"]
    out = normalizer.normalize([finding])
    assert out == []


def test_hrd_013_accepted_with_outdated_standard_and_standard_ref():
    normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")
    normalizer.evidence = {
        "security-hub-enabled-standards": [
            {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"}
        ]
    }

    finding = _finding("HRD-013")
    finding.description = "Legacy PCI DSS standard version is still enabled"
    finding.evidence_refs = [
        "security-hub-enabled-standards.json#arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"
    ]
    finding.evidence_snippet = {"outdated": ["pci-dss/v/3.2.1"]}
    out = normalizer.normalize([finding])
    assert len(out) == 1
    assert out[0].id == "HRD-013"
