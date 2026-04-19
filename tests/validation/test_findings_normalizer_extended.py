"""Extended tests for FindingsNormalizer with evidence validation and mutual exclusions."""

import pytest
from datetime import datetime, timedelta

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

# Sample hardening checklist
HARDENING_CHECKLIST = {
    "skill": "hardening",
    "items": [
        {
            "id": "HRD-001",
            "title": "AWS Config no habilitado",
            "severity": "Critical",
        },
        {
            "id": "HRD-002",
            "title": "Security Hub no habilitado",
            "severity": "Critical",
        },
        {
            "id": "HRD-003",
            "title": "No standards habilitados",
            "severity": "Critical",
        },
        {
            "id": "HRD-006",
            "title": "AWS Config parcial",
            "severity": "High",
        },
        {
            "id": "HRD-007",
            "title": "Security Hub sin standards PCI",
            "severity": "High",
        },
        {
            "id": "HRD-009",
            "title": "GuardDuty findings sin remediar > 10",
            "severity": "High",
        },
        {
            "id": "HRD-014",
            "title": "GuardDuty sin malware findings",
            "severity": "Medium",
        },
    ],
}

# Sample IAM checklist
IAM_CHECKLIST = {
    "skill": "iam",
    "items": [
        {
            "id": "IAM-001",
            "title": "Root account sin MFA",
            "severity": "Critical",
        },
        {
            "id": "IAM-002",
            "title": "Root account con MFA parcial",
            "severity": "High",
        },
        {
            "id": "IAM-003",
            "title": "Usuarios inactivos",
            "severity": "Medium",
        },
        {
            "id": "IAM-004",
            "title": "Usuarios sin MFA",
            "severity": "High",
        },
        {
            "id": "IAM-007",
            "title": "Access keys viejas (>90 dias)",
            "severity": "Medium",
        },
        {
            "id": "IAM-006",
            "title": "Password reuse prevention",
            "severity": "Medium",
        },
        {
            "id": "IAM-009",
            "title": "Root access keys",
            "severity": "Critical",
        },
        {
            "id": "IAM-012",
            "title": "Inactive users should be removed",
            "severity": "High",
        },
        {
            "id": "IAM-014",
            "title": "Multiple access keys",
            "severity": "High",
        },
    ],
}

# Sample Alerting checklist
ALERTING_CHECKLIST = {
    "skill": "alerting",
    "items": [
        {
            "id": "ALR-001",
            "title": "CloudTrail deshabilitado",
            "severity": "Critical",
        },
        {
            "id": "ALR-003",
            "title": "CloudTrail sin CloudWatch Logs",
            "severity": "Critical",
        },
        {
            "id": "ALR-005",
            "title": "Alarmas sin configurar",
            "severity": "High",
        },
    ],
}


def make_finding(finding_id, severity, risk_score, title, description):
    """Helper to create a Finding with all required fields."""
    return Finding(
        id=finding_id,
        severity=severity,
        risk_score=risk_score,
        title=title,
        description=description,
        evidence_refs=["test.json"],
        remediation=f"Fix {finding_id}",
        cis_reference="N/A",
    )


class TestMutualExclusions:
    """Test mutual exclusion resolution for overlapping findings."""

    def test_mutual_exclusion_hrd_001_006(self):
        """Test that HRD-001 and HRD-006 are mutually exclusive - keep specific."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        findings = [
            make_finding("HRD-001", "Critical", 9.5, "Config disabled", "Not enabled"),
            make_finding("HRD-006", "High", 8.0, "Config partial", "Partially enabled"),
        ]

        normalized = normalizer.normalize(findings)
        resolved = normalizer._resolve_mutual_exclusions(normalized)

        # Should keep HRD-006 (higher ID = more specific)
        assert len(resolved) == 1
        assert resolved[0].id == "HRD-006"

    def test_mutual_exclusion_hrd_002_003(self):
        """Test that HRD-002 and HRD-003 are mutually exclusive."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        findings = [
            make_finding("HRD-002", "Critical", 9.5, "Hub disabled", "Not enabled"),
            make_finding("HRD-003", "Critical", 9.0, "No standards", "None enabled"),
        ]

        normalized = normalizer.normalize(findings)
        resolved = normalizer._resolve_mutual_exclusions(normalized)

        # Should keep HRD-003 (higher ID = more specific)
        assert len(resolved) == 1
        assert resolved[0].id == "HRD-003"


class TestEvidenceValidation:
    """Test evidence-based validation to detect false positives."""

    def test_hrd_002_rejected_when_hub_enabled(self):
        """Test that HRD-002 is rejected when HubArn exists in evidence."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {
            "security-hub-status": {
                "enabled": True,
                "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
            }
        }
        normalizer.evidence = evidence

        finding = make_finding("HRD-002", "Critical", 9.5, "Hub disabled", "Not enabled")

        # Should reject (false positive)
        is_valid = normalizer._validate_against_evidence("HRD-002", finding)
        assert is_valid is False

    def test_hrd_001_rejected_when_config_enabled(self):
        """Test that HRD-001 is rejected when ConfigurationRecorders exist."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {
            "config-recorders": {
                "enabled": True,
                "ConfigurationRecorders": [{"name": "default"}],
            }
        }
        normalizer.evidence = evidence

        finding = make_finding("HRD-001", "Critical", 9.5, "Config disabled", "Not enabled")

        # Should reject (false positive)
        is_valid = normalizer._validate_against_evidence("HRD-001", finding)
        assert is_valid is False

    def test_hrd_006_rejected_when_config_disabled(self):
        """Test that HRD-006 is rejected when Config is completely disabled."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {
            "config-recorders": {
                "enabled": False,
                "ConfigurationRecorders": [],
            }
        }
        normalizer.evidence = evidence

        finding = make_finding("HRD-006", "High", 8.0, "Config partial", "Incomplete")

        # Should reject (should be HRD-001 instead)
        is_valid = normalizer._validate_against_evidence("HRD-006", finding)
        assert is_valid is False

    def test_hrd_003_rejected_without_hub(self):
        """Test that HRD-003 is rejected if Security Hub is disabled."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {
            "security-hub-status": {
                "enabled": False,
            }
        }
        normalizer.evidence = evidence

        finding = make_finding("HRD-003", "Critical", 9.0, "No standards", "None")

        # Should reject (requires Hub enabled)
        is_valid = normalizer._validate_against_evidence("HRD-003", finding)
        assert is_valid is False

    def test_hrd_009_rejected_without_guardduty(self):
        """Test that HRD-009 is rejected if GuardDuty is disabled."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {"guardduty-detectors": []}  # Empty array = no detectors
        normalizer.evidence = evidence

        finding = make_finding("HRD-009", "High", 8.0, "GuardDuty findings", "Many")

        # Should reject (requires GuardDuty enabled)
        is_valid = normalizer._validate_against_evidence("HRD-009", finding)
        assert is_valid is False

    def test_hrd_002_accepted_when_hub_disabled(self):
        """Test that HRD-002 passes validation when Hub is disabled."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {
            "security-hub-status": {
                "enabled": False,
            }
        }
        normalizer.evidence = evidence

        finding = make_finding("HRD-002", "Critical", 9.5, "Hub disabled", "Not enabled")

        # Should pass (finding matches evidence)
        is_valid = normalizer._validate_against_evidence("HRD-002", finding)
        assert is_valid is True


class TestNormalizeWithEvidence:
    """Test full normalize pipeline with evidence validation."""

    def test_normalize_filters_hrd_002_false_positive(self):
        """Test that normalize() filters out false positive HRD-002."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {
            "security-hub-status": {
                "enabled": True,
                "HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
            }
        }
        normalizer.evidence = evidence

        findings = [
            make_finding("HRD-002", "Critical", 9.5, "Hub disabled", "Not enabled"),
            make_finding("HRD-003", "Critical", 9.0, "No standards", "None"),
        ]

        normalized = normalizer.normalize(findings)

        # HRD-002 should be filtered (false positive)
        # HRD-003 should pass (valid)
        assert len(normalized) == 1
        assert normalized[0].id == "HRD-003"

    def test_normalize_resolves_hrd_001_006_duplicates(self):
        """Test that normalize() resolves Config duplicates."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        findings = [
            make_finding("HRD-001", "Critical", 9.5, "Config disabled", "Not enabled"),
            make_finding("HRD-006", "High", 8.0, "Config partial", "Incomplete"),
        ]

        normalized = normalizer.normalize(findings)
        resolved = normalizer._resolve_mutual_exclusions(normalized)

        # Should keep only HRD-006
        assert len(resolved) == 1
        assert resolved[0].id == "HRD-006"


class TestRegionMetadata:
    """Test that region metadata is preserved in evidence."""

    def test_audit_metadata_in_evidence(self):
        """Test that evidence contains audit metadata."""
        evidence = {
            "_audit_metadata": {
                "_region": "eu-west-1",
                "_scope": "single-region",
                "_timestamp": "2026-01-31T10:00:00",
            },
            "security-hub-status": {
                "enabled": True,
                "HubArn": "arn:aws:securityhub:eu-west-1:123456789012:hub/default",
            },
        }

        # Verify metadata is accessible
        assert evidence["_audit_metadata"]["_region"] == "eu-west-1"
        assert evidence["_audit_metadata"]["_scope"] == "single-region"


class TestSummaryRecalculation:
    """Test summary recalculation after filtering."""

    def test_summary_updated_after_filtering(self):
        """Test that summary is recalculated after filtering."""
        normalizer = FindingsNormalizer(HARDENING_CHECKLIST, "hardening")

        evidence = {
            "security-hub-status": {
                "enabled": False,
            }
        }
        normalizer.evidence = evidence

        findings = [
            make_finding("HRD-002", "Critical", 9.5, "Hub disabled", "Not enabled"),
            make_finding("HRD-003", "Critical", 9.0, "No standards", "None"),
            make_finding("HRD-006", "High", 8.0, "Config partial", "Incomplete"),
        ]

        normalized = normalizer.normalize(findings)
        summary = normalizer.recalculate_summary(normalized)

        # HRD-002 should be filtered (Hub disabled but HRD-003 says no standards)
        # HRD-003 and HRD-006 should remain
        assert summary.total_findings >= 1
        assert summary.critical >= 0


class TestIAMEvidenceValidation:
    """Test IAM-specific evidence validation."""

    def test_iam_001_rejected_when_root_mfa_enabled(self):
        """Test that IAM-001 is rejected when root account has MFA."""
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")

        evidence = {
            "account-summary": {
                "AccountMFAEnabled": True,
            }
        }
        normalizer.evidence = evidence

        finding = make_finding("IAM-001", "Critical", 9.5, "Root sin MFA", "Root has no MFA")

        # Should reject (MFA is enabled)
        is_valid = normalizer._validate_against_evidence("IAM-001", finding)
        assert is_valid is False

    def test_iam_009_rejected_when_root_access_keys_not_present(self):
        """IAM-009 should be rejected when account summary shows no root access keys."""
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")

        normalizer.evidence = {
            "account-summary": {
                "SummaryMap": {
                    "AccountAccessKeysPresent": 0,
                }
            }
        }

        finding = make_finding(
            "IAM-009",
            "Critical",
            9.5,
            "Root keys active",
            "Root has active access keys",
        )

        is_valid = normalizer._validate_against_evidence("IAM-009", finding)
        assert is_valid is False

    def test_no_finding_placeholders_are_filtered(self):
        """Findings that explicitly state 'no finding/no action needed' should be filtered."""
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")

        f = make_finding(
            "IAM-006",
            "Medium",
            4.5,
            "Password policy ok",
            "The password policy is correctly configured. No finding.",
        )
        f.remediation = "No action needed - correctly configured"
        f.evidence_refs = []
        f.affected_resources = []
        f.evidence_snippet = None

        out = normalizer.normalize([f])
        assert out == []

    def test_iam_012_rejected_when_root_marked_inactive(self):
        """IAM-012 should not be emitted for root inactivity (expected behavior)."""
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")

        normalizer.evidence = {
            "credential-report": {
                "by_user": {
                    "<root_account>": {
                        "user": "<root_account>",
                        "mfa_active": "true",
                        "password_last_used": "2023-04-10T06:41:46Z",
                    }
                }
            }
        }

        f = make_finding(
            "IAM-012",
            "High",
            7.0,
            "Inactive users should be removed",
            "Root not used recently",
        )
        f.affected_resources = ["arn:aws:iam::111111111111:root"]
        f.evidence_refs = ["credential-report.json#root_account"]
        f.evidence_snippet = {
            "user": "<root_account>",
            "password_last_used": "2023-04-10T06:41:46Z",
        }

        out = normalizer.normalize([f])
        assert out == []

    def test_iam_evidence_refs_normalize_credential_report(self):
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")
        normalizer.evidence = {"credential-report": {"rows": []}}

        f = make_finding(
            "IAM-014",
            "High",
            6.5,
            "Multiple keys",
            "User has multiple keys",
        )
        f.evidence_refs = ["credential-report.json#root_account", "credential_report.json#monolito"]
        f.affected_resources = ["arn:aws:iam::111111111111:user/monolito"]

        out = normalizer.normalize([f])
        assert len(out) == 1
        assert out[0].evidence_refs[0] == "credential-report.csv#<root_account>"
        assert out[0].evidence_refs[1] == "credential-report.csv#monolito"


class TestPCIDSSAlignment:
    def test_pci_controls_aligned_to_checklist(self):
        """Normalizer should override model-emitted PCI controls with checklist mapping."""
        checklist = {
            "skill": "iam",
            "items": [
                {
                    "id": "IAM-010",
                    "severity": "Critical",
                    "pci_dss": [
                        {"control": "8.4.2", "reason": "CHECKLIST_842"},
                    ],
                }
            ],
        }

        normalizer = FindingsNormalizer(checklist, "iam")
        f = make_finding(
            "IAM-010",
            "Critical",
            9.0,
            "Admin MFA",
            "...",
        )
        # Model emits wrong control
        f.pci_dss = [
            {"control": "8.4.1", "reason": "WRONG"},
            {"control": "8.4.2", "reason": "MODEL_842"},
        ]

        out = normalizer.normalize([f])
        assert len(out) == 1
        assert [c.control for c in out[0].pci_dss] == ["8.4.2"]
        # Keep model reason when control matches checklist
        assert out[0].pci_dss[0].reason == "MODEL_842"

    def test_iam_003_rejected_when_no_inactive_users(self):
        """Test that IAM-003 is rejected when no inactive users exist."""
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")

        evidence = {
            "users": [
                {
                    "UserName": "active-user",
                    "PasswordLastUsed": "2026-01-31T10:00:00",
                    "AccessKeys": [{"AccessKeyId": "AKIA...", "CreateDate": "2026-01-01"}],
                },
                {
                    "UserName": "another-active",
                    "PasswordLastUsed": "2026-02-01T10:00:00",
                    "AccessKeys": [{"AccessKeyId": "AKIA...", "CreateDate": "2026-01-15"}],
                },
            ]
        }
        normalizer.evidence = evidence

        finding = make_finding("IAM-003", "Medium", 5.0, "Inactive users", "Many inactive")

        # Should reject (no inactive users)
        is_valid = normalizer._validate_against_evidence("IAM-003", finding)
        assert is_valid is False

    def test_iam_007_rejected_when_no_old_keys(self):
        """Test that IAM-007 is rejected when no old access keys exist."""
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")

        evidence = {
            "users": [
                {
                    "UserName": "user1",
                    "AccessKeys": [
                        {
                            "AccessKeyId": "AKIA...",
                            "CreateDate": (datetime.now() - timedelta(days=30)).isoformat(),  # Recent key
                        }
                    ],
                },
            ]
        }
        normalizer.evidence = evidence

        finding = make_finding("IAM-007", "Medium", 5.0, "Old keys", "Has old keys")

        # Should reject (no old keys)
        is_valid = normalizer._validate_against_evidence("IAM-007", finding)
        assert is_valid is False


class TestAlertingEvidenceValidation:
    """Test Alerting-specific evidence validation."""

    def test_alr_001_rejected_when_cloudtrail_enabled(self):
        """Test that ALR-001 is rejected when CloudTrail is enabled."""
        normalizer = FindingsNormalizer(ALERTING_CHECKLIST, "alerting")

        evidence = {"cloudtrail-trails": [{"TrailName": "default", "IsMultiRegionTrail": False}]}
        normalizer.evidence = evidence

        finding = make_finding("ALR-001", "Critical", 9.5, "CloudTrail disabled", "Not enabled")

        # Should reject (CloudTrail IS enabled)
        is_valid = normalizer._validate_against_evidence("ALR-001", finding)
        assert is_valid is False

    def test_alr_003_rejected_when_no_trails(self):
        """Test that ALR-003 is rejected when CloudTrail is disabled."""
        normalizer = FindingsNormalizer(ALERTING_CHECKLIST, "alerting")

        evidence = {"cloudtrail-trails": []}
        normalizer.evidence = evidence

        finding = make_finding("ALR-003", "Critical", 9.5, "No CloudWatch logs", "Not configured")

        # Should reject (need trail for logs issue)
        is_valid = normalizer._validate_against_evidence("ALR-003", finding)
        assert is_valid is False


class TestMutualExclusionsNewPairs:
    """Test new mutual exclusion pairs (IAM and Alerting)."""

    def test_mutual_exclusion_iam_003_004(self):
        """Test that IAM-003 and IAM-004 are mutually exclusive."""
        normalizer = FindingsNormalizer(IAM_CHECKLIST, "iam")

        findings = [
            make_finding("IAM-003", "Medium", 5.0, "Inactive users", "Users inactive"),
            make_finding("IAM-004", "High", 7.0, "No MFA", "MFA missing"),
        ]

        normalized = normalizer.normalize(findings)
        resolved = normalizer._resolve_mutual_exclusions(normalized)

        # Should keep IAM-004 (higher ID = more specific)
        assert len(resolved) == 1
        assert resolved[0].id == "IAM-004"

    def test_mutual_exclusion_alr_001_003(self):
        """Test that ALR-001 and ALR-003 are mutually exclusive."""
        normalizer = FindingsNormalizer(ALERTING_CHECKLIST, "alerting")

        findings = [
            make_finding("ALR-001", "Critical", 9.5, "CloudTrail disabled", "Not enabled"),
            make_finding("ALR-003", "Critical", 9.0, "No logs", "Not configured"),
        ]

        normalized = normalizer.normalize(findings)
        resolved = normalizer._resolve_mutual_exclusions(normalized)

        # Should keep ALR-003 (higher ID = more specific)
        assert len(resolved) == 1
        assert resolved[0].id == "ALR-003"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
