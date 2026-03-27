"""Evidence-based validation tests for KMS findings."""

from typing import Literal

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

KMS_CHECKLIST = {
    "skill": "kms",
    "items": [
        {"id": "KMS-001", "severity": "Critical"},
        {"id": "KMS-002", "severity": "High"},
        {"id": "KMS-003", "severity": "High"},
        {"id": "KMS-004", "severity": "Medium"},
    ],
}


def _finding(
    fid: str,
    severity: Literal["Critical", "High", "Medium", "Low"],
    risk: float,
    ref: str,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        risk_score=risk,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=[ref],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_kms_001_rejected_when_no_wildcard_principal():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-key-policies": {
            "items": [
                {
                    "KeyId": "key-1",
                    "PolicyName": "default",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                                "Action": "kms:Decrypt",
                            }
                        ]
                    },
                }
            ]
        }
    }

    out = n.normalize([_finding("KMS-001", "Critical", 9.2, "kms-key-policies.json#/items/0")])
    assert out == []


def test_kms_001_accepted_when_wildcard_principal_present():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-key-policies": {
            "items": [
                {
                    "KeyId": "key-1",
                    "PolicyName": "default",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "kms:Decrypt",
                            }
                        ]
                    },
                }
            ]
        }
    }

    out = n.normalize([_finding("KMS-001", "Critical", 9.2, "kms-key-policies.json#/items/0")])
    assert len(out) == 1
    assert out[0].id == "KMS-001"


def test_kms_002_rejected_when_no_decrypt_or_generatedatakey_grants():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-grants": {
            "items": [{"KeyId": "key-1", "GranteePrincipal": "arn:...", "Operations": ["Encrypt"]}]
        }
    }

    out = n.normalize([_finding("KMS-002", "High", 7.2, "kms-grants.json#/items/0")])
    assert out == []


def test_kms_002_accepted_when_decrypt_grant_present():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-grants": {
            "items": [{"KeyId": "key-1", "GranteePrincipal": "arn:...", "Operations": ["Decrypt"]}]
        }
    }

    out = n.normalize([_finding("KMS-002", "High", 7.2, "kms-grants.json#/items/0")])
    assert len(out) == 1
    assert out[0].id == "KMS-002"


def test_kms_003_rejected_when_no_admin_actions_present():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-key-policies": {
            "items": [
                {
                    "KeyId": "key-1",
                    "PolicyName": "default",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                                "Action": "kms:Decrypt",
                            }
                        ]
                    },
                }
            ]
        }
    }
    out = n.normalize([_finding("KMS-003", "High", 7.5, "kms-key-policies.json#/items/0")])
    assert out == []


def test_kms_003_accepted_when_putkeypolicy_present():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-key-policies": {
            "items": [
                {
                    "KeyId": "key-1",
                    "PolicyName": "default",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                                "Action": ["kms:PutKeyPolicy"],
                            }
                        ]
                    },
                }
            ]
        }
    }
    out = n.normalize([_finding("KMS-003", "High", 7.5, "kms-key-policies.json#/items/0")])
    assert len(out) == 1
    assert out[0].id == "KMS-003"


def test_kms_004_rejected_when_no_rotation_disabled_keys():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-keys": {
            "items": [
                {
                    "KeyId": "key-1",
                    "Metadata": {"KeyManager": "CUSTOMER"},
                    "KeyRotationEnabled": True,
                }
            ]
        }
    }
    out = n.normalize([_finding("KMS-004", "Medium", 4.5, "kms-keys.json#/items/0")])
    assert out == []


def test_kms_004_accepted_when_rotation_disabled_key_present():
    n = FindingsNormalizer(KMS_CHECKLIST, "kms")
    n.evidence = {
        "kms-keys": {
            "items": [
                {
                    "KeyId": "key-1",
                    "Metadata": {"KeyManager": "CUSTOMER"},
                    "KeyRotationEnabled": False,
                }
            ]
        }
    }
    out = n.normalize([_finding("KMS-004", "Medium", 4.5, "kms-keys.json#/items/0")])
    assert len(out) == 1
    assert out[0].id == "KMS-004"
