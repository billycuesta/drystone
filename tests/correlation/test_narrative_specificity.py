"""Regression tests for P1: Pentest Skill Quality Audit, rec. A/F.

Before this fix, every finding matching a given correlation pattern got
identical attack_path/remediation text -- the narrative functions received
the real match context and discarded it. These tests construct two DIFFERENT
findings/evidence matching the SAME pattern and assert the resulting text
actually differs. A regression back to generic-only text must fail here,
even though it wouldn't fail any pre-existing structural test.

Covers a representative sample across pattern categories: evidence-based
matchers (assume_role, messaging DLQ, CI/CD), finding-ID-based matchers
(OIDC takeover, KMS ransomware), and a multi-skill composite (S3 ransomware).
"""

from drystone.correlation.patterns import PATTERN_REGISTRY
from drystone.models.findings import Finding


def _pattern(pattern_id):
    return {p.id: p for p in PATTERN_REGISTRY.all()}[pattern_id]


def _finding(id, resource, **overrides):
    defaults = dict(
        severity="Critical",
        risk_score=9.0,
        title="Finding",
        description="...",
        evidence_refs=[],
        affected_resources=[resource],
        remediation="...",
        cis_reference=None,
        pci_dss=[],
    )
    defaults.update(overrides)
    return Finding(id=id, **defaults)


def test_assume_role_narrative_varies_by_role():
    pattern = _pattern("iam_assume_role_privilege_escalation")

    def context_for(role_name, role_arn):
        return {
            "evidence_by_skill": {
                "iam": {
                    "assumeRole-chains": {
                        "chains": [
                            {
                                "RoleName": role_name,
                                "Arn": role_arn,
                                "TrustedPrincipals": ["*"],
                            }
                        ]
                    }
                }
            },
            "findings_by_skill": {},
        }

    ctx_a = context_for("AdminRoleA", "arn:aws:iam::111111111111:role/AdminRoleA")
    ctx_b = context_for("AdminRoleB", "arn:aws:iam::222222222222:role/AdminRoleB")

    path_a = pattern.attack_path_generator(ctx_a)
    path_b = pattern.attack_path_generator(ctx_b)
    remediation_a = pattern.remediation_generator(ctx_a)
    remediation_b = pattern.remediation_generator(ctx_b)

    assert path_a != path_b
    assert "AdminRoleA" in " ".join(path_a)
    assert "AdminRoleB" in " ".join(path_b)
    assert remediation_a != remediation_b
    assert "AdminRoleA" in " ".join(remediation_a)
    assert "AdminRoleB" in " ".join(remediation_b)


def test_iam_oidc_takeover_narrative_varies_by_role():
    pattern = _pattern("iam_oidc_ci_cd_webidentity_takeover_chain")

    ctx_a = {
        "evidence_by_skill": {},
        "findings_by_skill": {"iam": [_finding("IAM-032", "arn:aws:iam::111111111111:role/CIRoleA")]},
    }
    ctx_b = {
        "evidence_by_skill": {},
        "findings_by_skill": {"iam": [_finding("IAM-034", "arn:aws:iam::222222222222:role/CIRoleB")]},
    }

    path_a = pattern.attack_path_generator(ctx_a)
    path_b = pattern.attack_path_generator(ctx_b)

    assert path_a != path_b
    assert "CIRoleA" in " ".join(path_a)
    assert "CIRoleB" in " ".join(path_b)


def test_kms_ransomware_narrative_varies_by_key():
    pattern = _pattern("kms_ransomware_availability_chain")

    ctx_a = {
        "evidence_by_skill": {},
        "findings_by_skill": {"kms": [_finding("KMS-005", "arn:aws:kms:us-east-1:111111111111:key/key-a")]},
    }
    ctx_b = {
        "evidence_by_skill": {},
        "findings_by_skill": {"kms": [_finding("KMS-006", "arn:aws:kms:us-east-1:222222222222:key/key-b")]},
    }

    path_a = pattern.attack_path_generator(ctx_a)
    path_b = pattern.attack_path_generator(ctx_b)
    remediation_a = pattern.remediation_generator(ctx_a)
    remediation_b = pattern.remediation_generator(ctx_b)

    assert path_a != path_b
    assert "key-a" in " ".join(path_a)
    assert "key-b" in " ".join(path_b)
    assert remediation_a != remediation_b


def test_messaging_dlq_narrative_varies_by_queue():
    pattern = _pattern("messaging_sqs_dlq_exfiltration_chain")

    def context_for(queue_arn):
        return {
            "evidence_by_skill": {
                "messaging": {
                    "sqs-queues": {
                        "items": [{"QueueArn": queue_arn, "RedrivePolicy": {"maxReceiveCount": 3}}]
                    }
                }
            },
            "findings_by_skill": {},
        }

    ctx_a = context_for("arn:aws:sqs:us-east-1:111111111111:queue-a")
    ctx_b = context_for("arn:aws:sqs:us-east-1:222222222222:queue-b")

    path_a = pattern.attack_path_generator(ctx_a)
    path_b = pattern.attack_path_generator(ctx_b)

    assert path_a != path_b
    assert "queue-a" in " ".join(path_a)
    assert "queue-b" in " ".join(path_b)


def test_cicd_token_leakage_narrative_varies_by_project():
    pattern = _pattern("cicd_codebuild_token_leakage_chain")

    def context_for(project_name):
        return {
            "evidence_by_skill": {
                "cicd": {
                    "codebuild-projects": {
                        "items": [{"name": project_name, "source": {"insecureSsl": True}}]
                    }
                }
            },
            "findings_by_skill": {},
        }

    ctx_a = context_for("build-project-a")
    ctx_b = context_for("build-project-b")

    path_a = pattern.attack_path_generator(ctx_a)
    path_b = pattern.attack_path_generator(ctx_b)
    remediation_a = pattern.remediation_generator(ctx_a)
    remediation_b = pattern.remediation_generator(ctx_b)

    assert path_a != path_b
    assert "build-project-a" in " ".join(path_a)
    assert "build-project-b" in " ".join(path_b)
    assert remediation_a != remediation_b


def test_s3_ransomware_narrative_varies_by_bucket_and_role():
    """Multi-skill composite pattern (exposure + iam)."""
    pattern = _pattern("exposure_s3_ransomware_impact_chain")

    def context_for(bucket_arn, role_arn):
        return {
            "evidence_by_skill": {},
            "findings_by_skill": {
                "exposure": [_finding("EXP-001", bucket_arn)],
                "iam": [_finding("IAM-038", role_arn)],
            },
        }

    ctx_a = context_for(
        "arn:aws:s3:::bucket-a", "arn:aws:iam::111111111111:role/DestructiveRoleA"
    )
    ctx_b = context_for(
        "arn:aws:s3:::bucket-b", "arn:aws:iam::222222222222:role/DestructiveRoleB"
    )

    path_a = pattern.attack_path_generator(ctx_a)
    path_b = pattern.attack_path_generator(ctx_b)

    assert path_a != path_b
    assert "bucket-a" in " ".join(path_a)
    assert "bucket-b" in " ".join(path_b)
    assert "DestructiveRoleA" in " ".join(path_a)
    assert "DestructiveRoleB" in " ".join(path_b)
