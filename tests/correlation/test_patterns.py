"""Tests for dynamic correlation pattern registry."""

from drystone.correlation.patterns import PATTERN_REGISTRY
from drystone.models.findings import Finding


def test_dynamic_pattern_registered():
    patterns = {p.id: p for p in PATTERN_REGISTRY.all()}
    assert "iam_assume_role_privilege_escalation" in patterns
    assert "vulns_imdsv1_ssrf_credential_theft" in patterns
    assert "exposure_public_lambda_url_abuse" in patterns
    assert "network_tgw_lateral_movement" in patterns
    assert "vulns_ec2_user_data_secret_exposure" in patterns
    assert "exposure_api_gateway_no_waf" in patterns
    assert "exposure_api_unauthenticated_mutation_chain" in patterns
    assert "iam_resource_policy_wildcard_principal" in patterns
    assert "network_nat_egress_pivoting" in patterns
    assert "exposure_iam_public_api_privilege_escalation" in patterns
    assert "vulns_lambda_env_secret_leakage" in patterns
    assert "exposure_opensearch_public_data_exposure" in patterns
    assert "compute_ecs_scheduled_task_persistence" in patterns
    assert "compute_eks_public_endpoint_risk" in patterns
    assert "compute_ec2_imdsv1_instance_profile_credential_theft" in patterns
    assert "compute_lambda_public_url_overprivileged_role_chain" in patterns
    assert "exposure_iam_compute_entrypoint_chain" in patterns
    assert "cicd_codebuild_token_leakage_chain" in patterns
    assert "messaging_sqs_dlq_exfiltration_chain" in patterns
    assert "messaging_sns_sqs_unauth_exfiltration_chain" in patterns
    assert "messaging_queue_destruction_disruption_chain" in patterns
    assert "kms_policy_backdoor_exfil_chain" in patterns
    assert "cicd_iam_token_leakage_privilege_escalation" in patterns
    assert "messaging_iam_dlq_exfiltration_chain" in patterns
    assert "kms_iam_policy_backdoor_escalation_chain" in patterns
    assert "secretsmanager_rotation_hijack_persistence_chain" in patterns
    assert "secretsmanager_cross_region_backdoor_chain" in patterns
    assert "iam_oidc_ci_cd_webidentity_takeover_chain" in patterns
    assert "iam_policy_version_backdoor_persistence_chain" in patterns
    assert "iam_mfa_device_hijack_persistence_chain" in patterns
    assert "iam_authorization_wipeout_dos_chain" in patterns
    assert "vulns_ec2_userdata_iam_pivot_chain" in patterns
    assert "vulns_lambda_secret_public_entrypoint_chain" in patterns
    assert "exposure_s3_ransomware_impact_chain" in patterns
    assert "vulns_public_ebs_snapshot_exfiltration_chain" in patterns
    assert "alerting_sns_subscription_exfiltration_chain" in patterns
    assert "alerting_sns_publish_spoofing_chain" in patterns


def test_assume_role_pattern_matches_wildcard_trust():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["iam_assume_role_privilege_escalation"]

    findings_by_skill = {"iam": []}
    resource_index = {}
    evidence = {
        "iam": {
            "assumeRole-chains": {
                "chains": [
                    {
                        "RoleName": "AdminRole",
                        "TrustedPrincipals": ["arn:aws:iam::*:root"],
                    }
                ]
            }
        }
    }

    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_assume_role_pattern_does_not_match_without_wildcard():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["iam_assume_role_privilege_escalation"]

    findings_by_skill = {"iam": []}
    resource_index = {}
    evidence = {
        "iam": {
            "assumeRole-chains": {
                "chains": [
                    {
                        "RoleName": "AppRole",
                        "TrustedPrincipals": ["arn:aws:iam::123456789012:role/Deployer"],
                    }
                ]
            }
        }
    }

    assert pattern.matcher(findings_by_skill, resource_index, evidence) is False


def test_resource_policy_wildcard_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["iam_resource_policy_wildcard_principal"]

    findings_by_skill = {"iam": []}
    resource_index = {}
    evidence = {
        "iam": {
            "resource-based-policies": {
                "s3": [
                    {
                        "BucketName": "public-bucket",
                        "Policy": {
                            "Statement": [
                                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
                            ]
                        },
                    }
                ]
            }
        }
    }

    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_lambda_env_secret_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["vulns_lambda_env_secret_leakage"]
    findings_by_skill = {"vulns": []}
    resource_index = {}
    evidence = {
        "vulns": {
            "lambda-environment-variables": {
                "items": [
                    {
                        "FunctionName": "fn-a",
                        "PotentialSecretKeys": ["DB_PASSWORD"],
                    }
                ]
            }
        }
    }
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_exposure_api_unauthenticated_mutation_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "exposure_api_unauthenticated_mutation_chain"
    ]
    findings_by_skill = {
        "exposure": [
            Finding(
                id="EXP-021",
                severity="Critical",
                risk_score=9.0,
                title="Unauthenticated mutating API",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_alerting_sns_subscription_exfiltration_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "alerting_sns_subscription_exfiltration_chain"
    ]
    findings_by_skill = {
        "alerting": [
            Finding(
                id="ALRT-023",
                severity="High",
                risk_score=8.2,
                title="Permissive subscribe on alert SNS topic",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    assert pattern.matcher(findings_by_skill, {}, {}) is True


def test_alerting_sns_publish_spoofing_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["alerting_sns_publish_spoofing_chain"]
    findings_by_skill = {
        "alerting": [
            Finding(
                id="ALRT-022",
                severity="Critical",
                risk_score=9.0,
                title="Permissive publish on alert SNS topic",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    assert pattern.matcher(findings_by_skill, {}, {}) is True


def test_messaging_unauth_exfiltration_chain_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "messaging_sns_sqs_unauth_exfiltration_chain"
    ]
    findings_by_skill = {
        "messaging": [
            Finding(
                id="MSG-007",
                severity="High",
                risk_score=8.1,
                title="Wildcard SNS subscribe",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    assert pattern.matcher(findings_by_skill, {}, {}) is True


def test_messaging_destruction_disruption_chain_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "messaging_queue_destruction_disruption_chain"
    ]
    findings_by_skill = {
        "messaging": [
            Finding(
                id="MSG-005",
                severity="Critical",
                risk_score=9.0,
                title="Wildcard SQS data-plane",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ],
        "iam": [
            Finding(
                id="IAM-038",
                severity="Critical",
                risk_score=9.2,
                title="IAM delete wildcard",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ],
    }
    assert pattern.matcher(findings_by_skill, {}, {}) is True


def test_secretsmanager_rotation_hijack_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "secretsmanager_rotation_hijack_persistence_chain"
    ]
    findings_by_skill = {
        "secretsmanager": [
            Finding(
                id="SM-014",
                severity="High",
                risk_score=7.0,
                title="Rotation hijack risk",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            ),
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_secretsmanager_cross_region_backdoor_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "secretsmanager_cross_region_backdoor_chain"
    ]
    findings_by_skill = {
        "secretsmanager": [
            Finding(
                id="SM-017",
                severity="High",
                risk_score=7.2,
                title="Cross-region backdoor risk",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            ),
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_iam_oidc_webidentity_takeover_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["iam_oidc_ci_cd_webidentity_takeover_chain"]
    findings_by_skill = {
        "iam": [
            Finding(
                id="IAM-032",
                severity="Critical",
                risk_score=9.1,
                title="Broad OIDC trust",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            ),
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_iam_policy_version_backdoor_pattern_matches_with_overprivileged_signal():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "iam_policy_version_backdoor_persistence_chain"
    ]
    findings_by_skill = {
        "iam": [
            Finding(
                id="IAM-035",
                severity="Critical",
                risk_score=9.0,
                title="Policy version escalation",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            ),
            Finding(
                id="IAM-008",
                severity="Critical",
                risk_score=9.5,
                title="Wildcard admin permissions",
                description="Admin wildcard",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            ),
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_iam_mfa_hijack_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["iam_mfa_device_hijack_persistence_chain"]
    findings_by_skill = {
        "iam": [
            Finding(
                id="IAM-037",
                severity="High",
                risk_score=8.0,
                title="Broad MFA device manipulation",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_iam_authorization_wipeout_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["iam_authorization_wipeout_dos_chain"]
    findings_by_skill = {
        "iam": [
            Finding(
                id="IAM-038",
                severity="Critical",
                risk_score=9.4,
                title="IAM delete wildcard",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_compute_ec2_imdsv1_profile_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "compute_ec2_imdsv1_instance_profile_credential_theft"
    ]
    findings_by_skill = {"compute": []}
    resource_index = {}
    evidence = {
        "compute": {
            "ec2-inventory": {
                "instances": [
                    {
                        "InstanceId": "i-123",
                        "IamInstanceProfile": {"Arn": "arn:aws:iam::111:instance-profile/p1"},
                        "MetadataOptions": {"HttpTokens": "optional"},
                    }
                ]
            }
        }
    }
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_compute_lambda_public_url_overpriv_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "compute_lambda_public_url_overprivileged_role_chain"
    ]
    findings_by_skill = {"compute": []}
    resource_index = {}
    evidence = {
        "compute": {
            "lambda-inventory": {
                "functions": [
                    {
                        "FunctionName": "fn-a",
                        "AuthType": "NONE",
                        "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
                    }
                ]
            }
        }
    }
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_vulns_ec2_userdata_iam_pivot_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["vulns_ec2_userdata_iam_pivot_chain"]
    findings_by_skill = {
        "vulns": [
            Finding(
                id="VULN-023",
                severity="High",
                risk_score=7.2,
                title="EC2 user-data contains secrets",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ],
        "iam": [
            Finding(
                id="IAM-008",
                severity="Critical",
                risk_score=9.5,
                title="Wildcard admin",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ],
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_vulns_lambda_secret_public_entrypoint_pattern_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "vulns_lambda_secret_public_entrypoint_chain"
    ]
    findings_by_skill = {
        "vulns": [
            Finding(
                id="VULN-024",
                severity="High",
                risk_score=7.0,
                title="Lambda env secrets",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    resource_index = {}
    evidence = {
        "exposure": {
            "lambda-function-urls": {
                "function_urls": [
                    {"FunctionName": "fn-a", "IsPublic": True},
                ]
            }
        }
    }
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_exposure_s3_ransomware_impact_chain_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}["exposure_s3_ransomware_impact_chain"]
    findings_by_skill = {
        "exposure": [
            Finding(
                id="EXP-014",
                severity="High",
                risk_score=7.3,
                title="S3 versioning missing",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ],
        "iam": [
            Finding(
                id="IAM-038",
                severity="Critical",
                risk_score=9.4,
                title="IAM delete wildcard",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ],
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True


def test_vulns_public_ebs_snapshot_exfil_chain_matches():
    pattern = {p.id: p for p in PATTERN_REGISTRY.all()}[
        "vulns_public_ebs_snapshot_exfiltration_chain"
    ]
    findings_by_skill = {
        "vulns": [
            Finding(
                id="VULN-028",
                severity="Critical",
                risk_score=9.2,
                title="Public EBS snapshot",
                description="...",
                evidence_refs=[],
                affected_resources=[],
                remediation="...",
                cis_reference=None,
                pci_dss=[],
            )
        ]
    }
    resource_index = {}
    evidence = {}
    assert pattern.matcher(findings_by_skill, resource_index, evidence) is True
