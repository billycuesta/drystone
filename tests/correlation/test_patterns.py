"""Tests for dynamic correlation pattern registry."""

from drystone.correlation.patterns import PATTERN_REGISTRY


def test_dynamic_pattern_registered():
    patterns = {p.id: p for p in PATTERN_REGISTRY.all()}
    assert "iam_assume_role_privilege_escalation" in patterns
    assert "vulns_imdsv1_ssrf_credential_theft" in patterns
    assert "exposure_public_lambda_url_abuse" in patterns
    assert "network_tgw_lateral_movement" in patterns
    assert "vulns_ec2_user_data_secret_exposure" in patterns
    assert "exposure_api_gateway_no_waf" in patterns
    assert "iam_resource_policy_wildcard_principal" in patterns
    assert "network_nat_egress_pivoting" in patterns
    assert "exposure_iam_public_api_privilege_escalation" in patterns
    assert "vulns_lambda_env_secret_leakage" in patterns
    assert "exposure_opensearch_public_data_exposure" in patterns
    assert "network_privatelink_lateral_enumeration" in patterns
    assert "compute_ecs_scheduled_task_persistence" in patterns
    assert "compute_eks_public_endpoint_risk" in patterns
    assert "exposure_iam_compute_entrypoint_chain" in patterns
    assert "cicd_codebuild_token_leakage_chain" in patterns
    assert "messaging_sqs_dlq_exfiltration_chain" in patterns
    assert "kms_policy_backdoor_exfil_chain" in patterns
    assert "cicd_iam_token_leakage_privilege_escalation" in patterns
    assert "messaging_iam_dlq_exfiltration_chain" in patterns
    assert "kms_iam_policy_backdoor_escalation_chain" in patterns


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
