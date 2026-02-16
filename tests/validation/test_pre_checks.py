"""Tests for deterministic pre-checks (Tier 1 validation).

Verifies that pre-checks produce correct PASS/FAIL/SKIP results
based on known evidence patterns.
"""

import pytest

from drystone.validation.pre_checks import (
    PreCheckResult,
    format_pre_checks_for_prompt,
    run_pre_checks,
    check_iam_001,
    check_iam_004,
    check_iam_008,
    check_iam_009,
    check_iam_011,
    check_iam_014,
    check_iam_020,
    check_hrd_001,
    check_hrd_002,
    check_hrd_003,
    check_hrd_005,
    check_hrd_006,
    check_hrd_014,
    check_alr_001,
    check_alr_003,
    check_exp_001,
    check_exp_002,
    check_exp_003,
    check_net_001,
    check_net_018,
    check_sm_001,
    check_sm_003,
    check_ecr_001,
    check_ecr_004,
    check_ecr_007,
    check_kms_001,
    check_kms_004,
    check_waf_013,
    check_msg_001,
    check_msg_002,
    check_cicd_001,
    check_cicd_002,
    check_comp_eks_001,
    check_comp_eks_002,
    check_comp_ecs_002,
    check_comp_ecs_003,
)


# ============================================================================
# IAM CHECKS
# ============================================================================


class TestIAM001:
    def test_pass_when_mfa_enabled_summary_map(self):
        evidence = {"account-summary": {"SummaryMap": {"AccountMFAEnabled": 1}}}
        r = check_iam_001(evidence)
        assert r.status == "PASS"
        assert r.check_id == "IAM-001"

    def test_pass_when_mfa_enabled_flat(self):
        evidence = {"account-summary": {"AccountMFAEnabled": 1}}
        r = check_iam_001(evidence)
        assert r.status == "PASS"

    def test_fail_when_mfa_disabled(self):
        evidence = {"account-summary": {"SummaryMap": {"AccountMFAEnabled": 0}}}
        r = check_iam_001(evidence)
        assert r.status == "FAIL"
        assert "root" in r.affected_resources[0]

    def test_pass_with_credential_report_fallback(self):
        evidence = {
            "account-summary": {"SummaryMap": {"AccountMFAEnabled": 0}},
            "credential-report": {
                "by_user": {"<root_account>": {"mfa_active": "true"}}
            },
        }
        r = check_iam_001(evidence)
        assert r.status == "PASS"


class TestIAM009:
    def test_pass_when_no_root_keys(self):
        evidence = {"account-summary": {"SummaryMap": {"AccountAccessKeysPresent": 0}}}
        r = check_iam_009(evidence)
        assert r.status == "PASS"

    def test_fail_when_root_keys_present(self):
        evidence = {"account-summary": {"SummaryMap": {"AccountAccessKeysPresent": 1}}}
        r = check_iam_009(evidence)
        assert r.status == "FAIL"

    def test_pass_with_credential_report_both_inactive(self):
        evidence = {
            "account-summary": {"SummaryMap": {"AccountAccessKeysPresent": 1}},
            "credential-report": {
                "by_user": {"<root_account>": {
                    "access_key_1_active": "false",
                    "access_key_2_active": "false",
                }}
            },
        }
        r = check_iam_009(evidence)
        assert r.status == "PASS"


class TestIAM008:
    def test_pass_when_no_admin_policies(self):
        evidence = {
            "policies": [
                {"PolicyName": "ReadOnly", "PolicyDocument": {
                    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
                }}
            ]
        }
        r = check_iam_008(evidence)
        assert r.status == "PASS"

    def test_fail_when_wildcard_admin(self):
        evidence = {
            "policies": [
                {"PolicyName": "Admin", "Arn": "arn:aws:iam::123:policy/Admin",
                 "PolicyDocument": {
                     "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                 }}
            ]
        }
        r = check_iam_008(evidence)
        assert r.status == "FAIL"

    def test_skip_when_no_policies(self):
        r = check_iam_008({"policies": []})
        assert r.status == "SKIP"


class TestIAM011:
    def test_pass_when_no_public_trust(self):
        evidence = {
            "roles": [
                {"RoleName": "Lambda", "AssumeRolePolicyDocument": {
                    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}]
                }}
            ]
        }
        r = check_iam_011(evidence)
        assert r.status == "PASS"

    def test_fail_when_wildcard_principal(self):
        evidence = {
            "roles": [
                {"RoleName": "OpenRole", "Arn": "arn:aws:iam::123:role/OpenRole",
                 "AssumeRolePolicyDocument": {
                     "Statement": [{"Effect": "Allow", "Principal": "*"}]
                 }}
            ]
        }
        r = check_iam_011(evidence)
        assert r.status == "FAIL"


class TestIAM014:
    def test_pass_when_single_key(self):
        evidence = {
            "users": [
                {"UserName": "alice", "AccessKeys": [
                    {"AccessKeyId": "AKIA1", "Status": "Active"},
                ]}
            ]
        }
        r = check_iam_014(evidence)
        assert r.status == "PASS"

    def test_fail_when_two_active_keys(self):
        evidence = {
            "users": [
                {"UserName": "bob", "AccessKeys": [
                    {"AccessKeyId": "AKIA1", "Status": "Active"},
                    {"AccessKeyId": "AKIA2", "Status": "Active"},
                ]}
            ]
        }
        r = check_iam_014(evidence)
        assert r.status == "FAIL"


class TestIAM020:
    def test_pass_when_all_have_groups(self):
        evidence = {"users": [{"UserName": "alice", "Groups": [{"GroupName": "admin"}]}]}
        r = check_iam_020(evidence)
        assert r.status == "PASS"

    def test_fail_when_no_groups(self):
        evidence = {"users": [{"UserName": "alice", "Groups": []}]}
        r = check_iam_020(evidence)
        assert r.status == "FAIL"


# ============================================================================
# HARDENING CHECKS
# ============================================================================


class TestHRD001:
    def test_pass_when_recorders_exist(self):
        r = check_hrd_001({"config-recorders": {"ConfigurationRecorders": [{"name": "default"}]}})
        assert r.status == "PASS"

    def test_fail_when_no_recorders(self):
        r = check_hrd_001({"config-recorders": {"ConfigurationRecorders": []}})
        assert r.status == "FAIL"


class TestHRD002:
    def test_pass_when_hub_enabled(self):
        r = check_hrd_002({"security-hub-status": {"HubArn": "arn:aws:securityhub:us-east-1:123:hub/default"}})
        assert r.status == "PASS"

    def test_fail_when_no_hub(self):
        r = check_hrd_002({"security-hub-status": {}})
        assert r.status == "FAIL"


class TestHRD003:
    def test_skip_when_hub_disabled(self):
        r = check_hrd_003({"security-hub-status": {}})
        assert r.status == "SKIP"

    def test_pass_when_standards_enabled(self):
        r = check_hrd_003({
            "security-hub-status": {"HubArn": "arn:aws:securityhub:..."},
            "security-hub-enabled-standards": [{"Status": "READY"}],
        })
        assert r.status == "PASS"

    def test_fail_when_no_standards(self):
        r = check_hrd_003({
            "security-hub-status": {"HubArn": "arn:aws:securityhub:..."},
            "security-hub-enabled-standards": [],
        })
        assert r.status == "FAIL"


class TestHRD014:
    def test_pass_when_detectors_present(self):
        r = check_hrd_014({"guardduty-detectors": ["detector-123"]})
        assert r.status == "PASS"

    def test_fail_when_no_detectors(self):
        r = check_hrd_014({"guardduty-detectors": []})
        assert r.status == "FAIL"


# ============================================================================
# ALERTING CHECKS
# ============================================================================


class TestALR001:
    def test_pass_when_trails_exist(self):
        r = check_alr_001({"cloudtrail-trails": [{"Name": "main"}]})
        assert r.status == "PASS"

    def test_fail_when_no_trails(self):
        r = check_alr_001({"cloudtrail-trails": []})
        assert r.status == "FAIL"


class TestALR003:
    def test_skip_when_no_trails(self):
        r = check_alr_003({"cloudtrail-trails": []})
        assert r.status == "SKIP"

    def test_pass_when_log_group_present(self):
        r = check_alr_003({"cloudtrail-trails": [
            {"Name": "main", "CloudWatchLogsLogGroupArn": "arn:aws:logs:..."}
        ]})
        assert r.status == "PASS"

    def test_fail_when_no_log_group(self):
        r = check_alr_003({"cloudtrail-trails": [{"Name": "main"}]})
        assert r.status == "FAIL"


# ============================================================================
# EXPOSURE CHECKS
# ============================================================================


class TestEXP002:
    def test_pass_when_no_public_rds(self):
        r = check_exp_002({"rds-instances": [{"DBInstanceIdentifier": "db1", "PubliclyAccessible": False}]})
        assert r.status == "PASS"

    def test_fail_when_public_rds(self):
        r = check_exp_002({"rds-instances": [{"DBInstanceIdentifier": "db1", "PubliclyAccessible": True}]})
        assert r.status == "FAIL"


class TestEXP003:
    def test_pass_when_no_open_ssh(self):
        evidence = {"security-groups": {"by_id": {"sg-1": {
            "GroupId": "sg-1",
            "IngressRules": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                              "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        }}}}
        r = check_exp_003(evidence)
        assert r.status == "PASS"

    def test_fail_when_ssh_open(self):
        evidence = {"security-groups": {"by_id": {"sg-1": {
            "GroupId": "sg-1",
            "IngressRules": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                              "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
        }}}}
        r = check_exp_003(evidence)
        assert r.status == "FAIL"


# ============================================================================
# NETWORK CHECKS
# ============================================================================


class TestNET001:
    def test_pass_no_sensitive_ports(self):
        evidence = {"security-groups": [{"GroupId": "sg-1", "IngressRules": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]}]}
        r = check_net_001(evidence)
        assert r.status == "PASS"

    def test_fail_db_port_exposed(self):
        evidence = {"security-groups": [{"GroupId": "sg-1", "IngressRules": [
            {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]}]}
        r = check_net_001(evidence)
        assert r.status == "FAIL"


class TestNET018:
    def test_pass_flow_logs_active(self):
        evidence = {"vpcs": [{"VpcId": "vpc-1", "FlowLogs": [{"FlowLogStatus": "ACTIVE"}]}]}
        r = check_net_018(evidence)
        assert r.status == "PASS"

    def test_fail_no_flow_logs(self):
        evidence = {"vpcs": [{"VpcId": "vpc-1", "FlowLogs": []}]}
        r = check_net_018(evidence)
        assert r.status == "FAIL"


# ============================================================================
# SECRETS MANAGER CHECKS
# ============================================================================


class TestSM001:
    def test_pass_no_wildcard(self):
        r = check_sm_001({"secrets": {"secrets": [
            {"Name": "secret1", "ResourcePolicy": {"Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}}
            ]}}
        ]}})
        assert r.status == "PASS"

    def test_fail_wildcard_principal(self):
        r = check_sm_001({"secrets": {"secrets": [
            {"Name": "secret1", "ARN": "arn:aws:sm:...", "ResourcePolicy": {"Statement": [
                {"Effect": "Allow", "Principal": "*"}
            ]}}
        ]}})
        assert r.status == "FAIL"


class TestSM003:
    def test_pass_rotation_within_90(self):
        r = check_sm_003({"secrets": {"secrets": [
            {"Name": "s1", "RotationEnabled": True, "RotationRules": {"AutomaticallyAfterDays": 30}}
        ]}})
        assert r.status == "PASS"

    def test_fail_rotation_over_90(self):
        r = check_sm_003({"secrets": {"secrets": [
            {"Name": "s1", "ARN": "arn:...", "RotationEnabled": True,
             "RotationRules": {"AutomaticallyAfterDays": 120}}
        ]}})
        assert r.status == "FAIL"


# ============================================================================
# ECR CHECKS
# ============================================================================


class TestECR001:
    def test_pass_no_wildcard(self):
        r = check_ecr_001({"repositories": {"repositories": [
            {"repositoryName": "app", "Policy": {"Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}}
            ]}}
        ]}})
        assert r.status == "PASS"

    def test_fail_wildcard(self):
        r = check_ecr_001({"repositories": {"repositories": [
            {"repositoryName": "app", "RepositoryArn": "arn:...",
             "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]}}
        ]}})
        assert r.status == "FAIL"


class TestECR004:
    def test_pass_scanning_configured(self):
        r = check_ecr_004({"registry": {"registry_scanning": {
            "scanningConfiguration": {"scanType": "BASIC"}
        }}})
        assert r.status == "PASS"

    def test_fail_no_scanning(self):
        r = check_ecr_004({"registry": {"registry_scanning": {}}})
        assert r.status == "FAIL"

    def test_skip_error(self):
        r = check_ecr_004({"registry": {"registry_scanning": {"error": "AccessDenied"}}})
        assert r.status == "SKIP"


# ============================================================================
# KMS CHECKS
# ============================================================================


class TestKMS001:
    def test_pass_no_wildcard(self):
        r = check_kms_001({"kms-key-policies": {"items": [
            {"KeyId": "k1", "Policy": {"Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}}
            ]}}
        ]}})
        assert r.status == "PASS"

    def test_fail_wildcard(self):
        r = check_kms_001({"kms-key-policies": {"items": [
            {"KeyId": "k1", "KeyArn": "arn:...",
             "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]}}
        ]}})
        assert r.status == "FAIL"


class TestKMS004:
    def test_pass_rotation_enabled(self):
        r = check_kms_004({"kms-keys": {"items": [
            {"KeyId": "k1", "Metadata": {"KeyManager": "CUSTOMER"}, "KeyRotationEnabled": True}
        ]}})
        assert r.status == "PASS"

    def test_fail_rotation_disabled(self):
        r = check_kms_004({"kms-keys": {"items": [
            {"KeyId": "k1", "KeyArn": "arn:...",
             "Metadata": {"KeyManager": "CUSTOMER"}, "KeyRotationEnabled": False}
        ]}})
        assert r.status == "FAIL"


# ============================================================================
# WAF CHECKS
# ============================================================================


class TestWAF013:
    def test_pass_no_failures(self):
        r = check_waf_013({"waf-collection-status": {"cloudfront": {"ok": True}}})
        assert r.status == "PASS"

    def test_fail_when_failures(self):
        r = check_waf_013({"waf-collection-status": {"cloudfront": {"ok": False}}})
        assert r.status == "FAIL"


# ============================================================================
# MESSAGING CHECKS
# ============================================================================


class TestMSG001:
    def test_pass_orgid_present(self):
        r = check_msg_001({"sqs-queues": {"items": [
            {"QueueUrl": "q1", "Policy": {"Statement": [
                {"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}
            ]}}
        ]}})
        assert r.status == "PASS"

    def test_fail_no_orgid(self):
        r = check_msg_001({"sqs-queues": {"items": [
            {"QueueUrl": "q1", "Policy": {"Statement": [{"Effect": "Allow"}]}}
        ]}})
        assert r.status == "FAIL"


class TestMSG002:
    def test_pass_redrive_present(self):
        r = check_msg_002({"sqs-queues": {"items": [
            {"QueueUrl": "q1", "RedrivePolicy": {"deadLetterTargetArn": "arn:..."}}
        ]}})
        assert r.status == "PASS"

    def test_fail_no_redrive(self):
        r = check_msg_002({"sqs-queues": {"items": [{"QueueUrl": "q1"}]}})
        assert r.status == "FAIL"


# ============================================================================
# CICD CHECKS
# ============================================================================


class TestCICD001:
    def test_pass_no_credentials(self):
        r = check_cicd_001({"codebuild-source-credentials": {"items": []}})
        assert r.status == "PASS"

    def test_fail_credentials_exist(self):
        r = check_cicd_001({"codebuild-source-credentials": {"items": [{"arn": "arn:..."}]}})
        assert r.status == "FAIL"


class TestCICD002:
    def test_pass_no_insecure(self):
        r = check_cicd_002({"codebuild-projects": {"items": [
            {"name": "proj", "source": {"insecureSsl": False}}
        ]}})
        assert r.status == "PASS"

    def test_fail_insecure_ssl(self):
        r = check_cicd_002({"codebuild-projects": {"items": [
            {"name": "proj", "arn": "arn:...", "source": {"insecureSsl": True}}
        ]}})
        assert r.status == "FAIL"


# ============================================================================
# COMPUTE CHECKS
# ============================================================================


class TestCompEKS001:
    def test_pass_no_public_endpoint(self):
        r = check_comp_eks_001({"eks-inventory": {"clusters": [
            {"name": "prod", "resourcesVpcConfig": {"endpointPublicAccess": False}}
        ]}})
        assert r.status == "PASS"

    def test_fail_public_endpoint(self):
        r = check_comp_eks_001({"eks-inventory": {"clusters": [
            {"name": "prod", "arn": "arn:...", "resourcesVpcConfig": {"endpointPublicAccess": True}}
        ]}})
        assert r.status == "FAIL"


class TestCompEKS002:
    def test_pass_all_log_types(self):
        r = check_comp_eks_002({"eks-inventory": {"clusters": [
            {"name": "prod", "logging": {"clusterLogging": [
                {"enabled": True, "types": ["api", "audit", "authenticator", "controllerManager", "scheduler"]}
            ]}}
        ]}})
        assert r.status == "PASS"

    def test_fail_missing_log_types(self):
        r = check_comp_eks_002({"eks-inventory": {"clusters": [
            {"name": "prod", "arn": "arn:...", "logging": {"clusterLogging": [
                {"enabled": True, "types": ["api", "audit"]}
            ]}}
        ]}})
        assert r.status == "FAIL"


class TestCompECS002:
    def test_pass_pinned_images(self):
        r = check_comp_ecs_002({"ecs-inventory": {"task_definitions": [
            {"taskDefinitionArn": "arn:...", "containerDefinitions": [
                {"image": "123.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc123"}
            ]}
        ]}})
        assert r.status == "PASS"

    def test_fail_latest_tag(self):
        r = check_comp_ecs_002({"ecs-inventory": {"task_definitions": [
            {"taskDefinitionArn": "arn:...", "containerDefinitions": [
                {"image": "nginx:latest"}
            ]}
        ]}})
        assert r.status == "FAIL"


class TestCompECS003:
    def test_pass_awslogs(self):
        r = check_comp_ecs_003({"ecs-inventory": {"task_definitions": [
            {"containerDefinitions": [{"logConfiguration": {"logDriver": "awslogs"}}]}
        ]}})
        assert r.status == "PASS"

    def test_fail_no_logging(self):
        r = check_comp_ecs_003({"ecs-inventory": {"task_definitions": [
            {"taskDefinitionArn": "arn:...", "containerDefinitions": [{"name": "app"}]}
        ]}})
        assert r.status == "FAIL"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestRunPreChecks:
    def test_iam_full_run(self):
        evidence = {
            "account-summary": {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
            "users": [{"UserName": "alice", "Groups": [{"GroupName": "dev"}], "AccessKeys": []}],
            "policies": [],
            "roles": [],
        }
        checklist = {"items": [
            {"id": "IAM-001", "severity": "Critical"},
            {"id": "IAM-009", "severity": "Critical"},
        ]}
        results = run_pre_checks("iam", evidence, checklist)
        assert len(results) > 0
        ids = {r.check_id for r in results}
        assert "IAM-001" in ids
        assert "IAM-009" in ids
        for r in results:
            if r.check_id in ("IAM-001", "IAM-009"):
                assert r.status == "PASS"

    def test_unknown_skill_returns_empty(self):
        results = run_pre_checks("unknown_skill", {}, {"items": []})
        assert results == []


class TestFormatPreChecksForPrompt:
    def test_empty_returns_empty(self):
        assert format_pre_checks_for_prompt([]) == ""

    def test_basic_format(self):
        checks = [
            PreCheckResult("IAM-001", "PASS", "MFA enabled"),
            PreCheckResult("IAM-009", "FAIL", "Root keys present", ["arn:aws:iam::*:root"]),
        ]
        checklist = {"items": [
            {"id": "IAM-001", "severity": "Critical"},
            {"id": "IAM-009", "severity": "Critical"},
        ]}
        xml = format_pre_checks_for_prompt(checks, checklist)
        assert "<pre_computed_facts>" in xml
        assert 'id="IAM-001"' in xml
        assert 'status="PASS"' in xml
        assert 'id="IAM-009"' in xml
        assert 'status="FAIL"' in xml
        assert "arn:aws:iam::*:root" in xml
        assert "</pre_computed_facts>" in xml
