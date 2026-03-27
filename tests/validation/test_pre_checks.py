"""Tests for deterministic pre-checks (Tier 1 validation).

Verifies that pre-checks produce correct PASS/FAIL/SKIP results
based on known evidence patterns.
"""

import pytest

from drystone.validation.pre_checks import (
    PreCheckResult,
    check_alr_003,
    check_alr_022,
    check_alr_023,
    check_alr_024,
    check_alr_025,
    check_alrt_002,
    check_alrt_003,
    check_alrt_004,
    check_alrt_005,
    check_alrt_006,
    check_alrt_007,
    check_alrt_008,
    check_alrt_009,
    check_alrt_010,
    check_alrt_011,
    check_alrt_012,
    check_alrt_013,
    check_alrt_014,
    check_alrt_015,
    check_alrt_016,
    check_alrt_017,
    check_cicd_001,
    check_cicd_002,
    check_comp_ec2_001,
    check_comp_ec2_002,
    check_comp_ecs_002,
    check_comp_ecs_003,
    check_comp_eks_001,
    check_comp_eks_002,
    check_comp_lmb_001,
    check_comp_lmb_002,
    check_ecr_001,
    check_ecr_002,
    check_ecr_004,
    check_ecr_005,
    check_ecr_006,
    check_exp_002,
    check_exp_003,
    check_exp_020,
    check_exp_021,
    check_exp_022,
    check_hrd_001,
    check_hrd_002,
    check_hrd_003,
    check_hrd_007,
    check_hrd_008,
    check_hrd_010,
    check_hrd_011,
    check_hrd_013,
    check_hrd_014,
    check_hrd_015,
    check_iam_001,
    check_iam_007,
    check_iam_008,
    check_iam_009,
    check_iam_011,
    check_iam_014,
    check_iam_018,
    check_iam_019,
    check_iam_020,
    check_iam_032,
    check_iam_033,
    check_iam_034,
    check_iam_035,
    check_iam_036,
    check_iam_037,
    check_iam_038,
    check_iam_039,
    check_kms_001,
    check_kms_004,
    check_msg_001,
    check_msg_002,
    check_msg_005,
    check_msg_006,
    check_msg_007,
    check_msg_008,
    check_net_001,
    check_net_002,
    check_net_003,
    check_net_004,
    check_net_005,
    check_net_006,
    check_net_007,
    check_net_008,
    check_net_009,
    check_net_010,
    check_net_012,
    check_net_014,
    check_net_015,
    check_net_016,
    check_net_017,
    check_net_018,
    check_net_019,
    check_net_021,
    check_net_025,
    check_net_027,
    check_net_029,
    check_sm_001,
    check_sm_003,
    check_sm_013,
    check_sm_014,
    check_sm_015,
    check_sm_017,
    check_vuln_005,
    check_vuln_022,
    check_vuln_023,
    check_vuln_024,
    check_vuln_025,
    check_vuln_028,
    check_waf_013,
    format_pre_checks_for_prompt,
    run_pre_checks,
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
            "credential-report": {"by_user": {"<root_account>": {"mfa_active": "true"}}},
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
                "by_user": {
                    "<root_account>": {
                        "access_key_1_active": "false",
                        "access_key_2_active": "false",
                    }
                }
            },
        }
        r = check_iam_009(evidence)
        assert r.status == "PASS"


class TestIAM008:
    def test_pass_when_no_admin_policies(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "ReadOnly",
                    "PolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
                        ]
                    },
                }
            ]
        }
        r = check_iam_008(evidence)
        assert r.status == "PASS"

    def test_fail_when_wildcard_admin(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "Admin",
                    "Arn": "arn:aws:iam::123:policy/Admin",
                    "PolicyDocument": {
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    },
                }
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
                {
                    "RoleName": "Lambda",
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}
                        ]
                    },
                }
            ]
        }
        r = check_iam_011(evidence)
        assert r.status == "PASS"

    def test_fail_when_wildcard_principal(self):
        evidence = {
            "roles": [
                {
                    "RoleName": "OpenRole",
                    "Arn": "arn:aws:iam::123:role/OpenRole",
                    "AssumeRolePolicyDocument": {
                        "Statement": [{"Effect": "Allow", "Principal": "*"}]
                    },
                }
            ]
        }
        r = check_iam_011(evidence)
        assert r.status == "FAIL"


class TestIAM014:
    def test_pass_when_single_key(self):
        evidence = {
            "users": [
                {
                    "UserName": "alice",
                    "AccessKeys": [
                        {"AccessKeyId": "AKIA1", "Status": "Active"},
                    ],
                }
            ]
        }
        r = check_iam_014(evidence)
        assert r.status == "PASS"

    def test_fail_when_two_active_keys(self):
        evidence = {
            "users": [
                {
                    "UserName": "bob",
                    "AccessKeys": [
                        {"AccessKeyId": "AKIA1", "Status": "Active"},
                        {"AccessKeyId": "AKIA2", "Status": "Active"},
                    ],
                }
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


class TestIAM032:
    def test_fail_github_oidc_missing_sub(self):
        evidence = {
            "roles": [
                {
                    "Arn": "arn:aws:iam::111111111111:role/gh-role",
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Principal": {
                                    "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
                                },
                                "Condition": {
                                    "StringEquals": {
                                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                                    }
                                },
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_032(evidence)
        assert r.status == "FAIL"

    def test_pass_github_oidc_strict_conditions(self):
        evidence = {
            "roles": [
                {
                    "Arn": "arn:aws:iam::111111111111:role/gh-role",
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Principal": {
                                    "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
                                },
                                "Condition": {
                                    "StringEquals": {
                                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                        "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main",
                                    }
                                },
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_032(evidence)
        assert r.status == "PASS"


class TestIAM033:
    def test_fail_cross_account_without_external_id(self):
        evidence = {
            "roles": [
                {
                    "Arn": "arn:aws:iam::111111111111:role/third-party-role",
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Principal": {"AWS": "arn:aws:iam::222222222222:role/vendor-role"},
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_033(evidence)
        assert r.status == "FAIL"

    def test_pass_cross_account_with_external_id(self):
        evidence = {
            "roles": [
                {
                    "Arn": "arn:aws:iam::111111111111:role/third-party-role",
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRole",
                                "Principal": {"AWS": "arn:aws:iam::222222222222:role/vendor-role"},
                                "Condition": {"StringEquals": {"sts:ExternalId": "vendor-secret"}},
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_033(evidence)
        assert r.status == "PASS"


class TestIAM034:
    def test_fail_broad_idp_mutation_permission(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "DangerousIdPAdmin",
                    "Arn": "arn:aws:iam::111111111111:policy/DangerousIdPAdmin",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "iam:UpdateSAMLProvider",
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_034(evidence)
        assert r.status == "FAIL"


class TestIAM035:
    def test_fail_policy_version_escalation_permission(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "PolicyVersionEscalation",
                    "Arn": "arn:aws:iam::111111111111:policy/PolicyVersionEscalation",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "iam:CreatePolicyVersion",
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_035(evidence)
        assert r.status == "FAIL"

    def test_pass_without_policy_version_actions(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "ReadOnly",
                    "Arn": "arn:aws:iam::111111111111:policy/ReadOnly",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "iam:ListUsers",
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_035(evidence)
        assert r.status == "PASS"


class TestIAM036:
    def test_fail_service_specific_credential_takeover(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "SvcCredTakeover",
                    "Arn": "arn:aws:iam::111111111111:policy/SvcCredTakeover",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "iam:CreateServiceSpecificCredential",
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_036(evidence)
        assert r.status == "FAIL"


class TestIAM037:
    def test_fail_broad_mfa_manipulation(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "MFAAdminBroad",
                    "Arn": "arn:aws:iam::111111111111:policy/MFAAdminBroad",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["iam:EnableMFADevice", "iam:DeactivateMFADevice"],
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_037(evidence)
        assert r.status == "FAIL"


class TestIAM038:
    def test_fail_iam_delete_wildcard(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "DeleteEverything",
                    "Arn": "arn:aws:iam::111111111111:policy/DeleteEverything",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "iam:Delete*",
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_038(evidence)
        assert r.status == "FAIL"


class TestIAM039:
    def test_fail_broad_policy_detach_delete(self):
        evidence = {
            "policies": [
                {
                    "PolicyName": "DetachDeleteBroad",
                    "Arn": "arn:aws:iam::111111111111:policy/DetachDeleteBroad",
                    "PolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["iam:DetachRolePolicy", "iam:DeletePolicyVersion"],
                                "Resource": "*",
                            }
                        ]
                    },
                }
            ]
        }
        r = check_iam_039(evidence)
        assert r.status == "FAIL"


class TestIAM007:
    """Tests for IAM-007: No inline policies on roles."""

    def test_fail_when_role_has_inline_policy(self):
        r = check_iam_007(
            {
                "roles": [
                    {
                        "RoleName": "SomeRole",
                        "Arn": "arn:aws:iam::111111111111:role/SomeRole",
                        "InlinePolicies": ["SomeInlinePolicy"],
                    }
                ]
            }
        )
        assert r.status == "FAIL"
        assert "1 role(s)" in r.evidence_summary

    def test_pass_when_no_inline_policies(self):
        r = check_iam_007(
            {
                "roles": [
                    {
                        "RoleName": "CleanRole",
                        "Arn": "arn:aws:iam::111111111111:role/CleanRole",
                        "InlinePolicies": [],
                    }
                ]
            }
        )
        assert r.status == "PASS"

    def test_skip_when_no_roles(self):
        r = check_iam_007({})
        assert r.status == "SKIP"


class TestIAM018:
    """Tests for IAM-018: Password policy must enforce max password age."""

    def _policy(self, **overrides) -> dict:
        base = {
            "ExpirePasswords": True,
            "MaxPasswordAge": 90,
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
        }
        base.update(overrides)
        return {"PasswordPolicy": base}

    def test_pass_when_max_age_90(self):
        r = check_iam_018({"password-policy": self._policy(MaxPasswordAge=90)})
        assert r.status == "PASS"

    def test_pass_when_max_age_60(self):
        r = check_iam_018({"password-policy": self._policy(MaxPasswordAge=60)})
        assert r.status == "PASS"

    def test_fail_when_expire_passwords_false(self):
        r = check_iam_018({"password-policy": self._policy(ExpirePasswords=False)})
        assert r.status == "FAIL"
        assert "ExpirePasswords=false" in r.evidence_summary

    def test_fail_when_max_age_exceeds_90(self):
        r = check_iam_018({"password-policy": self._policy(MaxPasswordAge=180)})
        assert r.status == "FAIL"

    def test_skip_when_no_evidence(self):
        r = check_iam_018({})
        assert r.status == "SKIP"


class TestIAM019:
    """Tests for IAM-019: Password policy must require symbol characters."""

    def _policy(self, **overrides) -> dict:
        base = {"RequireSymbols": True, "MinimumPasswordLength": 14}
        base.update(overrides)
        return {"PasswordPolicy": base}

    def test_pass_when_require_symbols_true(self):
        r = check_iam_019({"password-policy": self._policy(RequireSymbols=True)})
        assert r.status == "PASS"

    def test_fail_when_require_symbols_false(self):
        r = check_iam_019({"password-policy": self._policy(RequireSymbols=False)})
        assert r.status == "FAIL"

    def test_skip_when_no_evidence(self):
        r = check_iam_019({})
        assert r.status == "SKIP"


class TestVULN022:
    def test_fail_when_imdsv1_enabled(self):
        r = check_vuln_022(
            {
                "imds-configuration": {
                    "items": [
                        {
                            "InstanceId": "i-123",
                            "HttpTokens": "optional",
                            "VulnerableToSSRF": True,
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestVULN023:
    def test_fail_when_userdata_contains_secret_patterns(self):
        r = check_vuln_023(
            {
                "ec2-user-data": {
                    "items": [
                        {
                            "InstanceId": "i-abc",
                            "ContainsSecrets": {
                                "aws_access_key": True,
                                "password": False,
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestVULN024:
    def test_fail_when_lambda_has_sensitive_env_keys(self):
        r = check_vuln_024(
            {
                "lambda-environment-variables": {
                    "items": [
                        {
                            "FunctionName": "fn-a",
                            "FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:fn-a",
                            "PotentialSecretKeys": ["DB_PASSWORD"],
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestVULN025:
    def test_fail_when_instance_profile_role_has_admin_policy(self):
        r = check_vuln_025(
            {
                "instance-profiles-permissions": {
                    "items": [
                        {
                            "InstanceProfileName": "profile-a",
                            "Roles": [
                                {
                                    "RoleName": "role-a",
                                    "RoleArn": "arn:aws:iam::111111111111:role/role-a",
                                    "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
                                }
                            ],
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestVULN028:
    def test_fail_when_public_ebs_snapshot_exists(self):
        r = check_vuln_028(
            {
                "ebs-snapshot-sharing": {
                    "items": [
                        {
                            "SnapshotId": "snap-123",
                            "IsPublic": True,
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestVULN005:
    """Regression tests for VULN-005 high-criticality resource detection.

    Key invariant: substring keyword matching must NOT produce false positives.
    E.g. 'cards' contains 'rds' but is NOT an RDS database resource.
    """

    def _ecr_finding(self, repo_name: str, sha: str) -> dict:
        return {
            "findingArn": f"arn:aws:inspector2:us-east-1:111111111111:finding/abc{sha[:8]}",
            "status": "ACTIVE",
            "severity": "HIGH",
            "resources": [
                {
                    "id": f"arn:aws:ecr:us-east-1:111111111111:repository/{repo_name}/sha256:{sha}",
                    "type": "AWS_ECR_CONTAINER_IMAGE",
                    "tags": {},
                }
            ],
        }

    def _rds_finding(self, db_id: str) -> dict:
        return {
            "findingArn": f"arn:aws:inspector2:us-east-1:111111111111:finding/rds{db_id[:8]}",
            "status": "ACTIVE",
            "severity": "HIGH",
            "resources": [
                {
                    "id": f"arn:aws:rds:us-east-1:111111111111:db:{db_id}",
                    "type": "AWS_RDS_DB_INSTANCE",
                    "tags": {},
                }
            ],
        }

    def test_ecr_cards_repo_is_not_rds_false_positive(self):
        """ECR repository named 'cards' must NOT trigger VULN-005 due to 'rds' substring."""
        evidence = {
            "inspector-findings": [
                self._ecr_finding("cards", "a" * 64),
                self._ecr_finding("cards", "b" * 64),
                self._ecr_finding("cards", "c" * 64),
            ]
        }
        r = check_vuln_005(evidence)
        # 'cards' contains 'rds' as substring but is an ECR image, not an RDS database
        assert r.status in (
            "PASS",
            "SKIP",
        ), f"VULN-005 triggered on ECR 'cards' repository (false positive): {r.evidence_summary}"

    def test_actual_rds_resource_is_detected(self):
        """An actual RDS database with ACTIVE findings must trigger VULN-005."""
        evidence = {
            "inspector-findings": [
                self._rds_finding("prod-mysql-db"),
            ]
        }
        r = check_vuln_005(evidence)
        assert r.status == "FAIL", f"VULN-005 missed actual RDS finding: {r.evidence_summary}"

    def test_pass_when_no_high_criticality_resources(self):
        """Only non-critical ECR images → PASS."""
        evidence = {
            "inspector-findings": [
                self._ecr_finding("myapp", "d" * 64),
            ]
        }
        r = check_vuln_005(evidence)
        assert r.status in ("PASS", "SKIP")

    def test_skip_when_no_inspector_findings(self):
        """Missing evidence → SKIP."""
        r = check_vuln_005({})
        assert r.status == "SKIP"

    def test_ec2_non_critical_is_not_flagged(self):
        """A plain EC2 instance without RDS/DB/VPN keywords → not flagged."""
        evidence = {
            "inspector-findings": [
                {
                    "findingArn": "arn:aws:inspector2:us-east-1:111111111111:finding/ec2abc",
                    "status": "ACTIVE",
                    "severity": "HIGH",
                    "resources": [
                        {
                            "id": "i-0b8773f8bf56a7939",
                            "type": "AWS_EC2_INSTANCE",
                            "tags": {},
                        }
                    ],
                }
            ]
        }
        r = check_vuln_005(evidence)
        assert r.status in (
            "PASS",
            "SKIP",
        ), f"Generic EC2 instance should not be high-criticality: {r.evidence_summary}"


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
        r = check_hrd_002(
            {"security-hub-status": {"HubArn": "arn:aws:securityhub:us-east-1:123:hub/default"}}
        )
        assert r.status == "PASS"

    def test_fail_when_no_hub(self):
        r = check_hrd_002({"security-hub-status": {}})
        assert r.status == "FAIL"


class TestHRD003:
    def test_skip_when_hub_disabled(self):
        r = check_hrd_003({"security-hub-status": {}})
        assert r.status == "SKIP"

    def test_pass_when_standards_enabled(self):
        r = check_hrd_003(
            {
                "security-hub-status": {"HubArn": "arn:aws:securityhub:..."},
                "security-hub-enabled-standards": [{"Status": "READY"}],
            }
        )
        assert r.status == "PASS"

    def test_fail_when_no_standards(self):
        r = check_hrd_003(
            {
                "security-hub-status": {"HubArn": "arn:aws:securityhub:..."},
                "security-hub-enabled-standards": [],
            }
        )
        assert r.status == "FAIL"


class TestHRD007:
    def test_skip_when_hub_not_enabled(self):
        r = check_hrd_007({"security-hub-status": {}})
        assert r.status == "SKIP"

    def test_pass_when_pci_dss_standard_enabled(self):
        r = check_hrd_007(
            {
                "security-hub-status": {"HubArn": "arn:aws:securityhub:us-east-1:123:hub/default"},
                "security-hub-enabled-standards": [
                    {
                        "StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1",
                        "Status": "READY",
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_fail_when_no_pci_dss_standard(self):
        r = check_hrd_007(
            {
                "security-hub-status": {"HubArn": "arn:aws:securityhub:us-east-1:123:hub/default"},
                "security-hub-enabled-standards": [
                    {
                        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0",
                        "Status": "READY",
                    }
                ],
            }
        )
        assert r.status == "FAIL"

    def test_pass_uses_subscription_arn_fallback(self):
        r = check_hrd_007(
            {
                "security-hub-status": {"HubArn": "arn:aws:securityhub:us-east-1:123:hub/default"},
                "security-hub-enabled-standards": [
                    {
                        "StandardsArn": None,
                        "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:123:subscription/pci-dss/v/3.2.1",
                        "Status": "READY",
                    }
                ],
            }
        )
        assert r.status == "PASS"


class TestHRD008:
    _summary_50pct = {
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
        "compliance_status_counts": {"PASSED": 60, "FAILED": 40, "WARNING": 0},
    }
    _summary_30pct = {
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
        "compliance_status_counts": {"PASSED": 30, "FAILED": 70, "WARNING": 0},
    }
    _summary_65pct = {
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
        "compliance_status_counts": {"PASSED": 65, "FAILED": 35, "WARNING": 0},
    }

    def test_fail_when_score_in_50_70_band(self):
        r = check_hrd_008({"security-hub-findings-summary": self._summary_65pct})
        assert r.status == "FAIL"
        assert "65.0%" in r.evidence_summary

    def test_pass_when_score_below_50(self):
        r = check_hrd_008({"security-hub-findings-summary": self._summary_30pct})
        assert r.status == "PASS"

    def test_pass_when_score_at_or_above_70(self):
        # 60 PASS / 40 FAIL = exactly 60%... wait that's in 50-70 band
        # Use 80%
        summary_80 = {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 80, "FAILED": 20, "WARNING": 0},
        }
        r = check_hrd_008({"security-hub-findings-summary": summary_80})
        assert r.status == "PASS"

    def test_skip_when_no_compliance_data(self):
        r = check_hrd_008({})
        assert r.status == "SKIP"


class TestHRD010:
    def test_fail_when_no_conformance_packs(self):
        r = check_hrd_010({"config-conformance-packs": []})
        assert r.status == "FAIL"
        assert "0 conformance packs" in r.evidence_summary

    def test_pass_when_packs_configured(self):
        r = check_hrd_010(
            {"config-conformance-packs": [{"ConformancePackName": "OperationalBestPractices-IAM"}]}
        )
        assert r.status == "PASS"
        assert "1 conformance pack" in r.evidence_summary

    def test_skip_when_evidence_missing(self):
        r = check_hrd_010({})
        assert r.status == "SKIP"


class TestHRD011:
    def test_fail_when_score_in_70_85_band(self):
        summary = {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 75, "FAILED": 25, "WARNING": 0},
        }
        r = check_hrd_011({"security-hub-findings-summary": summary})
        assert r.status == "FAIL"
        assert "75.0%" in r.evidence_summary

    def test_pass_when_score_below_70(self):
        summary = {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 0, "FAILED": 100, "WARNING": 0},
        }
        r = check_hrd_011({"security-hub-findings-summary": summary})
        assert r.status == "PASS"

    def test_pass_when_score_at_or_above_85(self):
        summary = {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 90, "FAILED": 10, "WARNING": 0},
        }
        r = check_hrd_011({"security-hub-findings-summary": summary})
        assert r.status == "PASS"


class TestHRD013:
    """HRD-013: Outdated Security Hub standards should be detected."""

    def test_fail_when_cis_v120_present(self):
        """Regression test: CIS v1.2.0 in StandardsArn must trigger FAIL."""
        r = check_hrd_013(
            {
                "security-hub-enabled-standards": [
                    {
                        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                        "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:032014372957:subscription/cis-aws-foundations-benchmark/v/1.2.0",
                        "Status": "READY",
                        "ControlsSummary": {"total": 42, "enabled": 42, "disabled": 0},
                    }
                ]
            }
        )
        assert r.status == "FAIL", f"Expected FAIL but got {r.status}: {r.evidence_summary}"

    def test_fail_when_cis_v130_present(self):
        r = check_hrd_013(
            {
                "security-hub-enabled-standards": [
                    {
                        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.3.0",
                        "Status": "READY",
                    }
                ]
            }
        )
        assert r.status == "FAIL"

    def test_pass_when_only_current_standards(self):
        r = check_hrd_013(
            {
                "security-hub-enabled-standards": [
                    {
                        "StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0",
                        "Status": "READY",
                    },
                    {
                        "StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1",
                        "Status": "READY",
                    },
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_v120_and_v140_both_present(self):
        """Having v1.4.0 does not excuse keeping v1.2.0 enabled."""
        r = check_hrd_013(
            {
                "security-hub-enabled-standards": [
                    {
                        "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                        "Status": "READY",
                    },
                    {
                        "StandardsArn": "arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0",
                        "Status": "READY",
                    },
                ]
            }
        )
        assert r.status == "FAIL"

    def test_skip_when_no_standards_evidence(self):
        r = check_hrd_013({})
        assert r.status == "SKIP"


class TestHRD015:
    def test_fail_when_score_in_85_95_band(self):
        summary = {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 90, "FAILED": 10, "WARNING": 0},
        }
        r = check_hrd_015({"security-hub-findings-summary": summary})
        assert r.status == "FAIL"
        assert "90.0%" in r.evidence_summary

    def test_pass_when_score_below_85(self):
        summary = {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 0, "FAILED": 100, "WARNING": 0},
        }
        r = check_hrd_015({"security-hub-findings-summary": summary})
        assert r.status == "PASS"

    def test_pass_when_score_at_or_above_95(self):
        summary = {
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0},
            "compliance_status_counts": {"PASSED": 97, "FAILED": 3, "WARNING": 0},
        }
        r = check_hrd_015({"security-hub-findings-summary": summary})
        assert r.status == "PASS"

    def test_skip_when_no_compliance_data(self):
        r = check_hrd_015({})
        assert r.status == "SKIP"


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


class TestALR003:
    def test_skip_when_no_trails(self):
        r = check_alr_003({"cloudtrail-trails": []})
        assert r.status == "SKIP"

    def test_pass_when_log_group_present(self):
        r = check_alr_003(
            {
                "cloudtrail-trails": [
                    {"Name": "main", "CloudWatchLogsLogGroupArn": "arn:aws:logs:..."}
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_no_log_group(self):
        r = check_alr_003({"cloudtrail-trails": [{"Name": "main"}]})
        assert r.status == "FAIL"


class TestALR022:
    def test_fail_when_alert_topic_allows_wildcard_publish(self):
        r = check_alr_022(
            {
                "cloudwatch-alarms": [
                    {"AlarmActions": ["arn:aws:sns:us-east-1:111111111111:alerts"]}
                ],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111111111111:alerts",
                        "Attributes": {
                            "Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish"}]}'
                        },
                    }
                ],
            }
        )
        assert r.status == "FAIL"


class TestALR023:
    def test_fail_when_alert_topic_allows_wildcard_subscribe(self):
        r = check_alr_023(
            {
                "cloudwatch-alarms": [
                    {"AlarmActions": ["arn:aws:sns:us-east-1:111111111111:alerts"]}
                ],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111111111111:alerts",
                        "Attributes": {
                            "Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Subscribe"}]}'
                        },
                    }
                ],
            }
        )
        assert r.status == "FAIL"


class TestALR024:
    def test_fail_when_alert_topic_has_http_subscription(self):
        r = check_alr_024(
            {
                "eventbridge-rules": [
                    {
                        "Targets": [{"Arn": "arn:aws:sns:us-east-1:111111111111:alerts"}],
                    }
                ],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111111111111:alerts",
                        "Subscriptions": [{"Protocol": "https"}],
                    }
                ],
            }
        )
        assert r.status == "FAIL"


class TestALR025:
    def test_fail_when_security_eventbridge_rule_has_no_sns_target(self):
        r = check_alr_025(
            {
                "eventbridge-rules": [
                    {
                        "Name": "ct-stoplogging",
                        "EventPattern": '{"source":["aws.cloudtrail"],"detail":{"eventName":["StopLogging"]}}',
                        "Targets": [
                            {"Arn": "arn:aws:lambda:us-east-1:111111111111:function:handler"}
                        ],
                    }
                ]
            }
        )
        assert r.status == "FAIL"


class TestALRT002:
    def test_pass_when_cloudtrail_eventbridge_rule_exists(self):
        r = check_alrt_002(
            {
                "eventbridge-rules": [
                    {
                        "Name": "ct-security-alerts",
                        "EventPattern": '{"source":["aws.cloudtrail"]}',
                        "State": "ENABLED",
                        "Targets": [{"Arn": "arn:aws:sns:us-east-1:111:alerts"}],
                    }
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_no_cloudtrail_rules(self):
        r = check_alrt_002(
            {
                "eventbridge-rules": [
                    {
                        "Name": "some-other-rule",
                        "EventPattern": '{"source":["aws.ec2"]}',
                        "State": "ENABLED",
                        "Targets": [],
                    }
                ]
            }
        )
        assert r.status == "FAIL"

    def test_fail_when_cloudtrail_rule_disabled(self):
        r = check_alrt_002(
            {
                "eventbridge-rules": [
                    {
                        "Name": "ct-disabled",
                        "EventPattern": '{"source":["aws.cloudtrail"]}',
                        "State": "DISABLED",
                        "Targets": [],
                    }
                ]
            }
        )
        assert r.status == "FAIL"

    def test_skip_when_no_evidence(self):
        r = check_alrt_002({})
        assert r.status == "SKIP"

    def test_skips_aws_managed_rules(self):
        r = check_alrt_002(
            {
                "eventbridge-rules": [
                    {
                        "Name": "DO-NOT-DELETE-AmazonInspectorManagedRule",
                        "EventPattern": '{"source":["aws.cloudtrail"]}',
                        "State": "ENABLED",
                        "Targets": [],
                    }
                ]
            }
        )
        # Managed rule skipped → no matching rules → FAIL
        assert r.status == "FAIL"


class TestALRT003:
    def test_pass_when_all_filters_have_alarms(self):
        r = check_alrt_003(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "RootUsage",
                        "filterPattern": '{ $.userIdentity.type = "Root" }',
                        "logGroupName": "CloudtrailLogGroup",
                        "metricTransformations": [{"metricName": "RootAccountUsage"}],
                    }
                ],
                "cloudwatch-alarms": [
                    {"MetricName": "RootAccountUsage", "AlarmName": "root-alarm"}
                ],
            }
        )
        assert r.status == "PASS"

    def test_fail_when_filter_has_no_alarm(self):
        r = check_alrt_003(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "RootUsage",
                        "metricTransformations": [{"metricName": "RootAccountUsage"}],
                    }
                ],
                "cloudwatch-alarms": [],
            }
        )
        assert r.status == "FAIL"

    def test_skip_when_no_metric_filters(self):
        r = check_alrt_003({"cloudwatch-alarms": []})
        assert r.status == "SKIP"

    def test_fail_when_empty_metric_filters_list(self):
        # Empty list = evidence collected but zero filters = no alarm coverage possible
        r = check_alrt_003({"cloudwatch-metric-filters": [], "cloudwatch-alarms": []})
        assert r.status == "FAIL"
        assert "zero filters" in r.evidence_summary


class TestALRT004:
    def test_skip_when_no_security_rules(self):
        r = check_alrt_004(
            {
                "eventbridge-rules": [
                    {
                        "Name": "aws-health-rule",
                        "EventPattern": '{"source":["aws.health"]}',
                        "State": "ENABLED",
                        "Targets": [],
                    }
                ]
            }
        )
        assert r.status == "SKIP"

    def test_fail_when_ct_rule_has_no_sns(self):
        r = check_alrt_004(
            {
                "eventbridge-rules": [
                    {
                        "Name": "ct-security",
                        "EventPattern": '{"source":["aws.cloudtrail"]}',
                        "State": "ENABLED",
                        "Targets": [{"Arn": "arn:aws:lambda:us-east-1:111:function:handler"}],
                    }
                ]
            }
        )
        assert r.status == "FAIL"

    def test_pass_when_ct_rule_has_sns(self):
        r = check_alrt_004(
            {
                "eventbridge-rules": [
                    {
                        "Name": "ct-security",
                        "EventPattern": '{"source":["aws.cloudtrail"]}',
                        "State": "ENABLED",
                        "Targets": [{"Arn": "arn:aws:sns:us-east-1:111:security-alerts"}],
                    }
                ]
            }
        )
        assert r.status == "PASS"


class TestALRT007:
    def test_pass_when_all_critical_events_covered(self):
        r = check_alrt_007(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterPattern": '{ $.eventName = "ConsoleLogin" }',
                        "metricTransformations": [],
                    },
                    {
                        "filterPattern": '{ $.eventName = "StopLogging" }',
                        "metricTransformations": [],
                    },
                    {
                        "filterPattern": '{ $.eventName = "DeleteTrail" }',
                        "metricTransformations": [],
                    },
                    {
                        "filterPattern": '{ $.eventName = "CreateUser" }',
                        "metricTransformations": [],
                    },
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_events_missing(self):
        r = check_alrt_007(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterPattern": '{ $.eventName = "ConsoleLogin" }',
                        "metricTransformations": [],
                    },
                ]
            }
        )
        assert r.status == "FAIL"
        assert "StopLogging" in r.evidence_summary

    def test_skip_when_no_filters(self):
        r = check_alrt_007({})
        assert r.status == "SKIP"


class TestALRT009:
    def test_pass_when_ct_log_group_has_filters(self):
        r = check_alrt_009(
            {
                "cloudtrail-trails": [
                    {
                        "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:111:log-group:CloudtrailLG:*"
                    }
                ],
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "RootUsage",
                        "logGroupName": "CloudtrailLG",
                        "metricTransformations": [],
                    },
                ],
            }
        )
        assert r.status == "PASS"

    def test_fail_when_ct_log_group_has_no_filters(self):
        r = check_alrt_009(
            {
                "cloudtrail-trails": [
                    {
                        "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:111:log-group:CloudtrailLG:*"
                    }
                ],
                "cloudwatch-metric-filters": [],
            }
        )
        assert r.status == "FAIL"

    def test_skip_when_no_trail_cw_integration(self):
        r = check_alrt_009(
            {
                "cloudtrail-trails": [{"Name": "main"}],
                "cloudwatch-metric-filters": [],
            }
        )
        assert r.status == "SKIP"


class TestALRT017:
    def test_pass_when_all_groups_adequate(self):
        r = check_alrt_017(
            {
                "cloudwatch-log-groups": [
                    {"LogGroupName": "/app/logs", "RetentionInDays": 365},
                    {"LogGroupName": "/app/audit", "RetentionInDays": None},  # never expire
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_group_below_90_days(self):
        r = check_alrt_017(
            {
                "cloudwatch-log-groups": [
                    {"LogGroupName": "/aws/lambda/waf_lambda", "RetentionInDays": 7},
                ]
            }
        )
        assert r.status == "FAIL"
        assert "/aws/lambda/waf_lambda" in r.affected_resources

    def test_skip_when_no_evidence(self):
        r = check_alrt_017({})
        assert r.status == "SKIP"


class TestALRT005:
    def test_pass_when_alert_topic_has_confirmed_subscriptions(self):
        r = check_alrt_005(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:sec-alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:sec-alerts",
                        "Attributes": {"SubscriptionsConfirmed": "2"},
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_fail_when_alert_topic_has_no_confirmed_subscriptions(self):
        r = check_alrt_005(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:sec-alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:sec-alerts",
                        "Attributes": {"SubscriptionsConfirmed": "0"},
                    }
                ],
            }
        )
        assert r.status == "FAIL"
        assert "arn:aws:sns:us-east-1:111:sec-alerts" in r.affected_resources

    def test_skip_when_no_sns_evidence(self):
        r = check_alrt_005({})
        assert r.status == "SKIP"


class TestALRT006:
    def test_pass_when_no_pending_subscriptions(self):
        r = check_alrt_006(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:sec-alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:sec-alerts",
                        "Attributes": {"SubscriptionsPending": "0", "SubscriptionsConfirmed": "1"},
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_fail_when_pending_subscriptions_exist(self):
        r = check_alrt_006(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:sec-alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:sec-alerts",
                        "Attributes": {"SubscriptionsPending": "2"},
                    }
                ],
            }
        )
        assert r.status == "FAIL"

    def test_skip_when_no_sns_evidence(self):
        r = check_alrt_006({})
        assert r.status == "SKIP"


class TestALRT008:
    def test_pass_when_multi_region_trail_exists(self):
        r = check_alrt_008({"cloudtrail-trails": [{"Name": "main", "IsMultiRegionTrail": True}]})
        assert r.status == "PASS"

    def test_fail_when_all_trails_single_region(self):
        r = check_alrt_008(
            {
                "cloudtrail-trails": [
                    {"Name": "main", "IsMultiRegionTrail": False},
                    {"Name": "backup", "IsMultiRegionTrail": False},
                ]
            }
        )
        assert r.status == "FAIL"
        assert "main" in r.affected_resources

    def test_skip_when_no_evidence(self):
        r = check_alrt_008({})
        assert r.status == "SKIP"

    def test_skip_when_empty_trails(self):
        r = check_alrt_008({"cloudtrail-trails": []})
        assert r.status == "SKIP"


class TestALRT010:
    def test_pass_when_no_alarms_insufficient_data(self):
        r = check_alrt_010(
            {
                "cloudwatch-alarms": [
                    {"AlarmName": "alarm1", "StateValue": "OK"},
                    {"AlarmName": "alarm2", "StateValue": "ALARM"},
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_alarm_in_insufficient_data(self):
        r = check_alrt_010(
            {
                "cloudwatch-alarms": [
                    {"AlarmName": "security-alarm", "StateValue": "INSUFFICIENT_DATA"},
                    {"AlarmName": "ok-alarm", "StateValue": "OK"},
                ]
            }
        )
        assert r.status == "FAIL"
        assert "security-alarm" in r.affected_resources

    def test_skip_when_no_alarms(self):
        r = check_alrt_010({})
        assert r.status == "SKIP"

    def test_skip_when_state_value_not_collected(self):
        # StateValue is None/absent — skip since collector didn't collect it
        r = check_alrt_010(
            {
                "cloudwatch-alarms": [
                    {"AlarmName": "alarm1"},
                ]
            }
        )
        assert r.status == "SKIP"


class TestALRT011:
    def test_pass_when_alert_topic_restricts_publish_to_cloudwatch(self):
        r = check_alrt_011(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:sec-alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:sec-alerts",
                        "Attributes": {
                            "Policy": '{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudwatch.amazonaws.com"},"Action":"sns:Publish"}]}'
                        },
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_pass_when_alert_topic_has_same_account_condition(self):
        # AWS default policy: Principal:* + SourceOwner condition is acceptable
        r = check_alrt_011(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:sec-alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:sec-alerts",
                        "Attributes": {
                            "Policy": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sns:Publish","Condition":{"StringEquals":{"AWS:SourceOwner":"111"}}}]}'
                        },
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_fail_when_alert_topic_allows_wildcard_publish_no_condition(self):
        r = check_alrt_011(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:sec-alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:sec-alerts",
                        "Attributes": {
                            "Policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sns:Publish"}]}'
                        },
                    }
                ],
            }
        )
        assert r.status == "FAIL"

    def test_skip_when_no_alert_topics(self):
        # No alarms reference SNS ARNs -> no critical topics -> SKIP
        r = check_alrt_011(
            {
                "cloudwatch-alarms": [],
                "sns-topics": [
                    {"TopicArn": "arn:aws:sns:us-east-1:111:some-topic", "Attributes": {}}
                ],
            }
        )
        assert r.status == "SKIP"


class TestALRT013:
    def test_pass_when_all_trails_have_validation(self):
        r = check_alrt_013(
            {
                "cloudtrail-trails": [
                    {
                        "Name": "main",
                        "IsOrganizationTrail": False,
                        "LogFileValidationEnabled": True,
                        "Status": {"IsLogging": True},
                    }
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_trail_missing_validation(self):
        r = check_alrt_013(
            {
                "cloudtrail-trails": [
                    {
                        "Name": "main",
                        "IsOrganizationTrail": False,
                        "LogFileValidationEnabled": False,
                        "Status": {"IsLogging": True},
                    }
                ]
            }
        )
        assert r.status == "FAIL"
        assert "main" in r.affected_resources

    def test_skip_org_trail_with_no_status(self):
        # Organization trail with no Status -> not locally owned, skip
        r = check_alrt_013(
            {
                "cloudtrail-trails": [
                    {
                        "Name": "org-trail",
                        "IsOrganizationTrail": True,
                        "LogFileValidationEnabled": False,
                        "Status": {},
                    }
                ]
            }
        )
        assert r.status == "SKIP"

    def test_skip_when_no_evidence(self):
        r = check_alrt_013({})
        assert r.status == "SKIP"


class TestALRT014:
    def test_pass_when_all_trails_encrypted(self):
        r = check_alrt_014(
            {
                "cloudtrail-trails": [
                    {
                        "Name": "main",
                        "IsOrganizationTrail": False,
                        "KMSKeyId": "arn:aws:kms:us-east-1:111:key/abc",
                        "Status": {"IsLogging": True},
                    }
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_trail_not_encrypted(self):
        r = check_alrt_014(
            {
                "cloudtrail-trails": [
                    {
                        "Name": "main",
                        "IsOrganizationTrail": False,
                        "KMSKeyId": None,
                        "Status": {"IsLogging": True},
                    }
                ]
            }
        )
        assert r.status == "FAIL"
        assert "main" in r.affected_resources

    def test_skip_org_trail_with_no_status(self):
        r = check_alrt_014(
            {
                "cloudtrail-trails": [
                    {
                        "Name": "org-trail",
                        "IsOrganizationTrail": True,
                        "KMSKeyId": None,
                        "Status": {},
                    }
                ]
            }
        )
        assert r.status == "SKIP"

    def test_skip_when_no_evidence(self):
        r = check_alrt_014({})
        assert r.status == "SKIP"


class TestALRT015:
    def test_pass_when_iam_change_filter_exists(self):
        r = check_alrt_015(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "IAMChanges",
                        "filterPattern": "{ ($.eventName = PutUserPolicy) || ($.eventName = AttachUserPolicy) }",
                        "metricTransformations": [{"metricName": "IAMChanges"}],
                    }
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_no_iam_change_filters(self):
        r = check_alrt_015(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "ConsoleLogin",
                        "filterPattern": '{ $.eventName = "ConsoleLogin" }',
                        "metricTransformations": [],
                    }
                ]
            }
        )
        assert r.status == "FAIL"

    def test_fail_when_no_metric_filters_at_all(self):
        r = check_alrt_015({"cloudwatch-metric-filters": []})
        assert r.status == "FAIL"

    def test_skip_when_no_evidence(self):
        r = check_alrt_015({})
        assert r.status == "SKIP"


class TestALRT016:
    def test_pass_when_sg_change_filter_exists(self):
        r = check_alrt_016(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "SGChanges",
                        "filterPattern": "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupIngress) }",
                        "metricTransformations": [{"metricName": "SGChanges"}],
                    }
                ]
            }
        )
        assert r.status == "PASS"

    def test_fail_when_no_sg_change_filters(self):
        r = check_alrt_016(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "ConsoleLogin",
                        "filterPattern": '{ $.eventName = "ConsoleLogin" }',
                        "metricTransformations": [],
                    }
                ]
            }
        )
        assert r.status == "FAIL"

    def test_fail_when_no_metric_filters_at_all(self):
        r = check_alrt_016({"cloudwatch-metric-filters": []})
        assert r.status == "FAIL"

    def test_skip_when_no_evidence(self):
        r = check_alrt_016({})
        assert r.status == "SKIP"


class TestALRT012:
    def test_pass_when_metric_filter_covers_consolelogin(self):
        r = check_alrt_012(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "ConsoleLogin",
                        "filterPattern": '{ $.eventName = "ConsoleLogin" }',
                        "metricTransformations": [{"metricName": "ConsoleLoginCount"}],
                    }
                ],
                "eventbridge-rules": [],
            }
        )
        assert r.status == "PASS"

    def test_pass_when_metric_filter_covers_stoplogging(self):
        r = check_alrt_012(
            {
                "cloudwatch-metric-filters": [
                    {
                        "filterName": "StopLogging",
                        "filterPattern": '{ $.eventName = "StopLogging" }',
                        "metricTransformations": [{"metricName": "StopLoggingCount"}],
                    }
                ],
                "eventbridge-rules": [],
            }
        )
        assert r.status == "PASS"

    def test_pass_when_eventbridge_rule_covers_consolelogin(self):
        r = check_alrt_012(
            {
                "cloudwatch-metric-filters": [],
                "eventbridge-rules": [
                    {
                        "Name": "security-consolelogin",
                        "EventPattern": '{"source":["aws.signin"],"detail-type":["ConsoleLogin"]}',
                        "State": "ENABLED",
                        "Targets": [{"Arn": "arn:aws:sns:us-east-1:111:security-alerts"}],
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_pass_ignores_disabled_eventbridge_rules(self):
        """Disabled EB rules should not count as coverage."""
        r = check_alrt_012(
            {
                "cloudwatch-metric-filters": [],
                "eventbridge-rules": [
                    {
                        "Name": "security-consolelogin",
                        "EventPattern": '{"source":["aws.signin"],"detail-type":["ConsoleLogin"]}',
                        "State": "DISABLED",
                        "Targets": [],
                    }
                ],
            }
        )
        assert r.status == "FAIL"

    def test_pass_ignores_do_not_delete_managed_rules(self):
        """Inspector-managed rules should not count as security event coverage."""
        r = check_alrt_012(
            {
                "cloudwatch-metric-filters": [],
                "eventbridge-rules": [
                    {
                        "Name": "DO-NOT-DELETE-AmazonInspectorEc2ManagedRule",
                        "EventPattern": '{"source":["aws.ec2"]}',
                        "State": "ENABLED",
                        "Targets": [{"Arn": "arn:aws:inspector2:us-east-1:::"}],
                    }
                ],
            }
        )
        assert r.status == "FAIL"

    def test_fail_when_no_metric_filters_and_no_security_eventbridge_rules(self):
        """No metric filters and only managed EB rules -> FAIL."""
        r = check_alrt_012(
            {
                "cloudwatch-metric-filters": [],
                "eventbridge-rules": [
                    {
                        "Name": "DO-NOT-DELETE-AmazonInspectorEc2ManagedRule",
                        "EventPattern": '{"source":["aws.ec2"]}',
                        "State": "ENABLED",
                        "Targets": [{"Arn": "arn:aws:inspector2:us-east-1:::"}],
                    }
                ],
            }
        )
        assert r.status == "FAIL"
        assert "ConsoleLogin" in r.evidence_summary

    def test_skip_when_no_evidence_at_all(self):
        r = check_alrt_012({})
        assert r.status == "SKIP"

    def test_fail_when_both_sources_empty(self):
        r = check_alrt_012({"cloudwatch-metric-filters": [], "eventbridge-rules": []})
        assert r.status == "FAIL"


class TestALR022WithSameAccountPass:
    def test_pass_when_principal_wildcard_with_source_owner_condition(self):
        """AWS default SNS policy: Principal:* + SourceOwner condition = PASS."""
        r = check_alr_022(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:alerts",
                        "Attributes": {
                            "Policy": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sns:Publish","Condition":{"StringEquals":{"AWS:SourceOwner":"111"}}}]}'
                        },
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_skip_when_no_sns_topics(self):
        # Empty sns-topics list -> SKIP (no topics to evaluate)
        r = check_alr_022({"cloudwatch-alarms": [], "sns-topics": []})
        assert r.status == "SKIP"


class TestALR023WithSameAccountPass:
    def test_pass_when_principal_wildcard_with_source_account_condition(self):
        r = check_alr_023(
            {
                "cloudwatch-alarms": [{"AlarmActions": ["arn:aws:sns:us-east-1:111:alerts"]}],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:alerts",
                        "Attributes": {
                            "Policy": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sns:Subscribe","Condition":{"StringEquals":{"aws:SourceAccount":"111"}}}]}'
                        },
                    }
                ],
            }
        )
        assert r.status == "PASS"


class TestALR024WithPass:
    def test_pass_when_no_http_subscriptions_on_alert_topic(self):
        r = check_alr_024(
            {
                "eventbridge-rules": [
                    {
                        "Targets": [{"Arn": "arn:aws:sns:us-east-1:111:alerts"}],
                    }
                ],
                "sns-topics": [
                    {
                        "TopicArn": "arn:aws:sns:us-east-1:111:alerts",
                        "Subscriptions": [{"Protocol": "email"}],
                    }
                ],
            }
        )
        assert r.status == "PASS"

    def test_skip_when_no_sns_evidence(self):
        r = check_alr_024({})
        assert r.status == "SKIP"


class TestALR025WithPass:
    def test_pass_when_security_rule_has_sns_target(self):
        r = check_alr_025(
            {
                "eventbridge-rules": [
                    {
                        "Name": "ct-stoplogging",
                        "EventPattern": '{"source":["aws.cloudtrail"],"detail":{"eventName":["StopLogging"]}}',
                        "Targets": [{"Arn": "arn:aws:sns:us-east-1:111:alerts"}],
                    }
                ]
            }
        )
        assert r.status == "PASS"

    def test_skip_when_no_eventbridge_evidence(self):
        r = check_alr_025({})
        assert r.status == "SKIP"

    def test_pass_when_only_aws_managed_rules(self):
        # Inspector managed rules should be skipped entirely
        r = check_alr_025(
            {
                "eventbridge-rules": [
                    {
                        "Name": "DO-NOT-DELETE-AmazonInspectorManagedRule",
                        "EventPattern": '{"source":["aws.cloudtrail"]}',
                        "Targets": [],
                    }
                ]
            }
        )
        # No user security rules found -> PASS (nothing to fail)
        assert r.status == "PASS"


# ============================================================================
# EXPOSURE CHECKS
# ============================================================================


class TestEXP002:
    def test_pass_when_no_public_rds(self):
        r = check_exp_002(
            {"rds-instances": [{"DBInstanceIdentifier": "db1", "PubliclyAccessible": False}]}
        )
        assert r.status == "PASS"

    def test_fail_when_public_rds(self):
        r = check_exp_002(
            {"rds-instances": [{"DBInstanceIdentifier": "db1", "PubliclyAccessible": True}]}
        )
        assert r.status == "FAIL"


class TestEXP003:
    def test_pass_when_no_open_ssh(self):
        evidence = {
            "security-groups": {
                "by_id": {
                    "sg-1": {
                        "GroupId": "sg-1",
                        "IngressRules": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                    }
                }
            }
        }
        r = check_exp_003(evidence)
        assert r.status == "PASS"

    def test_fail_when_ssh_open(self):
        evidence = {
            "security-groups": {
                "by_id": {
                    "sg-1": {
                        "GroupId": "sg-1",
                        "IngressRules": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                    }
                }
            }
        }
        r = check_exp_003(evidence)
        assert r.status == "FAIL"


class TestEXP020:
    def test_fail_cloudfront_s3_origin_without_oai(self):
        evidence = {
            "cloudfront-distributions": {
                "items": [
                    {
                        "Id": "E123ABC",
                        "Enabled": True,
                        "Origins": [
                            {
                                "DomainName": "my-bucket.s3.amazonaws.com",
                                "S3OriginConfig": {"OriginAccessIdentity": ""},
                            }
                        ],
                    }
                ]
            }
        }
        r = check_exp_020(evidence)
        assert r.status == "FAIL"

    def test_pass_cloudfront_s3_origin_with_oai(self):
        evidence = {
            "cloudfront-distributions": {
                "items": [
                    {
                        "Id": "E123ABC",
                        "Enabled": True,
                        "Origins": [
                            {
                                "DomainName": "my-bucket.s3.amazonaws.com",
                                "S3OriginConfig": {
                                    "OriginAccessIdentity": "origin-access-identity/cloudfront/ABCDEFG"
                                },
                            }
                        ],
                    }
                ]
            }
        }
        r = check_exp_020(evidence)
        assert r.status == "PASS"


class TestEXP021:
    def test_fail_unauthenticated_mutating_route(self):
        evidence = {
            "api-gateway-routes": {
                "items": [
                    {
                        "ApiId": "abc123",
                        "Method": "POST",
                        "Path": "/admin/create",
                        "AuthorizationType": "NONE",
                    }
                ]
            }
        }
        r = check_exp_021(evidence)
        assert r.status == "FAIL"


class TestEXP022:
    def test_fail_unauthenticated_proxy_any_route(self):
        evidence = {
            "api-gateway-routes": {
                "items": [
                    {
                        "ApiId": "abc123",
                        "Method": "ANY",
                        "Path": "/{proxy+}",
                        "AuthorizationType": "NONE",
                    }
                ]
            }
        }
        r = check_exp_022(evidence)
        assert r.status == "FAIL"


# ============================================================================
# NETWORK CHECKS
# ============================================================================


class TestNET001:
    def test_pass_no_sensitive_ports(self):
        evidence = {
            "security-groups": [
                {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
        r = check_net_001(evidence)
        assert r.status == "PASS"

    def test_fail_db_port_exposed(self):
        evidence = {
            "security-groups": [
                {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3306,
                            "ToPort": 3306,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
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


class TestNET002:
    def _sg(self, sg_id, inbound_protocol, cidr="0.0.0.0/0"):
        return {
            "GroupId": sg_id,
            "GroupName": "test",
            "IngressRules": [
                {
                    "IpProtocol": inbound_protocol,
                    "IpRanges": [{"CidrIp": cidr}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                }
            ],
            "EgressRules": [],
        }

    def test_skip_no_evidence(self):
        r = check_net_002({})
        assert r.status == "SKIP"

    def test_pass_no_all_traffic(self):
        sg = self._sg("sg-1", "tcp", "0.0.0.0/0")
        r = check_net_002({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_fail_all_traffic_ipv4(self):
        sg = self._sg("sg-1", "-1", "0.0.0.0/0")
        r = check_net_002({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "FAIL"
        assert "sg-1" in r.affected_resources

    def test_fail_all_traffic_ipv6(self):
        sg = {
            "GroupId": "sg-2",
            "GroupName": "test",
            "IngressRules": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    "UserIdGroupPairs": [],
                }
            ],
            "EgressRules": [],
        }
        r = check_net_002({"security-groups": {"by_id": {"sg-2": sg}}})
        assert r.status == "FAIL"

    def test_pass_all_traffic_private_only(self):
        """ALL traffic from RFC1918 /16 is NOT internet exposure."""
        sg = self._sg("sg-3", "-1", "10.0.0.0/8")
        r = check_net_002({"security-groups": {"by_id": {"sg-3": sg}}})
        assert r.status == "PASS"

    def test_handles_list_format(self):
        """List format evidence also works."""
        sg = self._sg("sg-4", "tcp", "0.0.0.0/0")
        r = check_net_002({"security-groups": [sg]})
        assert r.status == "PASS"


class TestNET003:
    def _nacl(self, nacl_id, protocol, action, cidr, egress=False):
        return {
            "NetworkAclId": nacl_id,
            "IsDefault": False,
            "Entries": [
                {
                    "Protocol": protocol,
                    "RuleAction": action,
                    "CidrBlock": cidr,
                    "Egress": egress,
                    "RuleNumber": 100,
                }
            ],
            "Associations": [],
        }

    def test_skip_no_evidence(self):
        r = check_net_003({})
        assert r.status == "SKIP"

    def test_pass_specific_ports(self):
        nacl = self._nacl("acl-1", "6", "allow", "0.0.0.0/0")
        r = check_net_003({"network-acls": {"items": [nacl]}})
        assert r.status == "PASS"  # protocol 6 (TCP) not -1

    def test_fail_allow_all_inbound(self):
        nacl = self._nacl("acl-1", "-1", "allow", "0.0.0.0/0", egress=False)
        r = check_net_003({"network-acls": {"items": [nacl]}})
        assert r.status == "FAIL"
        assert "acl-1" in r.affected_resources

    def test_pass_deny_all_outbound(self):
        """Deny rule on egress with -1 is the standard last rule, not a finding."""
        nacl = self._nacl("acl-1", "-1", "deny", "0.0.0.0/0", egress=True)
        r = check_net_003({"network-acls": {"items": [nacl]}})
        assert r.status == "PASS"

    def test_pass_allow_all_egress(self):
        """Allow all egress is not what this check targets (inbound only)."""
        nacl = self._nacl("acl-1", "-1", "allow", "0.0.0.0/0", egress=True)
        r = check_net_003({"network-acls": {"items": [nacl]}})
        assert r.status == "PASS"


class TestNET009:
    def _sg(self, sg_id, proto, from_port, to_port, cidr):
        return {
            "GroupId": sg_id,
            "GroupName": "test",
            "IngressRules": [
                {
                    "IpProtocol": proto,
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": cidr}],
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                }
            ],
            "EgressRules": [],
        }

    def test_skip_no_evidence(self):
        r = check_net_009({})
        assert r.status == "SKIP"

    def test_fail_broad_cidr_non_web_port(self):
        """Port 8080 with /16 CIDR should trigger FAIL."""
        sg = self._sg("sg-1", "tcp", 8080, 8080, "10.70.0.0/16")
        r = check_net_009({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "FAIL"
        assert "sg-1" in r.affected_resources

    def test_pass_broad_cidr_web_port_80(self):
        """Port 80 with /16 CIDR should NOT trigger (web port)."""
        sg = self._sg("sg-1", "tcp", 80, 80, "10.70.0.0/16")
        r = check_net_009({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_pass_broad_cidr_web_port_443(self):
        """Port 443 with /16 CIDR should NOT trigger."""
        sg = self._sg("sg-1", "tcp", 443, 443, "10.70.0.0/16")
        r = check_net_009({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_pass_narrow_cidr_any_port(self):
        """/24 CIDR is not broad enough to trigger."""
        sg = self._sg("sg-1", "tcp", 5432, 5432, "10.70.21.0/24")
        r = check_net_009({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_fail_slash8_cidr(self):
        """/8 CIDR is broader than /16 and should trigger."""
        sg = self._sg("sg-1", "tcp", 5432, 5432, "10.0.0.0/8")
        r = check_net_009({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "FAIL"


class TestNET016:
    def _nacl(self, nacl_id, is_default, subnet_ids):
        return {
            "NetworkAclId": nacl_id,
            "IsDefault": is_default,
            "Entries": [],
            "Associations": [
                {"NetworkAclAssociationId": f"a-{i}", "NetworkAclId": nacl_id, "SubnetId": sid}
                for i, sid in enumerate(subnet_ids)
            ],
        }

    def test_skip_no_evidence(self):
        r = check_net_016({})
        assert r.status == "SKIP"

    def test_pass_custom_nacls_only(self):
        nacl = self._nacl("acl-custom", False, ["subnet-1", "subnet-2"])
        r = check_net_016({"network-acls": {"items": [nacl]}})
        assert r.status == "PASS"

    def test_fail_subnets_on_default_nacl(self):
        default = self._nacl("acl-default", True, ["subnet-3", "subnet-4", "subnet-5"])
        custom = self._nacl("acl-custom", False, ["subnet-1", "subnet-2"])
        r = check_net_016({"network-acls": {"items": [default, custom]}})
        assert r.status == "FAIL"
        assert len(r.affected_resources) == 3
        assert "subnet-3" in r.affected_resources

    def test_pass_default_nacl_no_subnets(self):
        """Default NACL exists but has no subnet associations → PASS."""
        default = self._nacl("acl-default", True, [])
        r = check_net_016({"network-acls": {"items": [default]}})
        assert r.status == "PASS"


class TestNET027:
    def _sg(self, sg_id, tags):
        return {
            "GroupId": sg_id,
            "GroupName": "test",
            "Tags": tags,
            "IngressRules": [],
            "EgressRules": [],
        }

    def test_skip_no_evidence(self):
        r = check_net_027({})
        assert r.status == "SKIP"

    def test_pass_all_tagged(self):
        sg = self._sg("sg-1", [{"Key": "Name", "Value": "mysg"}])
        r = check_net_027({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_fail_missing_tags(self):
        sg = self._sg("sg-1", [])
        r = check_net_027({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "FAIL"
        assert "sg-1" in r.affected_resources

    def test_fail_multiple_untagged(self):
        sgs = {
            "sg-1": self._sg("sg-1", [{"Key": "Name", "Value": "ok"}]),
            "sg-2": self._sg("sg-2", []),
            "sg-3": self._sg("sg-3", []),
        }
        r = check_net_027({"security-groups": {"by_id": sgs}})
        assert r.status == "FAIL"
        assert "sg-2" in r.affected_resources
        assert "sg-3" in r.affected_resources

    def test_handles_list_format(self):
        sg = self._sg("sg-5", [{"Key": "Name", "Value": "ok"}])
        r = check_net_027({"security-groups": [sg]})
        assert r.status == "PASS"


class TestNET004:
    def _rt(self, rt_id, has_igw, subnet_ids):
        routes = (
            [{"GatewayId": "igw-abc", "DestinationCidrBlock": "0.0.0.0/0", "State": "active"}]
            if has_igw
            else []
        )
        assocs = [{"SubnetId": sid} for sid in subnet_ids]
        return {"RouteTableId": rt_id, "Routes": routes, "Associations": assocs}

    def _subnet(self, sid, name):
        return {"SubnetId": sid, "Tags": [{"Key": "Name", "Value": name}]}

    def test_skip_no_route_tables(self):
        r = check_net_004({"subnets": {"items": [self._subnet("s-1", "private")]}})
        assert r.status == "SKIP"
        assert r.check_id == "NET-004"

    def test_skip_no_subnets(self):
        r = check_net_004({"route-tables": {"items": [self._rt("rt-1", True, ["s-1"])]}})
        assert r.status == "SKIP"

    def test_pass_private_subnet_no_igw(self):
        rt = self._rt("rt-1", False, ["s-1"])
        s = self._subnet("s-1", "vpc-private-us-east-1a")
        r = check_net_004(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [s]},
            }
        )
        assert r.status == "PASS"

    def test_fail_db_subnet_with_igw(self):
        rt = self._rt("rt-1", True, ["s-db"])
        s = self._subnet("s-db", "vpc-db-us-east-1a")
        r = check_net_004(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [s]},
            }
        )
        assert r.status == "FAIL"
        assert "s-db" in r.affected_resources

    def test_pass_public_subnet_with_igw(self):
        rt = self._rt("rt-1", True, ["s-pub"])
        s = self._subnet("s-pub", "vpc-public-us-east-1a")
        r = check_net_004(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [s]},
            }
        )
        # public subnet with IGW = expected, not flagged as DB/private
        assert r.status == "PASS"


class TestNET006:
    def _sg_with_ingress(self, sg_id, user_id, ref_sg_id):
        return {
            "GroupId": sg_id,
            "IngressRules": [{"UserIdGroupPairs": [{"UserId": user_id, "GroupId": ref_sg_id}]}],
            "EgressRules": [],
        }

    def test_skip_no_evidence(self):
        r = check_net_006({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-006"

    def test_pass_same_account(self):
        sg = self._sg_with_ingress("sg-1", "123456789012", "sg-other")
        r = check_net_006(
            {
                "_audit_metadata": {"_account_id": "123456789012"},
                "security-groups": {"by_id": {"sg-1": sg}},
            }
        )
        assert r.status == "PASS"

    def test_fail_cross_account_ref(self):
        sg = self._sg_with_ingress("sg-1", "999999999999", "sg-foreign")
        r = check_net_006(
            {
                "_audit_metadata": {"_account_id": "123456789012"},
                "security-groups": {"by_id": {"sg-1": sg}},
            }
        )
        assert r.status == "FAIL"
        assert len(r.affected_resources) == 1

    def test_infers_account_from_pairs(self):
        # No metadata — infer account_id from first UserIdGroupPairs seen
        sg = self._sg_with_ingress("sg-1", "111111111111", "sg-same")
        r = check_net_006({"security-groups": {"by_id": {"sg-1": sg}}})
        # sg-1 references 111111111111 which is the inferred account — PASS
        assert r.status == "PASS"


class TestNET005:
    def _rt(self, rt_id, routes):
        return {"RouteTableId": rt_id, "Routes": routes, "Associations": []}

    def test_skip_no_evidence(self):
        r = check_net_005({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-005"

    def test_pass_no_peering_routes(self):
        rt = self._rt("rt-1", [{"GatewayId": "igw-abc", "DestinationCidrBlock": "0.0.0.0/0"}])
        r = check_net_005({"route-tables": {"items": [rt]}})
        assert r.status == "PASS"

    def test_skip_when_peering_route_found(self):
        rt = self._rt(
            "rt-1", [{"GatewayId": "pcx-0123456789abcdef", "DestinationCidrBlock": "10.1.0.0/16"}]
        )
        r = check_net_005({"route-tables": {"items": [rt]}})
        assert r.status == "SKIP"
        assert "peering" in r.evidence_summary.lower()

    def test_pass_non_peering_gateways(self):
        rt = self._rt(
            "rt-1",
            [
                {"GatewayId": "igw-abc", "DestinationCidrBlock": "0.0.0.0/0"},
                {"GatewayId": "nat-0abc123", "DestinationCidrBlock": "10.0.0.0/8"},
            ],
        )
        r = check_net_005({"route-tables": {"items": [rt]}})
        assert r.status == "PASS"


class TestNET007:
    def _rt_with_igw(self):
        return {
            "RouteTableId": "rt-1",
            "Routes": [
                {"GatewayId": "igw-abc", "DestinationCidrBlock": "0.0.0.0/0", "State": "active"}
            ],
            "Associations": [],
        }

    def _rt_no_igw(self):
        return {
            "RouteTableId": "rt-1",
            "Routes": [{"GatewayId": "nat-abc", "DestinationCidrBlock": "0.0.0.0/0"}],
            "Associations": [],
        }

    def test_skip_no_evidence(self):
        r = check_net_007({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-007"

    def test_pass_no_igw_routes(self):
        r = check_net_007({"route-tables": {"items": [self._rt_no_igw()]}})
        assert r.status == "PASS"

    def test_fail_igw_no_nfw(self):
        vpces = [
            {
                "VpcEndpointId": "vpce-1",
                "ServiceName": "com.amazonaws.us-east-1.s3",
                "VpcEndpointType": "Gateway",
            }
        ]
        r = check_net_007(
            {
                "route-tables": {"items": [self._rt_with_igw()]},
                "vpc-endpoints": {"items": vpces},
            }
        )
        assert r.status == "FAIL"

    def test_pass_igw_with_nfw_endpoint(self):
        vpces = [
            {
                "VpcEndpointId": "vpce-nfw",
                "ServiceName": "com.amazonaws.us-east-1.network-firewall",
                "VpcEndpointType": "Interface",
            }
        ]
        r = check_net_007(
            {
                "route-tables": {"items": [self._rt_with_igw()]},
                "vpc-endpoints": {"items": vpces},
            }
        )
        assert r.status == "PASS"

    def test_fail_igw_empty_vpce_list(self):
        r = check_net_007(
            {
                "route-tables": {"items": [self._rt_with_igw()]},
                "vpc-endpoints": {"items": []},
            }
        )
        assert r.status == "FAIL"


class TestNET008:
    def _rt_public(self, subnet_id):
        return {
            "RouteTableId": "rt-pub",
            "Routes": [
                {"GatewayId": "igw-abc", "DestinationCidrBlock": "0.0.0.0/0", "State": "active"}
            ],
            "Associations": [{"SubnetId": subnet_id}],
        }

    def test_skip_no_evidence(self):
        r = check_net_008({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-008"

    def test_pass_no_public_subnets(self):
        rt = {"RouteTableId": "rt-1", "Routes": [], "Associations": [{"SubnetId": "s-priv"}]}
        subnet = {"SubnetId": "s-priv"}
        r = check_net_008(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [subnet]},
            }
        )
        assert r.status == "PASS"

    def test_fail_lambda_in_public_subnet(self):
        rt = self._rt_public("s-pub")
        fn = {"FunctionName": "my-func", "VpcConfig": {"SubnetIds": ["s-pub"]}}
        r = check_net_008(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [{"SubnetId": "s-pub"}]},
                "lambda-functions": {"items": [fn]},
            }
        )
        assert r.status == "FAIL"
        assert any("my-func" in res for res in r.affected_resources)

    def test_pass_lambda_in_private_subnet(self):
        rt = self._rt_public("s-pub")
        fn = {"FunctionName": "my-func", "VpcConfig": {"SubnetIds": ["s-priv"]}}
        r = check_net_008(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [{"SubnetId": "s-pub"}, {"SubnetId": "s-priv"}]},
                "lambda-functions": {"items": [fn]},
            }
        )
        assert r.status == "PASS"


class TestNET010:
    def _nacl(self, nacl_id, is_default, cidr, protocol="-1", action="allow"):
        return {
            "NetworkAclId": nacl_id,
            "IsDefault": is_default,
            "Entries": [
                {"Protocol": protocol, "RuleAction": action, "CidrBlock": cidr, "Egress": False}
            ],
        }

    def test_skip_no_evidence(self):
        r = check_net_010({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-010"

    def test_fail_default_nacl_allow_all_internet(self):
        nacl = self._nacl("acl-default", True, "0.0.0.0/0")
        r = check_net_010({"network-acls": {"items": [nacl]}})
        assert r.status == "FAIL"
        assert "acl-default" in r.affected_resources

    def test_pass_default_nacl_allows_vpc_cidr_only(self):
        nacl = self._nacl("acl-default", True, "10.70.0.0/16")
        r = check_net_010({"network-acls": {"items": [nacl]}})
        assert r.status == "PASS"

    def test_pass_custom_nacl_even_with_broad_rule(self):
        nacl = self._nacl("acl-custom", False, "0.0.0.0/0")
        r = check_net_010({"network-acls": {"items": [nacl]}})
        assert r.status == "PASS"

    def test_pass_default_nacl_deny_rule(self):
        nacl = self._nacl("acl-default", True, "0.0.0.0/0", action="deny")
        r = check_net_010({"network-acls": {"items": [nacl]}})
        assert r.status == "PASS"


class TestNET012:
    def test_skip_no_topology_evidence(self):
        r = check_net_012({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-012"

    def test_skip_empty_tgw_list(self):
        r = check_net_012({"transit-gateway-topology": {"transit_gateways": []}})
        assert r.status == "SKIP"

    def test_skip_when_tgw_present(self):
        r = check_net_012(
            {"transit-gateway-topology": {"transit_gateways": [{"TransitGatewayId": "tgw-abc"}]}}
        )
        assert r.status == "SKIP"
        assert "manual" in r.evidence_summary.lower() or "present" in r.evidence_summary.lower()


class TestNET014:
    def test_skip_no_evidence(self):
        r = check_net_014({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-014"

    def test_pass_no_blackhole_routes(self):
        rt = {
            "RouteTableId": "rt-1",
            "Routes": [
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1", "State": "active"}
            ],
            "Associations": [],
        }
        r = check_net_014({"route-tables": {"items": [rt]}})
        assert r.status == "PASS"

    def test_fail_blackhole_route(self):
        rt = {
            "RouteTableId": "rt-1",
            "Routes": [{"DestinationCidrBlock": "10.0.0.0/8", "State": "blackhole"}],
            "Associations": [],
        }
        r = check_net_014({"route-tables": {"items": [rt]}})
        assert r.status == "FAIL"
        assert "rt-1" in r.affected_resources


class TestNET017:
    def _rt(self, rt_id, has_igw, subnet_ids):
        routes = [{"GatewayId": "igw-abc", "DestinationCidrBlock": "0.0.0.0/0"}] if has_igw else []
        assocs = [{"SubnetId": sid} for sid in subnet_ids]
        return {"RouteTableId": rt_id, "Routes": routes, "Associations": assocs}

    def _subnet(self, sid, name):
        return {"SubnetId": sid, "Tags": [{"Key": "Name", "Value": name}]}

    def test_skip_no_route_tables(self):
        r = check_net_017({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-017"

    def test_pass_public_subnet_with_igw(self):
        rt = self._rt("rt-1", True, ["s-pub"])
        s = self._subnet("s-pub", "vpc-public-us-east-1a")
        r = check_net_017(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [s]},
            }
        )
        assert r.status == "PASS"

    def test_fail_non_public_subnet_with_igw(self):
        rt = self._rt("rt-1", True, ["s-priv"])
        s = self._subnet("s-priv", "vpc-private-us-east-1a")
        r = check_net_017(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [s]},
            }
        )
        assert r.status == "FAIL"
        assert "s-priv" in r.affected_resources

    def test_pass_no_igw_routes(self):
        rt = self._rt("rt-1", False, ["s-priv"])
        s = self._subnet("s-priv", "vpc-private-us-east-1a")
        r = check_net_017(
            {
                "route-tables": {"items": [rt]},
                "subnets": {"items": [s]},
            }
        )
        assert r.status == "PASS"


class TestNET019:
    def _sg(self, sg_id, n_ingress, n_egress):
        return {
            "GroupId": sg_id,
            "IngressRules": [{}] * n_ingress,
            "EgressRules": [{}] * n_egress,
        }

    def test_skip_no_evidence(self):
        r = check_net_019({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-019"

    def test_pass_small_sg(self):
        sg = self._sg("sg-1", 10, 5)
        r = check_net_019({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_fail_oversized_sg(self):
        sg = self._sg("sg-1", 30, 25)  # 55 total
        r = check_net_019({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "FAIL"
        assert "sg-1" in r.affected_resources

    def test_boundary_exactly_50_rules(self):
        sg = self._sg("sg-1", 25, 25)  # exactly 50 → PASS (> 50 required)
        r = check_net_019({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"


class TestNET021:
    def test_skip_no_evidence(self):
        r = check_net_021({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-021"

    def test_skip_always_even_with_sgs(self):
        sg = {"GroupId": "sg-1", "IngressRules": [], "EgressRules": []}
        r = check_net_021({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "SKIP"
        assert "ENI" in r.evidence_summary or "manual" in r.evidence_summary.lower()


class TestNET029:
    def _vpc(self, vpc_id, cidr):
        return {"VpcId": vpc_id, "CidrBlock": cidr}

    def test_skip_no_evidence(self):
        r = check_net_029({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-029"

    def test_pass_single_vpc(self):
        r = check_net_029({"vpcs": {"items": [self._vpc("vpc-1", "10.0.0.0/16")]}})
        assert r.status == "PASS"

    def test_pass_multiple_vpcs_no_overlap(self):
        vpcs = [self._vpc("vpc-1", "10.0.0.0/16"), self._vpc("vpc-2", "10.1.0.0/16")]
        r = check_net_029({"vpcs": {"items": vpcs}})
        assert r.status == "PASS"

    def test_fail_duplicate_cidr(self):
        vpcs = [self._vpc("vpc-1", "10.0.0.0/16"), self._vpc("vpc-2", "10.0.0.0/16")]
        r = check_net_029({"vpcs": {"items": vpcs}})
        assert r.status == "FAIL"


class TestNET015:
    def _sg(self, sg_id, egress_rules, ingress_rules=None):
        return {
            "GroupId": sg_id,
            "EgressRules": egress_rules,
            "IngressRules": ingress_rules or [],
        }

    def _rule_with_both(self, port, cidr="0.0.0.0/0", sg_ref="sg-other"):
        return {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": cidr}],
            "UserIdGroupPairs": [{"GroupId": sg_ref, "UserId": "111"}],
        }

    def _rule_ip_only(self, port, cidr="0.0.0.0/0"):
        return {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": cidr}],
            "UserIdGroupPairs": [],
        }

    def _rule_sg_only(self, port, sg_ref="sg-other"):
        return {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [],
            "UserIdGroupPairs": [{"GroupId": sg_ref}],
        }

    def test_skip_no_evidence(self):
        r = check_net_015({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-015"

    def test_fail_egress_rule_with_both(self):
        sg = self._sg("sg-1", [self._rule_with_both(443)])
        r = check_net_015({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "FAIL"
        assert "sg-1" in r.affected_resources

    def test_fail_ingress_rule_with_both(self):
        sg = self._sg("sg-1", [], [self._rule_with_both(80)])
        r = check_net_015({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "FAIL"
        assert "sg-1" in r.affected_resources

    def test_pass_rule_ip_only(self):
        sg = self._sg("sg-1", [self._rule_ip_only(443)])
        r = check_net_015({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_pass_rule_sg_only(self):
        sg = self._sg("sg-1", [self._rule_sg_only(443)])
        r = check_net_015({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_pass_sg_ref_plus_non_internet_cidr(self):
        # SG ref + private CIDR (not 0.0.0.0/0) should not be flagged
        rule = {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            "UserIdGroupPairs": [{"GroupId": "sg-other"}],
        }
        sg = self._sg("sg-1", [rule])
        r = check_net_015({"security-groups": {"by_id": {"sg-1": sg}}})
        assert r.status == "PASS"

    def test_fail_two_sgs_affected(self):
        sg1 = self._sg("sg-1", [self._rule_with_both(443)])
        sg2 = self._sg("sg-2", [self._rule_with_both(443)])
        r = check_net_015({"security-groups": {"by_id": {"sg-1": sg1, "sg-2": sg2}}})
        assert r.status == "FAIL"
        assert "sg-1" in r.affected_resources
        assert "sg-2" in r.affected_resources


class TestNET025:
    def _subnet(self, sid, tags):
        return {"SubnetId": sid, "Tags": tags}

    def test_skip_no_evidence(self):
        r = check_net_025({})
        assert r.status == "SKIP"
        assert r.check_id == "NET-025"

    def test_fail_all_subnets_missing_classification(self):
        s = self._subnet(
            "s-1", [{"Key": "Name", "Value": "vpc-public"}, {"Key": "Env", "Value": "prod"}]
        )
        r = check_net_025({"subnets": {"items": [s]}})
        assert r.status == "FAIL"
        assert "s-1" in r.affected_resources

    def test_pass_subnet_has_tier_tag(self):
        s = self._subnet("s-1", [{"Key": "Tier", "Value": "Public"}])
        r = check_net_025({"subnets": {"items": [s]}})
        assert r.status == "PASS"

    def test_pass_subnet_has_layer_tag(self):
        s = self._subnet("s-1", [{"Key": "Layer", "Value": "DB"}])
        r = check_net_025({"subnets": {"items": [s]}})
        assert r.status == "PASS"

    def test_pass_subnet_has_classification_tag(self):
        s = self._subnet("s-1", [{"Key": "Classification", "Value": "Private"}])
        r = check_net_025({"subnets": {"items": [s]}})
        assert r.status == "PASS"

    def test_fail_mixed_subnets(self):
        s1 = self._subnet("s-1", [{"Key": "Tier", "Value": "Public"}])  # has tag
        s2 = self._subnet("s-2", [{"Key": "Name", "Value": "private"}])  # missing
        r = check_net_025({"subnets": {"items": [s1, s2]}})
        assert r.status == "FAIL"
        assert "s-2" in r.affected_resources
        assert "s-1" not in r.affected_resources


# ============================================================================
# SECRETS MANAGER CHECKS
# ============================================================================


class TestSM001:
    def test_pass_no_wildcard(self):
        r = check_sm_001(
            {
                "secrets": {
                    "secrets": [
                        {
                            "Name": "secret1",
                            "ResourcePolicy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {"AWS": "arn:aws:iam::123:root"},
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_wildcard_principal(self):
        r = check_sm_001(
            {
                "secrets": {
                    "secrets": [
                        {
                            "Name": "secret1",
                            "ARN": "arn:aws:sm:...",
                            "ResourcePolicy": {
                                "Statement": [{"Effect": "Allow", "Principal": "*"}]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestSM003:
    def test_pass_rotation_within_90(self):
        r = check_sm_003(
            {
                "secrets": {
                    "secrets": [
                        {
                            "Name": "s1",
                            "RotationEnabled": True,
                            "RotationRules": {"AutomaticallyAfterDays": 30},
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_rotation_over_90(self):
        r = check_sm_003(
            {
                "secrets": {
                    "secrets": [
                        {
                            "Name": "s1",
                            "ARN": "arn:...",
                            "RotationEnabled": True,
                            "RotationRules": {"AutomaticallyAfterDays": 120},
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestSM013:
    def test_pass_no_external_principal(self):
        r = check_sm_013(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "ResourcePolicy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {
                                            "AWS": "arn:aws:iam::111111111111:role/AppRole"
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_external_principal(self):
        r = check_sm_013(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "ResourcePolicy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {
                                            "AWS": "arn:aws:iam::222222222222:role/ExternalRole"
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestSM014:
    def test_pass_rotation_lambda_present(self):
        r = check_sm_014(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "RotationEnabled": True,
                            "RotationLambdaARN": "arn:aws:lambda:us-east-1:111111111111:function:rotate-app",
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_rotation_enabled_without_lambda(self):
        r = check_sm_014(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "RotationEnabled": True,
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestSM015:
    def test_pass_same_account_kms_key(self):
        r = check_sm_015(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "KmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/abc",
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_cross_account_kms_key(self):
        r = check_sm_015(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "KmsKeyId": "arn:aws:kms:us-east-1:222222222222:key/xyz",
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestSM017:
    def test_pass_replicated_without_permissive_policy(self):
        r = check_sm_017(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "ReplicationStatus": [{"Region": "us-west-2"}],
                            "ResourcePolicy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {
                                            "AWS": "arn:aws:iam::111111111111:role/AppRole"
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_replicated_with_wildcard_policy(self):
        r = check_sm_017(
            {
                "secrets": {
                    "secrets": [
                        {
                            "ARN": "arn:aws:secretsmanager:us-east-1:111111111111:secret:app",
                            "ReplicationStatus": [{"Region": "us-west-2"}],
                            "ResourcePolicy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": "*",
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


# ============================================================================
# ECR CHECKS
# ============================================================================


class TestECR001:
    def test_pass_no_wildcard(self):
        r = check_ecr_001(
            {
                "repositories": {
                    "repositories": [
                        {
                            "repositoryName": "app",
                            "Policy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {"AWS": "arn:aws:iam::123:root"},
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_wildcard(self):
        r = check_ecr_001(
            {
                "repositories": {
                    "repositories": [
                        {
                            "repositoryName": "app",
                            "RepositoryArn": "arn:...",
                            "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestECR004:
    def test_pass_scanning_configured(self):
        r = check_ecr_004(
            {"registry": {"registry_scanning": {"scanningConfiguration": {"scanType": "BASIC"}}}}
        )
        assert r.status == "PASS"

    def test_fail_no_scanning(self):
        r = check_ecr_004({"registry": {"registry_scanning": {}}})
        assert r.status == "FAIL"

    def test_skip_error(self):
        r = check_ecr_004({"registry": {"registry_scanning": {"error": "AccessDenied"}}})
        assert r.status == "SKIP"


class TestECR002:
    def test_fail_when_mutable_tags_present(self):
        r = check_ecr_002(
            {
                "repositories": {
                    "repositories": [
                        {
                            "RepositoryArn": "arn:aws:ecr:us-east-1:123:repository/app",
                            "ImageTagMutability": "MUTABLE",
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"

    def test_pass_when_all_immutable(self):
        r = check_ecr_002(
            {
                "repositories": {
                    "repositories": [
                        {
                            "RepositoryArn": "arn:aws:ecr:us-east-1:123:repository/app",
                            "ImageTagMutability": "IMMUTABLE",
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"


class TestECR005:
    def test_fail_when_non_kms_or_missing_key(self):
        r = check_ecr_005(
            {
                "repositories": {
                    "repositories": [
                        {
                            "RepositoryArn": "arn:aws:ecr:us-east-1:123:repository/app",
                            "EncryptionType": "AES256",
                            "KmsKey": None,
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"

    def test_pass_when_kms_with_key(self):
        r = check_ecr_005(
            {
                "repositories": {
                    "repositories": [
                        {
                            "RepositoryArn": "arn:aws:ecr:us-east-1:123:repository/app",
                            "EncryptionType": "KMS",
                            "KmsKey": "arn:aws:kms:us-east-1:123:key/abc",
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"


class TestECR006:
    def test_fail_when_lifecycle_missing(self):
        r = check_ecr_006(
            {
                "repositories": {
                    "repositories": [
                        {
                            "RepositoryArn": "arn:aws:ecr:us-east-1:123:repository/app",
                            "HasLifecyclePolicy": False,
                            "LifecyclePolicy": None,
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"

    def test_pass_when_lifecycle_present(self):
        r = check_ecr_006(
            {
                "repositories": {
                    "repositories": [
                        {
                            "RepositoryArn": "arn:aws:ecr:us-east-1:123:repository/app",
                            "HasLifecyclePolicy": True,
                            "LifecyclePolicy": {"rules": []},
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"


# ============================================================================
# KMS CHECKS
# ============================================================================


class TestKMS001:
    def test_pass_no_wildcard(self):
        r = check_kms_001(
            {
                "kms-key-policies": {
                    "items": [
                        {
                            "KeyId": "k1",
                            "Policy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {"AWS": "arn:aws:iam::123:root"},
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_wildcard(self):
        r = check_kms_001(
            {
                "kms-key-policies": {
                    "items": [
                        {
                            "KeyId": "k1",
                            "KeyArn": "arn:...",
                            "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestKMS004:
    def test_pass_rotation_enabled(self):
        r = check_kms_004(
            {
                "kms-keys": {
                    "items": [
                        {
                            "KeyId": "k1",
                            "Metadata": {"KeyManager": "CUSTOMER"},
                            "KeyRotationEnabled": True,
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_rotation_disabled(self):
        r = check_kms_004(
            {
                "kms-keys": {
                    "items": [
                        {
                            "KeyId": "k1",
                            "KeyArn": "arn:...",
                            "Metadata": {"KeyManager": "CUSTOMER"},
                            "KeyRotationEnabled": False,
                        }
                    ]
                }
            }
        )
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
        r = check_msg_001(
            {
                "sqs-queues": {
                    "items": [
                        {
                            "QueueUrl": "q1",
                            "Policy": {
                                "Statement": [
                                    {"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}}
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_no_orgid(self):
        r = check_msg_001(
            {
                "sqs-queues": {
                    "items": [{"QueueUrl": "q1", "Policy": {"Statement": [{"Effect": "Allow"}]}}]
                }
            }
        )
        assert r.status == "FAIL"


class TestMSG002:
    def test_pass_redrive_present(self):
        r = check_msg_002(
            {
                "sqs-queues": {
                    "items": [
                        {"QueueUrl": "q1", "RedrivePolicy": {"deadLetterTargetArn": "arn:..."}}
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_no_redrive(self):
        r = check_msg_002({"sqs-queues": {"items": [{"QueueUrl": "q1"}]}})
        assert r.status == "FAIL"


class TestMSG005:
    def test_fail_wildcard_data_plane(self):
        r = check_msg_005(
            {
                "sqs-queues": {
                    "items": [
                        {
                            "QueueArn": "arn:aws:sqs:us-east-1:111111111111:q1",
                            "Policy": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": "*",
                                        "Action": "sqs:ReceiveMessage",
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestMSG006:
    def test_fail_unencrypted_queue(self):
        r = check_msg_006(
            {
                "sqs-queues": {
                    "items": [
                        {
                            "QueueArn": "arn:aws:sqs:us-east-1:111111111111:q1",
                            "KmsMasterKeyId": None,
                            "SqsManagedSseEnabled": "false",
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestMSG007:
    def test_fail_wildcard_subscribe(self):
        r = check_msg_007(
            {
                "sns-topics": {
                    "items": [
                        {
                            "TopicArn": "arn:aws:sns:us-east-1:111111111111:t1",
                            "Attributes": {
                                "Policy": {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Principal": "*",
                                            "Action": "sns:Subscribe",
                                        }
                                    ]
                                }
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestMSG008:
    def test_fail_wildcard_publish(self):
        r = check_msg_008(
            {
                "sns-topics": {
                    "items": [
                        {
                            "TopicArn": "arn:aws:sns:us-east-1:111111111111:t1",
                            "Attributes": {
                                "Policy": {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Principal": "*",
                                            "Action": "sns:Publish",
                                        }
                                    ]
                                }
                            },
                        }
                    ]
                }
            }
        )
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
        r = check_cicd_002(
            {"codebuild-projects": {"items": [{"name": "proj", "source": {"insecureSsl": False}}]}}
        )
        assert r.status == "PASS"

    def test_fail_insecure_ssl(self):
        r = check_cicd_002(
            {
                "codebuild-projects": {
                    "items": [{"name": "proj", "arn": "arn:...", "source": {"insecureSsl": True}}]
                }
            }
        )
        assert r.status == "FAIL"


# ============================================================================
# COMPUTE CHECKS
# ============================================================================


class TestCompEKS001:
    def test_pass_no_public_endpoint(self):
        r = check_comp_eks_001(
            {
                "eks-inventory": {
                    "clusters": [
                        {"name": "prod", "resourcesVpcConfig": {"endpointPublicAccess": False}}
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_public_endpoint(self):
        r = check_comp_eks_001(
            {
                "eks-inventory": {
                    "clusters": [
                        {
                            "name": "prod",
                            "arn": "arn:...",
                            "resourcesVpcConfig": {"endpointPublicAccess": True},
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestCompEKS002:
    def test_pass_all_log_types(self):
        r = check_comp_eks_002(
            {
                "eks-inventory": {
                    "clusters": [
                        {
                            "name": "prod",
                            "logging": {
                                "clusterLogging": [
                                    {
                                        "enabled": True,
                                        "types": [
                                            "api",
                                            "audit",
                                            "authenticator",
                                            "controllerManager",
                                            "scheduler",
                                        ],
                                    }
                                ]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_missing_log_types(self):
        r = check_comp_eks_002(
            {
                "eks-inventory": {
                    "clusters": [
                        {
                            "name": "prod",
                            "arn": "arn:...",
                            "logging": {
                                "clusterLogging": [{"enabled": True, "types": ["api", "audit"]}]
                            },
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestCompECS002:
    def test_pass_pinned_images(self):
        r = check_comp_ecs_002(
            {
                "ecs-inventory": {
                    "task_definitions": [
                        {
                            "taskDefinitionArn": "arn:...",
                            "containerDefinitions": [
                                {"image": "123.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc123"}
                            ],
                        }
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_latest_tag(self):
        r = check_comp_ecs_002(
            {
                "ecs-inventory": {
                    "task_definitions": [
                        {
                            "taskDefinitionArn": "arn:...",
                            "containerDefinitions": [{"image": "nginx:latest"}],
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestCompECS003:
    def test_pass_awslogs(self):
        r = check_comp_ecs_003(
            {
                "ecs-inventory": {
                    "task_definitions": [
                        {"containerDefinitions": [{"logConfiguration": {"logDriver": "awslogs"}}]}
                    ]
                }
            }
        )
        assert r.status == "PASS"

    def test_fail_no_logging(self):
        r = check_comp_ecs_003(
            {
                "ecs-inventory": {
                    "task_definitions": [
                        {"taskDefinitionArn": "arn:...", "containerDefinitions": [{"name": "app"}]}
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestCompEC2001:
    def test_fail_imdsv1_with_instance_profile(self):
        r = check_comp_ec2_001(
            {
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
        )
        assert r.status == "FAIL"


class TestCompEC2002:
    def test_fail_userdata_secret_or_remote_bootstrap(self):
        r = check_comp_ec2_002(
            {
                "ec2-inventory": {
                    "instances": [
                        {
                            "InstanceId": "i-abc",
                            "ContainsSecrets": {"password": True},
                            "HasRemoteBootstrap": False,
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestCompLMB001:
    def test_fail_lambda_url_auth_none(self):
        r = check_comp_lmb_001(
            {
                "lambda-inventory": {
                    "functions": [
                        {
                            "FunctionArn": "arn:aws:lambda:us-east-1:111:function:fn-a",
                            "FunctionUrl": "https://abc.lambda-url.us-east-1.on.aws/",
                            "AuthType": "NONE",
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


class TestCompLMB002:
    def test_fail_lambda_role_admin_policy(self):
        r = check_comp_lmb_002(
            {
                "lambda-inventory": {
                    "functions": [
                        {
                            "FunctionArn": "arn:aws:lambda:us-east-1:111:function:fn-a",
                            "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}],
                        }
                    ]
                }
            }
        )
        assert r.status == "FAIL"


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestRunPreChecks:
    def test_iam_full_run(self):
        evidence = {
            "account-summary": {
                "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
            },
            "users": [{"UserName": "alice", "Groups": [{"GroupName": "dev"}], "AccessKeys": []}],
            "policies": [],
            "roles": [],
        }
        checklist = {
            "items": [
                {"id": "IAM-001", "severity": "Critical"},
                {"id": "IAM-009", "severity": "Critical"},
            ]
        }
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
        checklist = {
            "items": [
                {"id": "IAM-001", "severity": "Critical"},
                {"id": "IAM-009", "severity": "Critical"},
            ]
        }
        xml = format_pre_checks_for_prompt(checks, checklist)
        assert "<pre_computed_facts>" in xml
        assert 'id="IAM-001"' in xml
        assert 'status="PASS"' in xml
        assert 'id="IAM-009"' in xml
        assert 'status="FAIL"' in xml
        assert "arn:aws:iam::*:root" in xml
        assert "</pre_computed_facts>" in xml

    def test_skip_instruction_present(self):
        """SKIP items should carry a 'DO NOT generate a finding' instruction."""
        xml = format_pre_checks_for_prompt([])
        # empty returns ""
        assert xml == ""

        checks = [
            PreCheckResult("ALRT-004", "SKIP", "no security-relevant EventBridge rules found")
        ]
        xml = format_pre_checks_for_prompt(checks)
        assert 'status="SKIP"' in xml
        # The instruction for SKIP must explicitly tell the LLM to not generate a finding
        assert "SKIP" in xml
        assert "DO NOT generate a finding" in xml or "not applicable" in xml

    def test_skip_status_in_xml(self):
        """SKIP status should appear in the fact element."""
        checks = [PreCheckResult("ALRT-025", "SKIP", "no eventbridge-rules evidence")]
        xml = format_pre_checks_for_prompt(checks)
        assert 'id="ALRT-025"' in xml
        assert 'status="SKIP"' in xml


class TestIAM040SCPs:
    """Tests for IAM-040 SCP/Organizations pre-check."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_iam_040

        return check_iam_040(evidence)

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "IAM-040"
        assert result.status == "SKIP"

    def test_skip_with_api_error(self):
        result = self._run(
            {
                "effective-scps": {
                    "service_control_policies": [],
                    "error": "AWSOrganizationsNotInUseException: Account is not a member of an organization.",
                }
            }
        )
        assert result.status == "SKIP"

    def test_skip_empty_scps_no_error(self):
        result = self._run(
            {
                "effective-scps": {
                    "service_control_policies": [],
                    "error": None,
                }
            }
        )
        assert result.status == "SKIP"

    def test_fail_only_fullawsaccess(self):
        """Only AWS-managed FullAWSAccess SCP — no Deny statements."""
        result = self._run(
            {
                "effective-scps": {
                    "service_control_policies": [
                        {
                            "PolicyId": "p-FullAWSAccess",
                            "Name": "FullAWSAccess",
                            "AwsManaged": True,
                            "PolicyDocument": {
                                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                            },
                            "Targets": [],
                        }
                    ],
                    "error": None,
                }
            }
        )
        assert result.status == "FAIL"
        assert "FullAWSAccess" in result.evidence_summary

    def test_fail_custom_scp_allow_only(self):
        """Custom SCP with only Allow statements — still no Deny guardrails."""
        result = self._run(
            {
                "effective-scps": {
                    "service_control_policies": [
                        {
                            "PolicyId": "p-custom",
                            "Name": "AllowAll",
                            "AwsManaged": False,
                            "PolicyDocument": {
                                "Statement": [
                                    {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                                ]
                            },
                            "Targets": [],
                        }
                    ],
                    "error": None,
                }
            }
        )
        assert result.status == "FAIL"

    def test_pass_custom_scp_with_deny(self):
        """Custom SCP with a Deny statement — org-level guardrail present."""
        result = self._run(
            {
                "effective-scps": {
                    "service_control_policies": [
                        {
                            "PolicyId": "p-deny-root",
                            "Name": "DenyRootUsage",
                            "AwsManaged": False,
                            "PolicyDocument": {
                                "Statement": [
                                    {
                                        "Effect": "Deny",
                                        "Action": "*",
                                        "Resource": "*",
                                        "Condition": {
                                            "StringLike": {
                                                "aws:PrincipalArn": "arn:aws:iam::*:root"
                                            }
                                        },
                                    }
                                ]
                            },
                            "Targets": [{"TargetId": "123456789012", "Type": "ACCOUNT"}],
                        }
                    ],
                    "error": None,
                }
            }
        )
        assert result.status == "PASS"
        assert (
            "custom SCP" in result.evidence_summary.lower()
            or "deny" in result.evidence_summary.lower()
        )

    def test_pass_mixed_scps_one_has_deny(self):
        """Mixed SCPs: AWS-managed Allow + custom Deny → PASS."""
        result = self._run(
            {
                "effective-scps": {
                    "service_control_policies": [
                        {
                            "PolicyId": "p-aws",
                            "Name": "FullAWSAccess",
                            "AwsManaged": True,
                            "PolicyDocument": {
                                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                            },
                            "Targets": [],
                        },
                        {
                            "PolicyId": "p-deny-ct",
                            "Name": "DenyCloudTrailDisable",
                            "AwsManaged": False,
                            "PolicyDocument": {
                                "Statement": [
                                    {
                                        "Effect": "Deny",
                                        "Action": ["cloudtrail:StopLogging"],
                                        "Resource": "*",
                                    }
                                ]
                            },
                            "Targets": [],
                        },
                    ],
                    "error": None,
                }
            }
        )
        assert result.status == "PASS"


class TestExploitabilityStatus:
    """Tests for exploitability_status field on Finding model."""

    def test_finding_accepts_validated(self):
        from drystone.models.findings import Finding

        f = Finding(
            id="IAM-001",
            severity="Critical",
            risk_score=9.0,
            title="Root without MFA",
            description="Root account has no MFA.",
            remediation="Enable MFA.",
            exploitability_status="validated",
        )
        assert f.exploitability_status == "validated"

    def test_finding_accepts_probable(self):
        from drystone.models.findings import Finding

        f = Finding(
            id="IAM-002",
            severity="High",
            risk_score=7.0,
            title="No MFA on user",
            description="User has no MFA.",
            remediation="Enable MFA.",
            exploitability_status="probable",
        )
        assert f.exploitability_status == "probable"

    def test_finding_defaults_to_none(self):
        from drystone.models.findings import Finding

        f = Finding(
            id="IAM-003",
            severity="Medium",
            risk_score=4.5,
            title="Weak password policy",
            description="Policy too weak.",
            remediation="Strengthen policy.",
        )
        assert f.exploitability_status is None

    def test_finding_rejects_invalid_status(self):
        from drystone.models.findings import Finding

        with pytest.raises(Exception):
            Finding(
                id="IAM-001",
                severity="Critical",
                risk_score=9.0,
                title="t",
                description="d",
                remediation="r",
                exploitability_status="unknown_value",
            )

    def test_model_dump_includes_status(self):
        from drystone.models.findings import Finding

        f = Finding(
            id="IAM-001",
            severity="Critical",
            risk_score=9.0,
            title="t",
            description="d",
            remediation="r",
            exploitability_status="theoretical",
        )
        dumped = f.model_dump(mode="json")
        assert dumped["exploitability_status"] == "theoretical"


class TestVULN029ECSTaskSecrets:
    """Tests for VULN-029: ECS task definitions with hardcoded secrets in env vars."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_vuln_029

        return check_vuln_029(evidence)

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "VULN-029"
        assert result.status == "SKIP"

    def test_skip_access_denied(self):
        result = self._run(
            {
                "ecs-task-env-secrets": {
                    "items": [],
                    "error": "AccessDeniedException: User is not authorized to perform ecs:ListTaskDefinitions",
                }
            }
        )
        assert result.status == "SKIP"

    def test_skip_empty_items(self):
        result = self._run({"ecs-task-env-secrets": {"items": [], "error": None}})
        assert result.status == "SKIP"

    def test_pass_no_sensitive_vars(self):
        result = self._run(
            {
                "ecs-task-env-secrets": {
                    "items": [
                        {
                            "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789:task-definition/web:5",
                            "Family": "web",
                            "Revision": 5,
                            "HasSensitiveEnvVars": False,
                            "ExposedContainers": [],
                        }
                    ],
                    "error": None,
                }
            }
        )
        assert result.status == "PASS"

    def test_fail_sensitive_env_key_detected(self):
        result = self._run(
            {
                "ecs-task-env-secrets": {
                    "items": [
                        {
                            "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789:task-definition/api:3",
                            "Family": "api",
                            "Revision": 3,
                            "HasSensitiveEnvVars": True,
                            "ExposedContainers": [
                                {
                                    "ContainerName": "api",
                                    "SensitiveEnvKeys": ["DB_PASSWORD", "API_SECRET"],
                                    "UsesSecretsManagerRefs": False,
                                }
                            ],
                        }
                    ],
                    "error": None,
                }
            }
        )
        assert result.status == "FAIL"
        assert "VULN-029" == result.check_id
        assert len(result.affected_resources) == 1
        assert "api:3" in result.affected_resources[0]

    def test_fail_multiple_task_definitions(self):
        result = self._run(
            {
                "ecs-task-env-secrets": {
                    "items": [
                        {
                            "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/svc-a:1",
                            "HasSensitiveEnvVars": True,
                            "ExposedContainers": [
                                {
                                    "ContainerName": "a",
                                    "SensitiveEnvKeys": ["DB_PASSWORD"],
                                    "UsesSecretsManagerRefs": False,
                                }
                            ],
                        },
                        {
                            "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/svc-b:2",
                            "HasSensitiveEnvVars": False,
                            "ExposedContainers": [],
                        },
                        {
                            "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/svc-c:3",
                            "HasSensitiveEnvVars": True,
                            "ExposedContainers": [
                                {
                                    "ContainerName": "c",
                                    "SensitiveEnvKeys": ["API_TOKEN"],
                                    "UsesSecretsManagerRefs": False,
                                }
                            ],
                        },
                    ],
                    "error": None,
                }
            }
        )
        assert result.status == "FAIL"
        assert len(result.affected_resources) == 2


class TestIAM041AdminRoles:
    """Tests for IAM-041: Roles with AdministratorAccess or PowerUserAccess."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_iam_041

        return check_iam_041(evidence)

    def _make_role(self, name, attached_arns=None, inline=None, trusted_by=None):
        trust_stmts = []
        if trusted_by:
            trust_stmts.append(
                {"Principal": {"AWS": trusted_by}, "Effect": "Allow", "Action": "sts:AssumeRole"}
            )
        return {
            "RoleName": name,
            "AttachedPolicies": [
                {"PolicyName": a.split("/")[-1], "PolicyArn": a} for a in (attached_arns or [])
            ],
            "InlinePolicies": inline or {},
            "AssumeRolePolicyDocument": {"Statement": trust_stmts},
        }

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "IAM-041"
        assert result.status == "SKIP"

    def test_pass_no_admin_roles(self):
        evidence = {
            "roles": [
                self._make_role("read-only", ["arn:aws:iam::aws:policy/ReadOnlyAccess"]),
                self._make_role("s3-writer", ["arn:aws:iam::aws:policy/AmazonS3FullAccess"]),
            ]
        }
        result = self._run(evidence)
        assert result.status == "PASS"

    def test_fail_administrator_access(self):
        evidence = {
            "roles": [
                self._make_role(
                    "ops-admin",
                    ["arn:aws:iam::aws:policy/AdministratorAccess"],
                    trusted_by="arn:aws:iam::123456789012:user/deploy-bot",
                )
            ]
        }
        result = self._run(evidence)
        assert result.status == "FAIL"
        assert len(result.affected_resources) == 1
        assert "ops-admin" in result.affected_resources[0]

    def test_fail_power_user_access(self):
        evidence = {
            "roles": [self._make_role("power-role", ["arn:aws:iam::aws:policy/PowerUserAccess"])]
        }
        result = self._run(evidence)
        assert result.status == "FAIL"
        assert "power-role" in result.affected_resources[0]

    def test_fail_multiple_admin_roles(self):
        evidence = {
            "roles": [
                self._make_role("admin-a", ["arn:aws:iam::aws:policy/AdministratorAccess"]),
                self._make_role("admin-b", ["arn:aws:iam::aws:policy/PowerUserAccess"]),
                self._make_role("safe-role", ["arn:aws:iam::aws:policy/ReadOnlyAccess"]),
            ]
        }
        result = self._run(evidence)
        assert result.status == "FAIL"
        assert len(result.affected_resources) == 2

    def test_fail_trust_context_included(self):
        """Trust principal should appear in affected resource label for context."""
        evidence = {
            "roles": [
                self._make_role(
                    "cicd-role",
                    ["arn:aws:iam::aws:policy/AdministratorAccess"],
                    trusted_by="arn:aws:iam::123456789012:root",
                )
            ]
        }
        result = self._run(evidence)
        assert result.status == "FAIL"
        # Label should reference the trust principal
        assert "trusted by" in result.affected_resources[0]

    def test_pass_empty_roles_list(self):
        result = self._run({"roles": []})
        assert result.status == "SKIP"


class TestPentestPresetSecretsmgr:
    """Tests for GAP-007: secretsmanager included in pentest preset."""

    def test_pentest_skill_expands_to_include_secretsmanager(self):
        from drystone.models.config import WizardConfig

        config = WizardConfig(
            client_name="TestClient",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            skills=["pentest"],
        )
        assert "secretsmanager" in config.skills

    def test_pentest_preset_full_list(self):
        from drystone.models.config import WizardConfig

        config = WizardConfig(
            client_name="TestClient",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            skills=["pentest"],
        )
        expected = ["recon", "iam", "exposure", "network", "vulns", "secretsmanager"]
        assert config.skills == expected


class TestIAM043ConfusedDeputy:
    """Tests for IAM-043: Service trust policies vulnerable to Confused Deputy."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_iam_043

        return check_iam_043(evidence)

    def _make_role(self, name, service_principal, conditions=None):
        stmt = {
            "Effect": "Allow",
            "Principal": {"Service": service_principal},
            "Action": "sts:AssumeRole",
        }
        if conditions:
            stmt["Condition"] = conditions
        return {
            "RoleName": name,
            "Arn": f"arn:aws:iam::123456789012:role/{name}",
            "AssumeRolePolicyDocument": {"Statement": [stmt]},
            "AttachedPolicies": [],
        }

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "IAM-043"
        assert result.status == "SKIP"

    def test_pass_no_service_principals(self):
        """Roles with only AWS principals (not services) should pass."""
        result = self._run(
            {
                "roles": [
                    {
                        "RoleName": "cross-account",
                        "Arn": "arn:aws:iam::123:role/cross",
                        "AssumeRolePolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::999:root"},
                                    "Action": "sts:AssumeRole",
                                }
                            ]
                        },
                        "AttachedPolicies": [],
                    }
                ]
            }
        )
        assert result.status == "PASS"

    def test_pass_excluded_service(self):
        """ec2.amazonaws.com is excluded by design."""
        result = self._run({"roles": [self._make_role("ec2-role", "ec2.amazonaws.com")]})
        assert result.status == "PASS"

    def test_pass_ecs_tasks_excluded(self):
        """ecs-tasks.amazonaws.com is excluded by design."""
        result = self._run({"roles": [self._make_role("ecs-role", "ecs-tasks.amazonaws.com")]})
        assert result.status == "PASS"

    def test_fail_lambda_no_source_condition(self):
        """Lambda service principal without SourceAccount → FAIL."""
        result = self._run({"roles": [self._make_role("lambda-role", "lambda.amazonaws.com")]})
        assert result.status == "FAIL"
        assert "lambda-role" in result.affected_resources[0]

    def test_pass_lambda_with_source_account(self):
        result = self._run(
            {
                "roles": [
                    self._make_role(
                        "lambda-scoped",
                        "lambda.amazonaws.com",
                        conditions={"StringEquals": {"aws:SourceAccount": "123456789012"}},
                    )
                ]
            }
        )
        assert result.status == "PASS"

    def test_pass_lambda_with_source_arn(self):
        result = self._run(
            {
                "roles": [
                    self._make_role(
                        "lambda-scoped",
                        "lambda.amazonaws.com",
                        conditions={
                            "ArnLike": {"aws:SourceArn": "arn:aws:lambda:us-east-1:123:function:*"}
                        },
                    )
                ]
            }
        )
        assert result.status == "PASS"

    def test_fail_glue_no_condition(self):
        result = self._run({"roles": [self._make_role("glue-role", "glue.amazonaws.com")]})
        assert result.status == "FAIL"

    def test_fail_multiple_roles(self):
        result = self._run(
            {
                "roles": [
                    self._make_role("lambda-role", "lambda.amazonaws.com"),
                    self._make_role("glue-role", "glue.amazonaws.com"),
                    # This one is safe
                    self._make_role(
                        "safe-role",
                        "sns.amazonaws.com",
                        conditions={"StringEquals": {"aws:SourceAccount": "123456789012"}},
                    ),
                ]
            }
        )
        assert result.status == "FAIL"
        assert len(result.affected_resources) == 2


class TestIAM042PrivEscalation:
    """Tests for IAM-042: Privilege escalation paths without MFA condition."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_iam_042

        return check_iam_042(evidence)

    def _make_policy(self, name, action, resource="*", effect="Allow", conditions=None):
        stmt = {"Effect": effect, "Action": action, "Resource": resource}
        if conditions:
            stmt["Condition"] = conditions
        return {
            "Arn": f"arn:aws:iam::123456789012:policy/{name}",
            "PolicyName": name,
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [stmt]},
        }

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "IAM-042"
        assert result.status == "SKIP"

    def test_pass_no_escalation_perms(self):
        result = self._run({"policies": [self._make_policy("read-only", "s3:GetObject")]})
        assert result.status == "PASS"

    def test_pass_aws_managed_policy_skipped(self):
        """AWS-managed policies should be skipped (we can't change them)."""
        pol = {
            "Arn": "arn:aws:iam::aws:policy/PowerUserAccess",
            "PolicyName": "PowerUserAccess",
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        }
        result = self._run({"policies": [pol]})
        assert result.status == "PASS"

    def test_fail_create_access_key_no_mfa(self):
        result = self._run(
            {"policies": [self._make_policy("dangerous", "iam:CreateAccessKey", resource="*")]}
        )
        assert result.status == "FAIL"
        assert "iam:createaccesskey" in result.affected_resources[0]

    def test_fail_attach_role_policy_no_mfa(self):
        result = self._run(
            {"policies": [self._make_policy("attacher", "iam:AttachRolePolicy", resource="*")]}
        )
        assert result.status == "FAIL"

    def test_pass_create_access_key_with_mfa(self):
        result = self._run(
            {
                "policies": [
                    self._make_policy(
                        "mfa-guarded",
                        "iam:CreateAccessKey",
                        conditions={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    )
                ]
            }
        )
        assert result.status == "PASS"

    def test_pass_scoped_resource_not_broad(self):
        """Scoped resource (not *) should not trigger even without MFA."""
        result = self._run(
            {
                "policies": [
                    self._make_policy(
                        "scoped",
                        "iam:CreateAccessKey",
                        resource="arn:aws:iam::123456789012:user/specific-user",
                    )
                ]
            }
        )
        assert result.status == "PASS"

    def test_fail_iam_wildcard_no_mfa(self):
        result = self._run({"policies": [self._make_policy("iam-all", "iam:*", resource="*")]})
        assert result.status == "FAIL"

    def test_fail_passrole_no_mfa(self):
        result = self._run(
            {"policies": [self._make_policy("passer", "iam:PassRole", resource="*")]}
        )
        assert result.status == "FAIL"


class TestEXP023ResourceBasedPolicies:
    """Tests for EXP-023: Resource-based policies with unrestricted Principal:*."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_exp_023

        return check_exp_023(evidence)

    def _make_item(self, service, arn, principal, conditions=None):
        stmt = {"Effect": "Allow", "Principal": principal, "Action": "*"}
        if conditions:
            stmt["Condition"] = conditions
        import json

        return {
            "Service": service,
            "ResourceArn": arn,
            "ResourceId": arn.split(":")[-1],
            "Policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]}),
        }

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "EXP-023"
        assert result.status == "SKIP"

    def test_pass_empty_items(self):
        result = self._run({"resource-based-policies": {"items": []}})
        assert result.status == "PASS"

    def test_pass_scoped_principal(self):
        """Principal with specific account ARN should pass."""
        result = self._run(
            {
                "resource-based-policies": {
                    "items": [
                        self._make_item(
                            "sqs",
                            "arn:aws:sqs:us-east-1:123:myqueue",
                            "arn:aws:iam::456789012345:root",
                        )
                    ]
                }
            }
        )
        assert result.status == "PASS"

    def test_fail_sqs_open_principal_string(self):
        """Principal: '*' (string) without condition → FAIL."""
        result = self._run(
            {
                "resource-based-policies": {
                    "items": [self._make_item("sqs", "arn:aws:sqs:us-east-1:123:myqueue", "*")]
                }
            }
        )
        assert result.status == "FAIL"
        assert "sqs" in result.affected_resources[0]

    def test_fail_sqs_open_principal_aws_dict(self):
        """Principal: {AWS: '*'} without condition → FAIL."""
        result = self._run(
            {
                "resource-based-policies": {
                    "items": [
                        self._make_item("sns", "arn:aws:sns:us-east-1:123:mytopic", {"AWS": "*"})
                    ]
                }
            }
        )
        assert result.status == "FAIL"

    def test_pass_open_principal_with_source_account(self):
        """Principal:* with aws:SourceAccount condition → PASS."""
        result = self._run(
            {
                "resource-based-policies": {
                    "items": [
                        self._make_item(
                            "secretsmanager",
                            "arn:aws:secretsmanager:us-east-1:123:secret:foo",
                            "*",
                            conditions={"StringEquals": {"aws:SourceAccount": "123456789012"}},
                        )
                    ]
                }
            }
        )
        assert result.status == "PASS"

    def test_pass_open_principal_with_vpc_condition(self):
        result = self._run(
            {
                "resource-based-policies": {
                    "items": [
                        self._make_item(
                            "sqs",
                            "arn:aws:sqs:us-east-1:123:queue",
                            "*",
                            conditions={"StringEquals": {"aws:SourceVpc": "vpc-12345678"}},
                        )
                    ]
                }
            }
        )
        assert result.status == "PASS"

    def test_fail_multiple_open_resources(self):
        result = self._run(
            {
                "resource-based-policies": {
                    "items": [
                        self._make_item("sqs", "arn:aws:sqs:us-east-1:123:q1", "*"),
                        self._make_item("sns", "arn:aws:sns:us-east-1:123:t1", {"AWS": "*"}),
                        # This one is safe
                        self._make_item(
                            "ecr",
                            "arn:aws:ecr:us-east-1:123:repo/safe",
                            "*",
                            conditions={"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
                        ),
                    ]
                }
            }
        )
        assert result.status == "FAIL"
        assert len(result.affected_resources) == 2


class TestVULN026TerraformState:
    """Tests for VULN-026: Terraform state files with secrets in S3."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_vuln_026

        return check_vuln_026(evidence)

    def _make_item(
        self, bucket, tf_objects=None, has_suspicious=False, patterns=None, access_error=None
    ):
        return {
            "BucketName": bucket,
            "IsTerraformCandidate": True,
            "TfstateObjects": tf_objects or [],
            "HasSuspiciousContent": has_suspicious,
            "MatchedPatterns": patterns or [],
            "AccessError": access_error,
        }

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "VULN-026"
        assert result.status == "SKIP"

    def test_skip_access_denied(self):
        result = self._run(
            {
                "terraform-state-scan": {
                    "items": [],
                    "error": "AccessDenied: User is not authorized to perform s3:ListBuckets",
                }
            }
        )
        assert result.status == "SKIP"

    def test_pass_no_candidates(self):
        result = self._run({"terraform-state-scan": {"items": [], "error": None}})
        assert result.status == "PASS"

    def test_pass_candidate_no_tfstate(self):
        """Terraform-named bucket but no .tfstate objects found."""
        result = self._run(
            {
                "terraform-state-scan": {
                    "items": [
                        self._make_item("terraform-state-prod", tf_objects=[], has_suspicious=False)
                    ]
                }
            }
        )
        assert result.status == "PASS"

    def test_fail_confirmed_secrets(self):
        result = self._run(
            {
                "terraform-state-scan": {
                    "items": [
                        self._make_item(
                            "myorg-tfstate",
                            tf_objects=[
                                {
                                    "Key": "prod/terraform.tfstate",
                                    "SizeBytes": 512000,
                                    "Patterns": ['"secret_string"'],
                                }
                            ],
                            has_suspicious=True,
                            patterns=['"secret_string"\\s*:\\s*"[^"]{8,}"'],
                        )
                    ]
                }
            }
        )
        assert result.status == "FAIL"
        assert "myorg-tfstate" in result.affected_resources[0]

    def test_fail_access_denied_on_candidate(self):
        """Candidate found but content unreadable → flag for manual review."""
        result = self._run(
            {
                "terraform-state-scan": {
                    "items": [
                        self._make_item(
                            "terraform-infra-state",
                            access_error="AccessDenied listing terraform-infra-state",
                        )
                    ]
                }
            }
        )
        assert result.status == "FAIL"
        assert "terraform-infra-state" in result.affected_resources[0]

    def test_fail_multiple_secrets_buckets(self):
        result = self._run(
            {
                "terraform-state-scan": {
                    "items": [
                        self._make_item(
                            "tf-state-prod", has_suspicious=True, patterns=['"password"']
                        ),
                        self._make_item(
                            "tf-state-dev", has_suspicious=True, patterns=['"private_key"']
                        ),
                        self._make_item("tf-state-staging", tf_objects=[], has_suspicious=False),
                    ]
                }
            }
        )
        assert result.status == "FAIL"
        assert len(result.affected_resources) == 2


class TestEXP024S3KMSEncryption:
    """Tests for EXP-024: S3 audit/log buckets without KMS encryption."""

    def _run(self, evidence):
        from drystone.validation.pre_checks import check_exp_024

        return check_exp_024(evidence)

    def _make_bucket(self, name, algorithm):
        return {"Name": name, "EncryptionAlgorithm": algorithm, "KMSMasterKeyID": None}

    def test_skip_no_evidence(self):
        result = self._run({})
        assert result.check_id == "EXP-024"
        assert result.status == "SKIP"

    def test_pass_all_kms(self):
        result = self._run(
            {
                "s3-buckets": {
                    "items": [
                        self._make_bucket("cloudtrail-logs", "aws:kms"),
                        self._make_bucket("app-data", "aws:kms"),
                    ]
                }
            }
        )
        assert result.status == "PASS"

    def test_pass_aes256_non_audit_bucket(self):
        """Non-audit bucket with AES256 is acceptable."""
        result = self._run(
            {
                "s3-buckets": {
                    "items": [
                        self._make_bucket("my-app-assets", "AES256"),
                        self._make_bucket("static-website", "AES256"),
                    ]
                }
            }
        )
        assert result.status == "PASS"

    def test_fail_no_encryption(self):
        """Any bucket with no encryption → FAIL."""
        result = self._run(
            {
                "s3-buckets": {
                    "items": [
                        self._make_bucket("old-bucket", None),
                    ]
                }
            }
        )
        assert result.status == "FAIL"
        assert "old-bucket" in result.affected_resources

    def test_fail_audit_bucket_aes256(self):
        """Audit/log bucket with AES256 (not KMS) → FAIL."""
        result = self._run(
            {
                "s3-buckets": {
                    "items": [
                        self._make_bucket("cloudtrail-logs-prod", "AES256"),
                    ]
                }
            }
        )
        assert result.status == "FAIL"
        assert "cloudtrail-logs-prod" in result.affected_resources

    def test_fail_mixed_buckets(self):
        """No encryption + AES256 audit buckets both flagged."""
        result = self._run(
            {
                "s3-buckets": {
                    "items": [
                        self._make_bucket("cloudtrail-prod", "AES256"),  # audit + AES256
                        self._make_bucket("legacy-bucket", None),  # no encryption
                        self._make_bucket("app-config-s3", "aws:kms"),  # compliant
                        self._make_bucket("audit-archive", "AES256"),  # audit + AES256
                    ]
                }
            }
        )
        assert result.status == "FAIL"
        # legacy-bucket (no enc) + cloudtrail-prod + audit-archive
        assert len(result.affected_resources) == 3

    def test_audit_pattern_matching(self):
        """Ensure various audit bucket name patterns are detected."""
        audit_names = [
            "audit-logs",
            "vpc-flow-logs",
            "config-snapshots",
            "security-events",
            "siem-bucket",
            "access-log-archive",
        ]
        result = self._run(
            {"s3-buckets": {"items": [self._make_bucket(name, "AES256") for name in audit_names]}}
        )
        assert result.status == "FAIL"
        assert len(result.affected_resources) == len(audit_names)
