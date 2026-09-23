"""Tests for PCI DSS CLI query resolution and IAM P1 coverage."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from drystone.reports import pci_cli_queries
from drystone.reports.pci_cli_queries import CliQuery, OutputSpec, resolve_query
from drystone.reports.pci_text_table import apply_output_spec

EXPECTED_LAYER_1_STEMS = {
    "iam": {
        "account-summary",
        "account-aliases",
        "password-policy",
        "credential-report",
        "users",
        "groups",
        "roles",
        "policies",
        "assumeRole-chains",
        "resource-based-policies",
        "instance-profiles",
        "effective-scps",
    },
    "network": {
        "security-groups",
        "network-acls",
        "route-tables",
        "subnets",
        "vpcs",
        "ec2-instances",
        "network-interfaces",
        "rds-instances",
        "lambda-functions",
        "vpc-endpoints",
        "internet-gateways",
        "vpn-connections",
        "transit-gateway-topology",
        "nat-gateway-routes",
    },
    "exposure": {
        "s3-buckets",
        "rds-instances",
        "security-groups",
        "ami-images",
        "cloudfront-distributions",
        "load-balancers",
        "load-balancer-listeners",
        "wafv2-web-acls",
        "wafv2-web-acl-alb-associations",
        "lambda-function-urls",
        "api-gateway-stages",
        "api-gateway-routes",
        "ecs-eks-ingress",
        "elasticsearch-domains",
        "resource-based-policies",
    },
    "waf": {
        "cloudfront-distributions",
        "cloudfront-wafv2-associations",
        "cloudfront-classic-associations",
        "wafv2-web-acls",
        "wafv2-ip-sets",
        "wafv2-rule-groups",
        "wafv2-managed-rule-groups",
        "alb-waf-associations",
        "api-entrypoints-waf-associations",
        "waf-classic",
        "waf-collection-status",
    },
    "hardening": {
        "security-hub-status",
        "security-hub-findings",
        "security-hub-findings-summary",
        "security-hub-enabled-standards",
        "config-recorders",
        "config-delivery-channels",
        "config-recorder-status",
        "config-compliance",
        "config-compliance-summary",
        "config-conformance-packs",
        "config-conformance-pack-compliance",
        "acm-certificates",
        "guardduty-detectors",
        "macie-session",
        "macie-findings",
        "backup-vaults",
        "backup-plans",
        "backup-plans-detailed",
        "account-summary",
        "account-aliases",
        "password-policy",
        "hardening-collection-status",
    },
    "vulns": {
        "inspector-org-config",
        "inspector-findings",
        "ec2-patch-status",
        "patch-baselines",
        "rds-patch-info",
        "ecr-image-scans",
        "ec2-user-data",
        "lambda-environment-variables",
        "imds-configuration",
        "instance-profiles-permissions",
        "ebs-snapshot-sharing",
        "guardduty-status",
        "ecs-task-env-secrets",
        "terraform-state-scan",
    },
    "alerting": {
        "cloudtrail-trails",
        "cloudtrail-s3-notifications",
        "cloudtrail-log-subscriptions",
        "cloudwatch-log-groups",
        "cloudwatch-metric-filters",
        "cloudwatch-alarms",
        "eventbridge-rules",
        "sns-topics",
        "vpc-flow-logs",
        "config-rules",
    },
    "recon": {
        "route53-zones",
        "api-gateway-stages",
        "lambda-urls",
        "load-balancer-dns",
        "public-endpoints",
        "cloudfront-origins",
        "attack-surface-score",
    },
    "secretsmanager": {
        "secrets",
        "cloudwatch_alarms",
        "eventbridge_rules",
    },
    "kms": {
        "kms-keys",
        "kms-key-policies",
        "kms-grants",
        "kms-aliases",
        "kms-custom-key-stores",
    },
    "compute": {
        "ecs-inventory",
        "eventbridge-rules",
        "eks-inventory",
        "ec2-inventory",
        "lambda-inventory",
    },
}


def test_resolve_query_layer_2_wins_over_source_fallback(monkeypatch):
    source_output = OutputSpec(source="users", columns=(("User", "UserName"),))
    check_output = OutputSpec(source="credential-report", rows="rows", columns=(("user", "user"),))
    monkeypatch.setattr(pci_cli_queries, "SOURCE_QUERIES", {"iam": {"users": CliQuery(commands=("aws iam list-users",), output=source_output)}})
    monkeypatch.setattr(
        pci_cli_queries,
        "CHECK_QUERIES",
        {
            "IAM-002": CliQuery(
                commands=("aws iam get-credential-report",),
                output=check_output,
                evidence_name="IAM users MFA",
            )
        },
    )

    resolved = resolve_query("iam", "IAM-002", ["users"], {"title": "Checklist title"})

    assert resolved.layer == "check"
    assert resolved.commands == ("aws iam get-credential-report",)
    assert resolved.outputs == (check_output,)
    assert resolved.evidence_name == "IAM users MFA"


def test_resolve_query_layer_1_fallback_dedupes_in_consulted_order(monkeypatch):
    users_output = OutputSpec(source="users", columns=(("User", "UserName"),))
    monkeypatch.setattr(pci_cli_queries, "CHECK_QUERIES", {})
    monkeypatch.setattr(
        pci_cli_queries,
        "SOURCE_QUERIES",
        {
            "iam": {
                "users": CliQuery(commands=("aws iam list-users",), output=users_output),
                "credential-report": CliQuery(
                    commands=("aws iam list-users", "aws iam get-credential-report"),
                    output=OutputSpec(source="credential-report", rows="rows", columns=(("user", "user"),)),
                ),
            }
        },
    )

    resolved = resolve_query(
        "iam",
        "IAM-999",
        ["credential-report", "users", "credential-report"],
        {"title": "Fallback title"},
    )

    assert resolved.layer == "source"
    assert resolved.commands == ("aws iam list-users", "aws iam get-credential-report")
    assert [output.source for output in resolved.outputs] == ["credential-report", "users"]
    assert resolved.evidence_name == "Fallback title"


def test_resolve_query_returns_placeholder_when_no_recipe_exists(monkeypatch):
    monkeypatch.setattr(pci_cli_queries, "CHECK_QUERIES", {})
    monkeypatch.setattr(pci_cli_queries, "SOURCE_QUERIES", {"iam": {}})

    resolved = resolve_query("iam", "IAM-999", ["users", "unknown"], {"title": "Unknown"})

    assert resolved.layer == "placeholder"
    assert resolved.outputs == ()
    assert resolved.commands == (
        "# No AWS CLI equivalent catalogued yet for IAM-999 (evidence consulted: users, unknown)",
    )


def test_resolve_query_preserves_alternative_commands_as_data_structure(monkeypatch):
    monkeypatch.setattr(
        pci_cli_queries,
        "CHECK_QUERIES",
        {
            "IAM-002": CliQuery(
                commands=(
                    "aws iam get-credential-report --query Content",
                    "for user in $(aws iam list-users --query Users[].UserName --output text); do echo $user; done",
                ),
            )
        },
    )

    resolved = resolve_query("iam", "IAM-002", [], {"title": "MFA"})

    assert resolved.layer == "check"
    assert resolved.commands == (
        "aws iam get-credential-report --query Content",
        "for user in $(aws iam list-users --query Users[].UserName --output text); do echo $user; done",
    )


def test_complete_skills_contains_p1_p2_and_p3_catalogs():
    assert pci_cli_queries.COMPLETE_SKILLS == frozenset(
        {
            "iam",
            "network",
            "exposure",
            "waf",
            "hardening",
            "vulns",
            "alerting",
            "recon",
            "secretsmanager",
            "kms",
            "compute",
        }
    )


@pytest.mark.parametrize("skill, expected_stems", EXPECTED_LAYER_1_STEMS.items())
def test_complete_skills_have_layer_1_recipes_for_expected_stems(skill: str, expected_stems: set[str]):
    assert set(pci_cli_queries.SOURCE_QUERIES[skill]) == expected_stems


def test_iam_keeps_p1_layer_1_recipes_for_plan_stems():
    assert set(pci_cli_queries.SOURCE_QUERIES["iam"]) == EXPECTED_LAYER_1_STEMS["iam"]


@pytest.mark.parametrize("skill", sorted(pci_cli_queries.COMPLETE_SKILLS))
def test_every_complete_skill_checklist_item_with_pci_dss_has_layer_2_recipe(skill: str):
    checklist = json_load(Path(f"drystone/skills/{skill}/checklist.json"))
    pci_check_ids = {item["id"] for item in checklist["items"] if item.get("pci_dss")}

    assert pci_check_ids <= set(pci_cli_queries.CHECK_QUERIES)


def test_catalogued_aws_cli_operations_exist_in_botocore_models():
    botocore = pytest.importorskip("botocore.session")
    botocore_package = pytest.importorskip("botocore")
    session = botocore.get_session()
    aliases = {"s3api": "s3", "configservice": "config"}

    for service, operation in aws_operations_from_catalog():
        model = session.get_service_model(aliases.get(service, service))
        cli_operations = {botocore_package.xform_name(name).replace("_", "-") for name in model.operation_names}
        assert operation in cli_operations, f"aws {service} {operation}"


@pytest.mark.parametrize("skill", ["vulns", "alerting", "recon", "secretsmanager", "kms", "compute"])
def test_p3_source_query_output_specs_resolve_against_stored_evidence_shapes(skill: str):
    evidence = p3_minimal_stored_evidence()[skill]

    unresolved = [
        stem
        for stem, query in pci_cli_queries.SOURCE_QUERIES[skill].items()
        if query.output is not None and apply_output_spec(query.output, evidence) is None
    ]

    assert unresolved == []


def p3_minimal_stored_evidence() -> dict[str, dict[str, Any]]:
    return {
        "vulns": {
            "inspector-org-config": {"Status": "enabled"},
            "inspector-findings": [
                {
                    "findingArn": "arn:aws:inspector2:finding/1",
                    "severity": "HIGH",
                    "status": "ACTIVE",
                    "type": "PACKAGE_VULNERABILITY",
                    "title": "openssl vulnerable",
                    "resources": [{"id": "i-123"}],
                    "exploitAvailable": "NO",
                    "fixAvailable": "YES",
                }
            ],
            "ec2-patch-status": [
                {"InstanceId": "i-123", "Platform": "Linux", "State": "running", "SSMStatus": "Online", "PatchCompliance": "COMPLIANT"}
            ],
            "patch-baselines": [
                {
                    "BaselineId": "pb-123",
                    "BaselineName": "Default",
                    "OperatingSystemFamily": "AMAZON_LINUX_2",
                    "DefaultBaseline": True,
                    "Details": {"approved_patches": []},
                }
            ],
            "rds-patch-info": [
                {
                    "DBInstanceIdentifier": "db-1",
                    "Engine": "postgres",
                    "EngineVersion": "15.4",
                    "UpgradeAvailable": True,
                    "MinorUpgradeCount": 1,
                    "MajorUpgradeCount": 0,
                }
            ],
            "ecr-image-scans": [
                {
                    "RepositoryName": "repo",
                    "ImageId": {"imageDigest": "sha256:1"},
                    "ImageScanStatus": {"status": "COMPLETE"},
                    "ImageScanFindingsSummary": {"findingSeverityCounts": {}},
                    "ScanFindings": [],
                }
            ],
            "ec2-user-data": {"items": [{"InstanceId": "i-123", "UserData": "IyEvYmluL2Jhc2g="}]},
            "lambda-environment-variables": {"items": [{"FunctionName": "fn", "Environment": {"Variables": {"MODE": "test"}}}]},
            "imds-configuration": {"items": [{"InstanceId": "i-123", "MetadataOptions": {"HttpTokens": "required"}}]},
            "instance-profiles-permissions": {"items": [{"InstanceProfileName": "profile", "Roles": ["role"]}]},
            "ebs-snapshot-sharing": {"items": [{"SnapshotId": "snap-123", "CreateVolumePermissions": []}]},
            "guardduty-status": {
                "detectors": [
                    {
                        "DetectorId": "det-123",
                        "Status": "ENABLED",
                        "S3LogsEnabled": True,
                        "MalwareProtectionEnabled": True,
                        "KubernetesAuditLogsEnabled": False,
                        "AutoArchiveRuleCount": 0,
                    }
                ]
            },
            "ecs-task-env-secrets": {"items": [{"taskDefinitionArn": "td", "containerDefinitions": []}]},
            "terraform-state-scan": {"items": [{"bucket": "tf-state", "key": "state.tfstate", "sensitive_matches": []}]},
        },
        "alerting": {
            "cloudtrail-trails": [
                {
                    "Name": "trail",
                    "IsMultiRegionTrail": True,
                    "CloudWatchLogsLogGroupArn": "arn:aws:logs:group",
                    "KmsKeyId": "key",
                    "LogFileValidationEnabled": True,
                }
            ],
            "cloudtrail-s3-notifications": [
                {
                    "bucket_name": "trail-bucket",
                    "trail_name": "trail",
                    "lambda_configs": [],
                    "sqs_configs": [],
                    "sns_configs": [],
                    "error": None,
                }
            ],
            "cloudtrail-log-subscriptions": [
                {"log_group_name": "/aws/cloudtrail", "trail_name": "trail", "subscription_filters": [], "error": None}
            ],
            "cloudwatch-log-groups": [
                {"LogGroupName": "/aws/cloudtrail", "RetentionInDays": 365, "StoredBytes": 1, "Arn": "arn:aws:logs", "ResourcePolicies": []}
            ],
            "cloudwatch-metric-filters": [{"FilterName": "RootUsage", "LogGroupName": "/aws/cloudtrail", "FilterPattern": "$.userIdentity.type=Root"}],
            "cloudwatch-alarms": [
                {
                    "AlarmName": "RootUsage",
                    "MetricName": "RootUsage",
                    "Namespace": "CloudTrailMetrics",
                    "AlarmActions": ["arn:aws:sns:topic"],
                    "StateValue": "OK",
                    "Threshold": 1,
                }
            ],
            "eventbridge-rules": [{"Name": "iam-change", "EventPattern": {}, "ScheduleExpression": None, "Targets": []}],
            "sns-topics": [{"TopicArn": "arn:aws:sns:topic", "Policy": {}, "Subscriptions": []}],
            "vpc-flow-logs": [{"FlowLogId": "fl-123", "ResourceId": "vpc-123", "FlowLogStatus": "ACTIVE"}],
            "config-rules": [{"ConfigRuleName": "required-tags", "Source": {}, "Scope": {}}],
        },
        "recon": {
            "route53-zones": {
                "zones": [{"Id": "/hostedzone/Z1", "Name": "example.com.", "IsPrivate": False, "RecordCount": 2, "Records": [], "SensitivityAnalysis": {}}]
            },
            "api-gateway-stages": {"apis": [{"Id": "api", "Name": "api", "Type": "REST", "Stages": [], "UnauthenticatedRouteCount": 0}]},
            "lambda-urls": {
                "urls": [
                    {
                        "FunctionName": "fn",
                        "FunctionArn": "arn:aws:lambda:fn",
                        "FunctionUrl": "https://fn.lambda-url.aws",
                        "AuthType": "AWS_IAM",
                        "IsPublic": False,
                        "Cors": {},
                    }
                ]
            },
            "load-balancer-dns": {
                "load_balancers": [
                    {
                        "Name": "alb",
                        "DNSName": "alb.example.com",
                        "Scheme": "internet-facing",
                        "Type": "application",
                        "IsPublic": True,
                        "Listeners": [],
                        "WafWebAclArn": "arn:aws:wafv2:acl",
                    }
                ]
            },
            "public-endpoints": {"elastic_ips": [{"PublicIp": "203.0.113.10", "AssociatedWithInstance": True, "InstanceId": "i-123", "PermissiveSGRules": []}]},
            "cloudfront-origins": {
                "distributions": [
                    {
                        "Id": "dist",
                        "DomainName": "d111.cloudfront.net",
                        "Aliases": ["www.example.com"],
                        "Enabled": True,
                        "Origins": [],
                        "LoggingEnabled": True,
                        "WebAclId": "acl",
                    }
                ]
            },
            "attack-surface-score": {"score": 1, "public_endpoint_count": 1},
        },
        "secretsmanager": {
            "secrets": {
                "secrets": [
                    {
                        "Region": "us-east-1",
                        "Name": "secret",
                        "ARN": "arn:aws:secretsmanager:secret",
                        "KmsKeyId": "key",
                        "RotationEnabled": True,
                        "RotationRules": {"AutomaticallyAfterDays": 30},
                        "LastRotatedDate": "2026-01-01",
                        "LastAccessedDate": "2026-01-02",
                        "Tags": [],
                        "ResourcePolicy": {},
                        "ReplicationStatus": [],
                        "SecurityIssues": [],
                        "RiskScore": 0,
                    }
                ]
            },
            "cloudwatch_alarms": {"us-east-1": {"likely_relevant": []}},
            "eventbridge_rules": {"us-east-1": {"likely_relevant": []}},
        },
        "kms": {
            "kms-keys": {"items": [{"KeyId": "key", "KeyArn": "arn:aws:kms:key", "Metadata": {}, "KeyRotationEnabled": True}]},
            "kms-key-policies": {"items": [{"KeyId": "key", "PolicyName": "default", "Policy": {}}]},
            "kms-grants": {"items": [{"KeyId": "key", "GrantId": "grant", "GranteePrincipal": "arn:aws:iam::123:role/R", "Operations": ["Decrypt"]}]},
            "kms-aliases": {"items": [{"AliasName": "alias/app", "AliasArn": "arn:aws:kms:alias/app", "TargetKeyId": "key"}]},
            "kms-custom-key-stores": {"items": [{"CustomKeyStoreId": "cks", "CustomKeyStoreName": "store", "ConnectionState": "CONNECTED"}]},
        },
        "compute": {
            "ecs-inventory": {
                "task_definitions": [
                    {
                        "taskDefinitionArn": "arn:aws:ecs:task-definition/app:1",
                        "family": "app",
                        "taskRoleArn": "arn:aws:iam::123:role/task",
                        "executionRoleArn": "arn:aws:iam::123:role/execution",
                        "containerDefinitions": [],
                    }
                ]
            },
            "eventbridge-rules": {"rules": [{"Name": "schedule", "ScheduleExpression": "rate(1 day)", "State": "ENABLED", "Targets": []}]},
            "eks-inventory": {
                "clusters": [
                    {
                        "name": "cluster",
                        "arn": "arn:aws:eks:cluster",
                        "resourcesVpcConfig": {"endpointPublicAccess": False},
                        "logging": {},
                        "status": "ACTIVE",
                    }
                ]
            },
            "ec2-inventory": {
                "instances": [
                    {
                        "InstanceId": "i-123",
                        "IamInstanceProfile": {},
                        "MetadataOptions": {"HttpTokens": "required"},
                        "UserData": "IyEvYmluL2Jhc2g=",
                        "ContainsSecrets": False,
                        "HasRemoteBootstrap": False,
                    }
                ]
            },
            "lambda-inventory": {
                "functions": [
                    {
                        "FunctionName": "fn",
                        "FunctionArn": "arn:aws:lambda:fn",
                        "Role": "arn:aws:iam::123:role/lambda",
                        "FunctionUrl": "https://fn.lambda-url.aws",
                        "AuthType": "AWS_IAM",
                        "AttachedPolicies": [],
                    }
                ]
            },
        },
    }


def json_load(path: Path) -> dict[str, Any]:
    import json

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def aws_operations_from_catalog() -> set[tuple[str, str]]:
    operations: set[tuple[str, str]] = set()
    queries = [*pci_cli_queries.CHECK_QUERIES.values()]
    for source_queries in pci_cli_queries.SOURCE_QUERIES.values():
        queries.extend(source_queries.values())

    for query in queries:
        for command in query.commands:
            for raw_line in command.splitlines():
                line = raw_line.strip()
                if not line.startswith("aws "):
                    continue
                tokens = line.split()
                if len(tokens) >= 3:
                    operations.add((tokens[1], tokens[2]))
    return operations
