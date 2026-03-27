"""Evidence-based validation tests for Compute findings."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer

COMPUTE_CHECKLIST = {
    "skill": "compute",
    "items": [
        {"id": "COMP-EKS-001", "severity": "High"},
        {"id": "COMP-EKS-002", "severity": "Medium"},
        {"id": "COMP-ECS-001", "severity": "High"},
        {"id": "COMP-ECS-002", "severity": "Medium"},
        {"id": "COMP-ECS-003", "severity": "Medium"},
        {"id": "COMP-ECS-004", "severity": "High"},
    ],
}


def _finding(fid: str) -> Finding:
    sev = "High" if fid in {"COMP-EKS-001", "COMP-ECS-001", "COMP-ECS-004"} else "Medium"
    risk = 7.8 if sev == "High" else 4.2

    ref = "eks-inventory.json#/clusters/0"
    if fid == "COMP-ECS-001":
        ref = "eventbridge-rules.json#/rules/0"
    if fid in {"COMP-ECS-002", "COMP-ECS-003", "COMP-ECS-004"}:
        ref = "ecs-inventory.json#/task_definitions/0"
    return Finding(
        id=fid,
        severity=sev,
        risk_score=risk,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=[ref],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_comp_eks_001_rejected_when_no_public_endpoints():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "eks-inventory": {
            "clusters": [
                {
                    "name": "c1",
                    "resourcesVpcConfig": {"endpointPublicAccess": False},
                }
            ]
        }
    }

    out = n.normalize([_finding("COMP-EKS-001")])
    assert out == []


def test_comp_eks_001_accepted_when_public_endpoint_present():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "eks-inventory": {
            "clusters": [
                {
                    "name": "c1",
                    "resourcesVpcConfig": {"endpointPublicAccess": True},
                }
            ]
        }
    }

    out = n.normalize([_finding("COMP-EKS-001")])
    assert len(out) == 1
    assert out[0].id == "COMP-EKS-001"


def test_comp_ecs_001_rejected_when_no_scheduled_ecs_targets():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "eventbridge-rules": {
            "rules": [
                {
                    "Name": "daily-rule",
                    "ScheduleExpression": "rate(1 day)",
                    "Targets": [{"Id": "t1", "Arn": "arn:aws:lambda:us-east-1:111:function:x"}],
                }
            ]
        }
    }

    out = n.normalize([_finding("COMP-ECS-001")])
    assert out == []


def test_comp_ecs_001_accepted_when_scheduled_rule_targets_ecs():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "eventbridge-rules": {
            "rules": [
                {
                    "Name": "daily-ecs",
                    "ScheduleExpression": "cron(0 12 * * ? *)",
                    "Targets": [
                        {
                            "Id": "t1",
                            "Arn": "arn:aws:ecs:us-east-1:111:cluster/cluster1",
                            "EcsParameters": {"TaskDefinitionArn": "arn:aws:ecs:...:task-def/x"},
                        }
                    ],
                }
            ]
        }
    }

    out = n.normalize([_finding("COMP-ECS-001")])
    assert len(out) == 1
    assert out[0].id == "COMP-ECS-001"


def test_comp_eks_002_rejected_when_all_log_types_enabled():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "eks-inventory": {
            "clusters": [
                {
                    "name": "c1",
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
    out = n.normalize([_finding("COMP-EKS-002")])
    assert out == []


def test_comp_eks_002_accepted_when_logging_missing_type():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "eks-inventory": {
            "clusters": [
                {
                    "name": "c1",
                    "logging": {"clusterLogging": [{"enabled": True, "types": ["api", "audit"]}]},
                }
            ]
        }
    }
    out = n.normalize([_finding("COMP-EKS-002")])
    assert len(out) == 1
    assert out[0].id == "COMP-EKS-002"


def test_comp_ecs_002_rejected_when_no_suspicious_images():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "ecs-inventory": {
            "task_definitions": [
                {
                    "containerDefinitions": [
                        {"image": "111.dkr.ecr.us-east-1.amazonaws.com/app@sha256:abc"}
                    ]
                }
            ]
        }
    }
    out = n.normalize([_finding("COMP-ECS-002")])
    assert out == []


def test_comp_ecs_002_accepted_when_latest_image_present():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "ecs-inventory": {
            "task_definitions": [{"containerDefinitions": [{"image": "nginx:latest"}]}]
        }
    }
    out = n.normalize([_finding("COMP-ECS-002")])
    assert len(out) == 1
    assert out[0].id == "COMP-ECS-002"


def test_comp_ecs_003_rejected_when_all_containers_have_awslogs():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "ecs-inventory": {
            "task_definitions": [
                {
                    "containerDefinitions": [
                        {"logConfiguration": {"logDriver": "awslogs"}, "image": "nginx:1"}
                    ]
                }
            ]
        }
    }
    out = n.normalize([_finding("COMP-ECS-003")])
    assert out == []


def test_comp_ecs_003_accepted_when_missing_log_configuration():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {
        "ecs-inventory": {"task_definitions": [{"containerDefinitions": [{"image": "nginx:1"}]}]}
    }
    out = n.normalize([_finding("COMP-ECS-003")])
    assert len(out) == 1
    assert out[0].id == "COMP-ECS-003"


def test_comp_ecs_004_rejected_when_no_wildcard_evidence_snippet():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {"ecs-inventory": {"task_definitions": [{"containerDefinitions": []}]}}
    out = n.normalize([_finding("COMP-ECS-004")])
    assert out == []


def test_comp_ecs_004_accepted_when_wildcard_action_in_snippet():
    n = FindingsNormalizer(COMPUTE_CHECKLIST, "compute")
    n.evidence = {"ecs-inventory": {"task_definitions": [{"containerDefinitions": []}]}}
    f = _finding("COMP-ECS-004")
    f.evidence_snippet = {"Statement": {"Action": "*"}}
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "COMP-ECS-004"
