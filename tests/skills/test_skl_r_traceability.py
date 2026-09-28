"""Focused tests for SKL-R traceability hook modules."""

from types import SimpleNamespace

from drystone.skills.cicd import CICDSkill
from drystone.skills.compute import ComputeSkill
from drystone.skills.messaging import MessagingSkill


def _result(check_id: str, *resources: str):
    return SimpleNamespace(
        check_id=check_id,
        affected_resources=list(resources),
        evidence_summary=f"{check_id} failed",
    )


def test_compute_traceability_maps_ecs_task_definition_arn():
    evidence = {
        "ecs-inventory": {
            "task_definitions": [
                {"taskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/app:1"}
            ]
        }
    }

    refs, snippet = ComputeSkill()._skill_specific_traceability(
        "COMP-ECS-002",
        _result("COMP-ECS-002", "arn:aws:ecs:us-east-1:123:task-definition/app:1"),
        evidence,
    )

    assert refs == ["ecs-inventory.json#/task_definitions/0"]
    assert snippet["affected_resources"] == ["arn:aws:ecs:us-east-1:123:task-definition/app:1"]


def test_compute_traceability_maps_ec2_instance_arn_to_instance_id():
    evidence = {"ec2-inventory": {"instances": [{"InstanceId": "i-1234567890abcdef0"}]}}

    refs, _ = ComputeSkill()._skill_specific_traceability(
        "COMP-EC2-001",
        _result("COMP-EC2-001", "arn:aws:ec2:us-east-1:123:instance/i-1234567890abcdef0"),
        evidence,
    )

    assert refs == ["ec2-inventory.json#/instances/0"]


def test_cicd_traceability_maps_codebuild_project_arn():
    evidence = {
        "codebuild-projects": {
            "items": [{"arn": "arn:aws:codebuild:us-east-1:123:project/insecure", "name": "insecure"}]
        }
    }

    refs, _ = CICDSkill()._skill_specific_traceability(
        "CICD-002",
        _result("CICD-002", "arn:aws:codebuild:us-east-1:123:project/insecure"),
        evidence,
    )

    assert refs == ["codebuild-projects.json#/items/0"]


def test_cicd_traceability_maps_source_credentials_without_affected_resources():
    evidence = {
        "codebuild-source-credentials": {
            "items": [{"arn": "arn:aws:codebuild:us-east-1:123:token/github"}]
        }
    }

    refs, _ = CICDSkill()._skill_specific_traceability(
        "CICD-001",
        _result("CICD-001"),
        evidence,
    )

    assert refs == ["codebuild-source-credentials.json#/items/0"]


def test_messaging_traceability_maps_sqs_queue_arn():
    evidence = {"sqs-queues": {"items": [{"QueueArn": "arn:aws:sqs:us-east-1:123:queue"}]}}

    refs, _ = MessagingSkill()._skill_specific_traceability(
        "MSG-003",
        _result("MSG-003", "arn:aws:sqs:us-east-1:123:queue"),
        evidence,
    )

    assert refs == ["sqs-queues.json#/items/0"]


def test_messaging_traceability_maps_sns_topic_arn():
    evidence = {"sns-topics": {"items": [{"TopicArn": "arn:aws:sns:us-east-1:123:topic"}]}}

    refs, _ = MessagingSkill()._skill_specific_traceability(
        "MSG-008",
        _result("MSG-008", "arn:aws:sns:us-east-1:123:topic"),
        evidence,
    )

    assert refs == ["sns-topics.json#/items/0"]
