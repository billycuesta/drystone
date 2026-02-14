"""Tests for Compute (ECS/EKS) skill evidence collection."""

from pathlib import Path
from unittest.mock import Mock, patch

from drystone.skills.compute import ComputeSkill


class _DummyPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class _DummyECSClient:
    def get_paginator(self, op_name: str):
        if op_name == "list_clusters":
            return _DummyPaginator([{"clusterArns": ["arn:aws:ecs:us-east-1:1:cluster/c1"]}])
        if op_name == "list_services":
            return _DummyPaginator([{"serviceArns": ["arn:aws:ecs:us-east-1:1:service/s1"]}])
        if op_name == "list_tasks":
            return _DummyPaginator([{"taskArns": ["arn:aws:ecs:us-east-1:1:task/t1"]}])
        if op_name == "list_task_definitions":
            return _DummyPaginator(
                [{"taskDefinitionArns": ["arn:aws:ecs:us-east-1:1:task-definition/td:1"]}]
            )
        raise AssertionError(op_name)

    def describe_clusters(self, clusters):
        return {"clusters": [{"clusterArn": clusters[0], "clusterName": "c1"}]}

    def describe_services(self, cluster, services):
        return {
            "services": [{"clusterArn": cluster, "serviceArn": services[0], "serviceName": "s1"}]
        }

    def describe_tasks(self, cluster, tasks):
        return {"tasks": [{"clusterArn": cluster, "taskArn": tasks[0], "taskDefinitionArn": "td"}]}

    def describe_task_definition(self, task_definition):
        return {
            "taskDefinition": {
                "taskDefinitionArn": task_definition,
                "containerDefinitions": [],
            }
        }


class _DummyEventsClient:
    def get_paginator(self, op_name: str):
        assert op_name == "list_rules"
        return _DummyPaginator(
            [{"Rules": [{"Name": "r1", "ScheduleExpression": "rate(5 minutes)"}]}]
        )

    def list_targets_by_rule(self, rule: str):
        assert rule
        return {"Targets": [{"Arn": "arn:aws:ecs:us-east-1:1:cluster/c1"}]}


class _DummyEKSClient:
    def get_paginator(self, op_name: str):
        if op_name == "list_clusters":
            return _DummyPaginator([{"clusters": ["k1"]}])
        if op_name == "list_nodegroups":
            return _DummyPaginator([{"nodegroups": ["ng1"]}])
        raise AssertionError(op_name)

    def describe_cluster(self, name: str):
        return {
            "cluster": {
                "name": name,
                "resourcesVpcConfig": {"endpointPublicAccess": True},
                "logging": {"clusterLogging": []},
            }
        }

    def describe_nodegroup(self, cluster_name: str, nodegroup_name: str):
        return {
            "nodegroup": {
                "clusterName": cluster_name,
                "nodegroupName": nodegroup_name,
            }
        }


class _DummySession:
    def client(self, service_name: str, region_name: str):
        assert region_name
        if service_name == "ecs":
            return _DummyECSClient()
        if service_name == "events":
            return _DummyEventsClient()
        if service_name == "eks":
            return _DummyEKSClient()
        raise AssertionError(service_name)


def test_compute_collect_writes_expected_files(tmp_path: Path):
    aws_client = Mock()
    aws_client.access_key_id = "AKIA0000000000000000"
    aws_client.secret_access_key = "x" * 40
    aws_client.region_name = "us-east-1"
    aws_client.session_token = None

    session = Mock()
    session.get_evidence_path.return_value = tmp_path

    skill = ComputeSkill()
    with patch("boto3.Session", return_value=_DummySession()):
        skill.collect(aws_client, session)

    assert (tmp_path / "_audit_metadata.json").exists()
    assert (tmp_path / "ecs-inventory.json").exists()
    assert (tmp_path / "eventbridge-rules.json").exists()
    assert (tmp_path / "eks-inventory.json").exists()
