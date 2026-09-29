"""Tests for Compute (ECS/EKS) skill evidence collection."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from drystone.skills.compute import ComputeSkill


def _client_error(code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Compute")


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

    def describe_task_definition(self, taskDefinition):  # noqa: N803
        return {
            "taskDefinition": {
                "taskDefinitionArn": taskDefinition,
                "containerDefinitions": [],
            }
        }


class _DummyEventsClient:
    def get_paginator(self, op_name: str):
        assert op_name == "list_rules"
        return _DummyPaginator(
            [{"Rules": [{"Name": "r1", "ScheduleExpression": "rate(5 minutes)"}]}]
        )

    def list_targets_by_rule(self, Rule: str):  # noqa: N803
        assert Rule
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

    def describe_nodegroup(self, clusterName: str, nodegroupName: str):  # noqa: N803
        return {
            "nodegroup": {
                "clusterName": clusterName,
                "nodegroupName": nodegroupName,
            }
        }


class _DummyEC2Client:
    def get_paginator(self, op_name: str):
        assert op_name == "describe_instances"
        return _DummyPaginator(
            [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-123",
                                    "State": {"Name": "running"},
                                    "IamInstanceProfile": {
                                        "Arn": "arn:aws:iam::1:instance-profile/p1"
                                    },
                                    "MetadataOptions": {"HttpTokens": "optional"},
                                    "SecurityGroups": [],
                                }
                            ]
                        }
                    ]
                }
            ]
        )

    def describe_instance_attribute(self, InstanceId: str, Attribute: str):  # noqa: N803
        assert InstanceId and Attribute == "userData"
        return {"UserData": {"Value": "IyEvYmluL2Jhc2gKZWNobyBoZWxsbwo="}}


class _DummyLambdaClient:
    def get_paginator(self, op_name: str):
        assert op_name == "list_functions"
        return _DummyPaginator(
            [
                {
                    "Functions": [
                        {
                            "FunctionName": "fn-a",
                            "FunctionArn": "arn:aws:lambda:us-east-1:1:function:fn-a",
                            "Role": "arn:aws:iam::1:role/lambda-role",
                        }
                    ]
                }
            ]
        )

    def get_function_url_config(self, FunctionName: str):  # noqa: N803
        assert FunctionName
        return {
            "FunctionUrl": "https://abc.lambda-url.us-east-1.on.aws/",
            "AuthType": "NONE",
        }


class _DummyIAMClient:
    def list_attached_role_policies(self, RoleName: str):  # noqa: N803
        assert RoleName
        return {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]}


class _DummySession:
    def client(self, service_name: str, region_name: str):
        assert region_name
        if service_name == "ecs":
            return _DummyECSClient()
        if service_name == "events":
            return _DummyEventsClient()
        if service_name == "eks":
            return _DummyEKSClient()
        if service_name == "ec2":
            return _DummyEC2Client()
        if service_name == "lambda":
            return _DummyLambdaClient()
        if service_name == "iam":
            return _DummyIAMClient()
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
    assert (tmp_path / "ec2-inventory.json").exists()
    assert (tmp_path / "lambda-inventory.json").exists()


def _run_compute_collect(tmp_path: Path, session_obj):
    aws_client = Mock()
    aws_client.region_name = "us-east-1"
    aws_client.boto3_session.return_value = session_obj
    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    ComputeSkill().collect(aws_client, session)
    return json.loads((tmp_path / "compute-collection-status.json").read_text())


def test_compute_collection_status_happy_path(tmp_path: Path):
    status = _run_compute_collect(tmp_path, _DummySession())

    assert status["ok"] is True
    for component in (
        "ecs-inventory",
        "eventbridge-rules",
        "eks-inventory",
        "ec2-inventory",
        "lambda-inventory",
    ):
        assert status["components"][component] == {"ok": True}


def test_compute_error_code_uses_aws_code_not_error_message(tmp_path: Path):
    status = _run_compute_collect(tmp_path, _DummySession())
    ComputeSkill()._record_errors_component_status(
        status["components"],
        "synthetic",
        {"list_clusters": "AccessDeniedException: denied message"},
        collection_failure_keys={"list_clusters"},
    )

    component = status["components"]["synthetic"]
    assert component["error_code"] == "AccessDeniedException"
    assert component["error"] == "list_clusters: AccessDeniedException: denied message"


def test_compute_ecs_list_failure_is_collection_failed(tmp_path: Path):
    class _FailECSClient(_DummyECSClient):
        def get_paginator(self, op_name: str):
            if op_name == "list_clusters":
                raise _client_error("AccessDeniedException")
            return super().get_paginator(op_name)

    class _Session(_DummySession):
        def client(self, service_name: str, region_name: str):
            if service_name == "ecs":
                return _FailECSClient()
            return super().client(service_name, region_name)

    status = _run_compute_collect(tmp_path, _Session())

    component = status["components"]["ecs-inventory"]
    assert component["ok"] is False
    assert component["reason_code"] == "collection_failed"
    assert component["error_code"] == "AccessDeniedException"


def test_compute_ec2_user_data_failure_is_partial_collection(tmp_path: Path):
    class _PartialEC2Client(_DummyEC2Client):
        def describe_instance_attribute(self, InstanceId: str, Attribute: str):  # noqa: N803
            raise _client_error("AccessDeniedException")

    class _Session(_DummySession):
        def client(self, service_name: str, region_name: str):
            if service_name == "ec2":
                return _PartialEC2Client()
            return super().client(service_name, region_name)

    status = _run_compute_collect(tmp_path, _Session())

    component = status["components"]["ec2-inventory"]
    assert component["ok"] is False
    assert component["reason_code"] == "partial_collection"
