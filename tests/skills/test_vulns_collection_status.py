"""Collection status tests for the vulns skill.

The vulns skill must persist `vulns-collection-status.json` with a
`components` dict keyed by evidence file stem, using the shared
BaseSkill status helpers. Swallowed collection failures must surface
as `collection_failed` / `partial_collection` entries without leaking
secret values or full exception messages.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from botocore.exceptions import ClientError

from drystone.skills.vulns import VulnsSkill

EXPECTED_COMPONENTS = {
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
}


def build_fake_clients() -> dict:
    """Build per-service MagicMock clients with empty-but-valid responses."""
    clients: dict = {}

    inspector2 = MagicMock(name="inspector2")
    inspector2.describe_organization_configuration.return_value = {
        "delegatedAdminAccountId": "123456789012"
    }
    inspector2.get_paginator.return_value.paginate.return_value = [{"findings": []}]
    clients["inspector2"] = inspector2

    ec2 = MagicMock(name="ec2")
    ec2.describe_instances.return_value = {"Reservations": []}

    def _ec2_paginator(op):
        paginator = MagicMock(name=f"ec2-paginator-{op}")
        if op == "describe_instances":
            paginator.paginate.return_value = [{"Reservations": []}]
        elif op == "describe_snapshots":
            paginator.paginate.return_value = [{"Snapshots": []}]
        else:
            paginator.paginate.return_value = []
        return paginator

    ec2.get_paginator.side_effect = _ec2_paginator
    clients["ec2"] = ec2

    ssm = MagicMock(name="ssm")
    ssm.get_paginator.return_value.paginate.return_value = [{"PatchBaselines": []}]
    ssm.describe_instance_information.return_value = {"InstanceInformationList": []}
    ssm.get_compliance_details_by_resource.return_value = {"ComplianceItems": []}
    clients["ssm"] = ssm

    rds = MagicMock(name="rds")
    rds.describe_db_instances.return_value = {"DBInstances": []}
    clients["rds"] = rds

    ecr = MagicMock(name="ecr")
    ecr.describe_repositories.return_value = {"repositories": []}
    clients["ecr"] = ecr

    guardduty = MagicMock(name="guardduty")
    guardduty.list_detectors.return_value = {"DetectorIds": []}
    clients["guardduty"] = guardduty

    lam = MagicMock(name="lambda")
    lam.get_paginator.return_value.paginate.return_value = [{"Functions": []}]
    clients["lambda"] = lam

    iam = MagicMock(name="iam")
    clients["iam"] = iam

    ecs = MagicMock(name="ecs")
    ecs.get_paginator.return_value.paginate.return_value = [{"taskDefinitionArns": []}]
    clients["ecs"] = ecs

    s3 = MagicMock(name="s3")
    s3.list_buckets.return_value = {"Buckets": []}
    clients["s3"] = s3

    return clients


def make_aws_client() -> Mock:
    aws_client = Mock()
    aws_client.client_kwargs.return_value = {"region_name": "us-east-1"}
    return aws_client


def make_session(tmp_path: Path, feature_flags: dict = None) -> Mock:
    session = Mock()
    session.get_evidence_path.return_value = tmp_path
    session.feature_flags = (
        {"terraform_state_scan_enabled": False} if feature_flags is None else feature_flags
    )
    return session


def run_collect(tmp_path: Path, clients: dict, feature_flags: dict = None) -> dict:
    """Run VulnsSkill.collect against fake clients and return the status doc."""
    skill = VulnsSkill()
    aws_client = make_aws_client()
    session = make_session(tmp_path, feature_flags)

    def _client(service, **_kwargs):
        if service not in clients:
            raise AssertionError(f"Unexpected boto3 client service: {service}")
        return clients[service]

    with patch("boto3.client", side_effect=_client):
        skill.collect(aws_client, session)

    status_file = tmp_path / "vulns-collection-status.json"
    assert status_file.exists(), "vulns-collection-status.json was not written"
    return json.loads(status_file.read_text())


def client_error(code: str, operation: str, message: str = "denied") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        operation,
    )


class TestVulnsCollectionStatus:
    def test_collection_status_happy_path(self, tmp_path):
        clients = build_fake_clients()
        status = run_collect(tmp_path, clients)

        assert status["ok"] is True
        assert set(status["components"]) == EXPECTED_COMPONENTS
        for component, entry in status["components"].items():
            assert entry == {"ok": True}, f"component {component} should be ok"

    def test_collection_status_component_keys_match_written_evidence_stems(self, tmp_path):
        """Components consumed by pre-checks must use evidence file stems."""
        clients = build_fake_clients()
        status = run_collect(tmp_path, clients)

        evidence_stems = {
            path.stem
            for path in tmp_path.glob("*.json")
            if not path.name.endswith("-collection-status.json")
        }
        auxiliary_components = set()
        for component in status["components"]:
            assert component in evidence_stems | auxiliary_components

    def test_inspector_findings_list_failure_records_collection_failed_without_leak(self, tmp_path):
        clients = build_fake_clients()
        clients["inspector2"].get_paginator.return_value.paginate.side_effect = client_error(
            "AccessDeniedException", "ListFindings", message="token SECRET_VALUE"
        )

        status = run_collect(tmp_path, clients)

        component = status["components"]["inspector-findings"]
        assert component["ok"] is False
        assert component["reason_code"] == "collection_failed"
        assert component["error_code"] == "AccessDeniedException"
        assert "SECRET_VALUE" not in json.dumps(status)
        # The org-config component is unaffected by the findings list failure.
        assert status["components"]["inspector-org-config"] == {"ok": True}

    def test_ec2_patch_status_per_instance_failure_records_partial_collection(self, tmp_path):
        clients = build_fake_clients()
        clients["ec2"].describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0123456789abcdef0",
                            "InstanceType": "t3.micro",
                            "State": {"Name": "running"},
                            "Tags": [],
                        }
                    ]
                }
            ]
        }
        clients["ssm"].describe_instance_information.side_effect = client_error(
            "AccessDenied", "DescribeInstanceInformation", message="SECRET_VALUE denied"
        )

        status = run_collect(tmp_path, clients)

        component = status["components"]["ec2-patch-status"]
        assert component["ok"] is False
        assert component["reason_code"] == "partial_collection"
        assert component["error_code"] == "AccessDenied"
        assert "SECRET_VALUE" not in json.dumps(status)
        # Evidence file is still written with the instance record.
        patch_file = tmp_path / "ec2-patch-status.json"
        assert patch_file.exists()
        records = json.loads(patch_file.read_text())
        assert len(records) == 1
        assert records[0]["InstanceId"] == "i-0123456789abcdef0"

    def test_lambda_helper_list_failure_records_collection_failed_from_error_string(self, tmp_path):
        clients = build_fake_clients()
        clients["lambda"].get_paginator.return_value.paginate.side_effect = client_error(
            "ThrottlingException", "ListFunctions", message="rate SECRET_VALUE"
        )

        status = run_collect(tmp_path, clients)

        component = status["components"]["lambda-environment-variables"]
        assert component["ok"] is False
        assert component["reason_code"] == "collection_failed"
        assert component["error_code"] == "ThrottlingException"
        assert "SECRET_VALUE" not in json.dumps(status)

    def test_guardduty_not_enabled_is_ok(self, tmp_path):
        clients = build_fake_clients()
        clients["guardduty"].list_detectors.side_effect = client_error(
            "AccessDeniedException", "ListDetectors"
        )

        status = run_collect(tmp_path, clients)

        assert status["components"]["guardduty-status"] == {"ok": True}
        guardduty_file = tmp_path / "guardduty-status.json"
        assert guardduty_file.exists()
        data = json.loads(guardduty_file.read_text())
        assert data.get("access_error")

    def test_terraform_flag_skipped_is_ok(self, tmp_path):
        clients = build_fake_clients()
        status = run_collect(
            tmp_path, clients, feature_flags={"terraform_state_scan_enabled": False}
        )

        assert status["components"]["terraform-state-scan"] == {"ok": True}
        tf_file = tmp_path / "terraform-state-scan.json"
        assert tf_file.exists()
        data = json.loads(tf_file.read_text())
        assert data.get("skipped") is True
