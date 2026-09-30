"""End-to-end collect() tests for the sistemas_explotables_red collection status sidecar.

These tests exercise the full collect() flow with mocked boto3 clients and a
mocked urllib layer so they never touch the network, the real home directory,
or real AWS credentials. The external-intel cache directory is redirected to
tmp_path, and most tests run with external_intel_mode="off" for hermeticity.
"""

import json
import urllib.error
from typing import Any, Dict
from unittest.mock import MagicMock, Mock, patch

import pytest
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.sistemas_explotables_red import SistemasExplotablesRedSkill
from drystone.storage.session import AuditSession

STATUS_FILENAME = "sistemas_explotables_red-collection-status.json"
EXPECTED_COMPONENTS = {
    "compute-inventory",
    "network-controls",
    "front-doors",
    "inspector-findings-normalized",
    "cve-intelligence",
}

LONG_MESSAGE = "very long secret message that must never leak " * 10


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": LONG_MESSAGE}},
        operation,
    )


def _paginator(pages: Any) -> MagicMock:
    paginator = MagicMock()
    paginator.paginate.return_value = pages
    return paginator


def make_services() -> Dict[str, MagicMock]:
    """Per-service mocks wired for a fully successful, empty-account collect()."""
    ec2 = MagicMock()

    def _ec2_paginator(operation: str) -> MagicMock:
        pages = {
            "describe_instances": [{"Reservations": []}],
            "describe_security_groups": [{"SecurityGroups": []}],
            "describe_route_tables": [{"RouteTables": []}],
            "describe_network_acls": [{"NetworkAcls": []}],
        }[operation]
        return _paginator(pages)

    ec2.get_paginator.side_effect = _ec2_paginator

    ecs = MagicMock()
    ecs.list_clusters.return_value = {"clusterArns": []}

    lam = MagicMock()
    lam.get_paginator.return_value = _paginator([{"Functions": []}])

    rds = MagicMock()
    rds.get_paginator.return_value = _paginator([{"DBInstances": []}])

    elbv2 = MagicMock()
    elbv2.describe_load_balancers.return_value = {"LoadBalancers": []}

    apigw = MagicMock()
    apigw.get_rest_apis.return_value = {"items": []}

    apigw2 = MagicMock()
    apigw2.get_apis.return_value = {"Items": []}

    inspector2 = MagicMock()
    inspector2.list_findings.return_value = {"findings": []}

    return {
        "ec2": ec2,
        "ecs": ecs,
        "lambda": lam,
        "rds": rds,
        "elbv2": elbv2,
        "apigateway": apigw,
        "apigatewayv2": apigw2,
        "inspector2": inspector2,
    }


def _cve_finding() -> Dict[str, Any]:
    return {
        "severity": "HIGH",
        "status": "ACTIVE",
        "title": "CVE-2024-26130 cryptography 41.0.4",
        "resources": [{"id": "i-ec2abc", "type": "AWS_EC2_INSTANCE"}],
    }


@pytest.fixture
def skill(tmp_path, monkeypatch):
    instance = SistemasExplotablesRedSkill()
    # Redirect the external-intel cache away from the real home directory.
    monkeypatch.setattr(
        instance, "_external_intel_cache_dir", lambda: tmp_path / "intel-cache"
    )
    return instance


@pytest.fixture
def aws_client():
    client = Mock(spec=AWSClient)
    client.region_name = "us-east-1"
    client.client_kwargs.return_value = {}
    return client


@pytest.fixture
def session(tmp_path):
    audit = Mock(spec=AuditSession)
    audit.account_id = "123456789012"
    audit.feature_flags = {"external_intel_mode": "off"}
    evidence_dir = tmp_path / "evidence" / "sistemas_explotables_red"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    audit.get_evidence_path.return_value = evidence_dir
    return audit


def run_collect(skill, aws_client, session, services) -> Dict[str, Any]:
    """Run collect() hermetically and return the parsed status sidecar."""
    with patch(
        "drystone.skills.sistemas_explotables_red.boto3.client",
        side_effect=lambda name, **kwargs: services[name],
    ), patch(
        "drystone.skills.sistemas_explotables_red.urllib.request.urlopen",
        side_effect=AssertionError("unexpected network call"),
    ):
        skill.collect(aws_client, session)
    status_path = session.get_evidence_path.return_value / STATUS_FILENAME
    return json.loads(status_path.read_text())


class TestCollectionStatusSidecar:
    def test_success_path_writes_status_with_all_components_ok(
        self, skill, aws_client, session
    ):
        services = make_services()

        status = run_collect(skill, aws_client, session, services)

        assert status["ok"] is True
        assert set(status["components"]) == EXPECTED_COMPONENTS
        for component in status["components"].values():
            assert component == {"ok": True}

    def test_compute_inventory_partial_collection_when_one_service_fails(
        self, skill, aws_client, session
    ):
        services = make_services()
        services["rds"].get_paginator.side_effect = _client_error(
            "AccessDenied", "DescribeDBInstances"
        )

        status = run_collect(skill, aws_client, session, services)

        component = status["components"]["compute-inventory"]
        assert component["ok"] is False
        assert component["reason_code"] == "partial_collection"
        assert component["error_code"] == "AccessDenied"
        assert "rds" in component["error"]
        assert len(component["error"]) <= 200
        assert LONG_MESSAGE[:20] not in component["error"]
        assert status["ok"] is False
        # Evidence file is still written with the services that succeeded.
        evidence_dir = session.get_evidence_path.return_value
        inventory = json.loads((evidence_dir / "compute-inventory.json").read_text())
        assert inventory["ec2_instances"] == []

    def test_network_controls_collection_failed_when_all_blocks_fail(
        self, skill, aws_client, session
    ):
        services = make_services()

        def _ec2_paginator(operation: str) -> MagicMock:
            if operation == "describe_instances":
                return _paginator([{"Reservations": []}])
            raise _client_error("AccessDenied", operation)

        services["ec2"].get_paginator.side_effect = _ec2_paginator

        status = run_collect(skill, aws_client, session, services)

        component = status["components"]["network-controls"]
        assert component["ok"] is False
        assert component["reason_code"] == "collection_failed"
        assert component["error_code"] == "AccessDenied"
        assert len(component["error"]) <= 200
        # compute-inventory is unaffected by the network block failures.
        assert status["components"]["compute-inventory"] == {"ok": True}

    def test_front_doors_partial_collection_when_one_family_fails(
        self, skill, aws_client, session
    ):
        services = make_services()
        services["apigatewayv2"].get_apis.side_effect = _client_error(
            "AccessDeniedException", "GetApis"
        )

        status = run_collect(skill, aws_client, session, services)

        component = status["components"]["front-doors"]
        assert component["ok"] is False
        assert component["reason_code"] == "partial_collection"
        assert component["error_code"] == "AccessDeniedException"
        assert len(component["error"]) <= 200

    def test_front_doors_ok_when_function_url_config_is_absent(
        self, skill, aws_client, session
    ):
        services = make_services()
        services["lambda"].get_paginator.return_value = _paginator(
            [{"Functions": [{"FunctionName": "fn-a", "FunctionArn": "arn:aws:lambda:fn-a"}]}]
        )
        services["lambda"].get_function_url_config.side_effect = _client_error(
            "ResourceNotFoundException", "GetFunctionUrlConfig"
        )

        status = run_collect(skill, aws_client, session, services)

        assert status["components"]["front-doors"] == {"ok": True}
        assert status["ok"] is True

    def test_inspector_component_collection_failed_on_client_error(
        self, skill, aws_client, session
    ):
        services = make_services()
        services["inspector2"].list_findings.side_effect = _client_error(
            "AccessDeniedException", "ListFindings"
        )

        status = run_collect(skill, aws_client, session, services)

        component = status["components"]["inspector-findings-normalized"]
        assert component["ok"] is False
        assert component["reason_code"] == "collection_failed"
        assert component["error_code"] == "AccessDeniedException"
        assert len(component["error"]) <= 200
        assert LONG_MESSAGE[:20] not in component["error"]

    def test_cve_intelligence_ok_when_external_intel_off(
        self, skill, aws_client, session
    ):
        session.feature_flags = {"external_intel_mode": "off"}
        services = make_services()
        services["inspector2"].list_findings.return_value = {"findings": [_cve_finding()]}

        status = run_collect(skill, aws_client, session, services)

        assert status["components"]["cve-intelligence"] == {"ok": True}
        evidence_dir = session.get_evidence_path.return_value
        cve_doc = json.loads((evidence_dir / "cve-intelligence.json").read_text())
        assert cve_doc["enrichment_errors"] == [
            "External vulnerability intelligence disabled"
        ]

    def test_cve_intelligence_partial_collection_on_enrichment_errors(
        self, skill, aws_client, session
    ):
        session.feature_flags = {"external_intel_mode": "live"}
        services = make_services()
        services["inspector2"].list_findings.return_value = {"findings": [_cve_finding()]}

        with patch(
            "drystone.skills.sistemas_explotables_red.boto3.client",
            side_effect=lambda name, **kwargs: services[name],
        ), patch(
            "drystone.skills.sistemas_explotables_red.urllib.request.urlopen",
            side_effect=urllib.error.URLError("no network in test"),
        ), patch(
            "drystone.skills.sistemas_explotables_red.time.sleep"
        ):
            skill.collect(aws_client, session)

        status_path = session.get_evidence_path.return_value / STATUS_FILENAME
        status = json.loads(status_path.read_text())

        component = status["components"]["cve-intelligence"]
        assert component["ok"] is False
        assert component["reason_code"] == "partial_collection"
        assert "error_code" not in component
        assert "enrichment error" in component["error"]
        assert "nvd" in component["error"]
        assert len(component["error"]) <= 200
        assert "http" not in component["error"].lower()
        # The evidence file itself keeps the full error list.
        evidence_dir = session.get_evidence_path.return_value
        cve_doc = json.loads((evidence_dir / "cve-intelligence.json").read_text())
        assert cve_doc["enrichment_errors"]

    def test_collection_status_component_keys_match_written_evidence_stems(
        self, skill, aws_client, session
    ):
        """Components consumed by pre-checks must use evidence file stems."""
        services = make_services()

        status = run_collect(skill, aws_client, session, services)

        evidence_dir = session.get_evidence_path.return_value
        evidence_stems = {
            path.stem
            for path in evidence_dir.glob("*.json")
            if not path.name.endswith("-collection-status.json")
        }
        auxiliary_components: set = set()
        for component in status["components"]:
            assert component in evidence_stems | auxiliary_components
        assert set(status["components"]) == EXPECTED_COMPONENTS
