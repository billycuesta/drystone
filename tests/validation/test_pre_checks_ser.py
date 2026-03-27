"""Tests for sistemas_explotables_red deterministic pre-checks."""

from drystone.validation.pre_checks import (
    check_ser_cor_003,
    check_ser_ec2_001,
    check_ser_ec2_002,
    check_ser_ecs_001,
    check_ser_lmb_001,
    check_ser_lmb_002,
    check_ser_rds_001,
)


def test_ser_ec2_001_fail_when_world_open_ssh_attached_to_instance() -> None:
    evidence = {
        "network-controls": {
            "security_groups": [
                {
                    "GroupId": "sg-1",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ],
            "route_tables": [],
        },
        "compute-inventory": {
            "ec2_instances": [
                {
                    "InstanceId": "i-123",
                    "SecurityGroups": [{"GroupId": "sg-1"}],
                }
            ]
        },
    }

    result = check_ser_ec2_001(evidence)
    assert result.status == "FAIL"
    assert result.check_id == "SER-EC2-001"


def test_ser_ec2_001_pass_when_instance_in_private_subnet() -> None:
    """D3: SG is world-open but instance subnet has no IGW route -> PASS."""
    evidence = {
        "network-controls": {
            "security_groups": [
                {
                    "GroupId": "sg-1",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ],
            "route_tables": [
                {
                    "RouteTableId": "rtb-priv",
                    "VpcId": "vpc-1",
                    "Associations": [{"SubnetId": "subnet-priv", "Main": False}],
                    "Routes": [
                        {
                            "DestinationCidrBlock": "10.0.0.0/16",
                            "GatewayId": "local",
                            "State": "active",
                        }
                    ],
                }
            ],
        },
        "compute-inventory": {
            "ec2_instances": [
                {
                    "InstanceId": "i-private",
                    "SubnetId": "subnet-priv",
                    "VpcId": "vpc-1",
                    "SecurityGroups": [{"GroupId": "sg-1"}],
                }
            ]
        },
    }

    result = check_ser_ec2_001(evidence)
    assert result.status == "PASS"
    assert result.check_id == "SER-EC2-001"


def test_ser_ec2_001_fail_when_instance_in_public_subnet() -> None:
    """D3: SG world-open AND subnet has IGW route -> FAIL."""
    evidence = {
        "network-controls": {
            "security_groups": [
                {
                    "GroupId": "sg-1",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ],
            "route_tables": [
                {
                    "RouteTableId": "rtb-pub",
                    "VpcId": "vpc-1",
                    "Associations": [{"SubnetId": "subnet-pub", "Main": False}],
                    "Routes": [
                        {
                            "DestinationCidrBlock": "0.0.0.0/0",
                            "GatewayId": "igw-abc",
                            "State": "active",
                        }
                    ],
                }
            ],
        },
        "compute-inventory": {
            "ec2_instances": [
                {
                    "InstanceId": "i-public",
                    "SubnetId": "subnet-pub",
                    "VpcId": "vpc-1",
                    "SecurityGroups": [{"GroupId": "sg-1"}],
                }
            ]
        },
    }

    result = check_ser_ec2_001(evidence)
    assert result.status == "FAIL"
    assert result.check_id == "SER-EC2-001"


def test_ser_lmb_001_fail_when_lambda_url_is_unauthenticated() -> None:
    evidence = {
        "front-doors": {
            "lambda_function_urls": [
                {
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:public-fn",
                    "AuthType": "NONE",
                }
            ]
        }
    }

    result = check_ser_lmb_001(evidence)
    assert result.status == "FAIL"
    assert result.check_id == "SER-LMB-001"


def test_ser_rds_001_fail_when_public_rds_has_world_open_engine_port() -> None:
    evidence = {
        "network-controls": {
            "security_groups": [
                {
                    "GroupId": "sg-db",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 5432,
                            "ToPort": 5432,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        },
        "compute-inventory": {
            "rds_instances": [
                {
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
                    "Engine": "postgres",
                    "PubliclyAccessible": True,
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db"}],
                }
            ]
        },
    }

    result = check_ser_rds_001(evidence)
    assert result.status == "FAIL"
    assert result.check_id == "SER-RDS-001"


def test_ser_cor_003_fail_when_correlated_scores_are_high() -> None:
    evidence = {
        "attack-path-candidates": {
            "paths": [
                {
                    "target_resource": "arn:aws:ec2:*:*:instance/i-123",
                    "reachability_score": 0.9,
                    "vulnerability_score": 0.8,
                    "blast_radius_score": 0.8,
                    "overall_score": 0.82,
                }
            ]
        }
    }

    result = check_ser_cor_003(evidence)
    assert result.status == "FAIL"
    assert result.check_id == "SER-COR-003"


def test_ser_cor_003_pass_when_no_high_correlated_paths() -> None:
    evidence = {
        "attack-path-candidates": {
            "paths": [
                {
                    "target_resource": "arn:aws:ec2:*:*:instance/i-999",
                    "reachability_score": 0.5,
                    "vulnerability_score": 0.2,
                    "blast_radius_score": 0.3,
                    "overall_score": 0.38,
                }
            ]
        }
    }

    result = check_ser_cor_003(evidence)
    assert result.status == "PASS"
    assert result.check_id == "SER-COR-003"


def test_ser_ec2_002_fail_when_reachable_ec2_has_inspector_signal() -> None:
    evidence = {
        "attack-path-candidates": {
            "paths": [
                {
                    "target_resource": "arn:aws:ec2:*:*:instance/i-123",
                    "reachability_score": 0.9,
                    "inspector_signal": {
                        "critical": 0,
                        "high": 0,
                        "medium": 2,
                        "internet_reachability_findings": 1,
                    },
                }
            ]
        }
    }
    result = check_ser_ec2_002(evidence)
    assert result.status == "FAIL"
    assert result.check_id == "SER-EC2-002"


class TestSerEcs001:
    def test_fail_when_ecs_reachable_via_alb(self) -> None:
        evidence = {
            "reachability-graph": {
                "edges": [
                    {
                        "source": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/pub/abc",
                        "target": "arn:aws:ecs:us-east-1:123:service/cluster/svc-a",
                        "path_type": "alb->ecs-service",
                    }
                ]
            }
        }
        result = check_ser_ecs_001(evidence)
        assert result.status == "FAIL"
        assert result.check_id == "SER-ECS-001"
        assert "arn:aws:ecs:us-east-1:123:service/cluster/svc-a" in result.affected_resources

    def test_pass_when_no_alb_ecs_edges(self) -> None:
        evidence = {
            "reachability-graph": {
                "edges": [
                    {
                        "source": "internet",
                        "target": "arn:aws:ec2:us-east-1:123:instance/i-abc",
                        "path_type": "public-ip",
                    }
                ]
            }
        }
        result = check_ser_ecs_001(evidence)
        assert result.status == "PASS"

    def test_skip_when_reachability_graph_is_none(self) -> None:
        """SKIP only when reachability-graph value is explicitly not a dict."""
        result = check_ser_ecs_001({"reachability-graph": None})
        assert result.status == "SKIP"

    def test_pass_when_no_reachability_graph_key(self) -> None:
        """Missing key defaults to empty dict -> empty edges -> PASS."""
        result = check_ser_ecs_001({})
        assert result.status == "PASS"

    def test_pass_when_edges_empty(self) -> None:
        evidence = {"reachability-graph": {"edges": []}}
        result = check_ser_ecs_001(evidence)
        assert result.status == "PASS"


class TestSerLmb002:
    def test_fail_when_api_gw_routes_have_no_auth(self) -> None:
        evidence = {
            "front-doors": {
                "api_gateway_routes": [
                    {
                        "ApiId": "abc123",
                        "Path": "/users",
                        "Method": "GET",
                        "AuthorizationType": "NONE",
                    }
                ]
            }
        }
        result = check_ser_lmb_002(evidence)
        assert result.status == "FAIL"
        assert result.check_id == "SER-LMB-002"

    def test_pass_when_all_routes_have_auth(self) -> None:
        evidence = {
            "front-doors": {
                "api_gateway_routes": [
                    {
                        "ApiId": "abc123",
                        "Path": "/users",
                        "Method": "GET",
                        "AuthorizationType": "AWS_IAM",
                    }
                ]
            }
        }
        result = check_ser_lmb_002(evidence)
        assert result.status == "PASS"

    def test_pass_when_no_routes(self) -> None:
        evidence = {"front-doors": {"api_gateway_routes": []}}
        result = check_ser_lmb_002(evidence)
        assert result.status == "PASS"

    def test_skip_when_front_doors_is_none(self) -> None:
        """SKIP only when front-doors value is explicitly not a dict."""
        result = check_ser_lmb_002({"front-doors": None})
        assert result.status == "SKIP"

    def test_pass_when_front_doors_key_missing(self) -> None:
        """Missing key defaults to empty dict -> empty routes -> PASS."""
        result = check_ser_lmb_002({})
        assert result.status == "PASS"

    def test_deduplicates_routes(self) -> None:
        evidence = {
            "front-doors": {
                "api_gateway_routes": [
                    {"ApiId": "x", "Path": "/a", "Method": "GET", "AuthorizationType": "NONE"},
                    {"ApiId": "x", "Path": "/a", "Method": "GET", "AuthorizationType": "NONE"},
                ]
            }
        }
        result = check_ser_lmb_002(evidence)
        assert result.status == "FAIL"
        assert len(result.affected_resources) == 1


class TestSerEc2002Metadata:
    """Tests for metadata propagation in check_ser_ec2_002."""

    def _base_evidence(self) -> dict:
        return {
            "attack-path-candidates": {
                "paths": [
                    {
                        "target_resource": "arn:aws:ec2:us-east-1:123:instance/i-abc",
                        "reachability_score": 0.9,
                        "inspector_signal": {
                            "critical": 1,
                            "high": 0,
                            "medium": 0,
                            "internet_reachability_findings": 1,
                        },
                    }
                ]
            },
            "inspector-findings-normalized": {
                "findings": [
                    {
                        "severity": "CRITICAL",
                        "status": "ACTIVE",
                        "title": "CVE-2024-26130 cryptography",
                        "resources": [{"id": "i-abc", "type": "AWS_EC2_INSTANCE"}],
                    }
                ]
            },
        }

    def test_fail_result_has_metadata_with_cve_details(self) -> None:
        result = check_ser_ec2_002(self._base_evidence())
        assert result.status == "FAIL"
        assert "cve_details" in result.metadata
        assert len(result.metadata["cve_details"]) >= 1

    def test_evidence_summary_is_clean_no_pipe_separator(self) -> None:
        """evidence_summary must NOT contain '| Findings:' pipe-separated CVE list."""
        result = check_ser_ec2_002(self._base_evidence())
        assert result.status == "FAIL"
        assert "| Findings:" not in result.evidence_summary
        assert "Findings:" not in result.evidence_summary

    def test_cve_details_contain_resource_field(self) -> None:
        result = check_ser_ec2_002(self._base_evidence())
        assert result.status == "FAIL"
        cve_details = result.metadata.get("cve_details", [])
        assert all("resource" in c for c in cve_details)

    def test_enriched_cve_details_used_when_cve_intelligence_present(self) -> None:
        """When cve-intelligence.json is in evidence, enriched data should be used."""
        evidence = self._base_evidence()
        evidence["cve-intelligence"] = {
            "instances": {
                "i-abc": {
                    "cves": [
                        {
                            "id": "CVE-2024-26130",
                            "package": "cryptography",
                            "inspector_severity": "CRITICAL",
                            "cvss_score": 7.5,
                            "attack_vector": "NETWORK",
                            "exploitable_from_internet": True,
                            "relevant_open_ports": [22],
                        }
                    ],
                    "attack_path": {
                        "narrative": "Test narrative",
                        "steps": [{"step": 1, "action": "Reach port 22", "technique": "T1595.001"}],
                    },
                }
            }
        }
        result = check_ser_ec2_002(evidence)
        assert result.status == "FAIL"
        cve_details = result.metadata.get("cve_details", [])
        assert len(cve_details) >= 1
        enriched = cve_details[0]
        assert enriched.get("cvss_score") == 7.5
        assert enriched.get("exploitable_from_internet") is True
        # Attack paths should also be in metadata
        assert "attack_paths" in result.metadata
