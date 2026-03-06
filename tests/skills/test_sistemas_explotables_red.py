"""Unit tests for sistemas_explotables_red skill helper logic."""

from drystone.skills.sistemas_explotables_red import SistemasExplotablesRedSkill


def test_build_reachability_includes_alb_to_ecs_edge_for_public_alb() -> None:
    skill = SistemasExplotablesRedSkill()
    front_doors = {
        "load_balancers": [
            {
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/public/abc",
                "Scheme": "internet-facing",
            }
        ],
        "listeners": [],
        "target_groups": [
            {
                "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/tg-1/def",
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/public/abc",
            }
        ],
        "lambda_function_urls": [],
        "api_gateway_routes": [],
    }
    compute_inventory = {
        "ec2_instances": [],
        "lambda_functions": [],
        "rds_instances": [],
        "ecs_services": [
            {
                "ServiceArn": "arn:aws:ecs:us-east-1:123:service/cluster/service-a",
                "LoadBalancers": [
                    {
                        "targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/tg-1/def"
                    }
                ],
            }
        ],
    }

    reachability, _ = skill._build_reachability(
        front_doors=front_doors, compute_inventory=compute_inventory
    )
    edges = reachability.get("edges", [])
    assert any(
        isinstance(e, dict)
        and e.get("path_type") == "alb->ecs-service"
        and e.get("target") == "arn:aws:ecs:us-east-1:123:service/cluster/service-a"
        for e in edges
    )


def test_build_attack_paths_scores_high_when_vuln_and_blast_radius_present() -> None:
    skill = SistemasExplotablesRedSkill()
    reachability_doc = {
        "edges": [
            {
                "source": "internet",
                "target": "arn:aws:ec2:*:*:instance/i-123",
                "confidence": 0.9,
            }
        ]
    }
    inspector_doc = {
        "findings": [
            {
                "severity": "HIGH",
                "resources": [{"id": "arn:aws:ec2:*:*:instance/i-123", "type": "AWS_EC2_INSTANCE"}],
            },
            {
                "severity": "CRITICAL",
                "resources": [{"id": "arn:aws:ec2:*:*:instance/i-123", "type": "AWS_EC2_INSTANCE"}],
            },
        ]
    }
    compute_inventory = {
        "ec2_instances": [
            {
                "InstanceId": "i-123",
                "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/prof-a"},
            }
        ],
        "lambda_functions": [],
    }

    paths = skill._build_attack_paths(
        reachability_doc=reachability_doc,
        inspector_doc=inspector_doc,
        compute_inventory=compute_inventory,
    )
    assert len(paths) == 1
    assert paths[0]["overall_score"] >= 0.75


def test_build_reachability_uses_real_region_account_in_arns() -> None:
    """B2: EC2 ARNs should use real region and account_id instead of wildcards."""
    skill = SistemasExplotablesRedSkill()
    front_doors = {
        "load_balancers": [],
        "listeners": [],
        "target_groups": [],
        "lambda_function_urls": [],
        "api_gateway_routes": [],
    }
    compute_inventory = {
        "ec2_instances": [
            {
                "InstanceId": "i-real123",
                "PublicIpAddress": "1.2.3.4",
                "SecurityGroups": [],
            }
        ],
        "ecs_services": [],
        "lambda_functions": [],
        "rds_instances": [],
    }

    reachability, _ = skill._build_reachability(
        front_doors=front_doors,
        compute_inventory=compute_inventory,
        region="us-east-1",
        account_id="111122223333",
    )
    edges = reachability.get("edges", [])
    assert len(edges) == 1
    assert edges[0]["target"] == "arn:aws:ec2:us-east-1:111122223333:instance/i-real123"
    assert "*" not in edges[0]["target"]


def test_build_attack_paths_severity_mapping() -> None:
    """D2: overall_score maps to the correct severity label."""
    skill = SistemasExplotablesRedSkill()
    assert skill._overall_score_to_severity(0.9) == "Critical"
    assert skill._overall_score_to_severity(0.75) == "Critical"
    assert skill._overall_score_to_severity(0.74) == "High"
    assert skill._overall_score_to_severity(0.55) == "High"
    assert skill._overall_score_to_severity(0.54) == "Medium"
    assert skill._overall_score_to_severity(0.35) == "Medium"
    assert skill._overall_score_to_severity(0.34) == "Low"
    assert skill._overall_score_to_severity(0.0) == "Low"


def test_build_attack_paths_includes_severity_field() -> None:
    """D2: attack paths must include a severity field derived from overall_score."""
    skill = SistemasExplotablesRedSkill()
    reachability_doc = {
        "edges": [
            {
                "source": "internet",
                "target": "arn:aws:ec2:us-east-1:123:instance/i-sev",
                "confidence": 0.9,
            }
        ]
    }
    inspector_doc = {
        "findings": [
            {
                "severity": "CRITICAL",
                "resources": [{"id": "i-sev", "type": "AWS_EC2_INSTANCE"}],
            }
        ]
    }
    compute_inventory = {
        "ec2_instances": [
            {"InstanceId": "i-sev", "IamInstanceProfile": {"Arn": "arn:aws:iam::123:ip/p"}}
        ],
        "lambda_functions": [],
    }

    paths = skill._build_attack_paths(
        reachability_doc=reachability_doc,
        inspector_doc=inspector_doc,
        compute_inventory=compute_inventory,
    )
    assert len(paths) == 1
    assert "severity" in paths[0]
    assert paths[0]["severity"] in ("Critical", "High", "Medium", "Low")
    # With CRITICAL inspector signal + IAM role, score should be high -> Critical
    assert paths[0]["severity"] == "Critical"


def test_build_attack_paths_matches_ec2_short_id_from_inspector() -> None:
    skill = SistemasExplotablesRedSkill()
    reachability_doc = {
        "edges": [
            {
                "source": "internet",
                "target": "arn:aws:ec2:*:*:instance/i-abc123",
                "confidence": 0.9,
            }
        ]
    }
    inspector_doc = {
        "findings": [
            {
                "severity": "MEDIUM",
                "title": "Port 22 is reachable from an Internet Gateway - TCP",
                "resources": [{"id": "i-abc123", "type": "AWS_EC2_INSTANCE"}],
            }
        ]
    }
    compute_inventory = {
        "ec2_instances": [
            {
                "InstanceId": "i-abc123",
                "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/prof-a"},
            }
        ],
        "lambda_functions": [],
    }

    paths = skill._build_attack_paths(
        reachability_doc=reachability_doc,
        inspector_doc=inspector_doc,
        compute_inventory=compute_inventory,
    )
    assert len(paths) == 1
    assert paths[0]["vulnerability_score"] >= 0.55
    assert paths[0]["inspector_signal"]["internet_reachability_findings"] == 1
