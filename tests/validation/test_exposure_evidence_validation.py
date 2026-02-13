"""Tests for Exposure evidence-based validation and evidence_refs normalization."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer


EXPOSURE_CHECKLIST = {
    "skill": "exposure",
    "items": [
        {"id": "EXP-001", "severity": "Critical"},
        {"id": "EXP-002", "severity": "Critical"},
        {"id": "EXP-003", "severity": "Critical"},
        {"id": "EXP-007", "severity": "Critical"},
        {"id": "EXP-010", "severity": "High"},
        {"id": "EXP-011", "severity": "High"},
        {"id": "EXP-013", "severity": "High"},
        {"id": "EXP-014", "severity": "High"},
        {"id": "EXP-015", "severity": "High"},
    ],
}


def _finding(fid: str, sev: str = "Critical", rs: float = 9.0) -> Finding:
    return Finding(
        id=fid,
        severity=sev,
        risk_score=rs,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=[],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_exp_002_rejected_when_no_public_rds():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "rds-instances": {
            "items": [
                {
                    "DBInstanceIdentifier": "db1",
                    "PubliclyAccessible": False,
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}],
                }
            ]
        },
        "security-groups": {
            "items": [
                {
                    "GroupId": "sg-1",
                    "IngressRules": [
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
    }

    out = n.normalize([_finding("EXP-002")])
    assert out == []


def test_exp_002_accepted_when_public_rds_and_open_sg():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "rds-instances": {
            "items": [
                {
                    "DBInstanceIdentifier": "db1",
                    "PubliclyAccessible": True,
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}],
                }
            ]
        },
        "security-groups": {
            "items": [
                {
                    "GroupId": "sg-1",
                    "IngressRules": [
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
    }

    f = _finding("EXP-002")
    f.affected_resources = ["arn:aws:rds:us-east-1:111111111111:db:db1"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "EXP-002"


def test_exp_003_rejected_when_ssh_not_open_to_world():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "security-groups": {
            "items": [
                {
                    "GroupId": "sg-1",
                    "IngressRules": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "3.3.3.3/32"}],
                        }
                    ],
                }
            ]
        }
    }

    f = _finding("EXP-003")
    f.affected_resources = ["arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"]
    out = n.normalize([f])
    assert out == []


def test_exp_003_accepted_when_ssh_open_to_world_and_refs_normalized():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "security-groups": {
            "items": [
                {
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
            ],
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
            },
        }
    }

    f = _finding("EXP-003")
    f.affected_resources = ["arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"]
    f.evidence_refs = ["security-groups.json#sg-1"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].evidence_refs[0] == "security-groups.json#by_id.sg-1"


def test_exp_007_requires_specific_alb_arn():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "load-balancers": {
            "items": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/alb/123",
                    "Type": "application",
                    "Scheme": "internet-facing",
                }
            ],
            "by_id": {
                "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/alb/123": {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/alb/123",
                    "Type": "application",
                    "Scheme": "internet-facing",
                }
            },
        },
        "wafv2-web-acl-alb-associations": {"by_alb_arn": {}},
    }

    out = n.normalize([_finding("EXP-007")])
    assert out == []


def test_exp_007_accepted_for_internet_alb_without_waf():
    alb_arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/alb/123"
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "load-balancers": {
            "items": [
                {"LoadBalancerArn": alb_arn, "Type": "application", "Scheme": "internet-facing"}
            ]
        },
        "wafv2-web-acl-alb-associations": {"by_alb_arn": {}},
    }

    f = _finding("EXP-007")
    f.affected_resources = [alb_arn]
    out = n.normalize([f])
    assert len(out) == 1


def test_exp_010_rejected_when_no_obsolete_ssl_policy():
    alb_arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/alb/123"
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "load-balancers": {"items": [{"LoadBalancerArn": alb_arn, "Scheme": "internet-facing"}]},
        "load-balancer-listeners": {
            "items": [
                {
                    "LoadBalancerArn": alb_arn,
                    "Protocol": "HTTPS",
                    "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
                }
            ]
        },
    }

    out = n.normalize([_finding("EXP-010", sev="High", rs=7.0)])
    assert out == []


def test_exp_010_accepted_when_obsolete_ssl_policy():
    alb_arn = "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/alb/123"
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "load-balancers": {"items": [{"LoadBalancerArn": alb_arn, "Scheme": "internet-facing"}]},
        "load-balancer-listeners": {
            "items": [
                {
                    "LoadBalancerArn": alb_arn,
                    "Protocol": "HTTPS",
                    "SslPolicy": "ELBSecurityPolicy-2016-08",
                }
            ]
        },
    }

    f = _finding("EXP-010", sev="High", rs=7.0)
    f.affected_resources = [alb_arn]
    out = n.normalize([f])
    assert len(out) == 1


def test_exp_013_rejected_when_securetransport_deny_present():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "s3-buckets": {
            "items": [],
            "by_name": {
                "b": {
                    "Name": "b",
                    "BucketPolicy": {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                            }
                        ]
                    },
                }
            },
        }
    }
    f = _finding("EXP-013", sev="High", rs=7.0)
    f.affected_resources = ["arn:aws:s3:::b"]
    out = n.normalize([f])
    assert out == []


def test_exp_013_accepted_when_missing_securetransport_deny():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "s3-buckets": {
            "items": [],
            "by_name": {"b": {"Name": "b", "BucketPolicy": {"Statement": []}}},
        }
    }
    f = _finding("EXP-013", sev="High", rs=7.0)
    f.affected_resources = ["arn:aws:s3:::b"]
    out = n.normalize([f])
    assert len(out) == 1


def test_exp_014_rejected_when_versioning_enabled():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "s3-buckets": {
            "items": [],
            "by_name": {"b": {"Name": "b", "Versioning": "Enabled"}},
        }
    }
    f = _finding("EXP-014", sev="High", rs=7.0)
    f.affected_resources = ["arn:aws:s3:::b"]
    out = n.normalize([f])
    assert out == []


def test_exp_014_accepted_when_versioning_missing():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "s3-buckets": {
            "items": [],
            "by_name": {"b": {"Name": "b", "Versioning": None}},
        }
    }
    f = _finding("EXP-014", sev="High", rs=7.0)
    f.affected_resources = ["arn:aws:s3:::b"]
    out = n.normalize([f])
    assert len(out) == 1


def test_exp_001_rejected_when_bucket_not_public():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "_audit_metadata": {"_account_id": "111111111111"},
        "s3-buckets": {
            "items": [],
            "by_name": {
                "b": {
                    "Name": "b",
                    "ACL": [],
                    "BucketPolicy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111111111111:root"},
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::b/*",
                            }
                        ]
                    },
                }
            },
        },
    }

    f = _finding("EXP-001")
    f.affected_resources = ["arn:aws:s3:::b"]
    out = n.normalize([f])
    assert out == []


def test_exp_001_remaps_to_exp_015_for_cross_account_policy():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {
        "_audit_metadata": {"_account_id": "111111111111"},
        "s3-buckets": {
            "items": [],
            "by_name": {
                "b": {
                    "Name": "b",
                    "BucketPolicy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::b/*",
                            }
                        ]
                    },
                }
            },
        },
    }

    f = _finding("EXP-001")
    f.affected_resources = ["arn:aws:s3:::b", "arn:aws:iam::222222222222:root"]
    f.evidence_snippet = {
        "Name": "b",
        "BucketPolicy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::222222222222:root"},
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::b/*",
                }
            ]
        },
    }

    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "EXP-015"


def test_exposure_refs_by_name_are_normalized_to_s3_buckets_file():
    n = FindingsNormalizer(EXPOSURE_CHECKLIST, "exposure")
    n.evidence = {"s3-buckets": {"by_name": {"b": {"Name": "b"}}, "items": []}}
    f = _finding("EXP-013", sev="High", rs=7.0)
    f.affected_resources = ["arn:aws:s3:::b"]
    f.evidence_refs = ["by_name.b"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].evidence_refs[0] == "s3-buckets.json#by_name.b"
