from drystone.analysis.distiller import distill_evidence
from drystone.analysis.prioritizer import score_chunk


def test_distiller_prunes_vpc_fields_and_size():
    evidence = {
        "vpcs": [
            {
                "VpcId": "vpc-1",
                "CidrBlock": "10.0.0.0/16",
                "IsDefault": False,
                "State": "available",
                "Tags": [{"Key": "Name", "Value": "prod"}],
                "OwnerId": "123456789012",
                "DhcpOptionsId": "dopt-1",
            }
            for _ in range(30)
        ]
    }

    distilled, stats = distill_evidence(evidence, max_list_items=10)
    assert stats["files_reduced"] == 1
    items = distilled["vpcs"]["items"]
    assert len(items) == 10
    assert "VpcId" in items[0]
    assert "DhcpOptionsId" not in items[0]


def test_prioritizer_prefers_security_critical_files():
    low = score_chunk("account-summary", {"account-summary": {"x": 1}})
    high = score_chunk("inspector-findings", {"inspector-findings": [{"severity": "CRITICAL"}]})
    assert high > low
