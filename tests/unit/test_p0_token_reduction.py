from drystone.agent.budget import get_budget_policy
from drystone.analysis.distiller import distill_evidence
from drystone.analysis.router import route_checklist_for_llm


def test_router_excludes_deterministic_checks():
    checklist = {
        "items": [
            {"id": "IAM-001"},
            {"id": "IAM-002"},
            {"id": "IAM-003"},
        ]
    }
    routed, stats = route_checklist_for_llm(checklist, {"IAM-001"}, {"IAM-002"})
    assert stats["total_checks"] == 3
    assert stats["deterministic_resolved"] == 2
    assert stats["llm_checks"] == 1
    assert routed["items"][0]["id"] == "IAM-003"


def test_distiller_truncates_long_lists():
    evidence = {
        "roles": [{"id": i} for i in range(50)],
        "_audit_metadata": {"_region": "us-east-1"},
    }
    distilled, stats = distill_evidence(evidence, max_list_items=10)
    assert stats["files_reduced"] == 1
    assert stats["items_removed"] == 40
    assert distilled["_audit_metadata"]["_region"] == "us-east-1"
    assert distilled["roles"]["_distilled"] is True
    assert len(distilled["roles"]["items"]) == 10


def test_distiller_prioritizes_active_inspector_findings():
    evidence = {
        "inspector-findings": [
            {"title": f"closed-{i}", "status": "CLOSED", "severity": "CRITICAL"}
            for i in range(20)
        ]
        + [
            {
                "title": "active-exploit",
                "status": "ACTIVE",
                "severity": "HIGH",
                "exploitAvailable": "YES",
                "fixAvailable": "YES",
                "resources": [{"id": "i-1", "type": "AWS_EC2_INSTANCE"}],
            }
        ]
    }

    distilled, _ = distill_evidence(evidence, max_list_items=5)

    kept = distilled["inspector-findings"]["items"]
    assert kept[0]["title"] == "active-exploit"
    assert kept[0]["status"] == "ACTIVE"
    assert kept[0]["resources"][0]["id"] == "i-1"


def test_distiller_compacts_inspector_finding_payloads():
    evidence = {
        "inspector-findings": [
            {
                "findingArn": "arn:aws:inspector2:us-east-1:123:finding/1",
                "status": "ACTIVE",
                "severity": "CRITICAL",
                "title": "CVE finding",
                "description": "d" * 1000,
                "remediation": {
                    "recommendation": "r" * 1000,
                    "url": "https://example.invalid/fix",
                },
                "resources": [
                    {"id": "i-1", "type": "AWS_EC2_INSTANCE", "details": {"large": "x" * 100}},
                    {"id": "i-2", "type": "AWS_EC2_INSTANCE", "details": {"large": "x" * 100}},
                    {"id": "i-3", "type": "AWS_EC2_INSTANCE"},
                ],
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": "CVE-2026-0001",
                    "source": "NVD",
                    "cvss": [{"baseScore": 9.8}, {"baseScore": 8.1}],
                    "vulnerablePackages": [
                        {
                            "name": f"pkg-{i}",
                            "version": "1.0",
                            "fixedInVersion": "1.1",
                            "packageManager": "OS",
                            "filePath": "/very/long/path",
                        }
                        for i in range(6)
                    ],
                },
                "unusedLargeField": "x" * 1000,
            }
        ]
    }

    distilled, stats = distill_evidence(evidence, max_list_items=20)

    assert stats["files_reduced"] == 0
    finding = distilled["inspector-findings"][0]
    assert len(finding["description"]) <= 243
    assert len(finding["remediation"]["recommendation"]) <= 243
    assert finding["remediation"]["url"] == "https://example.invalid/fix"
    assert len(finding["resources"]) == 2
    assert finding["resources"][0] == {"id": "i-1", "type": "AWS_EC2_INSTANCE"}
    details = finding["packageVulnerabilityDetails"]
    assert details["vulnerabilityId"] == "CVE-2026-0001"
    assert len(details["cvss"]) == 1
    assert len(details["vulnerablePackages"]) == 3
    assert "filePath" not in details["vulnerablePackages"][0]
    assert "unusedLargeField" not in finding


def test_budget_policy_by_provider():
    claude_cli = get_budget_policy("claude-cli", "iam")
    claude_api = get_budget_policy("claude-api", "iam")
    assert claude_cli.max_tokens_per_chunk < claude_api.max_tokens_per_chunk
    assert claude_cli.max_chunks <= claude_api.max_chunks


def test_budget_policy_changes_with_scan_depth():
    shallow = get_budget_policy("claude-cli", "vulns", "shallow")
    normal = get_budget_policy("claude-cli", "vulns", "normal")
    deep = get_budget_policy("claude-cli", "vulns", "deep")
    very_deep = get_budget_policy("claude-cli", "vulns", "very-deep")

    assert shallow.max_chunks <= normal.max_chunks <= deep.max_chunks <= very_deep.max_chunks
    assert (
        shallow.distill_max_list_items
        <= normal.distill_max_list_items
        <= deep.distill_max_list_items
        <= very_deep.distill_max_list_items
    )
