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
