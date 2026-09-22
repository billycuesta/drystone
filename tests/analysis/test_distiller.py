# ruff: noqa: I001
"""Tests for evidence distillation with distilled file keys tracking."""

from drystone.analysis.distiller import distill_evidence


class TestDistilledFileKeysTracking:
    """Tests for tracking which file keys were distilled."""

    def test_distilled_file_keys_when_top_level_list_exceeds_max(self):
        """Verify distilled_file_keys includes key when top-level list exceeds max_list_items."""
        evidence = {"users": [{"name": f"user-{i}"} for i in range(30)]}
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert stats["files_reduced"] == 1
        assert stats["items_removed"] == 5
        assert "users" in stats["distilled_file_keys"]
        assert len(stats["distilled_file_keys"]) == 1

    def test_distilled_file_keys_when_nested_list_exceeds_max(self):
        """Verify distilled_file_keys includes key when nested list within dict exceeds max_list_items."""
        evidence = {
            "account": {
                "policies": [{"name": f"policy-{i}"} for i in range(30)],
                "metadata": "test",
            }
        }
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert stats["files_reduced"] == 1
        assert stats["items_removed"] == 5
        assert "account" in stats["distilled_file_keys"]
        assert len(stats["distilled_file_keys"]) == 1

    def test_distilled_file_keys_empty_when_no_distillation(self):
        """Verify distilled_file_keys is empty when no distillation occurs."""
        evidence = {
            "users": [{"name": f"user-{i}"} for i in range(10)],
            "roles": [{"name": f"role-{i}"} for i in range(5)],
        }
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert stats["files_reduced"] == 0
        assert stats["items_removed"] == 0
        assert stats["distilled_file_keys"] == []

    def test_distilled_file_keys_with_multiple_distilled_keys(self):
        """Verify distilled_file_keys includes multiple keys when multiple files are distilled."""
        evidence = {
            "users": [{"name": f"user-{i}"} for i in range(30)],
            "roles": [{"name": f"role-{i}"} for i in range(30)],
            "groups": [{"name": f"group-{i}"} for i in range(10)],
        }
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert stats["files_reduced"] == 2
        assert stats["items_removed"] == 10  # 5 from users + 5 from roles
        assert "users" in stats["distilled_file_keys"]
        assert "roles" in stats["distilled_file_keys"]
        assert "groups" not in stats["distilled_file_keys"]
        assert len(stats["distilled_file_keys"]) == 2

    def test_distilled_file_keys_with_both_top_level_and_nested_distillation(self):
        """Verify distilled_file_keys includes key only once when both top-level and nested lists are distilled."""
        evidence = {
            "users": [{"name": f"user-{i}"} for i in range(30)],
            "roles": {
                "policy_attachments": [{"arn": f"arn-{i}"} for i in range(30)],
                "name": "test-role",
            },
        }
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert stats["files_reduced"] == 2
        assert "users" in stats["distilled_file_keys"]
        assert "roles" in stats["distilled_file_keys"]
        # Should not have duplicates
        assert stats["distilled_file_keys"].count("users") == 1
        assert stats["distilled_file_keys"].count("roles") == 1

    def test_distilled_file_keys_with_metadata_not_included(self):
        """Verify distilled_file_keys only includes actual data keys, not metadata keys."""
        evidence = {
            "users": [{"name": f"user-{i}"} for i in range(30)],
            "_audit_metadata": {"collection_time": "2026-01-16"},
            "_account_id": "123456789",
        }
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert "users" in stats["distilled_file_keys"]
        assert "_audit_metadata" not in stats["distilled_file_keys"]
        assert "_account_id" not in stats["distilled_file_keys"]
        assert len(stats["distilled_file_keys"]) == 1

    def test_distilled_file_keys_preserves_order(self):
        """Verify distilled_file_keys preserves the order in which files were distilled."""
        evidence = {
            "alpha": [{"id": f"a-{i}"} for i in range(30)],
            "beta": [{"id": f"b-{i}"} for i in range(30)],
            "gamma": [{"id": f"g-{i}"} for i in range(30)],
        }
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert stats["distilled_file_keys"] == ["alpha", "beta", "gamma"]

    def test_stats_includes_distilled_file_keys_field(self):
        """Verify stats dict includes distilled_file_keys field in all cases."""
        evidence = {"users": [{"name": f"user-{i}"} for i in range(30)]}
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        assert "distilled_file_keys" in stats
        assert isinstance(stats["distilled_file_keys"], list)

    def test_stats_all_keys_present(self):
        """Verify stats dict includes all expected keys."""
        evidence = {"users": [{"name": f"user-{i}"} for i in range(30)]}
        distilled, stats = distill_evidence(evidence, max_list_items=25)

        required_keys = {"files_reduced", "items_removed", "distilled_file_keys"}
        assert required_keys.issubset(stats.keys())
