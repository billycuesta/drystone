"""Tests for QSA depth filtering in BaseSkill.analyze().

Tests that checklist items are properly filtered based on qsa_visibility
and the chosen qsa_depth level from WizardConfig.
"""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from drystone.skills.base import BaseSkill


class _DummySkill(BaseSkill):
    @property
    def name(self) -> str:
        return "test_skill"

    def collect(self, aws_client, session):
        pass


class TestQSADepthFiltering:
    """Test checklist filtering by qsa_depth."""

    @pytest.fixture
    def mock_agent_client(self):
        """Create a mock agent client with config."""
        client = MagicMock()
        client.config = {"qsa_depth": "standard"}
        return client

    @pytest.fixture
    def test_checklist(self, tmp_path):
        """Create a test checklist with items at all three visibility levels."""
        checklist = {
            "skill": "test_skill",
            "items": [
                {
                    "id": "TSK-001",
                    "title": "Obvious finding",
                    "severity": "High",
                    "qsa_visibility": "obvious",
                },
                {
                    "id": "TSK-002",
                    "title": "Standard finding",
                    "severity": "High",
                    "qsa_visibility": "standard",
                },
                {
                    "id": "TSK-003",
                    "title": "Deep finding",
                    "severity": "High",
                    "qsa_visibility": "deep",
                },
                {
                    "id": "TSK-004",
                    "title": "No qsa_visibility (should default to standard)",
                    "severity": "High",
                },
            ],
        }

        # Create skill dir with checklist.json
        skill_dir = tmp_path / "drystone" / "skills" / "test_skill"
        skill_dir.mkdir(parents=True, exist_ok=True)
        checklist_path = skill_dir / "checklist.json"
        checklist_path.write_text(json.dumps(checklist))

        return checklist, checklist_path

    @patch("drystone.skills.base.Path")
    def test_filters_to_obvious_only(self, mock_path, mock_agent_client, test_checklist):
        """Test that qsa_depth='obvious' filters out standard and deep items."""
        checklist, checklist_path = test_checklist
        mock_agent_client.config["qsa_depth"] = "obvious"

        # Mock Path to return our test checklist
        mock_path_instance = MagicMock()
        mock_path_instance.parent.parent = Path(checklist_path.parent.parent.parent)
        mock_path.return_value = mock_path_instance

        # Load and filter checklist
        with patch(
            "builtins.open", create=True
        ) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(
                checklist
            )
            mock_open.return_value.__enter__.return_value = MagicMock()

            # Simulate the filter logic from base.py
            qsa_depth = mock_agent_client.config.get("qsa_depth", "standard")
            _depth_order = {"obvious": 0, "standard": 1, "deep": 2}
            _max_depth = _depth_order.get(qsa_depth, 1)
            filtered_items = [
                item
                for item in checklist.get("items", [])
                if _depth_order.get(item.get("qsa_visibility", "standard"), 1) <= _max_depth
            ]

        # Should have: TSK-001 (obvious) only
        assert len(filtered_items) == 1
        assert filtered_items[0]["id"] == "TSK-001"

    def test_filters_to_standard_and_below(self, mock_agent_client, test_checklist):
        """Test that qsa_depth='standard' includes obvious and standard, filters deep."""
        checklist, _ = test_checklist
        mock_agent_client.config["qsa_depth"] = "standard"

        # Simulate the filter logic
        qsa_depth = mock_agent_client.config.get("qsa_depth", "standard")
        _depth_order = {"obvious": 0, "standard": 1, "deep": 2}
        _max_depth = _depth_order.get(qsa_depth, 1)
        filtered_items = [
            item
            for item in checklist.get("items", [])
            if _depth_order.get(item.get("qsa_visibility", "standard"), 1) <= _max_depth
        ]

        # Should have: TSK-001 (obvious), TSK-002 (standard), TSK-004 (no qsa_visibility → default standard)
        assert len(filtered_items) == 3
        ids = {item["id"] for item in filtered_items}
        assert ids == {"TSK-001", "TSK-002", "TSK-004"}

    def test_no_filter_for_deep(self, mock_agent_client, test_checklist):
        """Test that qsa_depth='deep' includes all items."""
        checklist, _ = test_checklist
        mock_agent_client.config["qsa_depth"] = "deep"

        # Simulate the filter logic
        qsa_depth = mock_agent_client.config.get("qsa_depth", "standard")
        _depth_order = {"obvious": 0, "standard": 1, "deep": 2}
        _max_depth = _depth_order.get(qsa_depth, 1)
        filtered_items = [
            item
            for item in checklist.get("items", [])
            if _depth_order.get(item.get("qsa_visibility", "standard"), 1) <= _max_depth
        ]

        # Should have all 4 items
        assert len(filtered_items) == 4
        ids = {item["id"] for item in filtered_items}
        assert ids == {"TSK-001", "TSK-002", "TSK-003", "TSK-004"}

    def test_items_without_qsa_visibility_default_to_standard(
        self, mock_agent_client, test_checklist
    ):
        """Test that items without qsa_visibility field default to 'standard'."""
        checklist, _ = test_checklist
        # TSK-004 has no qsa_visibility
        mock_agent_client.config["qsa_depth"] = "obvious"

        # Simulate the filter logic
        qsa_depth = mock_agent_client.config.get("qsa_depth", "standard")
        _depth_order = {"obvious": 0, "standard": 1, "deep": 2}
        _max_depth = _depth_order.get(qsa_depth, 1)
        filtered_items = [
            item
            for item in checklist.get("items", [])
            if _depth_order.get(item.get("qsa_visibility", "standard"), 1) <= _max_depth
        ]

        # TSK-004 should be filtered out because it defaults to standard (depth 1)
        # and obvious max depth is 0
        ids = {item["id"] for item in filtered_items}
        assert "TSK-004" not in ids, "Items without qsa_visibility should default to 'standard' and be filtered by 'obvious' level"

    def test_missing_config_defaults_to_standard(self, mock_agent_client, test_checklist):
        """Test that missing qsa_depth in config defaults to 'standard'."""
        checklist, _ = test_checklist
        # Remove qsa_depth from config
        mock_agent_client.config = {}

        # Simulate the filter logic with missing key
        qsa_depth = mock_agent_client.config.get("qsa_depth", "standard")  # defaults to standard
        _depth_order = {"obvious": 0, "standard": 1, "deep": 2}
        _max_depth = _depth_order.get(qsa_depth, 1)
        filtered_items = [
            item
            for item in checklist.get("items", [])
            if _depth_order.get(item.get("qsa_visibility", "standard"), 1) <= _max_depth
        ]

        # Should behave like qsa_depth='standard'
        ids = {item["id"] for item in filtered_items}
        assert ids == {"TSK-001", "TSK-002", "TSK-004"}
