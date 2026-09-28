"""Tests for shared collection status normalization."""

from pathlib import Path

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession


class _DummySkill(BaseSkill):
    @property
    def name(self) -> str:
        return "dummy"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        raise NotImplementedError


def test_save_collection_status_adds_common_fields_and_preserves_legacy_keys(tmp_path: Path):
    status = {
        "region": "us-east-1",
        "component": {"ok": False, "error": "AccessDenied", "count": 0},
    }

    normalized = _DummySkill()._save_collection_status(tmp_path, status)

    assert normalized["_schema"] == "drystone.collection_status.v1"
    assert normalized["_skill"] == "dummy"
    assert normalized["region"] == "us-east-1"
    assert normalized["component"] == {"ok": False, "error": "AccessDenied", "count": 0}
    assert normalized["ok"] is False
    assert normalized["errors"] == {"component": {"error": "AccessDenied"}}
    assert (tmp_path / "dummy-collection-status.json").exists()


def test_save_collection_status_preserves_explicit_aggregate_fields(tmp_path: Path):
    status = {
        "region": "us-east-1",
        "ok": True,
        "errors": {"non_blocking": "AccessDeniedException"},
        "component": {"ok": False, "error": "AccessDenied"},
    }

    normalized = _DummySkill()._save_collection_status(tmp_path, status)

    assert normalized["ok"] is True
    assert normalized["errors"] == {"non_blocking": "AccessDeniedException"}


def test_save_collection_status_supports_custom_filename(tmp_path: Path):
    _DummySkill()._save_collection_status(tmp_path, {}, filename="custom-status.json")

    assert (tmp_path / "custom-status.json").exists()
