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


# ── _record_component_status (P4/slice-4 batch A) ──────────────────────────


def test_record_component_status_ok_true_has_no_reason_code():
    components: dict = {}
    _DummySkill()._record_component_status(components, "users", ok=True)

    assert components == {"users": {"ok": True}}


def test_record_component_status_collection_failed_includes_error_details():
    components: dict = {}
    _DummySkill()._record_component_status(
        components,
        "users",
        ok=False,
        reason_code="collection_failed",
        error_code="AccessDenied",
        error="User is not authorized to perform: iam:ListUsers",
    )

    assert components == {
        "users": {
            "ok": False,
            "reason_code": "collection_failed",
            "error_code": "AccessDenied",
            "error": "User is not authorized to perform: iam:ListUsers",
        }
    }


def test_record_component_status_partial_collection():
    components: dict = {}
    _DummySkill()._record_component_status(
        components,
        "s3-buckets",
        ok=False,
        reason_code="partial_collection",
        error="2 bucket policies unreadable",
    )

    assert components == {
        "s3-buckets": {
            "ok": False,
            "reason_code": "partial_collection",
            "error": "2 bucket policies unreadable",
        }
    }


def test_record_component_status_ok_true_ignores_reason_code():
    """reason_code is only meaningful for failures; never leak it when ok=True."""
    components: dict = {}
    _DummySkill()._record_component_status(
        components, "roles", ok=True, reason_code="collection_failed"
    )

    assert components == {"roles": {"ok": True}}


def test_record_component_status_feeds_save_collection_status(tmp_path: Path):
    """Components recorded this way roll up into the aggregate ok/errors fields."""
    components: dict = {}
    skill = _DummySkill()
    skill._record_component_status(components, "users", ok=True)
    skill._record_component_status(
        components,
        "roles",
        ok=False,
        reason_code="collection_failed",
        error_code="AccessDenied",
        error="boom",
    )

    normalized = skill._save_collection_status(tmp_path, {"components": components})

    assert normalized["ok"] is False
    assert normalized["errors"] == {"components": {"roles": {"error": "boom"}}}
