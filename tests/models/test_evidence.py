"""Tests for AWS evidence data models."""

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from drystone.models.evidence import (
    IAMEvidence,
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMUser,
)

NOW = datetime(2026, 1, 1, 12, 0, 0)


# ── IAMUser ───────────────────────────────────────────────────────────────────


class TestIAMUser:
    def test_valid_minimal_user(self):
        user = IAMUser(
            user_name="alice",
            user_id="AIDIOSFODNN7EXAMPLE",
            arn="arn:aws:iam::123456789012:user/alice",
            create_date=NOW,
        )
        assert user.user_name == "alice"
        assert user.path == "/"
        assert user.mfa_enabled is None
        assert user.access_keys == []
        assert user.groups == []

    def test_required_fields_missing_raises(self):
        with pytest.raises(ValidationError):
            IAMUser(user_name="alice")  # missing user_id, arn, create_date

    def test_mfa_enabled_flag(self):
        user = IAMUser(
            user_name="alice",
            user_id="ID1",
            arn="arn:aws:iam::123:user/alice",
            create_date=NOW,
            mfa_enabled=True,
        )
        assert user.mfa_enabled is True

    def test_access_keys_and_groups_populated(self):
        user = IAMUser(
            user_name="alice",
            user_id="ID1",
            arn="arn:aws:iam::123:user/alice",
            create_date=NOW,
            access_keys=[{"AccessKeyId": "AKIA...", "Status": "Active"}],
            groups=["Admins", "Developers"],
        )
        assert len(user.access_keys) == 1
        assert user.groups == ["Admins", "Developers"]

    def test_custom_path(self):
        user = IAMUser(
            user_name="svc",
            user_id="ID2",
            arn="arn:aws:iam::123:user/svc",
            create_date=NOW,
            path="/service-accounts/",
        )
        assert user.path == "/service-accounts/"


# ── IAMRole ───────────────────────────────────────────────────────────────────


class TestIAMRole:
    def test_valid_minimal_role(self):
        role = IAMRole(
            role_name="LambdaExec",
            role_id="AROAIOSFODNN7EXAMPLE",
            arn="arn:aws:iam::123456789012:role/LambdaExec",
            create_date=NOW,
        )
        assert role.role_name == "LambdaExec"
        assert role.path == "/"
        assert role.assume_role_policy is None

    def test_required_fields_missing_raises(self):
        with pytest.raises(ValidationError):
            IAMRole(role_name="X")

    def test_assume_role_policy_stored(self):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}}],
        }
        role = IAMRole(
            role_name="LambdaExec",
            role_id="ID1",
            arn="arn:aws:iam::123:role/LambdaExec",
            create_date=NOW,
            assume_role_policy=trust_policy,
        )
        assert role.assume_role_policy["Version"] == "2012-10-17"


# ── IAMGroup ──────────────────────────────────────────────────────────────────


class TestIAMGroup:
    def test_valid_minimal_group(self):
        group = IAMGroup(
            group_name="Admins",
            group_id="AGPAIOSFODNN7EXAMPLE",
            arn="arn:aws:iam::123456789012:group/Admins",
            create_date=NOW,
        )
        assert group.group_name == "Admins"
        assert group.users == []

    def test_required_fields_missing_raises(self):
        with pytest.raises(ValidationError):
            IAMGroup(group_name="Admins")

    def test_users_list_populated(self):
        group = IAMGroup(
            group_name="Admins",
            group_id="ID1",
            arn="arn:aws:iam::123:group/Admins",
            create_date=NOW,
            users=["alice", "bob"],
        )
        assert group.users == ["alice", "bob"]


# ── IAMPolicy ─────────────────────────────────────────────────────────────────


class TestIAMPolicy:
    def test_valid_minimal_policy(self):
        policy = IAMPolicy(
            policy_name="ReadOnlyAccess",
            policy_id="ANPAIOSFODNN7EXAMPLE",
            arn="arn:aws:iam::aws:policy/ReadOnlyAccess",
            create_date=NOW,
        )
        assert policy.attachment_count == 0
        assert policy.policy_document is None
        assert policy.update_date is None

    def test_required_fields_missing_raises(self):
        with pytest.raises(ValidationError):
            IAMPolicy(policy_name="X")

    def test_policy_document_stored(self):
        doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*"}]}
        policy = IAMPolicy(
            policy_name="AdminAccess",
            policy_id="ID1",
            arn="arn:aws:iam::aws:policy/AdminAccess",
            create_date=NOW,
            policy_document=doc,
        )
        assert policy.policy_document["Version"] == "2012-10-17"

    def test_attachment_count_and_update_date(self):
        policy = IAMPolicy(
            policy_name="X",
            policy_id="ID1",
            arn="arn:aws:iam::123:policy/X",
            create_date=NOW,
            update_date=datetime(2026, 6, 1),
            attachment_count=5,
        )
        assert policy.attachment_count == 5
        assert policy.update_date == datetime(2026, 6, 1)


# ── IAMEvidence ───────────────────────────────────────────────────────────────


class TestIAMEvidence:
    def test_empty_evidence_uses_defaults(self):
        ev = IAMEvidence()
        assert ev.users == []
        assert ev.roles == []
        assert ev.groups == []
        assert ev.policies == []
        assert ev.account_summary is None
        assert ev.password_policy is None
        assert isinstance(ev.collected_at, datetime)

    def test_populated_evidence(self):
        ev = IAMEvidence(
            users=[{"UserName": "alice"}],
            roles=[{"RoleName": "Lambda"}],
            groups=[{"GroupName": "Admins"}],
            policies=[{"PolicyName": "ReadOnly"}],
            account_summary={"UsersQuota": 5000},
            password_policy={"MinimumPasswordLength": 14},
        )
        assert len(ev.users) == 1
        assert ev.account_summary["UsersQuota"] == 5000
        assert ev.password_policy["MinimumPasswordLength"] == 14

    def test_json_serialization_roundtrip(self):
        ev = IAMEvidence(
            users=[{"UserName": "alice"}],
            collected_at=NOW,
        )
        serialized = json.loads(ev.model_dump_json())
        assert serialized["users"][0]["UserName"] == "alice"
        assert "collected_at" in serialized

    def test_collected_at_is_iso_format_in_json(self):
        ev = IAMEvidence(collected_at=NOW)
        serialized = json.loads(ev.model_dump_json())
        # Should be a valid ISO string, not a raw datetime object
        assert isinstance(serialized["collected_at"], str)
        datetime.fromisoformat(serialized["collected_at"])  # must not raise
