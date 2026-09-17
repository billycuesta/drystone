"""Tests for IAMSkill.collect() with mocked boto3.

Strategy (mirrors tests/skills/test_alerting_collect.py):
- Patch boto3.client with a factory dispatch function keyed by service name
- Use _make_paginator() helper to avoid unconfigured-MagicMock infinite-loop pitfalls
- Test: happy path (all evidence files written with expected structure/content)
- Test: each service's own try/except swallows its exception and collection
  continues for the other services
- Test: session_token branch adds aws_session_token to boto3 client kwargs

Note: collect() calls iam_client.list_roles() twice — once for the detailed
roles collection (wrapped in a broad `except Exception`) and once inside
_collect_assume_role_chains() (wrapped only in `except ClientError`). A plain
Mock with a fixed return_value satisfies both calls identically, so the
happy-path fixture is safe; error-resilience tests below avoid touching
list_roles() to sidestep this asymmetry (see class docstring below).

time.sleep is patched everywhere collect() is invoked: the credential report
polling loop sleeps 2s before every attempt (even the first, successful one),
and Access Advisor polling sleeps 0.5s per privileged role. Neither test
fixture below defines privileged roles (Admin/PowerUser attached policies),
so Access Advisor's inner loop never triggers, but the credential report
sleep always does.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from drystone.skills.iam import IAMSkill

# ── Exception stubs (mirrors tests/skills/test_hardening.py) ──────────────────


class _NoSuchEntityError(Exception):  # noqa: N818
    pass


# ── Low-level helpers ──────────────────────────────────────────────────────────


def _make_paginator(*pages):
    """Return a mock paginator whose .paginate() returns the given pages."""
    pag = MagicMock()
    pag.paginate.return_value = iter(pages)
    return pag


def _make_aws_client(access_key="AKID", secret="SECRET", region="us-east-1", token=None):
    client = MagicMock()
    client.access_key_id = access_key
    client.secret_access_key = secret
    client.region_name = region
    client.session_token = token
    return client


def _make_session(tmp_path, skill_name="iam", account_id="123456789012"):
    session = MagicMock()
    evidence_path = tmp_path / "evidence" / skill_name
    evidence_path.mkdir(parents=True)
    session.get_evidence_path.return_value = evidence_path
    session.account_id = account_id
    return session, evidence_path


# ── Per-service mock factories ────────────────────────────────────────────────


def _make_iam_client(with_password_policy=True):
    """IAM mock covering account info, users, groups, roles, policies, credential
    report, and instance profiles."""
    c = MagicMock()
    c.exceptions.NoSuchEntityException = _NoSuchEntityError

    c.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    c.list_account_aliases.return_value = {"AccountAliases": ["my-account"]}

    if with_password_policy:
        c.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 14}
        }
    else:
        c.get_account_password_policy.side_effect = _NoSuchEntityError()

    # Users
    c.list_users.return_value = {
        "Users": [
            {
                "UserName": "alice",
                "UserId": "AID123",
                "Arn": "arn:aws:iam::123456789012:user/alice",
                "CreateDate": "2026-01-01",
                "Path": "/",
            }
        ]
    }
    c.list_access_keys.return_value = {
        "AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE", "Status": "Active"}]
    }
    c.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": "2026-02-01"}
    }
    c.list_mfa_devices.return_value = {"MFADevices": []}
    c.list_user_policies.return_value = {"PolicyNames": []}
    c.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    c.list_groups_for_user.return_value = {"Groups": [{"GroupName": "admins"}]}

    # Groups
    c.list_groups.return_value = {
        "Groups": [
            {
                "GroupName": "admins",
                "GroupId": "GID123",
                "Arn": "arn:aws:iam::123456789012:group/admins",
                "CreateDate": "2026-01-01",
                "Path": "/",
            }
        ]
    }
    c.get_group.return_value = {"Users": [{"UserName": "alice"}]}
    c.list_attached_group_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]
    }
    c.list_group_policies.return_value = {"PolicyNames": []}

    # Roles
    c.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "app-role",
                "RoleId": "RID123",
                "Arn": "arn:aws:iam::123456789012:role/app-role",
                "CreateDate": "2026-01-01",
                "Path": "/",
                "AssumeRolePolicyDocument": {
                    "Statement": [{"Principal": {"Service": "ec2.amazonaws.com"}}]
                },
                "MaxSessionDuration": 3600,
            }
        ]
    }
    c.get_role.return_value = {"Role": {"RoleName": "app-role"}}
    c.list_attached_role_policies.return_value = {"AttachedPolicies": []}
    c.list_role_policies.return_value = {"PolicyNames": []}

    # Policies (customer-managed)
    c.list_policies.return_value = {
        "Policies": [
            {
                "PolicyName": "custom-policy",
                "PolicyId": "POL123",
                "Arn": "arn:aws:iam::123456789012:policy/custom-policy",
                "CreateDate": "2026-01-01",
                "UpdateDate": "2026-01-01",
                "AttachmentCount": 1,
            }
        ]
    }
    c.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    c.get_policy_version.return_value = {
        "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow"}]}}
    }

    # Credential report — succeeds on first poll
    c.generate_credential_report.return_value = {"State": "STARTED"}
    c.get_credential_report.return_value = {
        "Content": b"user,arn\nalice,arn:aws:iam::123456789012:user/alice\n"
    }

    # Instance profiles — empty, via paginator
    c.get_paginator.side_effect = lambda name: _make_paginator({"InstanceProfiles": []})

    return c


def _make_s3_client():
    c = MagicMock()
    c.list_buckets.return_value = {"Buckets": []}
    return c


def _make_lambda_client():
    c = MagicMock()
    c.get_paginator.return_value = _make_paginator({"Functions": []})
    return c


def _make_sqs_client():
    c = MagicMock()
    c.list_queues.return_value = {"QueueUrls": []}
    return c


def _make_sns_client():
    c = MagicMock()
    c.get_paginator.return_value = _make_paginator({"Topics": []})
    return c


def _make_organizations_client():
    c = MagicMock()
    c.get_paginator.return_value = _make_paginator({"Policies": []})
    return c


def _boto3_factory(**overrides):
    """Dispatch factory: returns the appropriate mock client by service name."""
    clients = {
        "iam": _make_iam_client(),
        "s3": _make_s3_client(),
        "lambda": _make_lambda_client(),
        "sqs": _make_sqs_client(),
        "sns": _make_sns_client(),
        "organizations": _make_organizations_client(),
    }
    clients.update(overrides)

    def _factory(service, **kwargs):
        return clients[service]

    return _factory


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def skill():
    return IAMSkill()


@pytest.fixture
def aws_client():
    return _make_aws_client()


@pytest.fixture(autouse=True)
def _no_sleep():
    """Avoid real delays from the credential-report polling loop and the
    Access Advisor polling loop inside collect()."""
    with patch("time.sleep"):
        yield


# ── Happy path ────────────────────────────────────────────────────────────────


class TestCollectHappyPath:
    def test_all_evidence_files_created(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        expected = [
            "account-summary.json",
            "account-aliases.json",
            "password-policy.json",
            "users.json",
            "groups.json",
            "roles.json",
            "policies.json",
            "assumeRole-chains.json",
            "resource-based-policies.json",
            "instance-profiles.json",
            "effective-scps.json",
        ]
        for fname in expected:
            assert (evidence_path / fname).exists(), f"Missing: {fname}"
        assert (evidence_path / "credential-report.csv").exists()

    def test_users_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "users.json").read_text())
        assert len(data) == 1
        user = data[0]
        assert user["UserName"] == "alice"
        assert len(user["AccessKeys"]) == 1
        assert user["AccessKeys"][0]["LastUsed"] == {"LastUsedDate": "2026-02-01"}
        assert user["MFADevices"] == []
        assert user["Groups"] == [{"GroupName": "admins"}]

    def test_groups_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "groups.json").read_text())
        assert len(data) == 1
        assert data[0]["GroupName"] == "admins"
        assert data[0]["Users"] == [{"UserName": "alice"}]
        assert data[0]["AttachedPolicies"] == [{"PolicyName": "AdministratorAccess"}]

    def test_roles_content_and_type_classification(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "roles.json").read_text())
        assert len(data) == 1
        assert data[0]["RoleName"] == "app-role"
        assert data[0]["RoleType"] == "CustomerCreated"

    def test_policies_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "policies.json").read_text())
        assert len(data) == 1
        assert data[0]["PolicyName"] == "custom-policy"
        assert data[0]["PolicyDocument"] == {"Statement": [{"Effect": "Allow"}]}

    def test_credential_report_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        content = (evidence_path / "credential-report.csv").read_text()
        assert "alice" in content

    def test_assume_role_chains_content(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "assumeRole-chains.json").read_text())
        assert data["error"] is None
        assert len(data["chains"]) == 1
        assert data["chains"][0]["RoleName"] == "app-role"
        assert data["chains"][0]["TrustedPrincipals"] == ["ec2.amazonaws.com"]

    def test_password_policy_missing_stores_error_marker(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        iam_no_policy = _make_iam_client(with_password_policy=False)
        with patch("boto3.client", side_effect=_boto3_factory(iam=iam_no_policy)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "password-policy.json").read_text())
        assert data == {"error": "No password policy configured"}


# ── Session token branch ──────────────────────────────────────────────────────


class TestSessionToken:
    def test_session_token_passed_to_boto3(self, skill, tmp_path):
        aws_client = _make_aws_client(token="STS-TOKEN-123")
        session, _ = _make_session(tmp_path)

        captured_kwargs = []

        def _tracking_factory(service, **kwargs):
            captured_kwargs.append(kwargs)
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_tracking_factory):
            skill.collect(aws_client, session)

        token_calls = [k for k in captured_kwargs if "aws_session_token" in k]
        assert len(token_calls) > 0
        assert token_calls[0]["aws_session_token"] == "STS-TOKEN-123"

    def test_no_session_token_not_in_kwargs(self, skill, tmp_path):
        aws_client = _make_aws_client(token=None)
        session, _ = _make_session(tmp_path)

        captured_kwargs = []

        def _tracking_factory(service, **kwargs):
            captured_kwargs.append(kwargs)
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_tracking_factory):
            skill.collect(aws_client, session)

        token_calls = [k for k in captured_kwargs if "aws_session_token" in k]
        assert len(token_calls) == 0


# ── Error resilience: each service's own try/except swallows its exception ───


class TestErrorResilience:
    def _collect_with_broken(self, skill, tmp_path, broken_service):
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        def _factory(service, **kwargs):
            if service == broken_service:
                raise Exception(f"{service} unavailable")
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            skill.collect(aws_client, session)  # Must not raise

        return evidence_path

    def test_iam_client_creation_failure_aborts_collection(self, skill, tmp_path):
        """If boto3.client('iam', ...) itself fails, collect() has nothing to
        work with and raises: there is no outer try/except around client
        creation. This documents that behavior rather than asserting resilience."""
        aws_client = _make_aws_client()
        session, _ = _make_session(tmp_path)

        def _factory(service, **kwargs):
            if service == "iam":
                raise Exception("iam unavailable")
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            with pytest.raises(Exception, match="iam unavailable"):
                skill.collect(aws_client, session)

    def _collect_with_client_error(self, skill, tmp_path, broken_service):
        """Like _collect_with_broken, but raises botocore ClientError instead
        of a generic Exception. Needed for services whose try/except inside
        _collect_resource_based_policies() catches ONLY ClientError (no
        generic Exception fallback) — see class docstring note below."""
        aws_client = _make_aws_client()
        session, evidence_path = _make_session(tmp_path)

        def _factory(service, **kwargs):
            if service == broken_service:
                raise ClientError(
                    {"Error": {"Code": "ServiceUnavailable", "Message": f"{service} unavailable"}},
                    "CreateClient",
                )
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            skill.collect(aws_client, session)  # Must not raise

        return evidence_path

    def test_s3_resource_policy_failure_swallowed(self, skill, tmp_path):
        """s3's block inside _collect_resource_based_policies() catches ONLY
        ClientError (no generic `except Exception` fallback) — a plain
        Exception there would propagate uncaught through collect() itself,
        since collect() does not wrap this call either. This is a real gap
        worth knowing about: production AWS errors do surface as ClientError,
        but any other failure mode (e.g. a bug, a network-layer exception)
        would crash the whole IAM collection instead of degrading gracefully."""
        evidence_path = self._collect_with_client_error(skill, tmp_path, "s3")
        assert (evidence_path / "users.json").exists()
        data = json.loads((evidence_path / "resource-based-policies.json").read_text())
        assert data["s3"] == []
        assert "s3:" in data["error"]

    def test_lambda_resource_policy_failure_swallowed(self, skill, tmp_path):
        """Same ClientError-only catch as s3 above (no generic Exception fallback)."""
        evidence_path = self._collect_with_client_error(skill, tmp_path, "lambda")
        assert (evidence_path / "roles.json").exists()
        data = json.loads((evidence_path / "resource-based-policies.json").read_text())
        assert data["lambda"] == []
        assert "lambda:" in data["error"]

    def test_organizations_failure_swallowed(self, skill, tmp_path):
        evidence_path = self._collect_with_broken(skill, tmp_path, "organizations")
        assert (evidence_path / "policies.json").exists()
        data = json.loads((evidence_path / "effective-scps.json").read_text())
        assert data["service_control_policies"] == []
        assert "organizations unavailable" in data["error"]


class TestSubCallResilience:
    def test_list_users_failure_writes_empty_list(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        iam = _make_iam_client()
        iam.list_users.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(iam=iam)):
            skill.collect(aws_client, session)  # Must not raise

        data = json.loads((evidence_path / "users.json").read_text())
        assert data == []

    def test_list_groups_failure_writes_empty_list(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        iam = _make_iam_client()
        iam.list_groups.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(iam=iam)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "groups.json").read_text())
        assert data == []

    def test_list_access_keys_failure_still_saves_user(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        iam = _make_iam_client()
        iam.list_access_keys.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(iam=iam)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "users.json").read_text())
        assert len(data) == 1
        assert data[0]["AccessKeys"] == []

    def test_list_mfa_devices_failure_still_saves_user(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        iam = _make_iam_client()
        iam.list_mfa_devices.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(iam=iam)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "users.json").read_text())
        assert len(data) == 1
        assert data[0]["MFADevices"] == []

    def test_get_policy_failure_still_saves_policy_stub(self, skill, aws_client, tmp_path):
        session, evidence_path = _make_session(tmp_path)
        iam = _make_iam_client()
        iam.get_policy.side_effect = Exception("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(iam=iam)):
            skill.collect(aws_client, session)

        data = json.loads((evidence_path / "policies.json").read_text())
        assert len(data) == 1
        assert "Policy" not in data[0]

    def test_credential_report_never_ready_does_not_raise(self, skill, aws_client, tmp_path):
        """get_credential_report keeps failing for all 5 attempts: collect()
        must swallow this and continue without writing the CSV."""
        session, evidence_path = _make_session(tmp_path)
        iam = _make_iam_client()
        iam.get_credential_report.side_effect = Exception("ReportInProgress")

        with patch("boto3.client", side_effect=_boto3_factory(iam=iam)):
            skill.collect(aws_client, session)  # Must not raise

        assert not (evidence_path / "credential-report.csv").exists()
        # Collection continues past the credential report step
        assert (evidence_path / "assumeRole-chains.json").exists()


def test_skill_name():
    assert IAMSkill().name == "iam"
