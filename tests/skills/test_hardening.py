"""Tests for HardeningSkill — collector and _save_json."""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.skills.hardening import HardeningSkill
from drystone.storage.session import AuditSession

# ── Exception stubs ───────────────────────────────────────────────────────────


class _InvalidAccessError(Exception):  # noqa: N818
    pass


class _NoSuchEntityError(Exception):  # noqa: N818
    pass


class _GenericAWSError(Exception):
    pass


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def skill():
    return HardeningSkill()


@pytest.fixture
def aws_client():
    c = Mock(spec=AWSClient)
    c.access_key_id = "AKIAIOSFODNN7EXAMPLE"
    c.secret_access_key = "wJalrXUtnFEMI/K7MDENG"
    c.session_token = None
    c.region_name = "us-east-1"
    return c


@pytest.fixture
def mock_session(tmp_path):
    session = Mock(spec=AuditSession)
    evidence_dir = tmp_path / "evidence" / "hardening"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    session.get_evidence_path.return_value = evidence_dir
    return session


# ── boto3 client factory ──────────────────────────────────────────────────────


def _make_sh_client(hub_enabled=True, findings=None, standards=None):
    """Build a minimal Security Hub mock."""
    mock = MagicMock()
    mock.exceptions.InvalidAccessException = _InvalidAccessError

    if hub_enabled:
        mock.describe_hub.return_value = {
            "HubArn": "arn:aws:securityhub:us-east-1:123:hub/default",
            "AutoEnableControls": True,
            "ControlFindingGenerator": "STANDARD_CONTROL",
        }
    else:
        mock.describe_hub.side_effect = _InvalidAccessError("not enabled")

    paginator = MagicMock()
    paginator.paginate.return_value = [{"Findings": findings or []}]
    mock.get_paginator.return_value = paginator

    mock.get_enabled_standards.return_value = {
        "StandardsSubscriptions": standards or [],
    }
    return mock


def _make_config_client(recorders=None):
    mock = MagicMock()
    mock.describe_configuration_recorders.return_value = {
        "ConfigurationRecorders": recorders or [{"name": "default"}]
    }
    mock.describe_delivery_channels.return_value = {"DeliveryChannels": []}
    mock.describe_configuration_recorder_status.return_value = {
        "ConfigurationRecordersStatus": [{"name": "default", "recording": True}]
    }
    mock.describe_config_rules.return_value = {"ConfigRules": []}
    mock.describe_conformance_packs.return_value = {"ConformancePackDetails": []}
    return mock


def _make_acm_client():
    mock = MagicMock()
    pag = MagicMock()
    pag.paginate.return_value = [{"CertificateSummaryList": []}]
    mock.get_paginator.return_value = pag
    return mock


def _make_guardduty_client(detector_ids=None):
    mock = MagicMock()
    mock.list_detectors.return_value = {"DetectorIds": detector_ids or []}
    return mock


def _make_macie_client(enabled=False):
    mock = MagicMock()
    if enabled:
        mock.get_macie_session.return_value = {"Status": "ENABLED"}
        mock.list_findings.return_value = {"findingIds": []}
    else:
        mock.get_macie_session.side_effect = _GenericAWSError("Macie not enabled")
    return mock


def _make_backup_client():
    mock = MagicMock()
    pag = MagicMock()
    pag.paginate.return_value = [{"BackupVaultList": []}]
    mock.get_paginator.return_value = pag
    mock.list_backup_plans.return_value = {"BackupPlansList": []}
    return mock


def _make_iam_client(no_password_policy=False):
    mock = MagicMock()
    mock.exceptions.NoSuchEntityException = _NoSuchEntityError
    mock.get_account_summary.return_value = {"SummaryMap": {}}
    mock.list_account_aliases.return_value = {"AccountAliases": []}
    if no_password_policy:
        mock.get_account_password_policy.side_effect = _NoSuchEntityError()
    else:
        mock.get_account_password_policy.return_value = {
            "PasswordPolicy": {"MinimumPasswordLength": 14}
        }
    return mock


def _boto3_factory(**overrides):
    """Return a side_effect function for patch('boto3.client')."""
    clients = {
        "securityhub": _make_sh_client(),
        "config": _make_config_client(),
        "acm": _make_acm_client(),
        "guardduty": _make_guardduty_client(),
        "macie2": _make_macie_client(),
        "backup": _make_backup_client(),
        "iam": _make_iam_client(),
    }
    clients.update(overrides)

    def _factory(service, **kwargs):
        return clients[service]

    return _factory


# ── Basic properties ──────────────────────────────────────────────────────────


class TestHardeningSkillProperties:
    def test_name(self, skill):
        assert skill.name == "hardening"

    def test_inherits_base_skill(self, skill):
        assert isinstance(skill, BaseSkill)


# ── _save_json ─────────────────────────────────────────────────────────────────


class TestSaveJson:
    def test_writes_json_file(self, skill, tmp_path):
        path = tmp_path / "test.json"
        skill._save_json(path, {"key": "value"})
        assert path.exists()
        data = json.loads(path.read_text())
        assert data == {"key": "value"}

    def test_handles_non_serializable_with_str_fallback(self, skill, tmp_path):
        from datetime import datetime

        path = tmp_path / "dt.json"
        skill._save_json(path, {"ts": datetime(2025, 1, 1)})
        data = json.loads(path.read_text())
        assert "2025-01-01" in data["ts"]

    def test_pretty_printed(self, skill, tmp_path):
        path = tmp_path / "pretty.json"
        skill._save_json(path, {"a": 1, "b": 2})
        content = path.read_text()
        # indent=2 means newlines are present
        assert "\n" in content

    def test_overwrites_existing_file(self, skill, tmp_path):
        path = tmp_path / "overwrite.json"
        path.write_text('{"old": true}')
        skill._save_json(path, {"new": True})
        data = json.loads(path.read_text())
        assert data == {"new": True}
        assert "old" not in data


# ── collect: happy path ───────────────────────────────────────────────────────


class TestCollectHappyPath:
    def test_evidence_path_requested(self, skill, aws_client, mock_session):
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        mock_session.get_evidence_path.assert_called_once_with("hardening")

    def test_security_hub_status_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "security-hub-status.json").exists()

    def test_security_hub_findings_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "security-hub-findings.json").exists()

    def test_security_hub_findings_summary_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "security-hub-findings-summary.json").exists()

    def test_security_hub_standards_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "security-hub-enabled-standards.json").exists()

    def test_config_recorders_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "config-recorders.json").exists()

    def test_guardduty_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "guardduty-detectors.json").exists()

    def test_macie_session_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "macie-session.json").exists()

    def test_collection_status_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "hardening-collection-status.json").exists()

    def test_audit_metadata_file_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "_audit_metadata.json").exists()

    def test_audit_metadata_contains_region(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        meta = json.loads((evidence_dir / "_audit_metadata.json").read_text())
        assert meta["_region"] == "us-east-1"
        assert meta["_skill"] == "hardening"

    def test_security_hub_enabled_flag_true(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        status = json.loads((evidence_dir / "security-hub-status.json").read_text())
        assert status["enabled"] is True

    def test_session_token_included_when_present(self, skill, aws_client, mock_session):
        aws_client.session_token = "mysessiontoken"
        captured = {}

        def _factory(service, **kwargs):
            captured[service] = kwargs
            return _boto3_factory()(service, **kwargs)

        with patch("boto3.client", side_effect=_factory):
            skill.collect(aws_client, mock_session)

        assert captured["securityhub"].get("aws_session_token") == "mysessiontoken"


# ── collect: Security Hub disabled (InvalidAccessException) ───────────────────


class TestCollectSecurityHubDisabled:
    def test_hub_status_enabled_false(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        sh_mock = _make_sh_client(hub_enabled=False)
        with patch("boto3.client", side_effect=_boto3_factory(securityhub=sh_mock)):
            skill.collect(aws_client, mock_session)
        status = json.loads((evidence_dir / "security-hub-status.json").read_text())
        assert status["enabled"] is False
        assert status["reason"] == "not_enabled"

    def test_files_still_written_when_hub_disabled(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        sh_mock = _make_sh_client(hub_enabled=False)
        with patch("boto3.client", side_effect=_boto3_factory(securityhub=sh_mock)):
            skill.collect(aws_client, mock_session)
        # Other evidence files should still be written
        assert (evidence_dir / "config-recorders.json").exists()


# ── collect: Security Hub complete failure ────────────────────────────────────


class TestCollectSecurityHubError:
    def test_collection_continues_after_sh_error(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        # Use _make_sh_client as base so pagination/standards mocks are properly configured.
        # An unconfigured MagicMock.get() returns a truthy MagicMock, causing an infinite loop.
        sh_mock = _make_sh_client()
        sh_mock.describe_hub.side_effect = _GenericAWSError("service unavailable")

        with patch("boto3.client", side_effect=_boto3_factory(securityhub=sh_mock)):
            skill.collect(aws_client, mock_session)

        # Config should still have been collected
        assert (evidence_dir / "config-recorders.json").exists()


# ── collect: Config service failures ─────────────────────────────────────────


class TestCollectConfigErrors:
    def test_recorder_status_error_recorded_in_collection_status(
        self, skill, aws_client, mock_session
    ):
        """describe_configuration_recorder_status failure updates collection_status['config']."""
        evidence_dir = mock_session.get_evidence_path.return_value
        cfg_mock = _make_config_client()
        cfg_mock.describe_configuration_recorder_status.side_effect = _GenericAWSError(
            "AccessDenied"
        )

        with patch("boto3.client", side_effect=_boto3_factory(config=cfg_mock)):
            skill.collect(aws_client, mock_session)

        status = json.loads((evidence_dir / "hardening-collection-status.json").read_text())
        assert status["config"]["ok"] is False

    def test_recorder_describe_error_saved_in_file(self, skill, aws_client, mock_session):
        """describe_configuration_recorders failure is persisted in config-recorders.json."""
        evidence_dir = mock_session.get_evidence_path.return_value
        cfg_mock = _make_config_client()
        cfg_mock.describe_configuration_recorders.side_effect = _GenericAWSError("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(config=cfg_mock)):
            skill.collect(aws_client, mock_session)

        recorders = json.loads((evidence_dir / "config-recorders.json").read_text())
        assert recorders["enabled"] is False
        assert "error" in recorders


# ── collect: GuardDuty detectors ─────────────────────────────────────────────


class TestCollectGuardDuty:
    def test_no_detectors_enabled_false(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        gd = json.loads((evidence_dir / "guardduty-detectors.json").read_text())
        assert gd["enabled"] is False
        assert gd["DetectorIds"] == []

    def test_with_detector_enabled_true(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        gd_mock = _make_guardduty_client(detector_ids=["abc123"])
        gd_mock.get_detector.return_value = {
            "Status": "ENABLED",
            "FindingPublishingFrequency": "SIX_HOURS",
        }
        gd_mock.list_findings.return_value = {"FindingIds": []}
        gd_mock.get_findings_statistics.return_value = {"FindingStatistics": {}}

        with patch("boto3.client", side_effect=_boto3_factory(guardduty=gd_mock)):
            skill.collect(aws_client, mock_session)

        gd = json.loads((evidence_dir / "guardduty-detectors.json").read_text())
        assert gd["enabled"] is True
        assert "abc123" in gd["DetectorIds"]

    def test_guardduty_list_error_saved(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        gd_mock = _make_guardduty_client()
        gd_mock.list_detectors.side_effect = _GenericAWSError("AccessDenied")

        with patch("boto3.client", side_effect=_boto3_factory(guardduty=gd_mock)):
            skill.collect(aws_client, mock_session)

        gd = json.loads((evidence_dir / "guardduty-detectors.json").read_text())
        assert gd["enabled"] is False
        assert "error" in gd


# ── collect: Macie ────────────────────────────────────────────────────────────


class TestCollectMacie:
    def test_macie_disabled_saved(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        macie = json.loads((evidence_dir / "macie-session.json").read_text())
        assert macie["enabled"] is False

    def test_macie_enabled_status(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        macie_mock = _make_macie_client(enabled=True)

        with patch("boto3.client", side_effect=_boto3_factory(macie2=macie_mock)):
            skill.collect(aws_client, mock_session)

        macie = json.loads((evidence_dir / "macie-session.json").read_text())
        assert macie["enabled"] is True


# ── collect: IAM account settings ────────────────────────────────────────────


class TestCollectIAMAccountSettings:
    def test_account_summary_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "account-summary.json").exists()

    def test_password_policy_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "password-policy.json").exists()

    def test_no_password_policy_written_as_error(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        iam_mock = _make_iam_client(no_password_policy=True)
        with patch("boto3.client", side_effect=_boto3_factory(iam=iam_mock)):
            skill.collect(aws_client, mock_session)
        policy = json.loads((evidence_dir / "password-policy.json").read_text())
        assert "error" in policy

    def test_account_aliases_written(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        with patch("boto3.client", side_effect=_boto3_factory()):
            skill.collect(aws_client, mock_session)
        assert (evidence_dir / "account-aliases.json").exists()


# ── collect: Security Hub findings with content ───────────────────────────────


class TestCollectSHFindingsContent:
    def _make_finding(self, severity_label="CRITICAL", compliance_status="FAILED"):
        return {
            "Id": "finding-001",
            "GeneratorId": "gen-001",
            "ProductName": "Security Hub",
            "Region": "us-east-1",
            "AwsAccountId": "123456789012",
            "CreatedAt": "2025-01-01",
            "Title": "Root MFA not enabled",
            "Description": "Root account has no MFA",
            "Severity": {"Label": severity_label, "Normalized": 90, "Original": "CRITICAL"},
            "Compliance": {"Status": compliance_status},
            "WorkflowState": "NEW",
            "RecordState": "ACTIVE",
            "Resources": [{"Type": "AwsAccount", "Id": "123", "Region": "us-east-1"}],
            "Remediation": {
                "Recommendation": {"Text": "Enable MFA", "Url": "https://docs.aws.amazon.com"}
            },
        }

    def test_findings_counted_in_summary(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        sh_mock = _make_sh_client(findings=[self._make_finding()])

        with patch("boto3.client", side_effect=_boto3_factory(securityhub=sh_mock)):
            skill.collect(aws_client, mock_session)

        summary = json.loads((evidence_dir / "security-hub-findings-summary.json").read_text())
        assert summary["total"] == 1
        assert summary["severity_counts"]["CRITICAL"] == 1

    def test_compliance_counted_in_summary(self, skill, aws_client, mock_session):
        evidence_dir = mock_session.get_evidence_path.return_value
        sh_mock = _make_sh_client(findings=[self._make_finding(compliance_status="FAILED")])

        with patch("boto3.client", side_effect=_boto3_factory(securityhub=sh_mock)):
            skill.collect(aws_client, mock_session)

        summary = json.loads((evidence_dir / "security-hub-findings-summary.json").read_text())
        assert summary["compliance_status_counts"]["FAILED"] == 1
