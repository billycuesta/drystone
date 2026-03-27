"""Tests for drystone CLI configuration management."""

import json
from unittest.mock import patch

import pytest

from drystone.cli.config import ensure_config_dir, load_last_config, save_config
from drystone.models.config import WizardConfig


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Patch CONFIG_DIR and LAST_RUN_FILE to an isolated temp directory."""
    config_dir = tmp_path / ".drystone"
    last_run = config_dir / "last-run.json"
    with (
        patch("drystone.cli.config.CONFIG_DIR", config_dir),
        patch("drystone.cli.config.LAST_RUN_FILE", last_run),
    ):
        yield config_dir, last_run


@pytest.fixture
def sample_config():
    return WizardConfig(
        client_name="ACME Corp",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        aws_region="us-east-1",
        skills=["iam"],
        output_formats=["markdown"],
        report_type="general",
    )


# ── ensure_config_dir ─────────────────────────────────────────────────────────


class TestEnsureConfigDir:
    def test_creates_directory_when_missing(self, tmp_config_dir):
        config_dir, _ = tmp_config_dir
        assert not config_dir.exists()
        ensure_config_dir()
        assert config_dir.exists()

    def test_does_not_raise_if_directory_already_exists(self, tmp_config_dir):
        config_dir, _ = tmp_config_dir
        config_dir.mkdir(parents=True)
        ensure_config_dir()  # Should not raise
        assert config_dir.exists()

    def test_creates_nested_parents(self, tmp_path):
        deep_dir = tmp_path / "a" / "b" / ".drystone"
        last_run = deep_dir / "last-run.json"
        with (
            patch("drystone.cli.config.CONFIG_DIR", deep_dir),
            patch("drystone.cli.config.LAST_RUN_FILE", last_run),
        ):
            ensure_config_dir()
        assert deep_dir.exists()


# ── save_config ───────────────────────────────────────────────────────────────


class TestSaveConfig:
    def test_returns_path_to_saved_file(self, tmp_config_dir, sample_config):
        _, last_run = tmp_config_dir
        result = save_config(sample_config)
        assert result == last_run

    def test_creates_file_on_disk(self, tmp_config_dir, sample_config):
        _, last_run = tmp_config_dir
        save_config(sample_config)
        assert last_run.exists()

    def test_creates_config_dir_if_missing(self, tmp_config_dir, sample_config):
        config_dir, _ = tmp_config_dir
        assert not config_dir.exists()
        save_config(sample_config)
        assert config_dir.exists()

    def test_saved_file_is_valid_json(self, tmp_config_dir, sample_config):
        _, last_run = tmp_config_dir
        save_config(sample_config)
        data = json.loads(last_run.read_text())
        assert isinstance(data, dict)
        assert data["client_name"] == "ACME Corp"

    def test_overwrites_existing_file(self, tmp_config_dir, sample_config):
        _, last_run = tmp_config_dir
        save_config(sample_config)
        sample_config.client_name = "Updated Corp"
        save_config(sample_config)
        data = json.loads(last_run.read_text())
        assert data["client_name"] == "Updated Corp"


# ── load_last_config ──────────────────────────────────────────────────────────


class TestLoadLastConfig:
    def test_returns_none_when_file_does_not_exist(self, tmp_config_dir):
        _, last_run = tmp_config_dir
        assert not last_run.exists()
        assert load_last_config() is None

    def test_returns_wizard_config_when_file_exists(self, tmp_config_dir, sample_config):
        save_config(sample_config)
        result = load_last_config()
        assert isinstance(result, WizardConfig)

    def test_returns_none_on_corrupted_json(self, tmp_config_dir, capsys):
        config_dir, last_run = tmp_config_dir
        config_dir.mkdir(parents=True)
        last_run.write_text("{ this is not valid json }")
        result = load_last_config()
        assert result is None

    def test_prints_warning_on_corrupted_json(self, tmp_config_dir, capsys):
        config_dir, last_run = tmp_config_dir
        config_dir.mkdir(parents=True)
        last_run.write_text("{ bad json }")
        load_last_config()
        captured = capsys.readouterr()
        assert "Could not load saved config" in captured.out

    def test_returns_none_on_invalid_config_values(self, tmp_config_dir):
        config_dir, last_run = tmp_config_dir
        config_dir.mkdir(parents=True)
        # Valid JSON but invalid WizardConfig (missing required client_name)
        last_run.write_text(json.dumps({"aws_region": "us-east-1"}))
        result = load_last_config()
        assert result is None


# ── round-trip ────────────────────────────────────────────────────────────────


class TestRoundTrip:
    def test_save_then_load_returns_equivalent_config(self, tmp_config_dir, sample_config):
        save_config(sample_config)
        loaded = load_last_config()
        assert loaded is not None
        assert loaded.client_name == sample_config.client_name
        assert loaded.aws_region == sample_config.aws_region
        assert loaded.skills == sample_config.skills
        assert loaded.output_formats == sample_config.output_formats
        assert loaded.report_type == sample_config.report_type

    def test_direct_credentials_preserved_in_round_trip(self, tmp_config_dir, sample_config):
        save_config(sample_config)
        loaded = load_last_config()
        assert loaded is not None
        assert loaded.aws_access_key_id == sample_config.aws_access_key_id
        assert loaded.aws_secret_access_key == sample_config.aws_secret_access_key

    def test_credentials_omitted_when_using_credentials_file(self, tmp_config_dir, tmp_path):
        creds_file = tmp_path / "creds.json"
        creds_file.write_text("{}")
        config = WizardConfig(
            client_name="ACME",
            aws_credentials_file=creds_file,
            aws_region="us-east-1",
            skills=["iam"],
        )
        save_config(config)
        _, last_run = tmp_config_dir
        data = json.loads(last_run.read_text())
        assert "aws_access_key_id" not in data
        assert "aws_secret_access_key" not in data

    def test_credentials_omitted_when_using_aws_profile(self, tmp_config_dir):
        config = WizardConfig(
            client_name="ACME",
            aws_profile="my-profile",
            aws_region="us-east-1",
            skills=["iam"],
        )
        save_config(config)
        _, last_run = tmp_config_dir
        data = json.loads(last_run.read_text())
        assert "aws_access_key_id" not in data
        assert "aws_secret_access_key" not in data
