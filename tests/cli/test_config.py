"""Tests for drystone CLI configuration management."""

import json
from unittest.mock import patch

import pytest

from drystone.cli.config import (
    _config_path_for_client,
    _slugify_client_name,
    ensure_config_dir,
    load_last_config,
    save_config,
)
from drystone.models.config import PENTEST_CORE_SKILLS, WizardConfig


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Patch CONFIG_DIR/CONFIGS_DIR/LAST_CLIENT_FILE to an isolated temp directory."""
    config_dir = tmp_path / ".drystone"
    configs_dir = config_dir / "configs"
    last_client = config_dir / "last-client.json"
    with (
        patch("drystone.cli.config.CONFIG_DIR", config_dir),
        patch("drystone.cli.config.CONFIGS_DIR", configs_dir),
        patch("drystone.cli.config.LAST_CLIENT_FILE", last_client),
    ):
        yield config_dir, configs_dir, last_client


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


# ── AI provider defaults ──────────────────────────────────────────────────────


class TestAIProviderDefaults:
    def test_defaults_to_claude_api(self):
        config = WizardConfig(
            client_name="ACME",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            aws_region="us-east-1",
            skills=["iam"],
        )
        assert config.ai_provider == "claude-api"

    def test_claude_cli_remains_explicit_opt_in(self):
        config = WizardConfig(
            client_name="ACME",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            aws_region="us-east-1",
            skills=["iam"],
            ai_provider="claude-cli",
        )
        assert config.ai_provider == "claude-cli"

    def test_claude_api_key_can_come_from_environment(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        config = WizardConfig(
            client_name="ACME",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            aws_region="us-east-1",
            skills=["iam"],
        )
        assert config.ai_api_key == "sk-ant-test"


# ── _slugify_client_name / _config_path_for_client ────────────────────────────


class TestSlugifyClientName:
    def test_simple_name_lowercased_untouched_case(self):
        assert _slugify_client_name("ACME") == "ACME"

    def test_spaces_become_underscores(self):
        assert _slugify_client_name("ACME Corp") == "ACME_Corp"

    def test_special_characters_stripped(self):
        assert _slugify_client_name("ACME & Co. / Ltd!") == "ACME_Co._Ltd"

    def test_empty_name_falls_back_to_placeholder(self):
        assert _slugify_client_name("   ") == "unnamed-client"

    def test_two_different_names_never_collide_into_the_same_slug(self):
        """The specific bug rec H exists to fix: two different clients must
        never end up sharing one saved config."""
        assert _slugify_client_name("ACME") != _slugify_client_name("ACME_Subsidiary")


class TestConfigPathForClient:
    def test_different_clients_get_different_paths(self, tmp_config_dir):
        _, configs_dir, _ = tmp_config_dir
        acme_path = _config_path_for_client("ACME")
        other_path = _config_path_for_client("OtherClient")
        assert acme_path != other_path
        assert acme_path.parent == configs_dir


# ── ensure_config_dir ─────────────────────────────────────────────────────────


class TestEnsureConfigDir:
    def test_creates_directory_when_missing(self, tmp_config_dir):
        _, configs_dir, _ = tmp_config_dir
        assert not configs_dir.exists()
        ensure_config_dir()
        assert configs_dir.exists()

    def test_does_not_raise_if_directory_already_exists(self, tmp_config_dir):
        _, configs_dir, _ = tmp_config_dir
        configs_dir.mkdir(parents=True)
        ensure_config_dir()  # Should not raise
        assert configs_dir.exists()

    def test_creates_nested_parents(self, tmp_path):
        deep_dir = tmp_path / "a" / "b" / ".drystone"
        configs_dir = deep_dir / "configs"
        with (
            patch("drystone.cli.config.CONFIG_DIR", deep_dir),
            patch("drystone.cli.config.CONFIGS_DIR", configs_dir),
        ):
            ensure_config_dir()
        assert configs_dir.exists()


# ── save_config ───────────────────────────────────────────────────────────────


class TestSaveConfig:
    def test_returns_path_under_configs_dir(self, tmp_config_dir, sample_config):
        _, configs_dir, _ = tmp_config_dir
        result = save_config(sample_config)
        assert result.parent == configs_dir
        assert result.exists()

    def test_creates_config_dir_if_missing(self, tmp_config_dir, sample_config):
        _, configs_dir, _ = tmp_config_dir
        assert not configs_dir.exists()
        save_config(sample_config)
        assert configs_dir.exists()

    def test_saved_file_is_valid_json(self, tmp_config_dir, sample_config):
        result = save_config(sample_config)
        data = json.loads(result.read_text())
        assert isinstance(data, dict)
        assert data["client_name"] == "ACME Corp"

    def test_overwrites_existing_file_for_same_client(self, tmp_config_dir, sample_config):
        result = save_config(sample_config)
        sample_config.skills = ["network"]
        save_config(sample_config)
        data = json.loads(result.read_text())
        assert data["skills"] == ["network"]

    def test_two_clients_get_two_separate_files_neither_overwritten(self, tmp_config_dir):
        acme = WizardConfig(client_name="ACME", aws_region="us-east-1", skills=["iam"])
        other = WizardConfig(client_name="OtherClient", aws_region="us-east-1", skills=["network"])

        acme_path = save_config(acme)
        other_path = save_config(other)

        assert acme_path != other_path
        assert json.loads(acme_path.read_text())["skills"] == ["iam"]
        assert json.loads(other_path.read_text())["skills"] == ["network"]

    def test_records_last_used_client(self, tmp_config_dir):
        _, _, last_client_file = tmp_config_dir
        save_config(WizardConfig(client_name="ACME", aws_region="us-east-1", skills=["iam"]))
        assert json.loads(last_client_file.read_text())["client_name"] == "ACME"

        save_config(
            WizardConfig(client_name="OtherClient", aws_region="us-east-1", skills=["network"])
        )
        assert json.loads(last_client_file.read_text())["client_name"] == "OtherClient"


# ── load_last_config ──────────────────────────────────────────────────────────


class TestLoadLastConfig:
    def test_returns_none_when_nothing_saved(self, tmp_config_dir):
        assert load_last_config() is None

    def test_returns_wizard_config_after_save(self, tmp_config_dir, sample_config):
        save_config(sample_config)
        result = load_last_config()
        assert isinstance(result, WizardConfig)

    def test_explicit_client_loads_that_clients_own_config_not_last_used(self, tmp_config_dir):
        """rec H: this is the actual bug fix -- a client's own saved settings
        (skills here) must not be silently overridden by whichever client
        happened to run most recently."""
        save_config(WizardConfig(client_name="ACME", aws_region="us-east-1", skills=["iam"]))
        save_config(
            WizardConfig(client_name="OtherClient", aws_region="us-east-1", skills=["network"])
        )

        result = load_last_config(client="ACME")

        assert result is not None
        assert result.client_name == "ACME"
        assert result.skills == ["iam"]

    def test_no_client_given_falls_back_to_most_recently_saved(self, tmp_config_dir):
        save_config(WizardConfig(client_name="ACME", aws_region="us-east-1", skills=["iam"]))
        save_config(
            WizardConfig(client_name="OtherClient", aws_region="us-east-1", skills=["network"])
        )

        result = load_last_config()

        assert result is not None
        assert result.client_name == "OtherClient"

    def test_unknown_client_returns_none(self, tmp_config_dir, sample_config):
        save_config(sample_config)
        assert load_last_config(client="NeverAuditedClient") is None

    def test_returns_none_on_corrupted_json(self, tmp_config_dir, sample_config):
        result = save_config(sample_config)
        result.write_text("{ this is not valid json }")
        assert load_last_config(client=sample_config.client_name) is None

    def test_prints_warning_on_corrupted_json(self, tmp_config_dir, sample_config, capsys):
        result = save_config(sample_config)
        result.write_text("{ bad json }")
        load_last_config(client=sample_config.client_name)
        captured = capsys.readouterr()
        assert "Could not load saved config" in captured.out

    def test_returns_none_on_invalid_config_values(self, tmp_config_dir):
        _, configs_dir, _ = tmp_config_dir
        configs_dir.mkdir(parents=True)
        # Valid JSON but invalid WizardConfig (missing required client_name)
        (configs_dir / "Broken.json").write_text(json.dumps({"aws_region": "us-east-1"}))
        assert load_last_config(client="Broken") is None


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

    def test_direct_credentials_never_persisted(self, tmp_config_dir, sample_config):
        # Credentials must never be written to disk (security requirement)
        result = save_config(sample_config)
        data = json.loads(result.read_text())
        assert "aws_access_key_id" not in data
        assert "aws_secret_access_key" not in data
        assert "ai_api_key" not in data

    def test_credentials_omitted_when_using_credentials_file(self, tmp_config_dir, tmp_path):
        creds_file = tmp_path / "creds.json"
        creds_file.write_text("{}")
        config = WizardConfig(
            client_name="ACME",
            aws_credentials_file=creds_file,
            aws_region="us-east-1",
            skills=["iam"],
        )
        result = save_config(config)
        data = json.loads(result.read_text())
        assert "aws_access_key_id" not in data
        assert "aws_secret_access_key" not in data

    def test_credentials_omitted_when_using_aws_profile(self, tmp_config_dir):
        config = WizardConfig(
            client_name="ACME",
            aws_profile="my-profile",
            aws_region="us-east-1",
            skills=["iam"],
        )
        result = save_config(config)
        data = json.loads(result.read_text())
        assert "aws_access_key_id" not in data
        assert "aws_secret_access_key" not in data

    def test_assume_role_persists_non_secret_settings_only(self, tmp_config_dir):
        config = WizardConfig(
            client_name="ACME",
            aws_profile="my-profile",
            aws_region="us-east-1",
            skills=["iam"],
            aws_role_arn="arn:aws:iam::123456789012:role/Audit",
            aws_role_session_name="drystone-audit",
            aws_external_id="sensitive-external-id",
            aws_role_duration_seconds=1800,
        )
        result = save_config(config)
        data = json.loads(result.read_text())
        assert data["aws_role_arn"] == "arn:aws:iam::123456789012:role/Audit"
        assert data["aws_role_session_name"] == "drystone-audit"
        assert data["aws_role_duration_seconds"] == 1800
        assert "aws_external_id" not in data

    def test_pdf_branding_settings_persist(self, tmp_config_dir, tmp_path):
        client_logo = tmp_path / "client.png"
        firm_logo = tmp_path / "firm.png"
        client_logo.write_bytes(b"client-logo")
        firm_logo.write_bytes(b"firm-logo")
        config = WizardConfig(
            client_name="ACME",
            aws_profile="my-profile",
            aws_region="us-east-1",
            skills=["iam"],
            brand_accent_color="#2563eb",
            client_logo_path=client_logo,
            firm_logo_path=firm_logo,
        )
        save_config(config)
        loaded = load_last_config()
        assert loaded is not None
        assert loaded.brand_accent_color == "#2563eb"
        assert loaded.client_logo_path == client_logo
        assert loaded.firm_logo_path == firm_logo


# ── QSA Depth Tests ──────────────────────────────────────────────────────────


class TestQSADepth:
    def test_qsa_depth_defaults_to_standard(self, sample_config):
        """Verify qsa_depth field defaults to 'standard'."""
        assert sample_config.qsa_depth == "standard"

    def test_qsa_depth_accepts_obvious(self):
        """Verify qsa_depth accepts 'obvious' value."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            qsa_depth="obvious",
        )
        assert config.qsa_depth == "obvious"

    def test_qsa_depth_accepts_standard(self):
        """Verify qsa_depth accepts 'standard' value."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            qsa_depth="standard",
        )
        assert config.qsa_depth == "standard"

    def test_qsa_depth_accepts_deep(self):
        """Verify qsa_depth accepts 'deep' value."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            qsa_depth="deep",
        )
        assert config.qsa_depth == "deep"

    def test_qsa_depth_rejects_invalid_value(self):
        """Verify qsa_depth rejects invalid values."""
        with pytest.raises(Exception):  # Pydantic validation error
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["iam"],
                qsa_depth="invalid",
            )

    def test_qsa_depth_preserved_in_round_trip(self, tmp_config_dir):
        """Verify qsa_depth is preserved through save/load cycle."""
        config = WizardConfig(
            client_name="Test",
            aws_profile="my-profile",
            aws_region="us-east-1",
            skills=["iam"],
            qsa_depth="deep",
        )
        save_config(config)
        loaded = load_last_config()
        assert loaded is not None
        assert loaded.qsa_depth == "deep"


# ── WizardConfig Field Validators ────────────────────────────────────────────


class TestValidateRegion:
    """Test validate_region field validator."""

    def test_valid_region_passes(self):
        """Valid AWS region passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
        )
        assert config.aws_region == "us-east-1"

    def test_region_converted_to_lowercase(self):
        """Region is converted to lowercase."""
        config = WizardConfig(
            client_name="Test",
            aws_region="US-EAST-1",
            skills=["iam"],
        )
        assert config.aws_region == "us-east-1"

    def test_various_valid_regions(self):
        """Various valid AWS regions pass."""
        regions = ["eu-west-1", "ap-southeast-2", "ca-central-1"]
        for region in regions:
            config = WizardConfig(
                client_name="Test",
                aws_region=region,
                skills=["iam"],
            )
            assert config.aws_region == region

    def test_empty_region_rejected(self):
        """Empty region string is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="",
                skills=["iam"],
            )

    def test_none_region_rejected(self):
        """None region is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region=None,
                skills=["iam"],
            )


class TestValidateSkills:
    """Test validate_skills field validator."""

    def test_single_skill_iam_passes(self):
        """Single IAM skill passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
        )
        assert config.skills == ["iam"]

    def test_single_skill_exposure_passes(self):
        """Single exposure skill passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["exposure"],
        )
        assert config.skills == ["exposure"]

    def test_pentest_preset_expands_to_core_skills(self):
        """Pentest preset expands to core skills."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["pentest"],
        )
        # pentest should expand to PENTEST_CORE_SKILLS
        assert set(config.skills) == set(PENTEST_CORE_SKILLS)
        assert "pentest" not in config.skills

    def test_pentest_with_other_skills_rejected(self):
        """Pentest preset cannot be combined with other skills."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["pentest", "iam"],
            )

    def test_multiple_non_pentest_skills_rejected(self):
        """Multiple non-pentest skills are rejected (single-skill scans only)."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["iam", "exposure"],
            )

    def test_invalid_skill_rejected(self):
        """Invalid skill name is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["invalid_skill"],
            )

    def test_empty_skills_rejected(self):
        """Empty skills list is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=[],
            )


class TestValidateReportType:
    """Test validate_report_type field validator."""

    def test_general_report_type_passes(self):
        """General report type passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            report_type="general",
        )
        assert config.report_type == "general"

    def test_pci_dss_report_type_passes(self):
        """PCI DSS report type passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            report_type="pci-dss",
        )
        assert config.report_type == "pci-dss"

    def test_pentest_report_type_with_pentest_skills_passes(self):
        """Pentest report type with pentest skills passes."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["pentest"],
            report_type="pentest",
        )
        assert config.report_type == "pentest"

    def test_pentest_report_type_with_single_skill_rejected(self):
        """Pentest report type with non-pentest skills is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["iam"],
                report_type="pentest",
            )


class TestValidateFormats:
    """Test validate_formats field validator."""

    def test_markdown_format_passes(self):
        """Markdown format passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            output_formats=["markdown"],
        )
        assert config.output_formats == ["markdown"]

    def test_json_format_passes(self):
        """JSON format passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            output_formats=["json"],
        )
        assert config.output_formats == ["json"]

    def test_pdf_format_passes(self):
        """PDF format passes validation."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            output_formats=["pdf"],
        )
        assert config.output_formats == ["pdf"]

    def test_multiple_formats_pass(self):
        """Multiple valid formats pass."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            output_formats=["markdown", "json", "pdf"],
        )
        assert set(config.output_formats) == {"markdown", "json", "pdf"}

    def test_invalid_format_rejected(self):
        """Invalid format is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["iam"],
                output_formats=["invalid"],
            )

    def test_empty_formats_rejected(self):
        """Empty formats list is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["iam"],
                output_formats=[],
            )


class TestValidateApiKey:
    """Test validate_ai_api_key field validator."""

    def test_explicit_api_key_preserved(self):
        """Explicit API key is preserved."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            ai_api_key="sk-ant-explicit-key",
        )
        assert config.ai_api_key == "sk-ant-explicit-key"

    def test_whitespace_stripped_from_api_key(self):
        """Whitespace is stripped from API key."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            ai_api_key="  sk-ant-test-key  ",
        )
        assert config.ai_api_key == "sk-ant-test-key"

    def test_markdown_bullet_prefix_stripped(self):
        """Markdown bullet prefix is stripped (common copy/paste mistake)."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            ai_api_key="- sk-ant-key-from-markdown",
        )
        assert config.ai_api_key == "sk-ant-key-from-markdown"

    def test_markdown_bullet_with_whitespace_stripped(self):
        """Markdown bullet with whitespace is stripped."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            ai_api_key="-  sk-ant-key-with-spaces  ",
        )
        assert config.ai_api_key == "sk-ant-key-with-spaces"

    def test_api_key_from_environment_when_not_provided(self, monkeypatch):
        """API key is loaded from ANTHROPIC_API_KEY environment variable."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-env")
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            ai_api_key=None,
        )
        assert config.ai_api_key == "sk-ant-from-env"

    def test_explicit_key_preferred_over_environment(self, monkeypatch):
        """Explicit API key takes precedence over environment variable."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-env")
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            ai_api_key="sk-ant-explicit",
        )
        assert config.ai_api_key == "sk-ant-explicit"


class TestNormalizeScanDepth:
    """Test normalize_scan_depth field validator."""

    def test_shallow_depth_passes(self):
        """Shallow scan depth passes."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="shallow",
        )
        assert config.scan_depth == "shallow"

    def test_normal_depth_passes(self):
        """Normal scan depth passes."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="normal",
        )
        assert config.scan_depth == "normal"

    def test_deep_depth_passes(self):
        """Deep scan depth passes."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="deep",
        )
        assert config.scan_depth == "deep"

    def test_very_deep_depth_passes(self):
        """Very-deep scan depth passes."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="very-deep",
        )
        assert config.scan_depth == "very-deep"

    def test_uppercase_depth_normalized(self):
        """Uppercase scan depth is normalized to lowercase."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="NORMAL",
        )
        assert config.scan_depth == "normal"

    def test_legacy_spanish_superficial_alias(self):
        """Legacy Spanish 'superficial' maps to 'shallow'."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="superficial",
        )
        assert config.scan_depth == "shallow"

    def test_legacy_spanish_profundo_alias(self):
        """Legacy Spanish 'profundo' maps to 'deep'."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="profundo",
        )
        assert config.scan_depth == "deep"

    def test_legacy_spanish_muy_profundo_alias(self):
        """Legacy Spanish 'muy-profundo' maps to 'very-deep'."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
            scan_depth="muy-profundo",
        )
        assert config.scan_depth == "very-deep"

    def test_invalid_scan_depth_rejected(self):
        """Invalid scan depth is rejected."""
        with pytest.raises(Exception):
            WizardConfig(
                client_name="Test",
                aws_region="us-east-1",
                skills=["iam"],
                scan_depth="invalid",
            )

    def test_default_scan_depth_is_normal(self):
        """Default scan depth is 'normal' when not specified."""
        config = WizardConfig(
            client_name="Test",
            aws_region="us-east-1",
            skills=["iam"],
        )
        assert config.scan_depth == "normal"
