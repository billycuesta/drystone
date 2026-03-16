"""Configuration models for Drystone."""

from datetime import datetime
from pathlib import Path
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, validator

# Example credentials for documentation (NOT REAL)
# nosec B105 - Example credentials from AWS documentation, not real secrets
_EXAMPLE_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # nosec
_EXAMPLE_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # nosec


# Canonical pentest skill list — single source of truth for --skills=pentest
PENTEST_CORE_SKILLS = ["recon", "iam", "exposure", "network", "vulns", "secretsmanager"]


class WizardConfig(BaseModel):
    """Configuration from the interactive wizard."""

    # Step 1: Client/Project
    client_name: str = Field(..., description="Client or project name")

    # Step 2: AWS Credentials Source
    # OPCIÓN 1: Credenciales directas (manual entry, backward compat)
    aws_access_key_id: Optional[str] = Field(default=None, description="AWS Access Key ID")
    aws_secret_access_key: Optional[str] = Field(default=None, description="AWS Secret Access Key")
    aws_session_token: Optional[str] = Field(
        default=None, description="AWS Session Token for temporary credentials (STS/AssumeRole)"
    )
    # OPCIÓN 2: Custom credential file JSON (NEW)
    aws_credentials_file: Optional[Path] = Field(
        default=None, description="Path to AWS credentials file"
    )

    # OPCIÓN 3: AWS profile estándar (NEW, revierte decisión anterior)
    aws_profile: Optional[str] = Field(default=None, description="AWS profile name")

    # Step 4: AWS Region
    aws_region: str = Field(default="us-east-1", description="AWS region")

    # Step 5: Skills to execute
    skills: List[str] = Field(
        default=["iam"],
        description=(
            "Security skills to execute (iam, exposure, network, vulns, alerting, hardening, secretsmanager, waf)"
        ),
    )

    # Step 6: Output formats
    output_formats: List[Literal["markdown", "json", "pdf"]] = Field(
        default=["markdown"], description="Report output formats"
    )

    # Step 6.5: Report Type
    report_type: Literal["general", "pci-dss", "pentest"] = Field(
        default="general",
        description="Report type: general security report, PCI DSS compliance report, or pentest technical report",
    )

    # Step 7: AI Provider for analysis
    ai_provider: Literal["claude-api", "claude-cli"] = Field(
        default="claude-cli",
        description="AI provider for security analysis (claude-cli or claude-api)",
    )

    claude_cli_model: Literal["haiku", "sonnet", "opus"] = Field(
        default="haiku",
        description="Model alias for claude-cli provider",
    )

    # Step 8: AI API Key (if needed)
    ai_api_key: Optional[str] = Field(
        default=None, description="API key for AI provider (if using API-based option)"
    )

    # Step 6: Minimum severity to collect and report
    min_severity: Literal["low", "medium", "high", "critical"] = Field(
        default="medium",
        description="Minimum severity level for collected findings (filters out lower severities at collection time)",
    )

    scan_depth: Literal["shallow", "normal", "deep", "very-deep"] = Field(
        default="normal",
        description="Scan depth controlling chunk budget and analysis coverage",
    )

    # Report language
    report_language: Literal["en", "es"] = Field(
        default="en",
        description="Language used in generated reports",
    )

    # Client context file (optional, enriches reports with business context)
    client_context_file: Optional[Path] = Field(
        default=None,
        description="Path to client-context.md file for report enrichment",
    )

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    non_interactive: bool = Field(default=False)

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "client_name": "ACME Corp",
                "aws_access_key_id": _EXAMPLE_AWS_ACCESS_KEY,
                "aws_secret_access_key": _EXAMPLE_AWS_SECRET_KEY,
                "aws_session_token": None,
                "aws_region": "us-east-1",
                "skills": ["iam", "exposure"],
                "output_formats": ["markdown", "json"],
                "ai_provider": "claude-cli",
                "claude_cli_model": "haiku",
                "ai_api_key": None,
                "scan_depth": "normal",
                "created_at": "2026-01-17T10:30:00",
                "non_interactive": False,
            }
        }

    def get_aws_credentials(self) -> tuple[str, str, Optional[str]]:
        """Get credentials with priority: manual > file > env."""

        # Priority 1: Manual entry (direct credentials)
        if self.aws_access_key_id and self.aws_secret_access_key:
            return (self.aws_access_key_id, self.aws_secret_access_key, self.aws_session_token)

        # Priority 2: Credential file (custom JSON or AWS profile)
        if self.aws_credentials_file:
            return self._load_from_file(self.aws_credentials_file)

        if self.aws_profile:
            return self._load_from_aws_profile(self.aws_profile)

        # Priority 3: Environment variables (fallback)
        if env_vars := self._check_env_vars():
            return env_vars

        raise ValueError("No AWS credentials configured")

    def _load_from_file(self, file_path: Path) -> tuple[str, str, Optional[str]]:
        """Load credentials from custom JSON file."""
        import json

        if file_path is None:
            raise ValueError("Credential file path is None")

        expanded_path = Path(file_path).expanduser()
        if not expanded_path.exists():
            raise FileNotFoundError(f"Credential file not found: {expanded_path}")

        try:
            with open(expanded_path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Credential file is not valid JSON: {expanded_path}") from e
        except Exception as e:
            raise ValueError(f"Error reading credential file: {expanded_path}") from e

        if data is None:
            raise ValueError(f"Credential file contains null: {expanded_path}")

        if not isinstance(data, dict):
            raise ValueError(
                f"Credential file must contain a JSON object, got {type(data).__name__}: {expanded_path}"
            )

        if not data.get("aws_access_key_id"):
            raise ValueError(f"Credential file missing 'aws_access_key_id': {expanded_path}")

        if not data.get("aws_secret_access_key"):
            raise ValueError(f"Credential file missing 'aws_secret_access_key': {expanded_path}")

        return (
            data["aws_access_key_id"],
            data["aws_secret_access_key"],
            data.get("aws_session_token"),
        )

    def _load_from_aws_profile(self, profile_name: str) -> tuple[str, str, Optional[str]]:
        """Load credentials from ~/.aws/credentials profile."""
        import boto3

        session = boto3.Session(profile_name=profile_name)
        creds = session.get_credentials()

        if not creds:
            raise ValueError(f"No credentials found for profile: {profile_name}")

        return (creds.access_key, creds.secret_key, creds.token)

    def _check_env_vars(self) -> Optional[tuple[str, str, Optional[str]]]:
        """Check for AWS credentials in environment variables."""
        import os

        access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

        if access_key and secret_key:
            return (access_key, secret_key, os.environ.get("AWS_SESSION_TOKEN"))

        return None

    @validator("aws_region")
    def validate_region(cls, v: str) -> str:
        """Validate AWS region format."""
        if not v or not isinstance(v, str):
            raise ValueError("Region must be a non-empty string")
        return v.lower()

    @validator("skills")
    def validate_skills(cls, v: List[str]) -> List[str]:
        """Validate skill names."""
        # Meta-skill: pentest is an execution preset (not a collector/analyzer by itself).
        # Option 1 UX: selecting pentest excludes other skills and expands to core skills.
        if "pentest" in v:
            if len(v) > 1:
                raise ValueError("'pentest' skill cannot be combined with other skills")
            return list(PENTEST_CORE_SKILLS)

        pentest_core = PENTEST_CORE_SKILLS
        if len(v) > 1 and v != pentest_core:
            raise ValueError(
                "Single-skill scans only. Select one skill, or use 'pentest' preset for multi-skill execution."
            )

        valid_skills = {
            "recon",
            "iam",
            "exposure",
            "network",
            "vulns",
            "alerting",
            "hardening",
            "ecr",
            "secretsmanager",
            "waf",
            "pentest",
            "kms",
            "messaging",
            "cicd",
            "compute",
        }
        invalid = set(v) - valid_skills
        if invalid:
            raise ValueError(f"Invalid skills: {invalid}. Valid: {valid_skills}")
        if not v:
            raise ValueError("At least one skill must be selected")
        return v

    @validator("report_type")
    def validate_report_type(cls, v: str, values: dict) -> str:
        """Disallow pentest report unless pentest preset used.

        In the wizard, selecting the pentest preset expands skills to core skills and
        forces report_type='pentest'. This validator prevents manual combinations like
        report_type='pentest' with arbitrary skill sets.
        """

        if v == "pentest":
            skills = values.get("skills") or []
            # After validation, preset expands to core skills.
            if skills != ["recon", "iam", "exposure", "network", "vulns", "secretsmanager"]:
                raise ValueError(
                    "report_type='pentest' is only supported with the pentest preset (Recon+IAM+Exposure+Network+Vulns)"
                )
        return v

    @validator("output_formats")
    def validate_formats(cls, v: List[str]) -> List[str]:
        """Validate output formats."""
        valid_formats = {"markdown", "json", "pdf"}
        invalid = set(v) - valid_formats
        if invalid:
            raise ValueError(f"Invalid formats: {invalid}. Valid: {valid_formats}")
        if not v:
            raise ValueError("At least one output format must be selected")
        return v

    @validator("ai_api_key", pre=True, always=True)
    def validate_ai_api_key(cls, v: Optional[str], values: dict) -> Optional[str]:
        """Validate AI API key based on provider."""
        if isinstance(v, str):
            v = v.strip()
            # Common copy/paste mistake from markdown bullets: "- sk-..."
            if v.startswith("- "):
                v = v[2:].strip()

        ai_provider = values.get("ai_provider")

        # If using API-based provider, key must be provided
        if ai_provider in ["claude-api"]:
            if not v or not v.strip():
                raise ValueError(f"API key required for {ai_provider}")

        return v

    @validator("scan_depth", pre=True, always=True)
    def normalize_scan_depth(cls, v: Optional[str]) -> str:
        """Normalize scan depth values and support legacy Spanish values."""
        value = str(v or "normal").strip().lower()
        legacy_map = {
            "superficial": "shallow",
            "profundo": "deep",
            "muy-profundo": "very-deep",
        }
        value = legacy_map.get(value, value)
        allowed = {"shallow", "normal", "deep", "very-deep"}
        if value not in allowed:
            raise ValueError(f"Invalid scan_depth: {value}. Valid: {sorted(allowed)}")
        return value

    @property
    def _client_context(self):
        """Load and cache client context from file if configured."""
        if not hasattr(self, "_cached_client_context"):
            if self.client_context_file:
                try:
                    from drystone.models.client_context import ClientContext

                    self._cached_client_context = ClientContext.from_file(self.client_context_file)
                except Exception:
                    self._cached_client_context = None
            else:
                self._cached_client_context = None
        return self._cached_client_context

    def dict_for_json(self) -> dict:
        """Convert to JSON-serializable dict, excluding sensitive credentials if not stored directly."""
        # Convert Path objects to strings for JSON serialization
        data = self.model_dump(mode="json")

        # If using a file, profile, or env vars for AWS, don't save direct keys
        # BUT keep the file/profile paths for reconfiguration
        if self.aws_credentials_file or self.aws_profile or not self.aws_access_key_id:
            data.pop("aws_access_key_id", None)
            data.pop("aws_secret_access_key", None)
            data.pop("aws_session_token", None)

        # Always preserve aws_credentials_file and aws_profile (they're not sensitive)
        # They will be None if not used, which is fine

        data["created_at"] = self.created_at.isoformat()
        return data


class AuditConfig(WizardConfig):
    """Extended config for audit execution."""

    session_id: str = Field(..., description="Unique audit session ID")
    output_dir: Path = Field(..., description="Audit output directory")
    aws_account_id: str = Field(default="", description="AWS account ID")

    model_config = ConfigDict(arbitrary_types_allowed=True)
