"""Configuration models for Drystone."""

from datetime import datetime
from pathlib import Path
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel, Field, validator


class WizardConfig(BaseModel):
    """Configuration from the interactive wizard."""

    # Step 1: Client/Project
    client_name: str = Field(..., description="Client or project name")

    # Step 2: AWS Credentials Source
    # OPCIÓN 1: Credenciales directas (manual entry, backward compat)
    aws_access_key_id: Optional[str] = Field(default=None, description="AWS Access Key ID")
    aws_secret_access_key: Optional[str] = Field(default=None, description="AWS Secret Access Key")
    aws_session_token: Optional[str] = Field(
        default=None,
        description="AWS Session Token for temporary credentials (STS/AssumeRole)"
    )
    # OPCIÓN 2: Custom credential file JSON (NEW)
    aws_credentials_file: Optional[Path] = Field(default=None, description="Path to AWS credentials file")

    # OPCIÓN 3: AWS profile estándar (NEW, revierte decisión anterior)
    aws_profile: Optional[str] = Field(default=None, description="AWS profile name")

    # Step 4: AWS Region
    aws_region: str = Field(default="us-east-1", description="AWS region")

    # Step 5: Skills to execute
    skills: List[str] = Field(
        default=["iam"],
        description="Security skills to execute (iam, exposure, network, vulns)"
    )

    # Step 6: Output formats
    output_formats: List[Literal["markdown", "json"]] = Field(
        default=["markdown"],
        description="Report output formats"
    )

    # Step 7: AI Provider for analysis
    ai_provider: Literal["claude-api", "claude-cli", "gemini-api", "bedrock"] = Field(
        default="claude-cli",
        description="AI provider for security analysis"
    )

    # Step 8: AI API Key (if needed)
    ai_api_key: Optional[str] = Field(
        default=None,
        description="API key for AI provider (if using API-based option)"
    )

    # Step 8.5: Bedrock AWS Credentials (separate from client credentials)
    bedrock_access_key_id: Optional[str] = Field(
        default=None,
        description="AWS Access Key ID for Bedrock (if using bedrock provider)"
    )

    bedrock_secret_access_key: Optional[str] = Field(
        default=None,
        description="AWS Secret Access Key for Bedrock"
    )

    bedrock_session_token: Optional[str] = Field(
        default=None,
        description="AWS Session Token for Bedrock (optional, for temporary credentials)"
    )
    
    # OPCIÓN 2: Custom credential file JSON (NEW)
    bedrock_credentials_file: Optional[Path] = Field(default=None, description="Path to Bedrock credentials file")

    # OPCIÓN 3: AWS profile estándar (NEW)
    bedrock_profile: Optional[str] = Field(default=None, description="Bedrock profile name")
    
    bedrock_use_same_credentials: bool = Field(default=False, description="Reuse AWS credentials for Bedrock")

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    non_interactive: bool = Field(default=False)

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "client_name": "ACME Corp",
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_session_token": None,
                "aws_region": "us-east-1",
                "skills": ["iam", "exposure"],
                "output_formats": ["markdown", "json"],
                "ai_provider": "bedrock",
                "ai_api_key": None,
                "bedrock_access_key_id": "AKIAIOSFODNN7BEDROCK",
                "bedrock_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "bedrock_session_token": None,
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
            raise ValueError(f"Credential file must contain a JSON object, got {type(data).__name__}: {expanded_path}")

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
    
    def get_bedrock_credentials(self) -> tuple[str, str, Optional[str]]:
        """Get Bedrock credentials with priority: manual > file > env."""

        # Option: Reuse AWS audit credentials for Bedrock
        if self.bedrock_use_same_credentials:
            return self.get_aws_credentials()

        # Priority 1: Manual entry (direct credentials)
        if self.bedrock_access_key_id and self.bedrock_secret_access_key:
            return (
                self.bedrock_access_key_id,
                self.bedrock_secret_access_key,
                self.bedrock_session_token,
            )

        # Priority 2: Credential file (custom JSON or AWS profile)
        if self.bedrock_credentials_file:
            return self._load_from_file(self.bedrock_credentials_file)

        if self.bedrock_profile:
            return self._load_from_aws_profile(profile_name=self.bedrock_profile)

        # Priority 3: Environment variables (fallback)
        if env_vars := self._check_bedrock_env_vars():
            return env_vars

        raise ValueError("No Bedrock credentials configured")

    def _check_bedrock_env_vars(self) -> Optional[tuple[str, str, Optional[str]]]:
        """Check for Bedrock credentials in environment variables."""
        import os

        # Try Bedrock-specific env vars first
        access_key = os.environ.get("BEDROCK_AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("BEDROCK_AWS_SECRET_ACCESS_KEY")

        if access_key and secret_key:
            return (access_key, secret_key, os.environ.get("BEDROCK_AWS_SESSION_TOKEN"))

        # Fallback: use standard AWS env vars
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
        valid_skills = {"iam", "exposure", "network", "vulns"}
        invalid = set(v) - valid_skills
        if invalid:
            raise ValueError(f"Invalid skills: {invalid}. Valid: {valid_skills}")
        if not v:
            raise ValueError("At least one skill must be selected")
        return v

    @validator("output_formats")
    def validate_formats(cls, v: List[str]) -> List[str]:
        """Validate output formats."""
        valid_formats = {"markdown", "json"}
        invalid = set(v) - valid_formats
        if invalid:
            raise ValueError(f"Invalid formats: {invalid}. Valid: {valid_formats}")
        if not v:
            raise ValueError("At least one output format must be selected")
        return v

    @validator("ai_api_key", pre=True, always=True)
    def validate_ai_api_key(cls, v: Optional[str], values: dict) -> Optional[str]:
        """Validate AI API key based on provider."""
        ai_provider = values.get("ai_provider")

        # If using API-based provider, key must be provided
        if ai_provider in ["claude-api", "gemini-api"]:
            if not v or not v.strip():
                raise ValueError(f"API key required for {ai_provider}")

        return v

    def dict_for_json(self) -> dict:
        """Convert to JSON-serializable dict, excluding sensitive credentials if not stored directly."""
        # Convert Path objects to strings for JSON serialization
        data = self.model_dump(mode='json')

        # If using a file, profile, or env vars for AWS, don't save direct keys
        # BUT keep the file/profile paths for reconfiguration
        if self.aws_credentials_file or self.aws_profile or not self.aws_access_key_id:
            data.pop("aws_access_key_id", None)
            data.pop("aws_secret_access_key", None)
            data.pop("aws_session_token", None)

        # Always preserve aws_credentials_file and aws_profile (they're not sensitive)
        # They will be None if not used, which is fine

        # If using a file, profile, env vars, or same-as-aws for Bedrock, don't save direct keys
        # BUT keep the file/profile paths for reconfiguration
        if (self.bedrock_credentials_file or self.bedrock_profile or self.bedrock_use_same_credentials or not self.bedrock_access_key_id):
            data.pop("bedrock_access_key_id", None)
            data.pop("bedrock_secret_access_key", None)
            data.pop("bedrock_session_token", None)

        # Always preserve bedrock_credentials_file and bedrock_profile (they're not sensitive)
        # They will be None if not used, which is fine

        data["created_at"] = self.created_at.isoformat()
        return data


class AuditConfig(WizardConfig):
    """Extended config for audit execution."""

    session_id: str = Field(..., description="Unique audit session ID")
    output_dir: Path = Field(..., description="Audit output directory")
    aws_account_id: str = Field(default="", description="AWS account ID")

    class Config:
        arbitrary_types_allowed = True
