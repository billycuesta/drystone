"""Configuration models for Drystone."""

from datetime import datetime
from pathlib import Path
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, validator


class WizardConfig(BaseModel):
    """Configuration from the interactive wizard."""

    # Step 1: Client/Project
    client_name: str = Field(..., description="Client or project name")

    # Step 2: AWS Access Key ID
    aws_access_key_id: str = Field(..., description="AWS Access Key ID")

    # Step 3: AWS Secret Access Key
    aws_secret_access_key: str = Field(..., description="AWS Secret Access Key")

    # Step 3.5: AWS Session Token (optional for temporary credentials)
    aws_session_token: Optional[str] = Field(
        default=None,
        description="AWS Session Token for temporary credentials (STS/AssumeRole)"
    )

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
        """Convert to JSON-serializable dict."""
        data = self.model_dump()
        data["created_at"] = self.created_at.isoformat()
        return data


class AuditConfig(WizardConfig):
    """Extended config for audit execution."""

    session_id: str = Field(..., description="Unique audit session ID")
    output_dir: Path = Field(..., description="Audit output directory")
    aws_account_id: str = Field(default="", description="AWS account ID")

    class Config:
        arbitrary_types_allowed = True
