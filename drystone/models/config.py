"""Configuration models for Drystone."""

from datetime import datetime
from pathlib import Path
from typing import List, Literal

from pydantic import BaseModel, Field, validator


class WizardConfig(BaseModel):
    """Configuration from the interactive wizard."""

    # Step 1: Client/Project
    client_name: str = Field(..., description="Client or project name")

    # Step 2: AWS Profile
    aws_profile: str = Field(default="default", description="AWS profile to use")

    # Step 3: AWS Region
    aws_region: str = Field(default="us-east-1", description="AWS region")

    # Step 4: Skills to execute
    skills: List[str] = Field(
        default=["iam"],
        description="Security skills to execute (iam, exposure, network, vulns)"
    )

    # Step 5: Output formats
    output_formats: List[Literal["markdown", "html", "json"]] = Field(
        default=["markdown"],
        description="Report output formats"
    )

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    non_interactive: bool = Field(default=False)

    class Config:
        """Pydantic config."""
        json_schema_extra = {
            "example": {
                "client_name": "ACME Corp",
                "aws_profile": "production",
                "aws_region": "us-east-1",
                "skills": ["iam", "exposure"],
                "output_formats": ["markdown", "html"],
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
        valid_formats = {"markdown", "html", "json"}
        invalid = set(v) - valid_formats
        if invalid:
            raise ValueError(f"Invalid formats: {invalid}. Valid: {valid_formats}")
        if not v:
            raise ValueError("At least one output format must be selected")
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
