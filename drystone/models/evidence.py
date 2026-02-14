"""Data models for AWS evidence collection."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class IAMUser(BaseModel):
    """IAM User model with credential metadata."""

    user_name: str = Field(..., description="IAM user name")
    user_id: str = Field(..., description="AWS user ID")
    arn: str = Field(..., description="AWS ARN")
    create_date: datetime = Field(..., description="Creation timestamp")
    path: str = Field(default="/", description="IAM path")
    mfa_enabled: Optional[bool] = Field(default=None, description="MFA enabled")
    access_keys: List[dict] = Field(default_factory=list, description="Access keys")
    groups: List[str] = Field(default_factory=list, description="Group memberships")


class IAMRole(BaseModel):
    """IAM Role model."""

    role_name: str = Field(..., description="Role name")
    role_id: str = Field(..., description="Role ID")
    arn: str = Field(..., description="AWS ARN")
    create_date: datetime = Field(..., description="Creation timestamp")
    path: str = Field(default="/", description="IAM path")
    assume_role_policy: Optional[dict] = Field(default=None, description="Trust policy")


class IAMGroup(BaseModel):
    """IAM Group model."""

    group_name: str = Field(..., description="Group name")
    group_id: str = Field(..., description="Group ID")
    arn: str = Field(..., description="AWS ARN")
    create_date: datetime = Field(..., description="Creation timestamp")
    path: str = Field(default="/", description="IAM path")
    users: List[str] = Field(default_factory=list, description="User members")


class IAMPolicy(BaseModel):
    """IAM Policy model with document."""

    policy_name: str = Field(..., description="Policy name")
    policy_id: str = Field(..., description="Policy ID")
    arn: str = Field(..., description="AWS ARN")
    create_date: datetime = Field(..., description="Creation timestamp")
    update_date: Optional[datetime] = Field(default=None, description="Last update")
    attachment_count: int = Field(default=0, description="Number of attachments")
    policy_document: Optional[dict] = Field(default=None, description="Policy document")


class IAMEvidence(BaseModel):
    """Complete IAM evidence collection."""

    users: List[dict] = Field(default_factory=list, description="Raw IAM users")
    roles: List[dict] = Field(default_factory=list, description="Raw IAM roles")
    groups: List[dict] = Field(default_factory=list, description="Raw IAM groups")
    policies: List[dict] = Field(default_factory=list, description="Raw IAM policies")
    account_summary: Optional[dict] = Field(default=None, description="Account summary")
    password_policy: Optional[dict] = Field(default=None, description="Password policy")
    collected_at: datetime = Field(default_factory=datetime.now, description="Collection timestamp")

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat()}
