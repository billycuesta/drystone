"""Finding models for AI agent analysis output."""

from datetime import datetime
from typing import List, Optional, Literal

from pydantic import BaseModel, Field


class PCIDSSControl(BaseModel):
    """PCI DSS control mapping for a finding."""

    control: str = Field(..., description="PCI DSS control ID (e.g., '8.4.1')")
    reason: str = Field(
        ..., description="Why this finding relates to this control"
    )


class Finding(BaseModel):
    """Individual security finding from agent analysis."""

    id: str = Field(..., description="Unique finding ID (e.g., IAM-001)")
    severity: Literal["Critical", "High", "Medium", "Low"] = Field(
        ..., description="Finding severity level"
    )
    risk_score: float = Field(
        ..., ge=0.0, le=10.0, description="Risk score 0.0-10.0"
    )
    title: str = Field(..., description="Brief finding title")
    description: str = Field(..., description="Detailed description of the finding")
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="References to evidence files (e.g., 'evidence/iam/users.json#root')",
    )
    affected_resources: List[str] = Field(
        default_factory=list, description="ARNs or identifiers of affected resources"
    )
    remediation: str = Field(
        ..., description="Specific remediation steps or recommendations"
    )
    cis_reference: Optional[str] = Field(
        None, description="CIS AWS Foundations reference (e.g., '1.5')"
    )
    pci_dss: List[PCIDSSControl] = Field(
        default_factory=list,
        description="PCI DSS controls related to this finding (v4.0)",
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "id": "IAM-001",
                "severity": "Critical",
                "risk_score": 9.5,
                "title": "Root account without MFA",
                "description": "Root account has no MFA devices configured...",
                "evidence_refs": ["evidence/iam/users.json#root"],
                "affected_resources": ["arn:aws:iam::123456789012:root"],
                "remediation": "Enable MFA on root account...",
                "cis_reference": "1.5",
                "pci_dss": [
                    {
                        "control": "8.4.1",
                        "reason": "This control requires MFA for all non-console administrative access into the CDE. The root user is the highest privileged account.",
                    }
                ],
            }
        }


class FindingsSummary(BaseModel):
    """Summary statistics for skill findings."""

    total_findings: int = Field(..., ge=0, description="Total number of findings")
    critical: int = Field(default=0, ge=0, description="Count of critical findings")
    high: int = Field(default=0, ge=0, description="Count of high findings")
    medium: int = Field(default=0, ge=0, description="Count of medium findings")
    low: int = Field(default=0, ge=0, description="Count of low findings")
    overall_risk_score: float = Field(
        default=0.0, ge=0.0, le=10.0, description="Average risk score across all findings"
    )

    class Config:
        """Pydantic config."""

        json_schema_extra = {
            "example": {
                "total_findings": 12,
                "critical": 2,
                "high": 5,
                "medium": 3,
                "low": 2,
                "overall_risk_score": 7.5,
            }
        }


class SkillFindings(BaseModel):
    """Complete findings from skill analysis."""

    skill: str = Field(..., description="Skill name (e.g., 'iam')")
    findings: List[Finding] = Field(
        default_factory=list, description="List of security findings"
    )
    summary: FindingsSummary = Field(..., description="Summary statistics")
    analyzed_at: datetime = Field(
        default_factory=datetime.utcnow, description="Analysis timestamp"
    )
    evidence_count: int = Field(..., ge=0, description="Number of evidence files analyzed")
    checklist_version: str = Field(
        default="1.0", description="Version of security checklist used"
    )

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat()}
        json_schema_extra = {
            "example": {
                "skill": "iam",
                "findings": [
                    {
                        "id": "IAM-001",
                        "severity": "Critical",
                        "risk_score": 9.5,
                        "title": "Root account without MFA",
                        "description": "...",
                        "evidence_refs": ["evidence/iam/users.json#root"],
                        "affected_resources": ["arn:aws:iam::123456789012:root"],
                        "remediation": "Enable MFA on root account",
                        "cis_reference": "1.5",
                    }
                ],
                "summary": {
                    "total_findings": 1,
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "overall_risk_score": 9.5,
                },
                "analyzed_at": "2026-01-18T20:30:00",
                "evidence_count": 7,
                "checklist_version": "1.0",
            }
        }
