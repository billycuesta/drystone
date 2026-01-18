"""Base skill interface for AWS security audits."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from drystone.storage.session import AuditSession
from drystone.cloud.aws.client import AWSClient

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient


class BaseSkill(ABC):
    """Abstract base class for Drystone security skills.

    Subclasses must implement:
        - name: Property returning skill identifier
        - collect(): Method to collect AWS data and save evidence
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Skill name identifier (e.g., 'iam', 'exposure').

        Returns:
            Unique skill name
        """
        pass

    @abstractmethod
    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect AWS data and save to evidence directory.

        Called by the orchestrator to:
            1. Query AWS APIs using aws_client
            2. Structure the raw data
            3. Save JSON files to session.get_evidence_path(self.name)

        Args:
            aws_client: Authenticated AWS client with credentials
            session: Current audit session for evidence storage

        Raises:
            Exception: If AWS API calls fail or evidence cannot be saved
        """
        pass

    @abstractmethod
    def analyze(self, session: AuditSession, agent_client: "AgentClient") -> Path:
        """Analyze collected evidence using AI agent.

        Called by the orchestrator to:
            1. Read evidence from session.get_evidence_path(self.name)
            2. Read security checklist for this skill
            3. Call agent_client.analyze_evidence() with evidence and checklist
            4. Save findings to session.get_findings_path()/{skill_name}.json
            5. Return path to saved findings file

        Args:
            session: Current audit session with collected evidence
            agent_client: AI agent client for analysis

        Returns:
            Path to saved findings JSON file

        Raises:
            Exception: If evidence cannot be read, analysis fails, or findings cannot be saved
        """
        pass
