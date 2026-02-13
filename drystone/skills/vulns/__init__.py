"""Vulnerability management skill for AWS audit."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

import boto3

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient

logger = get_logger(__name__)


class VulnsSkill(BaseSkill):
    """Vulnerability management audit skill - analyzes Inspector and patch status."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "vulns"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect vulnerability management data from AWS account.

        Collects:
            - AWS Inspector v2 configuration and findings
            - EC2 instance patch status
            - Systems Manager patch baselines
            - EC2 vulnerability assessment data
            - Container image scanning results
            - Lambda function vulnerability status
            - RDS patch information

        Args:
            aws_client: Authenticated AWS client
            session: Audit session for evidence storage
        """
        client_kwargs = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        evidence_path = session.get_evidence_path(self.name)

        # === INSPECTOR V2 ===
        print("  Collecting AWS Inspector v2 data...")
        try:
            inspector_client = boto3.client("inspector2", **client_kwargs)

            # Get delegated admin account status
            try:
                delegated = inspector_client.describe_organization_configuration()
                self._save_json(evidence_path / "inspector-org-config.json", delegated)
            except Exception as e:
                logger.warning(f"Could not describe Inspector organization config: {e}")

            # List findings (filtered by severity: Critical, High, Medium)
            findings_list = []
            try:
                paginator = inspector_client.get_paginator("list_findings")

                # Filter criteria for Inspector v2 (only Critical, High)
                # Note: severity parameter uses CRITICAL, HIGH values
                # MEDIUM excluded to focus on critical/actionable findings
                filter_criteria = {
                    "severity": [
                        {"comparison": "EQUALS", "value": "CRITICAL"},
                        {"comparison": "EQUALS", "value": "HIGH"},
                    ]
                }

                for page in paginator.paginate(filterCriteria=filter_criteria):
                    raw_findings = page.get("findings", [])

                    # Post-process: simplify findings (remove verbose fields)
                    for finding in raw_findings:
                        # Remove verbose nested objects
                        finding.pop("packageVulnerabilityDetails", None)
                        finding.pop("networkReachabilityDetails", None)
                        finding.pop("codeVulnerabilityDetails", None)
                        finding.pop("inspectorScoreDetails", None)
                        finding.pop("epss", None)

                        # Simplify resources (keep only essential fields)
                        if "resources" in finding:
                            for resource in finding["resources"]:
                                resource.pop("details", None)  # Remove IPs, subnets, AMI IDs

                        # Remove timestamps (not critical for analysis)
                        finding.pop("firstObservedAt", None)
                        finding.pop("lastObservedAt", None)
                        finding.pop("updatedAt", None)

                    findings_list.extend(raw_findings)
            except Exception as e:
                logger.warning(f"Could not list Inspector findings: {e}")
                findings_list = []

            self._save_json(evidence_path / "inspector-findings.json", findings_list)
        except Exception as e:
            logger.error(f"Could not collect Inspector data: {e}")

        # === EC2 PATCH STATUS ===
        print("  Collecting EC2 patch compliance...")
        try:
            ec2_client = boto3.client("ec2", **client_kwargs)
            ssm_client = boto3.client("ssm", **client_kwargs)

            instances = ec2_client.describe_instances()
            patch_status_list = []

            for reservation in instances.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance.get("InstanceId")
                    instance_detail = {
                        "InstanceId": instance_id,
                        "InstanceType": instance.get("InstanceType"),
                        "Platform": instance.get("Platform", "linux"),
                        "State": instance.get("State", {}).get("Name"),
                        "Tags": instance.get("Tags", []),
                    }

                    # Get compliance status from Systems Manager
                    try:
                        compliance = ssm_client.describe_instance_information(
                            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
                        )
                        instance_detail["SSMStatus"] = compliance.get("InstanceInformationList", [])

                        # Get patch compliance details
                        patch_compliance = ssm_client.get_compliance_details_by_resource(
                            ResourceId=instance_id,
                            ResourceType="ManagedInstance",
                            ComplianceTypes=["PATCH"],
                        )
                        instance_detail["PatchCompliance"] = patch_compliance.get(
                            "ComplianceItems", []
                        )
                    except Exception as e:
                        logger.warning(
                            f"Could not get patch compliance for instance {instance_id}: {e}"
                        )
                        instance_detail["SSMStatus"] = []
                        instance_detail["PatchCompliance"] = []

                    patch_status_list.append(instance_detail)

            self._save_json(evidence_path / "ec2-patch-status.json", patch_status_list)
        except Exception as e:
            logger.error(f"Could not collect patch status: {e}")

        # === SYSTEMS MANAGER PATCH BASELINES ===
        print("  Collecting patch baselines...")
        try:
            ssm_client = boto3.client("ssm", **client_kwargs)
            baselines_list = []
            paginator = ssm_client.get_paginator("describe_patch_baselines")
            for page in paginator.paginate():
                for baseline in page.get("PatchBaselines", []):
                    baseline_detail = {
                        "BaselineId": baseline.get("BaselineId"),
                        "BaselineName": baseline.get("BaselineName"),
                        "OperatingSystemFamily": baseline.get("OperatingSystemFamily"),
                        "DefaultBaseline": baseline.get("DefaultBaseline"),
                    }

                    # Get baseline details
                    try:
                        details = ssm_client.get_patch_baseline(
                            BaselineId=baseline.get("BaselineId")
                        )
                        baseline_detail["Details"] = {
                            "ApprovalRules": details.get("ApprovalRules"),
                            "GlobalFilters": details.get("GlobalFilters"),
                            "ApprovedPatches": details.get("ApprovedPatches", []),
                            "RejectedPatches": details.get("RejectedPatches", []),
                        }
                    except Exception as e:
                        logger.warning(
                            f"Could not get details for patch baseline {baseline.get('BaselineId')}: {e}"
                        )
                        baseline_detail["Details"] = {}

                    baselines_list.append(baseline_detail)

            self._save_json(evidence_path / "patch-baselines.json", baselines_list)
        except Exception as e:
            logger.error(f"Could not collect patch baselines: {e}")

        # === RDS PATCH INFORMATION ===
        print("  Collecting RDS patch information...")
        try:
            rds_client = boto3.client("rds", **client_kwargs)
            rds_instances = rds_client.describe_db_instances()
            rds_patch_list = []

            for instance in rds_instances.get("DBInstances", []):
                rds_detail = {
                    "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                    "Engine": instance.get("Engine"),
                    "EngineVersion": instance.get("EngineVersion"),
                    "DBInstanceStatus": instance.get("DBInstanceStatus"),
                    "LatestRestorableTime": instance.get("LatestRestorableTime"),
                    "PendingModifiedValues": instance.get("PendingModifiedValues", {}),
                }

                try:
                    # Get upgrade details
                    upgradeable = rds_client.describe_db_engine_versions(
                        Engine=instance.get("Engine"),
                        EngineVersion=instance.get("EngineVersion"),
                    )
                    rds_detail["ValidUpgradeTarget"] = upgradeable.get("DBEngineVersions", [{}])[
                        0
                    ].get("ValidUpgradeTarget", [])
                except Exception as e:
                    logger.warning(
                        f"Could not describe DB engine versions for {instance.get('DBInstanceIdentifier')}: {e}"
                    )
                    rds_detail["ValidUpgradeTarget"] = []

                rds_patch_list.append(rds_detail)

            self._save_json(evidence_path / "rds-patch-info.json", rds_patch_list)
        except Exception as e:
            logger.error(f"Could not collect RDS patch info: {e}")

        # === ECR IMAGE SCANNING ===
        print("  Collecting ECR image scan results...")
        try:
            ecr_client = boto3.client("ecr", **client_kwargs)
            repositories = ecr_client.describe_repositories()
            ecr_images_list = []

            for repo in repositories.get("repositories", []):
                repo_name = repo.get("repositoryName")

                try:
                    images = ecr_client.describe_images(repositoryName=repo_name)
                    for image in images.get("imageDetails", []):
                        image_detail = {
                            "RepositoryName": repo_name,
                            "ImageId": image.get("imageId"),
                            "ImageSizeBytes": image.get("imageSizeBytes"),
                            "ImageScanStatus": image.get("imageScanStatus", {}),
                            "ImageScanFindingsSummary": image.get("imageScanFindingsSummary", {}),
                        }

                        # Get scan findings if available
                        if image.get("imageScanStatus", {}).get("status") == "COMPLETE":
                            try:
                                findings = ecr_client.describe_image_scan_findings(
                                    repositoryName=repo_name, imageId=image.get("imageId")
                                )
                                image_detail["ScanFindings"] = findings.get("imageScanFindings", {})
                            except Exception as e:
                                logger.warning(
                                    f"Could not get scan findings for image {image.get('imageId')}: {e}"
                                )
                                image_detail["ScanFindings"] = {}

                        ecr_images_list.append(image_detail)
                except Exception as e:
                    logger.warning(f"Could not describe images for repository {repo_name}: {e}")

            self._save_json(evidence_path / "ecr-image-scans.json", ecr_images_list)
        except Exception as e:
            logger.error(f"Could not collect ECR scan data: {e}")

        print(f"\n✅ Vulnerability collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def analyze(self, session: AuditSession, agent_client: "AgentClient") -> Path:
        """Analyze collected vulnerability evidence using Gemini API.

        1. Read all evidence files
        2. Read security checklist
        3. Send to Gemini API for analysis
        4. Save findings to findings/vulns.json
        5. Print summary

        Args:
            session: Audit session with collected evidence
            agent_client: Gemini AI client for analysis

        Returns:
            Path to saved findings JSON file

        Raises:
            Exception: If evidence cannot be read or analysis fails
        """
        print("  Reading evidence files...")

        # 1. Read all evidence files
        evidence_path = session.get_evidence_path(self.name)
        evidence = {}

        if not evidence_path.exists():
            raise FileNotFoundError(f"Evidence directory not found: {evidence_path}")

        for json_file in evidence_path.glob("*.json"):
            try:
                with open(json_file) as f:
                    evidence[json_file.stem] = json.load(f)
            except Exception as e:
                logger.warning(f"Could not read evidence file {json_file.name}: {e}")

        print(f"    Loaded {len(evidence)} evidence files")

        # 2. Read checklist
        checklist_path = Path(__file__).parent / "checklist.json"
        if not checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {checklist_path}")

        with open(checklist_path) as f:
            checklist = json.load(f)

        print(f"    Loaded {len(checklist['items'])} security checks")

        # 3. Call agent for analysis (with automatic chunking for large evidence)
        provider_name = agent_client.get_display_name()
        print(f"  Analyzing with {provider_name}...")
        findings = agent_client.analyze_evidence_chunked(
            skill_name=self.name, evidence=evidence, checklist=checklist
        )

        # 3a. Normalize findings (reduce variance between models)
        print("  Normalizing findings...")
        findings = self._normalize_findings(findings, checklist, evidence=evidence)

        # 4. Save findings
        findings_dir = session.get_findings_path()
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / f"{self.name}.json"

        with open(findings_path, "w") as f:
            json.dump(findings.model_dump(mode="json"), f, indent=2, default=str)

        # 5. Print summary
        print(f"\n✅ Analysis complete:")
        print(f"   Total findings: {findings.summary.total_findings}")
        print(f"   Critical: {findings.summary.critical}")
        print(f"   High: {findings.summary.high}")
        print(f"   Medium: {findings.summary.medium}")
        print(f"   Low: {findings.summary.low}")
        print(f"   Overall Risk: {findings.summary.overall_risk_score:.1f}/10")

        return findings_path


__all__ = ["VulnsSkill"]
