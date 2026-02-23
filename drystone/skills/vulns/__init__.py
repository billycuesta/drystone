"""Vulnerability management skill for AWS audit."""

import base64
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

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
                err = str(e)
                if "AccessDeniedException" in err:
                    logger.info(
                        "Inspector organization config not accessible (expected for non-org/delegated accounts)"
                    )
                else:
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
                        try:
                            patch_compliance = ssm_client.get_compliance_details_by_resource(
                                ResourceId=instance_id,
                                ResourceType="ManagedInstance",
                                ComplianceTypes=["PATCH"],
                            )
                            instance_detail["PatchCompliance"] = patch_compliance.get(
                                "ComplianceItems", []
                            )
                        except AttributeError:
                            # Older boto3/botocore may not expose this API.
                            # Fallback to list_compliance_items.
                            patch_compliance = ssm_client.list_compliance_items(
                                ResourceIds=[instance_id],
                                ResourceTypes=["ManagedInstance"],
                                Filters=[{"Key": "ComplianceType", "Values": ["Patch"]}],
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
                    # Check if an upgrade is available (boolean summary, not full list)
                    # Full ValidUpgradeTarget list is omitted — it contains 20-30 entries per
                    # RDS instance and adds thousands of tokens with no security value.
                    upgradeable = rds_client.describe_db_engine_versions(
                        Engine=instance.get("Engine"),
                        EngineVersion=instance.get("EngineVersion"),
                    )
                    targets = upgradeable.get("DBEngineVersions", [{}])[0].get(
                        "ValidUpgradeTarget", []
                    )
                    minor_upgrades = [t for t in targets if not t.get("IsMajorVersionUpgrade")]
                    major_upgrades = [t for t in targets if t.get("IsMajorVersionUpgrade")]
                    rds_detail["UpgradeAvailable"] = len(targets) > 0
                    rds_detail["MinorUpgradeCount"] = len(minor_upgrades)
                    rds_detail["MajorUpgradeCount"] = len(major_upgrades)
                    rds_detail["LatestMinorVersion"] = (
                        minor_upgrades[-1].get("EngineVersion") if minor_upgrades else None
                    )
                    rds_detail["LatestMajorVersion"] = (
                        major_upgrades[-1].get("EngineVersion") if major_upgrades else None
                    )
                except Exception as e:
                    logger.warning(
                        f"Could not describe DB engine versions for {instance.get('DBInstanceIdentifier')}: {e}"
                    )
                    rds_detail["UpgradeAvailable"] = None

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

                        # Only keep records with actual scan data to avoid token bloat
                        # Inspector v2 already captures CVEs; ECR legacy scans with no data add noise
                        has_scan_data = (
                            image_detail.get("ImageId") is not None
                            or bool(image_detail.get("ImageScanStatus"))
                            or bool(image_detail.get("ImageScanFindingsSummary"))
                        )
                        if has_scan_data:
                            ecr_images_list.append(image_detail)
                except Exception as e:
                    logger.warning(f"Could not describe images for repository {repo_name}: {e}")

            self._save_json(evidence_path / "ecr-image-scans.json", ecr_images_list)
        except Exception as e:
            logger.error(f"Could not collect ECR scan data: {e}")

        # === EC2 USER-DATA ===
        print("  Collecting EC2 user-data scripts...")
        try:
            user_data, user_data_error = self._collect_ec2_user_data(client_kwargs)
            self._save_json(
                evidence_path / "ec2-user-data.json",
                {
                    "items": user_data,
                    "error": user_data_error,
                },
            )
        except Exception as e:
            logger.error(f"Could not collect EC2 user-data: {e}")

        # === LAMBDA ENVIRONMENT VARIABLES ===
        print("  Collecting Lambda environment variables...")
        try:
            env_vars, env_error = self._collect_lambda_environment_variables(client_kwargs)
            self._save_json(
                evidence_path / "lambda-environment-variables.json",
                {
                    "items": env_vars,
                    "error": env_error,
                },
            )
        except Exception as e:
            logger.error(f"Could not collect Lambda environment variables: {e}")

        # === IMDS CONFIGURATION ===
        print("  Collecting IMDS configuration...")
        try:
            imds, imds_error = self._collect_imds_configuration(client_kwargs)
            self._save_json(
                evidence_path / "imds-configuration.json",
                {
                    "items": imds,
                    "error": imds_error,
                },
            )
        except Exception as e:
            logger.error(f"Could not collect IMDS configuration: {e}")

        # === INSTANCE PROFILE PERMISSIONS ===
        print("  Collecting instance profile permissions...")
        try:
            profiles, profiles_error = self._collect_instance_profiles_permissions(client_kwargs)
            self._save_json(
                evidence_path / "instance-profiles-permissions.json",
                {
                    "items": profiles,
                    "error": profiles_error,
                },
            )
        except Exception as e:
            logger.error(f"Could not collect instance profile permissions: {e}")

        # === EBS SNAPSHOT SHARING ===
        print("  Collecting EBS snapshot sharing posture...")
        try:
            snapshots, snapshots_error = self._collect_ebs_snapshot_sharing(client_kwargs)
            self._save_json(
                evidence_path / "ebs-snapshot-sharing.json",
                {
                    "items": snapshots,
                    "error": snapshots_error,
                },
            )
        except Exception as e:
            logger.error(f"Could not collect EBS snapshot sharing posture: {e}")

        print("\n✅ Vulnerability collection complete")

    def _scan_for_secrets(self, text: str) -> Dict[str, bool]:
        """Scan text for common secret patterns."""
        patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"(?i)aws(.{0,20})?(secret|access).{0,10}[=:]\s*[A-Za-z0-9/+=]{30,}",
            "password": r"(?i)password\s*[=:]\s*[^\s\"']+",
            "api_key": r"(?i)api[_-]?key\s*[=:]\s*[^\s\"']+",
            "token": r"(?i)(token|secret)\s*[=:]\s*[^\s\"']+",
        }
        return {name: bool(re.search(pattern, text)) for name, pattern in patterns.items()}

    def _collect_ec2_user_data(
        self, client_kwargs: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Extract user-data from EC2 instances for credential analysis."""
        ec2 = boto3.client("ec2", **client_kwargs)
        out: List[Dict[str, Any]] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_id = instance.get("InstanceId")
                        if not instance_id:
                            continue
                        try:
                            resp = ec2.describe_instance_attribute(
                                InstanceId=instance_id,
                                Attribute="userData",
                            )
                        except Exception:
                            continue
                        user_data = ((resp or {}).get("UserData") or {}).get("Value")
                        if not user_data:
                            continue
                        decoded = ""
                        try:
                            decoded = base64.b64decode(user_data).decode("utf-8", errors="replace")
                        except Exception:
                            decoded = str(user_data)
                        out.append(
                            {
                                "InstanceId": instance_id,
                                "UserData": decoded,
                                "ContainsSecrets": self._scan_for_secrets(decoded),
                            }
                        )
            return out, None
        except Exception as e:
            return out, str(e)

    def _collect_lambda_environment_variables(
        self, client_kwargs: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Collect Lambda environment variables for exposed secret analysis."""
        lam = boto3.client("lambda", **client_kwargs)
        out: List[Dict[str, Any]] = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []) or []:
                    fn_name = fn.get("FunctionName")
                    if not fn_name:
                        continue
                    try:
                        details = lam.get_function(FunctionName=fn_name)
                    except Exception:
                        continue
                    cfg = (details.get("Configuration") or {}) if isinstance(details, dict) else {}
                    env = (cfg.get("Environment") or {}).get("Variables") or {}
                    env_keys = sorted([k for k in env.keys()]) if isinstance(env, dict) else []
                    secret_flags = {
                        k: bool(re.search(r"(?i)(password|secret|token|key|credential)", k))
                        for k in env_keys
                    }
                    out.append(
                        {
                            "FunctionName": fn_name,
                            "FunctionArn": cfg.get("FunctionArn"),
                            "EnvironmentKeys": env_keys,
                            "PotentialSecretKeys": [k for k, v in secret_flags.items() if v],
                        }
                    )
            return out, None
        except Exception as e:
            return out, str(e)

    def _collect_imds_configuration(
        self, client_kwargs: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Detect IMDSv1 vs IMDSv2 configuration across EC2 instances."""
        ec2 = boto3.client("ec2", **client_kwargs)
        out: List[Dict[str, Any]] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        md = instance.get("MetadataOptions") or {}
                        out.append(
                            {
                                "InstanceId": instance.get("InstanceId"),
                                "HttpTokens": md.get("HttpTokens", "optional"),
                                "HttpPutResponseHopLimit": md.get("HttpPutResponseHopLimit", 1),
                                "State": (instance.get("State") or {}).get("Name"),
                                "VulnerableToSSRF": md.get("HttpTokens") != "required",
                            }
                        )
            return out, None
        except Exception as e:
            return out, str(e)

    def _collect_instance_profiles_permissions(
        self, client_kwargs: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Collect effective permission indicators for EC2 instance profiles."""
        ec2 = boto3.client("ec2", **client_kwargs)
        iam = boto3.client("iam", **client_kwargs)
        out: List[Dict[str, Any]] = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            profile_arns: Dict[str, List[str]] = {}
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        prof = instance.get("IamInstanceProfile") or {}
                        arn = prof.get("Arn")
                        iid = instance.get("InstanceId")
                        if isinstance(arn, str) and arn and isinstance(iid, str):
                            profile_arns.setdefault(arn, []).append(iid)

            for profile_arn, instance_ids in profile_arns.items():
                profile_name = profile_arn.split("/")[-1]
                try:
                    prof = iam.get_instance_profile(InstanceProfileName=profile_name).get(
                        "InstanceProfile", {}
                    )
                except Exception:
                    continue
                roles_out = []
                for role in prof.get("Roles", []) or []:
                    role_name = role.get("RoleName")
                    attached = []
                    inline = []
                    if role_name:
                        try:
                            attached = iam.list_attached_role_policies(RoleName=role_name).get(
                                "AttachedPolicies", []
                            )
                        except Exception:
                            pass
                        try:
                            inline = iam.list_role_policies(RoleName=role_name).get(
                                "PolicyNames", []
                            )
                        except Exception:
                            pass
                    roles_out.append(
                        {
                            "RoleName": role_name,
                            "RoleArn": role.get("Arn"),
                            "AttachedPolicies": attached,
                            "InlinePolicies": inline,
                        }
                    )
                out.append(
                    {
                        "InstanceProfileArn": profile_arn,
                        "InstanceProfileName": profile_name,
                        "AttachedInstanceIds": sorted(instance_ids),
                        "Roles": roles_out,
                    }
                )
            return out, None
        except Exception as e:
            return out, str(e)

    def _collect_ebs_snapshot_sharing(
        self, client_kwargs: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Collect EBS snapshot sharing posture (public createVolumePermission)."""
        ec2 = boto3.client("ec2", **client_kwargs)
        out: List[Dict[str, Any]] = []
        try:
            paginator = ec2.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snap in page.get("Snapshots", []) or []:
                    if not isinstance(snap, dict):
                        continue
                    snap_id = snap.get("SnapshotId")
                    if not isinstance(snap_id, str) or not snap_id:
                        continue

                    rec: Dict[str, Any] = {
                        "SnapshotId": snap_id,
                        "VolumeId": snap.get("VolumeId"),
                        "State": snap.get("State"),
                        "Encrypted": snap.get("Encrypted"),
                    }
                    try:
                        attrs = ec2.describe_snapshot_attribute(
                            SnapshotId=snap_id,
                            Attribute="createVolumePermission",
                        )
                        perms = (
                            attrs.get("CreateVolumePermissions", [])
                            if isinstance(attrs, dict)
                            else []
                        )
                        rec["CreateVolumePermissions"] = perms
                        rec["IsPublic"] = any(
                            isinstance(p, dict) and p.get("Group") == "all" for p in perms
                        )
                    except Exception as e:
                        rec["AttributeError"] = str(e)

                    out.append(rec)
            return out, None
        except Exception as e:
            return out, str(e)

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["VulnsSkill"]
