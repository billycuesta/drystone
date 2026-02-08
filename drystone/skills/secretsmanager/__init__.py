"""AWS Secrets Manager security audit skill."""

import json
import boto3
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError

from drystone.skills.base import BaseSkill
from drystone.cloud.aws.client import AWSClient
from drystone.storage.session import AuditSession


class SecretsManagerSkill(BaseSkill):
    """Secrets Manager security audit for rotation, encryption, and access control."""

    @property
    def name(self) -> str:
        return "secretsmanager"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect Secrets Manager data across all regions.

        Collects:
        - All secrets with metadata (name, ARN, KMS key)
        - Rotation configuration (enabled, interval, Lambda ARN)
        - Resource policies (access control)
        - Security analysis (rotation status, encryption, tags)
        - Risk scoring (0-100 based on security issues)
        """
        print("  🔍 Scanning all AWS regions for secrets...")

        # Create boto3 session
        client_kwargs = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        session_obj = boto3.Session(**client_kwargs)

        # Get all regions
        try:
            ec2_client = session_obj.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2_client.describe_regions()["Regions"]]
        except ClientError as e:
            print(f"  ⚠️  Could not retrieve regions: {e}")
            regions = ["us-east-1", "us-west-2", "eu-west-1"]  # Fallback

        all_secrets = []
        regions_scanned = 0

        # Scan each region
        for region in regions:
            try:
                secrets_client = session_obj.client("secretsmanager", region_name=region)
                paginator = secrets_client.get_paginator("list_secrets")

                for page in paginator.paginate():
                    for secret in page.get("SecretList", []):
                        secret_arn = secret["ARN"]

                        try:
                            # Get detailed secret information
                            secret_details = secrets_client.describe_secret(SecretId=secret_arn)

                            # Get resource policy if exists
                            resource_policy = self._get_resource_policy(secrets_client, secret_arn)

                            # Analyze rotation configuration
                            rotation_analysis = self._analyze_rotation(secret_details)

                            # Security analysis
                            security_issues = self._analyze_security(
                                secret_details, resource_policy
                            )

                            # Calculate risk score
                            risk_score = self._calculate_risk_score(
                                secret_details, resource_policy, security_issues
                            )

                            all_secrets.append(
                                {
                                    "Region": region,
                                    "Name": secret_details.get("Name"),
                                    "ARN": secret_arn,
                                    "Description": secret_details.get(
                                        "Description", "No description"
                                    ),
                                    "KmsKeyId": secret_details.get(
                                        "KmsKeyId", "Default AWS managed key"
                                    ),
                                    "RotationEnabled": secret_details.get("RotationEnabled", False),
                                    "RotationLambdaARN": secret_details.get("RotationLambdaARN"),
                                    "RotationRules": secret_details.get("RotationRules", {}),
                                    "LastRotatedDate": str(
                                        secret_details.get("LastRotatedDate", "")
                                    ),
                                    "LastChangedDate": str(
                                        secret_details.get("LastChangedDate", "")
                                    ),
                                    "LastAccessedDate": str(
                                        secret_details.get("LastAccessedDate", "")
                                    ),
                                    "Tags": secret_details.get("Tags", []),
                                    "ResourcePolicy": resource_policy,
                                    "RotationAnalysis": rotation_analysis,
                                    "SecurityIssues": security_issues,
                                    "RiskScore": risk_score,
                                    "CreatedDate": str(secret_details.get("CreatedDate", "")),
                                    "PrimaryRegion": secret_details.get("PrimaryRegion"),
                                    "ReplicationStatus": secret_details.get(
                                        "ReplicationStatus", []
                                    ),
                                }
                            )

                        except ClientError as e:
                            # Log individual secret errors but continue
                            all_secrets.append(
                                {
                                    "Region": region,
                                    "Name": secret.get("Name", "Unknown"),
                                    "ARN": secret_arn,
                                    "Error": f"Failed to retrieve details: {e.response['Error']['Code']}",
                                }
                            )

                regions_scanned += 1

            except ClientError as e:
                # Skip inaccessible regions
                common_errors = [
                    "InvalidClientTokenId",
                    "UnrecognizedClientException",
                    "AuthFailure",
                    "AccessDeniedException",
                    "OptInRequired",
                ]
                if e.response["Error"]["Code"] in common_errors:
                    continue
            except Exception:
                continue

        print(f"  ✅ Found {len(all_secrets)} secrets across {regions_scanned} regions")

        # Save evidence
        evidence_path = session.get_evidence_path(self.name)
        self._save_json(evidence_path / "secrets.json", {"secrets": all_secrets})

        # Collect alerting evidence for rotation failures (SM-012)
        # CloudWatch + EventBridge are regional, so we collect per region.
        print("  🔔 Collecting rotation alerting evidence (CloudWatch/EventBridge)...")

        cw_data = self._collect_cloudwatch_alarms(session_obj, regions)
        self._save_json(evidence_path / "cloudwatch_alarms.json", cw_data)

        eb_data = self._collect_eventbridge_rules(session_obj, regions)
        self._save_json(evidence_path / "eventbridge_rules.json", eb_data)

        print("  ✅ Alerting evidence saved")

    def _collect_cloudwatch_alarms(
        self, session_obj: boto3.Session, regions: List[str]
    ) -> Dict[str, Any]:
        """Collect CloudWatch alarms that may cover Secrets Manager rotation failures."""
        result: Dict[str, Any] = {
            "regions": {},
            "notes": (
                "This evidence is best-effort. If AccessDenied, region will include an error field."
            ),
        }

        for region in regions:
            try:
                cw = session_obj.client("cloudwatch", region_name=region)
                alarms: List[Dict[str, Any]] = []
                paginator = cw.get_paginator("describe_alarms")
                for page in paginator.paginate():
                    for a in page.get("MetricAlarms", []) or []:
                        namespace = a.get("Namespace")
                        metric_name = a.get("MetricName")
                        alarm_name = a.get("AlarmName", "")
                        # Keep evidence reasonably small but useful.
                        alarms.append(
                            {
                                "AlarmName": alarm_name,
                                "AlarmArn": a.get("AlarmArn"),
                                "StateValue": a.get("StateValue"),
                                "ActionsEnabled": a.get("ActionsEnabled"),
                                "AlarmActions": a.get("AlarmActions", []),
                                "OKActions": a.get("OKActions", []),
                                "InsufficientDataActions": a.get("InsufficientDataActions", []),
                                "Namespace": namespace,
                                "MetricName": metric_name,
                                "Dimensions": a.get("Dimensions", []),
                                "ComparisonOperator": a.get("ComparisonOperator"),
                                "Threshold": a.get("Threshold"),
                                "EvaluationPeriods": a.get("EvaluationPeriods"),
                                "TreatMissingData": a.get("TreatMissingData"),
                                "DatapointsToAlarm": a.get("DatapointsToAlarm"),
                                "Period": a.get("Period"),
                                "Statistic": a.get("Statistic"),
                                "ExtendedStatistic": a.get("ExtendedStatistic"),
                                "Unit": a.get("Unit"),
                                "AlarmDescription": a.get("AlarmDescription"),
                            }
                        )

                # Convenience view: alarms likely relevant to Secrets Manager rotation.
                likely = [
                    x
                    for x in alarms
                    if (
                        (x.get("Namespace") == "AWS/SecretsManager")
                        or (str(x.get("MetricName") or "").lower().find("rotation") != -1)
                        or (str(x.get("AlarmName") or "").lower().find("secret") != -1)
                        or (str(x.get("AlarmName") or "").lower().find("rotation") != -1)
                    )
                ]

                result["regions"][region] = {
                    "alarm_count": len(alarms),
                    "likely_relevant_count": len(likely),
                    "likely_relevant": likely,
                }
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                result["regions"][region] = {
                    "error": f"{code}",
                }
            except Exception as e:
                result["regions"][region] = {
                    "error": f"UnexpectedError: {type(e).__name__}",
                }

        return result

    def _collect_eventbridge_rules(
        self, session_obj: boto3.Session, regions: List[str]
    ) -> Dict[str, Any]:
        """Collect EventBridge rules that could alert on Secrets Manager events."""
        result: Dict[str, Any] = {
            "regions": {},
            "notes": (
                "We only include rules that look relevant to Secrets Manager/rotation to keep evidence small. "
                "If AccessDenied, region will include an error field."
            ),
        }

        for region in regions:
            try:
                events = session_obj.client("events", region_name=region)
                paginator = events.get_paginator("list_rules")

                relevant_rules: List[Dict[str, Any]] = []

                for page in paginator.paginate():
                    for r in page.get("Rules", []) or []:
                        name = r.get("Name", "")
                        desc = r.get("Description", "")

                        # Cheap pre-filter before calling get_rule.
                        pre = f"{name} {desc}".lower()
                        if not any(
                            k in pre for k in ["secret", "secretsmanager", "rotation", "rotate"]
                        ):
                            continue

                        rule_detail = events.describe_rule(Name=name)
                        pattern = rule_detail.get("EventPattern")

                        # Include if the pattern references secretsmanager/rotation.
                        pattern_l = (pattern or "").lower()
                        if not any(
                            k in pattern_l for k in ["secretsmanager", "rotation", "rotatesecret"]
                        ):
                            # Still keep name-based matches (some rules use CloudTrail patterns without explicit keywords).
                            pass

                        targets_resp = events.list_targets_by_rule(Rule=name)
                        targets = targets_resp.get("Targets", [])
                        relevant_rules.append(
                            {
                                "Name": name,
                                "Arn": r.get("Arn"),
                                "State": r.get("State"),
                                "Description": desc,
                                "EventPattern": pattern,
                                "ScheduleExpression": rule_detail.get("ScheduleExpression"),
                                "RoleArn": rule_detail.get("RoleArn"),
                                "ManagedBy": rule_detail.get("ManagedBy"),
                                "Targets": targets,
                            }
                        )

                result["regions"][region] = {
                    "relevant_rule_count": len(relevant_rules),
                    "relevant_rules": relevant_rules,
                }

            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "Unknown")
                result["regions"][region] = {
                    "error": f"{code}",
                }
            except Exception as e:
                result["regions"][region] = {
                    "error": f"UnexpectedError: {type(e).__name__}",
                }

        return result

    def _get_resource_policy(self, client, secret_arn: str) -> Optional[Dict[str, Any]]:
        """Retrieve resource policy for secret."""
        try:
            response = client.get_resource_policy(SecretId=secret_arn)
            return json.loads(response.get("ResourcePolicy", "{}"))
        except ClientError:
            return None

    def _analyze_rotation(self, secret_details: Dict) -> Dict[str, Any]:
        """Analyze rotation configuration."""
        analysis = {"status": "Not Configured", "issues": [], "recommendations": []}

        rotation_enabled = secret_details.get("RotationEnabled", False)
        rotation_rules = secret_details.get("RotationRules", {})
        last_rotated = secret_details.get("LastRotatedDate")

        if not rotation_enabled:
            analysis["status"] = "Disabled"
            analysis["issues"].append("Automatic rotation not enabled")
            analysis["recommendations"].append("Enable automatic rotation")
        else:
            analysis["status"] = "Enabled"
            interval = rotation_rules.get("AutomaticallyAfterDays", 0)

            if interval > 90:
                analysis["issues"].append(f"Rotation interval ({interval}d) exceeds 90 days")

            if last_rotated:
                now = datetime.now(timezone.utc)
                if isinstance(last_rotated, datetime):
                    days_since = (now - last_rotated).days
                    if days_since > 365:
                        analysis["issues"].append(f"Not rotated for {days_since} days")

        return analysis

    def _analyze_security(
        self, secret_details: Dict, resource_policy: Optional[Dict[str, Any]]
    ) -> list:
        """Analyze security issues."""
        issues = []

        # Check KMS encryption
        kms_key = secret_details.get("KmsKeyId", "")
        if not kms_key or "aws/secretsmanager" in kms_key:
            issues.append(
                {
                    "type": "encryption",
                    "severity": "medium",
                    "description": "Using AWS managed KMS key",
                    "recommendation": "Use customer managed KMS key",
                }
            )

        # Check resource policy for public access
        if resource_policy and isinstance(resource_policy, dict):
            for statement in resource_policy.get("Statement", []):
                principal = statement.get("Principal", {})
                if principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                ):
                    issues.append(
                        {
                            "type": "access_control",
                            "severity": "critical",
                            "description": "Resource policy allows public access",
                            "recommendation": "Restrict to specific principals",
                        }
                    )

        # Check tags
        if not secret_details.get("Tags"):
            issues.append(
                {
                    "type": "governance",
                    "severity": "low",
                    "description": "No tags for governance",
                    "recommendation": "Add environment, owner, purpose tags",
                }
            )

        # Check replication
        if not secret_details.get("ReplicationStatus"):
            issues.append(
                {
                    "type": "availability",
                    "severity": "medium",
                    "description": "Not replicated to other regions",
                    "recommendation": "Replicate critical secrets for DR",
                }
            )

        return issues

    def _calculate_risk_score(
        self,
        secret_details: Dict,
        resource_policy: Optional[Dict[str, Any]],
        security_issues: list,
    ) -> int:
        """Calculate risk score (0-100)."""
        score = 10  # Base score

        # Add for security issues
        for issue in security_issues:
            severity_points = {"critical": 35, "high": 25, "medium": 15, "low": 5}
            score += severity_points.get(issue.get("severity", "low"), 5)

        # Reduce for good practices
        if secret_details.get("RotationEnabled"):
            score -= 10
        if secret_details.get("Tags"):
            score -= 5
        if secret_details.get("ReplicationStatus"):
            score -= 5

        return max(0, min(100, score))

    def _save_json(self, filepath: Path, data: Dict):
        """Save JSON with datetime serialization."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
