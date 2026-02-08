"""AWS Secrets Manager security audit skill."""

import json
import boto3
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any
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
            'aws_access_key_id': aws_client.access_key_id,
            'aws_secret_access_key': aws_client.secret_access_key,
        }
        if aws_client.session_token:
            client_kwargs['aws_session_token'] = aws_client.session_token

        session_obj = boto3.Session(**client_kwargs)

        # Get all regions
        try:
            ec2_client = session_obj.client('ec2', region_name='us-east-1')
            regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        except ClientError as e:
            print(f"  ⚠️  Could not retrieve regions: {e}")
            regions = ['us-east-1', 'us-west-2', 'eu-west-1']  # Fallback

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
                            security_issues = self._analyze_security(secret_details, resource_policy)

                            # Calculate risk score
                            risk_score = self._calculate_risk_score(
                                secret_details, resource_policy, security_issues
                            )

                            all_secrets.append({
                                "Region": region,
                                "Name": secret_details.get("Name"),
                                "ARN": secret_arn,
                                "Description": secret_details.get("Description", "No description"),
                                "KmsKeyId": secret_details.get("KmsKeyId", "Default AWS managed key"),
                                "RotationEnabled": secret_details.get("RotationEnabled", False),
                                "RotationLambdaARN": secret_details.get("RotationLambdaARN"),
                                "RotationRules": secret_details.get("RotationRules", {}),
                                "LastRotatedDate": str(secret_details.get("LastRotatedDate", "")),
                                "LastChangedDate": str(secret_details.get("LastChangedDate", "")),
                                "LastAccessedDate": str(secret_details.get("LastAccessedDate", "")),
                                "Tags": secret_details.get("Tags", []),
                                "ResourcePolicy": resource_policy,
                                "RotationAnalysis": rotation_analysis,
                                "SecurityIssues": security_issues,
                                "RiskScore": risk_score,
                                "CreatedDate": str(secret_details.get("CreatedDate", "")),
                                "PrimaryRegion": secret_details.get("PrimaryRegion"),
                                "ReplicationStatus": secret_details.get("ReplicationStatus", []),
                            })

                        except ClientError as e:
                            # Log individual secret errors but continue
                            all_secrets.append({
                                "Region": region,
                                "Name": secret.get("Name", "Unknown"),
                                "ARN": secret_arn,
                                "Error": f"Failed to retrieve details: {e.response['Error']['Code']}"
                            })

                regions_scanned += 1

            except ClientError as e:
                # Skip inaccessible regions
                common_errors = [
                    'InvalidClientTokenId', 'UnrecognizedClientException',
                    'AuthFailure', 'AccessDeniedException', 'OptInRequired'
                ]
                if e.response['Error']['Code'] in common_errors:
                    continue
            except Exception:
                continue

        print(f"  ✅ Found {len(all_secrets)} secrets across {regions_scanned} regions")

        # Save evidence
        evidence_path = session.get_evidence_path(self.name)
        self._save_json(evidence_path / "secrets.json", {"secrets": all_secrets})

    def _get_resource_policy(self, client, secret_arn: str) -> Dict[str, Any]:
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

    def _analyze_security(self, secret_details: Dict, resource_policy: Dict) -> list:
        """Analyze security issues."""
        issues = []

        # Check KMS encryption
        kms_key = secret_details.get("KmsKeyId", "")
        if not kms_key or "aws/secretsmanager" in kms_key:
            issues.append({
                "type": "encryption",
                "severity": "medium",
                "description": "Using AWS managed KMS key",
                "recommendation": "Use customer managed KMS key"
            })

        # Check resource policy for public access
        if resource_policy and isinstance(resource_policy, dict):
            for statement in resource_policy.get("Statement", []):
                principal = statement.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    issues.append({
                        "type": "access_control",
                        "severity": "critical",
                        "description": "Resource policy allows public access",
                        "recommendation": "Restrict to specific principals"
                    })

        # Check tags
        if not secret_details.get("Tags"):
            issues.append({
                "type": "governance",
                "severity": "low",
                "description": "No tags for governance",
                "recommendation": "Add environment, owner, purpose tags"
            })

        # Check replication
        if not secret_details.get("ReplicationStatus"):
            issues.append({
                "type": "availability",
                "severity": "medium",
                "description": "Not replicated to other regions",
                "recommendation": "Replicate critical secrets for DR"
            })

        return issues

    def _calculate_risk_score(self, secret_details: Dict, resource_policy: Dict,
                              security_issues: list) -> int:
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
