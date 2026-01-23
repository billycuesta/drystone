"""Exposure security skill for AWS audit."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

import boto3

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient


class ExposureSkill(BaseSkill):
    """Public exposure audit skill - identifies resources exposed to internet."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "exposure"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect data about publicly exposed AWS resources.

        Collects:
            - S3 buckets (public access blocks, ACLs, policies)
            - RDS instances (public accessibility)
            - Snapshots (public sharing)
            - AMI images (public sharing)
            - Security group rules (0.0.0.0/0 access)
            - VPC endpoints and their configurations
            - CloudFront distributions (origins and settings)

        Args:
            aws_client: Authenticated AWS client
            session: Audit session for evidence storage
        """
        client_kwargs = {
            'aws_access_key_id': aws_client.access_key_id,
            'aws_secret_access_key': aws_client.secret_access_key,
            'region_name': aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs['aws_session_token'] = aws_client.session_token

        evidence_path = session.get_evidence_path(self.name)

        # === S3 BUCKETS ===
        print("  Collecting S3 bucket configurations...")
        try:
            s3_client = boto3.client("s3", **client_kwargs)
            buckets_response = s3_client.list_buckets()
            buckets_list = []

            for bucket in buckets_response.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_detail = {
                    "Name": bucket_name,
                    "CreationDate": bucket.get("CreationDate"),
                }

                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    bucket_detail["ACL"] = acl.get("Grants", [])
                except Exception:
                    bucket_detail["ACL"] = []

                try:
                    pab = s3_client.get_public_access_block(Bucket=bucket_name)
                    bucket_detail["PublicAccessBlock"] = pab.get("PublicAccessBlockConfiguration", {})
                except Exception:
                    bucket_detail["PublicAccessBlock"] = None

                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    bucket_detail["BucketPolicy"] = json.loads(policy.get("Policy", "{}"))
                except Exception:
                    bucket_detail["BucketPolicy"] = None

                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    bucket_detail["Versioning"] = versioning.get("Status")
                except Exception:
                    bucket_detail["Versioning"] = None

                buckets_list.append(bucket_detail)

            self._save_json(evidence_path / "s3-buckets.json", buckets_list)
        except Exception as e:
            print(f"    Warning: Could not collect S3 data: {e}")

        # === RDS INSTANCES ===
        print("  Collecting RDS instance configurations...")
        try:
            rds_client = boto3.client("rds", **client_kwargs)
            rds_response = rds_client.describe_db_instances()
            rds_list = []

            for instance in rds_response.get("DBInstances", []):
                rds_detail = {
                    "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                    "DBInstanceStatus": instance.get("DBInstanceStatus"),
                    "Engine": instance.get("Engine"),
                    "PubliclyAccessible": instance.get("PubliclyAccessible"),
                    "VpcSecurityGroups": instance.get("VpcSecurityGroups", []),
                    "DBSubnetGroup": instance.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                }
                rds_list.append(rds_detail)

            self._save_json(evidence_path / "rds-instances.json", rds_list)
        except Exception as e:
            print(f"    Warning: Could not collect RDS data: {e}")

        # === RDS SNAPSHOTS ===
        print("  Collecting RDS snapshot sharing...")
        try:
            snapshots = rds_client.describe_db_snapshots()
            snapshots_list = []

            for snapshot in snapshots.get("DBSnapshots", []):
                snapshot_detail = {
                    "DBSnapshotIdentifier": snapshot.get("DBSnapshotIdentifier"),
                    "Engine": snapshot.get("Engine"),
                    "SnapshotCreateTime": snapshot.get("SnapshotCreateTime"),
                }

                try:
                    attributes = rds_client.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snapshot.get("DBSnapshotIdentifier")
                    )
                    snapshot_detail["Attributes"] = attributes.get("DBSnapshotAttributesResult", {})
                except Exception:
                    snapshot_detail["Attributes"] = {}

                snapshots_list.append(snapshot_detail)

            self._save_json(evidence_path / "rds-snapshots.json", snapshots_list)
        except Exception as e:
            print(f"    Warning: Could not collect RDS snapshot data: {e}")

        # === AMI IMAGES ===
        print("  Collecting AMI image sharing...")
        try:
            ec2_client = boto3.client("ec2", **client_kwargs)
            images = ec2_client.describe_images(Owners=["self"])
            images_list = []

            for image in images.get("Images", []):
                image_detail = {
                    "ImageId": image.get("ImageId"),
                    "Name": image.get("Name"),
                    "Public": image.get("Public"),
                    "CreationDate": image.get("CreationDate"),
                }

                try:
                    launch_perms = ec2_client.describe_image_attribute(
                        ImageId=image.get("ImageId"),
                        Attribute="launchPermission"
                    )
                    image_detail["LaunchPermissions"] = launch_perms.get("LaunchPermissions", [])
                except Exception:
                    image_detail["LaunchPermissions"] = []

                images_list.append(image_detail)

            self._save_json(evidence_path / "ami-images.json", images_list)
        except Exception as e:
            print(f"    Warning: Could not collect AMI data: {e}")

        # === SECURITY GROUPS ===
        print("  Collecting security group rules...")
        try:
            sgs = ec2_client.describe_security_groups()
            sgs_list = []

            for sg in sgs.get("SecurityGroups", []):
                sg_detail = {
                    "GroupId": sg.get("GroupId"),
                    "GroupName": sg.get("GroupName"),
                    "VpcId": sg.get("VpcId"),
                    "IngressRules": sg.get("IpPermissions", []),
                    "EgressRules": sg.get("IpPermissionsEgress", []),
                }
                sgs_list.append(sg_detail)

            self._save_json(evidence_path / "security-groups.json", sgs_list)
        except Exception as e:
            print(f"    Warning: Could not collect security group data: {e}")

        # === CLOUDFRONT DISTRIBUTIONS ===
        print("  Collecting CloudFront distributions...")
        try:
            cf_client = boto3.client("cloudfront", **client_kwargs)
            distributions = cf_client.list_distributions()
            dists_list = []

            for dist in distributions.get("DistributionList", {}).get("Items", []):
                dist_detail = {
                    "Id": dist.get("Id"),
                    "DomainName": dist.get("DomainName"),
                    "Enabled": dist.get("Enabled"),
                    "Origins": dist.get("Origins", []),
                    "DefaultCacheBehavior": dist.get("DefaultCacheBehavior", {}),
                }
                dists_list.append(dist_detail)

            self._save_json(evidence_path / "cloudfront-distributions.json", dists_list)
        except Exception as e:
            print(f"    Warning: Could not collect CloudFront data: {e}")

        print(f"\n✅ Exposure collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["ExposureSkill"]
