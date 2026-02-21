"""IAM security skill for AWS audit."""

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient

logger = get_logger(__name__)


class IAMSkill(BaseSkill):
    """IAM security audit skill for CIS AWS Foundations compliance."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "iam"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect comprehensive IAM data from AWS account.

        Collects:
            - Account information (summary, aliases)
            - Password policy
            - Users (with access keys, MFA, groups, policies)
            - Groups (with users, policies)
            - Roles (with trust policies, attached policies)
            - Customer-managed policies (with documents)
            - Credential report (CSV)

        Args:
            aws_client: Authenticated AWS client
            session: Audit session for evidence storage
        """
        # Create IAM client using credentials
        client_kwargs = {
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        # Add session token only if provided (for temporary credentials)
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        iam_client = boto3.client("iam", **client_kwargs)

        evidence_path = session.get_evidence_path(self.name)

        # === ACCOUNT INFORMATION ===
        print("  Collecting account information...")
        try:
            account_summary = iam_client.get_account_summary()
            self._save_json(evidence_path / "account-summary.json", account_summary)
        except Exception as e:
            logger.warning(f"Could not get account summary: {e}")

        try:
            account_aliases = iam_client.list_account_aliases()
            self._save_json(evidence_path / "account-aliases.json", account_aliases)
        except Exception as e:
            logger.warning(f"Could not get account aliases: {e}")

        # === PASSWORD POLICY ===
        print("  Collecting password policy...")
        try:
            password_policy = iam_client.get_account_password_policy()
            self._save_json(evidence_path / "password-policy.json", password_policy)
        except iam_client.exceptions.NoSuchEntityException:
            logger.info("No password policy set for the account.")
            self._save_json(
                evidence_path / "password-policy.json",
                {"error": "No password policy configured"},
            )
        except Exception as e:
            logger.warning(f"Could not get password policy: {e}")

        # === USERS (detailed) ===
        print("  Collecting IAM users...")
        users_detailed = []
        try:
            users_basic = iam_client.list_users().get("Users", [])

            for user in users_basic:
                username = user["UserName"]
                user_detail = {
                    "UserName": username,
                    "UserId": user.get("UserId"),
                    "Arn": user.get("Arn"),
                    "CreateDate": user.get("CreateDate"),
                    "Path": user.get("Path"),
                }

                # Access keys
                try:
                    keys_response = iam_client.list_access_keys(UserName=username)
                    user_detail["AccessKeys"] = keys_response.get("AccessKeyMetadata", [])

                    # Get last used info for each key
                    for key in user_detail["AccessKeys"]:
                        try:
                            last_used = iam_client.get_access_key_last_used(
                                AccessKeyId=key["AccessKeyId"]
                            )
                            key["LastUsed"] = last_used.get("AccessKeyLastUsed", {})
                        except Exception as e:
                            logger.warning(
                                f"Could not get last used status for access key {key['AccessKeyId']}: {e}"
                            )
                            key["LastUsed"] = None
                except Exception as e:
                    logger.warning(f"Could not list access keys for user {username}: {e}")
                    user_detail["AccessKeys"] = []

                # MFA devices
                try:
                    mfa_response = iam_client.list_mfa_devices(UserName=username)
                    user_detail["MFADevices"] = mfa_response.get("MFADevices", [])
                except Exception as e:
                    logger.warning(f"Could not list MFA devices for user {username}: {e}")
                    user_detail["MFADevices"] = []

                # Inline policies
                try:
                    inline_response = iam_client.list_user_policies(UserName=username)
                    user_detail["InlinePolicies"] = inline_response.get("PolicyNames", [])
                except Exception as e:
                    logger.warning(f"Could not list inline policies for user {username}: {e}")
                    user_detail["InlinePolicies"] = []

                # Attached managed policies
                try:
                    attached_response = iam_client.list_attached_user_policies(UserName=username)
                    user_detail["AttachedPolicies"] = attached_response.get("AttachedPolicies", [])
                except Exception as e:
                    logger.warning(f"Could not list attached policies for user {username}: {e}")
                    user_detail["AttachedPolicies"] = []

                # Groups
                try:
                    groups_response = iam_client.list_groups_for_user(UserName=username)
                    user_detail["Groups"] = groups_response.get("Groups", [])
                except Exception as e:
                    logger.warning(f"Could not list groups for user {username}: {e}")
                    user_detail["Groups"] = []

                users_detailed.append(user_detail)
        except Exception as e:
            logger.error(f"Could not list IAM users: {e}")

        self._save_json(evidence_path / "users.json", users_detailed)

        # === GROUPS (detailed) ===
        print("  Collecting IAM groups...")
        groups_detailed = []
        try:
            groups_basic = iam_client.list_groups().get("Groups", [])

            for group in groups_basic:
                group_name = group["GroupName"]
                group_detail = {
                    "GroupName": group_name,
                    "GroupId": group.get("GroupId"),
                    "Arn": group.get("Arn"),
                    "CreateDate": group.get("CreateDate"),
                    "Path": group.get("Path"),
                }

                # Get group details (includes users)
                try:
                    group_info = iam_client.get_group(GroupName=group_name)
                    group_detail["Users"] = group_info.get("Users", [])
                except Exception as e:
                    logger.warning(f"Could not get users for group {group_name}: {e}")
                    group_detail["Users"] = []

                # Attached policies
                try:
                    attached = iam_client.list_attached_group_policies(GroupName=group_name)
                    group_detail["AttachedPolicies"] = attached.get("AttachedPolicies", [])
                except Exception as e:
                    logger.warning(f"Could not list attached policies for group {group_name}: {e}")
                    group_detail["AttachedPolicies"] = []

                # Inline policies
                try:
                    inline = iam_client.list_group_policies(GroupName=group_name)
                    group_detail["InlinePolicies"] = inline.get("PolicyNames", [])
                except Exception as e:
                    logger.warning(f"Could not list inline policies for group {group_name}: {e}")
                    group_detail["InlinePolicies"] = []

                groups_detailed.append(group_detail)
        except Exception as e:
            logger.error(f"Could not list IAM groups: {e}")

        self._save_json(evidence_path / "groups.json", groups_detailed)

        # === ROLES (detailed) ===
        print("  Collecting IAM roles...")
        roles_detailed = []
        try:
            roles_basic = iam_client.list_roles().get("Roles", [])

            for role in roles_basic:
                role_name = role["RoleName"]
                role_detail = {
                    "RoleName": role_name,
                    "RoleId": role.get("RoleId"),
                    "Arn": role.get("Arn"),
                    "CreateDate": role.get("CreateDate"),
                    "Path": role.get("Path"),
                    "AssumeRolePolicyDocument": role.get("AssumeRolePolicyDocument"),
                }

                # Get full role info
                try:
                    role_info = iam_client.get_role(RoleName=role_name)
                    role_detail["Role"] = role_info.get("Role", {})
                except Exception as e:
                    logger.warning(f"Could not get role details for {role_name}: {e}")

                # Attached policies
                try:
                    attached = iam_client.list_attached_role_policies(RoleName=role_name)
                    role_detail["AttachedPolicies"] = attached.get("AttachedPolicies", [])
                except Exception as e:
                    logger.warning(f"Could not list attached policies for role {role_name}: {e}")
                    role_detail["AttachedPolicies"] = []

                # Inline policies
                try:
                    inline = iam_client.list_role_policies(RoleName=role_name)
                    role_detail["InlinePolicies"] = inline.get("PolicyNames", [])
                except Exception as e:
                    logger.warning(f"Could not list inline policies for role {role_name}: {e}")
                    role_detail["InlinePolicies"] = []

                roles_detailed.append(role_detail)
        except Exception as e:
            logger.error(f"Could not list IAM roles: {e}")

        self._save_json(evidence_path / "roles.json", roles_detailed)

        # === POLICIES (customer-managed with versions) ===
        print("  Collecting IAM policies...")
        policies_detailed = []
        try:
            policies_basic = iam_client.list_policies(Scope="Local").get("Policies", [])

            for policy in policies_basic:
                policy_arn = policy["Arn"]
                policy_detail = {
                    "PolicyName": policy.get("PolicyName"),
                    "PolicyId": policy.get("PolicyId"),
                    "Arn": policy_arn,
                    "CreateDate": policy.get("CreateDate"),
                    "UpdateDate": policy.get("UpdateDate"),
                    "AttachmentCount": policy.get("AttachmentCount"),
                }

                # Get policy details
                try:
                    policy_info = iam_client.get_policy(PolicyArn=policy_arn)
                    policy_detail["Policy"] = policy_info.get("Policy", {})

                    # Get default version document
                    default_version = policy_info["Policy"].get("DefaultVersionId")
                    if default_version:
                        version_doc = iam_client.get_policy_version(
                            PolicyArn=policy_arn, VersionId=default_version
                        )
                        policy_detail["PolicyDocument"] = version_doc.get("PolicyVersion", {}).get(
                            "Document"
                        )
                except Exception as e:
                    logger.warning(f"Could not get details for policy {policy_arn}: {e}")

                policies_detailed.append(policy_detail)
        except Exception as e:
            logger.error(f"Could not list IAM policies: {e}")

        self._save_json(evidence_path / "policies.json", policies_detailed)

        # === CREDENTIAL REPORT ===
        print("  Generating credential report...")
        try:
            # Generate report (may take a few seconds)
            iam_client.generate_credential_report()

            # Wait and retry a few times
            import time

            for i in range(5):
                time.sleep(2)
                try:
                    report_response = iam_client.get_credential_report()
                    if report_response["Content"]:
                        # In boto3, Content is typically raw CSV bytes (not base64).
                        # Some environments/tools may return a string; handle both.
                        content = report_response["Content"]

                        report_csv = ""
                        if isinstance(content, (bytes, bytearray)):
                            report_csv = bytes(content).decode("utf-8", errors="replace")
                        elif isinstance(content, str):
                            # Best-effort: try base64 decode if it's base64; otherwise treat as raw CSV.
                            try:
                                import base64

                                report_csv = base64.b64decode(content).decode(
                                    "utf-8", errors="replace"
                                )
                            except Exception:
                                report_csv = content
                        else:
                            report_csv = str(content)

                        # Save as CSV
                        with open(evidence_path / "credential-report.csv", "w") as f:
                            f.write(report_csv)
                        print("    Credential report saved")
                        break
                except Exception as e:
                    logger.info(f"Credential report not ready yet (attempt {i + 1}/5): {e}")
                    continue
        except Exception as e:
            logger.error(f"Could not generate credential report: {e}")

        # === ASSUME ROLE CHAINS ===
        print("  Collecting AssumeRole trust chains...")
        chains, chains_error = self._collect_assume_role_chains(iam_client)
        self._save_json(
            evidence_path / "assumeRole-chains.json",
            {
                "chains": chains,
                "error": chains_error,
            },
        )

        # === RESOURCE-BASED POLICIES ===
        print("  Collecting resource-based policies (S3/Lambda/SQS/SNS)...")
        resource_policies, policies_error = self._collect_resource_based_policies(client_kwargs)
        self._save_json(
            evidence_path / "resource-based-policies.json",
            {
                **resource_policies,
                "error": policies_error,
            },
        )

        # === INSTANCE PROFILES ===
        print("  Collecting instance profiles and attached role permissions...")
        profiles, profiles_error = self._collect_instance_profiles(iam_client)
        self._save_json(
            evidence_path / "instance-profiles.json",
            {
                "instance_profiles": profiles,
                "error": profiles_error,
            },
        )

        # === SUMMARY ===
        print("\n✅ IAM collection complete:")
        print(f"   - {len(users_detailed)} users")
        print(f"   - {len(groups_detailed)} groups")
        print(f"   - {len(roles_detailed)} roles")
        print(f"   - {len(policies_detailed)} custom policies")

    def _extract_trust_principals(self, trust_policy: Dict[str, Any]) -> List[str]:
        """Extract principal values from trust policy document."""
        out: List[str] = []
        for st in trust_policy.get("Statement", []) or []:
            if not isinstance(st, dict):
                continue
            principal = st.get("Principal")
            if principal == "*":
                out.append("*")
                continue
            if not isinstance(principal, dict):
                continue
            for key in ("AWS", "Service", "Federated", "CanonicalUser"):
                val = principal.get(key)
                if isinstance(val, str):
                    out.append(val)
                elif isinstance(val, list):
                    out.extend([x for x in val if isinstance(x, str)])
        return sorted(set(out))

    def _collect_assume_role_chains(
        self, iam_client: Any
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Map AssumeRole trust relationships for privilege-escalation analysis."""
        chains: List[Dict[str, Any]] = []
        try:
            roles = iam_client.list_roles().get("Roles", [])
            for role in roles:
                trust_policy = role.get("AssumeRolePolicyDocument") or {}
                chains.append(
                    {
                        "RoleName": role.get("RoleName"),
                        "Arn": role.get("Arn"),
                        "TrustedPrincipals": self._extract_trust_principals(trust_policy),
                        "MaxSessionDuration": role.get("MaxSessionDuration"),
                        "PermissionsBoundary": role.get("PermissionsBoundary"),
                    }
                )
            return chains, None
        except ClientError as e:
            return chains, str(e)

    def _collect_resource_based_policies(
        self, client_kwargs: Dict[str, Any]
    ) -> Tuple[Dict[str, List[Dict[str, Any]]], Optional[str]]:
        """Collect resource policies from S3/Lambda/SQS/SNS."""
        policies: Dict[str, List[Dict[str, Any]]] = {"s3": [], "lambda": [], "sqs": [], "sns": []}
        errors: List[str] = []

        # S3
        try:
            s3 = boto3.client("s3", **client_kwargs)
            for bucket in s3.list_buckets().get("Buckets", []) or []:
                name = bucket.get("Name")
                if not name:
                    continue
                try:
                    policy = s3.get_bucket_policy(Bucket=name)
                    policies["s3"].append(
                        {
                            "BucketName": name,
                            "Policy": json.loads(policy.get("Policy", "{}")),
                        }
                    )
                except ClientError:
                    continue
        except ClientError as e:
            errors.append(f"s3: {e}")

        # Lambda
        try:
            lam = boto3.client("lambda", **client_kwargs)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []) or []:
                    fn_name = fn.get("FunctionName")
                    if not fn_name:
                        continue
                    try:
                        resp = lam.get_policy(FunctionName=fn_name)
                        policies["lambda"].append(
                            {
                                "FunctionName": fn_name,
                                "FunctionArn": fn.get("FunctionArn"),
                                "Policy": json.loads(resp.get("Policy", "{}")),
                            }
                        )
                    except ClientError:
                        continue
        except ClientError as e:
            errors.append(f"lambda: {e}")

        # SQS
        try:
            sqs = boto3.client("sqs", **client_kwargs)
            urls = sqs.list_queues().get("QueueUrls", []) or []
            for queue_url in urls:
                try:
                    attrs = sqs.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=["QueueArn", "Policy"],
                    ).get("Attributes", {})
                    policy_raw = attrs.get("Policy")
                    if policy_raw:
                        policies["sqs"].append(
                            {
                                "QueueUrl": queue_url,
                                "QueueArn": attrs.get("QueueArn"),
                                "Policy": json.loads(policy_raw),
                            }
                        )
                except ClientError:
                    continue
        except ClientError as e:
            errors.append(f"sqs: {e}")

        # SNS
        try:
            sns = boto3.client("sns", **client_kwargs)
            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []) or []:
                    arn = topic.get("TopicArn")
                    if not arn:
                        continue
                    try:
                        attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                        policy_raw = attrs.get("Policy")
                        if policy_raw:
                            policies["sns"].append(
                                {
                                    "TopicArn": arn,
                                    "Policy": json.loads(policy_raw),
                                }
                            )
                    except ClientError:
                        continue
        except ClientError as e:
            errors.append(f"sns: {e}")

        return policies, "; ".join(errors) if errors else None

    def _collect_instance_profiles(
        self, iam_client: Any
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Collect instance profiles and attached role policy summaries."""
        out: List[Dict[str, Any]] = []
        try:
            paginator = iam_client.get_paginator("list_instance_profiles")
            for page in paginator.paginate():
                for prof in page.get("InstanceProfiles", []) or []:
                    p_name = prof.get("InstanceProfileName")
                    entry: Dict[str, Any] = {
                        "InstanceProfileName": p_name,
                        "Arn": prof.get("Arn"),
                        "Roles": [],
                    }
                    for role in prof.get("Roles", []) or []:
                        role_name = role.get("RoleName")
                        role_entry: Dict[str, Any] = {
                            "RoleName": role_name,
                            "Arn": role.get("Arn"),
                            "AttachedPolicies": [],
                            "InlinePolicies": [],
                        }
                        if role_name:
                            try:
                                attached = iam_client.list_attached_role_policies(
                                    RoleName=role_name
                                ).get("AttachedPolicies", [])
                                role_entry["AttachedPolicies"] = attached
                            except ClientError:
                                pass
                            try:
                                inline = iam_client.list_role_policies(RoleName=role_name).get(
                                    "PolicyNames", []
                                )
                                role_entry["InlinePolicies"] = inline
                            except ClientError:
                                pass
                        entry["Roles"].append(role_entry)
                    out.append(entry)
            return out, None
        except ClientError as e:
            return out, str(e)

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization.

        Args:
            filepath: Target file path
            data: Data to serialize (handles datetime objects)
        """
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _load_extra_evidence(self, evidence: dict, evidence_path: Path) -> None:
        """Load credential-report.csv into evidence dict.

        The IAM credential report is a CSV (not JSON) file that base.py's
        *.json glob skips.  This hook is called by BaseSkill.analyze() after
        the JSON files are loaded so that pre-checks can access it via
        evidence["credential-report"].
        """
        cred_report_path = evidence_path / "credential-report.csv"
        if not cred_report_path.exists():
            return
        try:
            import csv as _csv

            with open(cred_report_path, "r", encoding="utf-8", errors="replace") as f:
                reader = _csv.DictReader(f)
                rows = [dict(r) for r in reader]

            by_user: dict = {}
            for r in rows:
                u = r.get("user")
                if u and u not in by_user:
                    by_user[u] = r

            evidence["credential-report"] = {
                "rows": rows,
                "by_user": by_user,
            }
        except Exception as e:
            logger.warning(f"Could not read credential report CSV: {e}")


__all__ = ["IAMSkill"]
