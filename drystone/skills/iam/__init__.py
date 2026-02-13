"""IAM security skill for AWS audit."""

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

        # === SUMMARY ===
        print(f"\n✅ IAM collection complete:")
        print(f"   - {len(users_detailed)} users")
        print(f"   - {len(groups_detailed)} groups")
        print(f"   - {len(roles_detailed)} roles")
        print(f"   - {len(policies_detailed)} custom policies")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization.

        Args:
            filepath: Target file path
            data: Data to serialize (handles datetime objects)
        """
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def analyze(self, session: AuditSession, agent_client: "AgentClient") -> Path:
        """Analyze collected IAM evidence using Gemini API.

        1. Read all evidence files
        2. Read security checklist
        3. Send to Gemini API for analysis
        4. Save findings to findings/iam.json
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

        # Include credential report (CSV) if collected.
        # This is a high-signal artifact for root MFA + access key checks.
        cred_report_path = evidence_path / "credential-report.csv"
        if cred_report_path.exists():
            try:
                import csv

                with open(cred_report_path, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    rows = [dict(r) for r in reader]

                by_user = {}
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

        print(f"    Loaded {len(evidence)} evidence files")

        # 2. Read checklist
        checklist_path = Path(__file__).parent / "checklist.json"
        if not checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {checklist_path}")

        with open(checklist_path) as f:
            checklist = json.load(f)

        print(f"    Loaded {len(checklist['items'])} security checks")

        # 3. Call agent for analysis
        provider_name = agent_client.get_display_name()
        print(f"  Analyzing with {provider_name}...")
        findings = agent_client.analyze_evidence(
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


__all__ = ["IAMSkill"]
