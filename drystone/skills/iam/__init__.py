"""IAM security skill for AWS audit."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

import boto3

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession

if TYPE_CHECKING:
    from drystone.agent.client import AgentClient


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
            'aws_access_key_id': aws_client.access_key_id,
            'aws_secret_access_key': aws_client.secret_access_key,
            'region_name': aws_client.region_name,
        }
        # Add session token only if provided (for temporary credentials)
        if aws_client.session_token:
            client_kwargs['aws_session_token'] = aws_client.session_token

        iam_client = boto3.client("iam", **client_kwargs)

        evidence_path = session.get_evidence_path(self.name)

        # === ACCOUNT INFORMATION ===
        print("  Collecting account information...")
        try:
            account_summary = iam_client.get_account_summary()
            self._save_json(evidence_path / "account-summary.json", account_summary)
        except Exception as e:
            print(f"    Warning: Could not get account summary: {e}")

        try:
            account_aliases = iam_client.list_account_aliases()
            self._save_json(evidence_path / "account-aliases.json", account_aliases)
        except Exception as e:
            print(f"    Warning: Could not get account aliases: {e}")

        # === PASSWORD POLICY ===
        print("  Collecting password policy...")
        try:
            password_policy = iam_client.get_account_password_policy()
            self._save_json(evidence_path / "password-policy.json", password_policy)
        except iam_client.exceptions.NoSuchEntityException:
            print("    No password policy set")
            self._save_json(
                evidence_path / "password-policy.json",
                {"error": "No password policy configured"},
            )
        except Exception as e:
            print(f"    Warning: Could not get password policy: {e}")

        # === USERS (detailed) ===
        print("  Collecting IAM users...")
        users_basic = iam_client.list_users().get("Users", [])
        users_detailed = []

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
                    except Exception:
                        key["LastUsed"] = None
            except Exception:
                user_detail["AccessKeys"] = []

            # MFA devices
            try:
                mfa_response = iam_client.list_mfa_devices(UserName=username)
                user_detail["MFADevices"] = mfa_response.get("MFADevices", [])
            except Exception:
                user_detail["MFADevices"] = []

            # Inline policies
            try:
                inline_response = iam_client.list_user_policies(UserName=username)
                user_detail["InlinePolicies"] = inline_response.get("PolicyNames", [])
            except Exception:
                user_detail["InlinePolicies"] = []

            # Attached managed policies
            try:
                attached_response = iam_client.list_attached_user_policies(
                    UserName=username
                )
                user_detail["AttachedPolicies"] = attached_response.get(
                    "AttachedPolicies", []
                )
            except Exception:
                user_detail["AttachedPolicies"] = []

            # Groups
            try:
                groups_response = iam_client.list_groups_for_user(UserName=username)
                user_detail["Groups"] = groups_response.get("Groups", [])
            except Exception:
                user_detail["Groups"] = []

            users_detailed.append(user_detail)

        self._save_json(evidence_path / "users.json", users_detailed)

        # === GROUPS (detailed) ===
        print("  Collecting IAM groups...")
        groups_basic = iam_client.list_groups().get("Groups", [])
        groups_detailed = []

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
            except Exception:
                group_detail["Users"] = []

            # Attached policies
            try:
                attached = iam_client.list_attached_group_policies(GroupName=group_name)
                group_detail["AttachedPolicies"] = attached.get("AttachedPolicies", [])
            except Exception:
                group_detail["AttachedPolicies"] = []

            # Inline policies
            try:
                inline = iam_client.list_group_policies(GroupName=group_name)
                group_detail["InlinePolicies"] = inline.get("PolicyNames", [])
            except Exception:
                group_detail["InlinePolicies"] = []

            groups_detailed.append(group_detail)

        self._save_json(evidence_path / "groups.json", groups_detailed)

        # === ROLES (detailed) ===
        print("  Collecting IAM roles...")
        roles_basic = iam_client.list_roles().get("Roles", [])
        roles_detailed = []

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
            except Exception:
                pass

            # Attached policies
            try:
                attached = iam_client.list_attached_role_policies(RoleName=role_name)
                role_detail["AttachedPolicies"] = attached.get("AttachedPolicies", [])
            except Exception:
                role_detail["AttachedPolicies"] = []

            # Inline policies
            try:
                inline = iam_client.list_role_policies(RoleName=role_name)
                role_detail["InlinePolicies"] = inline.get("PolicyNames", [])
            except Exception:
                role_detail["InlinePolicies"] = []

            roles_detailed.append(role_detail)

        self._save_json(evidence_path / "roles.json", roles_detailed)

        # === POLICIES (customer-managed with versions) ===
        print("  Collecting IAM policies...")
        policies_basic = iam_client.list_policies(Scope="Local").get("Policies", [])
        policies_detailed = []

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
                    policy_detail["PolicyDocument"] = version_doc.get(
                        "PolicyVersion", {}
                    ).get("Document")
            except Exception:
                pass

            policies_detailed.append(policy_detail)

        self._save_json(evidence_path / "policies.json", policies_detailed)

        # === CREDENTIAL REPORT ===
        print("  Generating credential report...")
        try:
            # Generate report (may take a few seconds)
            iam_client.generate_credential_report()

            # Wait and retry a few times
            import time

            for _ in range(5):
                time.sleep(2)
                try:
                    report_response = iam_client.get_credential_report()
                    if report_response["Content"]:
                        # Decode base64 content
                        import base64

                        report_csv = base64.b64decode(
                            report_response["Content"]
                        ).decode("utf-8")

                        # Save as CSV
                        with open(evidence_path / "credential-report.csv", "w") as f:
                            f.write(report_csv)
                        print("    Credential report saved")
                        break
                except Exception:
                    continue
        except Exception as e:
            print(f"    Warning: Could not generate credential report: {e}")

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
        """Analyze collected IAM evidence using Claude API.

        1. Read all evidence files
        2. Read security checklist
        3. Send to Claude API for analysis
        4. Save findings to findings/iam.json
        5. Print summary

        Args:
            session: Audit session with collected evidence
            agent_client: Claude AI client for analysis

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
                print(f"    Warning: Could not read {json_file.name}: {e}")

        print(f"    Loaded {len(evidence)} evidence files")

        # 2. Read checklist
        checklist_path = Path(__file__).parent / "checklist.json"
        if not checklist_path.exists():
            raise FileNotFoundError(f"Checklist not found: {checklist_path}")

        with open(checklist_path) as f:
            checklist = json.load(f)

        print(f"    Loaded {len(checklist['items'])} security checks")

        # 3. Call agent for analysis
        print("  Analyzing with Claude API...")
        findings = agent_client.analyze_evidence(
            skill_name=self.name, evidence=evidence, checklist=checklist
        )

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
