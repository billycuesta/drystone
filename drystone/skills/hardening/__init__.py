"""Account hardening skill for AWS audit."""

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


class HardeningSkill(BaseSkill):
    """Account hardening audit skill - analyzes Config, Security Hub, and compliance posture."""

    @property
    def name(self) -> str:
        """Skill identifier."""
        return "hardening"

    def collect(self, aws_client: AWSClient, session: AuditSession):
        """Collect account hardening and compliance data from AWS account.

        Collects:
            - AWS Security Hub findings and compliance standards
            - AWS Config configuration and compliance rules
            - ACM certificates (expiry and validation)
            - GuardDuty findings and status
            - Macie findings and sensitivity
            - Account settings and backup configuration
            - Resource tags for governance
            - Disaster recovery and backup status

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

        # === SECURITY HUB ===
        print("  Collecting Security Hub findings...")
        try:
            sh_client = boto3.client("securityhub", **client_kwargs)

            # Get hub status
            try:
                hub = sh_client.describe_hub()
                self._save_json(evidence_path / "security-hub-status.json", hub)
            except Exception as e:
                logger.warning(f"Could not describe Security Hub: {e}")

            # List findings (filtered by severity: Critical, High only)
            findings_list = []
            try:
                paginator = sh_client.get_paginator('get_findings')

                # Filter criteria for Security Hub (only Critical, High + Active)
                # MEDIUM excluded: 80% are low-impact findings (consistent with Inspector filtering)
                filters = {
                    'SeverityLabel': [
                        {'Value': 'CRITICAL', 'Comparison': 'EQUALS'},
                        {'Value': 'HIGH', 'Comparison': 'EQUALS'}
                    ],
                    'RecordState': [
                        {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}
                    ]
                }

                for page in paginator.paginate(Filters=filters):
                    findings_list.extend(page.get("Findings", []))
            except Exception as e:
                logger.warning(f"Could not paginate Security Hub findings: {e}")

            self._save_json(evidence_path / "security-hub-findings.json", findings_list)

            # Get standards and compliance
            try:
                standards = sh_client.describe_standards()
                compliance_list = []

                for standard in standards.get("Standards", []):
                    std_detail = {
                        "StandardsArn": standard.get("StandardsArn"),
                        "Name": standard.get("Name"),
                        "Description": standard.get("Description"),
                    }

                    # Get subscription status
                    try:
                        subscriptions = sh_client.describe_standards_control(
                            StandardsSubscriptionArn=standard.get("StandardsArn")
                        )
                        std_detail["Controls"] = subscriptions.get("Controls", [])
                    except Exception as e:
                        logger.warning(f"Could not describe standards control for {standard.get('StandardsArn')}: {e}")
                        std_detail["Controls"] = []

                    compliance_list.append(std_detail)

                self._save_json(evidence_path / "security-hub-standards.json", compliance_list)
            except Exception as e:
                logger.warning(f"Could not describe Security Hub standards: {e}")

        except Exception as e:
            logger.error(f"Could not collect Security Hub data: {e}")

        # === AWS CONFIG ===
        print("  Collecting AWS Config compliance...")
        try:
            config_client = boto3.client("config", **client_kwargs)

            # Get recorder status
            try:
                recorders = config_client.describe_configuration_recorders()
                self._save_json(evidence_path / "config-recorders.json", recorders)
            except Exception as e:
                logger.warning(f"Could not describe Config recorders: {e}")

            # Get delivery channels
            try:
                channels = config_client.describe_delivery_channels()
                self._save_json(evidence_path / "config-delivery-channels.json", channels)
            except Exception as e:
                logger.warning(f"Could not describe Config delivery channels: {e}")

            # Get config rules compliance
            try:
                compliance_list = []
                rules = config_client.describe_config_rules()

                for rule in rules.get("ConfigRules", []):
                    rule_name = rule.get("ConfigRuleName")
                    try:
                        compliance = config_client.describe_compliance_by_config_rule(
                            ConfigRuleNames=[rule_name]
                        )
                        rule_detail = {
                            "ConfigRuleName": rule_name,
                            "Compliance": compliance.get("ComplianceByConfigRules", [{}])[0].get("Compliance", {}),
                        }
                        compliance_list.append(rule_detail)
                    except Exception as e:
                        logger.warning(f"Could not get compliance for Config rule {rule_name}: {e}")

                self._save_json(evidence_path / "config-compliance.json", compliance_list)
            except Exception as e:
                logger.warning(f"Could not describe Config rules: {e}")

        except Exception as e:
            logger.error(f"Could not collect Config data: {e}")

        # === ACM CERTIFICATES ===
        print("  Collecting ACM certificates...")
        try:
            acm_client = boto3.client("acm", **client_kwargs)
            certs_list = []

            paginator = acm_client.get_paginator('list_certificates')
            for page in paginator.paginate():
                for cert_summary in page.get("CertificateSummaryList", []):
                    cert_arn = cert_summary.get("CertificateArn")

                    try:
                        cert_detail = acm_client.describe_certificate(CertificateArn=cert_arn)
                        cert_info = {
                            "CertificateArn": cert_arn,
                            "DomainName": cert_detail.get("Certificate", {}).get("DomainName"),
                            "SubjectAlternativeNames": cert_detail.get("Certificate", {}).get(
                                "SubjectAlternativeNames", []
                            ),
                            "Status": cert_detail.get("Certificate", {}).get("Status"),
                            "NotBefore": cert_detail.get("Certificate", {}).get("NotBefore"),
                            "NotAfter": cert_detail.get("Certificate", {}).get("NotAfter"),
                            "ValidationMethod": cert_detail.get("Certificate", {}).get("ValidationMethod"),
                        }
                        certs_list.append(cert_info)
                    except Exception as e:
                        logger.warning(f"Could not describe ACM certificate {cert_arn}: {e}")

            self._save_json(evidence_path / "acm-certificates.json", certs_list)
        except Exception as e:
            logger.error(f"Could not collect ACM data: {e}")

        # === GUARDDUTY ===
        print("  Collecting GuardDuty status...")
        try:
            gd_client = boto3.client("guardduty", **client_kwargs)

            # List detectors
            try:
                detectors = gd_client.list_detectors()
                detectors_list = []

                for detector_id in detectors.get("DetectorIds", []):
                    detector_detail = gd_client.get_detector(DetectorId=detector_id)
                    detectors_list.append({
                        "DetectorId": detector_id,
                        "Status": detector_detail.get("Status"),
                        "FindingPublishingFrequency": detector_detail.get("FindingPublishingFrequency"),
                    })

                    # Get findings (up to 50, filtered by severity: Medium and above)
                    try:
                        findings = gd_client.list_findings(
                            DetectorId=detector_id,
                            MaxResults=50,
                            FindingCriteria={
                                'Criterion': {
                                    'severity': {
                                        'Gte': 4.0  # Medium (4.0-6.9), High (7.0-8.9), Critical (9.0+)
                                    }
                                }
                            }
                        )
                        detector_detail["FindingIds"] = findings.get("FindingIds", [])
                    except Exception as e:
                        logger.warning(f"Could not list GuardDuty findings for detector {detector_id}: {e}")
                        detector_detail["FindingIds"] = []

                self._save_json(evidence_path / "guardduty-detectors.json", detectors_list)
            except Exception as e:
                logger.warning(f"Could not list GuardDuty detectors: {e}")

        except Exception as e:
            logger.error(f"Could not collect GuardDuty data: {e}")

        # === MACIE ===
        print("  Collecting Macie status...")
        try:
            macie_client = boto3.client("macie2", **client_kwargs)

            # Get Macie status
            try:
                status = macie_client.get_macie_session()
                self._save_json(evidence_path / "macie-session.json", status)
            except Exception as e:
                logger.warning(f"Could not get Macie session: {e}")

            # List findings (filtered by severity: High only - post-filter since API doesn't support it)
            try:
                findings_list = []
                paginator = macie_client.get_paginator('list_findings')
                for page in paginator.paginate(MaxResults=50):
                    for finding_id in page.get("findingIds", []):
                        try:
                            finding = macie_client.get_findings(FindingIds=[finding_id])
                            finding_details = finding.get("findings", [])

                            # Post-filter: only High severity (Macie doesn't have Critical, MEDIUM excluded for consistency)
                            for f in finding_details:
                                severity = f.get("severity", {}).get("description", "").upper()
                                if severity in ["HIGH"]:
                                    findings_list.append(f)
                        except Exception as e:
                            logger.warning(f"Could not get Macie finding {finding_id}: {e}")

                self._save_json(evidence_path / "macie-findings.json", findings_list)
            except Exception as e:
                logger.warning(f"Could not list Macie findings: {e}")

        except Exception as e:
            logger.error(f"Could not collect Macie data: {e}")

        # === BACKUP VAULTS ===
        print("  Collecting backup configuration...")
        try:
            backup_client = boto3.client("backup", **client_kwargs)
            vaults_list = []

            # List backup vaults
            try:
                paginator = backup_client.get_paginator('list_backup_vaults')
                for page in paginator.paginate():
                    for vault in page.get("BackupVaultList", []):
                        vault_detail = {
                            "BackupVaultName": vault.get("BackupVaultName"),
                            "BackupVaultArn": vault.get("BackupVaultArn"),
                            "CreationDate": vault.get("CreationDate"),
                            "RecoveryPoints": vault.get("NumberOfRecoveryPoints"),
                        }
                        vaults_list.append(vault_detail)

                self._save_json(evidence_path / "backup-vaults.json", vaults_list)
            except Exception as e:
                logger.warning(f"Could not list backup vaults: {e}")

            # List backup plans
            try:
                plans = backup_client.list_backup_plans()
                self._save_json(evidence_path / "backup-plans.json", plans.get("BackupPlansList", []))
            except Exception as e:
                logger.warning(f"Could not list backup plans: {e}")

        except Exception as e:
            logger.error(f"Could not collect backup data: {e}")

        # === ACCOUNT SETTINGS ===
        print("  Collecting account settings...")
        try:
            iam_client = boto3.client("iam", **client_kwargs)

            # Account summary
            try:
                summary = iam_client.get_account_summary()
                self._save_json(evidence_path / "account-summary.json", summary)
            except Exception as e:
                logger.warning(f"Could not get account summary: {e}")

            # Account aliases
            try:
                aliases = iam_client.list_account_aliases()
                self._save_json(evidence_path / "account-aliases.json", aliases)
            except Exception as e:
                logger.warning(f"Could not list account aliases: {e}")

            # Password policy
            try:
                pwd_policy = iam_client.get_account_password_policy()
                self._save_json(evidence_path / "password-policy.json", pwd_policy)
            except iam_client.exceptions.NoSuchEntityException:
                self._save_json(evidence_path / "password-policy.json", {"error": "No password policy"})
            except Exception as e:
                logger.warning(f"Could not get account password policy: {e}")

        except Exception as e:
            logger.error(f"Could not collect account settings: {e}")

        print(f"\n✅ Hardening collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["HardeningSkill"]
