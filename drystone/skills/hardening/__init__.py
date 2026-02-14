"""Account hardening skill for AWS audit.

Collector design goals:
- Evidence must be unambiguous (distinguish "empty" from "collection failed")
- Prefer summary/typed evidence over huge raw payloads
- Align evidence files with checklist applicability
"""

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import boto3

from drystone.cloud.aws.client import AWSClient
from drystone.skills.base import BaseSkill
from drystone.storage.session import AuditSession
from drystone.utils.logging import get_logger

if TYPE_CHECKING:
    pass

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
            "aws_access_key_id": aws_client.access_key_id,
            "aws_secret_access_key": aws_client.secret_access_key,
            "region_name": aws_client.region_name,
        }
        if aws_client.session_token:
            client_kwargs["aws_session_token"] = aws_client.session_token

        evidence_path = session.get_evidence_path(self.name)

        collection_status: Dict[str, Any] = {
            "region": aws_client.region_name,
            "securityhub": {"ok": True, "error": None},
            "securityhub_findings": {"ok": True, "error": None, "count": 0},
            "securityhub_standards": {"ok": True, "error": None, "enabled_count": 0},
            "config": {"ok": True, "error": None},
            "guardduty": {"ok": True, "error": None},
            "macie": {"ok": True, "error": None},
            "backup": {"ok": True, "error": None},
            "iam_account": {"ok": True, "error": None},
        }

        # === SECURITY HUB ===
        print("  Collecting Security Hub findings...")
        try:
            sh_client = boto3.client("securityhub", **client_kwargs)

            # Get hub status with explicit enabled flag
            try:
                hub = sh_client.describe_hub()
                hub_status = {
                    "enabled": True,  # Explicit status flag
                    "HubArn": hub.get("HubArn"),
                    "SubscribedAt": hub.get("SubscribedAt"),
                    "AutoEnableControls": hub.get("AutoEnableControls"),
                    "ControlFindingGenerator": hub.get("ControlFindingGenerator"),
                    "EnabledStandardsSubscriptions": hub.get("EnabledStandardsSubscriptions", []),
                }
                self._save_json(evidence_path / "security-hub-status.json", hub_status)
            except sh_client.exceptions.InvalidAccessException:
                # Hub is not enabled
                hub_status = {
                    "enabled": False,
                    "reason": "not_enabled",
                    "error": "InvalidAccessException - Security Hub is not enabled",
                }
                self._save_json(evidence_path / "security-hub-status.json", hub_status)
            except Exception as e:
                logger.warning(f"Could not describe Security Hub: {e}")
                hub_status = {"enabled": False, "reason": "error", "error": str(e)}
                self._save_json(evidence_path / "security-hub-status.json", hub_status)

            # List findings (filtered by severity: Critical, High, Medium)
            findings_list: List[Dict[str, Any]] = []
            try:
                paginator = sh_client.get_paginator("get_findings")

                # Filter criteria for Security Hub (Critical, High, Medium + Active)
                # Keep Medium to support compliance scoring and posture evaluation.
                filters = {
                    "SeverityLabel": [
                        {"Value": "CRITICAL", "Comparison": "EQUALS"},
                        {"Value": "HIGH", "Comparison": "EQUALS"},
                        {"Value": "MEDIUM", "Comparison": "EQUALS"},
                    ],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                }

                # Cap findings collected to avoid extremely large evidence files.
                max_findings = 800

                for page in paginator.paginate(Filters=filters):
                    raw_findings = page.get("Findings", []) or []

                    for finding in raw_findings:
                        # Build a compact, stable representation.
                        sev = finding.get("Severity") or {}
                        compliance = finding.get("Compliance") or {}
                        resources_out: List[Dict[str, Any]] = []
                        for r in finding.get("Resources", []) or []:
                            resources_out.append(
                                {
                                    "Type": r.get("Type"),
                                    "Id": r.get("Id"),
                                    "Region": r.get("Region"),
                                    "Partition": r.get("Partition"),
                                }
                            )

                        findings_list.append(
                            {
                                "Id": finding.get("Id"),
                                "GeneratorId": finding.get("GeneratorId"),
                                "ProductName": finding.get("ProductName"),
                                "Region": finding.get("Region"),
                                "AwsAccountId": finding.get("AwsAccountId"),
                                "CreatedAt": finding.get("CreatedAt"),
                                "Title": finding.get("Title"),
                                "Description": finding.get("Description"),
                                "Severity": {
                                    "Label": sev.get("Label"),
                                    "Normalized": sev.get("Normalized"),
                                    "Original": sev.get("Original"),
                                },
                                "Compliance": {
                                    "Status": compliance.get("Status"),
                                }
                                if isinstance(compliance, dict)
                                else {},
                                "WorkflowState": finding.get("WorkflowState"),
                                "RecordState": finding.get("RecordState"),
                                "Resources": resources_out,
                                "Remediation": (finding.get("Remediation") or {}).get(
                                    "Recommendation"
                                ),
                            }
                        )

                        if len(findings_list) >= max_findings:
                            break

                    if len(findings_list) >= max_findings:
                        break
            except Exception as e:
                logger.warning(f"Could not paginate Security Hub findings: {e}")
                collection_status["securityhub_findings"].update({"ok": False, "error": str(e)})

            self._save_json(evidence_path / "security-hub-findings.json", findings_list)
            collection_status["securityhub_findings"]["count"] = len(findings_list)

            # Findings summary (small, stable, avoids re-parsing large arrays)
            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "OTHER": 0}
            comp_counts = {"PASSED": 0, "FAILED": 0, "WARNING": 0, "NOT_AVAILABLE": 0, "OTHER": 0}
            for f in findings_list:
                sev_label = ((f.get("Severity") or {}).get("Label") or "").upper()
                if sev_label in sev_counts:
                    sev_counts[sev_label] += 1
                else:
                    sev_counts["OTHER"] += 1

                comp_status = ((f.get("Compliance") or {}).get("Status") or "").upper()
                if comp_status in comp_counts:
                    comp_counts[comp_status] += 1
                elif comp_status:
                    comp_counts["OTHER"] += 1

            self._save_json(
                evidence_path / "security-hub-findings-summary.json",
                {
                    "severity_counts": sev_counts,
                    "compliance_status_counts": comp_counts,
                    "total": len(findings_list),
                },
            )

            # Enabled standards + controls (best-effort, compact)
            enabled_standards: List[Dict[str, Any]] = []
            try:
                token: Optional[str] = None
                while True:
                    args: Dict[str, Any] = {"MaxResults": 50}
                    if token:
                        args["NextToken"] = token
                    resp = sh_client.get_enabled_standards(**args)
                    enabled_standards.extend(resp.get("StandardsSubscriptions", []) or [])
                    token = resp.get("NextToken")
                    if not token:
                        break
            except Exception as e:
                logger.warning(f"Could not get enabled Security Hub standards: {e}")
                collection_status["securityhub_standards"].update({"ok": False, "error": str(e)})

            enabled_out: List[Dict[str, Any]] = []
            for sub in enabled_standards:
                sub_arn = sub.get("StandardsSubscriptionArn")
                std_arn = sub.get("StandardsArn")
                std_name = sub.get("StandardsSubscriptionName")

                # List controls for this enabled standard.
                controls_summary = {
                    "total": 0,
                    "enabled": 0,
                    "disabled": 0,
                }
                controls_sample: List[Dict[str, Any]] = []
                if sub_arn:
                    try:
                        ctl_token: Optional[str] = None
                        while True:
                            ctl_args: Dict[str, Any] = {
                                "StandardsSubscriptionArn": sub_arn,
                                "MaxResults": 100,
                            }
                            if ctl_token:
                                ctl_args["NextToken"] = ctl_token
                            ctl_resp = sh_client.describe_standards_controls(**ctl_args)
                            controls = ctl_resp.get("Controls", []) or []
                            for c in controls:
                                controls_summary["total"] += 1
                                if c.get("ControlStatus") == "ENABLED":
                                    controls_summary["enabled"] += 1
                                elif c.get("ControlStatus") == "DISABLED":
                                    controls_summary["disabled"] += 1

                                # Keep a small sample of control metadata for auditability.
                                if len(controls_sample) < 25:
                                    controls_sample.append(
                                        {
                                            "ControlId": c.get("ControlId"),
                                            "Title": c.get("Title"),
                                            "ControlStatus": c.get("ControlStatus"),
                                            "SeverityRating": c.get("SeverityRating"),
                                        }
                                    )

                            ctl_token = ctl_resp.get("NextToken")
                            if not ctl_token:
                                break
                    except Exception as e:
                        logger.warning(
                            f"Could not describe Security Hub controls for {sub_arn}: {e}"
                        )
                        collection_status["securityhub_standards"].update(
                            {"ok": False, "error": str(e)}
                        )

                enabled_out.append(
                    {
                        "StandardsSubscriptionArn": sub_arn,
                        "StandardsArn": std_arn,
                        "Name": std_name,
                        "Status": sub.get("StandardsStatus"),
                        "StatusReason": sub.get("StandardsStatusReason"),
                        "ControlsSummary": controls_summary,
                        "ControlsSample": controls_sample,
                    }
                )

            self._save_json(evidence_path / "security-hub-enabled-standards.json", enabled_out)
            collection_status["securityhub_standards"]["enabled_count"] = len(enabled_out)

        except Exception as e:
            logger.error(f"Could not collect Security Hub data: {e}")
            collection_status["securityhub"].update({"ok": False, "error": str(e)})

        # === AWS CONFIG ===
        print("  Collecting AWS Config compliance...")
        try:
            config_client = boto3.client("config", **client_kwargs)

            # Get recorder status with explicit enabled flag
            try:
                recorders_response = config_client.describe_configuration_recorders()
                recorders = recorders_response.get("ConfigurationRecorders", [])
                config_status = {
                    "enabled": len(recorders) > 0,  # Explicit status flag
                    "ConfigurationRecorders": recorders,
                }
                self._save_json(evidence_path / "config-recorders.json", config_status)
            except Exception as e:
                logger.warning(f"Could not describe Config recorders: {e}")
                config_status = {"enabled": False, "ConfigurationRecorders": [], "error": str(e)}
                self._save_json(evidence_path / "config-recorders.json", config_status)

            # Get delivery channels
            try:
                channels = config_client.describe_delivery_channels()
                self._save_json(evidence_path / "config-delivery-channels.json", channels)
            except Exception as e:
                logger.warning(f"Could not describe Config delivery channels: {e}")
                collection_status["config"].update({"ok": False, "error": str(e)})

            # Recorder status (RECORDING vs stopped)
            try:
                status = config_client.describe_configuration_recorder_status()
                self._save_json(evidence_path / "config-recorder-status.json", status)
            except Exception as e:
                logger.warning(f"Could not describe Config recorder status: {e}")
                self._save_json(
                    evidence_path / "config-recorder-status.json",
                    {"error": str(e), "ConfigurationRecordersStatus": []},
                )
                collection_status["config"].update({"ok": False, "error": str(e)})

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
                            "Compliance": compliance.get("ComplianceByConfigRules", [{}])[0].get(
                                "Compliance", {}
                            ),
                        }
                        compliance_list.append(rule_detail)
                    except Exception as e:
                        logger.warning(f"Could not get compliance for Config rule {rule_name}: {e}")

                self._save_json(evidence_path / "config-compliance.json", compliance_list)

                # Compact compliance summary
                c_counts = {
                    "COMPLIANT": 0,
                    "NON_COMPLIANT": 0,
                    "INSUFFICIENT_DATA": 0,
                    "NOT_APPLICABLE": 0,
                    "OTHER": 0,
                }
                for r in compliance_list:
                    ct = ((r.get("Compliance") or {}).get("ComplianceType") or "").upper()
                    if ct in c_counts:
                        c_counts[ct] += 1
                    elif ct:
                        c_counts["OTHER"] += 1
                self._save_json(
                    evidence_path / "config-compliance-summary.json",
                    {"counts": c_counts, "total_rules": len(compliance_list)},
                )
            except Exception as e:
                logger.warning(f"Could not describe Config rules: {e}")
                collection_status["config"].update({"ok": False, "error": str(e)})

            # Conformance packs (for HRD-010)
            try:
                packs = config_client.describe_conformance_packs().get("ConformancePackDetails", [])
                packs_out: List[Dict[str, Any]] = []
                for p in packs:
                    name = p.get("ConformancePackName")
                    packs_out.append(
                        {
                            "ConformancePackName": name,
                            "ConformancePackArn": p.get("ConformancePackArn"),
                            "ConformancePackState": p.get("ConformancePackState"),
                            "LastUpdateRequestedTime": p.get("LastUpdateRequestedTime"),
                        }
                    )
                self._save_json(evidence_path / "config-conformance-packs.json", packs_out)

                # Compliance summary per pack (best-effort)
                compliance_out: List[Dict[str, Any]] = []
                for p in packs_out:
                    name = p.get("ConformancePackName")
                    if not name:
                        continue
                    try:
                        comp = config_client.describe_conformance_pack_compliance(
                            ConformancePackNames=[name]
                        )
                        compliance_out.append(
                            {
                                "ConformancePackName": name,
                                "Compliance": (
                                    comp.get("ConformancePackComplianceList", [{}])[0] or {}
                                ).get("ConformancePackCompliance"),
                            }
                        )
                    except Exception as e:
                        logger.warning(f"Could not get conformance pack compliance for {name}: {e}")
                self._save_json(
                    evidence_path / "config-conformance-pack-compliance.json", compliance_out
                )
            except Exception as e:
                logger.warning(f"Could not describe conformance packs: {e}")

        except Exception as e:
            logger.error(f"Could not collect Config data: {e}")
            collection_status["config"].update({"ok": False, "error": str(e)})

        # === ACM CERTIFICATES ===
        print("  Collecting ACM certificates...")
        try:
            acm_client = boto3.client("acm", **client_kwargs)
            certs_list = []

            paginator = acm_client.get_paginator("list_certificates")
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
                            "ValidationMethod": cert_detail.get("Certificate", {}).get(
                                "ValidationMethod"
                            ),
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

            # List detectors with explicit enabled flag
            try:
                detectors = gd_client.list_detectors()
                detectors_list = detectors.get("DetectorIds", [])

                # Explicit status: GuardDuty is enabled if there are detectors
                gd_status = {
                    "enabled": len(detectors_list) > 0,  # Explicit status flag
                    "DetectorIds": detectors_list,
                    "Detectors": [],
                }

                for detector_id in detectors_list:
                    detector_detail = gd_client.get_detector(DetectorId=detector_id)
                    detector_info = {
                        "DetectorId": detector_id,
                        "Status": detector_detail.get("Status"),
                        "FindingPublishingFrequency": detector_detail.get(
                            "FindingPublishingFrequency"
                        ),
                    }

                    # Get findings (up to 50, filtered by severity: Medium and above)
                    try:
                        findings = gd_client.list_findings(
                            DetectorId=detector_id,
                            MaxResults=50,
                            FindingCriteria={
                                "Criterion": {
                                    "severity": {
                                        "Gte": 4  # Medium (4.0-6.9), High (7.0-8.9), Critical (9.0+)
                                    }
                                }
                            },
                        )
                        detector_info["FindingIds"] = findings.get("FindingIds", [])
                    except Exception as e:
                        logger.warning(
                            f"Could not list GuardDuty findings for detector {detector_id}: {e}"
                        )
                        detector_info["FindingIds"] = []
                        collection_status["guardduty"].update({"ok": False, "error": str(e)})

                    # Findings statistics (compact posture signal)
                    try:
                        stats = gd_client.get_findings_statistics(
                            DetectorId=detector_id,
                            FindingStatisticTypes=["COUNT_BY_SEVERITY"],
                            FindingCriteria={
                                "Criterion": {
                                    "service.archived": {"Eq": ["false"]},
                                }
                            },
                        )
                        detector_info["FindingsStatistics"] = stats.get("FindingStatistics")
                    except Exception as e:
                        logger.warning(
                            f"Could not get GuardDuty findings statistics for detector {detector_id}: {e}"
                        )

                    gd_status["Detectors"].append(detector_info)

                self._save_json(evidence_path / "guardduty-detectors.json", gd_status)
            except Exception as e:
                logger.warning(f"Could not list GuardDuty detectors: {e}")
                # Save empty status if error
                gd_status = {"enabled": False, "DetectorIds": [], "Detectors": [], "error": str(e)}
                self._save_json(evidence_path / "guardduty-detectors.json", gd_status)
                collection_status["guardduty"].update({"ok": False, "error": str(e)})

        except Exception as e:
            logger.error(f"Could not collect GuardDuty data: {e}")
            collection_status["guardduty"].update({"ok": False, "error": str(e)})

        # === MACIE ===
        print("  Collecting Macie status...")
        try:
            macie_client = boto3.client("macie2", **client_kwargs)

            # Get Macie status (always persist)
            macie_enabled = False
            try:
                status = macie_client.get_macie_session()
                macie_enabled = True
                out_status = {"enabled": True, **status}
                self._save_json(evidence_path / "macie-session.json", out_status)
            except Exception as e:
                logger.warning(f"Could not get Macie session: {e}")
                self._save_json(
                    evidence_path / "macie-session.json",
                    {"enabled": False, "error": str(e)},
                )
                collection_status["macie"].update({"ok": False, "error": str(e)})

            # List findings (filtered by severity: High only - post-filter)
            try:
                findings_list = []
                if macie_enabled:
                    token: Optional[str] = None
                    ids: List[str] = []
                    while True:
                        args: Dict[str, Any] = {"maxResults": 50}
                        if token:
                            args["nextToken"] = token
                        page = macie_client.list_findings(**args)
                        ids.extend(page.get("findingIds", []) or [])
                        token = page.get("nextToken")
                        if not token or len(ids) >= 200:
                            break

                    # Fetch details in small batches
                    for i in range(0, len(ids), 20):
                        batch = ids[i : i + 20]
                        try:
                            finding = macie_client.get_findings(FindingIds=batch)
                            for f in finding.get("findings", []) or []:
                                sev_desc = (f.get("severity") or {}).get("description", "")
                                if isinstance(sev_desc, str) and sev_desc.upper() == "HIGH":
                                    findings_list.append(f)
                        except Exception as e:
                            logger.warning(f"Could not get Macie findings batch: {e}")

                self._save_json(evidence_path / "macie-findings.json", findings_list)
            except Exception as e:
                logger.warning(f"Could not list Macie findings: {e}")
                self._save_json(evidence_path / "macie-findings.json", [])
                collection_status["macie"].update({"ok": False, "error": str(e)})

        except Exception as e:
            logger.error(f"Could not collect Macie data: {e}")
            self._save_json(
                evidence_path / "macie-session.json", {"enabled": False, "error": str(e)}
            )
            self._save_json(evidence_path / "macie-findings.json", [])
            collection_status["macie"].update({"ok": False, "error": str(e)})

        # === BACKUP VAULTS ===
        print("  Collecting backup configuration...")
        try:
            backup_client = boto3.client("backup", **client_kwargs)
            vaults_list = []

            # List backup vaults
            try:
                paginator = backup_client.get_paginator("list_backup_vaults")
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
                plans_list = plans.get("BackupPlansList", []) or []
                self._save_json(evidence_path / "backup-plans.json", plans_list)

                # Add selections per plan (coverage signal)
                plans_detailed: List[Dict[str, Any]] = []
                for p in plans_list:
                    plan_id = p.get("BackupPlanId")
                    entry = {
                        "BackupPlanId": plan_id,
                        "BackupPlanArn": p.get("BackupPlanArn"),
                        "BackupPlanName": p.get("BackupPlanName"),
                        "VersionId": p.get("VersionId"),
                        "CreationDate": p.get("CreationDate"),
                        "LastExecutionDate": p.get("LastExecutionDate"),
                        "Selections": [],
                    }
                    if plan_id:
                        try:
                            sel = backup_client.list_backup_selections(BackupPlanId=plan_id)
                            entry["Selections"] = sel.get("BackupSelectionsList", []) or []
                        except Exception as e:
                            entry["SelectionsError"] = str(e)
                    plans_detailed.append(entry)
                self._save_json(evidence_path / "backup-plans-detailed.json", plans_detailed)
            except Exception as e:
                logger.warning(f"Could not list backup plans: {e}")
                collection_status["backup"].update({"ok": False, "error": str(e)})

        except Exception as e:
            logger.error(f"Could not collect backup data: {e}")
            collection_status["backup"].update({"ok": False, "error": str(e)})

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
                collection_status["iam_account"].update({"ok": False, "error": str(e)})

            # Account aliases
            try:
                aliases = iam_client.list_account_aliases()
                self._save_json(evidence_path / "account-aliases.json", aliases)
            except Exception as e:
                logger.warning(f"Could not list account aliases: {e}")
                collection_status["iam_account"].update({"ok": False, "error": str(e)})

            # Password policy
            try:
                pwd_policy = iam_client.get_account_password_policy()
                self._save_json(evidence_path / "password-policy.json", pwd_policy)
            except iam_client.exceptions.NoSuchEntityException:
                self._save_json(
                    evidence_path / "password-policy.json", {"error": "No password policy"}
                )
            except Exception as e:
                logger.warning(f"Could not get account password policy: {e}")
                collection_status["iam_account"].update({"ok": False, "error": str(e)})

        except Exception as e:
            logger.error(f"Could not collect account settings: {e}")
            collection_status["iam_account"].update({"ok": False, "error": str(e)})

        # === AUDIT METADATA ===
        # Save region and scope information for evidence validation
        from datetime import datetime

        audit_metadata = {
            "_region": aws_client.region_name,
            "_timestamp": datetime.now().isoformat(),
            "_scope": "single-region",
            "_skill": self.name,
        }
        self._save_json(evidence_path / "_audit_metadata.json", audit_metadata)

        # === COLLECTION STATUS ===
        self._save_json(evidence_path / "hardening-collection-status.json", collection_status)

        print("\n✅ Hardening collection complete")

    def _save_json(self, filepath: Path, data):
        """Save data to JSON file with proper datetime serialization."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


__all__ = ["HardeningSkill"]
