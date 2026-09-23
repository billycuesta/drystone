"""Hardening AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"hardening"})

_SECURITY_HUB_SUMMARY_OUTPUT = OutputSpec(
    source="security-hub-findings-summary",
    style="kv",
)

SOURCE_QUERIES = {
    "hardening": {
        "security-hub-status": CliQuery(
            commands=("aws securityhub describe-hub",),
            output=OutputSpec(source="security-hub-status", style="kv"),
        ),
        "security-hub-findings": CliQuery(
            commands=("aws securityhub get-findings",),
            output=OutputSpec(source="security-hub-findings", rows="", columns=(("Id", "Id"), ("Title", "Title"), ("Severity", "Severity.Label"), ("Compliance", "Compliance.Status"), ("Resources", "Resources"))),
        ),
        "security-hub-findings-summary": CliQuery(
            commands=("aws securityhub get-findings",),
            output=_SECURITY_HUB_SUMMARY_OUTPUT,
            derived_note="Drystone aggregates Security Hub findings into severity and compliance-status counts.",
        ),
        "security-hub-enabled-standards": CliQuery(
            commands=(
                'for sub in $(aws securityhub get-enabled-standards --query "StandardsSubscriptions[].StandardsSubscriptionArn" --output text); do\n'
                '  aws securityhub describe-standards-controls --standards-subscription-arn "$sub"\n'
                "done",
            ),
            output=OutputSpec(source="security-hub-enabled-standards", rows="", columns=(("StandardsArn", "StandardsArn"), ("StandardsSubscriptionArn", "StandardsSubscriptionArn"), ("Status", "Status"), ("ControlsSummary", "ControlsSummary"))),
        ),
        "config-recorders": CliQuery(
            commands=("aws configservice describe-configuration-recorders",),
            output=OutputSpec(source="config-recorders", rows="ConfigurationRecorders", columns=(("Name", "name"), ("RoleARN", "roleARN"), ("RecordingGroup", "recordingGroup"))),
        ),
        "config-delivery-channels": CliQuery(
            commands=("aws configservice describe-delivery-channels",),
            output=OutputSpec(source="config-delivery-channels", rows="DeliveryChannels", columns=(("Name", "name"), ("S3BucketName", "s3BucketName"), ("SnsTopicARN", "snsTopicARN"))),
        ),
        "config-recorder-status": CliQuery(
            commands=("aws configservice describe-configuration-recorder-status",),
            output=OutputSpec(source="config-recorder-status", rows="ConfigurationRecordersStatus", columns=(("Name", "name"), ("Recording", "recording"), ("LastStatus", "lastStatus"), ("LastErrorCode", "lastErrorCode"))),
        ),
        "config-compliance": CliQuery(
            commands=("aws configservice describe-compliance-by-config-rule",),
            output=OutputSpec(source="config-compliance", rows="", columns=(("ConfigRuleName", "ConfigRuleName"), ("Compliance", "Compliance"))),
        ),
        "config-compliance-summary": CliQuery(
            commands=("aws configservice get-compliance-summary-by-config-rule",),
            output=OutputSpec(source="config-compliance-summary", style="kv"),
        ),
        "config-conformance-packs": CliQuery(
            commands=("aws configservice describe-conformance-packs",),
            output=OutputSpec(source="config-conformance-packs", rows="", columns=(("ConformancePackName", "ConformancePackName"), ("ConformancePackArn", "ConformancePackArn"), ("DeliveryS3Bucket", "DeliveryS3Bucket"))),
        ),
        "config-conformance-pack-compliance": CliQuery(
            commands=("aws configservice describe-conformance-pack-compliance",),
            output=OutputSpec(source="config-conformance-pack-compliance", rows="", columns=(("ConformancePackName", "ConformancePackName"), ("ComplianceType", "ComplianceType"), ("Controls", "Controls"))),
        ),
        "acm-certificates": CliQuery(
            commands=("aws acm list-certificates",),
            output=OutputSpec(source="acm-certificates", rows="", columns=(("CertificateArn", "CertificateArn"), ("DomainName", "DomainName"), ("Status", "Status"), ("NotAfter", "NotAfter"))),
        ),
        "guardduty-detectors": CliQuery(
            commands=("aws guardduty list-detectors",),
            output=OutputSpec(source="guardduty-detectors", rows="DetectorIds", columns=(("DetectorId", ""),)),
        ),
        "macie-session": CliQuery(
            commands=("aws macie2 get-macie-session",),
            output=OutputSpec(source="macie-session", style="kv"),
        ),
        "macie-findings": CliQuery(
            commands=("aws macie2 list-findings",),
            output=OutputSpec(source="macie-findings", rows="", columns=(("FindingId", ""),)),
        ),
        "backup-vaults": CliQuery(
            commands=("aws backup list-backup-vaults",),
            output=OutputSpec(source="backup-vaults", rows="", columns=(("BackupVaultName", "BackupVaultName"), ("BackupVaultArn", "BackupVaultArn"), ("NumberOfRecoveryPoints", "NumberOfRecoveryPoints"))),
        ),
        "backup-plans": CliQuery(
            commands=("aws backup list-backup-plans",),
            output=OutputSpec(source="backup-plans", rows="", columns=(("BackupPlanId", "BackupPlanId"), ("BackupPlanName", "BackupPlanName"), ("CreationDate", "CreationDate"))),
        ),
        "backup-plans-detailed": CliQuery(
            commands=(
                'for plan in $(aws backup list-backup-plans --query "BackupPlansList[].BackupPlanId" --output text); do\n'
                '  aws backup get-backup-plan --backup-plan-id "$plan"\n'
                "done",
            ),
            output=OutputSpec(source="backup-plans-detailed", rows="", columns=(("BackupPlanId", "BackupPlanId"), ("BackupPlan", "BackupPlan"), ("Selections", "Selections"))),
        ),
        "account-summary": CliQuery(
            commands=("aws iam get-account-summary",),
            output=OutputSpec(source="account-summary", rows="SummaryMap", style="kv"),
        ),
        "account-aliases": CliQuery(
            commands=("aws iam list-account-aliases",),
            output=OutputSpec(source="account-aliases", rows="AccountAliases", columns=(("Alias", ""),)),
        ),
        "password-policy": CliQuery(
            commands=("aws iam get-account-password-policy",),
            output=OutputSpec(source="password-policy", style="kv"),
        ),
        "hardening-collection-status": CliQuery(
            commands=(
                "aws securityhub describe-hub\n"
                "aws configservice describe-configuration-recorders\n"
                "aws guardduty list-detectors",
            ),
            output=OutputSpec(source="hardening-collection-status", style="kv"),
            derived_note="Drystone records collection success and errors across account hardening services while gathering evidence.",
        ),
    }
}

_CHECK_STEMS = {
    "HRD-001": "config-recorders",
    "HRD-002": "security-hub-status",
    "HRD-003": "security-hub-enabled-standards",
    "HRD-004": "security-hub-findings-summary",
    "HRD-005": "security-hub-findings-summary",
    "HRD-006": "config-recorder-status",
    "HRD-007": "security-hub-enabled-standards",
    "HRD-008": "security-hub-findings-summary",
    "HRD-009": "security-hub-findings-summary",
    "HRD-010": "config-conformance-packs",
    "HRD-011": "security-hub-findings-summary",
    "HRD-012": "security-hub-findings-summary",
    "HRD-013": "security-hub-enabled-standards",
    "HRD-014": "guardduty-detectors",
    "HRD-015": "security-hub-findings-summary",
    "HRD-016": "security-hub-findings-summary",
    "HRD-017": "security-hub-findings",
    "HRD-018": "hardening-collection-status",
}

_CHECK_NAMES = {
    "HRD-001": "AWS Config enabled",
    "HRD-002": "Security Hub enabled",
    "HRD-003": "Security Hub standards enabled",
    "HRD-004": "Compliance score below 50",
    "HRD-005": "Critical findings",
    "HRD-006": "Config recorder completeness",
    "HRD-007": "Security Hub PCI DSS standard",
    "HRD-008": "Compliance score 50 to 70",
    "HRD-009": "High findings backlog",
    "HRD-010": "Config conformance packs",
    "HRD-011": "Compliance score 70 to 85",
    "HRD-012": "Medium findings backlog",
    "HRD-013": "Outdated standards",
    "HRD-014": "GuardDuty enabled",
    "HRD-015": "Compliance score 85 to 95",
    "HRD-016": "Low findings pending",
    "HRD-017": "Resource tagging consistency",
    "HRD-018": "Hardening documentation evidence",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["hardening"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=_CHECK_NAMES[_check_id],
        derived_note=_source_query.derived_note,
    )
