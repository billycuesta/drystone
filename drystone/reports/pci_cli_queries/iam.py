"""IAM AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"iam"})

_USERS_OUTPUT = OutputSpec(
    source="users",
    rows="",
    columns=(
        ("UserName", "UserName"),
        ("Arn", "Arn"),
        ("MFADevices", "MFADevices"),
        ("AccessKeys", "AccessKeys"),
        ("Groups", "Groups"),
    ),
)

_CREDENTIAL_REPORT_OUTPUT = OutputSpec(
    source="credential-report",
    rows="rows",
    columns=(
        ("user", "user"),
        ("password_enabled", "password_enabled"),
        ("mfa_active", "mfa_active"),
        ("access_key_1_active", "access_key_1_active"),
        ("access_key_2_active", "access_key_2_active"),
    ),
)

_PASSWORD_POLICY_OUTPUT = OutputSpec(source="password-policy", style="kv")

_POLICIES_OUTPUT = OutputSpec(
    source="policies",
    rows="",
    columns=(
        ("PolicyName", "PolicyName"),
        ("Arn", "Arn"),
        ("AttachmentCount", "AttachmentCount"),
        ("PolicyDocument", "PolicyDocument"),
    ),
)

_ROLES_OUTPUT = OutputSpec(
    source="roles",
    rows="",
    columns=(
        ("RoleName", "RoleName"),
        ("Arn", "Arn"),
        ("AssumeRolePolicyDocument", "AssumeRolePolicyDocument"),
        ("AttachedPolicies", "AttachedPolicies"),
    ),
)

_GROUPS_OUTPUT = OutputSpec(
    source="groups",
    rows="",
    columns=(("GroupName", "GroupName"), ("Users", "Users"), ("AttachedPolicies", "AttachedPolicies")),
)

SOURCE_QUERIES = {
    "iam": {
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
            output=_PASSWORD_POLICY_OUTPUT,
        ),
        "credential-report": CliQuery(
            commands=(
                "aws iam generate-credential-report > /dev/null\n"
                "aws iam get-credential-report --output text --query Content | base64 --decode",
            ),
            output=_CREDENTIAL_REPORT_OUTPUT,
        ),
        "users": CliQuery(
            commands=(
                'for user in $(aws iam list-users --query "Users[].UserName" --output text); do\n'
                '  aws iam get-user --user-name "$user"\n'
                '  aws iam list-access-keys --user-name "$user"\n'
                '  aws iam list-mfa-devices --user-name "$user"\n'
                '  aws iam list-groups-for-user --user-name "$user"\n'
                "done",
            ),
            output=_USERS_OUTPUT,
        ),
        "groups": CliQuery(
            commands=(
                'for group in $(aws iam list-groups --query "Groups[].GroupName" --output text); do\n'
                '  aws iam get-group --group-name "$group"\n'
                '  aws iam list-attached-group-policies --group-name "$group"\n'
                '  aws iam list-group-policies --group-name "$group"\n'
                "done",
            ),
            output=_GROUPS_OUTPUT,
        ),
        "roles": CliQuery(
            commands=(
                'for role in $(aws iam list-roles --query "Roles[].RoleName" --output text); do\n'
                '  aws iam get-role --role-name "$role"\n'
                '  aws iam list-attached-role-policies --role-name "$role"\n'
                '  aws iam list-role-policies --role-name "$role"\n'
                "done",
            ),
            output=_ROLES_OUTPUT,
        ),
        "policies": CliQuery(
            commands=(
                'for policy in $(aws iam list-policies --scope Local --query "Policies[].Arn" --output text); do\n'
                '  version=$(aws iam get-policy --policy-arn "$policy" --query "Policy.DefaultVersionId" --output text)\n'
                '  aws iam get-policy-version --policy-arn "$policy" --version-id "$version"\n'
                "done",
            ),
            output=_POLICIES_OUTPUT,
        ),
        "assumeRole-chains": CliQuery(
            commands=(
                "aws iam list-roles --query 'Roles[].[RoleName,Arn,AssumeRolePolicyDocument]' --output table",
            ),
            output=OutputSpec(source="assumeRole-chains", rows="chains", columns=(("Chain", "chain"), ("Risk", "risk"))),
            derived_note="Drystone derives assume-role chains by walking IAM role trust policies and matching assumable principals.",
        ),
        "resource-based-policies": CliQuery(
            commands=(
                "aws s3api list-buckets\naws ecr describe-repositories\naws secretsmanager list-secrets\naws sqs list-queues\naws sns list-topics",
            ),
            output=OutputSpec(source="resource-based-policies", rows="items", columns=(("Service", "Service"), ("ResourceArn", "ResourceArn"), ("Policy", "Policy"))),
            derived_note="Drystone normalises resource policies collected from multiple AWS services and evaluates broad principals.",
        ),
        "instance-profiles": CliQuery(
            commands=(
                'for profile in $(aws iam list-instance-profiles --query "InstanceProfiles[].InstanceProfileName" --output text); do\n'
                '  aws iam get-instance-profile --instance-profile-name "$profile"\n'
                "done",
            ),
            output=OutputSpec(source="instance-profiles", rows="instance_profiles", columns=(("InstanceProfileName", "InstanceProfileName"), ("Roles", "Roles"))),
        ),
        "effective-scps": CliQuery(
            commands=(
                "aws organizations list-policies --filter SERVICE_CONTROL_POLICY\n"
                "aws organizations list-roots\n"
                "aws organizations list-accounts",
            ),
            output=OutputSpec(source="effective-scps", rows="service_control_policies", columns=(("Name", "Name"), ("Effect", "Effect"), ("Policy", "Policy"))),
            derived_note="Drystone combines Organization account/root policy attachments to infer effective service control policy guardrails.",
        ),
    }
}

_CHECK_OUTPUTS = {
    "IAM-001": ("Root account MFA", SOURCE_QUERIES["iam"]["account-summary"].output),
    "IAM-002": ("IAM users MFA", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-003": ("Inactive IAM credentials", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-004": ("IAM access key rotation", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-005": ("Password minimum length", _PASSWORD_POLICY_OUTPUT),
    "IAM-006": ("Password reuse prevention", _PASSWORD_POLICY_OUTPUT),
    "IAM-007": ("IAM inline policies", _USERS_OUTPUT),
    "IAM-008": ("IAM wildcard policies", _POLICIES_OUTPUT),
    "IAM-009": ("Root access keys", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-010": ("Privileged users MFA", _USERS_OUTPUT),
    "IAM-011": ("Wildcard role trust", _ROLES_OUTPUT),
    "IAM-012": ("Inactive IAM users", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-013": ("Unused IAM access keys", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-014": ("Multiple active access keys", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-015": ("Direct user permissions", _USERS_OUTPUT),
    "IAM-016": ("Programmatic only users", _CREDENTIAL_REPORT_OUTPUT),
    "IAM-017": ("Cross account role ExternalId", _ROLES_OUTPUT),
    "IAM-018": ("Password max age", _PASSWORD_POLICY_OUTPUT),
    "IAM-019": ("Password symbols", _PASSWORD_POLICY_OUTPUT),
    "IAM-020": ("IAM users groups", _USERS_OUTPUT),
    "IAM-021": ("Empty IAM groups", _GROUPS_OUTPUT),
    "IAM-022": ("Unused IAM roles", _ROLES_OUTPUT),
    "IAM-023": ("IAM logging", SOURCE_QUERIES["iam"]["account-summary"].output),
    "IAM-024": ("Access Analyzer", SOURCE_QUERIES["iam"]["account-summary"].output),
    "IAM-025": ("Redundant IAM policies", _POLICIES_OUTPUT),
    "IAM-026": ("Role permission boundaries", _ROLES_OUTPUT),
    "IAM-027": ("Account alias", SOURCE_QUERIES["iam"]["account-aliases"].output),
    "IAM-028": ("IAM resource tags", _USERS_OUTPUT),
    "IAM-029": ("AssumeRole chains", SOURCE_QUERIES["iam"]["assumeRole-chains"].output),
    "IAM-030": ("Resource based policies", SOURCE_QUERIES["iam"]["resource-based-policies"].output),
    "IAM-031": ("Instance profile privilege escalation", SOURCE_QUERIES["iam"]["instance-profiles"].output),
    "IAM-032": ("GitHub OIDC role trust", _ROLES_OUTPUT),
    "IAM-033": ("Cross account trust ExternalId", _ROLES_OUTPUT),
    "IAM-034": ("Federation mutation permissions", _POLICIES_OUTPUT),
    "IAM-035": ("Policy version mutation", _POLICIES_OUTPUT),
    "IAM-036": ("Service specific credential permissions", _POLICIES_OUTPUT),
    "IAM-037": ("MFA lifecycle permissions", _POLICIES_OUTPUT),
    "IAM-038": ("Destructive IAM permissions", _POLICIES_OUTPUT),
    "IAM-039": ("Policy detachment permissions", _POLICIES_OUTPUT),
    "IAM-040": ("Effective SCP guardrails", SOURCE_QUERIES["iam"]["effective-scps"].output),
    "IAM-041": ("Privileged role boundaries", _ROLES_OUTPUT),
    "IAM-042": ("Break glass access controls", _USERS_OUTPUT),
    "IAM-043": ("Human admin MFA", _USERS_OUTPUT),
    "IAM-044": ("IAM access analyzer findings", SOURCE_QUERIES["iam"]["account-summary"].output),
}

_CHECK_STEMS = {
    "IAM-001": "account-summary",
    "IAM-002": "credential-report",
    "IAM-003": "credential-report",
    "IAM-004": "credential-report",
    "IAM-005": "password-policy",
    "IAM-006": "password-policy",
    "IAM-007": "users",
    "IAM-008": "policies",
    "IAM-009": "credential-report",
    "IAM-010": "users",
    "IAM-011": "roles",
    "IAM-012": "credential-report",
    "IAM-013": "credential-report",
    "IAM-014": "credential-report",
    "IAM-015": "users",
    "IAM-016": "credential-report",
    "IAM-017": "roles",
    "IAM-018": "password-policy",
    "IAM-019": "password-policy",
    "IAM-020": "users",
    "IAM-021": "groups",
    "IAM-022": "roles",
    "IAM-023": "account-summary",
    "IAM-024": "account-summary",
    "IAM-025": "policies",
    "IAM-026": "roles",
    "IAM-027": "account-aliases",
    "IAM-028": "users",
    "IAM-029": "assumeRole-chains",
    "IAM-030": "resource-based-policies",
    "IAM-031": "instance-profiles",
    "IAM-032": "roles",
    "IAM-033": "roles",
    "IAM-034": "policies",
    "IAM-035": "policies",
    "IAM-036": "policies",
    "IAM-037": "policies",
    "IAM-038": "policies",
    "IAM-039": "policies",
    "IAM-040": "effective-scps",
    "IAM-041": "roles",
    "IAM-042": "users",
    "IAM-043": "users",
    "IAM-044": "account-summary",
}

CHECK_QUERIES = {}
for _check_id, (_evidence_name, _output) in _CHECK_OUTPUTS.items():
    _source_query = SOURCE_QUERIES["iam"][_CHECK_STEMS[_check_id]]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_output,
        evidence_name=_evidence_name,
        derived_note=_source_query.derived_note,
    )
