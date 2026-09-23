"""KMS AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"kms"})

SOURCE_QUERIES = {
    "kms": {
        "kms-keys": CliQuery(
            commands=(
                'for key in $(aws kms list-keys --query "Keys[].KeyId" --output text); do\n'
                '  aws kms describe-key --key-id "$key"\n'
                '  aws kms get-key-rotation-status --key-id "$key"\n'
                "done",
            ),
            output=OutputSpec(
                source="kms-keys",
                rows="items",
                columns=(
                    ("KeyId", "KeyId"),
                    ("KeyArn", "KeyArn"),
                    ("Metadata", "Metadata"),
                    ("KeyRotationEnabled", "KeyRotationEnabled"),
                ),
            ),
        ),
        "kms-key-policies": CliQuery(
            commands=(
                'for key in $(aws kms list-keys --query "Keys[].KeyId" --output text); do\n'
                '  aws kms list-key-policies --key-id "$key"\n'
                '  aws kms get-key-policy --key-id "$key" --policy-name default\n'
                "done",
            ),
            output=OutputSpec(
                source="kms-key-policies",
                rows="items",
                columns=(("KeyId", "KeyId"), ("PolicyName", "PolicyName"), ("Policy", "Policy")),
            ),
        ),
        "kms-grants": CliQuery(
            commands=(
                'for key in $(aws kms list-keys --query "Keys[].KeyId" --output text); do\n'
                '  aws kms list-grants --key-id "$key"\n'
                "done",
            ),
            output=OutputSpec(
                source="kms-grants",
                rows="items",
                columns=(("KeyId", "KeyId"), ("GrantId", "GrantId"), ("GranteePrincipal", "GranteePrincipal"), ("Operations", "Operations")),
            ),
        ),
        "kms-aliases": CliQuery(
            commands=("aws kms list-aliases",),
            output=OutputSpec(
                source="kms-aliases",
                rows="items",
                columns=(("AliasName", "AliasName"), ("AliasArn", "AliasArn"), ("TargetKeyId", "TargetKeyId")),
            ),
        ),
        "kms-custom-key-stores": CliQuery(
            commands=("aws kms describe-custom-key-stores",),
            output=OutputSpec(
                source="kms-custom-key-stores",
                rows="items",
                columns=(
                    ("CustomKeyStoreId", "CustomKeyStoreId"),
                    ("CustomKeyStoreName", "CustomKeyStoreName"),
                    ("ConnectionState", "ConnectionState"),
                ),
            ),
        ),
    }
}

_CHECK_STEMS = {
    "KMS-001": "kms-key-policies",
    "KMS-002": "kms-grants",
    "KMS-003": "kms-key-policies",
    "KMS-004": "kms-keys",
    "KMS-005": "kms-key-policies",
    "KMS-006": "kms-keys",
    "KMS-007": "kms-grants",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["kms"][_stem]
    _commands = _source_query.commands
    if _check_id == "KMS-006":
        _commands = (
            *SOURCE_QUERIES["kms"]["kms-keys"].commands,
            *SOURCE_QUERIES["kms"]["kms-key-policies"].commands,
        )
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_source_query.derived_note,
    )
