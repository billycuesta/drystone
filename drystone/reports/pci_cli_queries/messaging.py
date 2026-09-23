"""Messaging AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"messaging"})

SOURCE_QUERIES = {
    "messaging": {
        "sqs-queues": CliQuery(
            commands=(
                'for queue_url in $(aws sqs list-queues --query "QueueUrls[]" --output text); do\n'
                '  aws sqs get-queue-attributes --queue-url "$queue_url" --attribute-names All\n'
                "done",
            ),
            output=OutputSpec(
                source="sqs-queues",
                rows="items",
                columns=(
                    ("QueueUrl", "QueueUrl"),
                    ("QueueArn", "QueueArn"),
                    ("KmsMasterKeyId", "KmsMasterKeyId"),
                    ("SqsManagedSseEnabled", "SqsManagedSseEnabled"),
                    ("Policy", "Policy"),
                    ("RedrivePolicy", "RedrivePolicy"),
                    ("RedriveAllowPolicy", "RedriveAllowPolicy"),
                ),
            ),
        ),
        "sns-topics": CliQuery(
            commands=(
                'for topic_arn in $(aws sns list-topics --query "Topics[].TopicArn" --output text); do\n'
                '  aws sns get-topic-attributes --topic-arn "$topic_arn"\n'
                '  aws sns list-subscriptions-by-topic --topic-arn "$topic_arn"\n'
                "done",
            ),
            output=OutputSpec(
                source="sns-topics",
                rows="items",
                columns=(("TopicArn", "TopicArn"), ("Attributes", "Attributes"), ("Subscriptions", "Subscriptions")),
            ),
        ),
    }
}

_CHECK_STEMS = {
    "MSG-001": "sqs-queues",
    "MSG-002": "sqs-queues",
    "MSG-003": "sqs-queues",
    "MSG-004": "sqs-queues",
    "MSG-005": "sqs-queues",
    "MSG-006": "sqs-queues",
    "MSG-007": "sns-topics",
    "MSG-008": "sns-topics",
    "MSG-009": "sns-topics",
}

_DERIVED_NOTES = {
    "MSG-001": "Drystone interprets SQS resource policies for aws:PrincipalOrgID conditions and broad organization-scoped access.",
    "MSG-002": "Drystone interprets SQS redrive configuration and redrive allow policies to identify DLQ exfiltration paths.",
    "MSG-003": "Drystone correlates SNS topic policies and SQS queue policies to identify untrusted publish-to-queue paths.",
    "MSG-004": "Drystone treats message move task risk as a semantic control over administrative SQS permissions and DLQ operations.",
    "MSG-005": "Drystone interprets SQS queue policy principals and data-plane actions to identify wildcard access.",
    "MSG-007": "Drystone interprets SNS topic policies and subscriptions to identify wildcard or external Subscribe permissions.",
    "MSG-008": "Drystone interprets SNS topic policies to identify unrestricted wildcard Publish permissions.",
    "MSG-009": "Drystone interprets SNS topic policies to identify wildcard administrative actions.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["messaging"][_stem]
    _commands = _source_query.commands
    if _check_id == "MSG-003":
        _commands = (*SOURCE_QUERIES["messaging"]["sns-topics"].commands, *SOURCE_QUERIES["messaging"]["sqs-queues"].commands)
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
