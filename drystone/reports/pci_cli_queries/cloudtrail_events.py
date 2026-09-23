"""CloudTrail Events AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"cloudtrail_events"})

_EVENT_COLUMNS = (
    ("EventTime", "EventTime"),
    ("EventName", "EventName"),
    ("Username", "Username"),
    ("EventSource", "EventSource"),
    ("ErrorCode", "ErrorCode"),
    ("sourceIPAddress", "sourceIPAddress"),
    ("callerAccountId", "callerAccountId"),
    ("callerArn", "callerArn"),
)


def _event_output(stem: str) -> OutputSpec:
    return OutputSpec(source=stem, rows="", columns=_EVENT_COLUMNS)


def _lookup_by_event(stem: str, event_name: str) -> CliQuery:
    return CliQuery(
        commands=(
            'START_TIME="${START_TIME:-2026-01-01T00:00:00Z}"\n'
            'END_TIME="${END_TIME:-2026-01-31T23:59:59Z}"\n'
            f'aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue={event_name} '
            '--start-time "$START_TIME" --end-time "$END_TIME" --max-results 50',
        ),
        output=_event_output(stem),
    )


def _lookup_read_only_false(stem: str, derived_note: str | None = None) -> CliQuery:
    return CliQuery(
        commands=(
            'START_TIME="${START_TIME:-2026-01-01T00:00:00Z}"\n'
            'END_TIME="${END_TIME:-2026-01-31T23:59:59Z}"\n'
            'aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false '
            '--start-time "$START_TIME" --end-time "$END_TIME" --max-results 50',
        ),
        output=_event_output(stem),
        derived_note=derived_note,
    )


SOURCE_QUERIES = {
    "cloudtrail_events": {
        "root-events": CliQuery(
            commands=(
                'START_TIME="${START_TIME:-2026-01-01T00:00:00Z}"\n'
                'END_TIME="${END_TIME:-2026-01-31T23:59:59Z}"\n'
                'aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root '
                '--start-time "$START_TIME" --end-time "$END_TIME" --max-results 50',
            ),
            output=_event_output("root-events"),
        ),
        "console-login-events": _lookup_by_event("console-login-events", "ConsoleLogin"),
        "assume-role-events": _lookup_by_event("assume-role-events", "AssumeRole"),
        "stop-logging-events": _lookup_by_event("stop-logging-events", "StopLogging"),
        "delete-trail-events": _lookup_by_event("delete-trail-events", "DeleteTrail"),
        "update-trail-events": _lookup_by_event("update-trail-events", "UpdateTrail"),
        "create-access-key-events": _lookup_by_event("create-access-key-events", "CreateAccessKey"),
        "attach-user-policy-events": _lookup_by_event("attach-user-policy-events", "AttachUserPolicy"),
        "attach-role-policy-events": _lookup_by_event("attach-role-policy-events", "AttachRolePolicy"),
        "create-login-profile-events": _lookup_by_event("create-login-profile-events", "CreateLoginProfile"),
        "credential-report-events": _lookup_by_event("credential-report-events", "GenerateCredentialReport"),
        "get-credential-report-events": _lookup_by_event("get-credential-report-events", "GetCredentialReport"),
        "disable-security-hub-events": _lookup_by_event("disable-security-hub-events", "DisableSecurityHub"),
        "delete-detector-events": _lookup_by_event("delete-detector-events", "DeleteDetector"),
        "disable-alarm-actions-events": _lookup_by_event("disable-alarm-actions-events", "DisableAlarmActions"),
        "get-secret-value-events": _lookup_by_event("get-secret-value-events", "GetSecretValue"),
        "get-parameter-events": _lookup_by_event("get-parameter-events", "GetParameter"),
        "update-assume-role-events": _lookup_by_event("update-assume-role-events", "UpdateAssumeRolePolicy"),
        "put-role-policy-events": _lookup_by_event("put-role-policy-events", "PutRolePolicy"),
        "write-events": _lookup_read_only_false("write-events"),
        "access-denied-events": _lookup_read_only_false(
            "access-denied-events",
            "Drystone filters write-event CloudTrail records for AccessDenied and UnauthorizedOperation error codes.",
        ),
        "throttling-events": _lookup_read_only_false(
            "throttling-events",
            "Drystone filters write-event CloudTrail records for throttling-related error codes.",
        ),
        "delete-events": _lookup_read_only_false(
            "delete-events",
            "Drystone filters write-event CloudTrail records for Delete* event names and aggregates deletion volume.",
        ),
        "audit-tampering-events": _lookup_read_only_false(
            "audit-tampering-events",
            "Drystone derives audit tampering from StopLogging, DeleteTrail, and UpdateTrail CloudTrail events.",
        ),
        "privilege-escalation-events": _lookup_read_only_false(
            "privilege-escalation-events",
            "Drystone derives privilege-escalation indicators from IAM access-key, policy attachment, and login-profile events.",
        ),
    }
}

_CHECK_STEMS = {
    "CTEF-001": "root-events",
    "CTEF-002": "console-login-events",
    "CTEF-003": "audit-tampering-events",
    "CTEF-004": "privilege-escalation-events",
    "CTEF-005": "throttling-events",
    "CTEF-006": "access-denied-events",
    "CTEF-007": "console-login-events",
    "CTEF-008": "delete-events",
    "CTEF-009": "credential-report-events",
    "CTEF-010": "assume-role-events",
    "CTEF-011": "disable-security-hub-events",
    "CTEF-012": "get-secret-value-events",
    "CTEF-013": "update-assume-role-events",
}

_DERIVED_NOTES = {
    "CTEF-003": "Drystone derives audit tampering from StopLogging, DeleteTrail, and UpdateTrail CloudTrail events.",
    "CTEF-004": "Drystone derives privilege escalation from IAM access-key creation, policy attachment, and login-profile events.",
    "CTEF-005": "Drystone filters CloudTrail write events for throttling error codes and aggregates spikes.",
    "CTEF-006": "Drystone filters CloudTrail write events for access-denied error codes and aggregates denial storms.",
    "CTEF-007": "Drystone derives off-hours console login findings from ConsoleLogin event timestamps outside the business-hour window.",
    "CTEF-008": "Drystone filters CloudTrail write events for Delete* event names and aggregates high-volume deletion activity.",
    "CTEF-010": "Drystone derives cross-account AssumeRole risk by comparing caller and target account context in CloudTrail events.",
    "CTEF-011": "Drystone correlates disabling events across Security Hub, GuardDuty, and CloudWatch alarms as monitoring disruption.",
    "CTEF-012": "Drystone correlates Secrets Manager and SSM Parameter Store read events as credential-access activity.",
    "CTEF-013": "Drystone correlates trust-policy and inline-policy changes as IAM persistence or escalation activity.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["cloudtrail_events"][_stem]
    _commands = _source_query.commands
    if _check_id == "CTEF-003":
        _commands = (
            *SOURCE_QUERIES["cloudtrail_events"]["stop-logging-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["delete-trail-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["update-trail-events"].commands,
        )
    elif _check_id == "CTEF-004":
        _commands = (
            *SOURCE_QUERIES["cloudtrail_events"]["create-access-key-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["attach-user-policy-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["attach-role-policy-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["create-login-profile-events"].commands,
        )
    elif _check_id == "CTEF-009":
        _commands = (
            *SOURCE_QUERIES["cloudtrail_events"]["credential-report-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["get-credential-report-events"].commands,
        )
    elif _check_id == "CTEF-011":
        _commands = (
            *SOURCE_QUERIES["cloudtrail_events"]["disable-security-hub-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["delete-detector-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["disable-alarm-actions-events"].commands,
        )
    elif _check_id == "CTEF-012":
        _commands = (
            *SOURCE_QUERIES["cloudtrail_events"]["get-secret-value-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["get-parameter-events"].commands,
        )
    elif _check_id == "CTEF-013":
        _commands = (
            *SOURCE_QUERIES["cloudtrail_events"]["update-assume-role-events"].commands,
            *SOURCE_QUERIES["cloudtrail_events"]["put-role-policy-events"].commands,
        )
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
