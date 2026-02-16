"""Evidence-based validation tests for Messaging findings."""

from drystone.models.findings import Finding
from drystone.validation.findings_normalizer import FindingsNormalizer


MESSAGING_CHECKLIST = {
    "skill": "messaging",
    "items": [
        {"id": "MSG-001", "severity": "High"},
        {"id": "MSG-002", "severity": "High"},
        {"id": "MSG-003", "severity": "Medium"},
        {"id": "MSG-004", "severity": "Medium"},
    ],
}


def _finding(fid: str) -> Finding:
    sev = "High" if fid in {"MSG-001", "MSG-002"} else "Medium"
    risk = 7.1 if sev == "High" else 4.2
    return Finding(
        id=fid,
        severity=sev,
        risk_score=risk,
        title=fid,
        description=fid,
        remediation="fix",
        evidence_refs=["sqs-queues.json#/items/0"],
        affected_resources=[],
        cis_reference="N/A",
        pci_dss=[],
    )


def test_msg_001_rejected_when_no_orgid_condition():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {"sqs-queues": {"items": [{"QueueArn": "arn:...", "Policy": {"Statement": []}}]}}
    out = n.normalize([_finding("MSG-001")])
    assert out == []


def test_msg_001_accepted_when_orgid_condition_present():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {
        "sqs-queues": {
            "items": [
                {
                    "QueueArn": "arn:...",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sqs:*",
                                "Principal": "*",
                                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                            }
                        ]
                    },
                }
            ]
        }
    }
    out = n.normalize([_finding("MSG-001")])
    assert len(out) == 1
    assert out[0].id == "MSG-001"


def test_msg_002_rejected_when_no_redrive_config_present():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {
        "sqs-queues": {
            "items": [
                {
                    "QueueUrl": "https://sqs.us-east-1.amazonaws.com/111/q1",
                    "QueueArn": "arn:aws:sqs:us-east-1:111:q1",
                    "RedrivePolicy": None,
                    "RedriveAllowPolicy": None,
                },
                {
                    "QueueUrl": "https://sqs.us-east-1.amazonaws.com/111/q2",
                    "QueueArn": "arn:aws:sqs:us-east-1:111:q2",
                    "RedrivePolicy": None,
                    "RedriveAllowPolicy": None,
                },
            ]
        }
    }

    out = n.normalize([_finding("MSG-002")])
    assert out == []


def test_msg_002_accepted_when_redrive_policy_present():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {
        "sqs-queues": {
            "items": [
                {
                    "QueueArn": "arn:aws:sqs:us-east-1:111:q1",
                    "RedrivePolicy": {"deadLetterTargetArn": "arn:aws:sqs:us-east-1:111:dlq"},
                    "RedriveAllowPolicy": None,
                }
            ]
        }
    }

    out = n.normalize([_finding("MSG-002")])
    assert len(out) == 1
    assert out[0].id == "MSG-002"


def test_msg_003_rejected_when_sns_sendmessage_has_sourcearn_condition():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {
        "sqs-queues": {
            "items": [
                {
                    "QueueArn": "arn:...",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "SQS:SendMessage",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Condition": {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:...:t"}},
                            }
                        ]
                    },
                }
            ]
        }
    }
    f = _finding("MSG-003")
    f.evidence_refs = ["sqs-queues.json#/items/0"]
    out = n.normalize([f])
    assert out == []


def test_msg_003_accepted_when_sns_sendmessage_missing_sourcearn_and_sourceaccount():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {
        "sqs-queues": {
            "items": [
                {
                    "QueueArn": "arn:...",
                    "Policy": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "SQS:SendMessage",
                                "Principal": {"Service": "sns.amazonaws.com"},
                            }
                        ]
                    },
                }
            ]
        }
    }
    f = _finding("MSG-003")
    f.evidence_refs = ["sqs-queues.json#/items/0"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "MSG-003"


def test_msg_004_rejected_when_no_dlq_present():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {
        "sqs-queues": {
            "items": [
                {"QueueArn": "arn:...", "RedrivePolicy": None},
            ]
        }
    }
    f = _finding("MSG-004")
    f.evidence_refs = ["sqs-queues.json#/items/0"]
    out = n.normalize([f])
    assert out == []


def test_msg_004_accepted_when_dlq_present():
    n = FindingsNormalizer(MESSAGING_CHECKLIST, "messaging")
    n.evidence = {
        "sqs-queues": {
            "items": [
                {"QueueArn": "arn:...", "RedrivePolicy": {"deadLetterTargetArn": "arn:..."}},
            ]
        }
    }
    f = _finding("MSG-004")
    f.evidence_refs = ["sqs-queues.json#/items/0"]
    out = n.normalize([f])
    assert len(out) == 1
    assert out[0].id == "MSG-004"
