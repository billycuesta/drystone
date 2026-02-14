"""Report safety tests (no secret leaks)."""

from drystone.reports.safety import redact_secrets


def test_redacts_aws_access_key_id():
    text = "leak AKIA1234567890ABCDE1 in report"
    redacted, n = redact_secrets(text)
    assert n >= 1
    assert "AKIA****************" in redacted
    assert "AKIA1234567890ABCDE1" not in redacted


def test_redacts_aws_secret_key_like_token():
    token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40-ish chars base64-ish
    redacted, n = redact_secrets(f"secret={token}")
    assert n >= 1
    assert "[REDACTED_SECRET]" in redacted
    assert token not in redacted
