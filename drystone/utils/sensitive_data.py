"""Shared conservative detection and redaction for sensitive free text."""

import re
from typing import Dict

_SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"aws(.{0,20})?(secret|access).{0,10}[=:]\s*[A-Za-z0-9/+=]{30,}", re.IGNORECASE
    ),
    "password": re.compile(r"password\s*[=:]\s*[^\s\"']+", re.IGNORECASE),
    "api_key": re.compile(r"api[_-]?key\s*[=:]\s*[^\s\"']+", re.IGNORECASE),
    "token": re.compile(r"(token|secret)\s*[=:]\s*[^\s\"']+", re.IGNORECASE),
}
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<prefix>\b(?:password|passwd|pwd|api[_-]?key|token|secret|"
    r"access[_-]?key|client[_-]?secret|private[_-]?key)\b\s*[=:]\s*)"
    r"(?P<quote>[\"']?)(?P<value>[^\s\"']+)",
    re.IGNORECASE,
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)

def scan_for_secrets(text: str) -> Dict[str, bool]:
    """Return conservative flags for common credential-shaped values."""
    return {name: bool(pattern.search(text)) for name, pattern in _SECRET_PATTERNS.items()}

def redact_secrets(text: str) -> str:
    """Replace secret-shaped values while preserving non-secret user-data."""
    redacted = _PRIVATE_KEY_PATTERN.sub("[REDACTED:private_key]", text)
    redacted = _SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group('prefix')}{match.group('quote')}[REDACTED:secret]",
        redacted,
    )
    return re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED:aws_access_key]", redacted)
