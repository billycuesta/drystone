"""Safety helpers for report generation.

Goal: avoid leaking credentials or secret material into generated reports.
"""

import re
from typing import Tuple

_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
# Very rough heuristic for AWS secret access keys (base64-ish 40 chars).
_AWS_SECRET_KEY_RE = re.compile(r"\b[0-9A-Za-z/+]{40}\b")


def redact_secrets(text: str) -> Tuple[str, int]:
    """Redact obvious credential-like patterns.

    Returns:
        (redacted_text, redactions_count)
    """

    if not text:
        return text, 0

    redactions = 0

    def _sub(pattern: re.Pattern, repl: str, s: str) -> str:
        nonlocal redactions
        new_s, n = pattern.subn(repl, s)
        redactions += n
        return new_s

    out = text
    out = _sub(_AWS_ACCESS_KEY_RE, "AKIA****************", out)
    out = _sub(_AWS_SECRET_KEY_RE, "[REDACTED_SECRET]", out)
    return out, redactions
