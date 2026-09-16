"""Chain-of-custody-adjacent log of every active-verification API call made
against a client's AWS account. If Drystone ever needs to prove to a client
exactly what it did, this file is the record -- keep it complete and honest,
including denied/error attempts, not just successes.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from drystone.verification.active_verifier import VerificationResult

LOG_FILENAME = "active_verification_log.json"


def write_verification_log(session_base_path: Path, results: List[VerificationResult]) -> Path:
    """Persist every verification attempt (success, denied, or error) made
    during this audit to <session>/active_verification_log.json.
    """
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attempt_count": len(results),
        "attempts": [
            {
                "method": r.method,
                "target": r.target,
                "attempted": r.attempted,
                "result": r.result,
                "detail": r.detail,
                "timestamp": r.timestamp,
            }
            for r in results
        ],
    }
    log_path = session_base_path / LOG_FILENAME
    log_path.write_text(json.dumps(payload, indent=2))
    return log_path
