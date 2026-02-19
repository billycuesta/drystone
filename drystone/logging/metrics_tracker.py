"""Thread-safe metrics tracker with atomic updates using mutex.

Ensures metrics are updated atomically even during concurrent skill execution.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class MetricsTracker:
    """Thread-safe metrics tracker with atomic operations.

    Tracks audit metrics:
    - Evidence collection times
    - Analysis times
    - Finding counts
    - Risk scores
    - Validation results
    - Retry attempts
    """

    def __init__(self, metrics_file: Path):
        """Initialize metrics tracker.

        Args:
            metrics_file: Path to metrics JSON file
        """
        self.metrics_file = Path(metrics_file)
        self.lock = threading.RLock()  # Reentrant lock for nested calls

        # Ensure parent directory exists
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)

        # Initialize metrics
        self._ensure_metrics_file()

        logger.info(f"MetricsTracker initialized: {self.metrics_file}")

    def _ensure_metrics_file(self) -> None:
        """Ensure metrics file exists with initial structure."""
        if not self.metrics_file.exists():
            initial_metrics = {
                "start_time": datetime.utcnow().isoformat(),
                "skills": {},
                "total_findings": 0,
                "total_risk_score": 0.0,
                "total_prompt_tokens_est": 0,
                "total_response_tokens_est": 0,
                "total_tokens_est": 0,
                "validation_failures": 0,
                "retry_attempts": 0,
            }
            self._write_metrics(initial_metrics)

    def _read_metrics(self) -> Dict[str, Any]:
        """Read metrics from file (thread-safe)."""
        try:
            with open(self.metrics_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            self._ensure_metrics_file()
            return self._read_metrics()
        except Exception as e:
            logger.error(f"Failed to read metrics: {e}")
            return {}

    def _write_metrics(self, metrics: Dict[str, Any]) -> None:
        """Write metrics to file (thread-safe with flush)."""
        try:
            with open(self.metrics_file, "w") as f:
                json.dump(metrics, f, indent=2, default=str)
                f.flush()  # Critical: ensure written to disk
        except Exception as e:
            logger.error(f"Failed to write metrics: {e}", exc_info=True)

    def record_skill_start(self, skill_name: str) -> None:
        """Record skill analysis start (atomic).

        Args:
            skill_name: Name of skill (e.g., 'iam', 'network')
        """
        with self.lock:
            metrics = self._read_metrics()

            if "skills" not in metrics:
                metrics["skills"] = {}

            metrics["skills"][skill_name] = {
                "start_time": datetime.utcnow().isoformat(),
                "status": "in_progress",
                "findings": 0,
                "risk_score": 0.0,
                "validation_passed": False,
                "llm_checks": 0,
                "deterministic_checks": 0,
                "evidence_distilled_files": 0,
                "evidence_items_removed": 0,
                "prompt_tokens_est": 0,
                "response_tokens_est": 0,
                "total_tokens_est": 0,
            }

            self._write_metrics(metrics)

    def record_token_usage(self, skill_name: str, prompt_tokens: int, response_tokens: int) -> None:
        """Record estimated token usage for a model call."""
        with self.lock:
            metrics = self._read_metrics()

            if skill_name not in metrics.get("skills", {}):
                metrics.setdefault("skills", {})[skill_name] = {}

            skill = metrics["skills"][skill_name]
            skill_prompt = int(skill.get("prompt_tokens_est", 0)) + int(prompt_tokens)
            skill_response = int(skill.get("response_tokens_est", 0)) + int(response_tokens)
            skill_total = skill_prompt + skill_response

            skill.update(
                {
                    "prompt_tokens_est": skill_prompt,
                    "response_tokens_est": skill_response,
                    "total_tokens_est": skill_total,
                }
            )

            total_prompt = sum(
                int(s.get("prompt_tokens_est", 0)) for s in metrics["skills"].values()
            )
            total_response = sum(
                int(s.get("response_tokens_est", 0)) for s in metrics["skills"].values()
            )
            metrics["total_prompt_tokens_est"] = total_prompt
            metrics["total_response_tokens_est"] = total_response
            metrics["total_tokens_est"] = total_prompt + total_response

            self._write_metrics(metrics)

    def record_skill_provider(self, skill_name: str, provider: str) -> None:
        """Record provider used by skill analysis."""
        with self.lock:
            metrics = self._read_metrics()
            if skill_name not in metrics.get("skills", {}):
                metrics["skills"][skill_name] = {}
            metrics["skills"][skill_name]["provider"] = provider
            self._write_metrics(metrics)

    def record_skill_quality(
        self,
        skill_name: str,
        confidence_score: float,
        confidence_level: str,
        llm_skipped: bool,
    ) -> None:
        """Record quality/confidence metrics for a skill."""
        with self.lock:
            metrics = self._read_metrics()

            if skill_name not in metrics.get("skills", {}):
                metrics["skills"][skill_name] = {}

            metrics["skills"][skill_name].update(
                {
                    "confidence_score": float(confidence_score),
                    "confidence_level": str(confidence_level),
                    "llm_skipped": bool(llm_skipped),
                }
            )
            self._write_metrics(metrics)

    def record_llm_budget(
        self,
        skill_name: str,
        llm_checks: int,
        deterministic_checks: int,
        distilled_files: int,
        items_removed: int,
    ) -> None:
        """Record P0 token-saving routing/distillation metrics."""
        with self.lock:
            metrics = self._read_metrics()

            if skill_name not in metrics.get("skills", {}):
                metrics["skills"][skill_name] = {}

            metrics["skills"][skill_name].update(
                {
                    "llm_checks": int(llm_checks),
                    "deterministic_checks": int(deterministic_checks),
                    "evidence_distilled_files": int(distilled_files),
                    "evidence_items_removed": int(items_removed),
                }
            )

            self._write_metrics(metrics)

    def record_skill_findings(
        self,
        skill_name: str,
        findings_count: int,
        risk_score: float,
    ) -> None:
        """Record skill findings (atomic).

        Args:
            skill_name: Name of skill
            findings_count: Number of findings
            risk_score: Overall risk score (0-10)
        """
        with self.lock:
            metrics = self._read_metrics()

            if skill_name not in metrics.get("skills", {}):
                metrics["skills"][skill_name] = {}

            metrics["skills"][skill_name].update(
                {
                    "findings": findings_count,
                    "risk_score": risk_score,
                }
            )

            # Update totals
            total_findings = sum(s.get("findings", 0) for s in metrics.get("skills", {}).values())
            total_risk = sum(s.get("risk_score", 0.0) for s in metrics.get("skills", {}).values())

            metrics["total_findings"] = total_findings
            metrics["total_risk_score"] = total_risk

            self._write_metrics(metrics)

    def record_skill_complete(self, skill_name: str, validation_passed: bool) -> None:
        """Record skill analysis completion (atomic).

        Args:
            skill_name: Name of skill
            validation_passed: Whether validation succeeded
        """
        with self.lock:
            metrics = self._read_metrics()

            if skill_name not in metrics.get("skills", {}):
                metrics["skills"][skill_name] = {}

            metrics["skills"][skill_name].update(
                {
                    "end_time": datetime.utcnow().isoformat(),
                    "status": "complete" if validation_passed else "failed",
                    "validation_passed": validation_passed,
                }
            )

            if not validation_passed:
                metrics["validation_failures"] = metrics.get("validation_failures", 0) + 1

            self._write_metrics(metrics)

    def record_retry_attempt(self, skill_name: str, attempt_number: int, reason: str) -> None:
        """Record retry attempt (atomic).

        Args:
            skill_name: Name of skill
            attempt_number: Which retry attempt (1, 2, 3...)
            reason: Reason for retry (e.g., 'validation_failed', 'timeout')
        """
        with self.lock:
            metrics = self._read_metrics()

            if skill_name not in metrics.get("skills", {}):
                metrics["skills"][skill_name] = {}

            if "retries" not in metrics["skills"][skill_name]:
                metrics["skills"][skill_name]["retries"] = []

            metrics["skills"][skill_name]["retries"].append(
                {
                    "attempt": attempt_number,
                    "reason": reason,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

            metrics["retry_attempts"] = metrics.get("retry_attempts", 0) + 1

            self._write_metrics(metrics)

    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics (thread-safe read).

        Returns:
            Current metrics dict
        """
        with self.lock:
            return self._read_metrics()

    def get_skill_metrics(self, skill_name: str) -> Optional[Dict[str, Any]]:
        """Get metrics for specific skill (thread-safe read).

        Args:
            skill_name: Name of skill

        Returns:
            Skill metrics dict or None if not found
        """
        with self.lock:
            metrics = self._read_metrics()
            return metrics.get("skills", {}).get(skill_name)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary metrics (thread-safe read).

        Returns:
            Summary with totals and completion status
        """
        with self.lock:
            metrics = self._read_metrics()

            completed = sum(
                1 for s in metrics.get("skills", {}).values() if s.get("status") == "complete"
            )
            total_skills = len(metrics.get("skills", {}))

            return {
                "completion_rate": f"{completed}/{total_skills}",
                "total_findings": metrics.get("total_findings", 0),
                "total_risk_score": metrics.get("total_risk_score", 0.0),
                "validation_failures": metrics.get("validation_failures", 0),
                "retry_attempts": metrics.get("retry_attempts", 0),
                "elapsed_time": self._calculate_elapsed_time(metrics),
            }

    def _calculate_elapsed_time(self, metrics: Dict[str, Any]) -> Optional[str]:
        """Calculate elapsed time since start.

        Args:
            metrics: Metrics dict

        Returns:
            Formatted elapsed time string or None
        """
        try:
            start_raw = metrics.get("start_time")
            if not isinstance(start_raw, str) or not start_raw:
                return None
            start = datetime.fromisoformat(start_raw)
            elapsed = datetime.utcnow() - start
            minutes = int(elapsed.total_seconds() / 60)
            seconds = int(elapsed.total_seconds() % 60)
            return f"{minutes}m {seconds}s"
        except Exception:
            return None
