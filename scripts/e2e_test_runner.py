"""Drystone E2E test runner.

Runs Drystone audits across combinations of:
- skill sets (single skill, optional multi-skill pairs)
- report type (general, pci-dss)
- output format (markdown, json)

Design notes:
- Drystone CLI currently loads config from ~/.drystone/last-run.json.
  To avoid mutating the user's real config (and to support parallel runs),
  each test is executed with an isolated HOME directory.
- AWS credentials are loaded from a JSON file and injected into the per-test
  Drystone config via WizardConfig.aws_credentials_file.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, cast

import click

if TYPE_CHECKING:
    from drystone.models import WizardConfig


SKILLS_ALL: Tuple[str, ...] = (
    "iam",
    "exposure",
    "network",
    "vulns",
    "alerting",
    "hardening",
    "ecr",
    "secretsmanager",
    "waf",
    "kms",
    "messaging",
    "cicd",
    "compute",
)

REPORT_TYPES_ALL: Tuple[str, ...] = ("general", "pci-dss")
FORMATS_ALL: Tuple[str, ...] = ("markdown", "json")
AI_PROVIDERS_ALL: Tuple[str, ...] = ("claude-cli", "claude-api")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _slugify(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^A-Za-z0-9._+-]+", "-", s)
    s = re.sub(r"-+", "-", s)
    return s.strip("-") or "test"


@dataclass(frozen=True)
class TestCombination:
    """Represents one E2E test combination."""

    skills: Tuple[str, ...]
    report_type: str
    format: str
    test_id: str
    multi_skill: bool = False

    @property
    def display_skill(self) -> str:
        return "+".join(self.skills)

    @property
    def client_name(self) -> str:
        return f"E2ETest_{self.test_id}"


@dataclass
class TestResult:
    """Result for one executed test."""

    combination: TestCombination
    status: str  # PASS, FAIL, ERROR, SKIP
    duration: float
    attempt: int = 1
    exit_code: Optional[int] = None
    error_message: Optional[str] = None
    stack_trace: Optional[str] = None
    session_path: Optional[str] = None
    artifacts: Dict[str, str] = field(default_factory=dict)
    log_path: Optional[str] = None

    def to_dict(self) -> Dict:
        d = asdict(self)
        # Make combination nested nicely
        d["combination"] = asdict(self.combination)
        return d


def load_credentials(creds_file: Path) -> Dict[str, str]:
    """Load AWS credentials from JSON file.

    Expected format:
    {
      "aws_access_key_id": "...",
      "aws_secret_access_key": "...",
      "aws_session_token": "..."  # optional
    }
    """
    expanded = Path(creds_file).expanduser()
    if not expanded.exists():
        raise FileNotFoundError(f"Credentials file not found: {expanded}")
    if not expanded.is_file():
        raise ValueError(f"Credentials path is not a file: {expanded}")

    with open(expanded, "r") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Credentials JSON must be an object: {expanded}")

    if not data.get("aws_access_key_id"):
        raise ValueError(f"Missing aws_access_key_id in: {expanded}")
    if not data.get("aws_secret_access_key"):
        raise ValueError(f"Missing aws_secret_access_key in: {expanded}")

    return {
        "aws_access_key_id": str(data["aws_access_key_id"]).strip(),
        "aws_secret_access_key": str(data["aws_secret_access_key"]).strip(),
        "aws_session_token": (
            str(data.get("aws_session_token")).strip() if data.get("aws_session_token") else ""
        ),
    }


def generate_combinations(
    skills: Optional[Sequence[str]] = None,
    report_types: Optional[Sequence[str]] = None,
    formats: Optional[Sequence[str]] = None,
    multi_skill: bool = False,
) -> List[TestCombination]:
    selected_skills = tuple(skills) if skills else SKILLS_ALL
    selected_report_types = tuple(report_types) if report_types else REPORT_TYPES_ALL
    selected_formats = tuple(formats) if formats else FORMATS_ALL

    combos: List[TestCombination] = []

    # Single-skill combinations
    for skill in selected_skills:
        for report_type in selected_report_types:
            for fmt in selected_formats:
                test_id = _slugify(f"{skill}_{report_type}_{fmt}")
                combos.append(
                    TestCombination(
                        skills=(skill,),
                        report_type=report_type,
                        format=fmt,
                        test_id=test_id,
                        multi_skill=False,
                    )
                )

    # Multi-skill (pairs)
    if multi_skill:
        for a, b in itertools.combinations(selected_skills, 2):
            for report_type in selected_report_types:
                for fmt in selected_formats:
                    test_id = _slugify(f"{a}+{b}_{report_type}_{fmt}")
                    combos.append(
                        TestCombination(
                            skills=(a, b),
                            report_type=report_type,
                            format=fmt,
                            test_id=test_id,
                            multi_skill=True,
                        )
                    )

    return combos


def create_test_config(
    combination: TestCombination,
    credentials_file: Path,
    region: str,
    ai_provider: str,
    ai_api_key: Optional[str],
    min_severity: str,
) -> "WizardConfig":
    from drystone.models import WizardConfig

    fmt = cast(Literal["markdown", "json"], combination.format)
    report_t = cast(Literal["general", "pci-dss"], combination.report_type)
    provider_t = cast(Literal["claude-cli", "claude-api"], ai_provider)
    min_sev_t = cast(Literal["low", "medium", "high", "critical"], min_severity)

    # Use credentials file to avoid storing secrets in config JSON.
    return WizardConfig(
        client_name=combination.client_name,
        aws_credentials_file=Path(credentials_file).expanduser(),
        aws_region=region,
        skills=list(combination.skills),
        output_formats=[fmt],
        report_type=report_t,
        ai_provider=provider_t,
        ai_api_key=ai_api_key,
        min_severity=min_sev_t,
        non_interactive=True,
    )


def _to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _write_isolated_last_run_config(home_dir: Path, config: "WizardConfig") -> Path:
    config_dir = home_dir / ".drystone"
    config_dir.mkdir(parents=True, exist_ok=True)
    last_run = config_dir / "last-run.json"
    with open(last_run, "w") as f:
        json.dump(config.dict_for_json(), f, indent=2)
    return last_run


def _detect_session_path_from_output(output: str) -> Optional[Path]:
    # Expected line: "   Session: audit-logs/Client_2026-..."
    m = re.search(r"\bSession:\s*(.+)\s*$", output, flags=re.MULTILINE)
    if not m:
        return None
    candidate = m.group(1).strip()
    try:
        return Path(candidate)
    except Exception:
        return None


def _find_latest_session_by_prefix(audit_logs_dir: Path, client_name: str) -> Optional[Path]:
    if not audit_logs_dir.exists():
        return None
    candidates = [p for p in audit_logs_dir.glob(f"{client_name}_*") if p.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def _expected_report_filename(skill: str, report_type: str, fmt: str) -> str:
    if fmt == "json":
        return f"findings-export-{skill}.json"
    if fmt == "markdown":
        if report_type == "pci-dss":
            return f"pci-dss-compliance-report-{skill}.md"
        return f"audit-report-{skill}.md"
    raise ValueError(f"Unknown format: {fmt}")


def validate_test_artifacts(
    combination: TestCombination, session_path: Path
) -> Tuple[bool, Optional[str], Dict[str, str]]:
    artifacts: Dict[str, str] = {"session": str(session_path)}

    if not session_path.exists():
        return False, f"Session path not found: {session_path}", artifacts

    audit_log = session_path / "audit.log"
    if audit_log.exists():
        try:
            content = audit_log.read_text(errors="replace")
            if re.search(r"\b(ERROR|CRITICAL)\b", content):
                return False, "audit.log contains ERROR/CRITICAL", artifacts
        except Exception:
            # If we can't read logs, don't hard fail; artifact checks will still validate output.
            pass
    else:
        # Not fatal, but worth noting.
        artifacts["audit_log_missing"] = str(audit_log)

    for skill in combination.skills:
        evidence_dir = session_path / "evidence" / skill
        artifacts[f"evidence:{skill}"] = str(evidence_dir)
        if not evidence_dir.exists():
            return (
                False,
                f"Evidence directory missing for skill '{skill}': {evidence_dir}",
                artifacts,
            )

        evidence_files = sorted(evidence_dir.glob("*.json"))
        if not evidence_files:
            return False, f"No evidence JSON files for skill '{skill}': {evidence_dir}", artifacts

        # Basic non-empty check
        for fp in evidence_files:
            if fp.stat().st_size <= 0:
                return False, f"Empty evidence file: {fp}", artifacts

        findings_file = session_path / "findings" / f"{skill}.json"
        artifacts[f"findings:{skill}"] = str(findings_file)
        if not findings_file.exists():
            return False, f"Findings file missing for skill '{skill}': {findings_file}", artifacts
        if findings_file.stat().st_size <= 0:
            return False, f"Empty findings file: {findings_file}", artifacts

        try:
            with open(findings_file, "r") as f:
                findings_json = json.load(f)
            if not isinstance(findings_json, dict):
                return False, f"Findings JSON is not an object: {findings_file}", artifacts
            if "findings" not in findings_json or "summary" not in findings_json:
                return (
                    False,
                    f"Findings JSON missing keys (findings/summary): {findings_file}",
                    artifacts,
                )
        except json.JSONDecodeError as e:
            return False, f"Invalid findings JSON ({e}): {findings_file}", artifacts

        report_name = _expected_report_filename(skill, combination.report_type, combination.format)
        report_file = session_path / "reports" / report_name
        artifacts[f"report:{skill}"] = str(report_file)
        if not report_file.exists():
            return False, f"Report file not found for skill '{skill}': {report_file}", artifacts
        if report_file.stat().st_size <= 0:
            return False, f"Empty report file: {report_file}", artifacts

    return True, None, artifacts


def _is_retryable_error(result: TestResult, combined_output: str) -> bool:
    if result.status != "ERROR":
        return False

    msg = (result.error_message or "") + "\n" + (combined_output or "")
    msg_l = msg.lower()

    # Do not retry invalid credentials.
    if "invalid aws credentials" in msg_l or "invalidclienttokenid" in msg_l:
        return False

    retry_markers = [
        "throttl",
        "rate exceeded",
        "requestlimitexceeded",
        "serviceunavailable",
        "temporarily unavailable",
        "timeout",
        "connection reset",
        "endpointconnectionerror",
    ]
    return any(m in msg_l for m in retry_markers)


def execute_test_once(
    repo_root: Path,
    output_dir: Path,
    combination: TestCombination,
    credentials_file: Path,
    credentials_env: Dict[str, str],
    region: str,
    ai_provider: str,
    ai_api_key: Optional[str],
    min_severity: str,
    timeout_sec: int,
    attempt: int,
) -> TestResult:
    start = time.monotonic()

    test_home = output_dir / "homes" / f"{combination.test_id}_{uuid.uuid4().hex[:8]}"
    test_home.mkdir(parents=True, exist_ok=True)

    # Prepare Drystone config for this test
    try:
        config = create_test_config(
            combination,
            credentials_file=credentials_file,
            region=region,
            ai_provider=ai_provider,
            ai_api_key=ai_api_key,
            min_severity=min_severity,
        )
        _write_isolated_last_run_config(test_home, config)
    except Exception as e:
        return TestResult(
            combination=combination,
            status="ERROR",
            duration=time.monotonic() - start,
            attempt=attempt,
            error_message=f"Failed to create/write config: {e}",
            stack_trace=traceback.format_exc(),
        )

    cmd = [sys.executable, "-m", "drystone", "audit", "--non-interactive"]

    env = os.environ.copy()
    env["HOME"] = str(test_home)
    env["PYTHONUNBUFFERED"] = "1"
    env["DRYSTONE_E2E"] = "1"
    env["AWS_REGION"] = region
    env["AWS_DEFAULT_REGION"] = region

    # Optional: also provide env creds (defense-in-depth, but runner never logs them)
    env["AWS_ACCESS_KEY_ID"] = credentials_env.get("aws_access_key_id", "")
    env["AWS_SECRET_ACCESS_KEY"] = credentials_env.get("aws_secret_access_key", "")
    if credentials_env.get("aws_session_token"):
        env["AWS_SESSION_TOKEN"] = credentials_env["aws_session_token"]

    log_path = output_dir / "logs" / f"{combination.test_id}.attempt{attempt}.log"

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as e:
        combined = _to_text(e.stdout) + "\n" + _to_text(e.stderr)
        log_path.write_text(combined, errors="replace")
        return TestResult(
            combination=combination,
            status="ERROR",
            duration=time.monotonic() - start,
            attempt=attempt,
            exit_code=None,
            error_message=f"Timeout after {timeout_sec}s",
            session_path=None,
            log_path=str(log_path),
        )
    except Exception as e:
        log_path.write_text(traceback.format_exc(), errors="replace")
        return TestResult(
            combination=combination,
            status="ERROR",
            duration=time.monotonic() - start,
            attempt=attempt,
            error_message=f"Subprocess execution failed: {e}",
            stack_trace=traceback.format_exc(),
            log_path=str(log_path),
        )

    combined_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    log_path.write_text(combined_output, errors="replace")

    # If Drystone returned non-zero, treat as ERROR (crash/infra/etc.).
    if proc.returncode != 0:
        # Try to locate a session anyway (sometimes session created before failure)
        session_path = _detect_session_path_from_output(combined_output)
        if session_path is None:
            session_path = _find_latest_session_by_prefix(
                repo_root / "audit-logs", combination.client_name
            )

        return TestResult(
            combination=combination,
            status="ERROR",
            duration=time.monotonic() - start,
            attempt=attempt,
            exit_code=proc.returncode,
            error_message=f"Drystone exit code {proc.returncode}",
            session_path=str(session_path) if session_path else None,
            log_path=str(log_path),
        )

    # Success exit code: validate artifacts
    session_path = _detect_session_path_from_output(combined_output)
    if session_path is None:
        session_path = _find_latest_session_by_prefix(
            repo_root / "audit-logs", combination.client_name
        )

    if session_path is None:
        return TestResult(
            combination=combination,
            status="FAIL",
            duration=time.monotonic() - start,
            attempt=attempt,
            exit_code=proc.returncode,
            error_message="Could not locate audit session directory",
            log_path=str(log_path),
        )

    ok, err, artifacts = validate_test_artifacts(combination, session_path=session_path)
    if not ok:
        return TestResult(
            combination=combination,
            status="FAIL",
            duration=time.monotonic() - start,
            attempt=attempt,
            exit_code=proc.returncode,
            error_message=err,
            session_path=str(session_path),
            artifacts=artifacts,
            log_path=str(log_path),
        )

    return TestResult(
        combination=combination,
        status="PASS",
        duration=time.monotonic() - start,
        attempt=attempt,
        exit_code=proc.returncode,
        session_path=str(session_path),
        artifacts=artifacts,
        log_path=str(log_path),
    )


def execute_test_with_retry(
    repo_root: Path,
    output_dir: Path,
    combination: TestCombination,
    credentials_file: Path,
    credentials_env: Dict[str, str],
    region: str,
    ai_provider: str,
    ai_api_key: Optional[str],
    min_severity: str,
    timeout_sec: int,
    max_retries: int,
) -> TestResult:
    last_result: Optional[TestResult] = None

    for attempt in range(1, max_retries + 2):
        result = execute_test_once(
            repo_root=repo_root,
            output_dir=output_dir,
            combination=combination,
            credentials_file=credentials_file,
            credentials_env=credentials_env,
            region=region,
            ai_provider=ai_provider,
            ai_api_key=ai_api_key,
            min_severity=min_severity,
            timeout_sec=timeout_sec,
            attempt=attempt,
        )
        last_result = result

        if result.status in ("PASS", "FAIL"):
            return result

        # ERROR
        try:
            combined_output = ""
            if result.log_path and Path(result.log_path).exists():
                combined_output = Path(result.log_path).read_text(errors="replace")
        except Exception:
            combined_output = ""

        if attempt <= max_retries and _is_retryable_error(result, combined_output):
            time.sleep(5)
            continue

        return result

    # Should be unreachable
    return last_result or TestResult(
        combination=combination,
        status="ERROR",
        duration=0.0,
        error_message="Unknown runner error",
    )


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def cleanup_audit_logs(repo_root: Path) -> None:
    audit_logs = repo_root / "audit-logs"
    if audit_logs.exists() and audit_logs.is_dir():
        shutil.rmtree(audit_logs)


def generate_summary_report(results: List[TestResult], output_dir: Path) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    errors = sum(1 for r in results if r.status == "ERROR")
    skipped = sum(1 for r in results if r.status == "SKIP")

    pass_rate = (passed / total * 100.0) if total else 0.0
    durations = [r.duration for r in results if r.duration is not None]
    duration_total = sum(durations) if durations else 0.0

    payload = {
        "timestamp": _utc_now_iso(),
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "pass_rate": round(pass_rate, 1),
            "duration_total_sec": round(duration_total, 2),
        },
        "results": [r.to_dict() for r in results],
    }

    _ensure_dir(output_dir)
    json_path = output_dir / "test-results.json"
    md_path = output_dir / "test-results.md"

    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2)

    # Markdown report
    lines: List[str] = []
    lines.append(f"# Drystone E2E Test Results")
    lines.append("")
    lines.append(f"- Timestamp: `{payload['timestamp']}`")
    lines.append(f"- Total: {total}")
    lines.append(f"- Passed: {passed}")
    lines.append(f"- Failed: {failed}")
    lines.append(f"- Errors: {errors}")
    lines.append(f"- Skipped: {skipped}")
    lines.append(f"- Pass rate: {payload['summary']['pass_rate']}%")
    lines.append(f"- Total duration: {payload['summary']['duration_total_sec']}s")
    lines.append("")

    lines.append("## Results")
    lines.append("")
    lines.append("| Test ID | Skills | Report Type | Format | Status | Duration (s) | Attempt |")
    lines.append("|---------|--------|------------|--------|--------|--------------|---------|")
    for r in results:
        c = r.combination
        lines.append(
            f"| `{c.test_id}` | `{c.display_skill}` | `{c.report_type}` | `{c.format}` | `{r.status}` | {r.duration:.2f} | {r.attempt} |"
        )

    # Failures/errors details
    bad = [r for r in results if r.status in ("FAIL", "ERROR")]
    if bad:
        lines.append("")
        lines.append("## Failures")
        lines.append("")
        for r in bad:
            c = r.combination
            lines.append(f"### {c.test_id}")
            lines.append("")
            lines.append(f"- Status: `{r.status}`")
            lines.append(f"- Skills: `{c.display_skill}`")
            lines.append(f"- Report type: `{c.report_type}`")
            lines.append(f"- Format: `{c.format}`")
            if r.exit_code is not None:
                lines.append(f"- Exit code: `{r.exit_code}`")
            if r.session_path:
                lines.append(f"- Session: `{r.session_path}`")
            if r.log_path:
                lines.append(f"- Log: `{r.log_path}`")
            if r.error_message:
                lines.append(f"- Error: {r.error_message}")
            lines.append("")

    with open(md_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def _print_plan(
    combinations: Sequence[TestCombination], region: str, output_dir: Path, parallel: int
) -> None:
    click.echo("\nE2E Test Plan")
    click.echo(f"  Combinations: {len(combinations)}")
    click.echo(f"  Region:       {region}")
    click.echo(f"  Parallel:     {parallel}")
    click.echo(f"  Output:       {output_dir}")
    click.echo("")
    for c in combinations:
        click.echo(f"  - {c.test_id}")


def _rich_available() -> bool:
    try:
        import rich  # noqa: F401

        return True
    except Exception:
        return False


def _run_with_progress(
    repo_root: Path,
    combinations: Sequence[TestCombination],
    output_dir: Path,
    credentials_file: Path,
    credentials_env: Dict[str, str],
    region: str,
    ai_provider: str,
    ai_api_key: Optional[str],
    min_severity: str,
    parallel: int,
    fail_fast: bool,
    timeout_sec: int,
    max_retries: int,
) -> List[TestResult]:
    results: List[TestResult] = []

    if parallel <= 1 or len(combinations) <= 1:
        for c in combinations:
            r = execute_test_with_retry(
                repo_root=repo_root,
                output_dir=output_dir,
                combination=c,
                credentials_file=credentials_file,
                credentials_env=credentials_env,
                region=region,
                ai_provider=ai_provider,
                ai_api_key=ai_api_key,
                min_severity=min_severity,
                timeout_sec=timeout_sec,
                max_retries=max_retries,
            )
            results.append(r)
            click.echo(f"{r.status:5} {c.test_id} ({r.duration:.1f}s)")
            if fail_fast and r.status != "PASS":
                break
        return results

    # Parallel execution
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if _rich_available():
        from rich.console import Console
        from rich.progress import (
            Progress,
            SpinnerColumn,
            TextColumn,
            BarColumn,
            TimeElapsedColumn,
            TimeRemainingColumn,
        )

        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running E2E tests...", total=len(combinations))
            with ThreadPoolExecutor(max_workers=parallel) as ex:
                futures = {
                    ex.submit(
                        execute_test_with_retry,
                        repo_root,
                        output_dir,
                        c,
                        credentials_file,
                        credentials_env,
                        region,
                        ai_provider,
                        ai_api_key,
                        min_severity,
                        timeout_sec,
                        max_retries,
                    ): c
                    for c in combinations
                }
                for fut in as_completed(futures):
                    c = futures[fut]
                    try:
                        r = fut.result()
                    except Exception as e:
                        r = TestResult(
                            combination=c,
                            status="ERROR",
                            duration=0.0,
                            error_message=f"Runner exception: {e}",
                            stack_trace=traceback.format_exc(),
                        )
                    results.append(r)
                    progress.advance(task, 1)
                    console.print(f"{r.status:5} {c.test_id} ({r.duration:.1f}s)")
                    if fail_fast and r.status != "PASS":
                        # Best-effort: do not cancel running futures (subprocess already started).
                        return results
        return results

    # Plain parallel output
    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futures = {
            ex.submit(
                execute_test_with_retry,
                repo_root,
                output_dir,
                c,
                credentials_file,
                credentials_env,
                region,
                ai_provider,
                ai_api_key,
                min_severity,
                timeout_sec,
                max_retries,
            ): c
            for c in combinations
        }
        for fut in as_completed(futures):
            c = futures[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = TestResult(
                    combination=c,
                    status="ERROR",
                    duration=0.0,
                    error_message=f"Runner exception: {e}",
                    stack_trace=traceback.format_exc(),
                )
            results.append(r)
            click.echo(f"{r.status:5} {c.test_id} ({r.duration:.1f}s)")
            if fail_fast and r.status != "PASS":
                return results

    return results


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--credentials",
    "credentials_path",
    type=click.Path(path_type=Path),
    required=True,
    help="Path to AWS credentials JSON (aws_access_key_id/aws_secret_access_key[/aws_session_token])",
)
@click.option("--dry-run", is_flag=True, help="Show plan without executing")
@click.option("--clean", "clean_sessions", is_flag=True, help="Delete audit-logs/ before running")
@click.option(
    "--skills",
    multiple=True,
    type=click.Choice(list(SKILLS_ALL)),
    help="Filter skills (repeatable)",
)
@click.option(
    "--report-types",
    multiple=True,
    type=click.Choice(list(REPORT_TYPES_ALL)),
    help="Filter report types (repeatable)",
)
@click.option(
    "--formats",
    multiple=True,
    type=click.Choice(list(FORMATS_ALL)),
    help="Filter output formats (repeatable)",
)
@click.option("--multi-skill", is_flag=True, help="Include multi-skill pairs")
@click.option(
    "--parallel", type=int, default=1, show_default=True, help="Number of parallel workers"
)
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("test-results"),
    show_default=True,
    help="Output directory for test results/logs",
)
@click.option("--fail-fast", is_flag=True, help="Stop after first FAIL/ERROR")
@click.option("--region", default="us-east-1", show_default=True, help="AWS region")
@click.option(
    "--timeout",
    "timeout_sec",
    type=int,
    default=600,
    show_default=True,
    help="Per-test timeout in seconds",
)
@click.option(
    "--max-retries", type=int, default=2, show_default=True, help="Retries for transient errors"
)
@click.option(
    "--ai-provider",
    type=click.Choice(list(AI_PROVIDERS_ALL)),
    default="claude-cli",
    show_default=True,
    help="AI provider for analysis (claude-cli or claude-api)",
)
@click.option(
    "--ai-api-key",
    default=None,
    help="Claude API key (required for claude-api). If unset, uses $ANTHROPIC_API_KEY.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    show_default=True,
    help="Minimum severity to collect/report",
)
def main(
    credentials_path: Path,
    dry_run: bool,
    clean_sessions: bool,
    skills: Tuple[str, ...],
    report_types: Tuple[str, ...],
    formats: Tuple[str, ...],
    multi_skill: bool,
    parallel: int,
    output_dir: Path,
    fail_fast: bool,
    region: str,
    timeout_sec: int,
    max_retries: int,
    ai_provider: str,
    ai_api_key: Optional[str],
    min_severity: str,
) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    output_dir = output_dir.resolve()

    selected_skills = list(skills) if skills else None
    selected_report_types = list(report_types) if report_types else None
    selected_formats = list(formats) if formats else None

    combinations = generate_combinations(
        skills=selected_skills,
        report_types=selected_report_types,
        formats=selected_formats,
        multi_skill=multi_skill,
    )

    _ensure_dir(output_dir / "logs")
    _ensure_dir(output_dir / "homes")

    # Validate creds file unless dry-run
    credentials_env: Dict[str, str] = {}
    if dry_run:
        if credentials_path and Path(credentials_path).expanduser().exists():
            credentials_env = load_credentials(Path(credentials_path))
        else:
            click.echo("⚠️  --dry-run: credentials file not found; continuing (no execution).")
    else:
        credentials_env = load_credentials(Path(credentials_path))

    _print_plan(combinations, region=region, output_dir=output_dir, parallel=parallel)
    if dry_run:
        return

    # Resolve AI credentials
    if ai_provider == "claude-api" and not ai_api_key:
        ai_api_key = os.environ.get("ANTHROPIC_API_KEY")
    if ai_provider == "claude-api" and not ai_api_key:
        raise SystemExit("--ai-provider=claude-api requires --ai-api-key or ANTHROPIC_API_KEY")

    if clean_sessions:
        click.echo("Cleaning audit-logs/ ...")
        cleanup_audit_logs(repo_root)

    click.echo("\nRunning tests...\n")
    started_at = time.monotonic()

    results = _run_with_progress(
        repo_root=repo_root,
        combinations=combinations,
        output_dir=output_dir,
        credentials_file=Path(credentials_path),
        credentials_env=credentials_env,
        region=region,
        ai_provider=ai_provider,
        ai_api_key=ai_api_key,
        min_severity=min_severity,
        parallel=max(1, int(parallel)),
        fail_fast=fail_fast,
        timeout_sec=timeout_sec,
        max_retries=max(0, int(max_retries)),
    )

    generate_summary_report(results, output_dir=output_dir)

    elapsed = time.monotonic() - started_at
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    errors = sum(1 for r in results if r.status == "ERROR")

    click.echo("\nDone.")
    click.echo(f"  Passed: {passed}")
    click.echo(f"  Failed: {failed}")
    click.echo(f"  Errors: {errors}")
    click.echo(f"  Duration: {elapsed:.1f}s")
    click.echo(f"  Results: {output_dir / 'test-results.json'}")
    click.echo(f"  Report:  {output_dir / 'test-results.md'}")

    # Exit code
    if failed or errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
