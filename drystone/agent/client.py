"""AI agent client for security analysis via Claude providers."""

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import anthropic

from drystone.agent.chunker import EvidenceChunker, FindingsAggregator
from drystone.agent.budget import get_budget_policy
from drystone.agent.cache import FindingsCache
from drystone.agent.retry import analyze_with_retry
from drystone.analysis.prioritizer import score_chunk
from drystone.logging import CrashSafeLogger
from drystone.models.findings import SkillFindings
from drystone.prompts import get_audit_template
from drystone.validation.output_validators import validate_findings

logger = logging.getLogger(__name__)


class AgentError(Exception):
    """Agent client error."""

    pass


class AgentClient:
    """AI agent client for AWS security analysis.

    Analyzes collected evidence against security checklists
    and generates findings with recommendations.

    Supports Claude CLI and Claude API (Anthropic).

    Example:
        >>> agent = AgentClient(api_key="sk-ant-...")
        >>> findings = agent.analyze_evidence(
        ...     skill_name="iam",
        ...     evidence={"users": [...]},
        ...     checklist={"items": [...]}
        ... )
        >>> print(findings.summary.overall_risk_score)
        7.5
    """

    def __init__(
        self,
        provider_config: Optional[Dict[str, str]] = None,
        crash_safe_logger: Optional[CrashSafeLogger] = None,
    ):
        """Initialize agent client.

        Args:
            provider_config: Configuration dictionary with:
                {
                    'type': 'claude-api' | 'claude-cli',
                    'api_key': provider API key (required for API providers)
                }
            crash_safe_logger: Optional crash-safe logger for audit events

        Raises:
            AgentError: If configuration invalid or backend unavailable
        """
        self.provider_config = provider_config or {}
        self.config = self.provider_config  # Store config for chunker
        self.provider_type = self.provider_config.get("type", "claude-cli")
        self.api_key = self._sanitize_api_key(self.provider_config.get("api_key"))
        self.client = None
        self.use_cli = False
        self.crash_safe_logger = crash_safe_logger
        self.metrics_tracker: Any = None
        self.findings_cache = FindingsCache()
        self.progress_callback: Optional[Callable[[str, int, int, str, str], None]] = None

        # Validate provider type
        valid_types = {"claude-api", "claude-cli"}
        if self.provider_type not in valid_types:
            raise AgentError(
                f"Provider type '{self.provider_type}' not supported. Valid: {valid_types}"
            )

        # Configure Claude (CLI or API)
        self._setup_claude()

    def _setup_claude(self) -> None:
        """Setup Claude provider (API or CLI)."""
        self.provider_name = "claude"

        if self.provider_type == "claude-cli":
            # Get absolute path to CLI executable for security
            self.claude_cli_path = self._get_claude_cli_path()
            self.use_cli = True
            self.model = str(self.provider_config.get("model", "haiku"))

        elif self.provider_type == "claude-api":
            # Use API
            if not self.api_key:
                raise AgentError("Claude API key required for 'claude-api' provider")

            try:
                self.client = anthropic.Anthropic(api_key=self.api_key)
                self.model = "claude-opus-4-5-20251101"
                self.max_tokens = 16000
                self.temperature = 0.0
            except Exception as e:
                raise AgentError(f"Failed to initialize Anthropic client: {e}")

    def _sanitize_api_key(self, api_key: Optional[str]) -> Optional[str]:
        """Normalize API keys to avoid common copy/paste mistakes."""
        if not isinstance(api_key, str):
            return api_key
        key = api_key.strip()
        if key.startswith("- "):
            key = key[2:].strip()
        return key

    def _get_claude_cli_path(self) -> str:
        """Get absolute path to claude CLI executable.

        Returns:
            Absolute path to claude executable

        Raises:
            AgentError: If claude CLI not found or is not a file
        """
        claude_path = shutil.which("claude")

        if not claude_path:
            raise AgentError(
                "Claude Code CLI not found in PATH.\n"
                "Install with: npm install -g @anthropic-ai/claude-code"
            )

        # Security: Verify it's a file before executing
        if not Path(claude_path).is_file():
            raise AgentError(f"Claude CLI path is not a file: {claude_path}")

        return claude_path

    def get_display_name(self) -> str:
        """Get user-friendly display name for the configured AI provider.

        Returns display name like "Claude API (Opus 4.5)" or "Claude CLI".

        Returns:
            Display name string for UI output
        """
        if self.provider_type == "claude-api":
            # Use self.model (e.g., "claude-opus-4-5-20251101")
            if hasattr(self, "model") and "opus" in self.model:
                return "Claude API (Opus 4.5)"
            elif hasattr(self, "model") and "sonnet" in self.model:
                return "Claude API (Sonnet)"
            else:
                return "Claude API"

        elif self.provider_type == "claude-cli":
            model = getattr(self, "model", "haiku")
            return f"Claude CLI ({str(model).capitalize()})"

        else:
            return "AI Provider"  # Fallback

    def analyze_evidence(
        self,
        skill_name: str,
        evidence: Dict[str, Any],
        checklist: Dict[str, Any],
        *,
        chunking: Optional[Dict[str, Any]] = None,
        pre_checks: Optional[list] = None,
    ) -> SkillFindings:
        """Analyze AWS evidence against security checklist.

        Uses Claude CLI (subprocess) if available, otherwise Claude API.

        Flow:
        1. Builds analysis prompt with evidence and checklist
        2. Calls Claude (CLI or API)
        3. Parses JSON response
        4. Validates with Pydantic model
        5. Returns structured findings

        Args:
            skill_name: Skill identifier (e.g., "iam")
            evidence: AWS evidence data (from collectors)
            checklist: Security checklist with items

        Returns:
            SkillFindings with structured findings and summary

        Raises:
            AgentError: If call fails or response invalid
        """
        # Log skill analysis start
        evidence_count = sum(len(v) if isinstance(v, list) else 1 for v in evidence.values())
        checklist_items = len(checklist.get("items", []))
        if self.crash_safe_logger:
            self.crash_safe_logger.log_skill_start(evidence_count, checklist_items)

        # 1. Get prompts (try templates first, fallback to legacy)
        system_prompt = self._get_system_prompt()
        try:
            # Try structured template approach (Shannon pattern)
            user_prompt = self._build_analysis_prompt_from_template(
                skill_name,
                evidence,
                checklist,
                chunking=chunking,
                pre_checks=pre_checks,
            )
        except Exception as e:
            # Fallback to legacy prompt if templates fail
            logger.warning(f"Template prompt failed for {skill_name}, using legacy: {e}")
            user_prompt = self._build_analysis_prompt(skill_name, evidence, checklist)

        # 2. Call LLM (Claude CLI or API)
        full_prompt = f"{system_prompt}\n\n{user_prompt}"
        prompt_tokens_est = self._estimate_tokens_text(full_prompt)
        if self.use_cli:
            response_text = self._call_claude_cli(full_prompt)
        else:
            response_text = self._call_claude_api(full_prompt)
        response_tokens_est = self._estimate_tokens_text(response_text)

        if self.metrics_tracker:
            try:
                self.metrics_tracker.record_token_usage(
                    skill_name,
                    prompt_tokens=prompt_tokens_est,
                    response_tokens=response_tokens_est,
                )
            except Exception:
                pass

        # 3. Parse JSON response
        try:
            findings_data = self._parse_json_response(response_text)
        except AgentError as first_error:
            # Claude CLI can occasionally return explanatory prose instead of strict JSON.
            # Detect interactive-session contamination early: if the response looks like
            # the Claude Code welcome message, raise immediately (repair would be useless).
            _INTERACTIVE_MARKERS = (
                "I'm ready to help",
                "What's next?",
                "Link to a failing test",
                "I'm Claude Code",
                # Spanish conversational responses from global ~/.claude/ context
                "Listo para empezar",
                "¿Evidencia a analizar?",
                "¿Cuál es el target?",
                "¿Qué necesito?",
                "/roth-init",
                "/roth-session-start",
            )
            if any(marker in response_text for marker in _INTERACTIVE_MARKERS):
                raise AgentError(
                    f"Claude CLI returned an interactive session response instead of JSON "
                    f"for {skill_name}. This usually means the CLI binary is in agent-mode. "
                    f"Try switching to 'claude-api' provider or re-authenticate the CLI."
                )
            # Attempt one lightweight repair pass that reformats the raw response into
            # the required JSON schema.
            try:
                from datetime import datetime as _dt
                _now = _dt.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                repaired = self._repair_response_to_json(
                    response_text,
                    skill_name=skill_name,
                    analyzed_at=_now,
                )
                findings_data = self._parse_json_response(repaired)
                logger.warning(
                    "Recovered non-JSON model output via repair pass for %s: %s",
                    skill_name,
                    first_error,
                )
            except AgentError:
                raise

        # 4. Validate with Pydantic
        try:
            findings = SkillFindings(**findings_data)
        except Exception as e:
            if self.crash_safe_logger:
                self.crash_safe_logger.log_validation_error(
                    f"Pydantic validation failed: {e}", {"skill": skill_name}
                )
            raise AgentError(f"Response validation failed: {e}")

        # 5. NEW: Validate output format (post-agent check)
        logger.debug(
            f"Validating {skill_name} findings: {findings.summary.total_findings} findings, severity breakdown: critical={findings.summary.critical}, high={findings.summary.high}, medium={findings.summary.medium}, low={findings.summary.low}"
        )

        if not validate_findings(skill_name, findings):
            logger.error(
                f"Validation failed for {skill_name}: summary={findings.summary}, findings count={len(findings.findings)}"
            )
            if self.crash_safe_logger:
                self.crash_safe_logger.log_validation_error(
                    f"Output validation failed for {skill_name}: findings structure invalid",
                    {
                        "skill": skill_name,
                        "summary": findings.summary.dict(),
                        "findings_count": len(findings.findings),
                    },
                )
            raise AgentError(
                f"Output validation failed for {skill_name}: findings structure invalid"
            )

        # Log skill analysis completion
        if self.crash_safe_logger:
            self.crash_safe_logger.log_skill_complete(
                len(findings.findings), findings.summary.overall_risk_score
            )

        return findings

    def _estimate_tokens_text(self, text: str) -> int:
        """Estimate tokens from text using conservative JSON-friendly ratio."""
        if not isinstance(text, str) or not text:
            return 0
        return max(1, len(text) // 3)

    def analyze_evidence_chunked(
        self,
        skill_name: str,
        evidence: Dict[str, Any],
        checklist: Dict[str, Any],
        chunker: Optional[EvidenceChunker] = None,
        pre_checks: Optional[list] = None,
    ) -> "SkillFindings":
        """Analyze evidence with automatic chunking for large datasets.

        Args:
            skill_name: Name of skill being analyzed
            evidence: Full evidence dictionary
            checklist: Security checklist
            chunker: Optional chunker instance (default: auto-created)

        Returns:
            SkillFindings with aggregated findings from all chunks
        """
        # Auto-create chunker if not provided
        budget = get_budget_policy(
            self.config.get("type", "claude-cli"),
            skill_name,
            self.config.get("scan_depth", "normal"),
        )

        cache_key = self.findings_cache.build_key(
            skill_name=skill_name,
            provider_type=self.provider_type,
            model=getattr(self, "model", "claude-cli"),
            evidence=evidence,
            checklist=checklist,
            pre_checks=pre_checks,
        )
        cached = self.findings_cache.get(cache_key)
        if cached is not None:
            print("  🧠 Cache hit: reusing previous LLM analysis")
            if self.metrics_tracker:
                try:
                    self.metrics_tracker.record_retry_attempt(skill_name, 0, "cache_hit")
                except Exception:
                    pass
            return cached

        if chunker is None:
            chunker = EvidenceChunker(max_tokens_per_chunk=budget.max_tokens_per_chunk)

        # Check if chunking is needed
        if not chunker.should_chunk(evidence):
            # Small evidence - use existing flow
            findings = self.analyze_evidence(skill_name, evidence, checklist, pre_checks=pre_checks)
            self.findings_cache.set(cache_key, findings)
            return findings

        # Large evidence - chunk and aggregate
        print("  📦 Evidence size requires chunking...")
        aggregator = FindingsAggregator()

        chunks = list(chunker.chunk_evidence(evidence))
        if len(chunks) > budget.max_chunks:
            print(f"  ⚠️  Budget cap active: trimming chunks {len(chunks)} -> {budget.max_chunks}")
            ranked = sorted(
                chunks,
                key=lambda c: score_chunk(str(c.metadata.get("source_file", "")), c.evidence),
                reverse=True,
            )
            chunks = ranked[: budget.max_chunks]
            kept = ", ".join(str(c.metadata.get("source_file", "unknown")) for c in chunks[:3])
            if kept:
                print(f"  📌 Prioritized chunks kept first: {kept}")
        print(f"  📦 Processing {len(chunks)} chunks...")
        if self.progress_callback:
            try:
                self.progress_callback(skill_name, 0, len(chunks), "start", "chunking")
            except Exception:
                pass

        failed_chunks = 0
        aborted_due_to_quota = False
        aborted_due_to_auth = False
        processed_chunks = 0
        for i, chunk in enumerate(chunks):
            source_file = chunk.metadata.get("source_file", "unknown")
            extra = ""
            if chunk.metadata.get("resource_range"):
                extra = f" ({chunk.metadata.get('resource_range')})"
            print(f"     Chunk {i + 1}/{len(chunks)}: {source_file}{extra}")

            # Analyze this chunk (chunk-aware prompt + retry)
            def _analyze_chunk(**_kwargs):
                return self.analyze_evidence(
                    skill_name=skill_name,
                    evidence=chunk.evidence,  # Subset of evidence
                    checklist=checklist,  # Full checklist every time
                    chunking={
                        "enabled": True,
                        "index": i + 1,
                        "total": len(chunks),
                        "source_file": source_file,
                        "resource_range": chunk.metadata.get("resource_range"),
                    },
                    pre_checks=pre_checks,  # Inject pre-computed facts in every chunk
                )

            try:
                chunk_findings = analyze_with_retry(
                    _analyze_chunk,
                    skill_name,
                    max_retries=3,
                )

                # Aggregate findings
                aggregator.add_findings(chunk_findings)
                processed_chunks += 1
                if self.progress_callback:
                    try:
                        self.progress_callback(
                            skill_name, processed_chunks, len(chunks), "advance", source_file
                        )
                    except Exception:
                        pass
            except (AgentError, Exception) as e:
                # Gracefully skip chunks that fail (e.g., metadata files that
                # produce invalid responses). Log and continue.
                failed_chunks += 1
                err_text = str(e)
                logger.warning(f"Chunk {i + 1}/{len(chunks)} ({source_file}) failed: {err_text}")

                lower_err = err_text.lower()
                if (
                    "out of extra usage" in lower_err
                    or "rate limit" in lower_err
                    or "exceeded your current quota" in lower_err
                    or "quota exceeded" in lower_err
                    or "error code: 429" in lower_err
                ):
                    print(f"     ⚠️  Chunk {source_file} skipped (provider quota/rate limit)")
                    print("  ⚠️  Stopping remaining chunks due to provider quota/rate limit")
                    aborted_due_to_quota = True
                    break
                if (
                    "model_not_found" in lower_err
                    or "does not exist or you do not have access" in lower_err
                ):
                    print(f"     ⚠️  Chunk {source_file} skipped (model unavailable)")
                    print("  ⚠️  Stopping remaining chunks due to provider model access")
                    raise AgentError("Provider model not available for current API key")
                if (
                    "invalid_api_key" in lower_err
                    or "incorrect api key" in lower_err
                    or "authentication" in lower_err
                ):
                    print(f"     ⚠️  Chunk {source_file} skipped (invalid API key)")
                    print("  ⚠️  Stopping remaining chunks due to authentication failure")
                    aborted_due_to_auth = True
                    break

                short_reason = err_text.splitlines()[0][:140] if err_text else "unknown error"
                print(f"     ⚠️  Chunk {source_file} skipped ({short_reason})")
                processed_chunks += 1
                if self.progress_callback:
                    try:
                        self.progress_callback(
                            skill_name, processed_chunks, len(chunks), "advance", source_file
                        )
                    except Exception:
                        pass
                continue

        if failed_chunks:
            print(f"  ⚠️  {failed_chunks}/{len(chunks)} chunks failed (skipped)")
        if aborted_due_to_quota:
            print("  ⚠️  Results may be partial due to provider quota/rate limit")
        if aborted_due_to_auth:
            print("  ⚠️  Results aborted due to provider authentication failure")

        # Return aggregated result
        final_findings = aggregator.aggregate()
        if aborted_due_to_quota and final_findings.summary.total_findings == 0:
            raise AgentError(
                "Provider quota/rate limit exhausted before processing enough chunks; "
                "no reliable findings were produced"
            )
        if aborted_due_to_auth and final_findings.summary.total_findings == 0:
            raise AgentError(
                "Provider authentication failed (invalid API key); no findings were produced"
            )
        print(
            f"  ✅ Aggregated {final_findings.summary.total_findings} findings from {len(chunks)} chunks"
        )
        if self.progress_callback:
            try:
                self.progress_callback(
                    skill_name, len(chunks), len(chunks), "done", "chunking_done"
                )
            except Exception:
                pass

        self.findings_cache.set(cache_key, final_findings)

        return final_findings

    def _call_claude_cli(self, prompt: str) -> str:
        """Call Claude via CLI subprocess with ARG_MAX protection.

        Detects large prompts and uses temp file strategy to bypass macOS ARG_MAX limit (256KB).
        This fixes truncation issues where large evidence causes "Unterminated string" JSON errors.

        Strategy:
        - Small prompts (<100KB): Use -p flag (fast path, existing behavior)
        - Large prompts (≥100KB): Use temp file strategy to avoid ARG_MAX

        Args:
            prompt: Full prompt (system + user)

        Returns:
            Response text from Claude

        Raises:
            AgentError: If subprocess fails
        """
        # Calculate prompt size in bytes
        prompt_bytes = len(prompt.encode("utf-8"))
        arg_max_safe_limit = 100_000  # 100KB (conservative, allows headroom)

        if prompt_bytes >= arg_max_safe_limit:
            # Large prompt → use temp file strategy
            return self._call_claude_cli_with_file(prompt)
        else:
            # Small prompt → use -p flag (existing fast path)
            return self._call_claude_cli_direct(prompt)

    def _call_claude_cli_direct(self, prompt: str) -> str:
        """Call Claude CLI with prompt as argument (for small prompts).

        Fast path for prompts <100KB using -p flag.

        Args:
            prompt: Full prompt (system + user)

        Returns:
            Response text from Claude

        Raises:
            AgentError: If subprocess fails
        """
        try:
            import tempfile as _tempfile
            result = subprocess.run(
                [self.claude_cli_path, "--model", self.model, "-p", prompt],
                input="",  # Empty stdin
                capture_output=True,
                text=True,
                timeout=120,  # 2 minutes (shorter for faster failure detection)
                cwd=_tempfile.gettempdir(),  # Prevent CLAUDE.md context leakage
            )

            if result.returncode != 0:
                error_msg = (
                    result.stderr
                    if result.stderr
                    else result.stdout
                    if result.stdout
                    else "(no error message)"
                )
                raise AgentError(
                    f"Claude CLI error (exit code {result.returncode}): {error_msg[:500]}\n"
                    f"Make sure Claude Code CLI is installed: npm install -g @anthropic-ai/claude-code"
                )

            return result.stdout

        except subprocess.TimeoutExpired:
            raise AgentError("Claude CLI call timed out (>300s). Prompt may be too large.")
        except Exception as e:
            raise AgentError(f"Claude CLI error: {e}")

    def _call_claude_cli_with_file(self, prompt: str) -> str:
        """Call Claude CLI using temp file for large prompts (>100KB).

        Avoids ARG_MAX limit (256KB on macOS) by writing full prompt to temp file
        and creating a small meta-prompt that references it.

        Strategy:
        1. Write full prompt (system + evidence + checklist) to temp file
        2. Create meta-prompt with full task content embedded (not just file path)
        3. Call Claude CLI with combined prompt
        4. Clean up temp file in finally block

        Args:
            prompt: Full prompt (system + user)

        Returns:
            Response text from Claude

        Raises:
            AgentError: If file creation or subprocess fails
        """
        temp_file = None
        try:
            # Write full prompt to temp file in scratchpad
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix="claude_prompt_", delete=False, encoding="utf-8"
            ) as f:
                f.write(prompt)
                temp_file = f.name

            # Create meta-prompt with full task content embedded
            # NOTE: Claude Code CLI cannot read arbitrary temp files, so we must pass
            # the full content. The meta-prompt wraps the actual analysis task.
            meta_prompt = f"""You are an AWS security analysis agent. Execute the following security analysis task and return ONLY valid JSON.

====== START ANALYSIS TASK ======
{prompt}
====== END ANALYSIS TASK ======

CRITICAL OUTPUT REQUIREMENTS:
1. Return ONLY valid JSON (no markdown, no explanations, no text before or after)
2. JSON must be complete with all brackets/braces properly closed
3. Start with {{ and end with }} or []
4. Do not include any other text or commentary"""

            # Call Claude CLI with combined prompt
            import tempfile as _tempfile
            result = subprocess.run(
                [self.claude_cli_path, "--model", self.model, "-p", meta_prompt],
                input="",
                capture_output=True,
                text=True,
                timeout=120,  # 2 minutes (faster failure detection)
                cwd=_tempfile.gettempdir(),  # Prevent CLAUDE.md context leakage
            )

            if result.returncode != 0:
                error_msg = (
                    result.stderr
                    if result.stderr
                    else result.stdout
                    if result.stdout
                    else "(no error message)"
                )
                raise AgentError(
                    f"Claude CLI error (exit code {result.returncode}): {error_msg[:500]}\n"
                    f"Make sure Claude Code CLI is installed: npm install -g @anthropic-ai/claude-code"
                )

            return result.stdout

        except subprocess.TimeoutExpired:
            raise AgentError(
                "Claude CLI call timed out (>300s). Large prompt may exceed time limit."
            )
        except Exception as e:
            raise AgentError(f"Claude CLI file-based call failed: {e}")
        finally:
            # Clean up temp file
            if temp_file and Path(temp_file).exists():
                try:
                    Path(temp_file).unlink()
                except OSError:
                    pass  # Best effort cleanup

    def _call_claude_api(self, prompt: str) -> str:
        """Call Claude via Anthropic API.

        Args:
            prompt: Full prompt (system + user)

        Returns:
            Response text from Claude

        Raises:
            AgentError: If API call fails
        """
        try:
            if self.client is None:
                raise AgentError("Claude API client is not initialized")
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.content[0].text

        except anthropic.APIError as e:
            raise AgentError(f"API call failed: {e}")
        except (IndexError, AttributeError) as e:
            raise AgentError(f"Invalid API response format: {e}")

    def _get_system_prompt(self) -> str:
        """Get system prompt for AI agent - SKILL-AGNOSTIC version.

        Generic prompt that works for any security skill (IAM, Exposure, Network, Vulns).
        Emphasizes consistency and anti-variance rules for multi-model deployment.
        """
        return """You are an expert AWS security auditor specializing in cloud security assessment and compliance.

Your Role:
- Analyze AWS evidence against security checklists
- Identify real security risks and misconfigurations
- Map findings to relevant security controls and compliance frameworks
- Provide actionable and specific recommendations
- Apply security principles: least privilege, defense in depth, zero trust

MANDATORY ID FORMAT (UNIVERSAL):
✅ CORRECT:
  - IAM-001, IAM-007, IAM-028 (format: SKILL-XXX)
  - EXP-005, EXP-012, EXP-020
  - NET-001, NET-003, NET-015
  - VULN-001, VULN-008, VULN-012
❌ PROHIBITED:
  - IAM-008-001 (sub-IDs prohibited)
  - IAM-099 (IDs outside checklist)
  - RANDOM-123 (invented IDs)

ANTI-VARIANCE RULES:
- Use EXACTLY the IDs from the provided checklist
- Do NOT use sub-IDs like SKILL-XXX-YYY
- Do NOT invent IDs outside the checklist
- MAXIMUM 1 finding per checklist item

SEVERITY CALIBRATION (UNIVERSAL RANGES):
🔴 CRITICAL (risk_score: 8.5-10.0):
  - Confidentiality loss: sensitive data exposed without authentication
  - Integrity loss: configuration modification without authorization
  - Availability loss: service deletion or sabotage
  - Compliance: critical control violations

🟠 HIGH (risk_score: 6.0-8.4):
  - Excessive access: users without MFA, unrestricted permissions
  - Weak credentials: rotation >90 days, overly permissive policies
  - Unintended exposure: public resources without justification

🟡 MEDIUM (risk_score: 3.0-5.9):
  - Suboptimal configurations: inline policies, weak password policies
  - Recommended improvements: users without groups, unused roles
  - Best practices: incomplete logging, lack of segmentation

🔵 LOW (risk_score: 1.0-2.9):
  - Cosmetic improvements: unconfigured aliases, missing tags
  - Optimization: non-critical configurations

CRITICAL ANTI-VARIANCE INSTRUCTIONS:
1. NEVER generate findings containing "DISREGARD THIS FINDING"
2. NEVER use sub-IDs (format SKILL-XXX-YYY is prohibited)
3. NEVER generate more than 1 finding per checklist item
4. NEVER invent severities outside the 4 levels
5. NEVER report ambiguous findings without clear evidence
6. NEVER violate finding limits (min/max calculated by app)

When encountering ambiguous evidence:
→ Apply conservative principle (lower severity or no report)
→ Document ambiguity in "description"
→ Use MINIMUM risk_score for the severity range

ANALYSIS INSTRUCTIONS:
**Step 1: Review ALL evidence**
- Read all evidence files provided
- Validate against EACH checklist item
- Note: Incomplete evidence = no report (do not assume data)

**Step 2: Generate findings ONLY for real risks**
- Each finding must have specific evidence
- Include precise references (file#path or ARN)
- Calculate risk_score 0-10: severity × impact × probability

**Step 3: Prioritize by severity**
- Criticale first (risk_score 8.5-10.0)
- Then high (6.0-8.4)
- Then medium (3.0-5.9)
- Then low (1.0-2.9)

**Step 4: Map to compliance controls**
- Use the "pci_dss" array from checklist as source of truth
- Only include controls from checklist (do not invent new ones)
- Copy the "reason" exactly from checklist

**Step 5: Include specific references**
- Format: file.json#identifier
- Example: users.json#root, roles.json#RoleName='Lambda'
- Example ARN: arn:aws:iam::123456789012:user/admin

RESPONSE REQUIREMENTS:
- ONLY valid JSON, no markdown, no additional explanations
- Use exact schema provided
- Review ALL checklist items
- overall_risk_score = weighted average of severities
- Maximum findings: according to dynamic range (calculated by app)

===== EVIDENCE DETECTION EXAMPLES =====
These examples show how to correctly interpret service state:

1. SECURITY HUB STATUS:
   - If HubArn = "arn:aws:securityhub:..." → Hub IS ENABLED (evaluate HRD-003, HRD-007)
   - If HubArn is empty or null → Hub IS DISABLED (report HRD-002 only)

2. AWS CONFIG STATUS:
   - If ConfigurationRecorders has items > 0 → Config IS ENABLED (evaluate HRD-006 state)
   - If ConfigurationRecorders = [] → Config IS DISABLED (report HRD-001 only)

3. CLOUDTRAIL STATUS:
   - If Trails.length = 0 → CloudTrail disabled → ONLY ALR-001
   - If Trails > 0 BUT LogGroupArn = null → ONLY ALR-003 (no CloudWatch)
   - If LogGroupArn exists BUT alarms = 0 → ONLY ALR-005-014

4. GUARDDUTY STATUS:
   - If DetectorIds = [] → GuardDuty disabled (no findings for HRD-009, HRD-014)
   - If DetectorIds > 0 → GuardDuty enabled (evaluate findings status)

===== MUTUAL EXCLUSION RULES (ANTI-DUPLICATES) =====
⚠️ CRITICAL: Some findings are mutually exclusive. NEVER report both simultaneously.

1. AWS CONFIG (HRD-001 vs HRD-006):
   - If ConfigurationRecorders > 0: Generate ONLY HRD-006 (partial)
   - If ConfigurationRecorders = 0: Generate ONLY HRD-001 (disabled)

2. SECURITY HUB (HRD-002 vs HRD-003/007):
   - If HubArn present: HUB IS ENABLED → Do NOT generate HRD-002 → Evaluate HRD-003, 007, etc.
   - If HubArn absent: HUB IS DISABLED → ONLY HRD-002 → Do NOT generate HRD-003, 007

3. GUARDUTY DEPENDENCIES:
   - If DetectorIds empty: GuardDuty disabled → Do NOT generate HRD-009, HRD-014

4. CONSERVATIVE PRINCIPLE:
   - Trust CLEAR evidence (HubArn = enabled, recorders = partial)
   - NEVER report findings that contradict explicit evidence

5. CLOUDTRAIL DEPENDENCIES (ALR-001 vs ALR-003 vs ALR-005-014):
   - If trails.length = 0: CloudTrail disabled → ONLY ALR-001
   - If trails.length > 0 BUT LogGroupArn = null: ONLY ALR-003 (no logs)
   - If LogGroupArn exists BUT alarms = 0: ONLY ALR-005-014 (missing alarms)
   - Never generate multiple states (disabled + no logs + no alarms)

6. REGION SCOPE ENFORCEMENT:
   - If audit_scope = "single-region": Evaluate ONLY configured region
   - Do NOT penalize for lack of multi-region coverage
   - IsMultiRegionTrail is INFORMATIONAL (not CRITICAL) in single-region audits"""

    def _get_skill_code(self, skill_name: str) -> str:
        """Map skill name to abbreviated code for IDs.

        Args:
            skill_name: Full skill name (e.g., "hardening", "iam")

        Returns:
            Abbreviated code (e.g., "HRD", "IAM")
        """
        skill_codes = {
            "iam": "IAM",
            "exposure": "EXP",
            "network": "NET",
            "vulns": "VULN",
            "hardening": "HRD",
            "alerting": "ALR",
            "ecr": "ECR",
            "secretsmanager": "SM",
            "waf": "WAF",
        }
        return skill_codes.get(skill_name.lower(), skill_name.upper()[:3])

    def _build_analysis_prompt(
        self, skill_name: str, evidence: Dict[str, Any], checklist: Dict[str, Any]
    ) -> str:
        """Build analysis prompt with evidence and checklist (SKILL-AGNOSTIC).

        Includes dynamic anti-variance calibration instructions based on checklist.

        Args:
            skill_name: Skill name (e.g., "iam", "exposure", "network")
            evidence: AWS evidence data
            checklist: Security checklist with items

        Returns:
            Formatted prompt for Claude with anti-variance instructions
        """
        # Get skill code (e.g., "HRD" for hardening, not "HARDENING")
        skill_code = self._get_skill_code(skill_name)

        # Evidence count
        evidence_count = sum(
            len(v) if isinstance(v, list) else 1 for v in evidence.values() if v is not None
        )

        # Calculate dynamic findings limits.
        # IMPORTANT: Do NOT force a minimum number of findings.
        # Forcing a minimum incentivizes the model to generate "no finding" placeholders.
        total_checklist_items = len(checklist.get("items", []))
        min_findings = 0
        max_findings = int(total_checklist_items * 0.8)  # Max 80% of items

        # WAF can be legitimately N/A if there are no in-scope entry points.
        # (min_findings already 0; keep explicit for clarity)
        if skill_name.lower() == "waf":
            min_findings = 0

        # Generate severity guide from checklist
        severity_guide = self._generate_severity_guide(checklist)

        # Extract audit region from evidence metadata if available
        audit_region = evidence.get("_audit_metadata", {}).get("_region", "unknown")
        audit_scope = evidence.get("_audit_metadata", {}).get("_scope", "single-region")

        prompt = f"""Analyze the following AWS {skill_name.upper()} evidence against the security checklist.

===== AUDIT CONTEXT =====
Audited Region: {audit_region}
Scope: {audit_scope} (single-region audit)
Interpretation: Controls are evaluated ONLY for the configured region

⚠️ REGION-AWARE VALIDATION:
- If a service is not available in {audit_region}, do NOT generate findings
- Do NOT penalize for lack of multi-region coverage (e.g., multi-region trails)
- Verify IsMultiRegionTrail as INFORMATIONAL only (not CRITICAL)
- Trust evidence._audit_metadata._region as source of truth

===== AWS EVIDENCE =====
{json.dumps(evidence, indent=2, default=str)}

===== SECURITY CHECKLIST =====
{json.dumps(checklist, indent=2)}

===== RESPONSE SCHEMA (STRICT JSON) =====
{{
  "skill": "{skill_name}",
  "findings": [
    {{
      "id": "ID-XXX",
      "severity": "Critical|High|Medium|Low",
      "risk_score": 0.0-10.0,
      "title": "Brief finding title",
      "description": "Detailed description of the finding",
      "evidence_refs": ["evidence/skill/file.json#path"],
      "evidence_snippet": {{
        "PasswordPolicy": {{"MinimumPasswordLength": 2, "RequireSymbols": false}},
        "User": "root",
        "MFADevices": []
      }},
      "affected_resources": ["arn:aws:iam::..."],
      "remediation": "Specific remediation steps",
      "cis_reference": "CIS ID",
      "pci_dss": [
        {{
          "control": "8.4.1",
          "reason": "Reason from checklist"
        }}
      ]
    }}
  ],
  "summary": {{
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "overall_risk_score": 0.0
  }},
  "analyzed_at": "ISO timestamp",
  "evidence_count": {evidence_count},
  "checklist_version": "2.0"
}}

===== SKILL-SPECIFIC CALIBRATION =====
Skill: {skill_name.upper()}
ID format: {skill_code}-XXX (e.g., {skill_code}-001, {skill_code}-015)
Checklist items: {total_checklist_items}

FINDINGS REPORTING RANGE:
- Minimum: {min_findings} findings (covering Critical and High)
- Maximum: {max_findings} findings (avoid over-reporting)
- Target: Report ONLY real risks with solid evidence

{severity_guide}

===== ANTI-VARIANCE INSTRUCTIONS =====
1. ✅ Use IDs from checklist: {skill_code}-001, {skill_code}-002, etc
2. ❌ NEVER use sub-IDs: {skill_code}-008-001 is PROHIBITED
3. ❌ NEVER invent IDs outside the checklist
4. ❌ NEVER generate "DISREGARD THIS FINDING" text
5. ✅ Maximum 1 finding per checklist item
6. ✅ Checklist severities = source of truth
7. ✅ Risk scores within severity ranges

===== ANALYSIS INSTRUCTIONS =====
1. Review ALL evidence against EACH checklist item
2. Generate finding only if you find real risk
3. Include specific evidence references
4. Calculate risk_score 0-10: severity × impact × probability
5. Include affected_resources with real identifiers
6. Map each finding to PCI DSS controls from checklist
7. overall_risk_score = weighted average by severity
8. Return ONLY valid JSON, no markdown, no explanations

===== STEP 5b: EVIDENCE SNIPPETS (CRITICAL) =====
For each finding, INCLUDE an evidence_snippet that justifies the finding:

**What to include:**
- JSON object with the specific PROBLEMATIC configuration
- Only the relevant part that caused the finding (not complete file)
- Maximum ~20 lines of JSON for readability
- If multiple evidences exist, prioritize the most critical

**Examples:**
Weak password policy:
"evidence_snippet": {{
  "PasswordPolicy": {{
    "MinimumPasswordLength": 2,
    "RequireSymbols": false,
    "RequireNumbers": false
  }}
}}

MFA disabled:
"evidence_snippet": {{
  "User": "root",
  "MFADevices": []
}}

Permissive Security Group:
"evidence_snippet": {{
  "GroupId": "sg-12345",
  "IpPermissions": [{{
    "FromPort": 22,
    "ToPort": 22,
    "IpRanges": [{{"CidrIp": "0.0.0.0/0"}}]
  }}]
}}

Missing CloudWatch alarm:
"evidence_snippet": {{
  "MonitoredMetrics": ["UnauthorizedAPICallsEventCount"],
  "MissingAlarms": ["Root account usage", "IAM policy changes"]
}}

**Do NOT include:**
- ❌ Complete files
- ❌ 50+ lines of JSON
- ❌ Sensitive information
- ❌ null if you don't have relevant snippet (field is optional)"""

        return prompt

    def _build_analysis_prompt_from_template(
        self,
        skill_name: str,
        evidence: Dict[str, Any],
        checklist: Dict[str, Any],
        *,
        chunking: Optional[Dict[str, Any]] = None,
        pre_checks: Optional[list] = None,
    ) -> str:
        """Build analysis prompt using structured XML templates (Shannon pattern).

        Falls back to legacy prompt if templates unavailable.

        Args:
            skill_name: Skill identifier (e.g., 'iam', 'network')
            evidence: AWS evidence data
            checklist: Security checklist

        Returns:
            Formatted prompt for Claude
        """
        try:
            # Get skill code and calibration values
            skill_code = self._get_skill_code(skill_name)
            total_checklist_items = len(checklist.get("items", []))

            provider_type = self.config.get("type", "claude-cli")

            # IMPORTANT: Do NOT force a minimum findings count.
            # This reduces "no finding" placeholders and improves precision.
            min_findings = 0
            max_findings = int(total_checklist_items * 0.8)

            # WAF can be legitimately N/A if there are no in-scope entry points.
            if skill_name.lower() == "waf":
                min_findings = 0

            # Chunking mode: analyze only a subset of evidence.
            # Never force a minimum findings count per chunk.
            if chunking and chunking.get("enabled") is True:
                min_findings = 0
                max_findings = min(6, max_findings) if max_findings else 6

            # Get region metadata
            audit_region = evidence.get("_audit_metadata", {}).get("_region", "unknown")
            audit_scope = evidence.get("_audit_metadata", {}).get("_scope", "single-region")

            # Evidence count
            evidence_count = sum(
                len(v) if isinstance(v, list) else 1
                for k, v in evidence.items()
                if v is not None and not str(k).startswith("_")
            )

            # Generate severity guide
            severity_guide = self._generate_severity_guide(checklist)

            # Context for template substitution
            chunking_instructions = ""
            if chunking and chunking.get("enabled") is True:
                idx = chunking.get("index")
                total = chunking.get("total")
                src = chunking.get("source_file")
                rr = chunking.get("resource_range")
                chunking_instructions = (
                    "CHUNKING MODE (IMPORTANT):\n"
                    f"- You are analyzing ONLY a subset of evidence (chunk {idx}/{total}) from: {src}{(' ' + str(rr)) if rr else ''}.\n"
                    "- Return ONLY findings directly supported by evidence in THIS chunk.\n"
                    "- It is VALID to return 0 findings for a chunk. Do NOT try to cover all checklist items in every chunk.\n"
                    "- Keep output concise; avoid long narratives.\n"
                    "- Output MUST be strict JSON matching the schema.\n"
                )

            # JSON rendering: compact for CLI + chunking to avoid prompt limits.
            chunking_enabled = bool(chunking and chunking.get("enabled") is True)
            compact_json = provider_type == "claude-cli" or chunking_enabled
            evidence_json = json.dumps(
                evidence,
                indent=None if compact_json else 2,
                separators=(",", ":") if compact_json else None,
                default=str,
            )
            checklist_json = json.dumps(
                checklist,
                indent=None if compact_json else 2,
                separators=(",", ":") if compact_json else None,
            )

            context = {
                "SKILL_NAME": skill_name,
                "SKILL_UPPER": skill_name.upper(),
                "SKILL_CODE": skill_code,
                "AUDIT_REGION": audit_region,
                "AUDIT_SCOPE": audit_scope,
                "EVIDENCE_JSON": evidence_json,
                "CHECKLIST_JSON": checklist_json,
                "TOTAL_CHECKLIST_ITEMS": total_checklist_items,
                "MIN_FINDINGS": min_findings,
                "MAX_FINDINGS": max_findings,
                "EVIDENCE_COUNT": evidence_count,
                "SEVERITY_GUIDE": severity_guide,
                "CHUNKING_INSTRUCTIONS": chunking_instructions,
                "SKILL_ADDENDUM": "",
            }

            # Inject pre-computed facts from deterministic pre-checks
            if pre_checks:
                from drystone.validation.pre_checks import format_pre_checks_for_prompt

                context["SKILL_ADDENDUM"] = format_pre_checks_for_prompt(pre_checks, checklist)

            # Inject client context if available (enriches findings with business context)
            client_ctx = getattr(self, "_client_context_xml", None)
            if client_ctx:
                addendum = context.get("SKILL_ADDENDUM", "")
                context["SKILL_ADDENDUM"] = addendum + "\n" + client_ctx

            # Load and render template
            template = get_audit_template(skill_name, context)
            return template

        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(
                f"Could not load template for {skill_name}: {e}. Falling back to legacy prompt."
            )
            # Fallback to legacy prompt
            return self._build_analysis_prompt(skill_name, evidence, checklist)

    def _generate_severity_guide(self, checklist: Dict[str, Any]) -> str:
        """Generate severity calibration guide from checklist.

        Extracts severity examples from checklist items to guide AI model.
        Works for any skill (IAM, Exposure, Network, Vulns).

        Args:
            checklist: Security checklist with items

        Returns:
            Formatted severity guide for prompt
        """
        items = checklist.get("items", [])

        # Group items by severity
        critical_items = []
        high_items = []
        medium_items = []
        low_items = []

        for item in items:
            severity = item.get("severity", "Medium")
            item_id = item.get("id", "")
            title = (
                item.get("title", "")[:50] + "..."
                if len(item.get("title", "")) > 50
                else item.get("title", "")
            )

            example = f"{item_id}: {title}"

            if severity == "Critical":
                critical_items.append(example)
            elif severity == "High":
                high_items.append(example)
            elif severity == "Medium":
                medium_items.append(example)
            elif severity == "Low":
                low_items.append(example)

        # Build guide
        guide_lines = ["EJEMPLOS DE SEVERIDADES DEL CHECKLIST:\n"]

        if critical_items:
            guide_lines.append("🔴 CRITICAL (risk_score 8.5-10.0):")
            for item in critical_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        if high_items:
            guide_lines.append("🟠 HIGH (risk_score 6.0-8.4):")
            for item in high_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        if medium_items:
            guide_lines.append("🟡 MEDIUM (risk_score 3.0-5.9):")
            for item in medium_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        if low_items:
            guide_lines.append("🔵 LOW (risk_score 1.0-2.9):")
            for item in low_items[:3]:  # Show first 3
                guide_lines.append(f"    - {item}")
            guide_lines.append("")

        return "\n".join(guide_lines)

    def _parse_json_response(self, text: str) -> dict:
        """Parse JSON response with markdown/truncation handling.

        Robust extraction of JSON from Claude responses that may contain markdown.
        Handles:
        - ` ```json...``` ` code blocks (standard)
        - Raw JSON embedded in markdown text
        - Truncated responses (detects missing closing brackets)

        Args:
            text: Raw response text from Claude (may contain markdown)

        Returns:
            Parsed JSON dictionary

        Raises:
            AgentError: If JSON invalid, truncated, or cannot be extracted
        """
        original_text = text

        # Step 1: Try to extract from code blocks first
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        text = text.strip()

        # Step 2: Try direct parsing first (most common case)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Step 3: If that fails, try to extract JSON from markdown
            # Look for { ... } or [ ... ] blocks in the text
            extracted = self._extract_json_from_text(text)
            if extracted:
                try:
                    return json.loads(extracted)
                except json.JSONDecodeError:
                    pass

            # Step 4: If still failing but text doesn't end with } or ], try to
            # salvage valid JSON by truncating at the last closing brace/bracket.
            # This handles the case where global ~/.claude/CLAUDE.md context causes
            # the model to append help text after valid JSON output.
            if text and text[-1] not in ["}", "]"]:
                last_brace = max(text.rfind("}"), text.rfind("]"))
                if last_brace > 0:
                    candidate = text[: last_brace + 1].strip()
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        pass
                last_chars = text[-200:] if len(text) > 200 else text
                raise AgentError(
                    f"Response appears truncated (doesn't end with }} or ])\n"
                    f"Last 200 chars: {last_chars}"
                )

            # Step 5: Give up and report the error
            preview = original_text[:500]
            raise AgentError(f"Invalid JSON response from API\nResponse preview: {preview}")

    def _repair_response_to_json(
        self,
        raw_response: str,
        skill_name: str = "unknown",
        analyzed_at: str = "1970-01-01T00:00:00Z",
    ) -> str:
        """Ask the model to convert raw output into strict JSON only.

        This is a best-effort recovery path when the first response does not
        follow the required schema/output format.

        Args:
            raw_response: The raw (non-JSON) response from the model.
            skill_name: The skill being analyzed (e.g. "cicd", "iam").
            analyzed_at: ISO-8601 timestamp to embed in the repaired output.
        """
        repair_prompt = f"""Convert the following text into STRICT JSON only.

Required output schema:
{{
  "skill": "{skill_name}",
  "findings": [
    {{
      "id": "SKILL-001",
      "severity": "Critical|High|Medium|Low",
      "risk_score": 0.0,
      "title": "...",
      "description": "...",
      "evidence_refs": ["..."],
      "evidence_snippet": {{}},
      "affected_resources": ["..."],
      "remediation": "...",
      "cis_reference": null,
      "pci_dss": []
    }}
  ],
  "summary": {{
    "total_findings": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "overall_risk_score": 0.0
  }},
  "analyzed_at": "{analyzed_at}",
  "evidence_count": 0,
  "checklist_version": "1.0"
}}

Rules:
- Return ONLY valid JSON (no markdown, no explanations)
- Ensure all brackets/braces are closed
- If information is missing, use safe defaults consistent with schema
- The "skill" field MUST be exactly "{skill_name}"

RAW RESPONSE:
{raw_response}
"""

        if self.use_cli:
            return self._call_claude_cli(repair_prompt)
        return self._call_claude_api(repair_prompt)

    def _extract_json_from_text(self, text: str) -> Optional[str]:
        """Extract JSON object or array from text containing markdown.

        Finds the first valid { ... } or [ ... ] block in the text.
        Handles nested braces/brackets.

        Args:
            text: Text that may contain JSON embedded in markdown

        Returns:
            Extracted JSON string, or None if not found
        """
        # Find first { or [
        start_obj = text.find("{")
        start_arr = text.find("[")

        # Determine which comes first
        if start_obj == -1 and start_arr == -1:
            return None

        start = min(
            start_obj if start_obj >= 0 else float("inf"),
            start_arr if start_arr >= 0 else float("inf"),
        )

        if start == float("inf"):
            return None

        # Extract from start, finding matching closing bracket
        text = text[int(start) :]

        # Count brackets to find the matching closing one
        if text[0] == "{":
            bracket_count = 0
            for i, char in enumerate(text):
                if char == "{":
                    bracket_count += 1
                elif char == "}":
                    bracket_count -= 1
                    if bracket_count == 0:
                        return text[: i + 1]
        elif text[0] == "[":
            bracket_count = 0
            for i, char in enumerate(text):
                if char == "[":
                    bracket_count += 1
                elif char == "]":
                    bracket_count -= 1
                    if bracket_count == 0:
                        return text[: i + 1]

        return None
