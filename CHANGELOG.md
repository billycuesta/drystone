# Changelog

Notable changes to Drystone. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Drystone hasn't cut a versioned release yet (`pyproject.toml` has stayed at `0.1.0` through active development) — this file starts documenting from the current `[Unreleased]` state rather than reconstructing a version history that doesn't exist. For change-by-change detail, `git log` is authoritative; `CLAUDE.md`'s "Session History" section has narrative context for major sessions.

## [Unreleased]

### Added
- 16 audit skills across identity, network, data, compute, and operations domains, auto-discovered via a skill registry (no manual wiring needed to add one — see `CONTRIBUTING.md`).
- 3-tier validation pipeline: 240+ deterministic pre-checks (Tier 1) → Claude analysis (Tier 2) → reconciliation/normalization (Tier 3).
- Cross-skill correlation engine mapping findings into multi-stage attack chains, with MITRE ATT&CK and TrailDiscover (CloudTrail threat-intel) enrichment.
- Active verification pilot: real, non-destructive AWS API calls (`sts:AssumeRole`, unauthenticated S3 HEAD/List) to confirm specific findings are actually exploitable, not just inferred — opt-out via `--no-active-verification`.
- Evidence chain-of-custody: SHA-256 manifest over every evidence/findings file, checkable via `drystone verify-integrity`.
- Report formats: Markdown, PDF (with client/firm logo and accent-color whitelabeling), PCI DSS v4.0 compliance tables, a dedicated pentest technical report (CVSS + exploitation narrative + blast radius), and JSON export — each carrying a `report_format_version` for downstream consumers.
- `drystone/core/audit_runner.py`: the audit pipeline (collection → analysis → correlation → reporting → QA gate) as an importable, Click-free function, so it can be driven programmatically rather than only from the CLI.
- Prompt-injection hardening: evidence is sanitized before interpolation into LLM prompts, since resource names/tags/policy text come from the audited account and are attacker-controllable in a compromise scenario.
- Native AWS AssumeRole/STS support for temporary and cross-account credentials.
- `scripts/prowler_gap_analysis.py`: cross-validates Drystone's check coverage against Prowler's public AWS check catalog and CIS AWS Foundations mapping (no `prowler-cloud` install needed).
- `Dockerfile` for a reproducible, non-editable-install distribution image.

### Changed
- Default AI provider is now `claude-api` (was the interactive `claude` CLI) — a better fit for unattended/scheduled runs; `claude-cli` remains available as an explicit opt-in.
- `pyproject.toml` packaging switched from a static `packages = ["drystone"]` list to `[tool.setuptools.packages.find]` auto-discovery, fixing a real bug where a non-editable install silently dropped every subpackage.

### Fixed
- A race condition in `AgentClient.last_analysis_status` that could corrupt confidence scoring under concurrent skill analysis.
- Documentation drift between the actual check/skill counts (240 checks, 16 skills) and what older docs claimed (69 checks, 13 skills).
- `CorrelationEngine` now actually enforces its total-correlation cap and surfaces a visible truncation warning in reports, instead of silently dropping attack chains past the cap.

### Security
- Evidence chain-of-custody hashing (see Added) makes post-audit tampering with evidence/findings detectable.
- Prompt-injection defenses on the evidence fed into LLM analysis (see Added).
