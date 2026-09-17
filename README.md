# Drystone

```text
 ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

[![CI](https://github.com/billycuesta/drystone/actions/workflows/ci.yml/badge.svg)](https://github.com/billycuesta/drystone/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://github.com/astral-sh/ruff)

**AWS Security Audit CLI powered by Claude**

Drystone automates AWS security audits using Claude as the analysis engine. It collects raw evidence from 16 AWS security domains via boto3, applies a 3-tier validation pipeline (240+ deterministic pre-checks → AI analysis → reconciliation), and generates findings mapped to PCI DSS v4.0 and CIS controls. Output includes Markdown, PDF, and JSON reports with MITRE ATT&CK enrichment and cross-skill attack chain correlation.

---

## Architecture

```
Drystone - AWS Security Audit CLI
├── 1. Orchestration & CLI
│   ├── Interactive Wizard (5-step guided setup)
│   ├── Parallel Execution (ThreadPoolExecutor, 4.8x speedup)
│   ├── AWS Credential Validation (STS)
│   └── Session & Audit Trail (append-only JSONL)
├── 2. Skills (16)
│   ├── Identity:    IAM · Recon
│   ├── Network:     Network · Exposure · WAF
│   ├── Data:        Secrets Manager · KMS · ECR
│   ├── Compute:     Compute · CICD · Vulns · Sistemas Explotables
│   └── Operations:  Alerting · Hardening · CloudTrail Events · Messaging
├── 3. 3-Tier Validation
│   ├── Tier 1 — Deterministic Pre-checks (240+ checks, ~0% FP)
│   ├── Tier 2 — Claude AI Analysis (XML-structured prompts)
│   └── Tier 3 — Reconcile & Normalize (dedup, severity calibration)
├── 4. Threat Intelligence
│   ├── TrailDiscover (377 AWS events catalog)
│   ├── MITRE ATT&CK Mapping (auto-enrichment)
│   ├── Correlation Engine (cross-skill attack chains)
│   └── Incident Pattern Detection (selective enrichment)
└── 5. Reports (6 formats)
    ├── General Security  — Markdown + PDF (dark theme)
    ├── PCI DSS           — Control-by-control compliance table
    ├── Pentest Technical — CVSS + ATT&CK + exploitation narrative
    └── JSON              — Machine-readable export
```

---

## Quick Start

```bash
pip install -e ".[dev]"

export ANTHROPIC_API_KEY=sk-ant-...

python -m drystone audit
```

**Non-interactive:** CLI flags override a config that already exists — run the wizard once first (`python -m drystone audit`) to create `~/.drystone/last-run.json`, then re-run with overrides:
```bash
python -m drystone audit --non-interactive

python -m drystone audit --client "ACME" --region us-east-1 --skills iam,network,exposure
```

**Docker:** the wizard's interactive prompts don't fit a container, so bake a saved config into the image (or mount `~/.drystone` from a host run) before invoking `--non-interactive`:
```bash
docker build -t drystone .

docker run --rm \
  -v "$HOME/.drystone:/home/drystone/.drystone" \
  -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... \
  -e ANTHROPIC_API_KEY=... \
  -v "$(pwd)/audit-logs:/data/audit-logs" \
  drystone audit --client "ACME" --region us-east-1 --skills iam \
    --formats markdown --non-interactive
```

---

## Example Run

Drystone is a terminal tool — no GUI to screenshot — so here's an illustrative excerpt of what a run looks like (Rich-formatted banner, live per-skill progress, final summary):

```text
 ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝

📁 Creating audit session...
   Session: audit-logs/ACME_2026-09-17T12-00-00/

🔄 Phase 1/3 Collection: 0/1 skills
🔍 Executing IAM Security Audit...
   ✅ Evidence saved (6 files):
      - users.json (4.2 KB)
      - roles.json (11.8 KB)
      - credential-report.csv (1.1 KB)

🤖 Analyzing evidence with AI...
   ✅ IAM:
      Total: 7 | Critical: 1 | High: 2 | Risk: 6.8/10

✅ QA Gate: PASS (critical coverage 100%, no placeholders)
✅ Audit Complete
   Audit data: audit-logs/ACME_2026-09-17T12-00-00/
```

---

## Skills

| Domain | Skills |
|--------|--------|
| Identity | IAM, Recon |
| Network | Network, Exposure, WAF |
| Data | Secrets Manager, KMS, ECR |
| Compute | Compute, CICD, Vulns, Sistemas Explotables |
| Operations | Alerting, Hardening, CloudTrail Events, Messaging |

---

## Output

```
audit-logs/{client}_{timestamp}/
├── evidence/{skill}/raw.json     # Raw AWS API data
├── findings/{skill}.json         # Structured findings (id, severity, PCI DSS, snippet)
└── reports/
    ├── report-general.md/pdf
    ├── report-pci-dss.md
    ├── report-pentest.md/pdf
    └── report.json
```

---

## Development

```bash
pytest tests/          # Run tests (2200+)
black drystone/        # Format
ruff check drystone/   # Lint
mypy drystone/         # Type check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full dev workflow, code conventions, and how to add a new skill.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Credential validation failed` | Double-check the Access Key ID/Secret; the IAM principal needs at minimum `sts:GetCallerIdentity` plus read access for the skills you selected. |
| No evidence collected for a skill | The IAM principal is missing a required read permission (e.g. `iam:ListUsers`, `ec2:DescribeSecurityGroups`) — Drystone logs a per-service warning instead of failing the whole audit, check `evidence/{skill}/` for what did come through. |
| Agent analysis times out / rate-limited | Reduce `--scan-depth`. The default provider is `claude-api` (set `ANTHROPIC_API_KEY`); if your saved config still points at `claude-cli`, note it runs skills sequentially to stay quota-safe, which is slower for large accounts. |
| `claude: command not found` (using `claude-cli`) | Install the Claude CLI and run `claude /login`, or re-run the wizard (`python -m drystone audit`) and pick the API provider with `ANTHROPIC_API_KEY` set — there's no CLI flag to switch providers non-interactively yet, it's a wizard/saved-config setting. |
| PDF report generation fails | `weasyprint` (the `pdf` extra) needs system libs (Cairo, Pango, GDK-Pixbuf). Install with `pip install -e ".[pdf]"` and see the [Dockerfile](Dockerfile) for the exact system packages on Debian/Ubuntu. |
| `No saved configuration found` with `--non-interactive` | Run the interactive wizard once first (`python -m drystone audit`) to create `~/.drystone/last-run.json`, or pass the full set of CLI flags instead. |

---

## Docs

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Architecture, patterns, how to add skills |
| `CONTRIBUTING.md` | Dev setup, tests, lint, PR workflow |
| `CHANGELOG.md` | Notable changes across sessions |
| `drystone-specs/drystone-architecture.md` | Workflow diagram (source of truth) |
| `drystone-specs/checks_inventory.md` | All checks with PCI DSS mappings |

---

**Stack:** Python 3.9+ · Click · boto3 · Anthropic SDK · Pydantic · Rich
**License:** MIT
