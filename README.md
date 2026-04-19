# Drystone

```text
 ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

**AWS Security Audit CLI powered by Claude**

Drystone automates AWS security audits using Claude as the analysis engine. It collects raw evidence from 15+ AWS services via boto3, applies a 3-tier validation pipeline (deterministic pre-checks → AI analysis → reconciliation), and generates findings mapped to PCI DSS v4.0 and CIS controls. Output includes Markdown, PDF, and JSON reports with MITRE ATT&CK enrichment and cross-skill attack chain correlation.

---

## Architecture

```
Drystone - AWS Security Audit CLI
├── 1. Orchestration & CLI
│   ├── Interactive Wizard (5-step guided setup)
│   ├── Parallel Execution (ThreadPoolExecutor, 4.8x speedup)
│   ├── AWS Credential Validation (STS)
│   └── Session & Audit Trail (append-only JSONL)
├── 2. Skills (15+)
│   ├── Identity:    IAM · Recon
│   ├── Network:     Network · Exposure · WAF
│   ├── Data:        Secrets Manager · KMS · ECR
│   ├── Compute:     Compute · CICD · Vulns · Sistemas Explotables
│   └── Operations:  Alerting · Hardening · CloudTrail Events · Messaging
├── 3. 3-Tier Validation
│   ├── Tier 1 — Deterministic Pre-checks (69+ checks, 0% FP)
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

**Non-interactive:**
```bash
python -m drystone audit --non-interactive

python -m drystone audit --client "ACME" --region us-east-1 --skills iam,network,exposure
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
pytest tests/          # Run tests (1900+)
black drystone/        # Format
ruff check drystone/   # Lint
mypy drystone/         # Type check
```

---

## Docs

| File | Purpose |
|------|---------|
| `CLAUDE.md` | Architecture, patterns, how to add skills |
| `drystone-specs/drystone-architecture.md` | Workflow diagram (source of truth) |
| `drystone-specs/checks_inventory.md` | All checks with PCI DSS mappings |

---

**Stack:** Python 3.9+ · Click · boto3 · Anthropic SDK · Pydantic · Rich
**Status:** Production Ready · Last updated: 2026-04-18
