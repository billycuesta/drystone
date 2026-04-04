# Drystone - AWS Security Audit CLI

Developer guide for working with Drystone using Claude Code.

## What is Drystone

CLI for AWS security audits. Similar to Shannon but for compliance/security (not active pentesting).

**Core principle:** App orchestrates, agent analyzes.

## Technology Stack

- **Python 3.9+** - Modern, fast iteration for MVP
- **Click** - CLI framework with intuitive command structure
- **Questionary** - Interactive prompts and wizard UI
- **Rich** - Beautiful terminal formatting and tables
- **boto3** - AWS SDK for data collection
- **Pydantic** - Type-safe data models and validation
- **Anthropic SDK** - Claude API integration
- **Modular skills:** IAM, Exposure, Network, Vulns, Alerting, Hardening, Secrets Manager, WAF, ECR
- **YAML workflows:** Define skill execution order and configuration
- **Claude API:** For evidence analysis and finding generation

## Documentation & Specs

All architecture documents, inventories, plans, and generated specs go in `drystone-specs/`.

**Current contents:**
- `drystone-architecture.md` - Workflow diagram, 3-tier validation architecture, and module overview
- `checks_inventory.md` - Exhaustive check inventory with PCI DSS mappings
- `PROJECT_PLAN.md` - Project plan and roadmap

**Rule:** Any new or updated documentation of this type MUST be placed in `drystone-specs/`.

## Project Structure

```
drystone/
├── cli/
│   ├── main.py                 - Click CLI entry point
│   ├── config.py               - Configuration management
│   └── ui/
│       ├── branding.py         - ASCII banner and UI components
│       └── wizard.py           - Interactive 5-step wizard
├── models/
│   ├── config.py               - WizardConfig (Pydantic)
│   ├── evidence.py             - IAM evidence models
│   └── __init__.py
├── cloud/
│   ├── aws/
│   │   ├── client.py           - AWS credential validation
│   │   └── __init__.py
│   └── __init__.py
├── skills/
│   ├── iam/
│   │   ├── collector.py        - TODO: IAM data collection
│   │   ├── analyzer.py         - TODO: Claude analysis
│   │   └── checklist.json      - TODO: Security checklist
│   └── __init__.py
├── storage/
│   ├── manager.py              - TODO: Evidence persistence
│   └── __init__.py
├── __main__.py                 - Entry for `python -m drystone`
└── __init__.py
```

## Execution Flow

1. User: `python -m drystone audit`
2. Phase 0: Interactive wizard (5 steps)
   - Client name
   - Direct AWS credentials (Access Key ID + Secret Access Key)
   - AWS region
   - Skills selection (IAM, Exposure, Network, Vulns, Alerting, Hardening, Secrets Manager, WAF, ECR)
   - Output formats (markdown, HTML, JSON)
3. Phase 1: AWS credential validation (boto3 STS)
4. Phase 1a: Data collection for each skill
   - **Collector** calls AWS APIs → saves raw evidence JSON
   - Evidence stored in Pydantic models
5. Phase 1b: Agent analysis
   - **Analyzer** sends evidence + checklist to Claude
   - Claude returns findings JSON
6. Phase 2: Cross-skill correlation and risk scoring
7. Phase 3: Report generation (HTML, Markdown, JSON)
8. Phase 4: Session logging and audit trail

## How to Add a Skill

1. Create directory `drystone/skills/{name}/`
2. Implement collector:
   ```python
   # drystone/skills/network/collector.py
   from drystone.models import Evidence
   import boto3

   class NetworkCollector:
       def __init__(self, client_config):
           self.ec2 = boto3.client('ec2', **client_config)

       def collect(self) -> Evidence:
           """Collect network evidence from AWS."""
           vpcs = self.ec2.describe_vpcs()
           security_groups = self.ec2.describe_security_groups()
           return Evidence(
               skill='network',
               data={
                   'vpcs': vpcs['Vpcs'],
                   'security_groups': security_groups['SecurityGroups']
               }
           )
   ```
3. Implement analyzer:
   ```python
   # drystone/skills/network/analyzer.py
   from anthropic import Anthropic

   class NetworkAnalyzer:
       def analyze(self, evidence: Evidence, agent: Anthropic) -> list:
           """Analyze evidence with Claude."""
           prompt = f"Analyze network security: {evidence.json()}"
           return agent.analyze(prompt)
   ```
4. Create checklist JSON:
   ```json
   // drystone/skills/network/checklist.json
   {
       "skill": "network",
       "items": [
           {
               "id": "NET-001",
               "title": "Restrict SSH access",
               "severity": "Critical"
           }
       ]
   }
   ```
5. Register the skill in the CLI + wizard:
   - `drystone/models/config.py` (`WizardConfig.validate_skills`)
   - `drystone/cli/ui/wizard.py` (skills checkbox list)
   - `drystone/cli/main.py` (`skills_map` for dynamic imports, and click `--skills` choices)
   - `scripts/e2e_test_runner.py` (`SKILLS_ALL` matrix)
   - Optional but recommended: add `drystone/prompts/templates/{skill}_audit.xml` to tighten evidence expectations

## Development Setup

```bash
# Clone and setup
git clone <repo>
cd drystone
pip install -e ".[dev]"

# Run interactive audit
python -m drystone audit

# Run with CLI args
python -m drystone audit --client "ACME" --region us-east-1

# Non-interactive (reuse last config)
python -m drystone audit --non-interactive

# View audit sessions
ls audit-logs/

# Format code
black drystone/

# Lint
ruff check drystone/

# Type check
mypy drystone/

# Run tests
pytest tests/
```

## E2E Testing (Pre-Release)

Use the E2E runner to execute Drystone end-to-end across combinations of skills, report types, and formats.

Script:
- `scripts/e2e_test_runner.py`

Examples:

```bash
# Dry run (prints the plan only)
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --dry-run

# IAM only (4 combinations: 2 report types x 2 formats)
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --skills iam

# Full single-skill matrix (24 combinations)
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json

# Include multi-skill pairs (adds 60 combinations)
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --multi-skill
```

Notes:
- Credentials file format is documented in `scripts/README.md`.
- The runner uses an isolated `HOME` per test to avoid mutating your real `~/.drystone` config.
- Prefer `--parallel 1-3` to reduce AWS throttling.
- If using `claude-cli`, ensure it's authenticated (`claude /login`) or use `--ai-provider claude-api` with `ANTHROPIC_API_KEY`.

## ⚠️ Important: Virtual Environment

**NEVER delete `drystone_env/` during any cleanup or maintenance operations.**

The virtual environment (`drystone_env/`) is critical for project functionality and contains all installed dependencies. It should be preserved through:
- Cleanup operations
- Git operations
- Documentation updates
- Any other project maintenance

**What CAN be safely deleted:**
- `audit-logs/` - Test/validation sessions (regenerated on next audit)
- `__pycache__/` - Python bytecode cache
- `.pytest_cache/` - Pytest cache
- `.egg-info/` - pip metadata (regenerated with `pip install`)
- Old virtual environments (e.g., `venv_py314/`, `venv_py39/`)
- Obsolete documentation files
- Test output directories

**What should NEVER be deleted:**
- `drystone_env/` - **Active virtual environment**
- `drystone/` - Source code
- `.git/` - Repository
- `tests/` - Test suite
- `scripts/` - Utility scripts

## Code Conventions

- **Evidence:** Always collect raw AWS API data before analysis; use Pydantic models
- **Findings:** Structured JSON with severity, risk_score, remediation, and evidence references
- **Checklists:** JSON with CIS/NIST framework items; one per skill
- **Models:** Pydantic BaseModel for all data structures with type hints
- **Error Handling:** Catch boto3 ClientError, return meaningful error messages
- **Logging:** Use Python logging with structured formatters
- **Credentials:** Never log credentials; always mask in UI

## Planning and Execution

### Creating Implementation Plans

**IMPORTANT:** Whenever you create an implementation plan for Drystone, you MUST:

1. **Create plan in Claude Code plan mode**
   - Use `/plan` command to enter plan mode
   - Build incrementally by editing the plan file
   - Use Phase 1 (Explore) → Phase 2 (Design) → Phase 3 (Review) → Phase 4 (Final Plan) → Phase 5 (ExitPlanMode)

2. **Copy completed plan to project repository**
   - After ExitPlanMode approval, copy the plan to the project root directory
   - **Naming convention:** `PLAN_<FEATURE>_<DATE_OR_SCOPE>.md`
   - **Examples:**
     - `PLAN_PENTEST_IMPROVEMENTS_HACKTRICKS.md`
     - `PLAN_SEVERITY_FILTERING.md`
     - `PLAN_FINDINGS_FIX.md`
   - **Command:** `cp /Users/gcuesta/.claude/plans/<plan-id>.md /Users/gcuesta/Projects/drystone/PLAN_<NAME>.md`

3. **Plan contents must include**
   - Context: Why is this plan needed?
   - Gaps analysis: What are we fixing?
   - Prioritization: P0, P1, P2, P3 phases
   - Implementation details: Code, tests, verification
   - Timeline and effort estimates
   - Coverage/metrics before and after
   - Files to be modified (with paths)

4. **Execution handoff**
   - Plans are stored in project root for other agents to execute
   - Reference the plan file explicitly when delegating work
   - Include plan metrics in commit messages

### Why This Matters

- **Traceability:** Plans in project root are part of version control and audit trail
- **Collaboration:** Other agents can reference completed plans for context
- **Documentation:** Future sessions can review planning decisions and trade-offs
- **Continuity:** Plans bridge planning (Claude Code) to execution (implementation agent)

## Claude API Integration

```python
# Prompt structure for Claude analysis
from anthropic import Anthropic
import json

client = Anthropic()

def analyze_iam_evidence(evidence: dict, checklist: dict) -> dict:
    """Pass evidence and checklist to Claude for security analysis."""

    prompt = f"""You are an AWS security auditor. Analyze the following evidence:

EVIDENCE:
{json.dumps(evidence, indent=2)}

CHECKLIST:
{json.dumps(checklist, indent=2)}

Return findings as JSON:
{{
  "findings": [
    {{
      "id": "IAM-001",
      "severity": "Critical",
      "risk_score": 9.5,
      "title": "Root account has active access keys",
      "remediation": "Delete root access keys, use IAM users instead",
      "evidence_refs": ["users[0].access_keys[0]"]
    }}
  ],
  "skill_risk_score": 7.5,
  "summary": "3 critical findings, 2 medium"
}}
"""

    response = client.messages.create(
        model="claude-opus-4-5-20251101",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}]
    )

    return json.loads(response.content[0].text)
```

**Critical:** Agent ONLY analyzes evidence, does NOT make orchestration decisions. App controls workflow.

## App vs Agent Architecture

### Separation of Concerns

```
App (Python)                     Agent (Claude)
├─ Read workflow YAML            ├─ Receive evidence JSON
├─ Validate AWS credentials  →   ├─ Apply checklist
├─ AWS data collection           ├─ Analyze patterns
├─ Save evidence JSON        →   ├─ Identify risks
├─ Parse findings            ←   └─ Return findings JSON
├─ Correlate cross-skill findings
├─ Calculate risk scores
└─ Generate reports
```

### Skill Structure (Python Pattern)

```python
# drystone/skills/iam/collector.py
class IAMCollector:
    """Collects raw IAM data from AWS."""

    def __init__(self, credentials: dict):
        self.iam = boto3.client('iam', **credentials)

    def collect(self) -> Evidence:
        """Return raw evidence without analysis."""
        return Evidence(
            skill='iam',
            collected_at=datetime.now(),
            data={
                'users': self.iam.list_users()['Users'],
                'roles': self.iam.list_roles()['Roles'],
            }
        )

# drystone/skills/iam/analyzer.py
class IAMAnalyzer:
    """Analyzes evidence with Claude."""

    def analyze(self, evidence: Evidence, client: Anthropic) -> list:
        """Send evidence to Claude, return findings."""
        # Claude analyzes evidence.data and returns findings
        pass
```

## Development Workflow: Adding a New Skill

### Step 1: Create Skill Structure

```bash
# Create directories
mkdir -p drystone/skills/{new_skill}
touch drystone/skills/{new_skill}/{__init__,collector,analyzer}.py
cp drystone/skills/iam/checklist.json drystone/skills/{new_skill}/

# Create __init__.py
echo "from .collector import NewSkillCollector\nfrom .analyzer import NewSkillAnalyzer" > drystone/skills/{new_skill}/__init__.py
```

### Step 2: Implement Collector

```python
# drystone/skills/new_skill/collector.py
import boto3
from drystone.models import Evidence
from datetime import datetime

class NewSkillCollector:
    def __init__(self, credentials: dict):
        self.client = boto3.client('service-name', **credentials)

    def collect(self) -> Evidence:
        """Collect raw evidence from AWS."""
        data = self.client.describe_resources()  # Your AWS API calls
        return Evidence(
            skill='new_skill',
            collected_at=datetime.now(),
            data=data
        )
```

### Step 3: Implement Analyzer

```python
# drystone/skills/new_skill/analyzer.py
from anthropic import Anthropic
from drystone.models import Evidence
import json

class NewSkillAnalyzer:
    def analyze(self, evidence: Evidence, checklist: dict, client: Anthropic) -> list:
        """Analyze evidence with Claude."""
        prompt = f"Analyze {evidence.skill}...\nEVIDENCE:\n{json.dumps(evidence.data)}"
        response = client.messages.create(
            model="claude-opus-4-5-20251101",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return json.loads(response.content[0].text)
```

### Step 4: Test

```bash
# Run audit with new skill
python -m drystone audit --skill new_skill

# Check output
ls audit-logs/
cat audit-logs/*/evidence/new_skill/raw.json | python -m json.tool
cat audit-logs/*/findings/new_skill.json | python -m json.tool
```

### Step 5: Integration

- Add checklist.json with CIS/NIST items
- Register in workflow YAML
- Update README.md with skill description
- Add unit tests in tests/skills/test_new_skill.py

## Common Patterns

### Evidence Structure

```json
{
  "skill": "iam",
  "collected_at": "2026-01-16T20:00:00Z",
  "data": {
    "users": [...],
    "roles": [...],
    "policies": [...]
  }
}
```

### Finding Format (v2.1 - With Evidence Snippets)

```json
{
  "id": "IAM-001",
  "severity": "Critical",
  "risk_score": 9.5,
  "title": "Root account used for daily operations",
  "description": "Root account has active access keys and no MFA...",
  "evidence_refs": ["evidence/iam/users.json#root"],
  "evidence_snippet": {
    "User": "root",
    "AccessKeys": [
      {
        "AccessKeyId": "AKIA...",
        "Status": "Active",
        "CreateDate": "2025-01-15"
      }
    ],
    "MFADevices": []
  },
  "affected_resources": ["arn:aws:iam::123456789012:root"],
  "remediation": "Delete root access keys, enable MFA",
  "cis_reference": "1.5",
  "pci_dss": [
    {
      "control": "8.4.1",
      "reason": "MFA required for all non-console admin access"
    }
  ]
}
```

**Cambios en v2.1:**
- ✅ `evidence_snippet`: JSON snippet extraído por el agente (NUEVO)
- ✅ Renderizado con syntax highlighting en reportes
- ✅ Límite de ~20 líneas para legibilidad
- ✅ Fallback a `evidence_refs` si snippet no disponible
- ✅ Campo opcional (backward compatible)

### PCI DSS Mapping

- Source of truth: each checklist item can include a `pci_dss` array with `{ control, reason }`.
- PCI DSS report formatter uses:
  - `drystone/reports/formats/pci_dss.py` (`_get_all_pci_controls_from_checklists`, `_map_findings_to_controls`)
- Inventory of all checks with PCI DSS control IDs: `checks_inventory.md`

### Checklist Format (v2.0 - PCI DSS Mapped)

```json
{
  "skill": "iam",
  "framework": "CIS AWS Foundations v1.5.0 + AWS Security Best Practices",
  "description": "Comprehensive Identity and Access Management (IAM) security checks",
  "version": "2.0",
  "total_checks": 28,
  "last_updated": "2026-01-18",
  "items": [
    {
      "id": "IAM-001",
      "cis_id": "1.5",
      "title": "Root account must have MFA enabled",
      "severity": "Critical",
      "description": "MFA on root account prevents unauthorized access...",
      "evidence_files": ["users.json", "account-summary.json"],
      "check_keywords": ["root", "mfa_active", "MFA"],
      "remediation": "Enable MFA on root account via AWS Console...",
      "pci_dss": [
        {
          "control": "8.4.1",
          "reason": "MFA required for non-console admin access into CDE..."
        },
        {
          "control": "7.2.1",
          "reason": "Access based on least privilege principle..."
        }
      ]
    }
  ],
  "notes": "Expanded checklist covers CIS AWS Foundations v1.5.0 + AWS Security Best Practices. Includes critical, high, medium, and low severity items. Mapped to PCI DSS v4.0 controls."
}
```

**Cambios v2.0:**
- ✅ Mapeo a **PCI DSS v4.0** (array `pci_dss` con justificación)
- ✅ `evidence_files`: qué AWS API responses buscar
- ✅ `check_keywords`: términos para búsqueda en evidencia
- ✅ Metadatos: `version`, `total_checks`, `last_updated`
- ✅ Todos los 28 controles IAM mapeados a PCI DSS

## Critical Files

### For Implementation (Python)

| File | Purpose | Status |
|------|---------|--------|
| `drystone/cli/main.py` | Click CLI entry point | Phase 0 Complete |
| `drystone/cloud/orchestrator.py` | Core orchestration logic | Phase 1 TODO |
| `drystone/skills/base.py` | Base skill class: 3-tier analyze(), reconciliation, normalization | Active |
| `drystone/skills/{skill}/__init__.py` | Skill implementation (collector + helpers) | Active |
| `drystone/agent/client.py` | Claude CLI/API integration, prompt building, chunking | Active |
| `drystone/agent/chunker.py` | Evidence chunking with metadata skip list | Active |
| `drystone/validation/pre_checks.py` | Tier 1: 69 deterministic pre-checks, registry, XML formatter | Active |
| `drystone/validation/findings_normalizer.py` | Tier 3: Evidence validation, severity calibration, dedup | Active |
| `drystone/validation/checklist_coverage.py` | Coverage gap detection | Active |
| `drystone/cloud/aws/client.py` | AWS credential validation | Phase 1 Complete |

### Configuration

| File | Purpose | Status |
|------|---------|--------|
| `drystone/skills/iam/checklist.json` | IAM security checklist | Phase 1 TODO |
| `drystone/skills/exposure/checklist.json` | Public exposure checklist | Phase 2 TODO |
| `drystone/skills/network/checklist.json` | Network security checklist | Phase 2 TODO |
| `drystone/skills/vulns/checklist.json` | Vulnerability checklist | Phase 2 TODO |
| `drystone/skills/alerting/checklist.json` | Alerting & monitoring checklist | Active |
| `drystone/skills/hardening/checklist.json` | Account hardening checklist | Active |
| `drystone/skills/secretsmanager/checklist.json` | Secrets Manager checklist | Active |
| `drystone/skills/waf/checklist.json` | WAF checklist | Active |
| `drystone/skills/ecr/checklist.json` | ECR checklist | Active |

## Debugging

### View Session Data

```bash
# List sessions
ls audit-logs/

# View evidence collected
find audit-logs -name "*.json" | head -5

# Pretty print JSON
python -m json.tool audit-logs/*/evidence/iam/raw.json

# View findings
python -c "import json; print(json.dumps(open('audit-logs/*/findings/iam.json').read(), indent=2))"

# Check logs
tail -f audit-logs/*/logs/audit.log
```

### Common Issues

1. **Credential validation failed:** Check Access Key ID and Secret Access Key are correct
2. **No evidence collected:** Verify IAM permissions (GetUser, ListUsers, ListRoles, etc.)
3. **Agent analysis timeout:** Reduce evidence size, simplify checklist items
4. **JSON parse error:** Verify Claude response is valid JSON, check prompt formatting
5. **Missing models:** Ensure evidence.py has all required Pydantic models

### Troubleshooting Commands

```bash
# Test credentials directly
python -c "from drystone.cloud.aws import validate_aws_credentials; print(validate_aws_credentials('KEY', 'SECRET', 'us-east-1'))"

# Check Pydantic models
python -c "from drystone.models import IAMEvidence; print(IAMEvidence.schema())"

# Verify Anthropic SDK
python -c "from anthropic import Anthropic; print('OK')"

# Run linter
ruff check drystone/
```

## Recent Context (Last 4 Sessions)

**2026-04-04 (Session 23):** TrailDiscover Integration — CloudTrail Threat Intelligence Complete
- ✅ Integrated TrailDiscover (377 AWS events catalog) as threat intelligence layer
- ✅ Added CTEF-011 (Security monitoring disabled), CTEF-012 (Secrets accessed), CTEF-013 (IAM policy modified) pre-checks
- ✅ Expanded CloudTrail collector: 15→19 lookups (added GetSecretValue, GetParameter, UpdateAssumeRolePolicy, PutRolePolicy)
- ✅ Implemented selective enrichment: only FAIL findings with severity get threat intel (no noise)
- ✅ Integrated MITRE ATT&CK mapping and incident correlation into findings
- ✅ Added compact 2-line threat intel blocks to markdown reports (e.g., "🎯 Threat Intel: MITRE: TA0005 / ✅ LUCR-3, SCARLETEEL")
- ✅ Checklist v1.0→v1.1 (10→13 checks)
- ✅ Added 39 new tests (23 threat_intel module, 16 CloudTrail skill) → 1926 passing, 0 regressions
- **Files:** threat_intel/traildiscover.py (NEW, with lru_cache), threat_intel/traildiscover_events.json (851KB), cloudtrail_events/__init__.py, post_processor.py, pre_checks.py, markdown.py
- **Commit:** dce75dd
- **Session Doc:** drystone-specs/SESSION_23_TRAILDISCOVER_2026-04-04.md

**2026-04-02 (Session 22):** CloudTrail Events Skill Planning - Design Complete, User Validated
- Completed exploit enrichment feature (commit d2ef454) with 35 new tests
- Launched parallel Explore agents → confirmed gap: no skill queries CloudTrail lookup_events
- Received comprehensive design from Plan agent: 7-phase implementation (14-19h)
- Validated with user: MVP scope (8-10 checks), scan_depth config, single-region, timeline viz
- All 4 design decisions finalized, user confirmed
- Files: drystone/cli/main.py, drystone/cli/ui/wizard.py, drystone/skills/sistemas_explotables_red/*, drystone/validation/pre_checks.py, drystone/reports/formats/markdown.py, tests/skills/test_sistemas_explotables_red.py
- Commit: d2ef454

**2026-03-16 (Session 21):** PDF Report Professionalism Complete — 7 Gaps Closed → 8.5+/10 Rating
- Closed final 7 PDF professionalism gaps vs. manual pentest reports
- Implemented Document Control section (auto-generated codes, optional override)
- Implemented Conditions & Exclusions (scope detection, default exclusions, bilingual)
- Enriched Executive Summary with risk scale visual + top 5 recommendations
- Added Client Context File support (YAML frontmatter parser, AI injection, cross-report integration)
- All 1032 tests passing (22 new tests, 0 regressions)
- Files: pdf.py (340+ lines), client_context.py (NEW), config.py, main.py, wizard.py, tests (2 NEW)
- Commit: 4440ea4

**2026-02-26 (Session 20):** Alerting Skill QA Complete - 8 Iterations to ROBUST (confidence 0.892)
- ✅ Completed full QA audit cycle: alerting-qa-1 through alerting-qa-8
- ✅ Fixed 6 bugs: ALRT-001 false positive, ALRT-007 status mismatch, ALRT-009 org-trail FP, 3 metric issues
- ✅ Added 14 deterministic pre-checks (CloudTrail, Config, CloudWatch, EventBridge coverage)
- ✅ Added 67 new tests across 8 commits, all passing
- ✅ Enhanced reports: Added `_resources_audited_section()` to all skill markdown reports
- ✅ PDF support: Populated Inventory section for non-pentest skill reports
- ✅ Pentest integration: Updated pentest_inventory_summary.py with alerting checks
- **Confidence Achieved:** 0.892 (ROBUST) with 0 FP, 0 FN
- **Files:** drystone/validation/pre_checks.py, drystone/skills/alerting/__init__.py, drystone/reports/formats/markdown.py, drystone/reports/formats/pdf.py, tests/skills/test_alerting.py
- **10 Commits:** efb0a32, 639112f, eddde60, f418bc3, ae76229, 24559cf, c421eb8, ee716a9, d696204, 2340443

**2026-02-16 (Session 17):** 3-Tier Pre-Checks + Chunker Resilience + Normalizer Fix
- ✅ Implemented full 3-Tier Validation Architecture (69 deterministic pre-checks across 13 skills)
- ✅ Created `drystone/validation/pre_checks.py` (~800 lines) with registry pattern
- ✅ Integrated pre-checks in `base.py` analyze() flow: Tier 1 → Tier 2 (AI) → Tier 3 (Reconcile)
- ✅ Injected `<pre_computed_facts>` XML into AI prompts via SKILL_ADDENDUM
- ✅ Added `_reconcile_with_pre_checks()` method: rejects PASS contradictions, injects missed FAILs
- ✅ Normalizer skips evidence validation for pre-checked IDs (`_pre_checked_ids` set)
- ✅ Fixed chunker crash on `account-aliases` metadata: added METADATA_KEYS skip list
- ✅ Added graceful error handling for individual chunk failures (catch + continue)
- ✅ Fixed `UnboundLocalError` on `datetime` in normalizer (local import shadowing in Python 3.13+)
- ✅ Updated architecture diagram (`drystone-specs/drystone-architecture.md`)
- ✅ Created 84 new tests (test_pre_checks.py + test_pre_check_reconciliation.py)
- ✅ All 426 tests passing, 0 regressions
- **Result:** False positives ~0% for Tier 1 checks, 100% reproducibility, resilient chunking
- **Files:** drystone/validation/pre_checks.py (NEW), drystone/skills/base.py, drystone/agent/client.py, drystone/agent/chunker.py, drystone/validation/findings_normalizer.py, drystone-specs/drystone-architecture.md, tests/validation/test_pre_checks.py (NEW), tests/validation/test_pre_check_reconciliation.py (NEW)

**2026-02-13 (Session 16):** ECR Skill Enhancement + Network Post-Processor + Validation Improvements
- ✅ Enhanced ECR skill with registry scanning configuration collection
- ✅ Implemented network post-processor for architecture visualization (OSI layer mapping)
- ✅ Enhanced evidence validation with gating rules across skills (exposure, network, ecr)
- ✅ Improved findings normalization with better snippet extraction
- ✅ Created 8 comprehensive test suites for validation + skill-specific evidence quality
- ✅ All 8 skills production ready with backward compatibility
- **Result:** Improved evidence quality, better architecture visualization, robust validation
- **Files:** drystone/skills/ecr/__init__.py, drystone/skills/network/post_processor.py, drystone/validation/*.py
- **Commit:** 08fb632 (wip: Session 15 - ECR/network enhancements)

## Session History

### Session: 2026-01-18 (Iterative Wizard Implementation)
**Phase:** Phase 0 Interactive UI Enhancement

**Accomplishments:**
- ✅ Refactored wizard to support flexible menu navigation
- ✅ Added `display_config_summary()` function for visual config overview
- ✅ Modified `run_project_menu()` and `run_ai_menu()` to accept pre-filled values
- ✅ Changed wizard flow: now starts with navigation menu (no forced Menu A)
- ✅ Menu A is required before "Continue" option appears
- ✅ AWS credentials validated on each Menu A edit
- ✅ Credentials/secrets never pre-filled for security
- ✅ Removed "Use last saved configuration?" prompt from main.py
- ✅ Created comprehensive testing guide (WIZARD_TESTING.md)
- ✅ Updated README with wizard features and examples

**Key Decisions:**
- User chooses which menu to configure first (Menu A or B)
- Menu A validation happens every time it's re-edited
- "Continue" option only visible after Menu A is complete
- Configuration summary shown after each menu change
- Backward compatible with `--non-interactive` mode

**Files Modified:**
- `drystone/cli/ui/wizard.py` - Core wizard refactor (~180 lines added/modified)
- `drystone/cli/main.py` - Removed config reuse prompt (simplified flow)
- `README.md` - Added wizard features and examples
- `WIZARD_TESTING.md` - New comprehensive testing guide

---

### Session: 2026-02-02 (Provider Consolidation - Claude Only)
**Phase:** Phase 1b Agent Analysis

**Accomplishments:**
- ✅ Removed AWS Bedrock integration (timeouts, complexity)
- ✅ Removed Google Gemini API integration (unnecessary)
- ✅ Consolidated to 2 providers: Claude CLI (default) + Claude API (paid)
- ✅ Cleaned up 200+ lines of dead code (bedrock, legacy providers, imports)
- ✅ Updated wizard to show only Claude options
- ✅ Updated all documentation and validation logic

**Why:**
- Bedrock had persistent timeout issues with large evidence
- Gemini integration was unmaintained
- Claude CLI is free, fast, and reliable for most use cases
- Claude API available as premium option with better context windows

**Files Modified:**
- `drystone/agent/client.py` - Removed 6 methods, 3 setups
- `drystone/cli/ui/wizard.py` - Simplified provider selection
- Removed imports: `botocore`, `google.generativeai`

---

### Previous Session: 2026-01-18 (Provider Cleanup)
**Phase:** Phase 1b Agent Analysis

**Accomplishments:**
- Removed non-functional legacy CLI provider option
- Validated all 2 remaining providers working (claude-api, claude-cli)
- Cleaned up dead code paths (40 lines removed)

---

## Next Session Priority (Próximos Pasos)

### Current Plans Status

**✅ COMPLETED: PLAN_SEVERITY_FILTERING.md**
- Commit: 6506175

**✅ COMPLETED: Pre-Checks Deterministas (3-Tier Validation)**
- 69 deterministic pre-checks across 13 skills
- `<pre_computed_facts>` XML injected into AI prompts
- Reconciliation: reject PASS contradictions, inject missed FAILs
- Normalizer skips pre-checked IDs
- 426 tests passing, 0 regressions

**✅ FIXED: Chunker crash on metadata files**
- `account-aliases` and `_audit_metadata` skipped in chunker
- Graceful error handling per chunk (catch + continue)

**✅ FIXED: `datetime` UnboundLocalError in normalizer**
- Removed redundant local import shadowing module-level import (Python 3.13+)

**🔄 PENDING: boto3/botocore upgrade for ECR registry scanning**
- Plan: `PLAN_BOTO3_BOTOCORE_UPDATE.md`

**🔄 OPTIONAL: Full E2E test audit**
- Verify pre-checks output in live audit
- Verify chunker resilience with all skills

---

### Phase 1a (In Progress - High Priority)
- [x] Implement iterative wizard with flexible menu navigation
- [x] Add visual config summary display
- [x] Simplify wizard startup flow
- [ ] Manual testing of wizard (all 6 test cases)
- [ ] Verify backward compatibility with --non-interactive

### Phase 1b (Pending - High Priority)
- [ ] Implement IAM collector (`drystone/skills/iam/__init__.py`)
- [ ] End-to-end integration test: collect → analyze → findings
- [ ] Test with actual AWS credentials and audit data

### Phase 1c (Pending - Medium Priority)
- [x] Create evidence storage layer foundation (`drystone/storage/session.py`)
- [ ] Finalize persistence logic for evidence and findings
- [ ] Implement audit-logs directory structure

### Phase 2 (Lower Priority)
- [ ] Implement Exposure skill (public S3, RDS, etc.)
- [ ] Implement Network skill (security groups, NACLs)
- [ ] Implement Vulns skill (patch status, misconfigs)
- [ ] Implement orchestrator for multi-skill execution
- [ ] Build correlation engine for cross-skill findings
- [ ] Add risk score calculation

### Phase 3 (Reporting - ✅ Enhanced)
- [x] Wizard selection of report type (General vs PCI DSS)
- [x] Enhanced Markdown report formatting with visual metrics
- [x] PCI DSS compliance report formatter (table-based)
- [x] Fix IAM hardcoded bug in report generation
- [x] Implement JSON report structure
- [ ] Add audit trail and compliance reporting

**Report Types Available:**

1. **General Security Report** (`report_type="general"`)
   - Executive Summary with ASCII charts
   - Severity Distribution visualization
   - Top 5 Affected Resources
   - Remediation Timeline (0-7, 8-30, 31-90 days)
   - Compliance Rate by Framework (CIS, PCI DSS)
   - Detailed Findings by Severity
   - Observations section

2. **PCI DSS Compliance Report** (`report_type="pci-dss"`)
   - 3-column table: Control ID | Status (✅/❌/⚠️) | Justification
   - Includes ALL controls from executed skills (not just findings)
   - Executive Summary with compliance rate
   - Critical Non-Compliances section
   - Compliance Statistics by Requirement
   - Prioritized Recommendations

**Report Modules:**
- `drystone/reports/generator.py` - Orchestrates report generation
- `drystone/reports/formats/markdown.py` - General security reports
- `drystone/reports/formats/pci_dss.py` - PCI DSS compliance reports
- `drystone/reports/formats/json.py` - JSON export format
- `drystone/reports/formats/base.py` - Abstract formatter base class

### Phase 4+ (Future)
- [ ] Scheduled audits and monitoring
- [ ] Multi-account AWS support
- [ ] Compliance framework templates (PCI-DSS, SOC2, etc.)
- [ ] Integration with security tools (Jira, ServiceNow)

## Shannon Improvements (2026-02-02)

**Architecture Analysis:** Study Shannon (autonomous pentesting) to improve Drystone reliability.

**Key Improvements Adopted:**

### P1: Output Validation + Error Classification + Retry (CRÍTICO - 5h)
- ✅ Skill-specific validators (post-agent checks)
- ✅ Error classification: retryable vs. permanent
- ✅ Multi-level retry with exponential backoff
- ✅ Rate limit detection (longer delays: 30s+)
- **Expected impact:** +90% resilience to rate limits/network errors

**Files:**
- `drystone/validation/output_validators.py` (NEW)
- `drystone/agent/retry.py` (NEW)
- `drystone/agent/client.py` (MODIFY)

### P2: Structured Prompts (MEDIA - 4h)
- ✅ XML-structured prompts (role, objective, methodology, format)
- ✅ Clear success criteria for validators
- ✅ Professional standards establish quality bar
- **Expected impact:** +25% prompt consistency

**Files:**
- `drystone/prompts/templates/iam_structured.xml` (NEW)
- `drystone/prompts/templates/{skill}_structured.xml` (NEW for each skill)

### P3: Crash-Safe Logging (BAJA - 2h, optional)
- ✅ Append-only JSONL logs with immediate flush
- ✅ Atomic metrics updates with mutex protection
- **Status:** Deferred (audits are short, low priority)

### P4: Testing Infrastructure (BAJA - 4h)
- ✅ Benchmark suite with evidence fixtures
- ✅ Regression tests for prompt changes
- **Status:** Phase 4 priority

**Timeline:** ~15h total (2 weeks)

**References:**
- `ARCHITECTURE_ANALYSIS_SHANNON.md` - Detailed analysis
- `SHANNON_IMPROVEMENTS_SUMMARY.md` - Executive summary
- `SHANNON_DECISIONS.md` - Decision documentation
- `IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md` - Step-by-step plan

**Pattern source:** `/Users/gcuesta/Projects/shannon/`

## Resources

- [Anthropic SDK Python](https://github.com/anthropics/anthropic-sdk-python)
- [boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Click Documentation](https://click.palletsprojects.com/)
- [Project Plan](PROJECT_PLAN.md)
- [Session Tracker](SESSION_TRACKER.md)
- [Project State](PROJECT_STATE.md)
