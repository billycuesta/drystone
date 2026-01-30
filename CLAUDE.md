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
- **Modular skills:** IAM, Exposure, Network, Vulns
- **YAML workflows:** Define skill execution order and configuration
- **Claude API:** For evidence analysis and finding generation

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
   - Skills selection (IAM, Exposure, Network, Vulns)
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
5. Register in workflow YAML

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

## Code Conventions

- **Evidence:** Always collect raw AWS API data before analysis; use Pydantic models
- **Findings:** Structured JSON with severity, risk_score, remediation, and evidence references
- **Checklists:** JSON with CIS/NIST framework items; one per skill
- **Models:** Pydantic BaseModel for all data structures with type hints
- **Error Handling:** Catch boto3 ClientError, return meaningful error messages
- **Logging:** Use Python logging with structured formatters
- **Credentials:** Never log credentials; always mask in UI

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
| `drystone/skills/base.py` | Base skill class (abstract) | Phase 1 TODO |
| `drystone/skills/iam/{collector,analyzer}.py` | IAM skill implementation | Phase 1 TODO |
| `drystone/cloud/agent.py` | Claude API integration | Phase 1b TODO |
| `drystone/cloud/aws/client.py` | AWS credential validation | Phase 1 Complete |

### Configuration

| File | Purpose | Status |
|------|---------|--------|
| `drystone/skills/iam/checklist.json` | IAM security checklist | Phase 1 TODO |
| `drystone/skills/exposure/checklist.json` | Public exposure checklist | Phase 2 TODO |
| `drystone/skills/network/checklist.json` | Network security checklist | Phase 2 TODO |
| `drystone/skills/vulns/checklist.json` | Vulnerability checklist | Phase 2 TODO |

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

## Recent Context (Last 3 Sessions)

**2026-01-30:** Evidence Snippets in Findings Reports
- Implemented end-to-end feature for displaying AWS API response snippets within findings
- Added EvidenceSnippet model with evidence_path and preview_lines configuration
- Enhanced agent evidence extractor with ARG_MAX protection for large prompts
- Implemented evidence rendering in both markdown and PCI DSS report formats
- 15 unit tests (100% pass rate) covering model validation, extraction, and rendering
- Next: Phase 5 Testing Infrastructure - comprehensive test coverage for all modules

**2026-01-29:** Project Finalization and GitHub Sync
- Completed synchronization with GitHub (23 commits)
- Verified Phase 0-4 completion (100%)
- Phase 5 (Testing Infrastructure) identified as critical next step
- All documentation updated and current

**2026-01-28:** Advanced Reporting and Skills Implementation
- Enhanced PCI DSS compliance reporting with 3-column control tables
- Added Alerting and Hardening skills to available audits
- Integrated skill validation and selection in wizard
- Report generation now supports both General and PCI DSS formats
- 19 unit tests with 100% pass rate

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

### Previous Session: 2026-01-18 (Provider Cleanup)
**Phase:** Phase 1b Agent Analysis

**Accomplishments:**
- Removed non-functional gemini-cli provider option
- Validated all 3 remaining providers working (claude-api, claude-cli, gemini-api)
- Cleaned up dead code paths (40 lines removed)

---

## Next Session Priority (Próximos Pasos)

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

## Resources

- [Anthropic SDK Python](https://github.com/anthropics/anthropic-sdk-python)
- [boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Click Documentation](https://click.palletsprojects.com/)
- [Project Plan](PROJECT_PLAN.md)
- [Session Tracker](SESSION_TRACKER.md)
- [Project State](PROJECT_STATE.md)
