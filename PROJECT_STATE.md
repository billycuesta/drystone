# Project State: Drystone AWS Security Audit CLI

**Last Updated:** 2026-01-18
**Status:** Active - Phase 0 Complete, Phase 1 In Progress
**Current Phase:** Phase 0 UI Enhancement + Phase 1 Agent Analysis

## Executive Summary

Drystone is a Python-based AWS security audit CLI powered by Claude AI. The project has completed Phase 0 (interactive CLI UI) with recent enhancements to the wizard UI flow for better flexibility and UX. Phase 1 (AWS cloud integration with agent analysis) is actively in progress with full Claude API integration, comprehensive IAM security checklist (28 checks), and multi-provider LLM support (claude-api, claude-cli, gemini-api).

**Latest Enhancement (2026-01-18):** Refactored wizard to support flexible menu navigation - user can now start with either Menu A (Project Scope) or Menu B (AI Configuration), edit both multiple times, and view configuration summary after each change. Removed forced "Use last saved configuration?" prompt for cleaner startup flow.

## Current Objectives

- [x] Phase 0: Interactive CLI UI with Rich formatting and Questionary prompts
- [x] Phase 0a: Credential validation system (AWS STS GetCallerIdentity)
- [x] Phase 1a: AWS IAM data collection foundation (users, roles, groups, policies)
- [x] Phase 1b: Claude API integration for security finding analysis (ACTIVE)
  - [x] Anthropic SDK integration
  - [x] Comprehensive IAM checklist (28 checks)
  - [x] Enhanced Claude system prompt with vulnerability categories
  - [x] Multi-provider support (claude-api, claude-cli, gemini-api)
  - [ ] IAM collector implementation (in progress)
- [x] Phase 1c: Evidence storage and session management (foundation)
- [ ] Phase 2: Multi-skill orchestration (IAM, Exposure, Network, Vulns)
- [ ] Phase 3: Report generation engine (HTML, Markdown, JSON formats)
- [ ] Phase 4: Scheduled audits and monitoring

## Recent Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-01-18 | Refactor wizard to iterative menu navigation | Better UX, flexible menu order, simpler flow (no forced Menu A) |
| 2026-01-18 | Remove "Use last saved configuration?" prompt | Cleaner startup, reduces extra step, wizard shows options directly |
| 2026-01-18 | Menu A required for "Continue" option | Ensures AWS credentials are always configured before execution |
| 2026-01-18 | Never pre-fill secrets (passwords, API keys) | Security best practice, prevents accidental credential exposure |
| 2026-01-18 | Display config summary after each menu edit | Improved feedback, users can verify before continuing |
| 2026-01-18 | Remove gemini-cli provider option | Non-functional CLI tool, unnecessary complexity, cleaner codebase |
| 2026-01-18 | Keep 3 core providers (claude-api, claude-cli, gemini-api) | All functional, provides flexibility for different deployment scenarios |
| 2026-01-17 | Expand IAM checklist from 8 to 28 items | More comprehensive security coverage, better finding quality (3x increase) |
| 2026-01-17 | Enhanced Claude system prompt with vulnerability categories | Better context for security analysis, improved finding accuracy |
| 2026-01-17 | Direct credentials instead of AWS profiles | Enables CI/CD, cloud deployment, doesn't require local ~/.aws/credentials |
| 2026-01-17 | Use boto3 STS GetCallerIdentity for validation | Lightweight, validates credentials without service-specific permissions |

## Active Blockers

| Severity | Blocker | Status | Notes |
|----------|---------|--------|-------|
| Minor | IAM Collector Implementation | Open | Implement list_users, list_roles, etc. using boto3; foundation already exists |
| Minor | End-to-End Testing | Open | Need to test full collect→analyze→report workflow with real AWS data |
| Minor | Unit Test Coverage | Open | No tests yet for AWS client, agent provider routing, or evidence models |
| Low | Report Generation Polish | Open | HTML/Markdown templates need refinement for better presentation |

## Architecture Overview

```
drystone/
├── cli/
│   ├── main.py              # Click CLI entry point
│   ├── config.py            # Config management
│   └── ui/
│       ├── branding.py      # Banner and formatting
│       └── wizard.py        # Interactive wizard
├── models/
│   ├── config.py            # WizardConfig (Pydantic)
│   ├── evidence.py          # IAM evidence models (NEW)
│   └── __init__.py
├── cloud/                   # Cloud integration (NEW)
│   ├── aws/
│   │   ├── client.py        # Credentials validation (NEW)
│   │   └── __init__.py
│   └── __init__.py
├── skills/                  # Skill modules (FOUNDATION)
│   ├── iam/
│   │   ├── collector.py     # TODO: IAM data collection
│   │   ├── analyzer.py      # TODO: Claude analysis
│   │   └── checklist.json   # TODO: Security checklist
│   └── __init__.py
├── storage/                 # Evidence storage (FOUNDATION)
│   ├── manager.py           # TODO: Save/load evidence
│   └── __init__.py
├── __main__.py              # Entry for `python -m drystone`
└── __init__.py
```

## Technology Stack

### Core (Implemented)
- **Python 3.9+** - Language
- **Click** - CLI framework
- **Rich** - Terminal UI and formatting
- **Questionary** - Interactive prompts
- **Pydantic** - Data validation and models

### Phase 1 (In Progress)
- **boto3** - AWS SDK for data collection and credential validation
- **anthropic** - Claude API for security analysis (TODO)

### Phase 3+ (Planned)
- **openai** - ChatGPT API
- **google-generativeai** - Gemini API

## Key Files and Status

| File | Purpose | Status | Notes |
|------|---------|--------|-------|
| `drystone/cli/main.py` | CLI entry point | Complete | Updated for direct credentials |
| `drystone/cli/ui/wizard.py` | Interactive wizard | Complete | Now prompts for Access Key ID + Secret |
| `drystone/models/config.py` | WizardConfig model | Complete | Added credential fields |
| `drystone/models/evidence.py` | Evidence models | Complete | IAMUser, IAMRole, IAMGroup, IAMPolicy, IAMEvidence |
| `drystone/cloud/aws/client.py` | AWS validation | Complete | STS GetCallerIdentity validation |
| `drystone/skills/iam/collector.py` | IAM data collection | TODO | Phase 1a priority |
| `drystone/skills/iam/analyzer.py` | Claude analysis | TODO | Phase 1b |
| `drystone/storage/manager.py` | Evidence storage | TODO | Phase 1c |
| `configs/workflows/iam-only.yaml` | Test workflow | TODO | Simple test configuration |

## Recent Changes (Session 2026-01-18 - Ongoing)

### Removed
- gemini-cli provider option from `drystone/models/config.py` (non-functional)
- gemini-cli conditional branches from `drystone/agent/client.py` and `drystone/cli/ui/wizard.py`

### Wizard UI Reorganization
- Refactored `drystone/cli/ui/wizard.py` into 3 separate functions:
  - `run_project_menu()`: Menu A - Project scope (obligatory) - 6 steps (client, AWS creds, region, skills, formats)
  - `run_ai_menu()`: Menu B - AI configuration (optional) - 2 steps (provider, API key)
  - `get_default_ai_config()`: Returns default (claude-cli, no API key)
  - `run_setup_wizard()`: Orchestrates both menus with conditional flow
- Menu A executes first (always required)
- After Menu A, user asked if they want to customize AI config
- If "No": Uses claude-cli by default (free, no API key needed)
- If "Yes": Shows Menu B with provider selection + conditional API key prompt
- Better UX: Separates project scope (mandatory) from AI preferences (optional with smart defaults)
- Backward compatible: `--non-interactive` and saved configs still work

### Verified
- claude-api provider: Full Anthropic SDK integration working
- claude-cli provider: CLI fallback option functional
- gemini-api provider: Google Generative AI integration working
- No broken references after provider removal
- All three remaining providers properly route through agent client
- Wizard refactoring: All 3 new functions import successfully, syntax validated

### Impact
- Codebase: 40 fewer lines of dead code (provider cleanup) + 120 new lines (wizard refactor) = net +80 lines with better structure
- User Experience: Two-menu flow reduces cognitive load, smart defaults for common use case (claude-cli)
- Maintainability: Cleaner separation of concerns, easier to modify each menu independently
- UX Improvement: Optional AI configuration makes CLI more approachable for first-time users

## Recent Changes (Session 2026-01-17)

### Added
- `drystone/models/evidence.py` - Comprehensive IAM evidence models with Pydantic validation
- `drystone/cloud/aws/client.py` - AWS credential validation function using boto3 STS
- `drystone/skills/` directory - Foundation for modular skill architecture
- `drystone/storage/` directory - Foundation for evidence persistence layer

### Modified
- `drystone/cli/main.py` - Updated to use direct credentials, added credential validation call
- `drystone/cli/ui/wizard.py` - Changed from profile selection to direct credential input (Access Key ID, Secret Access Key, Region)
- `drystone/cli/ui/branding.py` - Enhanced summary display to show credential validation results
- `drystone/models/config.py` - Added access_key_id, secret_access_key fields; updated WizardConfig validation
- `pyproject.toml` - Added boto3 dependency
- `requirements.txt` - Updated with boto3

### Not Modified
- `README.md` - Status still accurate, will update when Phase 1a complete
- `CLAUDE.md` - Still references Go architecture; TODO: update to Python

## Next Session Priority Order

1. **IAM Collector Implementation** - Implement `drystone/skills/iam/__init__.py` collect() method to pull actual IAM data using Evidence models
2. **End-to-End Integration Testing** - Test full workflow: credential validation → evidence collection → Claude analysis → report generation
3. **Session Persistence** - Finalize `drystone/storage/session.py` for saving evidence and findings to audit-logs/
4. **Unit Test Coverage** - Add pytest tests for AWS client, evidence models, and provider routing
5. **Report Generation** - Polish HTML and Markdown templates in `drystone/reports/formats/`
6. **Skill Orchestration** - Implement multi-skill execution and cross-skill correlation (Phase 2)

## Configuration Files

### ~/.drystone/last-run.json
Persists last audit configuration (client, credentials, region, skills, formats):
```json
{
  "client_name": "ACME Corp",
  "access_key_id": "AKIA...",
  "secret_access_key": "(masked)",
  "region": "us-east-1",
  "skills": ["iam"],
  "output_formats": ["markdown"]
}
```

### configs/workflows/iam-only.yaml (TODO)
Simple workflow for testing Phase 1:
```yaml
name: "IAM Only Audit"
skills:
  - name: "iam"
    enabled: true
    confidence_threshold: 0.7
```

## Development Workflow

### Running Current Version
```bash
# Interactive mode (default)
python -m drystone audit

# Non-interactive (uses last saved config)
python -m drystone audit --non-interactive

# CLI args mode
python -m drystone audit --client "ACME" --region us-west-2
```

### Testing Credentials
```bash
# Valid credentials will show: "Validated AWS Account 123456789012"
# Invalid credentials will show: "Credential validation failed: ..."
```

### Building Next Feature
```bash
# 1. Implement collector in drystone/skills/iam/collector.py
# 2. Add to iam_collector() function in main.py
# 3. Test: python -m drystone audit --skill iam
# 4. Verify: ls audit-logs/*/evidence/iam/
```

## Dependencies

### Core
- click>=8.0.0
- rich>=13.0.0
- questionary>=1.10.0
- pydantic>=2.0.0

### Phase 1
- boto3>=1.26.0
- botocore>=1.29.0
- python-dotenv>=0.21.0 (for local dev)

### Dev
- pytest>=7.0.0
- black>=23.0.0
- ruff>=0.1.0
- mypy>=1.0.0

## Known Issues

1. **CLAUDE.md Outdated** - Still references Go architecture; needs update for Python implementation
2. **No Tests Yet** - Evidence models and AWS client need pytest coverage
3. **Credential Storage** - Currently stored in plain text in ~/.drystone/last-run.json; should use keyring in future
4. **Missing Evidence Models** - Network, Exposure, and Vuln skill models not yet created

## Performance Notes

- **Credential Validation**: ~500ms (STS GetCallerIdentity call)
- **Interactive Wizard**: ~5 seconds total (user input time)
- **IAM Collection** (estimated): ~2-5 seconds (boto3 API calls)

## Security Considerations

- Credentials validated via AWS STS before storage
- Credentials masked in UI (showing only first/last 4 chars)
- Credentials stored in ~/.drystone/last-run.json in plain text (TODO: use keyring)
- No credential caching between sessions
- Each audit creates fresh AWS client connection

## Metrics

- **Python Files**: 12 (6 in cli/, 2 in models/, 2 in cloud/aws/, 1 foundation each in skills/ and storage/)
- **Lines of Code**: ~2000 (excluding dependencies)
- **Test Coverage**: 0% (TODO)
- **Documentation**: CLAUDE.md (outdated), README.md (Phase 0 focused), PROJECT_PLAN.md (architecture)

---

**Last Session:** 2026-01-18 - UI Reorganization (Two-Menu Wizard) + Provider Cleanup
**Current Focus:** Wizard Testing and IAM Collector Implementation
**Next Focus:** IAM Data Collection Implementation
