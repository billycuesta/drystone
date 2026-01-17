# Project State: Drystone AWS Security Audit CLI

**Last Updated:** 2026-01-17
**Status:** Active - Phase 1 in progress
**Current Phase:** Phase 1 AWS Cloud Integration - Direct Credentials

## Executive Summary

Drystone is a Python-based AWS security audit CLI powered by Claude AI. The project has completed Phase 0 (interactive CLI UI) and is actively implementing Phase 1 (AWS cloud integration). In this session, we transitioned from AWS profile-based input to direct credential management (Access Key ID + Secret Access Key), implemented credential validation via boto3 STS, and created foundational data models for evidence collection.

## Current Objectives

- [x] Phase 0: Interactive CLI UI with Rich formatting and Questionary prompts
- [x] Phase 0a: Credential validation system (AWS STS GetCallerIdentity)
- [ ] Phase 1a: AWS IAM data collection (users, roles, groups, policies)
- [ ] Phase 1b: Claude API integration for security finding analysis
- [ ] Phase 1c: Evidence storage and session management
- [ ] Phase 2: Multi-skill orchestration (IAM, Exposure, Network, Vulns)
- [ ] Phase 3: Multi-LLM support (Gemini, OpenAI in addition to Anthropic)
- [ ] Phase 4: Reporting engine (HTML, Markdown, JSON formats)

## Recent Decisions

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-01-17 | Direct credentials instead of AWS profiles | Enables CI/CD, cloud deployment, doesn't require local ~/.aws/credentials |
| 2026-01-17 | Use boto3 STS GetCallerIdentity for validation | Lightweight, validates credentials without service-specific permissions |
| 2026-01-17 | Pydantic models for evidence (IAMUser, IAMRole, etc.) | Type safety, validation, IDE support, consistent serialization |
| 2026-01-17 | Store credentials in WizardConfig during session | Single source of truth, simplifies credential passing to collection phase |

## Active Blockers

| Severity | Blocker | Status | Notes |
|----------|---------|--------|-------|
| Minor | IAM Collector Implementation | Open | Need to implement list_users, list_roles, etc. using boto3 |
| Minor | Evidence Storage Layer | Open | Decide: filesystem JSON vs database; implement audit-logs structure |
| Minor | Claude API Integration | Open | Phase 1b; add anthropic SDK and prompting logic |
| Low | Unit Test Coverage | Open | No tests yet for AWS client or evidence models |

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

## Recent Changes (This Session)

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

1. **Phase 1a: IAM Collector** - Implement `drystone/skills/iam/collector.py` to collect actual IAM data using Evidence models
2. **Evidence Storage** - Implement `drystone/storage/manager.py` to persist evidence JSON in audit-logs structure
3. **Phase 1b: Agent Integration** - Add Anthropic SDK and implement `drystone/skills/iam/analyzer.py` to pass evidence to Claude
4. **Integration Testing** - Test full workflow: `drystone audit --skill iam` with real AWS credentials
5. **Skill Orchestration** - Implement multi-skill execution and cross-skill correlation

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

**Last Session:** 2026-01-17 - Phase 1 AWS Integration, Direct Credentials
**Next Focus:** IAM Data Collection Implementation
