# Drystone 🪨

AWS Security Audit CLI powered by Claude.

## Status

✅ **Phase 0: Interactive UI - Complete**
🚧 **Phase 1: AWS Cloud Integration - Next**

## Quick Start

```bash
# Install (development mode)
pip install -e .

# Show help
python -m drystone --help

# Run interactive audit (flexible wizard menu)
python -m drystone audit

# Run with saved configuration
python -m drystone audit --non-interactive

# Run with CLI arguments
python -m drystone audit --client "ACME Corp" --region us-east-1 --skills iam --formats markdown
```

## Features

### ✅ Phase 0: Interactive CLI UI
- 🎨 Gemini-CLI style ASCII banner with RGB gradient colors
- 🪄 **Iterative wizard with flexible menu navigation**
  - Start with Menu A (Project & AWS Scope) or Menu B (AI Configuration)
  - Edit menus multiple times before finalizing
  - AWS credentials validated on each Menu A edit
  - Config summary displayed after each change
  - "Continue" option only appears after Menu A is complete
- 📋 Configuration validation with Pydantic
- 💾 Config persistence (~/.drystone/last-run.json)
- 🎯 Support both interactive and non-interactive modes
- 📊 Rich-formatted summary tables
- 🔐 Credentials masked in display (never logged)

### 🚧 Phase 1+: AWS Integration (coming soon)
- AWS data collection (boto3)
- Claude API analysis
- Multi-LLM support (Anthropic, Gemini, OpenAI)
- Modular skills (IAM, Exposure, Network, Vulns)
- Orchestration engine
- Shannon-style reporting

## Architecture

**Stack:**
- **Python 3.9+** - Language
- **Click** - CLI framework
- **Rich** - Terminal UI formatting
- **Questionary** - Interactive prompts
- **Pydantic** - Data validation

**Planned:**
- **boto3** - AWS SDK (Phase 1)
- **anthropic** - Claude API (Phase 1)
- **openai** - ChatGPT API (Phase 3)
- **google-generativeai** - Gemini API (Phase 3)

## Project Structure

```
drystone/
├── cli/
│   ├── main.py          # Click CLI entry point
│   ├── config.py        # Config management
│   └── ui/
│       ├── branding.py  # Banner and UI components
│       └── wizard.py    # Interactive wizard
├── models/
│   └── config.py        # Pydantic models
├── __main__.py          # Entry for python -m drystone
└── __init__.py
```

## Interactive Wizard

The iterative wizard allows flexible configuration:

```
$ python -m drystone audit

🪨 DRYSTONE
AWS Security Audit CLI

? Configuration Setup

  > 📋 Configure Menu A: Project Scope
    🤖 Configure Menu B: AI Configuration
```

**Features:**
- ✅ Start with either menu (no forced order)
- ✅ View configuration summary after each change
- ✅ Edit menus multiple times before finalizing
- ✅ Pre-filled values on re-edit (secrets excluded)
- ✅ AWS validation on each Menu A edit
- ✅ "Continue" appears only after Menu A is complete

For testing details, see [WIZARD_TESTING.md](WIZARD_TESTING.md)

## Commands

```
drystone audit          # Run security audit (interactive or CLI args)
drystone skill          # List/manage available skills
drystone logs           # View audit sessions and reports
drystone version        # Show version
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Format code
black drystone/

# Lint
ruff check drystone/

# Type checking
mypy drystone/

# Run tests
pytest tests/

# Clean
rm -rf build/ dist/ *.egg-info __pycache__ .pytest_cache
```

## Output

```
audit-logs/{session_id}/
├── evidence/          # Raw AWS data (Phase 1+)
├── findings/          # Agent analysis (Phase 1+)
├── correlations/      # Cross-skill findings (Phase 2+)
└── reports/
    ├── report.md      # Markdown report
    ├── report.html    # HTML dashboard
    └── report.json    # Machine-readable format
```

## Documentation

- **CLAUDE.md** - Developer guide for Claude Code
- **PROJECT_PLAN.md** - Complete implementation plan and architecture
