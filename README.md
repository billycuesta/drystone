# Drystone 🪨

AWS Security Audit CLI powered by Claude.

## Status

🚧 **En desarrollo - Fase 1: MVP**

Objetivo: `drystone audit --skill iam` funcional end-to-end

## Quick Start

```bash
# Build
make build

# Run IAM audit
export AWS_PROFILE=your-profile
./bin/drystone audit --skill iam
```

## Architecture

- **Go** + Cobra (CLI)
- **AWS SDK v2** (data collection)
- **Claude API** (analysis)
- **Modular skills** (IAM, Exposure, Network, Vulns)

Ver `CLAUDE.md` para detalles técnicos.

## Development

```bash
# Format code
make fmt

# Run tests
make test

# Clean build artifacts
make clean

# Install dependencies
make install-deps
```

## Output

```
audit-logs/{account}_{session}/
├── evidence/          # Raw AWS data
├── findings/          # Agent analysis
└── reports/           # Human-readable reports
```

## Documentation

- **CLAUDE.md** - Developer guide for Claude Code
- **PROJECT_PLAN.md** - Complete architecture and implementation plan
