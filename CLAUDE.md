# Drystone - AWS Security Audit CLI

Developer guide for working with Drystone using Claude Code.

## Qué es Drystone

CLI para auditorías de seguridad AWS. Similar a shannon pero para compliance/security (no pentesting activo).

**Principio core:** App orquesta, agente analiza.

## Arquitectura

- **Go** + Cobra (CLI)
- **Skills modulares:** IAM, Exposure, Network, Vulns
- **Workflow YAML:** Define qué skills ejecutar y en qué orden
- **Claude API:** Para análisis de evidencia

## Estructura Clave

```
cmd/main.go                      - Entry point
internal/orchestrator/engine.go  - Core orchestration
internal/skills/base/skill.go    - Interface común
internal/skills/iam/skill.go     - Patrón de referencia
internal/agent/client.go         - Claude integration
configs/workflows/               - Workflow definitions
```

## Flujo de Ejecución

1. Usuario: `drystone audit`
2. App lee workflow YAML
3. Por cada skill:
   - **Collector** llama AWS APIs → guarda evidencia JSON
   - **Analyzer** pasa evidencia + checklist a Claude → recibe findings JSON
4. App correlaciona findings cross-skill
5. App genera reportes (HTML/MD/JSON)

## Cómo Agregar un Skill

1. Crear directorio `internal/skills/{nombre}/`
2. Implementar interface `Skill`:
   ```go
   type MySkill struct {
       base.BaseSkill
   }

   func (s *MySkill) Collect(ctx, aws) (*Evidence, error) {
       // AWS API calls
   }

   func (s *MySkill) Analyze(ctx, evidence, agent) (*Result, error) {
       // Pass to agent
   }
   ```
3. Crear checklist JSON
4. Registrar en workflow YAML

## Testing Local

```bash
# Build
make build

# Run IAM audit
./bin/drystone audit --skill iam --profile dev

# Run full audit
./bin/drystone audit --profile dev

# View logs
./bin/drystone logs list
```

## Convenciones

- **Evidence:** Siempre guardar raw data antes de analizar
- **Findings:** JSON estructurado (severity, risk_score, remediation)
- **Checklists:** JSON con items CIS/NIST
- **Logs:** Structured logging con zerolog

## Integración con Claude

```go
// Prompt structure
prompt := fmt.Sprintf(`
Eres un auditor AWS. Analiza:

EVIDENCIA:
%s

CHECKLIST:
%s

Retorna JSON:
{
  "findings": [{
    "id": "IAM-001",
    "severity": "Critical",
    "risk_score": 9.5,
    "title": "...",
    "remediation": "..."
  }],
  "risk_score": 7.5
}
`, evidence, checklist)
```

**Crítico:** Agent SOLO analiza, NO decide workflow.

## Arquitectura de Ejecución

### App vs Agent Separation

```
App (Go)                  Agent (Claude)
├─ Read workflow YAML  →  ├─ Receive evidence JSON
├─ AWS data collect    →  ├─ Apply checklist
├─ Save evidence JSON  →  ├─ Analyze findings
├─ Call agent          →  └─ Return JSON
├─ Parse findings
├─ Correlate skills
└─ Generate reports
```

### Skill Interface

```go
type Skill interface {
    // Metadata
    Name() string
    Description() string
    Version() string

    // Execution
    Preflight(ctx context.Context, aws AWSClient) error
    Collect(ctx context.Context, aws AWSClient) (*Evidence, error)
    Analyze(ctx context.Context, evidence *Evidence, agent AgentClient) (*SkillResult, error)

    // Configuration
    LoadChecklist() ([]ChecklistItem, error)
    RequiredPermissions() []string
}
```

## Development Workflow

### 1. Starting New Skill

```bash
# Create skill structure
mkdir -p internal/skills/new-skill
touch internal/skills/new-skill/{skill,collector}.go
cp internal/skills/iam/checklist.json internal/skills/new-skill/

# Edit CLAUDE.md with new skill
# - Add to "Estructura Clave" section
# - Add to workflow YAML
```

### 2. AWS Data Collection

```go
// internal/skills/new-skill/collector.go
func (c *Collector) Collect(ctx context.Context, aws AWSClient) (*Evidence, error) {
    // 1. Call AWS APIs
    // 2. Validate responses
    // 3. Structure data
    // 4. Return Evidence with map[string]interface{}
}
```

### 3. Agent Analysis

```go
// Must return structured JSON
// Errors in parsing = skill failure
// Always validate agent response
```

### 4. Testing

```bash
# Test single skill
./bin/drystone audit --skill new-skill --profile dev

# Check output
ls audit-logs/
cat audit-logs/*/evidence/new-skill/*.json
cat audit-logs/*/findings/new-skill.json
```

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

### Finding Format

```json
{
  "id": "IAM-001",
  "severity": "Critical",
  "risk_score": 9.5,
  "title": "Root account used for daily operations",
  "evidence_refs": ["evidence/iam/users.json#root"],
  "remediation": "Create IAM user with admin permissions"
}
```

### Checklist Format

```json
{
  "skill": "iam",
  "items": [
    {
      "id": "IAM-001",
      "title": "Avoid root account usage",
      "severity": "Critical",
      "framework": "CIS AWS Foundations 1.1"
    }
  ]
}
```

## Critical Files

### For Implementation

| File | Purpose | Status |
|------|---------|--------|
| `cmd/main.go` | CLI entry point | TODO |
| `internal/orchestrator/engine.go` | Core orchestration logic | TODO |
| `internal/skills/base/skill.go` | Base skill interface | TODO |
| `internal/skills/iam/skill.go` | IAM skill (reference) | TODO |
| `internal/agent/client.go` | Claude integration | TODO |
| `internal/aws/client.go` | AWS SDK wrapper | TODO |

### Configuration

| File | Purpose |
|------|---------|
| `configs/workflows/iam-only.yaml` | Simple test workflow |
| `configs/workflows/full-audit.yaml` | Full audit workflow |
| `internal/skills/iam/checklist.json` | IAM security checklist |

## Debugging

### View Session Data

```bash
# List sessions
ls audit-logs/

# View evidence
cat audit-logs/*/evidence/iam/users.json | jq .

# View findings
cat audit-logs/*/findings/iam.json | jq .

# View logs
tail audit-logs/*/logs/orchestrator.log
```

### Common Issues

1. **No evidence collected:** Check AWS credentials, permissions
2. **Agent timeout:** Reduce evidence size, simplify checklist
3. **Parse error:** Check JSON response format from agent
4. **Corrupted session:** Delete audit-logs/{session} and retry

## Próximos Pasos

- [ ] Implement `cmd/main.go` with cobra setup
- [ ] Implement `internal/skills/base/skill.go` interface
- [ ] Implement `internal/aws/client.go` wrapper
- [ ] Implement `internal/skills/iam/skill.go` (reference implementation)
- [ ] Implement `internal/agent/client.go` with Claude API
- [ ] Create test workflow `configs/workflows/iam-only.yaml`
- [ ] Test MVP: `./bin/drystone audit --skill iam`
- [ ] Implement Exposure skill
- [ ] Implement Network skill
- [ ] Implement Orchestrator engine
- [ ] Full workflow testing

## Resources

- [Go AWS SDK v2](https://github.com/aws/aws-sdk-go-v2)
- [Cobra CLI Framework](https://github.com/spf13/cobra)
- [Anthropic SDK Go](https://github.com/anthropics/anthropic-sdk-go)
- [Project Plan](PROJECT_PLAN.md)
