# Plan: Proyecto Drystone

## Resumen Ejecutivo

**Drystone** = CLI de auditoría AWS + análisis con Claude

**Inspiración:** shannon (estructura CLI/output)
**Diferencia clave:** App orquesta workflow, agente solo analiza evidencia

**Stack:** Go + Cobra (CLI) + AWS SDK v2 + Claude API

---

## Pre-requisitos y Setup Inicial

### Estado Actual

**Verificado:**
- ✅ Homebrew instalado: `/opt/homebrew/bin/brew`
- ✅ GitHub CLI instalado: `gh version 2.83.2`
- ❌ Go NO instalado

**Configuración decidida:**
- Repo GitHub: `drystone` (privado)
- Directorio local: `/Users/gcuesta/Projects/drystone`

### Pasos de Setup (Ejecutar al salir de plan mode)

#### 1. Instalar Go
```bash
# Instalar Go via Homebrew
brew install go

# Verificar instalación
go version  # Debe mostrar go1.21+

# Configurar GOPATH (si no existe)
echo 'export GOPATH=$HOME/go' >> ~/.zshrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc
source ~/.zshrc
```

#### 2. Crear Repositorio GitHub
```bash
cd /Users/gcuesta/Projects/drystone

# Crear repo privado en GitHub
gh repo create drystone --private --source=. --remote=origin

# Verificar remoto
git remote -v
```

#### 3. Setup Proyecto Go
```bash
# Inicializar Git (si no existe)
git init

# Inicializar Go module
go mod init github.com/gcuesta/drystone

# Crear .gitignore inicial
cat > .gitignore << 'EOF'
# Binaries
bin/
*.exe
*.dll
*.so
*.dylib

# Go
*.test
*.out
vendor/
go.work

# Output
audit-logs/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Env vars
.env
.env.local
EOF

# Primer commit
git add .gitignore
git commit -m "Initial commit: Add .gitignore"
git branch -M main
git push -u origin main
```

#### 4. Crear Estructura de Directorios

Script completo está en la sección "Esquema de Directorios Inicial" más abajo.

```bash
# Directorios principales
mkdir -p cmd/commands
mkdir -p internal/{orchestrator,aws,agent,storage,report}
mkdir -p internal/skills/{base,iam}
mkdir -p pkg/models
mkdir -p configs/workflows
mkdir -p scripts

# Archivos de documentación
# (CLAUDE.md y PROJECT_PLAN.md se copiarán del plan)
```

#### 5. Instalar Dependencias Go

```bash
# Dependencias principales
go get github.com/spf13/cobra@latest
go get github.com/spf13/viper@latest
go get github.com/aws/aws-sdk-go-v2/config@latest
go get github.com/aws/aws-sdk-go-v2/service/iam@latest
go get github.com/aws/aws-sdk-go-v2/service/ec2@latest
go get github.com/anthropics/anthropic-sdk-go@latest
go get github.com/rs/zerolog@latest

# Limpiar y verificar
go mod tidy
go mod verify
```

#### 6. Verificar AWS Credentials

```bash
# Verificar AWS CLI
aws --version

# Listar perfiles disponibles
aws configure list-profiles

# Verificar credenciales
aws sts get-caller-identity --profile <tu-profile>
```

#### 7. Configurar Claude API Key

```bash
# Agregar a ~/.zshrc o ~/.bashrc
echo 'export ANTHROPIC_API_KEY="tu-api-key-aquí"' >> ~/.zshrc
source ~/.zshrc

# O crear .env local (gitignored)
echo 'ANTHROPIC_API_KEY=tu-api-key-aquí' > .env
```

### Checklist de Verificación

Antes de empezar a implementar código:

- [ ] Go instalado y en PATH (`go version` funciona)
- [ ] Repo GitHub creado y conectado (`git remote -v`)
- [ ] Go module inicializado (`go.mod` existe)
- [ ] Estructura de directorios creada
- [ ] Dependencias Go instaladas (`go mod download`)
- [ ] AWS CLI configurado con credenciales válidas
- [ ] Claude API key configurada (`echo $ANTHROPIC_API_KEY`)
- [ ] CLAUDE.md copiado al proyecto
- [ ] PROJECT_PLAN.md creado con plan completo

---

## Arquitectura Core

### Separación de Responsabilidades

```
┌─────────────────────────────────────────┐
│         APLICACIÓN (Go)                 │
│  ┌─────────────────────────────────┐   │
│  │ 1. Lee workflow (YAML)          │   │
│  │ 2. Ejecuta preflight checks     │   │
│  │ 3. Recolecta datos AWS (SDK)    │   │
│  │ 4. Guarda evidencia (JSON)      │   │
│  │ 5. Prepara contexto para agente │   │
│  └─────────────────────────────────┘   │
└──────────────┬──────────────────────────┘
               │
               │ Evidencia + Checklist
               ▼
┌─────────────────────────────────────────┐
│         AGENTE (Claude)                 │
│  ┌─────────────────────────────────┐   │
│  │ 1. Analiza evidencia            │   │
│  │ 2. Valida contra checklist      │   │
│  │ 3. Genera findings              │   │
│  │ 4. Calcula risk score           │   │
│  │ 5. Retorna JSON estructurado    │   │
│  └─────────────────────────────────┘   │
└──────────────┬──────────────────────────┘
               │
               │ Findings JSON
               ▼
┌─────────────────────────────────────────┐
│         APLICACIÓN (Go)                 │
│  ┌─────────────────────────────────┐   │
│  │ 1. Correlaciona findings        │   │
│  │ 2. Genera reportes              │   │
│  │ 3. Exporta (HTML/MD/JSON)       │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

**Garantiza:**
- ✅ Workflow sistemático (no ad-hoc)
- ✅ Agente no decide qué ejecutar
- ✅ Reproducibilidad completa

---

## Estructura del Proyecto

```
drystone/
├── cmd/                          # CLI entry points
│   ├── main.go
│   └── commands/
│       ├── audit.go              # drystone audit
│       ├── skill.go              # drystone skill <name>
│       └── logs.go               # drystone logs
│
├── internal/
│   ├── orchestrator/             # Workflow engine
│   │   ├── engine.go             # ⭐ CRÍTICO: Core orchestration
│   │   └── workflow.go           # YAML parser + executor
│   │
│   ├── skills/                   # Skills modulares
│   │   ├── base/
│   │   │   └── skill.go          # ⭐ CRÍTICO: Interface común
│   │   ├── iam/
│   │   │   ├── skill.go          # ⭐ CRÍTICO: Patrón de referencia
│   │   │   ├── collector.go     # AWS data collection
│   │   │   └── checklist.json   # IAM security checklist
│   │   ├── exposure/             # Internet exposure audit
│   │   ├── network/              # Network policies audit
│   │   └── vulns/                # Vulnerability scanning
│   │
│   ├── agent/
│   │   └── client.go             # ⭐ CRÍTICO: Claude API integration
│   │
│   ├── aws/
│   │   └── client.go             # AWS SDK wrapper
│   │
│   └── report/
│       └── generator.go          # Report generation
│
├── configs/
│   └── workflows/
│       ├── full-audit.yaml       # ⭐ CRÍTICO: Default workflow
│       └── quick-scan.yaml
│
├── audit-logs/                   # Output (gitignored)
│   └── {account}_{session}/
│       ├── evidence/             # Raw AWS data
│       ├── findings/             # Agent analysis
│       └── reports/              # Final reports
│
├── CLAUDE.md                     # ⭐ CRÍTICO: Docs para Claude Code
├── go.mod
└── README.md
```

---

## Comandos CLI

### Audit Completo
```bash
drystone audit --profile production
# Ejecuta workflow completo, genera reporte
```

### Skill Individual
```bash
drystone skill iam --profile dev
# Solo IAM audit, útil para testing
```

### Ver Logs
```bash
drystone logs list
drystone logs show <session-id>
```

---

## Flujo de Ejecución

### 1. Usuario ejecuta audit
```bash
drystone audit --profile prod
```

### 2. Orchestrator carga workflow
```yaml
# configs/workflows/full-audit.yaml
execution:
  - phase: "collection"
    parallel: true
    skills: ["iam", "exposure", "network"]
```

### 3. Por cada skill:

**3.1 Collection (App-driven):**
```go
// internal/skills/iam/collector.go
func (c *Collector) Collect(ctx, awsClient) (*Evidence, error) {
    users := awsClient.IAM.ListUsers()
    roles := awsClient.IAM.ListRoles()
    // ... más datos AWS

    return &Evidence{Data: map[string]interface{}{
        "users": users,
        "roles": roles,
    }}
}
```

**Output:** `audit-logs/.../evidence/iam/raw-data.json`

**3.2 Analysis (Agent-driven):**
```go
// internal/agent/client.go
func (a *AgentClient) Analyze(evidence, checklist) (*AnalysisResponse, error) {
    prompt := fmt.Sprintf(`
        Eres un auditor AWS. Analiza esta evidencia:
        %s

        Contra este checklist:
        %s

        Retorna JSON con:
        {
          "findings": [...],
          "risk_score": 7.5,
          "recommendations": [...]
        }
    `, evidence, checklist)

    response := claudeAPI.Messages.Create(prompt)
    return parseJSON(response)
}
```

**Output:** `audit-logs/.../findings/iam.json`

### 4. Correlation & Reporting
```go
// internal/orchestrator/engine.go
func (e *Engine) Correlate(allFindings) {
    // Detecta attack chains cross-skill
    // Ej: IAM overprivileged + EC2 public
}

func (e *Engine) GenerateReport(findings, correlations) {
    // HTML + Markdown + JSON
}
```

**Output:**
- `reports/executive-summary.html`
- `reports/technical-report.md`
- `reports/full-audit.json`

---

## Archivos Críticos a Crear

### 1. CLAUDE.md
Documentación para Claude Code sobre cómo trabajar con drystone.

### 2. cmd/main.go
Entry point, setup de comandos con cobra.

### 3. internal/orchestrator/engine.go
Core logic: cargar workflow → ejecutar skills → correlacionar → reportar.

### 4. internal/skills/base/skill.go
Interface común:
```go
type Skill interface {
    Name() string
    Collect(ctx, aws) (*Evidence, error)
    Analyze(ctx, evidence, agent) (*Result, error)
    LoadChecklist() ([]ChecklistItem, error)
}
```

### 5. internal/skills/iam/skill.go
Primer skill completo como referencia para otros.

### 6. internal/agent/client.go
Integración con Claude API:
```go
type AgentClient interface {
    Analyze(ctx, request) (*Response, error)
}
```

### 7. configs/workflows/full-audit.yaml
Workflow por defecto con todos los skills.

### 8. internal/aws/client.go
Wrapper del AWS SDK con helpers comunes.

---

## Skills Modulares

### Checklist Format (JSON)
```json
{
  "skill": "iam",
  "items": [
    {
      "id": "IAM-001",
      "title": "Avoid root account usage",
      "severity": "Critical",
      "check": "Verify CloudTrail for root activity",
      "remediation": "Enable MFA, use IAM users"
    }
  ]
}
```

### Skill Implementation Pattern
```go
type IAMSkill struct {
    base.BaseSkill
}

func (s *IAMSkill) Collect(ctx, aws) (*Evidence, error) {
    // 1. Call AWS APIs
    // 2. Structure data
    // 3. Return Evidence
}

func (s *IAMSkill) Analyze(ctx, evidence, agent) (*Result, error) {
    checklist := s.LoadChecklist()
    // 1. Pass evidence + checklist to agent
    // 2. Parse agent response (JSON)
    // 3. Return structured Result
}
```

**Todos los skills siguen este patrón.**

---

## Workflow Configuration

```yaml
# configs/workflows/full-audit.yaml

name: "Full Security Audit"

# Preflight checks (hardcoded en app)
preflight:
  - check_aws_credentials
  - check_agent_connectivity

# Execution phases
execution:
  - phase: "independent-skills"
    parallel: true
    max_concurrent: 3
    skills:
      - name: "iam"
        timeout: "10m"
      - name: "exposure"
        timeout: "15m"
      - name: "network"
        timeout: "15m"

  - phase: "dependent-skills"
    parallel: false
    skills:
      - name: "vulns"
        timeout: "20m"
        requires: ["exposure"]  # Necesita datos previos

# Correlation rules (hardcoded en app)
correlation:
  enabled: true

# Reporting
reporting:
  formats: ["html", "markdown", "json"]
  executive_summary: true
```

---

## Output Structure

```
audit-logs/123456789012_2026-01-16T18-30-45/
├── session.json              # Metadata: duración, skills ejecutados, scores
│
├── evidence/                 # Raw AWS data (JSON)
│   ├── iam/
│   │   ├── users.json
│   │   └── roles.json
│   ├── exposure/
│   │   └── public-resources.json
│   └── network/
│       └── security-groups.json
│
├── findings/                 # Agent analysis (JSON)
│   ├── iam.json              # {findings: [...], risk_score: 7.5}
│   ├── exposure.json
│   └── network.json
│
├── correlations/             # Cross-skill analysis
│   └── attack-chains.json
│
├── reports/                  # Human-readable
│   ├── executive-summary.html
│   ├── technical-report.md
│   └── full-audit.json
│
└── logs/
    ├── orchestrator.log
    └── skills.log
```

---

## Plan de Implementación

### Fase 1: MVP (Sprint 1-2)
**Objetivo:** CLI funcional con 1 skill end-to-end

**Tareas:**
1. ✅ Setup proyecto Go + cobra
2. ✅ Comando `drystone audit`
3. ✅ AWS client wrapper (credentials, session)
4. ✅ Skill IAM completo:
   - Collector (AWS API calls)
   - Checklist JSON
   - Analyzer (Claude API)
5. ✅ Output: evidence + findings en JSON
6. ✅ Report básico (Markdown)

**Entregable:** `drystone audit --skill iam` funciona

**Validación:**
```bash
drystone audit --skill iam --profile dev
# Debe generar:
# - audit-logs/{account}_{session}/evidence/iam/raw-data.json
# - audit-logs/{account}_{session}/findings/iam.json
# - audit-logs/{account}_{session}/reports/report.md
```

---

### Fase 2: Orquestación (Sprint 3-4)
**Objetivo:** Múltiples skills con workflow

**Tareas:**
1. ✅ Orchestrator engine
2. ✅ Workflow parser (YAML)
3. ✅ Ejecución paralela de skills
4. ✅ 2 skills más: exposure + network
5. ✅ Report HTML con template

**Entregable:** `drystone audit` (sin flags) ejecuta workflow completo

**Validación:**
```bash
drystone audit --workflow configs/workflows/full-audit.yaml
# Debe ejecutar 3 skills en paralelo
# Generar reporte HTML consolidado
```

---

### Fase 3: Correlación (Sprint 5-6)
**Objetivo:** Cross-skill analysis + risk scoring

**Tareas:**
1. ✅ Correlation engine
2. ✅ Attack chain detection
3. ✅ Risk scoring algorithm
4. ✅ Dashboard HTML con charts
5. ✅ Skill vulns

**Entregable:** Reportes profesionales con correlación

---

### Fase 4: Advanced (Ongoing)
- Más skills (AMC, etc.)
- Compare audits (trends)
- CI/CD integration
- Webhook notifications

---

## CLAUDE.md - Contenido Propuesto

```markdown
# Drystone - AWS Security Audit CLI

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

## Próximos Pasos

- [ ] Completar skill vulns
- [ ] Agregar skill AMC
- [ ] Correlation engine v2 (attack graphs)
- [ ] Compare audits (trend analysis)
```

---

## Verificación End-to-End

### Setup
```bash
cd /Users/gcuesta/Projects/drystone

# Inicializar Go project
go mod init github.com/gcuesta/drystone

# Instalar dependencias
go get github.com/spf13/cobra
go get github.com/aws/aws-sdk-go-v2
go get github.com/anthropics/anthropic-sdk-go
```

### Test Fase 1 (IAM Skill)
```bash
# Build
make build

# Configurar AWS
export AWS_PROFILE=dev

# Ejecutar
./bin/drystone audit --skill iam

# Verificar output
ls -la audit-logs/
cat audit-logs/*/evidence/iam/raw-data.json
cat audit-logs/*/findings/iam.json
cat audit-logs/*/reports/report.md
```

**Success criteria:**
- ✅ Comando ejecuta sin errores
- ✅ Crea directorio session
- ✅ Guarda evidencia JSON
- ✅ Llama a Claude API
- ✅ Genera findings JSON
- ✅ Genera reporte Markdown

### Test Fase 2 (Full Workflow)
```bash
./bin/drystone audit --workflow configs/workflows/full-audit.yaml
```

**Success criteria:**
- ✅ Ejecuta múltiples skills
- ✅ Ejecución paralela funciona
- ✅ Genera reporte consolidado HTML
- ✅ Session metadata completo

### Test Fase 3 (Correlation)
```bash
./bin/drystone audit

# Verificar correlación
cat audit-logs/*/correlations/attack-chains.json
```

**Success criteria:**
- ✅ Detecta attack chains cross-skill
- ✅ Risk scoring agregado correcto
- ✅ Dashboard HTML con visualización

---

## Decisiones Clave

### 1. App Orquesta, Agente Analiza
**Decisión:** Workflow hardcoded/YAML en app, agent solo recibe datos.

**Razón:** Determinismo, reproducibilidad, debugging, control de costos.

### 2. Skills Modulares
**Decisión:** Interface común, implementaciones independientes.

**Razón:** Testability, reutilización, fácil agregar skills.

### 3. Evidence-First
**Decisión:** Guardar raw data antes de analizar.

**Razón:** Audit trail, re-análisis sin re-fetch, debugging.

### 4. Go como Stack
**Decisión:** Go vs Python/TypeScript.

**Razón:** CLI tools, distribución (binario estático), AWS SDK completo, performance.

### 5. Claude API Direct (MVP)
**Decisión:** Empezar con API directa, considerar MCP después.

**Razón:** Simplicidad, time to market, evitar over-engineering.

---

## Resumen

**Proyecto:** drystone = CLI de auditoría AWS con análisis Claude
**Stack:** Go + Cobra + AWS SDK + Claude API
**Arquitectura:** App-orchestrated workflow, agent-based analysis
**Output:** `audit-logs/` estilo shannon

**Fases:**
1. MVP (1 skill) → 2-3 semanas
2. Orquestación (3 skills + workflow) → 2 semanas
3. Correlación + scoring → 2 semanas
4. Advanced features → ongoing

**Primer milestone:** `drystone audit --skill iam` funcional end-to-end

---

## Esquema de Directorios Inicial

### Estructura Mínima para Empezar (Fase 1 - MVP)

```
drystone/
├── .gitignore
├── README.md
├── CLAUDE.md
├── Makefile
├── go.mod
├── go.sum
│
├── cmd/
│   ├── main.go
│   └── commands/
│       ├── root.go           # Root command setup
│       ├── audit.go          # audit command
│       └── skill.go          # skill command
│
├── internal/
│   ├── orchestrator/
│   │   └── engine.go         # Orchestrator básico
│   │
│   ├── skills/
│   │   ├── base/
│   │   │   ├── skill.go      # Interface Skill
│   │   │   └── evidence.go   # Evidence struct
│   │   │
│   │   └── iam/
│   │       ├── skill.go      # IAM skill implementation
│   │       ├── collector.go  # AWS data collection
│   │       └── checklist.json
│   │
│   ├── aws/
│   │   ├── client.go         # AWS SDK wrapper
│   │   └── session.go        # Session management
│   │
│   ├── agent/
│   │   ├── client.go         # AgentClient interface
│   │   ├── claude.go         # Claude API implementation
│   │   └── prompts.go        # Prompt templates
│   │
│   ├── storage/
│   │   └── session.go        # Session directory manager
│   │
│   └── report/
│       └── markdown.go       # Markdown report generator
│
├── pkg/
│   └── models/
│       ├── finding.go        # Finding struct
│       └── evidence.go       # Evidence struct
│
├── configs/
│   └── workflows/
│       └── iam-only.yaml     # Simple workflow for testing
│
├── scripts/
│   └── setup.sh              # Helper scripts
│
└── audit-logs/               # Created at runtime (gitignored)
```

### Comandos para Crear Estructura

```bash
#!/bin/bash
# Ejecutar desde /Users/gcuesta/Projects/drystone

# Crear directorios
mkdir -p cmd/commands
mkdir -p internal/{orchestrator,aws,agent,storage,report}
mkdir -p internal/skills/{base,iam}
mkdir -p pkg/models
mkdir -p configs/workflows
mkdir -p scripts
mkdir -p audit-logs

# Crear archivos vacíos (placeholders)
touch cmd/main.go
touch cmd/commands/{root,audit,skill}.go

touch internal/orchestrator/engine.go

touch internal/skills/base/{skill,evidence}.go
touch internal/skills/iam/{skill,collector}.go

touch internal/aws/{client,session}.go
touch internal/agent/{client,claude,prompts}.go
touch internal/storage/session.go
touch internal/report/markdown.go

touch pkg/models/{finding,evidence}.go

touch configs/workflows/iam-only.yaml

# Inicializar Go module
go mod init github.com/gcuesta/drystone

# Crear .gitignore
cat > .gitignore << 'EOF'
# Binaries
bin/
*.exe
*.dll
*.so
*.dylib

# Go
*.test
*.out
vendor/

# Output
audit-logs/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
EOF

# Crear Makefile básico
cat > Makefile << 'EOF'
.PHONY: build install test clean run

build:
	go build -o bin/drystone cmd/main.go

install:
	go install cmd/main.go

test:
	go test -v ./...

clean:
	rm -rf bin/ audit-logs/

run-iam:
	./bin/drystone audit --skill iam

fmt:
	go fmt ./...

lint:
	golangci-lint run
EOF

# Crear README básico
cat > README.md << 'EOF'
# Drystone

AWS Security Audit CLI powered by Claude.

## Status

🚧 **En desarrollo - Fase 1: MVP**

## Quick Start

```bash
# Build
make build

# Run IAM audit
./bin/drystone audit --skill iam --profile dev
```

## Architecture

Ver `CLAUDE.md` para detalles completos.
EOF

echo "✅ Estructura creada"
echo "📋 Próximo paso: Implementar archivos Go"
```

### Archivos Prioritarios a Implementar

**Orden sugerido:**

1. **go.mod** → `go mod init`
2. **internal/skills/base/skill.go** → Interface `Skill`
3. **pkg/models/evidence.go** → Struct `Evidence`
4. **pkg/models/finding.go** → Struct `Finding`
5. **internal/aws/client.go** → AWS SDK wrapper
6. **internal/skills/iam/collector.go** → Primer collector
7. **internal/agent/client.go** → Interface `AgentClient`
8. **internal/agent/claude.go** → Implementación Claude API
9. **internal/skills/iam/skill.go** → Implementación completa skill
10. **cmd/commands/root.go** → Setup cobra
11. **cmd/commands/audit.go** → Comando audit
12. **cmd/main.go** → Entry point
13. **internal/storage/session.go** → Session management
14. **internal/report/markdown.go** → Report generator
15. **configs/workflows/iam-only.yaml** → Workflow simple
16. **CLAUDE.md** → Documentación

### Script de Setup Completo

```bash
#!/bin/bash
# scripts/setup.sh

set -e

echo "🚀 Configurando proyecto drystone..."

# Verificar que estamos en el directorio correcto
if [ ! -d "/Users/gcuesta/Projects/drystone" ]; then
    echo "❌ Error: No estás en /Users/gcuesta/Projects/drystone"
    exit 1
fi

# Crear estructura
echo "📁 Creando estructura de directorios..."
mkdir -p cmd/commands
mkdir -p internal/{orchestrator,aws,agent,storage,report}
mkdir -p internal/skills/{base,iam}
mkdir -p pkg/models
mkdir -p configs/workflows
mkdir -p scripts

# Inicializar Go module
echo "📦 Inicializando Go module..."
go mod init github.com/gcuesta/drystone

# Instalar dependencias básicas
echo "📥 Instalando dependencias..."
go get github.com/spf13/cobra@latest
go get github.com/spf13/viper@latest
go get github.com/aws/aws-sdk-go-v2/config@latest
go get github.com/aws/aws-sdk-go-v2/service/iam@latest
go get github.com/anthropics/anthropic-sdk-go@latest
go get github.com/rs/zerolog@latest

# Crear archivos de configuración
echo "⚙️ Creando archivos de configuración..."

# .gitignore
cat > .gitignore << 'GITIGNORE'
bin/
audit-logs/
*.exe
*.dll
*.so
*.dylib
*.test
*.out
vendor/
.vscode/
.idea/
.DS_Store
GITIGNORE

# Makefile
cat > Makefile << 'MAKEFILE'
.PHONY: build test clean run fmt

build:
	@echo "🔨 Building drystone..."
	@go build -o bin/drystone cmd/main.go
	@echo "✅ Built: bin/drystone"

test:
	@go test -v ./...

clean:
	@rm -rf bin/ audit-logs/
	@echo "🧹 Cleaned"

run-iam:
	@./bin/drystone audit --skill iam

fmt:
	@go fmt ./...

install-deps:
	@go mod download
	@go mod tidy

MAKEFILE

# README.md
cat > README.md << 'README'
# Drystone 🪨

AWS Security Audit CLI powered by Claude.

## Status

🚧 **En desarrollo - Fase 1: MVP**

Objetivo: `drystone audit --skill iam` funcional end-to-end

## Quick Start

```bash
# Setup
./scripts/setup.sh

# Build
make build

# Run
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
```

## Output

```
audit-logs/{account}_{session}/
├── evidence/          # Raw AWS data
├── findings/          # Agent analysis
└── reports/           # Human-readable reports
```
README

echo "✅ Setup completo!"
echo ""
echo "📋 Próximos pasos:"
echo "   1. Implementar internal/skills/base/skill.go (interface)"
echo "   2. Implementar pkg/models/*.go (structs)"
echo "   3. Implementar internal/aws/client.go"
echo "   4. Implementar internal/skills/iam/* (primer skill)"
echo "   5. make build && make run-iam"
echo ""
echo "📚 Ver CLAUDE.md para guía completa de desarrollo"
```

### Checklist Pre-Desarrollo

Antes de empezar a implementar, asegúrate de tener:

- ✅ Go 1.21+ instalado
- ✅ AWS CLI configurado con credenciales
- ✅ Claude API key (variable `ANTHROPIC_API_KEY`)
- ✅ Git configurado
- ✅ Editor con Go support (VS Code + Go extension recomendado)

### Siguiente Paso

Cuando estés listo para empezar desarrollo:

```bash
cd /Users/gcuesta/Projects/drystone
./scripts/setup.sh
# Luego empezar a implementar archivos Go
```
