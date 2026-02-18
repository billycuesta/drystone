# Drystone - Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENTRY POINT                                  │
│  python -m drystone audit                                           │
│  __main__.py → cli/main.py → audit()                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 0: WIZARD                          cli/ui/wizard.py         │
│                                                                     │
│  Menu A: Project & AWS Scope        Menu B: AI Configuration        │
│  ├─ Client name                     ├─ Provider (CLI / API)         │
│  ├─ AWS credentials (4 methods)     └─ API key (if API)             │
│  ├─ Region                                                          │
│  ├─ Skills (13 disponibles)                                         │
│  ├─ Output formats (md/json/pdf)                                    │
│  └─ Report type (general/pci-dss/pentest)                           │
│                                                                     │
│  Output: WizardConfig (Pydantic) → ~/.drystone/config.json          │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1: AWS VALIDATION               cloud/aws/client.py         │
│                                                                     │
│  boto3 → STS get_caller_identity()                                  │
│  Output: account_id + AuditSession created                          │
│          audit-logs/{client}_{timestamp}/                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1a: EVIDENCE COLLECTION    skills/{skill}/__init__.py        │
│  (ThreadPoolExecutor - parallel)                                    │
│                                                                     │
│  ┌──────┐ ┌──────────┐ ┌─────────┐ ┌───────┐ ┌──────────┐         │
│  │ IAM  │ │ Exposure │ │ Network │ │ Vulns │ │ Alerting │ ...      │
│  └──┬───┘ └────┬─────┘ └────┬────┘ └───┬───┘ └────┬─────┘         │
│     │          │            │           │          │                 │
│     ▼          ▼            ▼           ▼          ▼                 │
│  skill.collect(aws_client, session) → boto3 → AWS APIs              │
│                                                                     │
│  Output: evidence/{skill}/*.json                                    │
│  (users.json, roles.json, buckets.json, vpcs.json, ...)             │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 1b: 3-TIER ANALYSIS              skills/base.py → analyze() │
│  (ThreadPoolExecutor - parallel per skill)                          │
│                                                                     │
│  For each skill:                                                    │
│  ┌─────────────────────────────────────────────────────┐            │
│  │                                                     │            │
│  │  ┌─────────────────────────────────────────────┐    │            │
│  │  │  TIER 1: PRE-CHECKS (deterministic, <1s)    │    │            │
│  │  │  validation/pre_checks.py                    │    │            │
│  │  │                                              │    │            │
│  │  │  evidence + checklist → run_pre_checks()     │    │            │
│  │  │  Output: PreCheckResult[] (PASS/FAIL/SKIP)   │    │            │
│  │  │                                              │    │            │
│  │  │  69 checks across 13 skills:                 │    │            │
│  │  │  IAM(8) HRD(11) ALR(2) EXP(9) NET(3)        │    │            │
│  │  │  WAF(5) VULN(3) SM(2) ECR(4) KMS(4)         │    │            │
│  │  │  MSG(4) CICD(2) COMP(5)                      │    │            │
│  │  └──────────────────────┬──────────────────────┘    │            │
│  │                         │                            │            │
│  │                         ▼                            │            │
│  │  ┌─────────────────────────────────────────────┐    │            │
│  │  │  TIER 2: AI ANALYSIS (constrained)           │    │            │
│  │  │  agent/client.py                             │    │            │
│  │  │                                              │    │            │
│  │  │  Prompt = XML template + evidence            │    │            │
│  │  │        + <pre_computed_facts> (Tier 1)       │    │            │
│  │  │                                              │    │            │
│  │  │  Rules injected:                             │    │            │
│  │  │  • PASS → DO NOT generate finding            │    │            │
│  │  │  • FAIL → Generate with description/remed.   │    │            │
│  │  │  • Not listed → Analyze evidence yourself    │    │            │
│  │  │                                              │    │            │
│  │  │  ┌── Claude CLI ─────┐ ┌── Claude API ────┐  │    │            │
│  │  │  │ analyze_evidence  │ │ analyze_evidence │  │    │            │
│  │  │  │ _chunked() +     │ │ _chunked() +     │  │    │            │
│  │  │  │ retry             │ │ retry            │  │    │            │
│  │  │  └──────────────────┘ └──────────────────┘  │    │            │
│  │  └──────────────────────┬──────────────────────┘    │            │
│  │                         │                            │            │
│  │                         ▼                            │            │
│  │  ┌─────────────────────────────────────────────┐    │            │
│  │  │  TIER 3: RECONCILIATION + NORMALIZATION      │    │            │
│  │  │  base.py + validation/                       │    │            │
│  │  │                                              │    │            │
│  │  │  3a. _reconcile_with_pre_checks()            │    │            │
│  │  │      • Reject AI findings contradicting PASS │    │            │
│  │  │      • Inject findings for missed FAILs      │    │            │
│  │  │                                              │    │            │
│  │  │  3b. findings_normalizer.py                  │    │            │
│  │  │      • Dedup, severity calibration           │    │            │
│  │  │      • Evidence validation (non-pre-checked) │    │            │
│  │  │      • Pre-checked IDs → SKIP validation     │    │            │
│  │  │                                              │    │            │
│  │  │  3c. checklist_coverage.py                   │    │            │
│  │  │      • Missing critical checks detection     │    │            │
│  │  │                                              │    │            │
│  │  │  3d. queue_validator.py                      │    │            │
│  │  │      • Pre-correlation gate                  │    │            │
│  │  └──────────────────────────────────────────────┘    │            │
│  └─────────────────────────────────────────────────┘    │            │
│                                                         │            │
│  Output: SkillFindings → findings/{skill}.json          │            │
│  (+ validation_commands derived from evidence refs)      │            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 2: CORRELATION              correlation/engine.py            │
│  (Solo si ≥2 skills ejecutados)                                     │
│                                                                     │
│  1. Build resource index (O(n), cached)                             │
│  2. Apply patterns from patterns.py                                 │
│     (IAM+Exposure, Network+Vulns, KMS+IAM, CICD+Messaging...)      │
│  3. Generate attack chains                                          │
│  4. Limits: 50/pattern, 200 total, 60s timeout                     │
│                                                                     │
│  Output: CorrelatedFindings + attack chains                         │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 3: REPORT GENERATION           reports/generator.py          │
│                                                                     │
│  Post-processors (skill-specific):                                  │
│  ├─ alerting/post_processor.py  → Architecture diagram              │
│  ├─ waf/post_processor.py       → Protection flow                   │
│  └─ network/post_processor.py   → Topology diagram                  │
│                                                                     │
│  Formatters:                                                        │
│  ┌────────────┐ ┌───────────┐ ┌─────────┐ ┌─────────────┐          │
│  │  Markdown   │ │  PCI DSS  │ │ Pentest │ │    JSON     │          │
│  │  (general)  │ │ (control  │ │ (attack │ │ (machine    │          │
│  │  ASCII      │ │  table    │ │  chains │ │  readable)  │          │
│  │  charts     │ │  ✅/❌/⚠️) │ │  paths) │ │             │          │
│  └─────────────┘ └───────────┘ └─────────┘ └─────────────┘          │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  PDF (WeasyPrint)                                             │    │
│  │  reports/formats/pdf.py + reports/templates/pdf_report.xml    │    │
│  │  Visual report with styled header + scope + findings cards    │    │
│  └───────────────────────────────────────────────────────────────┘    │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  Pentest PDF (attack chains)                                  │    │
│  │  reports/formats/pentest_pdf.py                               │    │
│  │  Reuses shared PDF template (pdf_report.xml) for visual parity│    │
│  └───────────────────────────────────────────────────────────────┘    │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  Validation commands for reproducibility                      │    │
│  │  reports/validation_commands.py                               │    │
│  │  AWS CLI commands mapped from evidence_refs per skill         │    │
│  └───────────────────────────────────────────────────────────────┘    │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  Finding exploitation narrative                               │    │
│  │  PDF section: "Exploitation (Theoretical)" per finding       │    │
│  │  Derived from finding fields + command fallbacks              │    │
│  └───────────────────────────────────────────────────────────────┘    │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  Pentest Methodology section                                 │    │
│  │  reports/formats/pentest.py                                  │    │
│  │  PTES-adapted phases (+ PDF Methodology block for pentest)    │    │
│  └───────────────────────────────────────────────────────────────┘    │
│  ┌───────────────────────────────────────────────────────────────┐    │
│  │  Pentest exploitation enricher                                │    │
│  │  pentest/exploitation_enricher.py                             │    │
│  │  Adds exploitation_description + exploitation_commands         │    │
│  │  from evidence context (report_type=pentest only)             │    │
│  └───────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  Output: reports/*.{md|json|pdf}                                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PHASE 4: SESSION & METRICS           storage/session.py            │
│                                       logging/metrics_tracker.py    │
│                                                                     │
│  audit-logs/{client}_{timestamp}/                                   │
│  ├── evidence/{skill}/*.json      ← Raw AWS data                   │
│  ├── findings/{skill}.json        ← Normalized findings            │
│  ├── reports/*.md|*.json|*.pdf    ← Generated reports              │
│  ├── metrics.json                 ← Timing, counts, risk scores    │
│  └── audit.log                    ← Structured log                  │
└─────────────────────────────────────────────────────────────────────┘
```

## 3-Tier Validation Architecture

```
Evidence ─────►  Tier 1 (Pre-checks) ─────►  Tier 2 (AI) ─────►  Tier 3 (Reconcile)
                 DETERMINISTIC                CONSTRAINED          POST-VALIDATE
                 pre_checks.py                agent/client.py      base.py + normalizer

                 69 binary checks             Receives              • Reject PASS
                 PASS / FAIL / SKIP           <pre_computed_facts>    contradictions
                 ~1s, 100% reproducible       as XML in prompt      • Inject missed FAILs
                                              AI focuses on         • Normalize + dedup
                                              complex checks          (skip pre-checked)
```

### Data flow per check ID

```
Check IAM-001 (Root MFA):

  Tier 1: evidence["account-summary"]["AccountMFAEnabled"] == 1?
          → PASS (deterministic)

  Tier 2: <fact id="IAM-001" status="PASS">
            AI instructed: "DO NOT generate finding"

  Tier 3: If AI generates IAM-001 anyway → REJECTED
          normalizer skips IAM-001 evidence validation (already resolved)


Check IAM-008 (Admin policies):

  Tier 1: evidence["policies"] has Action:*/Resource:*?
          → FAIL (deterministic)

  Tier 2: <fact id="IAM-008" status="FAIL">
            AI writes professional description + remediation

  Tier 3: If AI missed IAM-008 → INJECTED from checklist
          normalizer skips IAM-008 evidence validation


Check IAM-005 (Password policy complexity):

  Tier 1: No pre-check registered → not in results

  Tier 2: No <fact> for IAM-005 → AI analyzes evidence itself

  Tier 3: Normal normalizer flow (evidence validation, severity calibration)
```

### Impact metrics

| Metric | Before (AI only) | After (3-Tier) |
|--------|-------------------|-----------------|
| False positives (Tier 1 checks) | ~5-7% | **~0%** |
| Missing criticals (Tier 1) | AI-dependent | **Deterministic injection** |
| Reproducibility (Tier 1) | Variable | **100%** |
| Tokens to AI | 100% evidence analysis | Evidence + pre-computed hints |
| Post-validation for Tier 1 | Full normalizer | **Skipped** (already resolved) |
| Deterministic checks | 0 pre-AI | **69** across 13 skills |

## Skills disponibles (13)

| Skill | AWS Services | Checks | Pre-checks |
|-------|-------------|--------|------------|
| `iam` | IAM users, roles, policies | MFA, access keys, permissions | 8 |
| `exposure` | S3, RDS, ELB, EC2 | Public endpoints, open buckets | 9 |
| `network` | VPC, SGs, NACLs, TGW | Open ports, routing rules | 3 |
| `vulns` | Inspector v2 | Known CVEs, patch status | 3 |
| `alerting` | CloudTrail, CloudWatch, SNS | Event monitoring coverage | 2 |
| `hardening` | Config, Security Hub | CIS/PCI compliance score | 11 |
| `ecr` | ECR | Image scanning, registry config | 4 |
| `secretsmanager` | Secrets Manager | Rotation, encryption | 2 |
| `waf` | WAF, CloudFront, ALB | Rule coverage, protection gaps | 5 |
| `kms` | KMS | Key rotation, policies | 4 |
| `messaging` | SQS, SNS | Encryption, access policies | 4 |
| `cicd` | CodeBuild | Build security, secrets in env | 2 |
| `compute` | ECS, EKS | Container hardening | 5 |

## Arquitectura clave

**Principio:** App orquesta, Agent analiza. Pre-checks resuelven lo determinista.

```
App (Python)                    Agent (Claude)
├─ Wizard + Config              ├─ Recibe evidence JSON
├─ AWS credential mgmt    →    ├─ Recibe <pre_computed_facts>
├─ boto3 data collection        ├─ Respeta PASS/FAIL verdicts
├─ Evidence persistence    →    ├─ Analiza checks complejos
├─ PRE-CHECKS (Tier 1)         ├─ Genera description/remediation
├─ Parse findings          ←    └─ Retorna findings JSON
├─ Reconciliation (Tier 3)
├─ Normalization (skip pre-checked)
├─ Correlation cross-skill
└─ Report generation
```

## Puntos clave para tuning

1. **Pre-checks** (`validation/pre_checks.py`) - Tier 1 determinista, 100% reproducible
2. **Prompts XML** (`prompts/templates/`) - Calidad de findings para checks complejos
3. **Findings normalizer** - Reduce varianza (skips pre-checked IDs)
4. **Checklists** - Determinan qué busca el agente (y qué pre-checks existen)
5. **Correlation patterns** - Attack chains cross-skill

## Pentest methodology diagram

- Detailed pentest-mode workflow and methodology mapping:
  - `drystone-specs/drystone-pentest-methodology.md`

## Regla de mantenimiento documental

- Cuando se haga un cambio relevante en arquitectura/reporting/flujo:
  - actualizar `opencode.md` para mantener contexto operativo vigente.
  - actualizar `drystone-specs/drystone-architecture.md` cuando el cambio impacte arquitectura o flujo.

## Key files

| File | Role |
|------|------|
| `validation/pre_checks.py` | Tier 1: 69 deterministic checks, registry, XML formatter |
| `skills/base.py` | Orchestrates 3-tier flow in `analyze()`, reconciliation |
| `agent/client.py` | Tier 2: Injects `<pre_computed_facts>` via SKILL_ADDENDUM |
| `validation/findings_normalizer.py` | Tier 3: Skips pre-checked IDs, handles complex checks |
| `validation/checklist_coverage.py` | Coverage gap detection |
| `validation/queue_validator.py` | Pre-correlation gate |

## Modulo CLI y Wizard (`drystone/cli/main.py`, `drystone/cli/ui/wizard.py`)

```
Objetivo:
- Ser la puerta de entrada de toda auditoria (`python -m drystone audit`).
- Recoger configuracion del usuario (cliente, credenciales, region, skills, formatos, tipo de reporte, proveedor AI).

Como funciona:
- `main.py` define comandos/opciones de Click y decide si usar wizard interactivo o argumentos directos.
- `wizard.py` guía al usuario por menus (scope AWS + configuracion AI) y retorna un `WizardConfig`.
- El resultado se valida con Pydantic y se usa para iniciar la sesion de auditoria.

Valor en el flujo:
- Estandariza la entrada y evita ejecuciones inconsistentes por parametros incompletos.
```

## Modulo Configuracion (`drystone/models/config.py`)

```
Objetivo:
- Definir un contrato fuerte de configuracion (tipos, defaults, validaciones).

Como funciona:
- `WizardConfig` centraliza campos clave: credenciales, skills, formatos, report_type, AI provider.
- Validadores aplican reglas de negocio (skills permitidos, coherencia report_type, API key requerida segun proveedor, etc.).

Valor en el flujo:
- Convierte entrada del usuario en un objeto confiable para todas las fases posteriores.
```

## Modulo Sesion y Persistencia (`drystone/storage/session.py`)

```
Objetivo:
- Crear y estructurar el workspace de una auditoria para trazabilidad completa.

Como funciona:
- Genera `audit-logs/{client}_{timestamp}/`.
- Expone rutas utilitarias para `evidence/`, `findings/`, `reports/`.
- Inicializa logging de archivo por sesion.

Valor en el flujo:
- Garantiza que cada ejecucion tenga artefactos aislados, auditables y reproducibles.
```

## Modulo Validacion AWS (`drystone/cloud/aws/client.py`)

```
Objetivo:
- Verificar temprano que las credenciales AWS son validas y obtener contexto de cuenta.

Como funciona:
- Ejecuta `STS GetCallerIdentity` con boto3.
- Devuelve `account_id` y contexto base para la auditoria.

Valor en el flujo:
- Evita correr coleccion y analisis con credenciales invalidas o cuenta inesperada.
```

## Modulo Skills de recoleccion (`drystone/skills/*/__init__.py`)

```
Objetivo:
- Obtener evidencia cruda de cada dominio de seguridad (IAM, Exposure, Network, Vulns, etc.).

Como funciona:
- Cada skill implementa `collect()` con llamadas boto3 al servicio correspondiente.
- Guarda evidencia en JSON (y artefactos especiales cuando aplica, p.ej. CSV de IAM).
- La ejecucion es paralela entre skills para reducir tiempo total.

Valor en el flujo:
- Separa claramente “recoleccion factual” de “interpretacion AI”.
```

## Modulo Pre-checks deterministas (Tier 1) (`drystone/validation/pre_checks.py`)

```
Objetivo:
- Resolver por codigo las comprobaciones binarias obvias y reproducibles.

Como funciona:
- Evalua evidencia+checklist y produce PASS/FAIL/SKIP por check.
- Devuelve hechos precomputados que luego se inyectan al prompt AI.

Valor en el flujo:
- Reduce falsos positivos y variabilidad en checks donde no hace falta inferencia LLM.
```

## Modulo Cliente AI y chunking (Tier 2 base) (`drystone/agent/client.py`, `drystone/agent/chunker.py`)

```
Objetivo:
- Ejecutar analisis AI de forma robusta sobre evidencia grande.

Como funciona:
- Construye prompt estructurado (plantilla + checklist + evidencia + pre_facts).
- Usa chunking para dividir evidencia extensa.
- Soporta Claude CLI/API con reintentos y manejo de errores.

Valor en el flujo:
- Permite escalar analisis sin romper por limite de contexto.
```

## Modulo Validacion de salida AI (`drystone/validation/output_validators.py`, `drystone/validation/reviewer.py`)

```
Objetivo:
- Asegurar que la salida del agente tenga estructura, consistencia y calidad minima antes de normalizar/reportar.

Como funciona:
- `output_validators.py` valida y corrige incoherencias estructurales (conteos, severidades, campos requeridos).
- `reviewer.py` aplica reglas de revision sobre findings para detectar gaps de calidad y priorizacion.
- Si hay inconsistencias no criticas, intenta reconciliarlas sin romper el flujo.

Valor en el flujo:
- Reduce drift en outputs AI y evita que errores de formato/consistencia lleguen al reporte final.
```

## Modulo Reconciliacion y Normalizacion (Tier 3) (`drystone/skills/base.py`, `drystone/validation/findings_normalizer.py`)

```
Objetivo:
- Convertir salida AI en findings consistentes, verificables y alineados al checklist.

Como funciona:
- Reconciliacion con pre-checks:
  - Rechaza findings que contradicen PASS.
  - Inyecta findings faltantes cuando hay FAIL no reportado.
- Normalizador:
  - Dedup, calibracion de severidad/risk score, validacion contra evidencia, reglas anti-falsos positivos.

Valor en el flujo:
- Capa final de control de calidad antes de reportar/correlacionar.
```

## Modulo Cobertura y Gate de cola (`drystone/validation/checklist_coverage.py`, `drystone/validation/queue_validator.py`)

```
Objetivo:
- Asegurar que no se pierdan checks importantes y que la salida minima sea estructuralmente valida.

Como funciona:
- `checklist_coverage` detecta huecos de cobertura (checks criticos no reflejados).
- `queue_validator` actua como compuerta antes de correlacion para detectar estados rotos.

Valor en el flujo:
- Previene que fases aguas abajo trabajen con findings incompletos o inconsistentes.
```

## Modulo Correlacion (Phase 2) (`drystone/correlation/engine.py`, `patterns.py`)

```
Objetivo:
- Unir findings de distintos skills para detectar cadenas de ataque y riesgo compuesto.

Como funciona:
- Indexa recursos, aplica patrones de correlacion y limita volumen/tiempo.
- Produce correlaciones con contexto de explotabilidad, impacto y relaciones entre hallazgos.

Valor en el flujo:
- Pasa de “lista de problemas aislados” a “escenarios de riesgo reales”.
```

## Modulo Reportes (Phase 3) (`drystone/reports/generator.py`, `drystone/reports/formats/*`)

```
Objetivo:
- Convertir findings/correlaciones en salidas consumibles por equipos tecnicos y compliance.

Como funciona:
- `generator.py` orquesta formateadores y post-procesadores.
- Formatos: General Markdown, PCI DSS, Pentest y JSON.
- En modo pentest puede consolidar salida para vista de engagement completo.

Valor en el flujo:
- Entrega final accionable con trazabilidad a evidencia.
```

## Modulo Metricas y observabilidad (`drystone/logging/metrics_tracker.py`, `audit.log`)

```
Objetivo:
- Medir rendimiento/calidad y facilitar debugging operativo.

Como funciona:
- Registra tiempos, contadores y metrica operativa por sesion/skill.
- Mantiene logs por sesion para reconstruir el flujo de ejecucion.

Valor en el flujo:
- Base para QA iterativo, tuning de prompts/rules y mejora continua.
```
