# Plan: Script de Testing E2E para Drystone

## 🎯 Objetivo

Crear un script Python que ejecute **todas las combinaciones posibles** de auditorías Drystone para validar que todo funciona correctamente antes de releases.

**Script debe:**
- Aceptar path a credentials AWS
- Ejecutar todas las combinaciones automáticamente (skills × report types × formats)
- Capturar errores y continuar
- Generar reporte de resultados (pass/fail)
- Mostrar progreso visual

---

## 📊 Combinaciones a Probar

### Single-skill tests (24 tests):
- **Skills:** 6 (iam, exposure, network, vulns, alerting, hardening)
- **Report types:** 2 (general, pci-dss)
- **Formats:** 2 (markdown, json)
- **Total:** 6 × 2 × 2 = **24 combinaciones**

### Multi-skill tests (60 tests, opcional):
- **Skill pairs:** C(6,2) = 15 combinaciones
- **Report types:** 2
- **Formats:** 2
- **Total:** 15 × 2 × 2 = **60 combinaciones adicionales**

**Gran Total:** 84 tests con `--multi-skill`

---

## 🏗️ Arquitectura del Script

### Ubicación
`/Users/gcuesta/Projects/drystone/scripts/e2e_test_runner.py`

### Clases Principales

```python
class TestCombination:
    """Representa una combinación de test específica"""
    skill: str                  # "iam" o "iam+exposure"
    report_type: str            # "general" o "pci-dss"
    format: str                 # "markdown" o "json"
    test_id: str                # "iam_general_markdown"
    multi_skill: bool = False

class TestResult:
    """Resultado de ejecución de un test"""
    combination: TestCombination
    status: str                 # "PASS", "FAIL", "ERROR", "SKIP"
    duration: float             # Segundos
    error_message: Optional[str]
    stack_trace: Optional[str]
    artifacts: Dict[str, Path]  # evidence, findings, reports

class E2ETestRunner:
    """Orquestador principal"""
    combinations: List[TestCombination]
    results: List[TestResult]
    credentials: Dict           # AWS credentials
    dry_run: bool
    clean_sessions: bool
    parallel: int               # Workers paralelos
```

---

## 🔧 CLI Interface (Click)

```bash
python scripts/e2e_test_runner.py \
  --credentials ~/.aws/credentials.json \  # REQUIRED
  --dry-run \                              # Mostrar plan sin ejecutar
  --clean \                                # Limpiar audit-logs antes
  --skills iam exposure \                  # Filtrar skills específicos
  --report-types pci-dss \                 # Filtrar report types
  --formats markdown \                     # Filtrar formatos
  --multi-skill \                          # Incluir combinaciones multi-skill
  --parallel 3 \                           # Ejecutar 3 tests en paralelo
  --output /tmp/test-results \             # Directorio output
  --fail-fast \                            # Parar en primer fallo
  --region us-east-1                       # AWS region
```

**Opciones:**
- `--credentials` (required): Path a JSON con AWS credentials
- `--dry-run`: Mostrar qué se ejecutaría sin ejecutar
- `--clean`: Limpiar `audit-logs/` antes de comenzar
- `--skills`: Filtrar skills específicos (default: todos)
- `--report-types`: Filtrar report types (default: ambos)
- `--formats`: Filtrar formatos (default: ambos)
- `--multi-skill`: Incluir tests con múltiples skills
- `--parallel`: Workers paralelos (default: 1)
- `--output`: Directorio para resultados (default: test-results/)
- `--fail-fast`: Parar en primer error
- `--region`: AWS region (default: us-east-1)

---

## 📝 Funciones Clave

### 1. Gestión de Credenciales

```python
def load_credentials(creds_file: Path) -> Dict:
    """Load AWS credentials from JSON file

    Expected format:
    {
      "aws_access_key_id": "AKIA...",
      "aws_secret_access_key": "...",
      "aws_session_token": "..."  # Optional
    }
    """
```

### 2. Generación de Combinaciones

```python
def generate_combinations(
    skills: Optional[List[str]] = None,
    report_types: Optional[List[str]] = None,
    formats: Optional[List[str]] = None,
    multi_skill: bool = False
) -> List[TestCombination]:
    """Generate all test combinations

    Single-skill: skill × report_type × format
    Multi-skill (optional): pairs of skills × report_type × format
    """
```

### 3. Creación de Config

```python
def create_test_config(
    combination: TestCombination,
    credentials: Dict,
    base_client_name: str = "E2ETest"
) -> WizardConfig:
    """Create WizardConfig for specific test

    Returns config with:
    - Unique client_name (includes test_id for isolation)
    - AWS credentials from file
    - Specific skill(s), report_type, format(s)
    - AI provider: claude-cli (faster, no API key needed)
    """
```

### 4. Ejecución de Test

```python
def execute_test(
    combination: TestCombination,
    config: WizardConfig,
    dry_run: bool = False
) -> TestResult:
    """Execute single test via subprocess

    Steps:
    1. Build command: python -m drystone audit --non-interactive ...
    2. Set AWS credentials in environment
    3. Execute with 10 min timeout
    4. Capture stdout/stderr
    5. Validate artifacts
    6. Return TestResult
    """
```

### 5. Validación de Artifacts

```python
def validate_test_artifacts(
    combination: TestCombination,
    session_path: Path
) -> Tuple[bool, Optional[str]]:
    """Validate all expected artifacts were generated

    Checks:
    - evidence/{skill}/*.json exists (non-empty)
    - findings/{skill}.json exists (valid JSON structure)
    - reports/*_{report_type}.{format} exists (non-empty)
    - No ERROR/CRITICAL in audit.log

    Returns: (is_valid, error_message)
    """
```

### 6. Limpieza de Sessions

```python
def cleanup_sessions(
    keep_failures: bool = True,
    max_age_hours: int = 24
):
    """Clean up old audit-logs sessions

    Options:
    - Keep only failed test sessions
    - Clean sessions older than X hours
    - Full clean (before test run)
    """
```

### 7. Generación de Reportes

```python
def generate_summary_report(
    results: List[TestResult],
    output_path: Path
):
    """Generate comprehensive test summary

    Outputs:
    1. Console: Rich table with pass/fail counts
    2. JSON: test-results.json (detailed machine-readable)
    3. Markdown: test-results.md (human-readable)

    Statistics:
    - Total tests
    - Passed/Failed/Errored
    - Pass rate %
    - Duration stats
    - Failed test details
    """
```

---

## 🔄 Flujo de Ejecución

```
1. Parse CLI arguments
2. Load AWS credentials from JSON file
3. Generate test combinations (filtered by CLI args)
4. [Optional] Clean audit-logs/ directory
5. Display test plan summary
6. [Dry-run] Exit after showing plan
7. Initialize progress tracking (Rich progress bar)

8. For each combination (sequentially or parallel):
   a. Create WizardConfig with unique client_name
   b. Build subprocess command
   c. Set AWS credentials in environment
   d. Execute: python -m drystone audit --non-interactive
   e. Capture stdout/stderr
   f. Validate artifacts (evidence, findings, reports)
   g. Store TestResult
   h. Update progress display
   i. [Fail-fast] Exit if test failed

9. Generate summary reports (console, JSON, markdown)
10. Exit with appropriate code:
    - 0 if all tests passed
    - 1 if any test failed/errored
```

---

## ✅ Criterios de Validación

### Test PASA si:
1. ✅ Proceso drystone exit code = 0
2. ✅ Archivos de evidencia existen (`evidence/{skill}/*.json`)
3. ✅ Findings JSON existe y tiene estructura válida
4. ✅ Archivo de reporte existe con nombre esperado
5. ✅ Reporte no está vacío (size > 0)
6. ✅ No hay ERROR/CRITICAL en `audit.log`
7. ✅ Proceso completa en < 10 minutos

### Test FALLA si:
1. ❌ Algún artifact falta
2. ❌ JSON malformado (findings)
3. ❌ Errores en logs
4. ❌ Reporte vacío (size = 0)

### Test ERROR si:
1. ⚠️ Proceso crash/timeout
2. ⚠️ Exception no esperada
3. ⚠️ Credenciales AWS inválidas
4. ⚠️ AWS API errors (infraestructura, no test)

---

## 📊 Display de Progreso (Rich)

### Durante ejecución:
```
Testing 24 combinations... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 42% 0:01:30
✅ iam_general_markdown - PASS (12.3s)
✅ iam_general_json - PASS (11.8s)
✅ iam_pci-dss_markdown - PASS (13.1s)
❌ iam_pci-dss_json - FAIL (5.2s)
   └─ Error: Report file not found
⏳ exposure_general_markdown - Running...
```

### Summary final:
```
╭──────────────────────────────────────────────────────────────╮
│                       E2E Test Results                       │
├──────────────────┬──────────┬──────────┬──────────┬──────────┤
│ Test ID          │ Skill    │ Report   │ Format   │ Status   │
├──────────────────┼──────────┼──────────┼──────────┼──────────┤
│ iam_general_md   │ iam      │ general  │ markdown │ ✅ PASS  │
│ iam_general_json │ iam      │ general  │ json     │ ✅ PASS  │
│ iam_pci-dss_md   │ iam      │ pci-dss  │ markdown │ ✅ PASS  │
│ iam_pci-dss_json │ iam      │ pci-dss  │ json     │ ❌ FAIL  │
│ ...              │ ...      │ ...      │ ...      │ ...      │
╰──────────────────┴──────────┴──────────┴──────────┴──────────╯

Summary:
  Total:  24
  ✅ Passed: 22
  ❌ Failed: 1
  ⚠️  Errors: 1
  Pass Rate: 91.7%

📄 Detailed results saved to: test-results/test-results.json
📄 Markdown report saved to: test-results/test-results.md
```

---

## 🛡️ Error Handling & Retry

```python
def execute_test_with_retry(
    combination: TestCombination,
    config: WizardConfig,
    max_retries: int = 2
) -> TestResult:
    """Execute test with retry logic

    Retries on:
    - Timeout (10 min exceeded)
    - AWS transient errors (throttling, etc.)
    - Infrastructure issues

    Does NOT retry on:
    - Artifact validation failures (test failed, not infrastructure)
    - Invalid credentials (permanent error)
    """
```

**Estrategia:**
- Retry automático en errores transitorios (max 2 intentos)
- Delay de 5 segundos entre retries
- Log detallado de intentos
- Diferenciar entre fallo de test vs error de infraestructura

---

## 📁 Output Structure

```
test-results/
├── test-results.json          # Machine-readable results
├── test-results.md            # Human-readable report
└── logs/
    ├── iam_general_markdown.log
    ├── iam_general_json.log
    └── ...
```

### test-results.json
```json
{
  "timestamp": "2026-01-30T21:30:00Z",
  "summary": {
    "total": 24,
    "passed": 22,
    "failed": 1,
    "errors": 1,
    "pass_rate": 91.7
  },
  "results": [
    {
      "test_id": "iam_general_markdown",
      "skill": "iam",
      "report_type": "general",
      "format": "markdown",
      "status": "PASS",
      "duration": 12.3,
      "artifacts": {
        "session": "audit-logs/E2ETest_iam_general_markdown_...",
        "evidence": "audit-logs/.../evidence/iam/",
        "findings": "audit-logs/.../findings/iam.json",
        "report": "audit-logs/.../reports/audit-report.md"
      }
    },
    ...
  ]
}
```

---

## 🚀 Implementación

### Fase 1: Core Classes (30 min)

**Archivo:** `/Users/gcuesta/Projects/drystone/scripts/e2e_test_runner.py`

Implementar:
1. `TestCombination` - dataclass para configuración de test
2. `TestResult` - dataclass para resultado
3. `E2ETestRunner` - clase orquestadora principal

**Dependencias:**
- `click` - CLI framework
- `rich` - Progress bars y tables
- `dataclasses` - Para models
- Standard library: `subprocess`, `json`, `pathlib`, etc.

---

### Fase 2: Utility Functions (30 min)

Implementar:
1. `load_credentials()` - Cargar JSON de credentials
2. `generate_combinations()` - Generar lista de combinaciones
3. `create_test_config()` - Crear WizardConfig para test
4. `cleanup_sessions()` - Limpiar audit-logs/

**Tests:**
- Validar parsing de credentials JSON
- Validar combinaciones generadas correctamente
- Validar WizardConfig tiene valores esperados

---

### Fase 3: Test Execution (45 min)

Implementar:
1. `execute_test()` - Ejecutar subprocess de drystone
2. `validate_test_artifacts()` - Validar outputs generados
3. `execute_test_with_retry()` - Wrapper con retry logic

**Key implementation:** Ver código completo en el plan original (líneas 445-501)

---

### Fase 4: Reporting (30 min)

Implementar:
1. `display_progress()` - Rich progress bar
2. `generate_summary_report()` - Console table + JSON + Markdown
3. `generate_markdown_report()` - Markdown detailed report

---

### Fase 5: CLI Interface (20 min)

Implementar:
1. Click command con todas las opciones
2. Argument parsing y validation
3. Main entry point

Ver código completo en el plan original (líneas 540-604)

---

### Fase 6: Testing & Documentation (30 min)

1. **Manual testing:**
   ```bash
   # Dry run
   python scripts/e2e_test_runner.py \
     --credentials test-creds.json \
     --dry-run

   # Single skill
   python scripts/e2e_test_runner.py \
     --credentials test-creds.json \
     --skills iam

   # Full run
   python scripts/e2e_test_runner.py \
     --credentials test-creds.json
   ```

2. **README:**
   - Crear `/Users/gcuesta/Projects/drystone/scripts/README.md`
   - Documentar usage, ejemplos, opciones
   - Incluir ejemplo de credentials.json

3. **Integration:**
   - Agregar a `CLAUDE.md` sección de E2E testing
   - Mencionar en `README.md` principal

---

## 🎯 Archivos Críticos

| Archivo | Tipo | Descripción |
|---------|------|-------------|
| `/Users/gcuesta/Projects/drystone/scripts/e2e_test_runner.py` | NUEVO | Script principal de testing |
| `/Users/gcuesta/Projects/drystone/scripts/README.md` | NUEVO | Documentación del script |
| `/Users/gcuesta/Projects/drystone/CLAUDE.md` | MODIFICAR | Agregar sección de E2E testing |
| `/Users/gcuesta/Projects/drystone/drystone/cli/main.py` | REFERENCE | Para entender CLI patterns |
| `/Users/gcuesta/Projects/drystone/drystone/models/config.py` | REFERENCE | Para crear WizardConfig correctamente |

---

## 🧪 Verificación End-to-End

### Test 1: Dry Run
```bash
python scripts/e2e_test_runner.py \
  --credentials ~/aws-creds.json \
  --dry-run

# Expected output:
# Test Plan:
#   Combinations: 24
#   AWS Region: us-east-1
#   - iam_general_markdown
#   - iam_general_json
#   - iam_pci-dss_markdown
#   - ...
```

### Test 2: Single Skill
```bash
python scripts/e2e_test_runner.py \
  --credentials ~/aws-creds.json \
  --skills iam

# Expected:
# - 4 tests executed (iam × 2 report_types × 2 formats)
# - All PASS or identified failures
# - test-results.json generated
```

### Test 3: Full Run
```bash
python scripts/e2e_test_runner.py \
  --credentials ~/aws-creds.json

# Expected:
# - 24 tests executed
# - Progress bar shows real-time status
# - Summary table at end
# - test-results.json + test-results.md generated
# - Exit code 0 if all pass, 1 if any fail
```

---

## ⏱️ Timeline

| Fase | Duración | Output |
|------|----------|--------|
| **Fase 1:** Core Classes | 30 min | TestCombination, TestResult, E2ETestRunner |
| **Fase 2:** Utility Functions | 30 min | load_credentials, generate_combinations, etc. |
| **Fase 3:** Test Execution | 45 min | execute_test, validate_artifacts, retry logic |
| **Fase 4:** Reporting | 30 min | Rich progress, summary reports |
| **Fase 5:** CLI Interface | 20 min | Click command, argument parsing |
| **Fase 6:** Testing & Docs | 30 min | Manual testing, README |
| **Total** | **3 horas** | Script funcional E2E |

---

## 📈 Success Metrics

1. ✅ Script ejecuta 24 tests sin crash
2. ✅ Detecta correctamente tests que fallan (validación de artifacts)
3. ✅ Genera reportes útiles (JSON + Markdown)
4. ✅ CLI intuitiva con dry-run mode
5. ✅ Error handling robusto (retry, timeout)
6. ✅ Performance aceptable (< 10 min/test en promedio)

---

## 🎁 Beneficios

1. **Smoke testing automático** antes de releases
2. **Detecta regresiones** en combinaciones específicas
3. **Valida integraciones** AWS + AI providers
4. **Documentación viva** de casos de uso válidos
5. **CI/CD ready** - puede integrarse en GitHub Actions
6. **Flexible** - filtros por skill, report type, format

---

## 🚀 Siguiente Paso

Una vez aprobado el plan, implementar en orden:
1. Fase 1: Core classes
2. Fase 2: Utilities
3. Fase 3: Test execution (crítico)
4. Fase 4: Reporting
5. Fase 5: CLI
6. Fase 6: Testing & docs
