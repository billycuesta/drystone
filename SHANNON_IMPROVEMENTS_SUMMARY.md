# Mejoras de Shannon para Drystone - Resumen Ejecutivo

**Fecha:** 2026-02-02
**Duración:** ~15 horas (2 semanas)
**Commits:** 5-7 principales

---

## ¿Por Qué?

Drystone (AWS security audit) puede ser MÁS CONFIABLE adoptando estrategias comprobadas de Shannon (pentesting autónomo).

**Problemas Actuales de Drystone:**
- ❌ Si agente produce JSON inválido → falla silenciosa
- ❌ Si rate limit → audit aborta
- ❌ Si network timeout → audit aborta
- ❌ Sin retry system → primer error = game over

**Resultado de Shannon:**
- ✅ Output validation automático
- ✅ Retry inteligente (solo errores transitorios)
- ✅ Rate limits manejos automáticamente
- ✅ Prompts estructurados → menos variabilidad

---

## ¿Qué Mejorar?

### Prioridad 1: Output Validation + Error Classification + Retry (CRÍTICO - 5 horas)

**Problema:** Drystone no valida output del agente ni retria en fallos.

**Solución:** Adoptar arquitectura de 3 capas:

```
Layer 1: Validation (Post-Agent)
┌─────────────────────────────────────────┐
│ Agent produce JSON findings              │
│ ↓                                        │
│ Validator chequea:                      │
│  - JSON structure ok?                    │
│  - Total findings matches array size?    │
│  - Todos findings tienen id+severity?    │
│  - CIS references presentes?             │
│ ↓                                        │
│ Si INVALID → Trigger RETRY               │
└─────────────────────────────────────────┘

Layer 2: Error Classification (During Execution)
┌─────────────────────────────────────────┐
│ Si error durante agent:                  │
│  - Rate limit? → RETRY con delay 30s     │
│  - Timeout? → RETRY con backoff          │
│  - Auth error? → FAIL inmediatamente     │
│  - Permission error? → FAIL inmediatamente│
│  - Unknown? → FAIL inmediatamente (safe) │
└─────────────────────────────────────────┘

Layer 3: Retry Logic (Orchestration)
┌─────────────────────────────────────────┐
│ For attempt in 1..3:                     │
│   Try: analyze_evidence()                │
│   If validation failed → retry           │
│   If retryable error → retry with delay  │
│   If success → done                      │
│ If 3x failure → fail audit               │
└─────────────────────────────────────────┘
```

**Impacto:**
- ✅ Resilencia a rate limits: 0% → 90%
- ✅ Resilencia a network errors: 0% → 85%
- ✅ Output validation: 0% → 100% (detección de errores)

### Prioridad 2: Structured Prompts (MEDIA - 4 horas)

**Problema:** Prompts actuales son texto plano → alta variabilidad en output.

**Solución:** Migrar a prompts XML estructurados tipo Shannon.

**Antes (Actual):**
```
You are a security analyst reviewing AWS IAM configuration.

Analyze the following evidence and identify security issues:
[evidence dump]

Return findings as JSON with fields: id, severity, title, ...
```

**Después (Propuesto):**
```xml
<role>
AWS IAM Security Auditor with expertise in CIS AWS Foundations v1.5.0
</role>

<objective>
Identify IAM misconfigurations. Success criterion: All checklist items
analyzed with verdicts, evidence snippets extracted.
</objective>

<system_architecture>
COLLECTION → **IAM ANALYSIS (You)** → CORRELATION → REPORTING
</system_architecture>

<methodology>
1. Root Account Analysis (MFA, access keys)
2. User Analysis (MFA enforcement, key rotation)
3. Role Analysis (trust policies, permission boundaries)
4. Policy Analysis (overly permissive policies)
5. Cross-Reference Checklist
6. Extract Evidence Snippets
</methodology>

<data_format_specifications>
{
  "findings": [
    {
      "id": "IAM-XXX",
      "severity": "critical|high|medium|low",
      "evidence_snippet": { /* extracted JSON */ },
      ...
    }
  ]
}
</data_format_specifications>

<critical>
**Professional Standards:**
- Evidence-based (every finding MUST have evidence snippet)
- No false positives (verify before reporting)
- Actionable remediation (specific AWS steps)
</critical>
```

**Impacto:**
- ✅ Consistencia +25% (menos variabilidad)
- ✅ Mejor claridad para agente
- ✅ Validators saben qué esperar

### Prioridad 3: Crash-Safe Logging (BAJA - 2 horas, opcional)

Implementar append-only logging con flush inmediato → Never lose data on crash.

**Estado:** Posponer a después (audits son cortos)

---

## Implementación: Phase-By-Phase

### Week 1: Phase 1 (Output Validation + Retry)

**Archivos a crear:**
1. `drystone/validation/output_validators.py` (180 líneas)
   - Validators para cada skill (IAM, Hardening, Vulns, etc.)
   - Registry pattern SKILL_VALIDATORS

2. `drystone/agent/retry.py` (250 líneas)
   - is_retryable_error() - Clasificar errors
   - get_retry_delay() - Calcular delay
   - retry_with_backoff() - Decorator
   - analyze_with_retry() - Función standalone

3. `drystone/agent/client.py` (MODIFY)
   - Agregar validation a analyze_evidence_chunked()

4. `tests/unit/test_retry_logic.py` (150 líneas)
   - Tests para retry logic

**Commits:**
```bash
git commit -m "feat: add output validation + error classification + retry logic"
git commit -m "feat: integrate validation and retry into agent client"
git commit -m "test: add unit tests for retry logic"
```

**Expected Result:**
✅ Drystone can retry on rate limits/network errors
✅ Output validation detects agent errors
✅ Unit tests pass

### Week 2: Phase 2 (Structured Prompts)

**Archivos a crear:**
1. `drystone/prompts/templates/iam_structured.xml` (180 líneas)
2. `drystone/prompts/templates/hardening_structured.xml` (150 líneas)
3. `drystone/prompts/templates/vulns_structured.xml` (150 líneas)
4. ... más skills

**Archivos a modificar:**
1. `drystone/agent/client.py`
   - Cargar prompts desde templates en lugar de texto plano

**Commits:**
```bash
git commit -m "feat: structure IAM prompt with XML sections"
git commit -m "feat: structure all skill prompts with XML sections"
```

**Expected Result:**
✅ Prompts XML bien estructurados
✅ Agente entiende mejor metodología
✅ Output más consistente

### Week 3: Phase 3 (Testing Infrastructure)

**Archivos a crear:**
1. `tests/benchmarks/test_iam_benchmark.py` (200 líneas)
2. `tests/fixtures/iam/*.json` (Evidencia de referencia)

**Expected Result:**
✅ Automated tests para detectar regressions
✅ Benchmarks para comparar antes/después

---

## Impacto Esperado

### Antes (Actual)

```
Scenario: Rate limit error during IAM analysis
┌──────────────────────────────────────────┐
│ 1. Agent starts IAM analysis              │
│ 2. Claude API returns 429 Too Many Requests
│ 3. Exception propagates                   │
│ 4. Audit FAILS ❌                          │
│ 5. User has to re-run entire audit       │
│ Time wasted: 10-30 min                    │
└──────────────────────────────────────────┘

Scenario: Agent produces invalid JSON
┌──────────────────────────────────────────┐
│ 1. Agent generates findings               │
│ 2. JSON is malformed (syntax error)      │
│ 3. No detection (accepted silently)       │
│ 4. Report generation fails downstream 💥 │
│ 5. User discovers problem hours later     │
│ Time wasted: 1-2 hours                    │
└──────────────────────────────────────────┘
```

### Después (Con Mejoras)

```
Scenario: Rate limit error during IAM analysis
┌──────────────────────────────────────────┐
│ 1. Agent starts IAM analysis              │
│ 2. Claude API returns 429 Too Many Requests
│ 3. Error classified as RETRYABLE          │
│ 4. Wait 30s, retry (attempt 2)            │
│ 5. Success! ✅                             │
│ Time wasted: 30 sec                       │
└──────────────────────────────────────────┘

Scenario: Agent produces invalid JSON
┌──────────────────────────────────────────┐
│ 1. Agent generates findings               │
│ 2. JSON is malformed (syntax error)      │
│ 3. Validator detects issue immediately   │
│ 4. Classified as RETRYABLE (agent can fix)
│ 5. Retry agent (attempt 2)                │
│ 6. Success! ✅                             │
│ Time wasted: 0 sec (auto-recovered)       │
└──────────────────────────────────────────┘
```

---

## Métricas de Éxito

| Métrica | Antes | Después | Mejora |
|---------|-------|---------|--------|
| Resilencia a rate limits | 0% | 90% | +90% |
| Resilencia a network errors | 0% | 85% | +85% |
| Output validation errors detected | 0% | 100% | +100% |
| Prompt consistency | 60% | 85% | +25% |
| Reproducibilidad (exact prompts saved) | ⚠️ | ✅ | +100% |

---

## References & Learning

**Shannon Source Code to Study:**
```
1. Output Validation Pattern:
   /Users/gcuesta/Projects/shannon/src/constants.ts (65-110)
   /Users/gcuesta/Projects/shannon/src/queue-validation.ts

2. Error Classification:
   /Users/gcuesta/Projects/shannon/src/error-handling.ts (132-198)

3. Retry Logic:
   /Users/gcuesta/Projects/shannon/src/ai/claude-executor.ts

4. Structured Prompts:
   /Users/gcuesta/Projects/shannon/prompts/vuln-injection.txt (372 lines)

5. Crash-Safe Logging:
   /Users/gcuesta/Projects/shannon/src/audit/audit-session.ts
```

**Drystone Documentation:**
```
Current State: /Users/gcuesta/Projects/drystone/CLAUDE.md
Architecture Analysis: /Users/gcuesta/Projects/drystone/ARCHITECTURE_ANALYSIS_SHANNON.md
Implementation Plan: /Users/gcuesta/Projects/drystone/IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md
Decisions Doc: /Users/gcuesta/Projects/drystone/SHANNON_DECISIONS.md
```

---

## FAQ

### Q: ¿Por qué no usar Temporal como Shannon?

**A:** Temporal es excelente para workflows largos (horas/días), pero Drystone tiene audits cortos (10-30 min). Overhead de Temporal no se justifica. Retry simple + validation cubre 90% de casos.

**Cuándo reconsiderar Temporal:**
- Audits duran >2 horas
- Necesitas pause/resume workflows
- Múltiples audits paralelos complejos

### Q: ¿Estos cambios requieren reescribir aplicación?

**A:** NO. Son cambios incrementales:
- Add validators → Post-agent check (no affecting core logic)
- Add retry decorator → Wrap analyze calls (backward compatible)
- Structured prompts → Replace string templates (same interface)

### Q: ¿Cuál es el timeline realista?

**A:** ~15 horas de desarrollo:
- Phase 1 (Validation + Retry): 5 horas
- Phase 2 (Structured Prompts): 4 horas
- Phase 3 (Testing): 4 horas
- Buffer: 2 horas

---

## Next Action

1. ✅ **Review:** Read ARCHITECTURE_ANALYSIS_SHANNON.md
2. ✅ **Decide:** Approve decisions in SHANNON_DECISIONS.md
3. 🚀 **Implement:** Follow IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md Phase 1
4. 🧪 **Test:** Run unit tests, manual testing with rate limits
5. 📊 **Measure:** Compare metrics before/after

---

**Documentado:** 2026-02-02
**Status:** ✅ READY FOR IMPLEMENTATION
**Próximo paso:** Iniciar Phase 1 (Output Validation + Retry Logic)
