# Validación: Reducción de Varianza en Findings de IA

**Estado:** ✅ IMPLEMENTACIÓN COMPLETA (Fases 1-4)

**Próximo paso:** FASE 5 - Validación end-to-end y benchmark

---

## Resumen de Cambios Implementados

### FASE 1: Prompt Engineering Genérico ✅
**Archivo:** `drystone/agent/client.py`

**Cambios:**
1. `_get_system_prompt()` (líneas 472-532): Reescrito para ser skill-agnostic
   - Prompts genéricos sin referencias específicas a IAM
   - Instrucciones anti-varianza explícitas
   - Reglas de formato de IDs obligatorias (SKILL-XXX, no sub-IDs)

2. `_build_analysis_prompt()` (líneas 534-635): Agregadas instrucciones dinámicas
   - Cálculo dinámico de límites de findings (min/max)
   - Generación de guía de severidades desde checklist
   - Instrucciones anti-varianza específicas del skill

3. Nuevo método: `_generate_severity_guide()` (líneas 637-691)
   - Extrae ejemplos de severidades del checklist
   - Genera guía dinámica para cada skill
   - Funciona con cualquier formato de checklist

**Impacto esperado:** 30% reducción de varianza

---

### FASE 2: Post-Processing Normalizer ✅
**Archivo:** `drystone/validation/findings_normalizer.py` (NUEVO)

**Funcionalidad:**
```python
class FindingsNormalizer:
    """Normaliza findings skill-agnostic."""

    - _normalize_id()          # IAM-008-001 → IAM-008
    - _is_false_positive()     # Detecta DISREGARD y IDs inválidos
    - _calibrate_severity()    # Alinea con checklist constraints
    - recalculate_summary()    # Recalcula overall_risk_score
```

**Características:**
- ✅ Skill-agnostic (funciona con IAM, Exposure, Network, Vulns)
- ✅ Severity ranges validadas (Critical 8.5-10, High 6.0-8.4, etc)
- ✅ Checklist como source of truth
- ✅ Cálculo de weighted average para overall_risk_score

**Impacto esperado:** 70% reducción total de varianza (Fase 1 + Fase 2)

---

### FASE 3: Integración en BaseSkill ✅
**Archivo:** `drystone/skills/base.py`

**Cambios:**
1. Nuevo método: `_normalize_findings()` (líneas 75-105)
   - Heredable por todos los skills
   - Llamada automática desde `analyze()`
   - Sin modificación de interfaz de skills

**Archivo:** `drystone/skills/iam/__init__.py`

**Cambios:**
1. Líneas 367-369: Agregada normalización automática
   ```python
   # 3a. Normalize findings (reduce variance between models)
   print("  Normalizing findings...")
   findings = self._normalize_findings(findings, checklist)
   ```

**Escalabilidad:**
- ✅ ExposureSkill: solo crear checklist.json → hereda normalización
- ✅ NetworkSkill: solo crear checklist.json → hereda normalización
- ✅ VulnsSkill: solo crear checklist.json → hereda normalización

---

### FASE 4: Tests Parametrizados ✅
**Archivo:** `tests/validation/test_findings_normalizer.py` (NUEVO)

**Cobertura:** ~300 líneas de tests

**Test suites:**
1. **TestNormalizeID** (8 tests)
   - IAM, Exposure, Network, VULN skills
   - Sub-ID removal, edge cases

2. **TestFalsePositiveDetection** (4 tests)
   - DISREGARD markers (title/description)
   - Invalid IDs not in checklist

3. **TestSeverityCalibration** (5 tests)
   - Severity matching
   - Mismatches (corrección automática)
   - Clamping a rangos válidos

4. **TestFullNormalization** (3 tests)
   - Pipeline completo
   - Deduplicación
   - Múltiples issues

5. **TestSummaryRecalculation** (4 tests)
   - Empty findings
   - Weighted average formula
   - Severity counts

6. **TestSkillAgnostic** (3 tests)
   - IAM, Exposure, Network skills
   - Comportamiento consistente

**Ejecución:**
```bash
pytest tests/validation/test_findings_normalizer.py -v
```

---

## Instrucciones de Validación (FASE 5)

### Opción A: Testing Manual (Recomendado para verificación rápida)

#### Test 1: Normalización de IDs

```bash
# Ejecutar auditoría
python -m drystone audit

# Verificar que los IDs son formato IAM-XXX (no sub-IDs)
grep -r '"id":' audit-logs/*/findings/iam.json | \
  grep -v '"id": "IAM-[0-9]\{3\}"' || echo "✅ All IDs normalized"
```

**Resultado esperado:** Sin matches (todos son IAM-XXX)

---

#### Test 2: Consistencia de Severidades

**Crear script `validate_severities.py`:**

```python
#!/usr/bin/env python3
import json
from pathlib import Path

# Find all IAM findings files
iam_files = list(Path('.').glob('audit-logs/*/findings/iam.json'))

severity_counts = {
    'Critical': 0,
    'High': 0,
    'Medium': 0,
    'Low': 0,
}

print("Analyzing findings severities...\n")

for file in iam_files:
    with open(file) as f:
        data = json.load(f)

    session_name = file.parent.parent.name

    # Count severities
    session_severities = {s: 0 for s in severity_counts}
    for finding in data['findings']:
        severity = finding['severity']
        session_severities[severity] += 1
        severity_counts[severity] += 1

    print(f"{session_name}:")
    for sev, count in session_severities.items():
        print(f"  {sev}: {count}")
    print()

print("OVERALL:")
for sev, count in severity_counts.items():
    print(f"  {sev}: {count}")
```

**Ejecutar:**

```bash
python validate_severities.py
```

**Resultado esperado:** Distribución consistente entre auditorías

---

#### Test 3: Falsos Positivos

```bash
# Buscar "DISREGARD" en findings (debe estar vacío)
grep -r "DISREGARD" audit-logs/*/findings/iam.json && \
  echo "❌ Found false positives" || \
  echo "✅ No false positives"
```

**Resultado esperado:** Sin matches

---

#### Test 4: Cantidad de Findings

```bash
# Contar findings por auditoría
for dir in audit-logs/*/findings/iam.json; do
    total=$(jq '.summary.total_findings' "$dir")
    session=$(dirname "$dir" | xargs dirname | xargs basename)
    echo "$session: $total findings"
done
```

**Resultado esperado:** Varianza < 15% entre auditorías

Ejemplo (aceptable):
```
MyOrg-bedrock A: 12 findings
MyOrg-bedrock B: 11 findings
MyOrg-claude A: 12 findings
MyOrg-claude B: 10 findings
```

Varianza = (max - min) / mean = (12 - 10) / 11.25 = 17.8% ❌

Ejemplo mejorado:
```
MyOrg-bedrock A: 12 findings
MyOrg-bedrock B: 11 findings
MyOrg-claude A: 11 findings
MyOrg-claude B: 12 findings
```

Varianza = (12 - 11) / 11.5 = 8.7% ✅

---

#### Test 5: Overall Risk Score

```bash
# Extraer overall_risk_score
echo "Overall Risk Scores:"
for dir in audit-logs/*/findings/iam.json; do
    score=$(jq '.summary.overall_risk_score' "$dir")
    session=$(dirname "$dir" | xargs dirname | xargs basename)
    echo "  $session: $score"
done

# Calcular rango
scores=$(for dir in audit-logs/*/findings/iam.json; do
    jq '.summary.overall_risk_score' "$dir"
done)
min=$(echo "$scores" | sort -n | head -1)
max=$(echo "$scores" | sort -n | tail -1)
echo "Range: $min to $max (spread: $(echo "$max - $min" | bc))"
```

**Resultado esperado:** Spread < 0.5 (antes era ±2.0)

Ejemplo (aceptable):
```
Overall Risk Scores:
  MyOrg-bedrock A: 6.8
  MyOrg-bedrock B: 6.9
  MyOrg-claude A: 6.8
  MyOrg-claude B: 6.9
Range: 6.8 to 6.9 (spread: 0.1) ✅
```

---

### Opción B: Testing Automatizado (Para CI/CD)

```bash
# Ejecutar tests unitarios
pytest tests/validation/test_findings_normalizer.py -v --tb=short

# Resultado esperado: 27 tests passed
```

---

## Benchmarks de Éxito

| Métrica | Antes | Target | Status |
|---------|-------|--------|--------|
| **Varianza cantidad** | 53% | < 15% | 🔄 Validar |
| **Consistencia IDs** | 40% | 100% | 🔄 Validar |
| **Consistencia severity** | 65% | > 95% | 🔄 Validar |
| **Falsos positivos** | 1-2/run | 0 | 🔄 Validar |
| **Risk score spread** | ±2.0 | < ±0.5 | 🔄 Validar |
| **Overall risk score** | 6.6 vs 6.5 | 1.5% diff | ✅ Meta original |

---

## Próximos Pasos (Roadmap)

### Week 1: Validación
- [ ] Ejecutar 4 auditorías (2 Bedrock, 2 Claude)
- [ ] Validar cada métrica de éxito
- [ ] Documentar resultados
- [ ] Decisión: ¿extender a otros skills?

### Week 2-3: Extensión a Otros Skills (Opcional)
- [ ] Crear `drystone/skills/exposure/`
- [ ] Crear `drystone/skills/network/`
- [ ] Validar que normalización funciona
- [ ] Tests paralelos con múltiples skills

### Week 4: Optimización
- [ ] Ajustar limites dinámicos si es necesario
- [ ] Refinamiento de prompts basado en resultados
- [ ] Documentación final
- [ ] Commit y push a main

---

## Escalabilidad: Cómo Aplica a Otros Skills

### Para crear un nuevo skill (ej. Exposure):

1. **Crear estructura:**
   ```bash
   mkdir -p drystone/skills/exposure
   touch drystone/skills/exposure/{__init__.py,checklist.json}
   ```

2. **Implementar collector:**
   ```python
   # drystone/skills/exposure/__init__.py
   from drystone.skills.base import BaseSkill

   class ExposureSkill(BaseSkill):
       @property
       def name(self) -> str:
           return "exposure"

       def collect(self, aws_client, session):
           # Implementar recolección de evidencia
           pass

       def analyze(self, session, agent_client):
           # Heredar normalización automática de BaseSkill
           # El mismo flujo que IAM funciona aquí
           pass
   ```

3. **Crear checklist:**
   ```json
   {
       "skill": "exposure",
       "items": [
           {
               "id": "EXP-001",
               "severity": "Critical",
               "title": "...",
               "pci_dss": [...]
           }
       ]
   }
   ```

4. **¡Normalización automática! ✅**
   - No necesita cambios adicionales
   - `_normalize_findings()` funciona igual
   - Mismos tests, misma reducción de varianza

---

## Debugging y Troubleshooting

### Si los findings todavía tienen varianza alta:

1. **Verificar que el normalizer se ejecutó:**
   ```bash
   grep "Normalizing findings..." audit-logs/*/logs/audit.log
   # Debe encontrar línea en cada auditoría
   ```

2. **Verificar checklist.json:**
   ```bash
   jq '.items | length' drystone/skills/iam/checklist.json
   # Debe estar > 20
   ```

3. **Verificar que los prompts incluyen guía de severidades:**
   ```bash
   grep -c "EJEMPLOS DE SEVERIDADES" /tmp/agent_prompt.log
   # Debe encontrar durante análisis
   ```

4. **Revisar finding IDs normalizados:**
   ```bash
   jq '.findings[].id' audit-logs/*/findings/iam.json | sort | uniq -c
   # Debe mostrar formato SKILL-XXX
   ```

---

## Documentación Adicional

- **Plan original:** Ver `PLAN.md` o sesión anterior
- **Code review:** Revisar diffs en `drystone/agent/client.py`, `drystone/skills/base.py`
- **Tests:** Ejecutar `pytest tests/validation/test_findings_normalizer.py::TestSkillAgnostic -v`

---

## Estado de Implementación

```
✅ FASE 1: Prompt Engineering (Skills-agnostic)
✅ FASE 2: Findings Normalizer (Skill-agnostic)
✅ FASE 3: BaseSkill Integration (Heredable)
✅ FASE 4: Tests Parametrizados (27 tests)
🔄 FASE 5: End-to-end Validation (EN PROGRESO)
```

**Última actualización:** 2026-01-23
**Próxima revisión:** Después de ejecutar validación end-to-end
