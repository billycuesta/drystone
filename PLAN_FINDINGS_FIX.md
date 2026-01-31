# Plan: Fix Findings Duplicates, False Positives, and Region Scope

**Alcance:** Global - Todos los skills (IAM, Exposure, Network, Vulns, Alerting, Hardening)
**Esfuerzo estimado:** 12-15 horas
**Prioridad:** P0 (Crítico)

---

## Problemas Identificados

### 1️⃣ Findings Duplicados (HRD-001 + HRD-006)
**Evidencia:**
- Archivo: `audit-logs/MyOrg_2026-01-31T06-51-30/reports/audit-report.md`
- **HRD-001:** "AWS Config no habilitado en ninguna region" (Critical)
- **HRD-006:** "AWS Config habilitado parcialmente" (High)
- **Ambos generados** cuando solo HRD-006 debería existir (Config SÍ está en us-east-1)

**Causa raíz:** El agente AI genera findings mutuamente excluyentes porque no hay reglas explícitas de exclusión mutua.

**Impacto:** Reportes confusos, riesgo calculado incorrectamente, pérdida de confianza del cliente.

---

### 2️⃣ Falso Positivo Security Hub (HRD-002)
**Evidencia:**
- Archivo: `audit-logs/MyOrg_2026-01-31T06-51-30/evidence/hardening/security-hub-status.json`
- **Evidence muestra:** `"HubArn": "arn:aws:securityhub:us-east-1:032014372957:hub/default"` (activo)
- **Finding generado:** HRD-002 "Security Hub no habilitado" (falso)

**Causa raíz:** El agente ignora evidencia clara o la malinterpreta. No hay validación post-análisis.

**Impacto:** Falsos positivos erosionan credibilidad del audit, tiempo perdido validando manualmente.

---

### 3️⃣ Scope de Región Confuso
**Configuración usuario:** `eu-west-1` (región única)
**Checklist dice:** "AWS Config no habilitado en ninguna region" (implica multi-región)
**Collector hace:** Solo busca en `eu-west-1` (correcto)

**Causa raíz:** Mismatch semántico entre wording del checklist (multi-región) y scope real del collector (región única).

**Impacto:** Findings ambiguos, cliente confundido sobre alcance del audit.

---

## Solución: Defensa en 3 Capas

### Capa 1: Mejorar System Prompt (Prevención)
**Objetivo:** Evitar que el agente genere findings incorrectos desde el origen.

**Archivo:** `drystone/agent/client.py`

**Cambios en `_get_system_prompt()` (después línea 748):**

```python
REGLAS DE EXCLUSIÓN MUTUA (ANTI-DUPLICADOS):

Para AWS Config:
- SI ConfigurationRecorders array CONTIENE 1+ recorders:
  → Genera SOLO HRD-006 (habilitado parcialmente)
  → NO generes HRD-001 (no habilitado)
- SI ConfigurationRecorders array está VACÍO:
  → Genera SOLO HRD-001 (no habilitado)
  → NO generes HRD-006

Para Security Hub:
- SI HubArn + SubscribedAt presentes en evidencia:
  → Security Hub ESTÁ HABILITADO
  → NO generes HRD-002
  → Evalúa solo HRD-003, HRD-007, HRD-004, etc.
- SI HubArn ausente O error response:
  → Security Hub NO HABILITADO
  → Genera HRD-002

TABLA DE DETECCIÓN DE ESTADO (CRÍTICA):

| Servicio       | Campo Evidencia          | Estado   | Findings Permitidos      |
|----------------|--------------------------|----------|--------------------------|
| Security Hub   | HubArn presente          | ENABLED  | HRD-003,004,005,007,...  |
| Security Hub   | HubArn ausente           | DISABLED | HRD-002                  |
| AWS Config     | ConfigurationRecorders>0 | PARTIAL  | HRD-006                  |
| AWS Config     | ConfigurationRecorders=0 | DISABLED | HRD-001                  |
| GuardDuty      | DetectorIds array >0     | ENABLED  | HRD-009,014              |
| GuardDuty      | DetectorIds array =0     | DISABLED | (new check needed)       |

PRINCIPIO CONSERVADOR:
- Si evidencia es CLARA (HubArn existe), CONFÍA en la evidencia
- Si evidencia es AMBIGUA, NO reportes finding
- NUNCA reportes hallazgos contradictorios con evidencia explícita
```

**Cambios en `_build_analysis_prompt()` (línea ~783):**

Agregar contexto de región al prompt:

```python
# Add region metadata to evidence
audit_metadata = {
    "region": evidence.get("_region", "unknown"),
    "scope": "single-region",
}

prompt = f"""Analiza la siguiente evidencia AWS {skill_name.upper()} contra el checklist de seguridad.

CONTEXTO DE AUDITORÍA:
- Región auditada: {audit_metadata['region']}
- Alcance: Auditoría de región única (no multi-región)
- Interpretación: Los controles se evalúan SOLO para la región configurada

===== EVIDENCIA AWS =====
{json.dumps(evidence, indent=2, default=str)}
```

---

### Capa 2: Actualizar Checklists (Claridad)
**Objetivo:** Eliminar ambigüedad semántica entre scope del checklist y scope del collector.

**Archivos a modificar:**

1. `drystone/skills/hardening/checklist.json`
2. `drystone/skills/iam/checklist.json`
3. `drystone/skills/exposure/checklist.json`
4. `drystone/skills/network/checklist.json`
5. `drystone/skills/vulns/checklist.json`
6. `drystone/skills/alerting/checklist.json`

**Patrón de cambio:**

```diff
- "title": "AWS Config no habilitado en ninguna region"
+ "title": "AWS Config no habilitado en la región configurada"

- "description": "AWS Config is not enabled in any active region..."
+ "description": "AWS Config is not enabled in the audited region (e.g., eu-west-1)..."

- "remediation": "Enable AWS Config in all active AWS regions..."
+ "remediation": "Enable AWS Config in the audited region. Consider multi-region deployment for production environments."
```

**Items afectados en hardening:**
- HRD-001: AWS Config (ninguna → configurada)
- HRD-002: Security Hub (ninguna → configurada)
- HRD-006: AWS Config parcial (no todas → verificar recorder)

**Validar otros skills:**
- Buscar pattern: `"ninguna region"`, `"todas las regiones"`, `"any region"`, `"all regions"`
- Reemplazar con: `"región configurada"`, `"audited region"`

---

### Capa 3: Post-Processing Validation (Red de Seguridad)
**Objetivo:** Validar findings contra evidencia y detectar contradicciones.

**Archivo:** `drystone/validation/findings_normalizer.py`

**Cambios:**

**1. Agregar exclusiones mutuas (después línea 70):**

```python
# Mutual exclusion pairs: (ID1, ID2) → resolution strategy
MUTUAL_EXCLUSIONS = {
    # Hardening
    ("HRD-001", "HRD-006"): "keep_specific",  # Config: disabled vs partial
    ("HRD-002", "HRD-003"): "keep_specific",  # Hub: disabled vs no standards
    ("HRD-004", "HRD-008"): "keep_higher",    # Compliance score ranges
    ("HRD-008", "HRD-011"): "keep_higher",    # Compliance score ranges

    # IAM (ejemplo - validar en implementación)
    ("IAM-001", "IAM-XXX"): "keep_specific",  # Root: no MFA vs partial

    # Exposure (ejemplo - validar en implementación)
    ("EXP-001", "EXP-XXX"): "keep_specific",  # Public vs partially public
}
```

**2. Agregar validación de evidencia (nuevo método después línea 242):**

```python
def _validate_against_evidence(
    self,
    finding: Finding,
    evidence: Dict[str, Any]
) -> bool:
    """Validate finding against actual evidence to detect false positives.

    Returns:
        True if finding is valid, False if contradicts evidence
    """
    finding_id = self._normalize_id(finding.id)

    # Security Hub false positive detection
    if finding_id == "HRD-002":
        hub_status = evidence.get("security-hub-status", {})
        if "HubArn" in hub_status and hub_status.get("HubArn"):
            # HubArn exists = Security Hub IS enabled
            logger.warning(f"Rejected HRD-002 - Security Hub IS enabled (HubArn present)")
            return False  # Reject false positive

    # AWS Config false positive detection
    if finding_id == "HRD-001":
        config_recorders = evidence.get("config-recorders", {})
        recorders = config_recorders.get("ConfigurationRecorders", [])
        if len(recorders) > 0:
            # Recorders exist = Config IS enabled (at least partially)
            logger.warning(f"Rejected HRD-001 - Config IS enabled ({len(recorders)} recorders)")
            return False  # Should be HRD-006 instead

    # GuardDuty validation (ejemplo)
    if finding_id in ["HRD-009", "HRD-014"]:
        gd_detectors = evidence.get("guardduty-detectors", [])
        if not gd_detectors or len(gd_detectors) == 0:
            logger.warning(f"Rejected {finding_id} - GuardDuty not enabled")
            return False

    return True  # Finding is valid
```

**3. Agregar resolución de exclusiones (nuevo método):**

```python
def _resolve_mutual_exclusions(self, findings: List[Finding]) -> List[Finding]:
    """Resolve mutually exclusive findings.

    If both findings in an exclusion pair are present, keep only one
    according to the resolution strategy.
    """
    findings_dict = {f.id: f for f in findings}
    to_remove = set()

    for (id1, id2), strategy in self.MUTUAL_EXCLUSIONS.items():
        if id1 in findings_dict and id2 in findings_dict:
            # Both present - resolve conflict
            if strategy == "keep_specific":
                # Keep the more specific finding (higher ID = more specific)
                to_remove.add(id1 if int(id1.split('-')[1]) < int(id2.split('-')[1]) else id2)
                logger.info(f"Mutual exclusion: {id1} vs {id2} → keeping more specific")
            elif strategy == "keep_higher":
                # Keep higher severity
                f1, f2 = findings_dict[id1], findings_dict[id2]
                to_remove.add(id1 if f1.risk_score < f2.risk_score else id2)
                logger.info(f"Mutual exclusion: {id1} vs {id2} → keeping higher severity")

    return [f for f in findings if f.id not in to_remove]
```

**4. Integrar en `normalize()` (línea ~96):**

```python
# 3. Skip false positives (existing)
if self._is_false_positive(finding):
    continue

# 3a. Validate against evidence (NEW)
if hasattr(self, 'evidence') and not self._validate_against_evidence(finding, self.evidence):
    continue  # Skip finding that contradicts evidence
```

**5. Modificar `base.py` para pasar evidence al normalizer (línea ~95):**

```python
# 3a. Normalize findings (reduce variance between models)
print("  Normalizing findings...")
normalizer = FindingsNormalizer(checklist, self.name)
normalizer.evidence = evidence  # Pass evidence for validation
findings.findings = normalizer.normalize(findings.findings)

# 3b. Resolve mutual exclusions
findings.findings = normalizer._resolve_mutual_exclusions(findings.findings)

# 3c. Recalculate summary
findings.summary = normalizer.recalculate_summary(findings.findings)
```

---

### Capa 4: Evidence Collection Enhancement (Opcional)
**Objetivo:** Hacer la evidencia más explícita para el agente.

**Archivo:** `drystone/skills/hardening/__init__.py` (y otros skills)

**Cambios:**

```python
# Add explicit status indicators
hub_status = {}
try:
    hub = sh_client.describe_hub()
    hub_status = {
        "enabled": True,  # Explicit status
        "HubArn": hub.get("HubArn"),
        "SubscribedAt": hub.get("SubscribedAt"),
        "AutoEnableControls": hub.get("AutoEnableControls")
    }
except sh_client.exceptions.InvalidAccessException:
    hub_status = {"enabled": False, "reason": "not_enabled"}
except Exception as e:
    hub_status = {"enabled": False, "reason": "error", "error": str(e)}

self._save_json(evidence_path / "security-hub-status.json", hub_status)
```

**Agregar metadata de región:**

```python
# Add audit metadata
audit_metadata = {
    "_region": aws_client.region_name,
    "_timestamp": datetime.now().isoformat(),
    "_scope": "single-region"
}

self._save_json(evidence_path / "_audit_metadata.json", audit_metadata)
```

**Aplicar a todos los skills.**

---

## Plan de Ejecución

### Fase 1: Prompt Engineering (2 horas)
- [ ] Modificar `drystone/agent/client.py:_get_system_prompt()`
  - Agregar tabla de detección de estado
  - Agregar reglas de exclusión mutua
- [ ] Modificar `drystone/agent/client.py:_build_analysis_prompt()`
  - Agregar contexto de región al prompt
- [ ] Probar con prompts sintéticos (ver Validación)

### Fase 2: Actualizar Checklists (3 horas)
- [ ] Auditar todos los checklists buscando:
  - Pattern: `"ninguna region"`, `"todas las regiones"`, `"all regions"`
  - Findings duplicados potenciales
  - Severidades solapadas (ranges de compliance score)
- [ ] Modificar `hardening/checklist.json`:
  - HRD-001, HRD-002, HRD-006 → wording regional
- [ ] Modificar otros skills si aplica:
  - `iam/checklist.json`
  - `exposure/checklist.json`
  - `network/checklist.json`
  - `vulns/checklist.json`
  - `alerting/checklist.json`
- [ ] Validar backward compatibility (PCI DSS mappings intactos)

### Fase 3: Post-Processing Validation (4 horas)
- [ ] Modificar `drystone/validation/findings_normalizer.py`:
  - Agregar `MUTUAL_EXCLUSIONS` dict
  - Implementar `_validate_against_evidence()`
  - Implementar `_resolve_mutual_exclusions()`
  - Actualizar `normalize()` para llamar validación
- [ ] Modificar `drystone/skills/base.py`:
  - Pasar `evidence` al normalizer
  - Llamar `_resolve_mutual_exclusions()` después de normalize
- [ ] Unit tests:
  - `test_mutual_exclusion_hrd_001_006()`
  - `test_evidence_validation_security_hub()`
  - `test_evidence_validation_config()`

### Fase 4: Evidence Enhancement (2 horas)
- [ ] Modificar collectors para agregar status explícito:
  - `hardening/__init__.py` (Security Hub, Config, GuardDuty)
  - `exposure/__init__.py` (S3 public, RDS public, etc.)
  - Otros si es necesario
- [ ] Agregar metadata de región a evidencia:
  - `_audit_metadata.json` en cada skill
  - Include: region, timestamp, scope

### Fase 5: Validación End-to-End (3-4 horas)
- [ ] Unit tests nuevos (ver sección Testing)
- [ ] Re-run audit contra cuenta real (MyOrg, eu-west-1)
- [ ] Validar que NO aparezcan:
  - HRD-001 Y HRD-006 juntos
  - HRD-002 cuando HubArn presente
  - Findings con "ninguna region" en scope
- [ ] Validar cross-model (Claude, Gemini, Bedrock)
- [ ] Comparar antes/después (snapshot testing)

---

## Archivos Críticos a Modificar

### Alta Prioridad (Core Fix)
1. ✅ `drystone/agent/client.py` - System prompt + analysis prompt
2. ✅ `drystone/validation/findings_normalizer.py` - Evidence validation + mutual exclusions
3. ✅ `drystone/skills/base.py` - Integration point
4. ✅ `drystone/skills/hardening/checklist.json` - Region scope wording

### Media Prioridad (Global Fix)
5. ⚠️ `drystone/skills/iam/checklist.json` - Audit for duplicates
6. ⚠️ `drystone/skills/exposure/checklist.json` - Audit for region scope
7. ⚠️ `drystone/skills/network/checklist.json` - Audit for region scope
8. ⚠️ `drystone/skills/vulns/checklist.json` - Audit for region scope
9. ⚠️ `drystone/skills/alerting/checklist.json` - Audit for region scope

### Baja Prioridad (Enhancement)
10. 🔵 `drystone/skills/hardening/__init__.py` - Explicit status in evidence
11. 🔵 `drystone/skills/exposure/__init__.py` - Explicit status in evidence
12. 🔵 (otros collectors según necesidad)

---

## Testing Plan

### Unit Tests (Nuevos)

**Archivo:** `tests/validation/test_findings_normalizer.py`

```python
def test_mutual_exclusion_hrd_001_006():
    """Test that HRD-001 and HRD-006 are mutually exclusive."""
    checklist = load_checklist("hardening")
    normalizer = FindingsNormalizer(checklist, "hardening")

    findings = [
        Finding(id="HRD-001", severity="Critical", risk_score=9.5, ...),
        Finding(id="HRD-006", severity="High", risk_score=8.0, ...)
    ]

    normalized = normalizer.normalize(findings)
    normalized = normalizer._resolve_mutual_exclusions(normalized)

    # Should keep only HRD-006 (more specific)
    assert len(normalized) == 1
    assert normalized[0].id == "HRD-006"

def test_evidence_validation_security_hub():
    """Test that HRD-002 is rejected when HubArn exists in evidence."""
    checklist = load_checklist("hardening")
    normalizer = FindingsNormalizer(checklist, "hardening")

    evidence = {
        "security-hub-status": {
            "HubArn": "arn:aws:securityhub:us-east-1:123:hub/default",
            "SubscribedAt": "2023-02-27T13:11:05.701Z"
        }
    }
    normalizer.evidence = evidence

    finding = Finding(id="HRD-002", severity="Critical", ...)

    # Should reject this finding
    assert normalizer._validate_against_evidence(finding, evidence) == False

def test_evidence_validation_config():
    """Test that HRD-001 is rejected when ConfigurationRecorders exist."""
    checklist = load_checklist("hardening")
    normalizer = FindingsNormalizer(checklist, "hardening")

    evidence = {
        "config-recorders": {
            "ConfigurationRecorders": [{"name": "default", "roleARN": "..."}]
        }
    }
    normalizer.evidence = evidence

    finding = Finding(id="HRD-001", severity="Critical", ...)

    # Should reject HRD-001 (should be HRD-006 instead)
    assert normalizer._validate_against_evidence(finding, evidence) == False
```

### Integration Tests (Modificar)

**Archivo:** `tests/skills/test_hardening.py` (crear)

```python
def test_hardening_no_duplicates_config(mock_aws_client, mock_session):
    """Test that Config findings don't produce duplicates."""
    skill = HardeningSkill()

    # Mock evidence: Config enabled with 1 recorder
    mock_evidence = {
        "config-recorders": {
            "ConfigurationRecorders": [{"name": "default", ...}]
        }
    }

    # Run analysis
    findings = skill.analyze(mock_evidence, checklist)

    # Should have HRD-006 but NOT HRD-001
    finding_ids = [f.id for f in findings.findings]
    assert "HRD-006" in finding_ids
    assert "HRD-001" not in finding_ids

def test_hardening_no_false_positive_security_hub(mock_aws_client, mock_session):
    """Test that Security Hub enabled doesn't trigger HRD-002."""
    skill = HardeningSkill()

    # Mock evidence: Security Hub enabled
    mock_evidence = {
        "security-hub-status": {
            "HubArn": "arn:aws:securityhub:us-east-1:123:hub/default",
            "SubscribedAt": "2023-02-27T13:11:05.701Z"
        }
    }

    # Run analysis
    findings = skill.analyze(mock_evidence, checklist)

    # Should NOT have HRD-002
    finding_ids = [f.id for f in findings.findings]
    assert "HRD-002" not in finding_ids
```

### Regression Testing

1. **Snapshot Testing:**
   - Guardar output actual de account conocida
   - Después de cambios, comparar nuevo output vs snapshot
   - Flagear diferencias inesperadas

2. **Cross-Model Testing:**
   - Correr mismo audit con Claude API, Gemini API, Bedrock
   - Validar que todos producen resultados consistentes
   - Medir variance reduction

---

## Validación End-to-End

### Escenarios de Prueba

**Escenario 1: Config Enabled (Partial)**
- Evidence: `ConfigurationRecorders: [{"name": "default"}]` (1 recorder)
- Expected: SOLO HRD-006
- Forbidden: HRD-001

**Escenario 2: Config Disabled**
- Evidence: `ConfigurationRecorders: []` (0 recorders)
- Expected: SOLO HRD-001
- Forbidden: HRD-006

**Escenario 3: Security Hub Enabled**
- Evidence: `{"HubArn": "...", "SubscribedAt": "..."}`
- Expected: HRD-003, HRD-007, etc. (NO HRD-002)
- Forbidden: HRD-002

**Escenario 4: Security Hub Disabled**
- Evidence: `InvalidAccessException` o HubArn ausente
- Expected: SOLO HRD-002
- Forbidden: HRD-003, HRD-007 (requieren Hub activo)

**Escenario 5: Region Scope Clarity**
- Config: `aws_region = "eu-west-1"`
- Expected: Findings dicen "región configurada (eu-west-1)"
- Forbidden: "ninguna region", "todas las regiones"

### Comandos de Validación

```bash
# Re-run audit con misma config
python -m drystone audit --client MyOrg --region eu-west-1 --skills hardening

# Comparar findings antes/después
diff \
  audit-logs/MyOrg_2026-01-31T06-51-30/findings/hardening.json \
  audit-logs/MyOrg_NUEVO/findings/hardening.json

# Validar que HRD-001 y HRD-006 no coexisten
jq '.findings[] | select(.id == "HRD-001" or .id == "HRD-006")' \
  audit-logs/MyOrg_NUEVO/findings/hardening.json

# Validar que HRD-002 no aparece si HubArn presente
jq '.findings[] | select(.id == "HRD-002")' \
  audit-logs/MyOrg_NUEVO/findings/hardening.json
```

---

## Criterios de Éxito

✅ **Zero Duplicates:**
- Ningún audit produce HRD-001 Y HRD-006 simultáneamente
- Ningún skill produce findings mutuamente excluyentes

✅ **Zero False Positives:**
- Security Hub activo (HubArn presente) → NO HRD-002
- Config activo (recorders presente) → NO HRD-001
- Validar con 3+ accounts reales

✅ **Region Clarity:**
- Todos los findings usan "región configurada" o "audited region"
- Remediation menciona alcance regional vs multi-regional

✅ **Cross-Model Consistency:**
- Claude API, Gemini API, Bedrock producen mismo resultado
- Variance < 5% (measured by FindingsNormalizer metrics)

✅ **Backward Compatible:**
- PCI DSS mappings intactos en todos los checklists
- Reportes existentes siguen siendo válidos
- No breaking changes en API de findings

---

## Rollback Plan

Si surgen problemas post-deployment:

1. **Prompt Changes:**
   ```bash
   git revert <commit-hash>  # Revert client.py changes
   ```

2. **Normalizer Changes:**
   - Agregar feature flag: `ENABLE_EVIDENCE_VALIDATION = False`
   - Deshabilitar `_validate_against_evidence()` vía flag

3. **Checklist Changes:**
   - Revertir a versión anterior (no afecta funcionalidad, solo wording)

**Feature Flags (agregar a config):**

```python
# drystone/models/config.py
class WizardConfig:
    ...
    enable_evidence_validation: bool = True  # Can toggle
    enable_mutual_exclusion: bool = True     # Can toggle
    enhanced_prompts: bool = True            # Can toggle
```

---

## Notas de Implementación

1. **Order of Implementation:**
   - Fase 1 (Prompt) primero → previene mayoría de problemas en origen
   - Fase 3 (Normalizer) segundo → red de seguridad
   - Fase 2 (Checklists) tercero → claridad
   - Fase 4 (Evidence) último → enhancement opcional

2. **Logging:**
   - Log todos los findings rechazados con razón
   - Log todas las exclusiones mutuas resueltas
   - Formato: `logger.warning(f"Rejected {finding_id} - reason: {reason}")`

3. **Metrics to Track:**
   - `duplicates_removed_count`: Cuántos duplicados evitados
   - `false_positives_rejected_count`: Cuántos falsos positivos filtrados
   - `mutual_exclusions_resolved`: Cuántos conflictos resueltos
   - Agregar a `FindingsSummary` model

4. **Documentation Updates:**
   - Actualizar `CLAUDE.md` con nueva lógica de validación
   - Documentar reglas de exclusión mutua
   - Agregar ejemplos de findings correctos/incorrectos

---

## Timeline Estimado

| Fase | Esfuerzo | Prioridad |
|------|----------|-----------|
| Fase 1: Prompt Engineering | 2 horas | P0 |
| Fase 2: Checklist Updates | 3 horas | P1 |
| Fase 3: Post-Processing | 4 horas | P0 |
| Fase 4: Evidence Enhancement | 2 horas | P2 |
| Fase 5: Testing & Validation | 3-4 horas | P0 |
| **TOTAL** | **14-15 horas** | **P0** |

---

## Referencias

- Informe problemático: `audit-logs/MyOrg_2026-01-31T06-51-30/reports/audit-report.md`
- Evidence Security Hub: `audit-logs/MyOrg_2026-01-31T06-51-30/evidence/hardening/security-hub-status.json`
- System prompt actual: `drystone/agent/client.py:671-748`
- Normalizer actual: `drystone/validation/findings_normalizer.py`
- Checklist hardening: `drystone/skills/hardening/checklist.json`
