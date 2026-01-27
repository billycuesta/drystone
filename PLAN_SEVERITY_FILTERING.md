# Plan: Filtrado de Severidad en Skills Vulns y Hardening

## 🎯 Objetivo

Implementar filtrado por severidad en los skills de **vulns** y **hardening** para reducir ruido y costos de análisis.

**Default:** Recolectar solo findings de severidad **Critical, High, Medium** (omitir Low e Informational)

---

## 📊 Problema Actual

| Skill | API | Volumen Sin Filtro | Problema |
|-------|-----|-------------------|----------|
| Vulns | AWS Inspector v2 | 100-1000+ findings | 70% son LOW/INFORMATIONAL |
| Hardening | Security Hub | 500-2000+ findings | 70% son LOW/INFORMATIONAL |

**Impacto:**
- Evidence files: 5-10MB por skill
- Tokens Claude: 1M+ tokens → requiere chunking
- Reportes: 50+ páginas con 70% ruido
- Costos: 3-4x API calls por chunking

---

## ✅ Solución: Collection-Time Filtering

Filtrar DURANTE la recolección de datos AWS (no después):

**Beneficios:**
- ✅ Reduce transferencia de datos (70% menos)
- ✅ Reduce tamaño de archivos evidence (5MB → 1.5MB)
- ✅ Reduce tokens Claude (1M → 300K tokens)
- ✅ Reportes enfocados en hallazgos críticos

---

## 📝 Archivos a Modificar

### 1. `drystone/models/config.py`
**Cambio:** Agregar campo de configuración para severidad mínima

**Ubicación:** Línea ~50 (dentro de `WizardConfig`)

**Código a agregar:**
```python
# Step 6: Minimum severity level for findings
min_severity_level: Literal["Critical", "High", "Medium", "Low"] = Field(
    default="Medium",
    description="Minimum severity level for collected findings (filters out lower severities)"
)
```

**Notas:**
- Agregar después de `output_formats` (línea ~50)
- Default = "Medium" (incluye Critical, High, Medium)
- Esto filtra Low e Informational

---

### 2. `drystone/skills/vulns/__init__.py`
**Cambios:** Agregar filtros AWS API para Inspector v2 y ECR

#### Cambio 2a: Inspector v2 Findings (Líneas 66-76)

**ANTES:**
```python
# List findings
findings_list = []
try:
    paginator = inspector_client.get_paginator('list_findings')
    for page in paginator.paginate():
        findings_list.extend(page.get("findings", []))
except Exception as e:
    logger.warning(f"Could not paginate Inspector findings: {e}")
```

**DESPUÉS:**
```python
# List findings (filtered by severity: Critical, High, Medium)
findings_list = []
try:
    paginator = inspector_client.get_paginator('list_findings')

    # Filter criteria for Inspector v2
    filter_criteria = {
        'severityLabel': [
            {'comparison': 'EQUALS', 'value': 'CRITICAL'},
            {'comparison': 'EQUALS', 'value': 'HIGH'},
            {'comparison': 'EQUALS', 'value': 'MEDIUM'}
        ]
    }

    for page in paginator.paginate(filterCriteria=filter_criteria):
        findings_list.extend(page.get("findings", []))
except Exception as e:
    logger.warning(f"Could not paginate Inspector findings: {e}")
```

**Documentación AWS:**
- API: [ListFindings](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html)
- Parámetro: `filterCriteria` con campo `severityLabel`
- Valores válidos: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNTRIAGED

#### Cambio 2b: ECR Image Scan Findings (Líneas 209-236)

**NOTA:** ECR devuelve summary con counts, NO lista individual de findings.

**NO requiere cambios** - El análisis de Claude ya puede filtrar severidades en el summary.

Ejemplo actual:
```json
{
  "findingSeverityCounts": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 10,
    "LOW": 3
  }
}
```

Claude puede ignorar counts de LOW al analizar.

---

### 3. `drystone/skills/hardening/__init__.py`
**Cambios:** Agregar filtros AWS API para Security Hub, GuardDuty, Macie

#### Cambio 3a: Security Hub Findings (Líneas 68-76)

**ANTES:**
```python
# List findings
findings_list = []
try:
    paginator = sh_client.get_paginator('get_findings')
    for page in paginator.paginate():
        findings_list.extend(page.get("Findings", []))
except Exception as e:
    logger.warning(f"Could not paginate Security Hub findings: {e}")
```

**DESPUÉS:**
```python
# List findings (filtered by severity: Critical, High, Medium)
findings_list = []
try:
    paginator = sh_client.get_paginator('get_findings')

    # Filter criteria for Security Hub
    filters = {
        'SeverityLabel': [
            {'Value': 'CRITICAL', 'Comparison': 'EQUALS'},
            {'Value': 'HIGH', 'Comparison': 'EQUALS'},
            {'Value': 'MEDIUM', 'Comparison': 'EQUALS'}
        ],
        'RecordState': [
            {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}  # Only active findings
        ]
    }

    for page in paginator.paginate(Filters=filters):
        findings_list.extend(page.get("Findings", []))
except Exception as e:
    logger.warning(f"Could not paginate Security Hub findings: {e}")
```

**Documentación AWS:**
- API: [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
- Parámetro: `Filters` con campo `SeverityLabel`
- Valores válidos: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL

#### Cambio 3b: GuardDuty Findings (Líneas 205-213)

**ANTES:**
```python
# Get findings (up to 50)
try:
    findings = gd_client.list_findings(
        DetectorId=detector_id,
        MaxResults=50
    )
    detector_detail["FindingIds"] = findings.get("FindingIds", [])
except Exception as e:
    logger.warning(f"Could not list GuardDuty findings for detector {detector_id}: {e}")
    detector_detail["FindingIds"] = []
```

**DESPUÉS:**
```python
# Get findings (up to 50, filtered by severity)
try:
    findings = gd_client.list_findings(
        DetectorId=detector_id,
        MaxResults=50,
        FindingCriteria={
            'Criterion': {
                'severity': {
                    'Gte': 4.0  # Medium and above (4.0-10.0 scale)
                }
            }
        }
    )
    detector_detail["FindingIds"] = findings.get("FindingIds", [])
except Exception as e:
    logger.warning(f"Could not list GuardDuty findings for detector {detector_id}: {e}")
    detector_detail["FindingIds"] = []
```

**Documentación AWS:**
- API: [ListFindings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListFindings.html)
- Parámetro: `FindingCriteria.Criterion.severity`
- Escala: 0.0-10.0 (Low: 0.1-3.9, Medium: 4.0-6.9, High: 7.0-8.9, Critical: 9.0+)
- Filtro: `Gte: 4.0` = Medium, High, Critical

#### Cambio 3c: Macie Findings (Líneas 235-248)

**NOTA:** Macie API `list_findings` NO soporta filtrado por severidad en el request.

**Opción:** Post-filtrar después de recolectar (o dejar como está con MaxResults=50)

**Cambio sugerido (post-filtrado):**
```python
# List findings (limited to 50, post-filtered by severity)
try:
    findings_list = []
    paginator = macie_client.get_paginator('list_findings')
    for page in paginator.paginate(MaxResults=50):
        for finding_id in page.get("findingIds", []):
            try:
                finding = macie_client.get_findings(findingIds=[finding_id])
                finding_details = finding.get("findings", [])

                # Post-filter: only Critical, High, Medium
                for f in finding_details:
                    severity = f.get("severity", {}).get("description", "").upper()
                    if severity in ["HIGH", "MEDIUM"]:  # Macie no tiene "CRITICAL"
                        findings_list.append(f)
            except Exception as e:
                logger.warning(f"Could not get Macie finding {finding_id}: {e}")

    self._save_json(evidence_path / "macie-findings.json", findings_list)
except Exception as e:
    logger.warning(f"Could not list Macie findings: {e}")
```

**Documentación AWS:**
- API: [GetFindings](https://docs.aws.amazon.com/macie/latest/APIReference/findings-describe.html)
- Campo: `severity.description` = "High", "Medium", "Low"
- Nota: Macie NO tiene severidad "Critical"

---

## 📋 Orden de Implementación

### Fase 1: Configuración (5 min)
1. Modificar `drystone/models/config.py`
   - Agregar campo `min_severity_level`
   - Default = "Medium"

### Fase 2: Vulns Skill (10 min)
2. Modificar `drystone/skills/vulns/__init__.py`
   - Línea 69: Agregar filtro a Inspector `list_findings()`
   - NO cambiar ECR (devuelve summary, no lista)

### Fase 3: Hardening Skill (15 min)
3. Modificar `drystone/skills/hardening/__init__.py`
   - Línea 69: Agregar filtros a Security Hub `get_findings()`
   - Línea 208: Agregar filtro a GuardDuty `list_findings()`
   - Línea 238: Post-filtrar Macie findings

### Fase 4: Verificación (10 min)
4. Ejecutar audit y verificar reducción de volumen
5. Verificar que solo se guardan findings Critical/High/Medium

**Total estimado:** 40 min

---

## ✅ Verificación

### Paso 1: Ejecutar Audit
```bash
python -m drystone audit --skills vulns,hardening
```

### Paso 2: Verificar Evidence Files
```bash
# Inspector findings (solo Critical/High/Medium)
cat audit-logs/*/evidence/vulns/inspector-findings.json | \
  jq '.[] | select(.severity != null) | .severity' | sort | uniq -c

# Debería mostrar solo:
#   X "CRITICAL"
#   Y "HIGH"
#   Z "MEDIUM"
# NO debe aparecer "LOW" ni "INFORMATIONAL"

# Security Hub findings
cat audit-logs/*/evidence/hardening/security-hub-findings.json | \
  jq '.[] | .Severity.Label' | sort | uniq -c

# Debería mostrar solo:
#   X "CRITICAL"
#   Y "HIGH"
#   Z "MEDIUM"
```

### Paso 3: Verificar Tamaño de Archivos
```bash
# Antes del filtrado (baseline esperado):
# inspector-findings.json: ~2MB (1000+ findings)
# security-hub-findings.json: ~5MB (2000+ findings)

# Después del filtrado (esperado):
# inspector-findings.json: ~600KB (300 findings) → 70% reducción
# security-hub-findings.json: ~1.5MB (600 findings) → 70% reducción

ls -lh audit-logs/*/evidence/vulns/inspector-findings.json
ls -lh audit-logs/*/evidence/hardening/security-hub-findings.json
```

### Paso 4: Verificar Findings Report
```bash
# Verificar que Claude solo analiza findings filtrados
cat audit-logs/*/findings/vulns.json | jq '.summary'
cat audit-logs/*/findings/hardening.json | jq '.summary'

# Summary debe mostrar solo Critical/High/Medium counts
# NO debe haber "low": N con valores > 0
```

---

## 🎯 Resultado Esperado

### Antes (Sin Filtrado)
```
Evidence:
- inspector-findings.json: 2MB (1000 findings, 70% LOW)
- security-hub-findings.json: 5MB (2000 findings, 70% LOW)

Analysis:
- Tokens: 1.5M → requires chunking
- API calls: 4-5 chunks × 2 skills = 8-10 calls
- Report: 50 páginas con ruido
```

### Después (Con Filtrado)
```
Evidence:
- inspector-findings.json: 600KB (300 findings, 100% relevant)
- security-hub-findings.json: 1.5MB (600 findings, 100% relevant)

Analysis:
- Tokens: 450K → NO chunking needed
- API calls: 1 call × 2 skills = 2 calls
- Report: 15 páginas enfocadas en crítico/alto/medio
```

**Mejoras:**
- ✅ 70% reducción en tamaño de evidence
- ✅ 75% reducción en API calls Claude
- ✅ 70% reducción en longitud de reportes
- ✅ Costos reducidos significativamente
- ✅ Análisis más rápido y enfocado

---

## 📚 Referencias

- [AWS Inspector ListFindings API](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html)
- [AWS Security Hub GetFindings API](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
- [AWS GuardDuty Severity Levels](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-severity.html)
- [AWS Inspector Severity Levels](https://docs.aws.amazon.com/inspector/latest/user/findings-understanding-severity.html)
