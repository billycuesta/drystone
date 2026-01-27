# Plan: Optimización de Inspector Findings para Claude CLI

## 🎯 Objetivo

**Problema:** Claude CLI falla con inspector-findings.json (7 MB, 1521 findings) debido a límite de argumentos del sistema (~128KB).

**Solución:** Estrategia combinada de reducción de datos para mantener Claude CLI:
1. Filtrar por severidad (solo CRITICAL + HIGH)
2. Simplificar campos verbosos
3. Mejorar chunking granular

**Resultado esperado:** 7 MB → 0.85 MB (-88% reducción), compatible con Claude CLI

---

## 📊 Situación Actual (DESPUÉS de implementación parcial)

### ✅ Ya Implementado (sesión anterior):
- `drystone/models/config.py`: campo `min_severity` agregado
- `drystone/skills/vulns/__init__.py`: filtro Inspector v2 con CRITICAL/HIGH/MEDIUM
- `drystone/skills/hardening/__init__.py`: filtros Security Hub, GuardDuty, Macie
- `drystone/agent/client.py`: import Path agregado, chunking habilitado

### ❌ Problema Actual:
```
inspector-findings.json: 7.0 MB (1,521 findings)
├─ CRITICAL: 4    (0.3%, 0.01 MB)
├─ HIGH: 471      (31%, 1.66 MB)
└─ MEDIUM: 1,046  (69%, 3.91 MB) ← 81% kernel CVEs (noise)

Tokens: ~1.9M tokens en UN chunk
Claude CLI error: [Errno 7] Argument list too long
```

### 🎯 Nueva Meta:
```
inspector-findings.json: 0.85 MB (475 findings)
├─ CRITICAL: 4    (0.8%, 0.01 MB)
└─ HIGH: 471      (99%, 0.84 MB)

Tokens: ~280K tokens total → 3-4 chunks pequeños
Claude CLI: ✅ FUNCIONA
```

---

## ✅ Solución: Estrategia Combinada (4 Fases)

---

## 📝 Fases de Implementación

### **Fase 1: Quitar MEDIUM del Filtro Inspector v2** (5 min)

**Archivo:** `drystone/skills/vulns/__init__.py`
**Ubicación:** Líneas 72-78

**Cambio:** Eliminar MEDIUM de filter_criteria (solo mantener CRITICAL + HIGH)

**ANTES:**
```python
filter_criteria = {
    'severity': [
        {'comparison': 'EQUALS', 'value': 'CRITICAL'},
        {'comparison': 'EQUALS', 'value': 'HIGH'},
        {'comparison': 'EQUALS', 'value': 'MEDIUM'}  # ← QUITAR
    ]
}
```

**DESPUÉS:**
```python
filter_criteria = {
    'severity': [
        {'comparison': 'EQUALS', 'value': 'CRITICAL'},
        {'comparison': 'EQUALS', 'value': 'HIGH'}
        # MEDIUM removed: 81% are low-score kernel CVEs (noise)
    ]
}
```

**Resultado:**
- Findings: 1,521 → 475 (-69%)
- Tamaño: 7.0 MB → 1.67 MB (-76%)
- Elimina 81% de kernel CVEs de bajo impacto

---

### **Fase 2: Simplificar Campos Verbosos** (15 min)

**Archivo:** `drystone/skills/vulns/__init__.py`
**Ubicación:** Después de línea 81 (dentro del loop de paginación)

**Problema:** AWS Inspector API NO soporta field projection → devuelve Finding completo

**Solución:** Post-procesamiento para eliminar campos innecesarios

**Implementar después de línea 81:**
```python
for page in paginator.paginate(filterCriteria=filter_criteria):
    raw_findings = page.get("findings", [])

    # Post-process: simplify findings (remove verbose fields)
    for finding in raw_findings:
        # Remove verbose nested objects
        finding.pop('packageVulnerabilityDetails', None)
        finding.pop('networkReachabilityDetails', None)
        finding.pop('codeVulnerabilityDetails', None)
        finding.pop('inspectorScoreDetails', None)
        finding.pop('epss', None)

        # Simplify resources (keep only essential fields)
        if 'resources' in finding:
            for resource in finding['resources']:
                resource.pop('details', None)  # Remove IPs, subnets, AMI IDs

        # Remove timestamps (not critical for analysis)
        finding.pop('firstObservedAt', None)
        finding.pop('lastObservedAt', None)
        finding.pop('updatedAt', None)

    findings_list.extend(raw_findings)
```

**Campos eliminados:**
- `packageVulnerabilityDetails` (referenceUrls, cvss, relatedVulnerabilities)
- `networkReachabilityDetails`, `codeVulnerabilityDetails`
- `inspectorScoreDetails` (score breakdown)
- `epss` (EPSS score details)
- `resources[].details` (IPs, subnets, AMI IDs)
- Timestamps (firstObservedAt, lastObservedAt, updatedAt)

**Campos mantenidos (críticos para análisis):**
- `findingArn`, `severity`, `type`, `status`, `title`, `description`
- `resources[].id`, `resources[].type`, `resources[].tags`
- `remediation`, `exploitAvailable`, `fixAvailable`
- `inspectorScore`

**Resultado:**
- Tamaño por finding: 3,858 bytes → 1,800 bytes (-53%)
- Tamaño total: 1.67 MB → 0.85 MB (-49% adicional)
- **Total combinado:** 7.0 MB → 0.85 MB (-88%)

---

### **Fase 3: Mejorar Chunking Granular** (20 min)

**Archivo:** `drystone/agent/chunker.py`
**Ubicación:** Nueva función después de línea 80

**Problema:** Actual `by_file` trata inspector-findings como UN chunk completo

**Solución:** Implementar `_chunk_large_file()` para subdividir archivos grandes

**Agregar nueva función:**
```python
def _chunk_large_file(
    self,
    filename: str,
    data: Any,
    resources_per_chunk: int = 30
) -> Iterator[EvidenceChunk]:
    """Chunk large arrays into smaller chunks.

    For files exceeding max_tokens, subdivide by resource count.
    Example: inspector-findings.json with 475 findings → 16 chunks of 30 findings.

    Args:
        filename: Source file name
        data: File data (must be list)
        resources_per_chunk: Max resources per chunk (default: 30 for CLI)

    Yields:
        EvidenceChunk instances with subdivided data
    """
    if not isinstance(data, list):
        # Not a list → cannot chunk, return as-is
        yield EvidenceChunk(
            chunk_id=1,
            total_chunks=1,
            evidence={filename: data},
            metadata={"source_file": filename}
        )
        return

    total_resources = len(data)
    total_chunks = (total_resources + resources_per_chunk - 1) // resources_per_chunk

    for i in range(0, total_resources, resources_per_chunk):
        chunk_data = data[i:i + resources_per_chunk]
        chunk_id = i // resources_per_chunk + 1

        yield EvidenceChunk(
            chunk_id=chunk_id,
            total_chunks=total_chunks,
            evidence={filename: chunk_data},
            metadata={
                "source_file": filename,
                "resource_range": f"{i+1}-{i+len(chunk_data)}/{total_resources}",
                "chunk_size_kb": len(json.dumps(chunk_data)) // 1024
            }
        )
```

**Modificar `chunk_evidence()` (líneas 40-60):**
```python
def chunk_evidence(
    self,
    evidence: Dict[str, Any]
) -> Iterator[EvidenceChunk]:
    """Split evidence into manageable chunks."""

    if self.strategy == "by_file":
        for filename, data in evidence.items():
            file_tokens = self._estimate_tokens({filename: data})

            if file_tokens > self.max_tokens:
                # File too large → subdivide
                yield from self._chunk_large_file(filename, data)
            else:
                # File fits in one chunk
                yield EvidenceChunk(
                    chunk_id=1,
                    total_chunks=1,
                    evidence={filename: data},
                    metadata={"source_file": filename}
                )
```

**Resultado con 475 findings CRITICAL/HIGH:**
- Chunk size: 30 findings/chunk
- Total chunks: 16 chunks
- Tokens/chunk: ~17K tokens (dentro del límite de 20K)

---

### **Fase 4: Ajustar Límites de Claude CLI** (5 min)

**Archivo:** `drystone/agent/client.py`
**Ubicación:** Línea 347

**Cambio:** Reducir límite para Claude CLI (más conservador)

**ANTES:**
```python
if chunker is None:
    max_tokens = 15000 if self.config.get('type') == 'bedrock' else 40000
    chunker = EvidenceChunker(max_tokens_per_chunk=max_tokens)
```

**DESPUÉS:**
```python
if chunker is None:
    # Adjust limits per provider
    provider_type = self.config.get('type', 'claude-cli')

    if provider_type == 'bedrock':
        max_tokens = 15000  # Nova Micro has smaller context
    elif provider_type == 'claude-cli':
        max_tokens = 20000  # CLI has OS argument limit, be conservative
    else:
        max_tokens = 40000  # API has better limits

    chunker = EvidenceChunker(max_tokens_per_chunk=max_tokens)
```

**Resultado:**
- Claude CLI: 40K → 20K tokens/chunk (más seguro)
- Claude API: 40K tokens/chunk (sin cambios)
- Bedrock: 15K tokens/chunk (sin cambios)

---

## 📋 Archivos Críticos a Modificar

### 1. `drystone/skills/vulns/__init__.py` (Fases 1 y 2)
**Cambios:**
- Línea 72-78: Quitar MEDIUM del filtro Inspector
- Línea 81+: Post-procesar findings para simplificar campos

**Status:** ✅ Ya tiene filtro severity (sesión anterior), ahora actualizar

### 2. `drystone/agent/chunker.py` (Fase 3)
**Cambios:**
- Agregar función `_chunk_large_file()` después de línea 80
- Modificar `chunk_evidence()` para detectar archivos grandes y subdividirlos

**Status:** ⚠️ Actual solo hace `by_file` sin subdivisión

### 3. `drystone/agent/client.py` (Fase 4)
**Cambios:**
- Línea 347: Reducir límite Claude CLI de 40K → 20K tokens

**Status:** ✅ Ya tiene chunking habilitado (sesión anterior), solo ajustar límite

### 4. `drystone/skills/hardening/__init__.py` (Opcional)
**Status:** ✅ Ya tiene filtros implementados (sesión anterior), no requiere cambios

### 5. `drystone/models/config.py` (Referencia)
**Status:** ✅ Ya tiene campo `min_severity` (sesión anterior), no requiere cambios

---

## ✅ Verificación End-to-End

### Paso 1: Ejecutar Audit con Vulns
```bash
source .venv/bin/activate
python3 -m drystone audit --skills vulns --non-interactive
```

### Paso 2: Verificar Severidades Filtradas
```bash
# Verificar que solo CRITICAL + HIGH están presentes (NO MEDIUM)
python3 << 'EOF'
import json, glob

files = glob.glob("audit-logs/*/evidence/vulns/inspector-findings.json")
for fpath in sorted(files)[-1:]:  # Latest file
    with open(fpath) as f:
        data = json.load(f)

    severities = {}
    for finding in data:
        sev = finding.get('severity', 'UNKNOWN')
        severities[sev] = severities.get(sev, 0) + 1

    print(f"Total findings: {len(data)}")
    print(f"Severities: {severities}")

    # Verify NO MEDIUM
    if 'MEDIUM' in severities:
        print("❌ ERROR: MEDIUM findings still present!")
    else:
        print("✅ SUCCESS: Only CRITICAL/HIGH")
EOF
```

**Expected output:**
```
Total findings: 475
Severities: {'CRITICAL': 4, 'HIGH': 471}
✅ SUCCESS: Only CRITICAL/HIGH
```

### Paso 3: Verificar Tamaño de Archivo
```bash
# Check file size reduction
find audit-logs -name "inspector-findings.json" -mmin -5 -exec ls -lh {} \;
```

**Expected output:**
```
-rw-r--r-- 1 user staff 850K Jan 26 06:30 inspector-findings.json
```

**Comparación:**
- Antes: 7.0 MB (1,521 findings)
- Después: 0.85 MB (475 findings)
- Reducción: **88%**

### Paso 4: Verificar Chunking Funciona
```bash
# Grep logs for chunking messages
tail -100 audit-logs/*/logs/audit.log | grep -E "chunk|📦"
```

**Expected output:**
```
📦 Evidence size requires chunking...
📦 Processing 16 chunks...
   Chunk 1/16: inspector-findings (30 findings)
   Chunk 2/16: inspector-findings (30 findings)
   ...
   Chunk 16/16: inspector-findings (25 findings)
✅ Aggregated 14 findings from 16 chunks
```

### Paso 5: Verificar Claude CLI NO Falla
```bash
# Check NO "Argument list too long" error
tail -50 audit-logs/*/logs/audit.log | grep -i "error\|errno"
```

**Expected:** NO debe aparecer "[Errno 7] Argument list too long"

### Paso 6: Verificar Análisis Completo
```bash
# Check findings were generated
cat audit-logs/*/findings/vulns.json | jq '.summary'
```

**Expected output:**
```json
{
  "total_findings": 14,
  "critical": 3,
  "high": 5,
  "medium": 4,
  "low": 2,
  "overall_risk_score": 7.2
}
```

---

## 🎯 Resultado Esperado

### Antes (Situación Actual - CON MEDIUM)
```
inspector-findings.json:
├─ Findings: 1,521
├─ Severidades: CRITICAL(4) + HIGH(471) + MEDIUM(1046)
├─ Tamaño: 7.0 MB
├─ Tokens: 1.9M tokens
├─ Chunking: 1 chunk gigante
└─ Claude CLI: ❌ FALLA (Errno 7)
```

### Después (Estrategia Combinada)
```
inspector-findings.json:
├─ Findings: 475 (-69%)
├─ Severidades: CRITICAL(4) + HIGH(471) only
├─ Tamaño: 0.85 MB (-88%)
├─ Tokens: 280K tokens (-85%)
├─ Chunking: 16 chunks pequeños (~17K tokens c/u)
└─ Claude CLI: ✅ FUNCIONA
```

**Mejoras:**
- ✅ 88% reducción en tamaño de evidence
- ✅ 85% reducción en tokens
- ✅ Elimina 81% de noise (kernel CVEs de bajo score)
- ✅ Chunking granular compatible con límite CLI
- ✅ Reportes enfocados en hallazgos críticos/altos
- ✅ Mantiene Claude CLI (no requiere cambiar a API)

---

## 📚 Referencias

- [AWS Inspector ListFindings API](https://docs.aws.amazon.com/inspector/v2/APIReference/API_ListFindings.html)
- [AWS Inspector Finding Structure](https://docs.aws.amazon.com/inspector/v2/APIReference/API_Finding.html)
- [Inspector Severity Levels](https://docs.aws.amazon.com/inspector/latest/user/findings-understanding-severity.html)

---

## 📝 Resumen de Implementación

| Fase | Archivo | Cambio | Impacto |
|------|---------|--------|---------|
| 1 | `vulns/__init__.py` | Quitar MEDIUM del filtro | -69% findings |
| 2 | `vulns/__init__.py` | Simplificar campos verbosos | -49% tamaño adicional |
| 3 | `chunker.py` | Implementar `_chunk_large_file()` | Chunks granulares |
| 4 | `client.py` | Reducir límite CLI 40K→20K | Más estabilidad |

**Total estimado:** 45 minutos

**Resultado final:** 7 MB → 0.85 MB (-88%), compatible con Claude CLI
