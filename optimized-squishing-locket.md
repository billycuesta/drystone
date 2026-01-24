# Plan: Wizard AWS Credentials - File-Based & Secure Storage

## 🎯 Objetivo

Rediseñar el wizard de Drystone para soportar **lectura de credenciales desde archivo** y **almacenamiento seguro del path** (en lugar de credenciales en texto plano).

---

## 📊 Estado Actual (Problemas Identificados)

### Flujo Actual
1. Usuario introduce **Access Key ID** y **Secret Access Key** manualmente
2. Wizard valida vía STS GetCallerIdentity
3. Credenciales se almacenan en **texto plano** en `~/.drystone/last-run.json`
4. `--non-interactive` recarga credenciales de `last-run.json`

### Problemas de Seguridad
- ✅ **CWE-256**: Plain-text credential storage
- ✅ **No encryption**: Secrets en filesystem sin protección
- ✅ **Repetición manual**: Usuario debe re-introducir credenciales cada vez (si no usa `--non-interactive`)
- ⚠️ **Riesgo de leak**: `last-run.json` podría committearse accidentalmente

### Archivos Críticos
| Archivo | Rol Actual |
|---------|-----------|
| `drystone/cli/ui/wizard.py` | Colecta credenciales manualmente (líneas 174-217) |
| `drystone/models/config.py` | `WizardConfig` almacena `aws_access_key_id`, `aws_secret_access_key` como `str` |
| `drystone/cli/config.py` | Guarda/carga config en `~/.drystone/last-run.json` (texto plano) |
| `drystone/cloud/aws/client.py` | Valida credenciales vía STS |

---

## 🔄 Alternativas Propuestas

### Alternativa 1: **Archivo de Credenciales JSON/YAML** (Recomendada)

**Descripción:**
- Wizard pregunta: "¿Introducir credenciales manualmente o leer desde archivo?"
- Si "desde archivo": prompt para path al archivo
- Archivo formato estándar:
  ```json
  {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_session_token": null,
    "aws_region": "us-east-1"
  }
  ```
- `last-run.json` guarda **solo el path**, no las credenciales:
  ```json
  {
    "client_name": "ACME Corp",
    "aws_credentials_file": "~/.aws/drystone-creds.json",  // NEW FIELD
    "aws_region": "us-east-1",
    "skills": ["iam"],
    ...
  }
  ```
- En runtime: **lazy load** de credenciales desde el archivo

**Pros:**
- ✅ Separa configuración de secretos
- ✅ Archivo de credenciales puede tener permisos `600` (owner-only read)
- ✅ Reutilizable: mismo archivo para múltiples proyectos
- ✅ No modifica credenciales en cada audit
- ✅ Compatible con rotación de credenciales (editas el archivo, no la config)

**Cons:**
- ⚠️ Credenciales aún en texto plano (pero archivo separado con mejores permisos)
- ⚠️ Usuario debe crear/gestionar archivo manualmente

**Implementación:**
1. Nuevo campo en `WizardConfig`: `aws_credentials_file: Optional[Path]`
2. Wizard Menu A: nueva opción "Read from file"
3. Prompt para file path (con validación de existencia)
4. Leer credenciales al inicio de `audit()`
5. Validar credenciales después de leer

---

### Alternativa 2: **AWS Credentials File Estándar** (`~/.aws/credentials`)

**Descripción:**
- Seguir el estándar de AWS CLI
- Wizard pregunta por **profile name** en lugar de credenciales
- Lee de `~/.aws/credentials`:
  ```ini
  [drystone-prod]
  aws_access_key_id = AKIAIOSFODNN7EXAMPLE
  aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  region = us-east-1
  ```
- Usar boto3's default credential chain

**Pros:**
- ✅ Estándar AWS (mismo archivo que AWS CLI, SDKs)
- ✅ Soporte para múltiples profiles
- ✅ boto3 maneja lectura/parsing automáticamente
- ✅ Usuarios familiarizados con AWS ya lo tienen configurado

**Cons:**
- ❌ **Contradice decisión de diseño anterior** (commit `4599598` eliminó soporte de profiles deliberadamente)
- ⚠️ Menos control sobre validación
- ⚠️ Credenciales aún en texto plano (pero es el estándar AWS)

**Implementación:**
1. Reintroducir soporte de profiles (revertir decisión anterior)
2. Wizard pregunta: "Manual entry" o "AWS Profile"
3. Campo `aws_profile: Optional[str]` en `WizardConfig`
4. Usar `boto3.Session(profile_name=...)` en `AWSClient`

**Nota:** Requiere **revisión de decisión de arquitectura**. Documento `PROJECT_STATE.md` línea 59 dice:
> "Direct credentials instead of AWS profiles (decided 2026-01-18)"

---

### Alternativa 3: **Keyring Integration** (Más Seguro)

**Descripción:**
- Almacenar credenciales en el sistema de keyring del OS
- macOS: Keychain
- Linux: Secret Service API (gnome-keyring, KWallet)
- Windows: Windows Credential Locker
- Usar librería `keyring` (Python)

**Implementación:**
```python
import keyring

# Guardar
keyring.set_password("drystone", "aws_access_key_id", access_key)
keyring.set_password("drystone", "aws_secret_access_key", secret_key)

# Leer
access_key = keyring.get_password("drystone", "aws_access_key_id")
secret_key = keyring.get_password("drystone", "aws_secret_access_key")
```

**`last-run.json` almacena solo flag:**
```json
{
  "client_name": "ACME",
  "use_keyring": true,  // NEW FIELD
  "aws_region": "us-east-1",
  ...
}
```

**Pros:**
- ✅ **Más seguro**: Credenciales encriptadas por el OS
- ✅ No hay texto plano en filesystem
- ✅ Integración nativa con OS security
- ✅ Mejor UX: credenciales persisten entre sesiones

**Cons:**
- ⚠️ Dependencia extra: `keyring` library
- ⚠️ Complejidad en CI/CD (headless environments)
- ⚠️ Requiere configuración inicial en algunos Linux

**Implementación:**
1. Agregar `keyring` a dependencies
2. Wizard pregunta: "Store in keyring?"
3. En `config.py`: funciones `save_to_keyring()` / `load_from_keyring()`
4. Lazy load en runtime

---

### Alternativa 4: **Variables de Entorno** (Simple)

**Descripción:**
- Wizard lee de variables de entorno si están definidas
- Orden de prioridad:
  1. CLI args (si se implementaran)
  2. Environment variables
  3. Credential file
  4. Manual entry (wizard)

**Variables soportadas:**
```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=optional_token
export AWS_DEFAULT_REGION=us-east-1
```

**Pros:**
- ✅ Patrón estándar (AWS SDK, CLI, todos lo soportan)
- ✅ Fácil en CI/CD
- ✅ No modifica `last-run.json`
- ✅ Zero config si ya están definidas

**Cons:**
- ⚠️ Credenciales en memoria (proceso env)
- ⚠️ Pueden leakearse en logs de shell (`printenv`, history)
- ⚠️ Menos secure que keyring

**Implementación:**
1. En `wizard.py`: check env vars antes de preguntar
2. Si definidas: skip credential prompts, usar env vars
3. Validar igual que manual entry

---

## 🎯 Decisión: **Híbrido (Alt 1 + Alt 2 + Alt 4)**

### Estrategia de Credenciales en Cascada

**Orden de prioridad (definido por usuario):**
1. **Manual entry** (introducción directa en wizard, backward compatible)
2. **Credential file** (JSON custom o `~/.aws/credentials` profile)
3. **Environment variables** (fallback automático si no hay otras fuentes)

**Ventajas:**
- ✅ Flexibilidad máxima (3 métodos soportados)
- ✅ Compatible con CI/CD (env vars como fallback)
- ✅ Compatible con desarrollo local (credential file)
- ✅ Backward compatible (manual entry tiene prioridad)
- ✅ Seguridad mejorada (credential file con path, no plain-text en `last-run.json`)
- ✅ AWS estándar (soporte para `~/.aws/credentials`)

### Cambios en `WizardConfig`

```python
class WizardConfig(BaseModel):
    client_name: str

    # OPCIÓN 1: Credenciales directas (manual entry, backward compat)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None

    # OPCIÓN 2: Custom credential file JSON (NEW)
    aws_credentials_file: Optional[Path] = None

    # OPCIÓN 3: AWS profile estándar (NEW, revierte decisión anterior)
    aws_profile: Optional[str] = None

    aws_region: str = "us-east-1"
    skills: List[str]
    output_formats: List[Literal["markdown", "json"]]
    ...

    def get_aws_credentials(self) -> Tuple[str, str, Optional[str]]:
        """Get credentials with priority: manual > file > env."""

        # Priority 1: Manual entry (direct credentials)
        if self.aws_access_key_id and self.aws_secret_access_key:
            return (self.aws_access_key_id, self.aws_secret_access_key, self.aws_session_token)

        # Priority 2: Credential file (custom JSON or AWS profile)
        if self.aws_credentials_file:
            return self._load_from_file()

        if self.aws_profile:
            return self._load_from_aws_profile()

        # Priority 3: Environment variables (fallback)
        if env_vars := self._check_env_vars():
            return env_vars

        raise ValueError("No AWS credentials configured")

    def _load_from_file(self) -> Tuple[str, str, Optional[str]]:
        """Load credentials from custom JSON file."""
        import json
        from pathlib import Path

        file_path = Path(self.aws_credentials_file).expanduser()
        if not file_path.exists():
            raise FileNotFoundError(f"Credential file not found: {file_path}")

        with open(file_path) as f:
            data = json.load(f)

        return (
            data["aws_access_key_id"],
            data["aws_secret_access_key"],
            data.get("aws_session_token"),
        )

    def _load_from_aws_profile(self) -> Tuple[str, str, Optional[str]]:
        """Load credentials from ~/.aws/credentials profile."""
        import boto3

        session = boto3.Session(profile_name=self.aws_profile)
        creds = session.get_credentials()

        if not creds:
            raise ValueError(f"No credentials found for profile: {self.aws_profile}")

        return (creds.access_key, creds.secret_key, creds.token)

    def _check_env_vars(self) -> Optional[Tuple[str, str, Optional[str]]]:
        """Check for AWS credentials in environment variables."""
        import os

        access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

        if access_key and secret_key:
            return (access_key, secret_key, os.environ.get("AWS_SESSION_TOKEN"))

        return None
```

### Wizard Flow Modificado

```
Menu A: Project Configuration
├─ Client Name: [input]
├─ AWS Credentials:
│  ├─ (1) Enter manually
│  ├─ (2) Read from JSON file
│  ├─ (3) Use AWS profile (~/.aws/credentials)
│  └─ (4) Use environment variables
├─ AWS Region: [select]
├─ Skills: [checkbox]
└─ Output Formats: [checkbox]

Si elige (1) - Manual entry:
  ├─ AWS Access Key ID: [input]
  ├─ AWS Secret Access Key: [password masked]
  ├─ AWS Session Token (optional): [password masked]
  ├─ Validar vía STS
  └─ Guardar credenciales en last-run.json (backward compat)

Si elige (2) - JSON file:
  ├─ File path: [input con autocomplete, default: ~/.aws/drystone-creds.json]
  ├─ Validar que archivo existe
  ├─ Parsear JSON: {"aws_access_key_id": "...", "aws_secret_access_key": "...", ...}
  ├─ Validar credenciales vía STS
  ├─ Guardar SOLO path en last-run.json (NO credenciales)
  └─ Check permisos: warning si no es 600

Si elige (3) - AWS profile:
  ├─ Profile name: [input, default: "default"]
  ├─ Verificar que ~/.aws/credentials existe
  ├─ Cargar credenciales vía boto3.Session(profile_name=...)
  ├─ Validar vía STS
  └─ Guardar SOLO profile name en last-run.json (NO credenciales)

Si elige (4) - Environment variables:
  ├─ Detectar env vars (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  ├─ Mostrar preview enmascarado: "AKIA***AMPLE"
  ├─ Validar vía STS
  └─ NO guardar nada (env vars son runtime, no persistentes)
```

---

## 📝 Implementación Detallada

### Fase 1: Estructura de Datos

**Archivos a modificar:**
- `drystone/models/config.py`

**Cambios:**
1. Agregar campo `aws_credentials_file: Optional[Path] = None`
2. Deprecar campos directos (mantener para backward compat)
3. Método `get_aws_credentials()` para resolver cascada
4. Método `_load_from_file()` para leer JSON/YAML
5. Método `_check_env_vars()` para detectar env vars

### Fase 2: Wizard Interactivo

**Archivos a modificar:**
- `drystone/cli/ui/wizard.py`

**Cambios:**
1. Nueva pregunta: "How to provide AWS credentials?"
   - Manual entry
   - Read from file
   - Use environment variables
2. Condicional: si "file", prompt para path
3. Validación de archivo (existencia, formato)
4. Preview enmascarado de credenciales cargadas
5. Validación STS como antes

### Fase 3: Persistencia Segura

**Archivos a modificar:**
- `drystone/cli/config.py`

**Cambios:**
1. `save_config()`: guardar path, NO credenciales
2. Migración automática de configs antiguas
3. Permisos de archivo: `chmod 600` para credential files

### Fase 4: Runtime Loading

**Archivos a modificar:**
- `drystone/cli/main.py`
- `drystone/cloud/aws/client.py`

**Cambios:**
1. `audit()`: resolver credenciales vía `config.get_aws_credentials()`
2. AWSClient: aceptar credenciales desde múltiples fuentes
3. Validación al inicio como antes

---

## 🧪 Validación

### Test Cases

1. **Manual Entry (Backward Compat):**
   ```bash
   python -m drystone audit
   # Wizard: choose "Enter manually"
   # Input: Access Key ID, Secret Access Key
   # Verify: audit runs, credentials in last-run.json (plain-text, legacy)
   ```

2. **Credential File (JSON):**
   ```bash
   echo '{"aws_access_key_id":"AKIA...","aws_secret_access_key":"secret","aws_region":"us-east-1"}' > ~/.aws/drystone-creds.json
   chmod 600 ~/.aws/drystone-creds.json
   python -m drystone audit
   # Wizard: choose "Read from JSON file" → path: ~/.aws/drystone-creds.json
   # Verify: audit runs, last-run.json contains path only (NO credentials)
   ```

3. **AWS Profile (Standard):**
   ```bash
   # Ensure ~/.aws/credentials exists with a profile
   python -m drystone audit
   # Wizard: choose "Use AWS profile" → profile: drystone-prod
   # Verify: audit runs, last-run.json contains profile name only
   ```

4. **Environment Variables (Fallback):**
   ```bash
   export AWS_ACCESS_KEY_ID=AKIA...
   export AWS_SECRET_ACCESS_KEY=secret
   python -m drystone audit
   # Wizard: choose "Use environment variables"
   # Verify: audit runs, NO credentials saved in last-run.json
   ```

5. **Non-interactive con file:**
   ```bash
   # Configurar credential file en wizard (primera vez)
   python -m drystone audit --non-interactive
   # Verify: lee de file automáticamente (lazy load)
   ```

6. **Non-interactive con profile:**
   ```bash
   # Configurar AWS profile en wizard (primera vez)
   python -m drystone audit --non-interactive
   # Verify: carga credenciales de ~/.aws/credentials automáticamente
   ```

7. **Invalid file path:**
   ```bash
   # Wizard: choose file, path: /nonexistent/creds.json
   # Verify: error message "File not found", retry prompt
   ```

8. **Invalid AWS profile:**
   ```bash
   # Wizard: choose profile, name: nonexistent-profile
   # Verify: error message "No credentials found for profile", retry prompt
   ```

9. **Priority override:**
   ```bash
   # Configurar manual entry en last-run.json
   # Set environment variables
   python -m drystone audit --non-interactive
   # Verify: usa manual entry (priority 1), NO env vars
   ```

### Security Checks

1. **Credential masking:**
   - Verificar que `display_config_summary()` NO muestra credenciales de archivo
   - Solo mostrar path: `~/.aws/drystone-creds.json`

2. **File permissions:**
   - Verificar que credential files tienen permisos `600` (owner read-only)
   - Warning si permisos son muy abiertos (644, 755)

3. **No plain-text:**
   - Verificar que `last-run.json` NO contiene `aws_access_key_id` si se usa file
   - Grep para asegurar: `grep -i "secret" ~/.drystone/last-run.json` → no match

---

## 📂 Archivos Críticos

| Archivo | Acción | Propósito |
|---------|--------|-----------|
| `drystone/models/config.py` | Modificar | Agregar `aws_credentials_file`, `aws_profile`, `bedrock_credentials_file`, `bedrock_profile`, `bedrock_use_same_credentials`. Métodos: `get_aws_credentials()`, `get_bedrock_credentials()`, `_load_from_file()`, `_load_from_aws_profile()`, `_check_env_vars()`, `_check_bedrock_env_vars()` |
| `drystone/cli/ui/wizard.py` | Modificar | 4 opciones: manual, JSON file, AWS profile, env vars. Prompts condicionales para cada opción. |
| `drystone/cli/config.py` | Modificar | Guardar path/profile en vez de credenciales (si aplica), migración de configs antiguos |
| `drystone/cli/main.py` | Modificar | Lazy load de credenciales en `audit()` vía `config.get_aws_credentials()` |
| `drystone/cloud/aws/client.py` | Review | Verificar compatibilidad con credenciales desde múltiples fuentes (manual, file, profile, env) |
| `tests/cli/test_wizard.py` | Crear | Tests para 4 métodos de credential input |
| `tests/cli/test_config.py` | Crear | Tests para persistencia de path/profile, backward compat |
| `tests/models/test_config.py` | Crear | Tests unitarios para `get_aws_credentials()`, `_load_from_file()`, `_load_from_aws_profile()`, `_check_env_vars()` |
| `PROJECT_STATE.md` | Actualizar | Documentar reversión de decisión "no profiles" (commit `4599598` es revertido) |
| `CLAUDE.md` | Actualizar | Nueva sección sobre credential sources y prioridades |

---

## 🚀 Roadmap

### Week 1: Foundation (Models & Core Logic)

**AWS Audit Credentials:**
- [ ] Implementar `aws_credentials_file: Optional[Path]` en `WizardConfig`
- [ ] Implementar `aws_profile: Optional[str]` en `WizardConfig`
- [ ] Método `get_aws_credentials()` con cascada (manual > file > env)
- [ ] Método `_load_from_file()` para JSON parsing
- [ ] Método `_load_from_aws_profile()` vía boto3
- [ ] Método `_check_env_vars()` para env var detection

**Bedrock Credentials:**
- [ ] Implementar `bedrock_credentials_file: Optional[Path]` en `WizardConfig`
- [ ] Implementar `bedrock_profile: Optional[str]` en `WizardConfig`
- [ ] Implementar `bedrock_use_same_credentials: bool` (opción recomendada)
- [ ] Método `get_bedrock_credentials()` con cascada (manual > file > env)
- [ ] Método `_load_bedrock_from_file()` para JSON parsing
- [ ] Método `_check_bedrock_env_vars()` (BEDROCK_AWS_* o AWS_* fallback)
- [ ] Unit tests para `config.py` (13 test cases: 9 AWS + 4 Bedrock)

### Week 2: Wizard UI (4 Credential Sources)

**Menu A: AWS Audit Credentials**
- [ ] Nueva pregunta: "How to provide AWS credentials?" (4 opciones)
- [ ] Opción 1: Manual entry (mantener flujo actual)
- [ ] Opción 2: JSON file (prompt path, validar existencia)
- [ ] Opción 3: AWS profile (prompt name, validar ~/.aws/credentials)
- [ ] Opción 4: Env vars (detectar, mostrar preview enmascarado)
- [ ] Preview enmascarado para todas las opciones
- [ ] Integración con validación STS (sin cambios)

**Menu B: Bedrock Credentials (si ai_provider=bedrock)**
- [ ] Nueva pregunta: "How to provide Bedrock credentials?" (5 opciones)
- [ ] Opción 0: Use same credentials as AWS audit (recomendada, default)
- [ ] Opción 1: Manual entry
- [ ] Opción 2: JSON file (separate file o unificado)
- [ ] Opción 3: AWS profile (mismo o diferente)
- [ ] Opción 4: Env vars (BEDROCK_AWS_* o AWS_* fallback)
- [ ] Condicional: solo preguntar si ai_provider=bedrock
- [ ] Preview enmascarado para todas las opciones

### Week 3: Persistence & Security
- [ ] `save_config()`: guardar path/profile (NO credenciales) para opciones 2-4
- [ ] Mantener backward compat: opción 1 guarda credenciales (legacy)
- [ ] Migración automática de configs antiguos
- [ ] File permissions check: warning si credential file no es 600
- [ ] Actualizar `display_config_summary()`: mostrar path/profile en vez de credenciales
- [ ] NO deprecation warnings (backward compat permanente)

### Week 4: Integration & Testing

**Integration:**
- [ ] `audit()` en main.py: lazy load vía `config.get_aws_credentials()`
- [ ] Bedrock client: lazy load vía `config.get_bedrock_credentials()`
- [ ] Verificar compatibilidad con `--non-interactive` para todas las opciones

**Testing:**
- [ ] 13 test cases de validación (9 AWS + 4 Bedrock, ver sección Test Cases)
- [ ] Security checks (credential masking, file permissions)
- [ ] Backward compatibility tests (configs antiguos con credenciales directas)
- [ ] Test de opción "Use same credentials" para Bedrock

**Documentation:**
- [ ] `README.md`: nuevas opciones de credenciales (AWS + Bedrock)
- [ ] `CLAUDE.md`: credential sources, prioridades, y ejemplos de uso
- [ ] `PROJECT_STATE.md`: reversión de decisión "no profiles"
- [ ] Agregar sección "Security Best Practices" sobre credential storage
- [ ] Ejemplos de credential files (JSON, AWS profiles)

---

## 🔐 Consideraciones de Seguridad

### Mitigaciones Actuales
- ✅ Masked input en wizard
- ✅ No logging de credenciales
- ✅ No CLI args para credenciales

### Mejoras con Este Plan
- ✅ No más plain-text en `last-run.json`
- ✅ Credential files separados con permisos restrictivos
- ✅ Soporte para env vars (CI/CD friendly)
- ✅ Deprecation path para credenciales directas

### Future Enhancements (Opcional)
- 🔮 Keyring integration (Alternativa 3)
- 🔮 AWS Secrets Manager integration
- 🔮 Encrypted credential files
- 🔮 Credential rotation automation

---

## ✅ Decisión Final del Usuario

### Alcance: AWS Audit Credentials + Bedrock Credentials

**Problema:** Drystone requiere introducir credenciales manualmente en 2 contextos:
1. **AWS Audit Credentials**: Para colectar evidencia (IAM, Exposure, etc.)
2. **Bedrock Credentials**: Para usar Amazon Nova Micro como AI provider

**Solución:** Aplicar la misma estrategia de credential sources a AMBOS conjuntos de credenciales.

---

## ✅ Decisión Final del Usuario

### Alternativas a Implementar

1. **Alternativa 1: Archivo de Credenciales JSON** (NO YAML)
   - Formato: Solo JSON (`{"aws_access_key_id": "...", "aws_secret_access_key": "...", ...}`)
   - Guardar path en `last-run.json`, no credenciales
   - Permisos: `600` (owner read-only)

2. **Alternativa 2: AWS Credentials File Estándar** (`~/.aws/credentials`)
   - Soporte para perfiles AWS estándar
   - Wizard pregunta por profile name
   - Usar boto3's credential chain
   - **Revierte decisión anterior** de "no profiles"

3. **Alternativa 4: Variables de Entorno**
   - `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_DEFAULT_REGION`
   - Detección automática si están definidas
   - No guardar en `last-run.json`

### Orden de Prioridad (Decisión del Usuario)

**Prioridad: manual > file > env**

```
1. Manual entry (siempre disponible en wizard)
2. Credential file (JSON custom o ~/.aws/credentials)
3. Environment variables (fallback automático)
```

**Implementación:**
```python
def get_aws_credentials(self) -> Tuple[str, str, Optional[str]]:
    """Get credentials with priority: manual > file > env."""

    # Priority 1: Manual entry (stored directly)
    if self.aws_access_key_id and self.aws_secret_access_key:
        return (self.aws_access_key_id, self.aws_secret_access_key, self.aws_session_token)

    # Priority 2: Credential file
    if self.aws_credentials_file:
        return self._load_from_file()

    if self.aws_profile:  # AWS standard profile
        return self._load_from_aws_profile()

    # Priority 3: Environment variables (fallback)
    if env_vars := self._check_env_vars():
        return env_vars

    raise ValueError("No AWS credentials configured")
```

### Decisiones Específicas

- ✅ **Formato JSON**: Solo JSON, no YAML
- ✅ **AWS Profiles**: Sí, reintroducir soporte (revierte commit `4599598`)
- ✅ **Keyring**: No en esta fase (posible future enhancement)
- ✅ **Backward compatibility**: Sí, mantener credenciales directas
- ✅ **Permisos**: Warning si > 600 (no error bloqueante)
- ✅ **Prioridad**: manual > file > env (no env-first)

---

## 🔧 Extensión: Bedrock Credentials (Amazon Nova Micro)

### Problema Actual

**Contexto:** Drystone usa Amazon Bedrock Nova Micro como AI provider para análisis de evidencia.

**Credenciales requeridas:**
- `bedrock_access_key_id`
- `bedrock_secret_access_key`
- `bedrock_session_token` (opcional)

**Problema:**
- Almacenadas en texto plano en `~/.drystone/last-run.json`
- Hay que introducirlas manualmente cada vez (si no usas `--non-interactive`)
- Mismo problema de seguridad que AWS audit credentials

### Solución: Aplicar Misma Estrategia

**Implementar las mismas 3 alternativas para Bedrock:**

1. **Manual entry** (actual, backward compat)
2. **JSON credential file** (path almacenado)
3. **AWS profile** (mismo profile que audit credentials o separado)
4. **Environment variables** (fallback)

### Cambios en `WizardConfig`

```python
class WizardConfig(BaseModel):
    client_name: str

    # AWS Audit Credentials (3 métodos)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_credentials_file: Optional[Path] = None
    aws_profile: Optional[str] = None

    # Bedrock Credentials (3 métodos) - NEW
    bedrock_access_key_id: Optional[str] = None  # Legacy/manual
    bedrock_secret_access_key: Optional[str] = None  # Legacy/manual
    bedrock_session_token: Optional[str] = None  # Legacy/manual
    bedrock_credentials_file: Optional[Path] = None  # NEW
    bedrock_profile: Optional[str] = None  # NEW

    # Option: Reuse AWS credentials for Bedrock
    bedrock_use_same_credentials: bool = False  # NEW

    aws_region: str = "us-east-1"
    skills: List[str]
    output_formats: List[Literal["markdown", "json"]]
    ai_provider: Literal["claude-api", "claude-cli", "gemini-api", "bedrock"]
    ...

    def get_bedrock_credentials(self) -> Tuple[str, str, Optional[str]]:
        """Get Bedrock credentials with priority: manual > file > env."""

        # Option: Reuse AWS audit credentials for Bedrock
        if self.bedrock_use_same_credentials:
            return self.get_aws_credentials()

        # Priority 1: Manual entry (direct credentials)
        if self.bedrock_access_key_id and self.bedrock_secret_access_key:
            return (
                self.bedrock_access_key_id,
                self.bedrock_secret_access_key,
                self.bedrock_session_token,
            )

        # Priority 2: Credential file (custom JSON or AWS profile)
        if self.bedrock_credentials_file:
            return self._load_bedrock_from_file()

        if self.bedrock_profile:
            return self._load_from_aws_profile(profile_name=self.bedrock_profile)

        # Priority 3: Environment variables (fallback)
        if env_vars := self._check_bedrock_env_vars():
            return env_vars

        raise ValueError("No Bedrock credentials configured")

    def _load_bedrock_from_file(self) -> Tuple[str, str, Optional[str]]:
        """Load Bedrock credentials from custom JSON file."""
        import json
        from pathlib import Path

        file_path = Path(self.bedrock_credentials_file).expanduser()
        if not file_path.exists():
            raise FileNotFoundError(f"Bedrock credential file not found: {file_path}")

        with open(file_path) as f:
            data = json.load(f)

        return (
            data["aws_access_key_id"],  # Bedrock usa mismas keys que AWS
            data["aws_secret_access_key"],
            data.get("aws_session_token"),
        )

    def _check_bedrock_env_vars(self) -> Optional[Tuple[str, str, Optional[str]]]:
        """Check for Bedrock credentials in environment variables."""
        import os

        # Try Bedrock-specific env vars first
        access_key = os.environ.get("BEDROCK_AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("BEDROCK_AWS_SECRET_ACCESS_KEY")

        if access_key and secret_key:
            return (access_key, secret_key, os.environ.get("BEDROCK_AWS_SESSION_TOKEN"))

        # Fallback: use standard AWS env vars
        access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

        if access_key and secret_key:
            return (access_key, secret_key, os.environ.get("AWS_SESSION_TOKEN"))

        return None
```

### Wizard Flow para Bedrock (Menu B)

**Opción nueva: "Use same credentials as AWS audit?"**

```
Menu B: AI Configuration
├─ AI Provider: [select: claude-api, claude-cli, gemini-api, bedrock]
│
└─ Si elige "bedrock":
   ├─ Bedrock Credentials:
   │  ├─ (0) Use same credentials as AWS audit ⭐ RECOMENDADO
   │  ├─ (1) Enter manually
   │  ├─ (2) Read from JSON file
   │  ├─ (3) Use AWS profile
   │  └─ (4) Use environment variables
   │
   ├─ Si elige (0) - Reuse AWS credentials:
   │  └─ No preguntar nada, usar get_aws_credentials()
   │
   ├─ Si elige (1) - Manual entry:
   │  ├─ Bedrock Access Key ID: [input]
   │  ├─ Bedrock Secret Access Key: [password masked]
   │  └─ Bedrock Session Token (optional): [password masked]
   │
   ├─ Si elige (2) - JSON file:
   │  ├─ File path: [input, default: ~/.aws/bedrock-creds.json]
   │  ├─ Validar existencia
   │  └─ Guardar path en last-run.json
   │
   ├─ Si elige (3) - AWS profile:
   │  ├─ Profile name: [input, default: "default" o mismo que AWS audit]
   │  └─ Guardar profile name en last-run.json
   │
   └─ Si elige (4) - Environment variables:
      ├─ Detectar: BEDROCK_AWS_ACCESS_KEY_ID o AWS_ACCESS_KEY_ID (fallback)
      └─ NO guardar
```

### Formato de Credential Files

**Opción 1: Archivo separado para Bedrock**
```json
// ~/.aws/bedrock-creds.json
{
  "aws_access_key_id": "AKIABEDROCK...",
  "aws_secret_access_key": "bedrock-secret-key",
  "aws_session_token": null,
  "aws_region": "us-east-1"
}
```

**Opción 2: Archivo unificado (audit + bedrock)**
```json
// ~/.aws/drystone-creds.json
{
  "audit": {
    "aws_access_key_id": "AKIAAUDIT...",
    "aws_secret_access_key": "audit-secret",
    "aws_region": "us-east-1"
  },
  "bedrock": {
    "aws_access_key_id": "AKIABEDROCK...",
    "aws_secret_access_key": "bedrock-secret",
    "aws_region": "us-east-1"
  }
}
```

**Opción 3: AWS profile estándar con diferentes profiles**
```ini
# ~/.aws/credentials

[drystone-audit]
aws_access_key_id = AKIAAUDIT...
aws_secret_access_key = audit-secret

[drystone-bedrock]
aws_access_key_id = AKIABEDROCK...
aws_secret_access_key = bedrock-secret
```

### Environment Variables para Bedrock

**Bedrock-specific (priority 1):**
```bash
export BEDROCK_AWS_ACCESS_KEY_ID=AKIA...
export BEDROCK_AWS_SECRET_ACCESS_KEY=secret
export BEDROCK_AWS_SESSION_TOKEN=token
```

**Standard AWS (fallback si bedrock_use_same_credentials=true):**
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=secret
export AWS_SESSION_TOKEN=token
```

### Test Cases Adicionales (Bedrock)

10. **Reuse AWS credentials for Bedrock:**
    ```bash
    python -m drystone audit
    # Menu A: configure AWS credentials (file-based)
    # Menu B: choose bedrock → "Use same credentials as AWS audit"
    # Verify: bedrock_use_same_credentials=true, no separate credentials
    ```

11. **Separate Bedrock credentials (JSON):**
    ```bash
    # Create ~/.aws/bedrock-creds.json
    python -m drystone audit
    # Menu B: choose bedrock → "Read from JSON file" → ~/.aws/bedrock-creds.json
    # Verify: bedrock_credentials_file set, NO credentials in last-run.json
    ```

12. **Bedrock with AWS profile:**
    ```bash
    # Use profile "drystone-bedrock" in ~/.aws/credentials
    python -m drystone audit
    # Menu B: choose bedrock → "Use AWS profile" → drystone-bedrock
    # Verify: bedrock_profile="drystone-bedrock", credentials loaded at runtime
    ```

13. **Bedrock env vars:**
    ```bash
    export BEDROCK_AWS_ACCESS_KEY_ID=AKIA...
    export BEDROCK_AWS_SECRET_ACCESS_KEY=secret
    python -m drystone audit
    # Menu B: choose bedrock → "Use environment variables"
    # Verify: credentials from env, nothing saved
    ```

### Security Improvements

**Antes (vulnerable):**
```json
// ~/.drystone/last-run.json
{
  "aws_access_key_id": "AKIA...",
  "aws_secret_access_key": "audit-secret",
  "bedrock_access_key_id": "AKIA...",
  "bedrock_secret_access_key": "bedrock-secret"  // PLAIN TEXT!
}
```

**Después (seguro):**
```json
// ~/.drystone/last-run.json
{
  "aws_credentials_file": "~/.aws/drystone-audit.json",
  "bedrock_use_same_credentials": true  // NO credentials!
}
```

O:

```json
// ~/.drystone/last-run.json
{
  "aws_profile": "drystone-audit",
  "bedrock_profile": "drystone-bedrock"  // Only profiles, NO credentials!
}
```

### Recomendación para el Usuario

**Caso de uso común:**

1. **Mismas credenciales** para audit + bedrock:
   - Opción simple: `bedrock_use_same_credentials=true`
   - O usar mismo AWS profile para ambos

2. **Credenciales separadas** (más seguro para producción):
   - AWS profile separado: `drystone-audit` vs `drystone-bedrock`
   - O archivos JSON separados con diferentes permisos/rotación

3. **CI/CD:**
   - Environment variables para ambos (auto-detect)
   - Sin necesidad de archivos en filesystem
