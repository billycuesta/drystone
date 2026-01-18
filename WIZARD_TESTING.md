# 🧪 Wizard Iterativo - Testing Guide

## ✅ Nuevo Flujo

```
┌─────────────────────────────────────────────┐
│ python3 -m drystone audit                   │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│ Configuration Setup                         │
│                                             │
│ ? What would you like to do?                │
│   > 📋 Configure Menu A: Project Scope      │
│     🤖 Configure Menu B: AI Configuration   │
│                                             │
│ ❌ "Continue" NO aparece (Menu A vacío)    │
└─────────────────────────────────────────────┘
                    ↓
    ┌──────────────────────────────────┐
    │ Usuario elige Menu A             │
    └──────────────────────────────────┘
                    ↓
    ┌──────────────────────────────────┐
    │ Menu A: Project & AWS Scope      │
    │ (completa formulario)            │
    └──────────────────────────────────┘
                    ↓
    ┌──────────────────────────────────┐
    │ ✅ Menu A updated!               │
    │                                  │
    │ Display Config Summary:          │
    │ - Project Scope                  │
    │ - AI Configuration               │
    │                                  │
    │ ? What would you like to do?     │
    │   ✅ "Continue" APARECE AHORA    │
    └──────────────────────────────────┘
```

## ✅ Criterios de Éxito

### Phase 1: Inicio del Wizard
- [x] NO pide Menu A obligatoriamente
- [x] Comienza con menu de navegación
- [x] Solo muestra 2 opciones inicialmente (sin Continue)
- [x] Menu B usa defaults (claude-cli)

### Phase 2: Primera Configuración
- [ ] Usuario puede elegir Menu A o Menu B
- [ ] Si elige Menu A: completa y valida AWS
- [ ] Si elige Menu B: abre menu de AI (sin necesidad de Menu A)

### Phase 3: Después de Menu A
- [ ] Display config summary aparece
- [ ] Review screen muestra ambos menus
- [ ] Opción "Continue" aparece

### Phase 4: Edit Menu A
- [ ] Valores previos están pre-llenos (excepto secret)
- [ ] AWS credentials se re-validan

### Phase 5: Edit Menu B
- [ ] Valores previos están pre-llenos (sin API key por seguridad)
- [ ] No requiere re-validación AWS

### Phase 6: Loop & Finalization
- [ ] Usuario puede editar múltiples veces
- [ ] "Continue" solo aparece después que Menu A esté completo
- [ ] Config final combina ambos menús

---

## 🧑‍💻 Manual Testing Cases

### Test 1: Empezar con Menu A

```bash
python3 -m drystone audit

# ✅ PRIMER MENÚ - Debería mostrar solo 2 opciones (sin Continue)
# ? Configuration Setup
#   > 📋 Configure Menu A: Project Scope
#     🤖 Configure Menu B: AI Configuration

# ✅ Elegir "Configure Menu A"
# → Client: "TestCorp"
# → Access Key: "AKIA..."
# → Secret Key: "wJal..."
# → Region: "us-east-1"
# → Skills: [iam, exposure]
# → Formats: [markdown, json]

# ✅ Ver Review Screen con Config Summary

# ✅ SEGUNDO MENÚ - Ahora APARECE "Continue"
# ? What would you like to do?
#   > 📋 Configure Menu A: Project Scope
#     🤖 Configure Menu B: AI Configuration
#     ✅ Continue with current configuration

# ✅ Seleccionar "Continue"
# → Wizard termina, retorna config
```

**Expected Output:**
```
? Configuration Setup
  > 📋 Configure Menu A: Project Scope
    🤖 Configure Menu B: AI Configuration

[User presses Enter on "Configure Menu A"]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 MENU A: Review Scope
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[... wizard forms ...]

✅ Menu A updated!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 CURRENT CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Project Scope:
   Client Name: TestCorp
   AWS Region: us-east-1
   AWS Access Key: AKIA...MPLE
   Security Skills: iam, exposure
   Output Formats: markdown, json

🤖 AI Configuration:
   Provider: claude-cli
   API Key: not required (using CLI)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

? What would you like to do?
  > 📋 Configure Menu A: Project Scope
    🤖 Configure Menu B: AI Configuration
    ✅ Continue with current configuration
```

---

### Test 2: Empezar con Menu B (sin Menu A)

```bash
python3 -m drystone audit

# ✅ PRIMER MENÚ - Sin Continue
# ? Configuration Setup
#   > 📋 Configure Menu A: Project Scope
#     🤖 Configure Menu B: AI Configuration

# ✅ Elegir "Configure Menu B" PRIMERO
# → Provider: "claude-api"
# → API Key: "sk-ant-test123"

# ✅ Volver al menú - TODAVÍA sin Continue (Menu A vacío)
# ? Configuration Setup
#   > 📋 Configure Menu A: Project Scope
#     🤖 Configure Menu B: AI Configuration

# ✅ Elegir "Configure Menu A"
# → Completar todas las preguntas

# ✅ Ahora APARECE "Continue"
# ? What would you like to do?
#   ...
#   ✅ Continue with current configuration

# ✅ Continue → Wizard termina
```

---

### Test 3: Pre-filled Values

```bash
python3 -m drystone audit

# ✅ Configure Menu A: Cliente "ACME", Region "us-east-2", Skills [iam, exposure]

# ✅ Ver Config Summary
# ✅ Elegir "Configure Menu A" (re-edit)

# Verificar pre-llenadosients:
#   - Client Name = "ACME" ✅
#   - Region = "us-east-2" ✅
#   - Access Key = "AKIA..." ✅
#   - Secret Key = VACÍO (por seguridad) ✅
#   - Skills = [iam, exposure] (checkboxes) ✅

# ✅ Cambiar cliente a "ACME-v2"
# ✅ Menu A actualiza con nuevo nombre
```

---

### Test 4: AWS Validation on Edit

```bash
python3 -m drystone audit

# ✅ Configure Menu A: credenciales VÁLIDAS

# ✅ Ver Config Summary
# ✅ Elegir "Configure Menu A" (re-edit)

# ✅ Cambiar a credenciales INVÁLIDAS
# → Access Key: "AKIA00000000000000000"
# → Secret: "invalid123456789"
# → Debería fallar validación
# → Permitir retry o cancelar

# ✅ Retry con credenciales válidas
```

---

### Test 5: Cancelación (CTRL+C)

```bash
# Test 5a: Cancel en primer menú
python3 -m drystone audit
# → Presionar CTRL+C en "Configuration Setup"
# → Debe terminar limpiamente ✅

# Test 5b: Cancel durante Menu A
python3 -m drystone audit
# → Elegir "Configure Menu A"
# → Presionar CTRL+C en formulario
# → Debe volver al menu sin guardar ✅

# Test 5c: Cancel durante Menu B
python3 -m drystone audit
# → Configure Menu A
# → Elegir "Configure Menu B"
# → Presionar CTRL+C
# → Debe mantener Menu B anterior ✅
```

---

### Test 6: Flujo Completo Multi-Edit

```bash
python3 -m drystone audit

# ✅ Menú inicial: sin Continue
# → Elegir "Configure Menu B" PRIMERO
#   - Provider: "claude-api"
#   - API Key: "sk-ant-first-key"

# ✅ Volver a menú: TODAVÍA sin Continue (Menu A vacío)
# → Elegir "Configure Menu A"
#   - Cliente: "Corp1"
#   - Region: "eu-west-1"
#   - Skills: [iam]

# ✅ Ver Config Summary
# ✅ Elegir "Configure Menu B" (re-edit)
#   - Cambiar a Provider: "gemini-api"
#   - API Key: "ai-gemini-test-key"

# ✅ Elegir "Configure Menu A" (re-edit)
#   - Cambiar Cliente a "Corp2"
#   - Cambiar Skills a [iam, exposure]

# ✅ Elegir "Continue"
# → Config final:
#   - Cliente: "Corp2"
#   - Region: "eu-west-1"
#   - Provider: "gemini-api"
#   - API Key: "ai-gemini-test-key"
```

---

## 🔍 Verification Checklist

### Code Quality
- [x] Syntax: `python3 -m py_compile drystone/cli/ui/wizard.py`
- [x] Imports: `python3 -c "from drystone.cli.ui.wizard import run_setup_wizard"`
- [x] Type hints: All functions have proper type hints
- [x] Docstrings: All functions documented

### Functionality - Nuevo Flujo
- [ ] Comienza sin ejecutar Menu A automáticamente
- [ ] Primer menú muestra solo 2 opciones (sin Continue)
- [ ] Menu B tiene defaults (claude-cli)
- [ ] Usuario puede elegir Menu A o Menu B primero
- [ ] Después de Menu A: aparece Config Summary
- [ ] Después de Menu A: aparece opción "Continue"
- [ ] Edit Menu A: Re-valida AWS, pre-llena valores
- [ ] Edit Menu B: No re-validación AWS, pre-llena valores
- [ ] Loop: Puede editar múltiples veces ambos menús
- [ ] Continue: Solo aparece después que Menu A está completo
- [ ] Continue: Termina loop y retorna config
- [ ] Error handling: AWS validation failures handled

### Backward Compatibility
- [ ] `--non-interactive` still works
- [ ] CLI args (`--client`, etc.) still work
- [ ] Saved configs still load
- [ ] WizardConfig validation passes

### UI/UX
- [ ] Masking of credentials in display
- [ ] Clear section separators (━)
- [ ] Emojis and formatting
- [ ] Progress messages ("✅", "🔄")

---

## 📊 Test Results Template

```
# Wizard Iterativo - Test Report

Date: 2026-01-18
Tester: [Name]

## Test Results

### Test 1: Flujo Completo
- Status: ✅ PASS / ❌ FAIL
- Notes: [Any observations]

### Test 2: Editar Menu B
- Status: ✅ PASS / ❌ FAIL
- Notes: [Any observations]

### Test 3: Pre-filled Values
- Status: ✅ PASS / ❌ FAIL
- Notes: [Any observations]

### Test 4: AWS Validation
- Status: ✅ PASS / ❌ FAIL
- Notes: [Any observations]

### Test 5: Cancelación
- Status: ✅ PASS / ❌ FAIL
- Notes: [Any observations]

### Test 6: Multiple Edits Loop
- Status: ✅ PASS / ❌ FAIL
- Notes: [Any observations]

## Overall Result
- Status: ✅ READY FOR PRODUCTION / ⚠️ NEEDS FIXES
- Issues found: [List any bugs]
- Recommendations: [Any improvements]
```

---

## 🐛 Known Issues & Troubleshooting

### Issue: Pre-filled values not showing
**Solution:** Verify `current_config` parameter is passed correctly

### Issue: AWS validation not re-running
**Solution:** Check that `validate_aws_creds()` is called in Menu A edit path

### Issue: API key being displayed
**Solution:** Verify masking logic in `display_config_summary()`

### Issue: Menu B defaults not applying
**Solution:** Verify `get_default_ai_config()` returns correct defaults

---

## 📝 Notes

- Credentials are NEVER pre-filled for security (passwords are always empty)
- API keys are masked in display (show first 4 and last 4 chars)
- Access keys are masked in display
- AWS validation happens every time Menu A is edited
- Loop continues until user selects "Continue"
- Configuration is immutable once wizard completes

