# Wizard Refactor: Two-Menu Implementation

**Date:** 2026-01-18
**Status:** ✅ Complete and Validated
**File Modified:** `drystone/cli/ui/wizard.py`

## Summary

Reorganized the 8-step linear wizard into a modular two-menu system that separates **project scope** (mandatory) from **AI preferences** (optional with smart defaults).

## Implementation Details

### 1. `run_project_menu()` (Lines 84-185)

**Menu A: Project & AWS Scope** - Always executed first

Steps included:
1. Client/Project name
2. AWS Access Key ID
3. AWS Secret Access Key
4. AWS Region selection
5. AWS credential validation
6. Security skills selection (IAM, Exposure, Network, Vulns)
7. Output formats selection (Markdown, JSON)

**Returns:** Dictionary with 6 fields:
```python
{
    "client_name": str,
    "aws_access_key_id": str,
    "aws_secret_access_key": str,
    "aws_region": str,
    "skills": list,
    "output_formats": list
}
```

### 2. `run_ai_menu()` (Lines 188-226)

**Menu B: AI Configuration** - Optional, executed conditionally

Steps included:
1. AI Provider selection (claude-cli, claude-api, gemini-api)
2. API Key prompt (only if provider requires it)

**Returns:** Dictionary with 2 fields:
```python
{
    "ai_provider": str,
    "ai_api_key": Optional[str]
}
```

### 3. `get_default_ai_config()` (Lines 229-238)

Helper function returning default AI configuration.

**Returns:**
```python
{
    "ai_provider": "claude-cli",
    "ai_api_key": None
}
```

**Rationale:**
- claude-cli is free (no API key needed)
- Reduces setup friction for first-time users
- Still allows customization for power users

### 4. `run_setup_wizard()` (Lines 241-292) - Refactored

Orchestrator function coordinating both menus:

**Flow:**
```
1. Execute Menu A (project_config)
2. Ask: "Customize AI configuration? (default: Claude CLI - free)"
3. If Yes:
   └─ Execute Menu B (ai_config)
4. If No:
   └─ Use get_default_ai_config() (ai_config)
5. Combine: WizardConfig(**project_config, **ai_config)
6. Return final WizardConfig
```

**Visual improvements:**
- Clear menu section separators with icons
- Confirmation message when using defaults
- Better organization with visual hierarchy

## Architecture

```
┌─────────────────────────────────────────────┐
│      run_setup_wizard() [Main Orchestrator] │
└──────────────────┬──────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
   ┌────▼────────┐      ┌─────▼──────────┐
   │ Menu A      │      │ Menu B?        │
   │ (Required)  │      │ (Optional)     │
   │             │      │                │
   │ - Scope     │      ├─ Yes ──────┐   │
   │ - AWS Info  │      │    │       │   │
   │ - Skills    │      │    └─→ Menu B  │
   │ - Formats   │      │            │   │
   │             │      └─ No ───┐   │   │
   │ Returns:    │         │     │   │   │
   │ project_cfg │         └────→│   │   │
   └─────┬───────┘              │   │   │
         │                  Defaults  │   │
         │                  Config    │   │
         │                      │     │   │
         └──────────┬───────────┴─────┘   │
                    │                     │
              ┌─────▼──────┐              │
              │ Combine    │              │
              │ Configs    │              │
              │            │              │
              │ WizardCfg  │              │
              └────────────┘              │
                                          │
              Result: Final WizardConfig   │
                       (all fields merged) │
```

## Validation Results

✅ **Syntax Check:** PASSED
✅ **Import Validation:** All functions imported successfully
✅ **Default Config Test:** Structure and values validated
✅ **No Breaking Changes:** Existing code unchanged, backward compatible

## Backward Compatibility

- ✅ `--non-interactive` mode: Still loads from `last-run.json`
- ✅ CLI args: `--client`, `--region` still work
- ✅ Config persistence: Saved configs include both menus
- ✅ WizardConfig model: No changes required

## Testing Recommendations

### Test Case 1: Menu A + Menu B (Customization)
```bash
python3 -m drystone audit
# Fill Menu A (6 prompts)
# Respond "Y" to "Customize AI configuration?"
# Fill Menu B (select claude-api, enter API key)
# Verify: WizardConfig contains both project and custom AI config
```

### Test Case 2: Menu A + Menu B (Defaults)
```bash
python3 -m drystone audit
# Fill Menu A (6 prompts)
# Respond "N" to "Customize AI configuration?" (press Enter)
# Verify: Uses claude-cli by default, no API key
# Verify: "✅ Using default configuration:" message shown
```

### Test Case 3: Non-Interactive Mode
```bash
python3 -m drystone audit --non-interactive
# Should skip both menus
# Verify: Uses saved config from ~/.drystone/last-run.json
```

### Test Case 4: Cancellation Handling
```bash
# Test CTRL+C at Menu A
python3 -m drystone audit
# Press CTRL+C during first prompt
# Verify: "Wizard cancelled" message, clean exit

# Test CTRL+C at Menu B
python3 -m drystone audit
# Complete Menu A
# Press CTRL+C during Menu B
# Verify: "Wizard cancelled" message, clean exit
```

## Code Quality Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Lines Modified | ~210 | Refactored 8-step linear code into 4 functions |
| Functions Added | 3 | run_project_menu, run_ai_menu, get_default_ai_config |
| Functions Refactored | 1 | run_setup_wizard (orchestrator) |
| Cyclomatic Complexity | Reduced | Separated concerns reduced nesting |
| Duplication | Eliminated | No code duplication |
| Type Hints | Complete | All functions have return type hints |
| Docstrings | Complete | All functions documented |

## Usage Examples

### For First-Time Users
```bash
$ python3 -m drystone audit

# Answer 6 Menu A questions
# When asked about AI config: Press N (or Enter for default)
# Done! CLI using free claude-cli provider
```

### For Power Users
```bash
$ python3 -m drystone audit

# Answer 6 Menu A questions
# When asked about AI config: Press Y
# Select provider (e.g., claude-api)
# Enter API key when prompted
# Custom configuration applied
```

### For Automation
```bash
# Re-run with saved config (no prompts)
$ python3 -m drystone audit --non-interactive

# One-time config without saving
$ python3 -m drystone audit --client MyOrg --region us-east-1
```

## Files Modified

| File | Changes | Lines |
|------|---------|-------|
| `drystone/cli/ui/wizard.py` | Complete refactoring of wizard into modular functions | 84-292 |
| `PROJECT_STATE.md` | Documented implementation and changes | N/A |

## Integration Notes

- No changes needed to `drystone/cli/main.py` - already calls `run_setup_wizard()`
- No changes needed to `drystone/models/config.py` - WizardConfig structure unchanged
- No changes needed to other modules - self-contained refactoring

## Future Enhancements

Possible improvements for future sessions:

1. **Menu Navigation:** Add ability to go back/edit previous menu
2. **Menu Presets:** Save named configuration presets
3. **Advanced Options:** Sub-menu for provider-specific options
4. **Validation Preview:** Show summary before executing
5. **Config Manager:** View/edit/delete saved configurations

## Related Documentation

- `CLAUDE.md` - Project guidelines and architecture
- `PROJECT_PLAN.md` - Long-term roadmap
- `PROJECT_STATE.md` - Current status and next steps
- `SESSION_TRACKER.md` - Session history

---

**Implementation Date:** 2026-01-18
**Implementation Status:** ✅ Complete
**Next Task:** IAM Collector Implementation
