# Quick Start: Implementar Phase 1 en Drystone

**Duración estimada:** 5 horas
**Objetivo:** Output validation + Error classification + Retry logic
**Timeline:** Lunes-Martes de próxima semana

---

## 📋 Pre-Implementation Checklist

- [ ] Leí `ARCHITECTURE_ANALYSIS_SHANNON.md` (entiendo patrones)
- [ ] Leí `SHANNON_DECISIONS.md` (estoy de acuerdo con decisiones)
- [ ] Leí `IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md` (tengo plan detallado)
- [ ] Tengo ambiente Python 3.9+ listo
- [ ] Tengo acceso a Shannon source code para referencia

---

## 🚀 Step-by-Step Implementation

### Step 1: Create Output Validators (1h 30m)

**File:** `drystone/validation/__init__.py` (NEW)
```python
# Empty file for package
```

**File:** `drystone/validation/output_validators.py` (NEW)

Copy template from `IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md` Phase 1.1

```bash
# Verify syntax
python -m py_compile drystone/validation/output_validators.py
```

**Checklist:**
- [ ] File created
- [ ] All validators implemented (6 skills)
- [ ] SKILL_VALIDATORS registry defined
- [ ] No syntax errors
- [ ] Logging configured

---

### Step 2: Create Retry Logic (1h 30m)

**File:** `drystone/agent/retry.py` (NEW)

Copy template from `IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md` Phase 1.2

```bash
# Verify syntax
python -m py_compile drystone/agent/retry.py
```

**Checklist:**
- [ ] File created
- [ ] RETRYABLE_ERROR_PATTERNS defined (15+ patterns)
- [ ] NON_RETRYABLE_ERROR_PATTERNS defined (6+ patterns)
- [ ] is_retryable_error() implemented
- [ ] get_retry_delay() implemented (rate limit + exponential)
- [ ] retry_with_backoff() decorator implemented
- [ ] analyze_with_retry() function implemented
- [ ] No syntax errors

---

### Step 3: Integrate with Agent Client (1h)

**File:** `drystone/agent/client.py` (MODIFY)

**Changes:**
```python
# Add imports at top:
from drystone.validation.output_validators import validate_findings
from drystone.agent.retry import analyze_with_retry, is_retryable_error

# Find: def analyze_evidence_chunked(self, skill_name, evidence, checklist)
# After findings normalization, add:
if not validate_findings(skill_name, findings):
    raise ValueError(f"Output validation failed for {skill_name}")

return findings
```

**Verify:**
```bash
python -c "from drystone.agent.client import AgentClient; print('OK')"
```

**Checklist:**
- [ ] Imports added
- [ ] Validation integrated to analyze_evidence_chunked()
- [ ] No syntax errors
- [ ] AgentClient still imports correctly

---

### Step 4: Create Unit Tests (1h)

**File:** `tests/unit/test_retry_logic.py` (NEW)

Copy template from `IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md` Phase 1.4

```bash
# Run tests
cd /Users/gcuesta/Projects/drystone
pytest tests/unit/test_retry_logic.py -v
```

**Expected output:**
```
test_retryable_rate_limit_error PASSED
test_retryable_timeout_error PASSED
test_retryable_server_error PASSED
test_non_retryable_auth_error PASSED
test_non_retryable_permission_error PASSED
test_unknown_error_conservative_default PASSED
test_rate_limit_delay_longer PASSED
test_exponential_backoff_delay PASSED
test_valid_iam_findings PASSED
test_invalid_findings_count_mismatch PASSED

10 passed in 0.5s
```

**Checklist:**
- [ ] Tests created
- [ ] All tests passing
- [ ] Coverage >80%

---

### Step 5: Manual Testing (30m)

**Scenario 1: Test retry on rate limit (simulated)**

```bash
python -c "
from drystone.agent.retry import is_retryable_error, get_retry_delay

# Test 1: Rate limit error
error = Exception('Rate limit exceeded: 429 Too Many Requests')
print(f'Rate limit retryable? {is_retryable_error(error)}')  # Should be True
print(f'Delay attempt 1: {get_retry_delay(error, 1)}s')      # Should be 30s
print(f'Delay attempt 2: {get_retry_delay(error, 2)}s')      # Should be 40s

# Test 2: Auth error
error = Exception('Authentication failed: invalid API key')
print(f'Auth retryable? {is_retryable_error(error)}')        # Should be False

# Test 3: Unknown error
error = Exception('Some random error')
print(f'Unknown retryable? {is_retryable_error(error)}')     # Should be False
"
```

**Expected output:**
```
Rate limit retryable? True
Delay attempt 1: 30s
Delay attempt 2: 40s
Auth retryable? False
Unknown retryable? False
```

**Scenario 2: Test output validation**

```bash
python -c "
from drystone.models.findings import Findings, FindingSummary, Finding
from drystone.validation.output_validators import validate_iam_findings

# Create valid findings
summary = FindingSummary(total_findings=1, critical=1, high=0, medium=0, low=0)
finding = Finding(
    id='IAM-001',
    severity='critical',
    title='Test',
    description='Test finding',
    cis_id='1.5'
)
findings = Findings(findings=[finding], summary=summary)

result = validate_iam_findings(findings)
print(f'Valid findings: {result}')  # Should be True

# Create invalid findings (count mismatch)
summary_invalid = FindingSummary(total_findings=5, critical=1, high=0, medium=0, low=0)
findings_invalid = Findings(findings=[finding], summary=summary_invalid)
result = validate_iam_findings(findings_invalid)
print(f'Invalid findings: {result}')  # Should be False
"
```

**Expected output:**
```
Valid findings: True
Invalid findings: False
```

**Checklist:**
- [ ] Rate limit delay test passed
- [ ] Auth error non-retryable test passed
- [ ] Output validation test passed

---

### Step 6: Git Commit (15m)

```bash
cd /Users/gcuesta/Projects/drystone

# Stage all changes
git add drystone/validation/ drystone/agent/retry.py tests/unit/test_retry_logic.py

# Check what we're committing
git status
git diff --cached --stat

# Create commit with summary
git commit -m "feat: add output validation + error classification + retry logic

- Add drystone/validation/output_validators.py with skill-specific validators
- Add drystone/agent/retry.py with error classification and retry with backoff
- Integrate validation into agent client (analyze_evidence_chunked)
- Add unit tests for retry logic and validation (10 tests, 100% pass)
- Pattern from Shannon: deterministic post-agent validation + multi-level retry
- Expected impact: +90% resilience to rate limits and network errors

Inspired by:
- Shannon src/constants.ts (AGENT_VALIDATORS registry)
- Shannon src/error-handling.ts (error classification)
- Shannon src/queue-validation.ts (validation pipeline)
- Shannon src/ai/claude-executor.ts (retry logic)"

# Verify commit
git log --oneline | head -1
```

**Expected output:**
```
[main abc1234] feat: add output validation + error classification + retry logic
```

**Checklist:**
- [ ] Commit created
- [ ] Commit message follows convention
- [ ] No uncommitted changes remain

---

## ✅ Verification Checklist (Post-Implementation)

- [ ] All files created/modified
- [ ] No syntax errors
- [ ] All unit tests passing
- [ ] Manual tests passed
- [ ] Commit created with good message
- [ ] CLAUDE.md updated (done automatically)
- [ ] Code follows project conventions

---

## 🧪 Integration Testing (Optional)

**Test with actual audit (if ready):**

```bash
python -m drystone audit --client TestOrg --region us-east-1 --non-interactive
```

**Expected behavior:**
- ✅ Audit completes successfully
- ✅ If rate limit occurs: auto-retries (should see retry log messages)
- ✅ If output invalid: detected and retried
- ✅ audit-logs/{client}_*/findings/*.json all valid JSON

---

## 📊 Metrics: Before vs. After

### Before Phase 1:
```
Scenario 1: Rate limit error → Audit fails immediately ❌
Scenario 2: Output validation error → Silently accepted (discovered later) ❌
Resilience: 0%
```

### After Phase 1:
```
Scenario 1: Rate limit error → Auto-retries, succeeds ✅
Scenario 2: Output validation error → Detected and retried immediately ✅
Resilience: ~90%
```

---

## 🔗 References

**Detailed docs:**
- `IMPLEMENTATION_PLAN_SHANNON_IMPROVEMENTS.md` - Complete templates
- `ARCHITECTURE_ANALYSIS_SHANNON.md` - Pattern explanation
- `SHANNON_DECISIONS.md` - Rationale

**Shannon source (for reference):**
- `/Users/gcuesta/Projects/shannon/src/constants.ts` (AGENT_VALIDATORS)
- `/Users/gcuesta/Projects/shannon/src/error-handling.ts` (error classification)
- `/Users/gcuesta/Projects/shannon/src/queue-validation.ts` (validation patterns)

---

## 🆘 Troubleshooting

### Import Error: `No module named drystone.validation`
**Solution:** Verify `drystone/validation/__init__.py` exists and is empty

### Test fails with `ModuleNotFoundError`
**Solution:** Run from project root: `cd /Users/gcuesta/Projects/drystone`

### Retry decorator not working
**Solution:** Check that `analyze_evidence_chunked` is being called with decorated function

### Commit fails
**Solution:** `git status` to see unstaged files, then `git add` them

---

## 📝 Next Steps After Phase 1

1. ✅ Phase 1 Complete: Validation + Retry (NOW)
2. 🚀 Phase 2: Structured Prompts (Next week)
3. 📊 Phase 3: Testing Infrastructure (Week after)
4. 💾 Phase 4: Crash-Safe Logging (Optional future)

---

## Timeline

| Step | Time | Status |
|------|------|--------|
| Create validators | 1h 30m | TODO |
| Create retry logic | 1h 30m | TODO |
| Integrate with agent | 1h | TODO |
| Create tests | 1h | TODO |
| Manual testing | 30m | TODO |
| Git commit | 15m | TODO |
| **TOTAL** | **~5h** | TODO |

---

**Status:** 🟢 READY TO START
**Estimated completion:** EOD Tuesday (assuming 5h available)
**Start date:** Next Monday

Good luck! 🚀
