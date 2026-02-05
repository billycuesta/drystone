# Production Validation Plan - 2026-02-05

**Objective:** Verify PLAN_PARALLEL_EVIDENCE_EXTRACTION + PLAN_FINDINGS_FIX work correctly in real AWS environment

**Estimated Time:** 1-2 hours
**Success Criteria:** All 4 validation checks pass

---

## 📋 Validation Checklist

### ✅ Pre-Execution Validation

- [ ] **Credentials Available**
  - AWS Access Key ID available
  - AWS Secret Access Key available
  - Region selected (recommend: us-east-1 or eu-west-1)

- [ ] **Dependencies Installed**
  ```bash
  pip list | grep -E "boto3|anthropic|click"
  ```

- [ ] **Environment Variables Set**
  ```bash
  export ANTHROPIC_API_KEY="your-key-here"  # Optional (CLI mode uses user auth)
  ```

---

### ✅ Test 1: Parallel Execution Performance (15 min)

**Goal:** Confirm 4.8x speedup is achieved in real audit

**Steps:**

1. Start audit with timing:
   ```bash
   time python -m drystone audit --client "ValidationTest" --region us-east-1
   ```

2. When prompted:
   - Enter AWS Access Key ID
   - Enter AWS Secret Access Key
   - Confirm region: `us-east-1`
   - Select ALL skills: `iam, exposure, network, vulns, alerting, hardening`
   - Select output: `markdown, json`

3. **Expected Result:**
   - Total execution time: **4-8 seconds** (with parallel)
   - Sequential would be: ~24+ seconds
   - Visible progress indicators showing `[1/6]`, `[2/6]`, etc.

**Acceptance Criteria:**
- ✅ Execution completes in <10 seconds
- ✅ All 6 skills execute (not sequential, visible overlapping)
- ✅ Progress output shows ETA and completion percentages

---

### ✅ Test 2: Evidence Size Reduction (15 min)

**Goal:** Confirm 70% evidence size reduction from severity filtering

**Steps:**

1. After audit completes, check evidence directory:
   ```bash
   # Find latest audit session
   LATEST=$(ls -td audit-logs/*/ | head -1)
   echo "Audit session: $LATEST"

   # Calculate total evidence size
   du -sh "$LATEST/evidence"

   # Show breakdown by skill
   for skill in iam exposure network vulns alerting hardening; do
     du -sh "$LATEST/evidence/$skill" 2>/dev/null
   done
   ```

2. Compare with baseline (expected):
   - **Original size:** 5-10 MB (without filtering)
   - **Target size:** 600 KB - 1.5 MB (with CRITICAL/HIGH/MEDIUM filtering)

3. **Expected Result:**
   ```
   Total evidence: 800 KB - 1.2 MB
   iam:      250-350 KB
   exposure: 100-200 KB
   network:  150-300 KB
   vulns:    100-200 KB
   alerting: 50-100 KB
   hardening: 50-100 KB
   ```

**Acceptance Criteria:**
- ✅ Total evidence size < 2 MB
- ✅ Evidence is 70% smaller than baseline (5-10 MB)
- ✅ No skill evidence > 500 KB (except maybe IAM)

---

### ✅ Test 3: No Duplicate Findings (20 min)

**Goal:** Confirm HRD-001 + HRD-006 never appear together (mutual exclusion works)

**Steps:**

1. Extract all findings from audit:
   ```bash
   LATEST=$(ls -td audit-logs/*/ | head -1)

   # Check for duplicates (HRD-001 + HRD-006)
   jq '.findings[] | select(.id == "HRD-001" or .id == "HRD-006") | .id' \
     "$LATEST/findings/hardening.json" | sort | uniq -c
   ```

2. Check all skills for finding ID duplicates:
   ```bash
   # Verify no finding ID appears twice in same skill
   for skill in iam exposure network vulns alerting hardening; do
     echo "=== $skill ==="
     jq '.findings[].id' "$LATEST/findings/$skill.json" 2>/dev/null | sort | uniq -d
   done
   ```

3. **Expected Result:**
   ```
   # No output (empty = no duplicates)

   # OR if HRD-001 and HRD-006 both exist:
   # They should NOT appear together in a single audit
   # Only HRD-006 (partial config) OR HRD-001 (not enabled)
   ```

**Acceptance Criteria:**
- ✅ No finding ID appears twice in any skill's findings
- ✅ HRD-001 and HRD-006 never both present
- ✅ ALR-001, ALR-003, ALR-005+ mutually exclusive

---

### ✅ Test 4: No False Positives (15 min)

**Goal:** Confirm HRD-002 not generated when Security Hub is actually enabled

**Steps:**

1. Check if Security Hub is enabled in test account:
   ```bash
   LATEST=$(ls -td audit-logs/*/ | head -1)

   # Check Security Hub evidence
   jq '.[] | select(.HubArn != null) | .HubArn' \
     "$LATEST/evidence/hardening/security-hub-status.json" 2>/dev/null
   ```

2. If HubArn is present, verify HRD-002 is NOT in findings:
   ```bash
   # This should return EMPTY (no results)
   jq '.findings[] | select(.id == "HRD-002")' \
     "$LATEST/findings/hardening.json"
   ```

3. Also check IAM findings for false positives:
   ```bash
   # Check for impossible findings (e.g., no root users but IAM-001 present)
   jq '.findings[] | select(.id == "IAM-001")' \
     "$LATEST/findings/iam.json" 2>/dev/null

   # Cross-check with evidence
   jq '.users[] | select(.UserName == "root")' \
     "$LATEST/evidence/iam/users.json" 2>/dev/null
   ```

**Acceptance Criteria:**
- ✅ Security Hub enabled (HubArn present) → HRD-002 NOT generated
- ✅ No findings contradict their own evidence
- ✅ Root account findings only if root actually exists

---

## 📊 Results Template

Create file: `VALIDATION_RESULTS.md`

```markdown
# Production Validation Results - 2026-02-05

## Test Environment
- **AWS Region:** [region]
- **Audit Timestamp:** [timestamp]
- **Client Name:** [client]
- **Skills Executed:** [6 or subset]

## Test 1: Parallel Execution Performance
- **Status:** ✅ PASS / ❌ FAIL
- **Execution Time:** [X seconds]
- **Expected:** < 10 seconds
- **Progress Output:** [sample]

## Test 2: Evidence Size Reduction
- **Status:** ✅ PASS / ❌ FAIL
- **Total Size:** [size]
- **Expected:** < 2 MB
- **Breakdown:**
  - iam: [size]
  - exposure: [size]
  - network: [size]
  - vulns: [size]
  - alerting: [size]
  - hardening: [size]

## Test 3: No Duplicate Findings
- **Status:** ✅ PASS / ❌ FAIL
- **Duplicate Check:** [results]
- **HRD-001/006 Together:** [yes/no]
- **Any ID Duplicates:** [yes/no]

## Test 4: No False Positives
- **Status:** ✅ PASS / ❌ FAIL
- **Security Hub Enabled:** [yes/no]
- **HRD-002 Generated:** [yes/no]
- **Evidence Contradictions:** [none/list]

## Overall Result
- **PASS:** All 4 tests passed ✅
- **FAIL:** [which tests failed]

## Notes
[Any observations or issues encountered]
```

---

## 🚀 Quick Start

**1. Prepare credentials:**
```bash
# You'll need:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Preferred region (us-east-1, eu-west-1, etc.)
```

**2. Run audit:**
```bash
cd /Users/gcuesta/Projects/drystone
python -m drystone audit --client "ValidationTest" --region us-east-1
```

**3. Validate results:**
```bash
# After audit completes, run validation script:
bash scripts/validate_production.sh
```

**4. Review findings:**
```bash
# View latest audit findings
LATEST=$(ls -td audit-logs/*/ | head -1)
cat "$LATEST/findings/findings_summary.json"
```

---

## ⏱️ Time Breakdown

| Task | Time | Notes |
|------|------|-------|
| Setup + credentials | 5 min | One-time |
| Run audit | 5-8 min | Parallel execution |
| Test 1: Performance | 5 min | Automatic (check time) |
| Test 2: Evidence size | 5 min | Manual jq commands |
| Test 3: Duplicates | 5 min | Manual jq commands |
| Test 4: False positives | 5 min | Manual jq commands |
| **Total** | **35-40 min** | + audit time |

---

## 🔍 Troubleshooting

### Issue: "Credential validation failed"
- **Cause:** Invalid AWS Access Key ID or Secret
- **Fix:** Double-check credentials in AWS console

### Issue: "Evidence size still > 2 MB"
- **Cause:** Severity filtering not applied
- **Fix:** Check if collectors are using severity filters (should be in cloud/collectors/)

### Issue: "HRD-001 and HRD-006 both present"
- **Cause:** Mutual exclusion not working
- **Fix:** Verify `findings_normalizer.py` has mutual exclusion rules

### Issue: "HRD-002 generated when Security Hub enabled"
- **Cause:** Evidence validation not working
- **Fix:** Check `findings_normalizer.py` evidence validation logic

---

## ✅ Next Steps After Validation

**If all tests PASS:**
1. ✅ Mark Phase 1d as complete
2. ✅ Update PROJECT_STATE.md
3. ✅ Plan P1: PLAN_E2E_TESTING

**If tests FAIL:**
1. Document failures in VALIDATION_RESULTS.md
2. Create bug report with specific findings
3. Debug specific issue
4. Re-run validation

---

*Validation Plan Created: 2026-02-05*
