# Production Validation - Quick Start Guide

**Objective:** Verify parallel execution + findings fixes work in real AWS
**Time Required:** 10 minutes (5 min audit + 5 min validation)
**Success Criteria:** All 5 validation tests pass ✅

---

## 🚀 Step 1: Prepare AWS Credentials (2 min)

You'll need:
- ✅ AWS Access Key ID
- ✅ AWS Secret Access Key
- ✅ AWS Region (default: `us-east-1`)

**Keep these handy for the wizard.**

---

## 🎯 Step 2: Run Audit (5-8 min)

```bash
cd /Users/gcuesta/Projects/drystone

# Start the audit
python -m drystone audit --client "ValidationTest" --region us-east-1
```

**When prompted:**

1. **Client Name?**
   ```
   Enter: ValidationTest
   ```

2. **AWS Access Key ID?**
   ```
   Enter: [your key from step 1]
   ```

3. **AWS Secret Access Key?**
   ```
   Enter: [your secret from step 1]
   ```

4. **AWS Region?**
   ```
   Confirm: us-east-1
   ```

5. **Which skills?**
   ```
   Select ALL:
   ✓ iam
   ✓ exposure
   ✓ network
   ✓ vulns
   ✓ alerting
   ✓ hardening
   ```

6. **Output formats?**
   ```
   Select:
   ✓ Markdown report
   ✓ JSON export
   ```

7. **Ready to execute?**
   ```
   Confirm: Yes
   ```

**Progress Output (you should see this):**
```
[████████████████████████████ ] 6/6 (100%)
Progress: 6/6 (100%) - Elapsed: 5.2s - ETA: Complete ✓
```

**⏱️ Expected execution time: 4-8 seconds** (proves parallel execution)

---

## ✅ Step 3: Validate Results (5 min)

After audit completes:

```bash
bash scripts/validate_production.sh
```

**Expected Output:**

```
=== Production Validation Results ===

Audit Session: audit-logs/ValidationTest_2026-02-05T12-30-00/

=== TEST 1: Evidence Size Reduction ===
Total evidence size: 1.2M (1.20 MB)
✅ Evidence size is under 2 MB target (1.20 MB)

=== TEST 2: No Duplicate Findings ===
✅ No duplicate finding IDs found

=== TEST 3: HRD-001/HRD-006 Mutual Exclusion ===
HRD-001 (Config disabled) count: 0
HRD-006 (Config partial) count: 1
✅ HRD-001 and HRD-006 are mutually exclusive

=== TEST 4: No False Positives (Security Hub) ===
Security Hub is ENABLED (HubArn: arn:aws:securityhub:us-east-1:...)
✅ Security Hub enabled and HRD-002 not generated (correct)

=== TEST 5: Evidence vs Findings Consistency ===
✅ IAM-001 findings consistent with evidence

=== Validation Summary ===
Tests Passed: ✅ 5/5
Tests Failed: ❌ 0/5

✅ All validation tests passed!
```

---

## 📊 What Each Test Validates

| Test | Validates | Target |
|------|-----------|--------|
| **Test 1** | Evidence reduction from severity filtering | < 2 MB |
| **Test 2** | No duplicate finding IDs in same skill | 0 duplicates |
| **Test 3** | HRD-001/006 mutual exclusion | Both never together |
| **Test 4** | No false positives (Security Hub) | Correct detection |
| **Test 5** | Evidence-findings consistency | No contradictions |

---

## 🎯 Success Criteria

**✅ PASS if:**
- Audit completes in < 10 seconds (proves parallelization)
- All 5 validation tests show ✅ PASS
- Evidence total < 2 MB (proves 70% reduction)

**❌ FAIL if:**
- Audit takes > 20 seconds (not parallel)
- Any validation test fails
- Evidence > 2 MB (filtering didn't work)

---

## 📁 Output Files

After audit completes, check:

```bash
# Find latest audit
LATEST=$(ls -td audit-logs/*/ | head -1)
echo $LATEST

# View findings summary
cat "$LATEST/findings/findings_summary.json"

# View detailed findings by skill
cat "$LATEST/findings/iam.json"
cat "$LATEST/findings/hardening.json"

# View evidence (filtered)
du -sh "$LATEST/evidence"/*
```

---

## 🔧 Troubleshooting

### "Credential validation failed"
- Check Access Key ID and Secret in AWS console
- Ensure keys are for the same AWS account
- Verify keys have `SecurityAudit` policy attached

### "Audit takes > 20 seconds"
- Parallel execution may not be working
- Check orchestrator.py uses ThreadPoolExecutor
- Run: `python -c "from drystone.cloud.orchestrator import AuditOrchestrator; print('OK')"`

### "Evidence size > 2 MB"
- Severity filtering not applied
- Check collectors use `severity_filter="CRITICAL,HIGH,MEDIUM"`
- Verify: `grep -r "severity_filter" drystone/cloud/collectors/`

### "HRD-001 and HRD-006 both present"
- Mutual exclusion not working
- Check `findings_normalizer.py` has MUTUAL_EXCLUSIONS dict
- Run findings through normalizer: `jq '.findings | length' findings.json`

---

## 📝 Document Results

After validation completes, save results:

```bash
# Create results file
cat > VALIDATION_RESULTS.md << 'EOF'
# Production Validation Results - 2026-02-05

## Summary
- **Status:** PASS ✅
- **Audit Time:** [copy from output]
- **Evidence Size:** [copy from output]
- **Tests Passed:** 5/5 ✅

## Details
[paste full validation script output]

## Next Steps
- [ ] Update PROJECT_STATE.md
- [ ] Plan PLAN_E2E_TESTING
- [ ] Commit validation results

EOF

# Commit results
git add VALIDATION_RESULTS.md
git commit -m "docs: production validation results - Phase 1d complete"
```

---

## ✨ Next Steps (After Validation Passes)

**1. Update Project State** (5 min)
```bash
# Edit PROJECT_STATE.md
# Add: "Phase 1d: Production validated ✅ (2026-02-05)"
```

**2. Plan Next Work** (Optional)
- **Option A:** PLAN_E2E_TESTING (4-6 hours)
- **Option B:** Documentation sprint (2-3 hours)
- **Option C:** Performance optimization (future)

---

## 📞 Need Help?

If validation fails:
1. Check `PRODUCTION_VALIDATION_PLAN.md` for detailed troubleshooting
2. Review audit logs: `cat audit-logs/*/logs/audit.log`
3. Check findings: `jq . audit-logs/*/findings/*.json | less`

---

**Good luck! 🚀**
