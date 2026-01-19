# Drystone Validation Module

## Overview

Post-analysis validation system ensuring audit quality and completeness. Three levels of validation work together to guarantee findings accuracy.

## Architecture

```
Evidence → Analyzer → Findings
                        ↓
                   VALIDATOR (3 levels)
                   ├─ Level 1: Checklist Coverage (FREE)
                   ├─ Level 2: Quality Review (AGENT)
                   └─ Level 3: Report Validation (STATIC)
                        ↓
                   Final Report
```

---

## Three Validation Levels

### Level 1: Checklist Coverage (Programmatic)

**Module:** `drystone/validation/checklist_coverage.py`

Guarantees 100% of checklist items are evaluated.

**How it works:**
- Compares checklist IDs vs findings checklist_ref fields
- Identifies missing checks
- Reports coverage percentage

**Cost:** $0 (deterministic, no API calls)

**Example:**
```python
from drystone.validation import validate_checklist_coverage

result = validate_checklist_coverage(checklist, findings)

print(f"Coverage: {result['coverage_percentage']:.1f}%")
print(f"Missing checks: {result['missing_checks']}")
# Output:
# Coverage: 100.0%
# Missing checks: []
```

**Result format:**
```json
{
  "coverage_valid": true,
  "total_checks": 15,
  "evaluated_checks": 15,
  "coverage_percentage": 100.0,
  "missing_checks": [],
  "details": [
    {
      "check_id": "IAM-001",
      "check_title": "Avoid root account usage",
      "evaluated": true,
      "finding_id": "f1"
    }
  ]
}
```

---

### Level 2: Findings Quality Review (Agent)

**Module:** `drystone/validation/reviewer.py`

Reviews findings quality using Claude API (skill-agnostic).

**What it checks:**
- Severity appropriateness given evidence
- Missing critical findings
- Remediation completeness
- Evidence-severity alignment

**Cost:** ~$0.02 per skill

**Skill-agnostic design:**
- Single `FindingsReviewer` class for all skills
- Works with IAM, Exposure, Network, Vulns identically
- No skill-specific logic needed

**Example:**
```python
from drystone.validation import FindingsReviewer
from anthropic import Anthropic

client = Anthropic()
reviewer = FindingsReviewer(client)

result = reviewer.validate(
    skill="iam",
    evidence=evidence_data,
    checklist=checklist,
    findings=findings,
)

print(f"Status: {result['validation_status']}")
print(f"Confidence: {result['confidence_score']:.2f}")
# Output:
# Status: PASS
# Confidence: 0.92
```

**Result format:**
```json
{
  "validation_status": "PASS",
  "confidence_score": 0.92,
  "severity_mismatches": [
    {
      "finding_id": "IAM-001",
      "agent_severity": "Medium",
      "recommended_severity": "Critical",
      "reason": "Clear evidence in logs showing active root key usage"
    }
  ],
  "missing_critical_findings": [
    {
      "check_id": "IAM-002",
      "check_title": "Enable MFA on root account",
      "reason": "Evidence shows MFA is disabled on root account",
      "severity": "Critical"
    }
  ],
  "remediation_issues": [
    {
      "finding_id": "IAM-001",
      "issue": "Remediation is vague - needs specific IAM user creation steps"
    }
  ],
  "summary": "Found 1 severity mismatch and 2 missing critical findings",
  "recommendations": [
    "Re-analyze with focus on MFA checks",
    "Clarify remediation steps for IAM-001"
  ]
}
```

---

### Level 3: Report Validation (Static)

**Module:** `drystone/validation/report_validator.py`

Validates report structure and completeness.

**Checks:**
- Required sections present (Executive Summary, Findings, Remediation)
- All findings referenced
- Proper formatting (markdown/HTML)
- Non-empty content

**Cost:** $0 (static checks only)

**Example:**
```python
from drystone.validation import validate_report_completeness

result = validate_report_completeness(report, findings, format_type="markdown")

print(f"Valid: {result['report_valid']}")
print(f"Gaps: {result['gaps']}")
# Output:
# Valid: True
# Gaps: []
```

**Result format:**
```json
{
  "report_valid": true,
  "format": "markdown",
  "total_findings": 2,
  "referenced_findings": 2,
  "findings_coverage_percentage": 100.0,
  "missing_sections": [],
  "unreferenced_findings": [],
  "gaps": [],
  "summary": "Report is complete and well-structured ✅"
}
```

---

## Integration in Orchestrator

The validation is integrated into the main audit workflow via `AuditOrchestrator`:

```python
from drystone.cloud.orchestrator import AuditOrchestrator

orchestrator = AuditOrchestrator(config)

result = orchestrator.run_skill_audit(
    skill_name="iam",
    collector_class=IAMCollector,
    analyzer_class=IAMAnalyzer,
    checklist_path=Path("drystone/skills/iam/checklist.json"),
)

print(result["validation"]["status"])  # "PASS", "FAIL", or "NEEDS_REVIEW"
```

### Validation Status Determination

Overall status is determined as:

```python
if coverage < 100% or quality == "FAIL":
    status = "FAIL"
elif quality == "NEEDS_REVIEW":
    status = "NEEDS_REVIEW"
elif report_valid == False:
    status = "FAIL"
else:
    status = "PASS"
```

---

## Handling Validation Failures

### If Checklist Coverage < 100%

Unevaluated checks are identified and can trigger re-analysis:

```python
from drystone.validation import get_unevaluated_checks

# Get checks that weren't evaluated
unevaluated = get_unevaluated_checks(checklist, findings)

# Re-analyze focused on missing checks
focused_findings = analyzer.analyze(
    evidence,
    {"items": unevaluated},
)

# Merge with original findings
findings.extend(focused_findings)
```

### If Quality Validation Fails

The reviewer identifies specific issues:
- **Severity mismatches:** Suggestions for corrected severity levels
- **Missing findings:** Specific checks that should have findings
- **Remediation issues:** Incomplete remediation steps

Options:
1. **Auto-fix:** Apply reviewer's corrections and re-analyze
2. **Manual review:** Flag for human review before finalizing
3. **Accept:** If reviewer confidence is low, accept with warnings

---

## Configuration (Future)

Add to `drystone/models/config.py`:

```python
class ValidationConfig(BaseModel):
    enabled: bool = True
    strategy: Literal["always", "high-risk", "sample"] = "always"
    re_analyze_on_fail: bool = False
    confidence_threshold: float = 0.7
```

---

## Cost Analysis

### Per-Skill Costs

| Skill | Analysis | Validation | Total |
|-------|----------|-----------|-------|
| IAM | $0.05 | $0.02 | $0.07 |
| Exposure | $0.03 | $0.02 | $0.05 |
| Network | $0.04 | $0.02 | $0.06 |
| Vulns | $0.06 | $0.02 | $0.08 |

**Full Audit:** $0.26 total (+44% over $0.18 without validation)

### Cost Optimization

To reduce costs:

1. **Sample validation:** Only validate high-risk findings
   ```python
   if finding["severity"] in ["Critical", "High"]:
       reviewer.validate(...)  # Only validate critical/high
   ```

2. **Batch validation:** Validate multiple skills in parallel
   ```python
   reviewer.validate_batch([iam_data, network_data, exposure_data])
   ```

3. **Selective re-analysis:** Only re-analyze if coverage < 80%
   ```python
   if coverage["coverage_percentage"] < 80:
       do_reanalysis()
   ```

---

## Testing

Run validation tests:

```bash
pytest tests/test_validation.py -v

# Test specific module
pytest tests/test_validation.py::TestChecklistCoverage -v

# Run with coverage
pytest tests/test_validation.py --cov=drystone.validation
```

### Test Cases

- ✅ Full checklist coverage (100%)
- ✅ Partial coverage with missing checks
- ✅ No findings (clean audit)
- ✅ Report completeness validation
- ✅ Report format validation (markdown/HTML)
- ✅ Finding reference verification
- ✅ Missing section detection

---

## Troubleshooting

### Coverage validation shows missing checks

**Cause:** Analyzer didn't evaluate all checklist items

**Solution:**
1. Re-run analysis with focused prompt
2. Check if evidence is sufficient for missing checks
3. Verify checklist IDs match finding checklist_ref fields

**Example:**
```python
# Check what's missing
missing = coverage["missing_checks"]
print(f"Missing: {missing}")

# Get unevaluated checks
unevaluated = get_unevaluated_checks(checklist, findings)
print(f"Unevaluated items: {[i['title'] for i in unevaluated]}")
```

### Quality review fails with low confidence

**Cause:** Reviewer uncertain about finding quality

**Solution:**
1. Provide more detailed evidence
2. Simplify checklist items
3. Review suggested corrections manually

**Example:**
```python
if result["confidence_score"] < 0.7:
    print(f"Low confidence: {result['confidence_score']}")
    print(f"Recommendations: {result['recommendations']}")
    # Flag for human review
```

### Report validation missing sections

**Cause:** Generated report lacks required sections

**Solution:**
1. Run report generation with proper templates
2. Ensure report includes all sections
3. Verify finding references in report

**Example:**
```python
gaps = result["gaps"]
print(f"Missing: {gaps}")

suggestions = suggest_report_fixes(result)
for suggestion in suggestions:
    print(f"Fix: {suggestion}")
```

---

## Next Steps

### Phase 2: Advanced Features

- [ ] Parallel validation for multiple skills
- [ ] Custom validation rules per skill
- [ ] Validation result caching
- [ ] Confidence score weighting
- [ ] A/B testing of validation strategies

### Phase 3: UI Integration

- [ ] Wizard validation progress indicator
- [ ] Real-time validation status display
- [ ] Validation report in final output
- [ ] Remediation suggestions from validator

---

## References

- **CLAUDE.md:** Architecture principles (App vs Agent)
- **PROJECT_PLAN.md:** Full development roadmap
- **drystone/validation/:** Implementation modules
- **tests/test_validation.py:** Test cases and examples
