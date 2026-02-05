#!/bin/bash
# Production Validation Script
# Validates parallel extraction + findings fix in real AWS audit
# Usage: bash scripts/validate_production.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0

# Functions
print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

print_pass() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED++))
}

print_fail() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED++))
}

print_info() {
    echo -e "${YELLOW}ℹ️ $1${NC}"
}

# Get latest audit session
LATEST=$(ls -td audit-logs/*/ 2>/dev/null | head -1)

if [ -z "$LATEST" ]; then
    print_fail "No audit logs found. Please run: python -m drystone audit"
    exit 1
fi

print_header "Production Validation Results"
echo "Audit Session: $LATEST"
echo "Timestamp: $(date)"

# =============================================================================
# TEST 1: Evidence Size Reduction
# =============================================================================
print_header "TEST 1: Evidence Size Reduction"

TOTAL_SIZE=$(du -sh "$LATEST/evidence" 2>/dev/null | awk '{print $1}')
TOTAL_BYTES=$(du -sb "$LATEST/evidence" 2>/dev/null | awk '{print $1}')
TOTAL_MB=$(echo "scale=2; $TOTAL_BYTES / 1024 / 1024" | bc)

echo "Total evidence size: $TOTAL_SIZE ($TOTAL_MB MB)"
echo ""
echo "Breakdown by skill:"
for skill in iam exposure network vulns alerting hardening; do
    if [ -d "$LATEST/evidence/$skill" ]; then
        SIZE=$(du -sh "$LATEST/evidence/$skill" | awk '{print $1}')
        BYTES=$(du -sb "$LATEST/evidence/$skill" | awk '{print $1}')
        KB=$(echo "scale=0; $BYTES / 1024" | bc)
        echo "  $skill: $SIZE ($KB KB)"
    fi
done

# Check against target (< 2 MB)
if [ $TOTAL_MB -lt 2 ]; then
    print_pass "Evidence size is under 2 MB target ($TOTAL_MB MB)"
else
    print_fail "Evidence size exceeds 2 MB target ($TOTAL_MB MB)"
fi

# =============================================================================
# TEST 2: Duplicate Finding IDs
# =============================================================================
print_header "TEST 2: No Duplicate Findings"

DUPLICATE_COUNT=0
for skill in iam exposure network vulns alerting hardening; do
    FINDINGS_FILE="$LATEST/findings/$skill.json"
    if [ -f "$FINDINGS_FILE" ]; then
        # Count duplicate IDs in this skill
        DUPES=$(jq -r '.findings[].id' "$FINDINGS_FILE" 2>/dev/null | sort | uniq -d | wc -l)
        if [ "$DUPES" -gt 0 ]; then
            echo "Duplicates in $skill:"
            jq -r '.findings[].id' "$FINDINGS_FILE" 2>/dev/null | sort | uniq -d | sed 's/^/  /'
            ((DUPLICATE_COUNT += DUPES))
        fi
    fi
done

if [ $DUPLICATE_COUNT -eq 0 ]; then
    print_pass "No duplicate finding IDs found"
else
    print_fail "Found $DUPLICATE_COUNT duplicate finding IDs"
fi

# =============================================================================
# TEST 3: HRD-001 and HRD-006 Mutual Exclusion
# =============================================================================
print_header "TEST 3: HRD-001/HRD-006 Mutual Exclusion"

HRD_FINDINGS_FILE="$LATEST/findings/hardening.json"
if [ -f "$HRD_FINDINGS_FILE" ]; then
    HRD_001_COUNT=$(jq '[.findings[] | select(.id == "HRD-001")] | length' "$HRD_FINDINGS_FILE")
    HRD_006_COUNT=$(jq '[.findings[] | select(.id == "HRD-006")] | length' "$HRD_FINDINGS_FILE")

    echo "HRD-001 (Config disabled) count: $HRD_001_COUNT"
    echo "HRD-006 (Config partial) count: $HRD_006_COUNT"

    # Both shouldn't be present together
    if [ $HRD_001_COUNT -gt 0 ] && [ $HRD_006_COUNT -gt 0 ]; then
        print_fail "Both HRD-001 and HRD-006 found together (should be mutually exclusive)"
    else
        if [ $HRD_001_COUNT -eq 0 ] && [ $HRD_006_COUNT -eq 0 ]; then
            print_info "Neither HRD-001 nor HRD-006 found (Config may be properly enabled)"
        else
            print_pass "HRD-001 and HRD-006 are mutually exclusive"
        fi
    fi
else
    print_info "No hardening findings file found"
fi

# =============================================================================
# TEST 4: Security Hub False Positive Check
# =============================================================================
print_header "TEST 4: No False Positives (Security Hub)"

SEC_HUB_FILE="$LATEST/evidence/hardening/security-hub-status.json"
if [ -f "$SEC_HUB_FILE" ]; then
    HUB_ARN=$(jq -r '.[0].HubArn // empty' "$SEC_HUB_FILE" 2>/dev/null)

    if [ -n "$HUB_ARN" ]; then
        echo "Security Hub is ENABLED (HubArn: $HUB_ARN)"

        # HRD-002 should NOT be present if Security Hub is enabled
        HRD_002_COUNT=$(jq '[.findings[] | select(.id == "HRD-002")] | length' "$HRD_FINDINGS_FILE" 2>/dev/null)

        if [ "$HRD_002_COUNT" -gt 0 ]; then
            print_fail "HRD-002 found but Security Hub is enabled (false positive)"
        else
            print_pass "Security Hub enabled and HRD-002 not generated (correct)"
        fi
    else
        echo "Security Hub is DISABLED"
        print_info "Skipping false positive check (Security Hub not enabled)"
    fi
else
    print_info "No Security Hub evidence found"
fi

# =============================================================================
# TEST 5: Evidence vs Findings Consistency
# =============================================================================
print_header "TEST 5: Evidence vs Findings Consistency"

IAM_FINDINGS="$LATEST/findings/iam.json"
IAM_EVIDENCE="$LATEST/evidence/iam/users.json"

if [ -f "$IAM_FINDINGS" ] && [ -f "$IAM_EVIDENCE" ]; then
    # Check if IAM-001 exists when there are actual root access keys
    ROOT_ACCESS_KEYS=$(jq '[.Users[] | select(.UserName == "root") | .AccessKeyMetadata[]? | select(.Status == "Active")] | length' "$IAM_EVIDENCE" 2>/dev/null)
    IAM_001_COUNT=$(jq '[.findings[] | select(.id == "IAM-001")] | length' "$IAM_FINDINGS" 2>/dev/null)

    echo "Root active access keys: $ROOT_ACCESS_KEYS"
    echo "IAM-001 findings: $IAM_001_COUNT"

    # They should correlate (if keys exist, finding should exist)
    if [ "$ROOT_ACCESS_KEYS" -gt 0 ] && [ "$IAM_001_COUNT" -eq 0 ]; then
        print_fail "Root has active access keys but IAM-001 not found"
    elif [ "$ROOT_ACCESS_KEYS" -eq 0 ] && [ "$IAM_001_COUNT" -gt 0 ]; then
        print_fail "IAM-001 found but no root active access keys in evidence"
    else
        print_pass "IAM-001 findings consistent with evidence"
    fi
else
    print_info "IAM evidence/findings not available for consistency check"
fi

# =============================================================================
# SUMMARY
# =============================================================================
print_header "Validation Summary"

TOTAL=$((PASSED + FAILED))
echo "Tests Passed: ${GREEN}$PASSED${NC}/$TOTAL"
echo "Tests Failed: ${RED}$FAILED${NC}/$TOTAL"

if [ $FAILED -eq 0 ]; then
    echo ""
    print_pass "All validation tests passed! ✅"
    echo ""
    echo "Next steps:"
    echo "  1. Review audit findings: cat $LATEST/findings/findings_summary.json"
    echo "  2. Update documentation: edit PROJECT_STATE.md"
    echo "  3. Plan next work: PLAN_E2E_TESTING or PLAN_DOCUMENTATION"
    exit 0
else
    echo ""
    print_fail "Some validation tests failed. Review output above."
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check evidence files: ls -la $LATEST/evidence/"
    echo "  2. Check findings files: ls -la $LATEST/findings/"
    echo "  3. View detailed findings: jq . $LATEST/findings/*.json"
    exit 1
fi
