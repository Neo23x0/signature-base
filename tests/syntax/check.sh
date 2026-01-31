#!/bin/bash
# YARA Syntax Check Script
# Tests all .yar files for compilation errors

set -euo pipefail

YARA_BIN="${YARA_BIN:-yara}"
RULES_DIR="${1:-./yara}"
FAILED=0
PASSED=0
SKIPPED=0

echo "=== YARA Syntax Check ==="
echo "YARA binary: $YARA_BIN"
echo "Rules directory: $RULES_DIR"
echo ""

# Check if yara is installed
if ! command -v "$YARA_BIN" &> /dev/null; then
    echo "ERROR: YARA not found. Please install YARA."
    exit 1
fi

# Get YARA version
YARA_VERSION=$($YARA_BIN --version 2>/dev/null || echo "unknown")
echo "YARA version: $YARA_VERSION"
echo ""

# Find all .yar and .yara files
echo "Scanning for YARA rules..."
RULES=$(find "$RULES_DIR" -type f \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | sort)
RULE_COUNT=$(echo "$RULES" | grep -c . || echo "0")
echo "Found $RULE_COUNT rule files"
echo ""

# Create dummy file for compilation test
DUMMY_FILE=$(mktemp)
echo "dummy" > "$DUMMY_FILE"

# Test each rule
for rule in $RULES; do
    # Skip files with external variables (they need special handling)
    if grep -q "extern\s" "$rule" 2>/dev/null || \
       echo "$rule" | grep -qE "(generic_anomalies|general_cloaking|gen_webshells_ext_vars|thor_inverse_matches|yara_mixed_ext_vars|configured_vulns_ext_vars|gen_fake_amsi_dll|expl_citrix|vuln_drivers_strict_renamed|expl_connectwise_screenconnect_vuln_feb24|gen_mal_3cx_compromise_mar23|gen_susp_obfuscation|gen_vcruntime140_dll_sideloading)"; then
        echo "SKIP: $rule (external variables)"
        ((SKIPPED++)) || true
        continue
    fi
    
    # Try to compile and run the rule (with -n to prevent actual scanning)
    if $YARA_BIN -n "$rule" "$DUMMY_FILE" 2>/dev/null; then
        echo "PASS: $rule"
        ((PASSED++)) || true
    else
        echo "FAIL: $rule"
        $YARA_BIN -n "$rule" "$DUMMY_FILE" 2>&1 | head -3
        ((FAILED++)) || true
    fi
done

# Cleanup
rm -f "$DUMMY_FILE"

echo ""
echo "=== Summary ==="
echo "Passed:  $PASSED"
echo "Skipped: $SKIPPED (external variables)"
echo "Failed:  $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "✅ All syntax checks passed!"
    exit 0
else
    echo "❌ $FAILED rule(s) failed syntax check"
    exit 1
fi
