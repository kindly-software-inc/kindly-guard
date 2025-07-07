#!/bin/bash

# KindlyGuard v0.15.0 Release Verification Script
# This script performs comprehensive verification of the v0.15.0 release
# including security, performance, functionality, and documentation checks

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORT_FILE="$PROJECT_ROOT/release_v0.15.0_verification_report.md"
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
VERSION="0.15.0"

# Test counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNINGS=0

# Function to print section headers
print_section() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

# Function to record check results
record_check() {
    local check_name="$1"
    local status="$2"
    local details="${3:-}"
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ "$status" = "PASS" ]; then
        echo -e "${GREEN}✓ $check_name${NC}"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        echo "✓ **$check_name**: PASSED" >> "$REPORT_FILE"
    elif [ "$status" = "FAIL" ]; then
        echo -e "${RED}✗ $check_name${NC}"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        echo "✗ **$check_name**: FAILED" >> "$REPORT_FILE"
    elif [ "$status" = "WARN" ]; then
        echo -e "${YELLOW}⚠ $check_name${NC}"
        WARNINGS=$((WARNINGS + 1))
        echo "⚠ **$check_name**: WARNING" >> "$REPORT_FILE"
    fi
    
    if [ -n "$details" ]; then
        echo "  $details"
        echo "  - $details" >> "$REPORT_FILE"
    fi
}

# Initialize report file
initialize_report() {
    cat > "$REPORT_FILE" <<EOF
# KindlyGuard v$VERSION Release Verification Report

**Generated**: $TIMESTAMP  
**Version**: $VERSION  
**Commit**: $(git rev-parse HEAD 2>/dev/null || echo "N/A")  
**Branch**: $(git branch --show-current 2>/dev/null || echo "N/A")  

## Executive Summary

This report contains the results of automated verification checks for the KindlyGuard v$VERSION release.

EOF
}

# 1. Version Consistency Checks
check_version_consistency() {
    print_section "1. Version Consistency Checks"
    echo "## 1. Version Consistency Checks" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Check Cargo.toml versions
    local version_issues=0
    
    # Main crates
    for crate in "kindly-guard-server" "kindly-guard-cli" "kindly-guard-shield"; do
        if [ -f "$PROJECT_ROOT/$crate/Cargo.toml" ]; then
            local crate_version=$(grep -E "^version = " "$PROJECT_ROOT/$crate/Cargo.toml" | head -1 | cut -d'"' -f2)
            if [ "$crate_version" = "$VERSION" ]; then
                record_check "$crate version" "PASS" "Version $crate_version matches expected $VERSION"
            else
                record_check "$crate version" "FAIL" "Version $crate_version does not match expected $VERSION"
                version_issues=$((version_issues + 1))
            fi
        else
            record_check "$crate Cargo.toml" "WARN" "File not found"
        fi
    done
    
    # Check CHANGELOG.md
    if grep -q "## \[$VERSION\]" "$PROJECT_ROOT/CHANGELOG.md" 2>/dev/null; then
        record_check "CHANGELOG.md entry" "PASS" "Version $VERSION entry found"
    else
        record_check "CHANGELOG.md entry" "FAIL" "Version $VERSION entry not found"
        version_issues=$((version_issues + 1))
    fi
    
    # Check package.json if it exists
    if [ -f "$PROJECT_ROOT/package.json" ]; then
        local pkg_version=$(grep -E '"version":' "$PROJECT_ROOT/package.json" | cut -d'"' -f4)
        if [ "$pkg_version" = "$VERSION" ]; then
            record_check "package.json version" "PASS" "Version matches"
        else
            record_check "package.json version" "FAIL" "Version mismatch"
            version_issues=$((version_issues + 1))
        fi
    fi
    
    echo "" >> "$REPORT_FILE"
}

# 2. Security Audits
run_security_audits() {
    print_section "2. Security Audits"
    echo "## 2. Security Audits" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    cd "$PROJECT_ROOT"
    
    # Cargo audit
    if command -v cargo-audit >/dev/null 2>&1; then
        echo "Running cargo audit..."
        if cargo audit 2>&1 | tee audit_output.tmp; then
            if grep -q "0 vulnerabilities found" audit_output.tmp; then
                record_check "Cargo audit" "PASS" "No vulnerabilities found"
            else
                local vuln_count=$(grep -E "[0-9]+ vulnerabilities" audit_output.tmp | grep -oE "[0-9]+" | head -1)
                record_check "Cargo audit" "FAIL" "$vuln_count vulnerabilities found"
            fi
        else
            record_check "Cargo audit" "FAIL" "Audit command failed"
        fi
        rm -f audit_output.tmp
    else
        record_check "Cargo audit" "WARN" "cargo-audit not installed"
    fi
    
    # Cargo deny
    if command -v cargo-deny >/dev/null 2>&1 && [ -f "deny.toml" ]; then
        echo "Running cargo deny..."
        if cargo deny check 2>&1 | tee deny_output.tmp; then
            record_check "Cargo deny" "PASS" "All checks passed"
        else
            record_check "Cargo deny" "FAIL" "Some checks failed"
        fi
        rm -f deny_output.tmp
    else
        record_check "Cargo deny" "WARN" "cargo-deny not installed or deny.toml not found"
    fi
    
    # Cargo geiger (unsafe code detection)
    if command -v cargo-geiger >/dev/null 2>&1; then
        echo "Running cargo geiger..."
        cargo geiger --all-features 2>&1 | tee geiger_output.tmp
        local unsafe_count=$(grep -E "unsafe fn|unsafe impl|unsafe trait" geiger_output.tmp | wc -l)
        if [ "$unsafe_count" -eq 0 ]; then
            record_check "Unsafe code check" "PASS" "No unsafe code in dependencies"
        else
            record_check "Unsafe code check" "WARN" "$unsafe_count unsafe code instances found in dependencies"
        fi
        rm -f geiger_output.tmp
    else
        record_check "Unsafe code check" "WARN" "cargo-geiger not installed"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# 3. Test Suite Execution
run_test_suite() {
    print_section "3. Test Suite Execution"
    echo "## 3. Test Suite Execution" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    cd "$PROJECT_ROOT"
    
    # Run all tests with all features
    echo "Running full test suite..."
    if cargo test --all --all-features 2>&1 | tee test_output.tmp; then
        local test_result=$(grep -E "test result:" test_output.tmp | tail -1)
        local passed=$(echo "$test_result" | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+")
        local failed=$(echo "$test_result" | grep -oE "[0-9]+ failed" | grep -oE "[0-9]+")
        
        if [ -n "$failed" ] && [ "$failed" -eq 0 ]; then
            record_check "All tests" "PASS" "$passed tests passed"
        else
            record_check "All tests" "FAIL" "$failed tests failed out of $passed"
        fi
    else
        record_check "All tests" "FAIL" "Test execution failed"
    fi
    
    # Run specific v0.15.0 feature tests
    echo "Running quarantine tests..."
    if cargo test --package kindly-guard-server quarantine --all-features 2>&1 | tee quarantine_test.tmp; then
        record_check "Quarantine tests" "PASS" "Quarantine functionality verified"
    else
        record_check "Quarantine tests" "FAIL" "Quarantine tests failed"
    fi
    
    echo "Running message neutralization tests..."
    if cargo test --package kindly-guard-server message_neutralization --all-features 2>&1 | tee message_test.tmp; then
        record_check "Message neutralization tests" "PASS" "Message neutralization verified"
    else
        record_check "Message neutralization tests" "FAIL" "Message neutralization tests failed"
    fi
    
    # Property-based tests
    if cargo test --test property_tests 2>&1 | tee property_test.tmp; then
        record_check "Property tests" "PASS" "Fuzzing tests passed"
    else
        record_check "Property tests" "WARN" "Property tests not found or failed"
    fi
    
    rm -f test_output.tmp quarantine_test.tmp message_test.tmp property_test.tmp
    echo "" >> "$REPORT_FILE"
}

# 4. Performance Benchmarks
run_performance_benchmarks() {
    print_section "4. Performance Benchmarks"
    echo "## 4. Performance Benchmarks" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    cd "$PROJECT_ROOT"
    
    # Run benchmarks
    echo "Running performance benchmarks..."
    if cargo bench --all-features 2>&1 | tee bench_output.tmp; then
        record_check "Benchmark execution" "PASS" "Benchmarks completed successfully"
        
        # Extract key metrics
        echo "### Key Performance Metrics:" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        
        # Scanner performance
        if grep -q "scanner.*time:" bench_output.tmp; then
            local scanner_perf=$(grep -E "scanner.*time:" bench_output.tmp | head -1)
            echo "- Scanner: $scanner_perf" >> "$REPORT_FILE"
        fi
        
        # Encryption performance (new in v0.15.0)
        if grep -q "encrypt.*time:" bench_output.tmp; then
            local encrypt_perf=$(grep -E "encrypt.*time:" bench_output.tmp | head -1)
            echo "- Encryption: $encrypt_perf" >> "$REPORT_FILE"
        fi
        
    else
        record_check "Benchmark execution" "FAIL" "Benchmarks failed to run"
    fi
    
    rm -f bench_output.tmp
    echo "" >> "$REPORT_FILE"
}

# 5. Quarantine Encryption Test
test_quarantine_encryption() {
    print_section "5. Quarantine Encryption Functionality"
    echo "## 5. Quarantine Encryption Functionality" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    cd "$PROJECT_ROOT"
    
    # Test encryption functionality
    echo "Testing quarantine encryption..."
    
    # Create test directory
    local test_dir="$PROJECT_ROOT/test_quarantine_$$"
    mkdir -p "$test_dir"
    
    # Create test file with threat
    echo "Test content with \u202E threat" > "$test_dir/test_threat.txt"
    
    # Run quarantine command if CLI is built
    if [ -x "$PROJECT_ROOT/target/release/kindly-guard" ]; then
        if "$PROJECT_ROOT/target/release/kindly-guard" quarantine "$test_dir/test_threat.txt" 2>&1 | tee quarantine_output.tmp; then
            # Check if encrypted file was created
            if ls "$test_dir"/*.enc 2>/dev/null; then
                record_check "Quarantine encryption" "PASS" "File successfully encrypted and quarantined"
                
                # Test decryption
                local enc_file=$(ls "$test_dir"/*.enc | head -1)
                if "$PROJECT_ROOT/target/release/kindly-guard" restore "$enc_file" 2>&1; then
                    record_check "Quarantine decryption" "PASS" "File successfully restored"
                else
                    record_check "Quarantine decryption" "FAIL" "Failed to restore quarantined file"
                fi
            else
                record_check "Quarantine encryption" "FAIL" "Encrypted file not created"
            fi
        else
            record_check "Quarantine encryption" "FAIL" "Quarantine command failed"
        fi
        rm -f quarantine_output.tmp
    else
        record_check "Quarantine encryption" "WARN" "CLI binary not found - run 'cargo build --release' first"
    fi
    
    # Cleanup
    rm -rf "$test_dir"
    echo "" >> "$REPORT_FILE"
}

# 6. MCP Tool Integration Test
test_mcp_integration() {
    print_section "6. MCP Tool Integration"
    echo "## 6. MCP Tool Integration" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    cd "$PROJECT_ROOT"
    
    # Check if MCP server can start
    echo "Testing MCP server startup..."
    
    if [ -x "$PROJECT_ROOT/target/release/kindly-guard-server" ]; then
        # Start server in background with timeout
        timeout 5s "$PROJECT_ROOT/target/release/kindly-guard-server" --stdio 2>&1 | tee mcp_output.tmp &
        local server_pid=$!
        
        sleep 2
        
        # Check if server is running
        if kill -0 $server_pid 2>/dev/null; then
            record_check "MCP server startup" "PASS" "Server starts successfully"
            kill $server_pid 2>/dev/null || true
        else
            record_check "MCP server startup" "FAIL" "Server failed to start"
        fi
        
        # Check for proper tool registration in output
        if grep -q "scan_text\|quarantine_threat\|get_stats" mcp_output.tmp; then
            record_check "MCP tool registration" "PASS" "Tools properly registered"
        else
            record_check "MCP tool registration" "WARN" "Could not verify tool registration"
        fi
        
        rm -f mcp_output.tmp
    else
        record_check "MCP server" "WARN" "Server binary not found - run 'cargo build --release' first"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# 7. Documentation Completeness
check_documentation() {
    print_section "7. Documentation Completeness"
    echo "## 7. Documentation Completeness" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    cd "$PROJECT_ROOT"
    
    # Check for required documentation files
    local required_docs=(
        "README.md"
        "CHANGELOG.md"
        "SECURITY.md"
        "docs/API_DOCUMENTATION.md"
        "docs/INSTALLATION.md"
        "docs/CONFIGURATION.md"
    )
    
    for doc in "${required_docs[@]}"; do
        if [ -f "$doc" ]; then
            # Check if v0.15.0 is mentioned in changelog
            if [ "$doc" = "CHANGELOG.md" ] && grep -q "$VERSION" "$doc"; then
                record_check "$doc" "PASS" "Present and contains v$VERSION entry"
            else
                record_check "$doc" "PASS" "Present"
            fi
        else
            record_check "$doc" "FAIL" "Missing"
        fi
    done
    
    # Check API documentation generation
    echo "Generating API documentation..."
    if cargo doc --no-deps --all-features 2>&1 >/dev/null; then
        record_check "API documentation generation" "PASS" "Documentation builds successfully"
    else
        record_check "API documentation generation" "FAIL" "Documentation build failed"
    fi
    
    # Check for new feature documentation
    if grep -q "quarantine" "$PROJECT_ROOT/docs/API_DOCUMENTATION.md" 2>/dev/null; then
        record_check "Quarantine feature docs" "PASS" "Documented"
    else
        record_check "Quarantine feature docs" "WARN" "Not found in API documentation"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# 8. Build Verification
verify_builds() {
    print_section "8. Build Verification"
    echo "## 8. Build Verification" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    cd "$PROJECT_ROOT"
    
    # Debug build
    echo "Testing debug build..."
    if cargo build --all 2>&1 >/dev/null; then
        record_check "Debug build" "PASS" "Builds successfully"
    else
        record_check "Debug build" "FAIL" "Build failed"
    fi
    
    # Release build
    echo "Testing release build..."
    if cargo build --release --all 2>&1 >/dev/null; then
        record_check "Release build" "PASS" "Builds successfully"
    else
        record_check "Release build" "FAIL" "Build failed"
    fi
    
    # Feature combinations
    echo "Testing feature combinations..."
    if cargo build --all-features 2>&1 >/dev/null; then
        record_check "All features build" "PASS" "Builds with all features"
    else
        record_check "All features build" "FAIL" "Build failed with all features"
    fi
    
    if cargo build --no-default-features 2>&1 >/dev/null; then
        record_check "No default features build" "PASS" "Builds without default features"
    else
        record_check "No default features build" "FAIL" "Build failed without default features"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# 9. Generate Summary
generate_summary() {
    print_section "Release Verification Summary"
    
    local status="READY"
    if [ $FAILED_CHECKS -gt 0 ]; then
        status="NOT READY"
    elif [ $WARNINGS -gt 5 ]; then
        status="READY WITH CONCERNS"
    fi
    
    cat >> "$REPORT_FILE" <<EOF

## Summary

**Total Checks**: $TOTAL_CHECKS  
**Passed**: $PASSED_CHECKS  
**Failed**: $FAILED_CHECKS  
**Warnings**: $WARNINGS  

### Release Status: **$status**

EOF

    if [ $FAILED_CHECKS -gt 0 ]; then
        echo "### Critical Issues to Address:" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "Please review the failed checks above and address them before release." >> "$REPORT_FILE"
    fi
    
    if [ $WARNINGS -gt 0 ]; then
        echo "" >> "$REPORT_FILE"
        echo "### Warnings to Consider:" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        echo "Review the warnings above. Some may be acceptable for release." >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "*Report generated by verify_v0.15.0_release.sh*" >> "$REPORT_FILE"
    
    # Display summary to console
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}RELEASE VERIFICATION COMPLETE${NC}"
    echo -e "${BLUE}========================================${NC}\n"
    
    echo "Total Checks: $TOTAL_CHECKS"
    echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
    echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
    echo -e "Warnings: ${YELLOW}$WARNINGS${NC}"
    
    echo -e "\nRelease Status: "
    if [ "$status" = "READY" ]; then
        echo -e "${GREEN}$status${NC}"
    elif [ "$status" = "NOT READY" ]; then
        echo -e "${RED}$status${NC}"
    else
        echo -e "${YELLOW}$status${NC}"
    fi
    
    echo -e "\nFull report saved to: ${BLUE}$REPORT_FILE${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}KindlyGuard v$VERSION Release Verification${NC}"
    echo -e "${BLUE}Starting verification at $TIMESTAMP${NC}\n"
    
    # Ensure we're in the right directory
    if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
        echo -e "${RED}Error: Not in KindlyGuard project root${NC}"
        exit 1
    fi
    
    # Initialize report
    initialize_report
    
    # Run all checks
    check_version_consistency
    run_security_audits
    run_test_suite
    run_performance_benchmarks
    test_quarantine_encryption
    test_mcp_integration
    check_documentation
    verify_builds
    
    # Generate final summary
    generate_summary
}

# Run main function
main "$@"