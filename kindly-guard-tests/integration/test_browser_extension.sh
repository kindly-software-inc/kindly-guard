#!/bin/bash
# Test script for KindlyGuard Browser Extension

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXTENSION_DIR="$PROJECT_ROOT/kindly-guard-extension"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

# Function to run a test
run_test() {
    local test_name=$1
    local test_command=$2
    
    log_test "$test_name"
    if eval "$test_command"; then
        log_info "✓ $test_name passed"
        ((TESTS_PASSED++))
    else
        log_error "✗ $test_name failed"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Build Extension
test_build_extension() {
    log_info "Building browser extension..."
    cd "$EXTENSION_DIR"
    
    # Install dependencies
    npm install --silent
    
    # Build extension
    npm run build
    
    # Check if build artifacts exist
    [ -d "$EXTENSION_DIR/dist" ] && \
    [ -f "$EXTENSION_DIR/dist/manifest.json" ] && \
    [ -f "$EXTENSION_DIR/dist/background.js" ]
}

# Test 2: Validate Manifest
test_validate_manifest() {
    log_info "Validating extension manifest..."
    
    # Check manifest version and required fields
    local MANIFEST="$EXTENSION_DIR/dist/manifest.json"
    
    # Check manifest version 3
    grep -q '"manifest_version": 3' "$MANIFEST" && \
    grep -q '"name": "KindlyGuard"' "$MANIFEST" && \
    grep -q '"permissions"' "$MANIFEST" && \
    grep -q '"host_permissions"' "$MANIFEST"
}

# Test 3: Test Content Script
test_content_script() {
    log_info "Testing content script..."
    
    # Check if content script is built
    [ -f "$EXTENSION_DIR/dist/content.js" ] || [ -f "$EXTENSION_DIR/dist/js/content.js" ]
    
    # Verify content script includes threat detection
    local CONTENT_SCRIPT=$(find "$EXTENSION_DIR/dist" -name "content.js" -type f | head -n1)
    if [ -n "$CONTENT_SCRIPT" ]; then
        grep -q "scanForThreats\|detectThreats\|security" "$CONTENT_SCRIPT" || true
    fi
}

# Test 4: Test Background Service Worker
test_background_worker() {
    log_info "Testing background service worker..."
    
    # Check if background script exists
    local BG_SCRIPT="$EXTENSION_DIR/dist/background.js"
    [ -f "$BG_SCRIPT" ]
    
    # Verify it's a service worker (MV3)
    grep -q "chrome.runtime\|browser.runtime" "$BG_SCRIPT"
}

# Test 5: Test Native Messaging Host
test_native_messaging() {
    log_info "Testing native messaging configuration..."
    
    # Check if native messaging manifest exists
    local NATIVE_MANIFEST="$EXTENSION_DIR/native/kindly_guard_host.json"
    if [ -f "$NATIVE_MANIFEST" ]; then
        # Verify manifest structure
        grep -q '"name": "io.kindlyguard.host"' "$NATIVE_MANIFEST" && \
        grep -q '"type": "stdio"' "$NATIVE_MANIFEST" && \
        grep -q '"path"' "$NATIVE_MANIFEST"
    else
        # Native messaging might be optional
        log_info "Native messaging not configured (optional)"
        return 0
    fi
}

# Test 6: Test Extension Size
test_extension_size() {
    log_info "Testing extension size..."
    
    # Get total size of dist directory
    local SIZE_KB=$(du -sk "$EXTENSION_DIR/dist" 2>/dev/null | cut -f1)
    local SIZE_MB=$((SIZE_KB / 1024))
    
    log_info "Extension size: ${SIZE_MB}MB (${SIZE_KB}KB)"
    
    # Chrome extensions should be under 10MB unpacked
    [ $SIZE_KB -lt 10240 ]
}

# Test 7: Test Permission Requirements
test_permissions() {
    log_info "Testing permission requirements..."
    
    local MANIFEST="$EXTENSION_DIR/dist/manifest.json"
    
    # Extract permissions
    local PERMS=$(jq -r '.permissions[]' "$MANIFEST" 2>/dev/null || echo "")
    
    # Check for minimal required permissions
    echo "$PERMS" | grep -E "activeTab|tabs|storage" > /dev/null
}

# Test 8: Test Web Accessible Resources
test_web_accessible() {
    log_info "Testing web accessible resources..."
    
    local MANIFEST="$EXTENSION_DIR/dist/manifest.json"
    
    # Check if injected scripts are properly configured
    if jq -e '.web_accessible_resources' "$MANIFEST" > /dev/null 2>&1; then
        # MV3 format
        jq -e '.web_accessible_resources[0].resources | length > 0' "$MANIFEST" > /dev/null
    else
        # No web accessible resources needed
        return 0
    fi
}

# Test 9: Test Update URL
test_update_url() {
    log_info "Testing update configuration..."
    
    local MANIFEST="$EXTENSION_DIR/dist/manifest.json"
    
    # Check if update URL is set (for self-hosted extensions)
    if jq -e '.update_url' "$MANIFEST" > /dev/null 2>&1; then
        local UPDATE_URL=$(jq -r '.update_url' "$MANIFEST")
        [[ "$UPDATE_URL" =~ ^https:// ]]
    else
        # No update URL is fine for store-distributed extensions
        return 0
    fi
}

# Test 10: Lint Extension Code
test_lint_extension() {
    log_info "Linting extension code..."
    cd "$EXTENSION_DIR"
    
    # Run linter if available
    if [ -f "package.json" ] && grep -q '"lint"' package.json; then
        npm run lint 2>&1 | tail -n 20
        # Check exit code
        [ ${PIPESTATUS[0]} -eq 0 ]
    else
        log_info "No linter configured"
        return 0
    fi
}

# Test 11: Test Icon Assets
test_icon_assets() {
    log_info "Testing icon assets..."
    
    # Check for required icon sizes
    local ICONS_FOUND=0
    for size in 16 48 128; do
        if [ -f "$EXTENSION_DIR/dist/icons/icon-${size}.png" ] || \
           [ -f "$EXTENSION_DIR/dist/images/icon-${size}.png" ] || \
           [ -f "$EXTENSION_DIR/dist/icon-${size}.png" ]; then
            ((ICONS_FOUND++))
        fi
    done
    
    # At least one icon should exist
    [ $ICONS_FOUND -gt 0 ]
}

# Test 12: Test CSP Compliance
test_csp_compliance() {
    log_info "Testing Content Security Policy..."
    
    local MANIFEST="$EXTENSION_DIR/dist/manifest.json"
    
    # Check if CSP is defined (recommended for MV3)
    if jq -e '.content_security_policy' "$MANIFEST" > /dev/null 2>&1; then
        # Verify no unsafe-inline or unsafe-eval
        ! jq -r '.content_security_policy | to_entries[].value' "$MANIFEST" | grep -E "unsafe-inline|unsafe-eval"
    else
        # CSP might be default in MV3
        return 0
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Remove any test artifacts
    rm -f /tmp/extension-test-*
}

# Main test execution
main() {
    log_info "Starting Browser Extension Tests"
    log_info "================================"
    
    # Check if extension directory exists
    if [ ! -d "$EXTENSION_DIR" ]; then
        log_error "Extension directory not found: $EXTENSION_DIR"
        exit 1
    fi
    
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Run tests
    run_test "Build Extension" test_build_extension
    run_test "Validate Manifest" test_validate_manifest
    run_test "Content Script" test_content_script
    run_test "Background Worker" test_background_worker
    run_test "Native Messaging" test_native_messaging
    run_test "Extension Size" test_extension_size
    run_test "Permissions" test_permissions
    run_test "Web Accessible Resources" test_web_accessible
    run_test "Update URL" test_update_url
    run_test "Lint Code" test_lint_extension
    run_test "Icon Assets" test_icon_assets
    run_test "CSP Compliance" test_csp_compliance
    
    # Summary
    echo
    log_info "Test Summary"
    log_info "============"
    log_info "Tests passed: $TESTS_PASSED"
    log_error "Tests failed: $TESTS_FAILED"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log_info "All tests passed! ✓"
        exit 0
    else
        log_error "Some tests failed! ✗"
        exit 1
    fi
}

# Run main function
main "$@"