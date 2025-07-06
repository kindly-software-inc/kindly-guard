#!/bin/bash
# Comprehensive CI/CD Diagnostic Script

echo "🔍 KindlyGuard CI/CD Diagnostic Report"
echo "====================================="
echo "Generated: $(date)"
echo ""

# Function to check dependencies
check_dependencies() {
    echo "📦 Checking for problematic dependencies..."
    echo ""
    
    # Check for OpenSSL
    echo "OpenSSL dependencies:"
    cargo tree 2>/dev/null | grep -i "openssl" || echo "  ✅ No direct OpenSSL dependencies found"
    
    # Check for native-tls
    echo -e "\nnative-tls dependencies:"
    cargo tree 2>/dev/null | grep -i "native-tls" || echo "  ✅ No native-tls dependencies found"
    
    # Check reqwest configuration
    echo -e "\nreqwest configurations in Cargo.toml files:"
    find . -name "Cargo.toml" -type f -exec grep -H "reqwest" {} \; 2>/dev/null | grep -v target || echo "  No reqwest dependencies found"
}

# Function to test local builds
test_local_builds() {
    echo -e "\n🏗️  Testing local builds..."
    echo ""
    
    # Test native build
    echo "Native build test:"
    if cargo build --release 2>&1 | grep -E "(error|failed)"; then
        echo "  ❌ Native build failed"
    else
        echo "  ✅ Native build successful"
    fi
    
    # Test musl build if cross is available
    if command -v cross &> /dev/null; then
        echo -e "\nMusl cross-compilation test:"
        if cross build --target x86_64-unknown-linux-musl --release 2>&1 | grep -E "(error|failed)"; then
            echo "  ❌ Musl build failed"
        else
            echo "  ✅ Musl build successful"
        fi
    else
        echo -e "\n⚠️  Cross not installed - skipping musl build test"
    fi
}

# Function to analyze GitHub Actions
analyze_github_actions() {
    echo -e "\n🎬 GitHub Actions Analysis..."
    echo ""
    
    if command -v gh &> /dev/null; then
        echo "Recent workflow runs:"
        gh run list --workflow=release.yml --limit 5 || echo "  Failed to fetch runs"
        
        # Get latest run details
        LATEST_RUN=$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null)
        if [ ! -z "$LATEST_RUN" ]; then
            echo -e "\nLatest run (#$LATEST_RUN) status:"
            gh run view "$LATEST_RUN" --json status,conclusion,event 2>/dev/null | jq -r '"  Status: " + .status + "\n  Conclusion: " + (.conclusion // "pending") + "\n  Event: " + .event' || echo "  Failed to get run details"
        fi
    else
        echo "❌ GitHub CLI not installed - cannot analyze workflows"
    fi
}

# Function to check workflow file
check_workflow_file() {
    echo -e "\n📄 Workflow File Check..."
    echo ""
    
    WORKFLOW_FILE=".github/workflows/release.yml"
    if [ -f "$WORKFLOW_FILE" ]; then
        echo "Workflow file exists: ✅"
        
        # Check for common issues
        echo -e "\nChecking for common issues:"
        
        # Check for OpenSSL references
        if grep -i "openssl" "$WORKFLOW_FILE" &> /dev/null; then
            echo "  ⚠️  Found OpenSSL references in workflow"
        else
            echo "  ✅ No OpenSSL references in workflow"
        fi
        
        # Check for proper YAML structure
        if python3 -c "import yaml; yaml.safe_load(open('$WORKFLOW_FILE'))" 2>/dev/null; then
            echo "  ✅ Valid YAML syntax"
        else
            echo "  ❌ Invalid YAML syntax!"
        fi
        
        # Check matrix configuration
        if grep -q "matrix:" "$WORKFLOW_FILE"; then
            echo "  ✅ Matrix build configured"
            echo -e "\n  Build targets:"
            grep -A20 "matrix:" "$WORKFLOW_FILE" | grep -E "(os:|target:)" | sed 's/^/    /'
        fi
    else
        echo "❌ Workflow file not found!"
    fi
}

# Function to suggest fixes
suggest_fixes() {
    echo -e "\n💡 Suggested Next Steps..."
    echo ""
    
    echo "1. If OpenSSL issues persist:"
    echo "   - Ensure ALL crates use rustls: reqwest = { version = \"0.11\", default-features = false, features = [\"json\", \"rustls-tls\"] }"
    echo "   - Check transitive dependencies: cargo tree --all-features | grep -E '(openssl|native-tls)'"
    echo ""
    
    echo "2. For debugging workflow:"
    echo "   - Add debug step: - run: ls -la target/release/"
    echo "   - Enable verbose logging: RUST_BACKTRACE=1 RUST_LOG=debug"
    echo ""
    
    echo "3. Quick fixes to try:"
    echo "   - Clear cargo cache: rm -rf ~/.cargo/registry/cache"
    echo "   - Update dependencies: cargo update"
    echo "   - Test minimal build: cargo build --no-default-features"
}

# Main execution
main() {
    check_dependencies
    test_local_builds
    analyze_github_actions
    check_workflow_file
    suggest_fixes
    
    echo -e "\n✅ Diagnostic complete!"
    echo ""
    echo "📊 Summary files created:"
    echo "  - CI_CD_JOURNEY_DOCUMENTATION.md"
    echo "  - CI_CD_TROUBLESHOOTING_GUIDE.md"
    echo "  - diagnose_ci_issues.sh (this file)"
}

# Run main function
main