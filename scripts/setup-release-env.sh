#!/bin/bash

# KindlyGuard Release Environment Setup Script
# This script helps set up the complete release environment by:
# - Checking for all required tools
# - Helping set up authentication tokens
# - Testing registry connections
# - Validating git configuration
# - Creating template .env file if missing
#
# Usage: ./scripts/setup-release-env.sh [--check-only]
#
# Options:
#   --check-only    Only check requirements without making changes
#   --help          Show this help message

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CHECK_ONLY=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        --help)
            grep "^#" "$0" | grep -E "^# (KindlyGuard|This script|Usage:|Options:)" | sed 's/^# //'
            echo ""
            echo "Environment Variables:"
            echo "  CRATES_IO_TOKEN    - Token for publishing to crates.io"
            echo "  NPM_TOKEN          - Token for publishing to npm"
            echo "  DOCKER_USERNAME    - Docker Hub username"
            echo "  DOCKER_PASSWORD    - Docker Hub password or access token"
            echo "  GITHUB_TOKEN       - GitHub personal access token"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Helper functions
echo_header() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

echo_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if a command exists
check_command() {
    local cmd=$1
    local install_hint=$2
    
    if command -v "$cmd" &> /dev/null; then
        echo_success "$cmd is installed ($(command -v "$cmd"))"
        return 0
    else
        echo_error "$cmd is not installed"
        echo_info "Installation: $install_hint"
        return 1
    fi
}

# Check if a Rust tool is installed
check_rust_tool() {
    local tool=$1
    local install_cmd=$2
    
    if cargo --list | grep -q "^$tool"; then
        echo_success "cargo-$tool is installed"
        return 0
    else
        echo_error "cargo-$tool is not installed"
        echo_info "Installation: $install_cmd"
        return 1
    fi
}

# Check version of a tool
check_version() {
    local cmd=$1
    local min_version=$2
    local version_arg=${3:-"--version"}
    
    if command -v "$cmd" &> /dev/null; then
        local version=$($cmd $version_arg 2>&1 | head -n1)
        echo_info "$cmd version: $version"
        return 0
    else
        return 1
    fi
}

# Initialize counters
TOTAL_CHECKS=0
FAILED_CHECKS=0

# Start setup process
echo -e "${BLUE}KindlyGuard Release Environment Setup${NC}"
echo -e "${BLUE}=====================================${NC}"

# Check required tools
echo_header "Checking Required Tools"

# Core tools
check_command "git" "https://git-scm.com/downloads" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

check_command "cargo" "https://rustup.rs/" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

check_command "rustc" "https://rustup.rs/" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

check_command "npm" "https://nodejs.org/" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

check_command "docker" "https://docs.docker.com/get-docker/" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

check_command "jq" "apt-get install jq / brew install jq" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

check_command "gh" "https://cli.github.com/" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

# Optional but recommended tools
echo_header "Checking Optional Tools"

check_command "gpg" "apt-get install gnupg / brew install gnupg" || echo_warning "GPG not found - needed for signing"

check_command "gitleaks" "https://github.com/zricethezav/gitleaks" || echo_warning "Gitleaks not found - recommended for secret scanning"

check_command "hadolint" "https://github.com/hadolint/hadolint" || echo_warning "Hadolint not found - recommended for Dockerfile linting"

# Rust tools
echo_header "Checking Rust Tools"

check_rust_tool "audit" "cargo install cargo-audit" || ((FAILED_CHECKS++))
((TOTAL_CHECKS++))

check_rust_tool "release" "cargo install cargo-release" || echo_warning "cargo-release not found - useful for release automation"

check_rust_tool "outdated" "cargo install cargo-outdated" || echo_warning "cargo-outdated not found - useful for dependency management"

check_rust_tool "nextest" "cargo install cargo-nextest" || echo_warning "cargo-nextest not found - faster test execution with better isolation"

# Check Docker buildx
echo_header "Checking Docker Configuration"

if docker buildx version &> /dev/null; then
    echo_success "Docker buildx is available"
    
    # Check if multi-platform builder exists
    if docker buildx ls | grep -q "multi-platform"; then
        echo_success "Multi-platform builder configured"
    else
        echo_warning "Multi-platform builder not found"
        if [[ "$CHECK_ONLY" == false ]]; then
            echo_info "Creating multi-platform builder..."
            docker buildx create --name multi-platform --use || echo_error "Failed to create builder"
        fi
    fi
else
    echo_error "Docker buildx not available"
    echo_info "Run: $SCRIPT_DIR/install-docker-buildx.sh"
    ((FAILED_CHECKS++))
fi
((TOTAL_CHECKS++))

# Check git configuration
echo_header "Checking Git Configuration"

# Check user name
if git config --global user.name &> /dev/null; then
    echo_success "Git user name configured: $(git config --global user.name)"
else
    echo_error "Git user name not configured"
    echo_info "Run: git config --global user.name \"Your Name\""
    ((FAILED_CHECKS++))
fi
((TOTAL_CHECKS++))

# Check user email
if git config --global user.email &> /dev/null; then
    echo_success "Git user email configured: $(git config --global user.email)"
else
    echo_error "Git user email not configured"
    echo_info "Run: git config --global user.email \"your.email@example.com\""
    ((FAILED_CHECKS++))
fi
((TOTAL_CHECKS++))

# Check GPG signing
if git config --global user.signingkey &> /dev/null; then
    echo_success "Git GPG signing key configured"
    
    # Check if commits are configured to be signed
    if [[ "$(git config --global commit.gpgsign)" == "true" ]]; then
        echo_success "Git commit signing enabled"
    else
        echo_warning "Git commit signing not enabled"
        echo_info "Run: git config --global commit.gpgsign true"
    fi
else
    echo_warning "Git GPG signing key not configured"
    echo_info "See: https://docs.github.com/en/authentication/managing-commit-signature-verification"
fi

# Check environment variables
echo_header "Checking Environment Variables"

check_env_var() {
    local var_name=$1
    local description=$2
    local test_command=$3
    
    if [[ -n "${!var_name:-}" ]]; then
        echo_success "$var_name is set"
        
        # Run test command if provided
        if [[ -n "$test_command" ]] && [[ "$CHECK_ONLY" == false ]]; then
            echo_info "Testing $var_name..."
            if eval "$test_command" &> /dev/null; then
                echo_success "$var_name test passed"
            else
                echo_error "$var_name test failed"
                ((FAILED_CHECKS++))
            fi
        fi
    else
        echo_error "$var_name is not set"
        echo_info "$description"
        ((FAILED_CHECKS++))
    fi
    ((TOTAL_CHECKS++))
}

# Check required environment variables
check_env_var "CRATES_IO_TOKEN" \
    "Get from: https://crates.io/settings/tokens" \
    "cargo search kindly-guard --limit 1"

check_env_var "NPM_TOKEN" \
    "Get from: https://www.npmjs.com/settings/~/tokens" \
    "npm whoami"

check_env_var "DOCKER_USERNAME" \
    "Your Docker Hub username" \
    ""

check_env_var "DOCKER_PASSWORD" \
    "Your Docker Hub password or access token" \
    "echo \$DOCKER_PASSWORD | docker login -u \$DOCKER_USERNAME --password-stdin"

check_env_var "GITHUB_TOKEN" \
    "Get from: https://github.com/settings/tokens (needs repo and packages scopes)" \
    "gh auth status"

# Create .env template if it doesn't exist
echo_header "Environment File Setup"

ENV_FILE="$PROJECT_ROOT/.env"
ENV_TEMPLATE="$PROJECT_ROOT/.env.template"

if [[ -f "$ENV_FILE" ]]; then
    echo_success ".env file exists"
else
    echo_warning ".env file not found"
    
    if [[ "$CHECK_ONLY" == false ]]; then
        echo_info "Creating .env.template..."
        cat > "$ENV_TEMPLATE" << 'EOF'
# KindlyGuard Release Environment Variables
# Copy this file to .env and fill in your values
# DO NOT commit .env to version control!

# Crates.io publishing token
# Get from: https://crates.io/settings/tokens
CRATES_IO_TOKEN=

# NPM publishing token
# Get from: https://www.npmjs.com/settings/~/tokens
NPM_TOKEN=

# Docker Hub credentials
DOCKER_USERNAME=
DOCKER_PASSWORD=

# GitHub personal access token
# Needs: repo, write:packages, read:packages scopes
# Get from: https://github.com/settings/tokens
GITHUB_TOKEN=

# Optional: Slack webhook for notifications
# SLACK_WEBHOOK_URL=

# Optional: Email configuration
# SMTP_SERVER=
# SMTP_USERNAME=
# SMTP_PASSWORD=
EOF
        echo_success "Created .env.template"
        echo_info "Copy to .env and fill in your values: cp .env.template .env"
    fi
fi

# Check .gitignore includes .env
if grep -q "^\.env$" "$PROJECT_ROOT/.gitignore" 2>/dev/null; then
    echo_success ".env is in .gitignore"
else
    echo_warning ".env is not in .gitignore"
    if [[ "$CHECK_ONLY" == false ]]; then
        echo ".env" >> "$PROJECT_ROOT/.gitignore"
        echo_success "Added .env to .gitignore"
    fi
fi

# Test registry connections
if [[ "$CHECK_ONLY" == false ]]; then
    echo_header "Testing Registry Connections"
    
    # Test crates.io
    if [[ -n "${CRATES_IO_TOKEN:-}" ]]; then
        echo_info "Testing crates.io connection..."
        if cargo search kindly-guard --limit 1 &> /dev/null; then
            echo_success "crates.io connection successful"
        else
            echo_error "crates.io connection failed"
        fi
    fi
    
    # Test npm
    if [[ -n "${NPM_TOKEN:-}" ]]; then
        echo_info "Testing npm connection..."
        if npm whoami &> /dev/null; then
            echo_success "npm connection successful (logged in as: $(npm whoami))"
        else
            echo_error "npm connection failed"
        fi
    fi
    
    # Test Docker Hub
    if [[ -n "${DOCKER_USERNAME:-}" ]] && [[ -n "${DOCKER_PASSWORD:-}" ]]; then
        echo_info "Testing Docker Hub connection..."
        if echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin &> /dev/null; then
            echo_success "Docker Hub connection successful"
            docker logout &> /dev/null
        else
            echo_error "Docker Hub connection failed"
        fi
    fi
    
    # Test GitHub
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        echo_info "Testing GitHub connection..."
        if gh auth status &> /dev/null; then
            echo_success "GitHub connection successful"
        else
            echo_error "GitHub connection failed"
        fi
    fi
fi

# Check release configuration
echo_header "Checking Release Configuration"

if [[ -f "$PROJECT_ROOT/release-config.yml" ]]; then
    echo_success "release-config.yml exists"
else
    echo_error "release-config.yml not found"
    ((FAILED_CHECKS++))
fi
((TOTAL_CHECKS++))

if [[ -f "$PROJECT_ROOT/version-locations.json" ]]; then
    echo_success "version-locations.json exists"
else
    echo_error "version-locations.json not found"
    ((FAILED_CHECKS++))
fi
((TOTAL_CHECKS++))

# Summary
echo_header "Setup Summary"

if [[ $FAILED_CHECKS -eq 0 ]]; then
    echo_success "All checks passed! ($TOTAL_CHECKS/$TOTAL_CHECKS)"
    echo -e "\n${GREEN}Your release environment is ready!${NC}"
    
    if [[ "$CHECK_ONLY" == false ]]; then
        echo -e "\nNext steps:"
        echo "1. Review and fill in .env file if needed"
        echo "2. Test a dry-run release: ./scripts/test-release-process.sh"
        echo "3. Run the actual release: ./scripts/release-all.sh"
    fi
else
    echo_error "$FAILED_CHECKS/$TOTAL_CHECKS checks failed"
    echo -e "\n${RED}Please fix the issues above before attempting a release.${NC}"
    
    echo -e "\nQuick fixes:"
    echo "- Missing tools: Install using the provided commands"
    echo "- Missing tokens: Visit the provided URLs to generate tokens"
    echo "- Git config: Run the suggested git config commands"
    
    exit 1
fi