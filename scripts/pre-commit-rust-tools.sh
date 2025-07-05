#!/usr/bin/env bash
# Pre-commit hook that runs kindly-tools and xtask checks
# This hook ensures code quality using KindlyGuard's own tools

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}🛠️  Running KindlyGuard pre-commit tools...${NC}"

# Check if kindly-tools is built
if [ ! -f "target/release/kindly-tools" ] && [ ! -f "target/debug/kindly-tools" ]; then
    echo -e "${YELLOW}⚠️  kindly-tools not found. Building...${NC}"
    cargo build --package kindly-tools --release
fi

# Check if xtask is built
if [ ! -f "target/release/xtask" ] && [ ! -f "target/debug/xtask" ]; then
    echo -e "${YELLOW}⚠️  xtask not found. Building...${NC}"
    cargo build --package xtask --release
fi

# Determine which binaries to use (prefer release builds)
KINDLY_TOOLS=""
XTASK=""

if [ -f "target/release/kindly-tools" ]; then
    KINDLY_TOOLS="target/release/kindly-tools"
elif [ -f "target/debug/kindly-tools" ]; then
    KINDLY_TOOLS="target/debug/kindly-tools"
fi

if [ -f "target/release/xtask" ]; then
    XTASK="target/release/xtask"
elif [ -f "target/debug/xtask" ]; then
    XTASK="target/debug/xtask"
fi

# Track if any checks fail
FAILED=0

# Run kindly-tools checks
if [ -n "$KINDLY_TOOLS" ]; then
    echo -e "${BLUE}Running kindly-tools checks...${NC}"
    
    # Run security scan on staged files
    echo "   • Security scan..."
    if ! $KINDLY_TOOLS scan --staged; then
        echo -e "${RED}❌ Security issues detected${NC}"
        FAILED=1
    fi
    
    # Run code quality checks
    echo "   • Code quality..."
    if ! $KINDLY_TOOLS check --quality; then
        echo -e "${RED}❌ Code quality issues found${NC}"
        FAILED=1
    fi
else
    echo -e "${YELLOW}⚠️  kindly-tools not available, skipping its checks${NC}"
fi

# Run xtask checks
if [ -n "$XTASK" ]; then
    echo -e "${BLUE}Running xtask checks...${NC}"
    
    # Run doctor to check project health
    echo "   • Project health check..."
    if ! $XTASK doctor --quiet; then
        echo -e "${RED}❌ Project health issues found${NC}"
        FAILED=1
    fi
    
    # Check for flaky tests if running tests
    if [ -f ".flaky-tests.json" ]; then
        echo "   • Checking for flaky tests..."
        if ! $XTASK flaky check; then
            echo -e "${YELLOW}⚠️  Flaky tests detected${NC}"
        fi
    fi
    
    # Validate configuration
    echo "   • Configuration validation..."
    if ! $XTASK validate-config; then
        echo -e "${RED}❌ Configuration issues found${NC}"
        FAILED=1
    fi
else
    echo -e "${YELLOW}⚠️  xtask not available, skipping its checks${NC}"
fi

# Check for sccache usage
if command -v sccache &> /dev/null; then
    echo -e "${GREEN}✓ sccache is available${NC}"
    
    # Show sccache stats
    echo -e "${BLUE}sccache statistics:${NC}"
    sccache --show-stats | grep -E "(Compile requests|Cache hits|Cache misses)" | sed 's/^/   /'
else
    echo -e "${YELLOW}⚠️  sccache not found. Consider installing it for faster builds:${NC}"
    echo "   cargo install sccache"
    echo "   export RUSTC_WRAPPER=sccache"
fi

# Final result
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All KindlyGuard tool checks passed!${NC}"
else
    echo -e "${RED}❌ Some checks failed. Please fix the issues before committing.${NC}"
    exit 1
fi