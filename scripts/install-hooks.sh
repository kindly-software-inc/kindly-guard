#!/usr/bin/env bash
# Install pre-commit hooks for KindlyGuard
# This script sets up security-focused development hooks

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

echo -e "${BLUE}🔒 KindlyGuard Pre-Commit Hook Installation${NC}"
echo -e "${BLUE}===========================================${NC}"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}❌ Error: Not in a git repository${NC}"
    exit 1
fi

# Install pre-commit if not already installed
if ! command -v pre-commit &> /dev/null; then
    echo -e "${YELLOW}📦 Installing pre-commit...${NC}"
    
    # Try pip first
    if command -v pip3 &> /dev/null; then
        pip3 install --user pre-commit
    elif command -v pip &> /dev/null; then
        pip install --user pre-commit
    else
        echo -e "${RED}❌ Error: pip not found. Please install Python and pip first.${NC}"
        echo "   On Ubuntu/Debian: sudo apt-get install python3-pip"
        echo "   On macOS: brew install python3"
        exit 1
    fi
fi

# Verify pre-commit is available
if ! command -v pre-commit &> /dev/null; then
    echo -e "${YELLOW}⚠️  pre-commit installed but not in PATH${NC}"
    echo "   Add ~/.local/bin to your PATH:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    exit 1
fi

echo -e "${GREEN}✓ pre-commit is installed${NC}"

# Install the git hook scripts
echo -e "${BLUE}🔧 Installing git hooks...${NC}"
pre-commit install --install-hooks

# Install commit-msg hook for conventional commits
pre-commit install --hook-type commit-msg

# Create .secrets.baseline if it doesn't exist
if [ ! -f .secrets.baseline ]; then
    echo -e "${BLUE}🔐 Creating secrets baseline...${NC}"
    detect-secrets scan --baseline .secrets.baseline || true
fi

# Install additional dependencies
echo -e "${BLUE}📦 Installing additional security tools...${NC}"

# Install cargo-audit if not present
if ! command -v cargo-audit &> /dev/null; then
    echo "   Installing cargo-audit..."
    cargo install cargo-audit
fi

# Install cargo-machete if not present
if ! command -v cargo-machete &> /dev/null; then
    echo "   Installing cargo-machete..."
    cargo install cargo-machete
fi

# Create git hooks directory if it doesn't exist
mkdir -p .git/hooks

# Create a custom pre-push hook for additional security checks
cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
# Additional security checks before push

echo "🔒 Running security checks before push..."

# Run tests
echo "   Running tests..."
cargo test --quiet || {
    echo "❌ Tests failed. Push aborted."
    exit 1
}

# Check for security vulnerabilities
echo "   Checking for vulnerabilities..."
cargo audit || {
    echo "❌ Security vulnerabilities found. Push aborted."
    echo "   Run 'cargo audit fix' to attempt automatic fixes."
    exit 1
}

echo "✅ All security checks passed!"
EOF

chmod +x .git/hooks/pre-push

# Create manual backup hooks
echo -e "${BLUE}📋 Creating manual backup hooks...${NC}"
mkdir -p .git-hooks

# Create manual pre-commit hook
cat > .git-hooks/pre-commit << 'EOF'
#!/bin/bash
# Manual pre-commit checks for KindlyGuard
# Use this if pre-commit framework is not available

set -e

echo "🔒 Running KindlyGuard pre-commit checks..."

# Format check
echo "   Checking formatting..."
cargo fmt -- --check || {
    echo "❌ Format check failed. Run 'cargo fmt' to fix."
    exit 1
}

# Clippy
echo "   Running clippy..."
cargo clippy -- -D warnings || {
    echo "❌ Clippy found issues."
    exit 1
}

# Check for unsafe without SAFETY
echo "   Checking unsafe blocks..."
if grep -r "unsafe\s*{" --include="*.rs" . | grep -v "SAFETY:" | grep -v "target/"; then
    echo "❌ Found unsafe blocks without SAFETY comments"
    exit 1
fi

# Check file sizes
echo "   Checking file sizes..."
for file in $(git diff --cached --name-only); do
    if [ -f "$file" ]; then
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
        if [ "$size" -gt 1000000 ]; then
            echo "❌ File $file is larger than 1MB (size: $size bytes)"
            exit 1
        fi
    fi
done

echo "✅ All checks passed!"
EOF

chmod +x .git-hooks/pre-commit

# Create manual commit-msg hook
cat > .git-hooks/commit-msg << 'EOF'
#!/bin/bash
# Check commit message format

commit_regex='^(feat|fix|docs|style|refactor|perf|test|chore|security)(\(.+\))?: .+'

if ! grep -qE "$commit_regex" "$1"; then
    echo "❌ Invalid commit message format!"
    echo "   Format: <type>(<scope>): <subject>"
    echo "   Types: feat|fix|docs|style|refactor|perf|test|chore|security"
    echo ""
    echo "   Example: feat(scanner): add unicode normalization"
    echo "   Example: security: fix timing attack in auth module"
    exit 1
fi
EOF

chmod +x .git-hooks/commit-msg

# Summary
echo -e "${GREEN}✅ Pre-commit hooks installed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Installed hooks:${NC}"
echo "   • rustfmt - Format consistency"
echo "   • clippy - Security lints"
echo "   • unsafe code check - Documentation requirements"
echo "   • detect-secrets - Prevent credential leaks"
echo "   • large file check - Prevent binary smuggling"
echo "   • conventional commits - Audit trail"
echo "   • cargo audit (pre-push) - Vulnerability scanning"
echo ""
echo -e "${BLUE}🚀 Quick commands:${NC}"
echo "   • Test hooks: pre-commit run --all-files"
echo "   • Skip hooks (emergency): git commit --no-verify"
echo "   • Update hooks: pre-commit autoupdate"
echo "   • Manual hooks: .git-hooks/"
echo ""
echo -e "${YELLOW}⚡ Developer tip:${NC}"
echo "   Hooks run automatically on commit. They're fast and help"
echo "   maintain security standards. If you must skip them, use"
echo "   --no-verify, but document why in your PR."