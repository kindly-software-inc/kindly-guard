#!/bin/bash

# Install commit hooks for KindlyGuard project
# Validates conventional commit format

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$PROJECT_ROOT/.git/hooks"

# Color codes
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

echo "Installing KindlyGuard commit hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Create commit-msg hook
cat > "$HOOKS_DIR/commit-msg" << 'EOF'
#!/bin/bash

# KindlyGuard commit message validation hook
# Ensures commits follow conventional commit format

# Color codes
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Read commit message
commit_regex='^(security|vuln|cve|audit|feat|fix|perf|docs|test|refactor|build|ci|deps|chore)(\([a-zA-Z0-9-]+\))?!?: .{1,72}$'
merge_regex='^Merge '

# Get the commit message
msg=$(cat "$1")
first_line=$(echo "$msg" | head -n1)

# Allow merge commits
if [[ "$first_line" =~ $merge_regex ]]; then
    exit 0
fi

# Validate format
if ! [[ "$first_line" =~ $commit_regex ]]; then
    echo -e "${RED}ERROR: Commit message does not follow conventional format${NC}" >&2
    echo "" >&2
    echo "Expected format: <type>(<scope>): <subject>" >&2
    echo "" >&2
    echo "Valid types:" >&2
    echo "  Security: security, vuln, cve, audit" >&2
    echo "  Standard: feat, fix, perf, docs, test, refactor, build, ci, deps, chore" >&2
    echo "" >&2
    echo "Examples:" >&2
    echo "  security: fix timing attack in token validation" >&2
    echo "  feat(scanner): add LDAP injection detection" >&2
    echo "  fix(unicode): correct homograph detection" >&2
    echo "" >&2
    echo "Your message: $first_line" >&2
    echo "" >&2
    echo "See CONTRIBUTING.md for details" >&2
    exit 1
fi

# Check subject line length
subject_length=${#first_line}
if [[ $subject_length -gt 72 ]]; then
    echo -e "${YELLOW}WARNING: Subject line is $subject_length characters (recommended: <72)${NC}" >&2
fi

exit 0
EOF

# Make hook executable
chmod +x "$HOOKS_DIR/commit-msg"

echo -e "${GREEN}✓${NC} Commit message validation hook installed"

# Create prepare-commit-msg hook to show template
cat > "$HOOKS_DIR/prepare-commit-msg" << 'EOF'
#!/bin/bash

# Show helpful commit format reminder
# This hook is bypassed when using -m flag

COMMIT_MSG_FILE=$1
COMMIT_SOURCE=$2

# Only show for interactive commits (not -m flag)
if [ -z "$COMMIT_SOURCE" ]; then
    # Check if commit template is configured
    template=$(git config --get commit.template)
    if [ -z "$template" ]; then
        # Add a simple reminder if no template configured
        cat >> "$COMMIT_MSG_FILE" << 'TEMPLATE'

# === COMMIT FORMAT ===
# <type>(<scope>): <subject>
#
# Security types: security, vuln, cve, audit
# Standard types: feat, fix, perf, docs, test, refactor, build, ci, deps, chore
# 
# Scopes: scanner, unicode, injection, xss, server, protocol, shield, storage, etc.
#
# Examples:
# security: fix timing attack vulnerability
# feat(scanner): add SQL injection detection
# fix(unicode): handle zero-width characters
TEMPLATE
    fi
fi
EOF

# Make hook executable  
chmod +x "$HOOKS_DIR/prepare-commit-msg"

echo -e "${GREEN}✓${NC} Commit template reminder hook installed"

# Summary
echo ""
echo "Commit hooks installed successfully!"
echo ""
echo "The hooks will:"
echo "  • Validate commit message format"
echo "  • Show format reminders for interactive commits"
echo "  • Enforce conventional commit standards"
echo ""
echo "To bypass hooks in emergency: git commit --no-verify"
echo "To set up commit template: ./scripts/setup-commit-template.sh"