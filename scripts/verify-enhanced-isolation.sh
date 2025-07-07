#!/bin/bash
# Verify that enhanced/proprietary files are properly gitignored

set -euo pipefail

echo "🔍 Verifying enhanced feature isolation..."
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}❌ Not in a git repository${NC}"
    exit 1
fi

# Patterns to check (from .gitignore)
PATTERNS=(
    "*_proprietary.rs"
    "*_enhanced_impl.rs"
    "*_pro.rs"
    "*_enterprise.rs"
    "*_patent.rs"
    "*_atomic_impl.rs"
    "*_PROPRIETARY.md"
    "*_PATENT_DETAILS.md"
    "*_ENHANCED_IMPL.md"
    "*_CONFIDENTIAL.md"
)

echo "📋 Checking gitignore patterns..."
echo

# Find all files matching the patterns
FOUND_FILES=()
for pattern in "${PATTERNS[@]}"; do
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            FOUND_FILES+=("$file")
        fi
    done < <(find . -name "$pattern" -type f -print0 2>/dev/null || true)
done

if [ ${#FOUND_FILES[@]} -eq 0 ]; then
    echo -e "${YELLOW}⚠️  No enhanced/proprietary files found${NC}"
    echo "   This is expected if you haven't created any yet."
    echo
else
    echo "📁 Found ${#FOUND_FILES[@]} enhanced/proprietary files:"
    for file in "${FOUND_FILES[@]}"; do
        echo "   - $file"
    done
    echo

    echo "🔒 Checking git status..."
    echo

    # Check if any of these files would be committed
    STAGED_FILES=()
    TRACKED_FILES=()
    
    for file in "${FOUND_FILES[@]}"; do
        # Check if file is staged
        if git ls-files --cached --others --exclude-standard | grep -q "^${file#./}$"; then
            STAGED_FILES+=("$file")
        fi
        
        # Check if file is tracked
        if git ls-files | grep -q "^${file#./}$"; then
            TRACKED_FILES+=("$file")
        fi
    done

    # Report results
    if [ ${#STAGED_FILES[@]} -gt 0 ]; then
        echo -e "${RED}❌ CRITICAL: Found staged proprietary files!${NC}"
        echo "   These files are staged for commit:"
        for file in "${STAGED_FILES[@]}"; do
            echo -e "   ${RED}- $file${NC}"
        done
        echo
        echo "   Run 'git reset HEAD <file>' to unstage them"
        exit 1
    fi

    if [ ${#TRACKED_FILES[@]} -gt 0 ]; then
        echo -e "${RED}❌ ERROR: Found tracked proprietary files!${NC}"
        echo "   These files are already in the repository:"
        for file in "${TRACKED_FILES[@]}"; do
            echo -e "   ${RED}- $file${NC}"
        done
        echo
        echo "   These need to be removed from git history!"
        exit 1
    fi

    # Check if files are properly ignored
    IGNORED_COUNT=0
    for file in "${FOUND_FILES[@]}"; do
        if git check-ignore "$file" > /dev/null 2>&1; then
            ((IGNORED_COUNT++))
        fi
    done

    if [ $IGNORED_COUNT -eq ${#FOUND_FILES[@]} ]; then
        echo -e "${GREEN}✅ All enhanced/proprietary files are properly gitignored${NC}"
        echo "   Total files checked: ${#FOUND_FILES[@]}"
        echo "   All files ignored: $IGNORED_COUNT"
    else
        echo -e "${RED}❌ Some files are not properly gitignored!${NC}"
        echo "   Check your .gitignore patterns"
        exit 1
    fi
fi

echo
echo "🛡️  Testing pre-commit hook integration..."
echo

# Check if pre-commit is installed
if command -v pre-commit &> /dev/null; then
    echo -e "${GREEN}✅ pre-commit is installed${NC}"
    
    # Check if there's a pre-commit config
    if [ -f ".pre-commit-config.yaml" ]; then
        echo -e "${GREEN}✅ pre-commit configuration found${NC}"
        
        # Look for company terms hook
        if grep -q "check.*proprietary\|check.*company.*terms\|check.*confidential" .pre-commit-config.yaml 2>/dev/null; then
            echo -e "${GREEN}✅ Company terms checking hook detected${NC}"
        else
            echo -e "${YELLOW}⚠️  No explicit company terms hook found${NC}"
            echo "   Make sure your pre-commit hooks check for proprietary terms"
        fi
    else
        echo -e "${YELLOW}⚠️  No .pre-commit-config.yaml found${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  pre-commit not installed${NC}"
    echo "   Install with: pip install pre-commit"
fi

echo
echo "📊 Summary of enhanced feature patterns in .gitignore:"
echo
grep -E "^\*.*proprietary|^\*.*enhanced|^\*.*pro\.|^\*.*enterprise|^\*.*patent" .gitignore | head -20 || echo "No patterns found!"

echo
echo -e "${GREEN}✅ Enhanced feature isolation verification complete!${NC}"
echo
echo "Best practices reminder:"
echo "  • Keep enhanced implementations in same directories as standard ones"
echo "  • Use consistent naming patterns (*_proprietary.rs, *_pro.rs, etc.)"
echo "  • Always run this script before committing"
echo "  • Document interfaces in committed files, implementations in gitignored files"