#!/bin/bash
# Script to check CI status for KindlyGuard

echo "=== Checking CI Status for KindlyGuard ==="
echo "Current time: $(date)"

if command -v gh &> /dev/null; then
    echo "Using GitHub CLI to check status..."
    
    # Get latest runs
    echo -e "\n=== Latest workflow runs ==="
    gh run list --limit 5
    
    # Get v0.11.9 specific runs
    echo -e "\n=== v0.11.9 workflow runs ==="
    gh run list --limit 10 | grep -E "(v0.11.9|bump version to 0.11.9)" || echo "No v0.11.9 runs found yet"
    
    # Get latest run status
    LATEST_RUN=$(gh run list --limit 1 --json databaseId,status,conclusion --jq '.[0] | "\(.databaseId) - Status: \(.status), Conclusion: \(.conclusion // "pending")"')
    if [ ! -z "$LATEST_RUN" ]; then
        echo -e "\n=== Latest run status ==="
        echo "$LATEST_RUN"
    fi
    
    # Show workflow run URLs for manual check
    echo -e "\n=== Recent workflow URLs ==="
    gh run list --limit 3 --json url,name,headBranch --jq '.[] | "\(.name) (\(.headBranch)): \(.url)"'
    
    # Check if any workflows are failing
    echo -e "\n=== Failed workflows (if any) ==="
    gh run list --status failure --limit 5 || echo "No recent failures"
    
    # Watch for completion (optional)
    echo -e "\n=== Monitoring tip ==="
    echo "To watch CI in real-time, run:"
    echo "  watch -n 30 ./check_ci_status.sh"
    echo ""
    echo "Or check specific run:"
    echo "  gh run watch"
else
    echo "GitHub CLI not available. Install with: brew install gh (macOS) or see https://cli.github.com/"
    echo "Check manually at: https://github.com/kindly-software-inc/kindly-guard/actions"
fi