#!/bin/bash
# Script to check CI status for KindlyGuard

echo "=== Checking CI Status for KindlyGuard ==="

if command -v gh &> /dev/null; then
    echo "Using GitHub CLI to check status..."
    
    # Get latest runs
    echo -e "\n=== Latest workflow runs ==="
    gh run list --limit 5
    
    # Get v0.11.9 specific runs
    echo -e "\n=== v0.11.9 workflow runs ==="
    gh run list --limit 10 | grep -E "(v0.11.9|bump version to 0.11.9)" || echo "No v0.11.9 runs found yet"
    
    # Get any failed jobs
    LATEST_RUN=$(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')
    if [ ! -z "$LATEST_RUN" ]; then
        echo -e "\n=== Latest run #$LATEST_RUN status ==="
        gh run view $LATEST_RUN --json jobs --jq '.jobs[] | select(.conclusion != "success" and .conclusion != null) | {name: .name, conclusion: .conclusion}'
    fi
else
    echo "GitHub CLI not available. Install with: brew install gh (macOS) or see https://cli.github.com/"
    echo "Check manually at: https://github.com/kindly-software-inc/kindly-guard/actions"
fi