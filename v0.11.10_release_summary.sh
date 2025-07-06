#!/bin/bash
# v0.11.10 Release Summary

echo "=== KindlyGuard v0.11.10 Release Summary ==="
echo "Time: $(date)"
echo ""

# Get the latest release workflow run
RELEASE_RUN=$(gh run list --workflow=release.yml --limit 1 --json databaseId,conclusion,status,headCommit --jq '.[0]')

if [ ! -z "$RELEASE_RUN" ]; then
    RUN_ID=$(echo "$RELEASE_RUN" | jq -r '.databaseId')
    STATUS=$(echo "$RELEASE_RUN" | jq -r '.status')
    CONCLUSION=$(echo "$RELEASE_RUN" | jq -r '.conclusion // "pending"')
    COMMIT_MSG=$(echo "$RELEASE_RUN" | jq -r '.headCommit.message' | head -1)
    
    echo "📦 Release Status: $STATUS ($CONCLUSION)"
    echo "💬 Commit: $COMMIT_MSG"
    echo ""
    
    # Get build job statuses
    echo "🔨 Build Jobs:"
    gh api repos/kindly-software-inc/kindly-guard/actions/runs/$RUN_ID/jobs --jq '.jobs[] | select(.name | startswith("build")) | "  - \(.name): \(.status) (\(.conclusion // "running"))"' 2>/dev/null || echo "  ⏳ Waiting for job data..."
    
    echo ""
    echo "📊 Summary:"
    if [ "$STATUS" == "completed" ] && [ "$CONCLUSION" == "success" ]; then
        echo "✅ Release successful! Check https://github.com/kindly-software-inc/kindly-guard/releases"
    elif [ "$STATUS" == "completed" ] && [ "$CONCLUSION" != "success" ]; then
        echo "❌ Release failed. Check logs at: https://github.com/kindly-software-inc/kindly-guard/actions/runs/$RUN_ID"
    else
        echo "⏳ Release in progress..."
    fi
else
    echo "❌ No release workflow found"
fi

echo ""
echo "🔗 Quick Links:"
echo "- Actions: https://github.com/kindly-software-inc/kindly-guard/actions"
echo "- Latest Release: https://github.com/kindly-software-inc/kindly-guard/releases/latest"