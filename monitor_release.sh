#!/bin/bash
# Monitor v0.11.9 release progress

echo "🚀 Monitoring KindlyGuard v0.11.9 Release"
echo "========================================="
echo ""

# Function to check workflow status
check_workflow() {
    local workflow=$1
    local status=$(gh run list --workflow "$workflow.yml" --limit 20 --json status,conclusion,headBranch --jq '.[] | select(.headBranch == "v0.11.9") | "\(.status):\(.conclusion // "pending")"' 2>/dev/null | head -1)
    
    if [ -z "$status" ] || [ "$status" = "null" ]; then
        echo "  ⏸️  $workflow: Not started"
    else
        IFS=':' read -r STATE CONCLUSION <<< "$status"
        case "$STATE:$CONCLUSION" in
            "completed:success")
                echo "  ✅ $workflow: Success"
                ;;
            "completed:failure")
                echo "  ❌ $workflow: Failed"
                ;;
            "in_progress:pending")
                echo "  🔄 $workflow: Running..."
                ;;
            "queued:pending")
                echo "  ⏳ $workflow: Queued"
                ;;
            *)
                echo "  ❓ $workflow: $STATE ($CONCLUSION)"
                ;;
        esac
    fi
}

# Check each workflow
echo "📋 Workflow Status:"
check_workflow "CI"
check_workflow "Security"
check_workflow "Release"
check_workflow "Parallel CI/CD"

echo ""
echo "📦 Release Artifacts:"
echo "─────────────────────"

# Check if release exists
RELEASE_INFO=$(gh release view v0.11.9 --json tagName,isDraft,isPrerelease,publishedAt 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "  ✅ Release v0.11.9 exists"
    IS_DRAFT=$(echo "$RELEASE_INFO" | jq -r '.isDraft')
    IS_PRERELEASE=$(echo "$RELEASE_INFO" | jq -r '.isPrerelease')
    PUBLISHED=$(echo "$RELEASE_INFO" | jq -r '.publishedAt')
    
    [ "$IS_DRAFT" = "true" ] && echo "  📝 Status: Draft"
    [ "$IS_PRERELEASE" = "true" ] && echo "  🔬 Status: Pre-release"
    [ ! -z "$PUBLISHED" ] && [ "$PUBLISHED" != "null" ] && echo "  📅 Published: $PUBLISHED"
    
    # List assets
    echo ""
    echo "  📎 Assets:"
    gh release view v0.11.9 --json assets --jq '.assets[] | "    - \(.name) (\(.size) bytes)"' 2>/dev/null || echo "    No assets yet"
else
    echo "  ⏳ Release not created yet"
fi

echo ""
echo "🔄 Auto-refresh every 30 seconds with:"
echo "   watch -n 30 ./monitor_release.sh"
echo ""
echo "📊 Full dashboard:"
echo "   ./ci_dashboard.sh"