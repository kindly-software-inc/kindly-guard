#!/bin/bash
# Interactive CI Dashboard for KindlyGuard

clear
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            KindlyGuard CI/CD Dashboard v0.11.9               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if gh is available
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI not installed. Please install with:"
    echo "   brew install gh (macOS) or see https://cli.github.com/"
    exit 1
fi

# Function to format status with color codes
format_status() {
    case $1 in
        "completed")
            if [ "$2" = "success" ]; then
                echo "✅ Success"
            elif [ "$2" = "failure" ]; then
                echo "❌ Failed"
            else
                echo "⚠️  $2"
            fi
            ;;
        "in_progress")
            echo "🔄 Running"
            ;;
        "queued")
            echo "⏳ Queued"
            ;;
        *)
            echo "❓ $1"
            ;;
    esac
}

# Get v0.11.9 workflows
echo "📊 v0.11.9 Workflow Status:"
echo "─────────────────────────────────────────────────────────────────"

# Get detailed status for each workflow type
for workflow in "CI" "Security" "Release" "Parallel CI/CD"; do
    echo -n "  $workflow: "
    
    # Get the latest run for this workflow on v0.11.9
    RUN_INFO=$(gh run list --workflow "$workflow.yml" --limit 20 --json status,conclusion,databaseId,createdAt,headBranch 2>/dev/null | jq -r '.[] | select(.headBranch == "v0.11.9") | "\(.status)|\(.conclusion // "pending")|\(.databaseId)|\(.createdAt)"' 2>/dev/null | head -1)
    
    if [ -z "$RUN_INFO" ] || [ "$RUN_INFO" = "null" ]; then
        echo "No runs found"
    else
        IFS='|' read -r STATUS CONCLUSION RUN_ID CREATED_AT <<< "$RUN_INFO"
        FORMATTED_STATUS=$(format_status "$STATUS" "$CONCLUSION")
        echo "$FORMATTED_STATUS (Run #$RUN_ID)"
    fi
done

echo ""
echo "📈 Build Progress:"
echo "─────────────────────────────────────────────────────────────────"

# Get all v0.11.9 runs with timing
RUNS=$(gh run list --limit 30 --json name,status,conclusion,createdAt,updatedAt,headBranch | jq -r '.[] | select(.headBranch == "v0.11.9") | "\(.name)|\(.status)|\(.conclusion // "pending")|\(.createdAt)|\(.updatedAt)"')

if [ ! -z "$RUNS" ]; then
    echo "$RUNS" | while IFS='|' read -r NAME STATUS CONCLUSION CREATED UPDATED; do
        # Calculate duration if completed
        if [ "$STATUS" = "completed" ]; then
            START_SEC=$(date -d "$CREATED" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$CREATED" +%s 2>/dev/null)
            END_SEC=$(date -d "$UPDATED" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$UPDATED" +%s 2>/dev/null)
            if [ ! -z "$START_SEC" ] && [ ! -z "$END_SEC" ]; then
                DURATION=$(( (END_SEC - START_SEC) / 60 ))
                echo "  $(format_status "$STATUS" "$CONCLUSION") $NAME (${DURATION}m)"
            else
                echo "  $(format_status "$STATUS" "$CONCLUSION") $NAME"
            fi
        else
            echo "  $(format_status "$STATUS" "$CONCLUSION") $NAME"
        fi
    done | head -8
else
    echo "  No v0.11.9 builds found"
fi

echo ""
echo "🔗 Quick Links:"
echo "─────────────────────────────────────────────────────────────────"
echo "  Main CI: https://github.com/kindly-software-inc/kindly-guard/actions"
echo "  v0.11.9: https://github.com/kindly-software-inc/kindly-guard/tree/v0.11.9"

# Get latest run URL
LATEST_URL=$(gh run list --limit 20 --json url,headBranch --jq '.[] | select(.headBranch == "v0.11.9") | .url' 2>/dev/null | head -1)
if [ ! -z "$LATEST_URL" ] && [ "$LATEST_URL" != "null" ]; then
    echo "  Latest: $LATEST_URL"
fi

echo ""
echo "💡 Commands:"
echo "─────────────────────────────────────────────────────────────────"
echo "  Watch live:     gh run watch"
echo "  View logs:      gh run view [run-id]"
echo "  Re-run failed:  gh run rerun [run-id]"
echo "  Auto-refresh:   watch -n 30 ./ci_dashboard.sh"

echo ""
echo "Last updated: $(date '+%Y-%m-%d %H:%M:%S')"