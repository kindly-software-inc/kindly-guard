#\!/bin/bash
# Watch v0.11.13 build progress

echo "🔍 Monitoring v0.11.13 Build Progress..."
echo "Press Ctrl+C to stop"
echo ""

while true; do
    clear
    echo "=== KindlyGuard v0.11.13 Build Monitor ==="
    echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # Get run status
    RUN_STATUS=$(gh run list --workflow=release.yml --limit 5  < /dev/null |  grep "v0.11.13" | head -1)
    if [ \! -z "$RUN_STATUS" ]; then
        echo "Overall Status:"
        echo "$RUN_STATUS"
        echo ""
        
        # Extract run ID
        RUN_ID=$(echo "$RUN_STATUS" | awk '{print $((NF-6))}')
        
        # Get job details
        echo "Job Details:"
        gh run view $RUN_ID --json jobs --jq '.jobs[] | 
            if .conclusion == "success" then "✅ " + .name
            elif .conclusion == "failure" then "❌ " + .name
            elif .status == "in_progress" then "🔄 " + .name + " (running...)"
            elif .status == "queued" then "⏳ " + .name + " (queued)"
            else "❓ " + .name + " (" + (.status // "unknown") + ")"
            end' 2>/dev/null || echo "Loading job details..."
        
        # Check if completed
        if echo "$RUN_STATUS" | grep -q "completed"; then
            echo -e "\n=== Build Complete\! ==="
            if echo "$RUN_STATUS" | grep -q "success"; then
                echo "✅ SUCCESS\! All builds completed successfully\!"
                echo ""
                echo "Next steps:"
                echo "1. Check releases: https://github.com/kindly-software-inc/kindly-guard/releases"
                echo "2. Verify binaries are uploaded"
                echo "3. Test the installers"
            else
                echo "❌ Build failed. Check the logs for details."
            fi
            break
        fi
    else
        echo "⏳ Waiting for v0.11.13 workflow..."
    fi
    
    echo -e "\n(Refreshing in 10 seconds...)"
    sleep 10
done
