#\!/bin/bash
# Monitor v0.11.10 release progress

echo "=== KindlyGuard v0.11.10 Release Monitor ==="
echo "Time: $(date)"
echo ""

if command -v gh &> /dev/null; then
    # Get v0.11.10 specific runs
    echo "🔍 Checking v0.11.10 workflows..."
    gh run list --limit 20  < /dev/null |  grep -E "(v0\.11\.10|0\.11\.10)" || echo "⏳ No v0.11.10 runs found yet"
    
    # Get latest release workflow
    echo -e "\n📦 Latest Release Workflow:"
    gh run list --workflow=release.yml --limit 1
    
    # Check for any errors in recent runs
    LATEST_RELEASE=$(gh run list --workflow=release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
    if [ \! -z "$LATEST_RELEASE" ]; then
        echo -e "\n📊 Release Run #$LATEST_RELEASE Details:"
        gh run view $LATEST_RELEASE
    fi
    
    echo -e "\n🔗 Direct Links:"
    echo "Actions: https://github.com/kindly-software-inc/kindly-guard/actions"
    echo "Releases: https://github.com/kindly-software-inc/kindly-guard/releases"
else
    echo "❌ GitHub CLI not installed"
fi

echo -e "\n💡 Tips:"
echo "- Run 'watch -n 30 ./monitor_v0.11.10.sh' for auto-refresh"
echo "- Check https://github.com/kindly-software-inc/kindly-guard/actions for details"
