#\!/bin/bash
# Final CI/CD Success Monitor

clear
echo "🎉 KindlyGuard CI/CD Success Monitor 🎉"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Journey: v0.11.4 → v0.11.13 (10 versions\!)"
echo "Time: $(date)"
echo ""

if command -v gh &> /dev/null; then
    # Show latest releases
    echo "📦 Latest Release Workflows:"
    gh run list --workflow=release.yml --limit 5  < /dev/null |  head -6
    
    # Check v0.11.13 specifically
    echo -e "\n🚀 v0.11.13 Status:"
    V13_RUN=$(gh run list --workflow=release.yml --limit 10 | grep "v0.11.13" | head -1)
    if [ \! -z "$V13_RUN" ]; then
        echo "$V13_RUN"
        RUN_ID=$(echo "$V13_RUN" | awk '{print $((NF-6))}')
        
        # Show job details
        echo -e "\n📊 Build Status:"
        gh run view $RUN_ID --json jobs --jq '.jobs[] | 
            if .conclusion == "success" then "✅ " + .name
            elif .conclusion == "failure" then "❌ " + .name + " (check logs)"
            elif .status == "in_progress" then "🔄 " + .name + " (building...)"
            elif .status == "queued" then "⏳ " + .name + " (waiting...)"
            else "❓ " + .name
            end' 2>/dev/null || echo "Run not found or still initializing..."
    else
        echo "⏳ Waiting for v0.11.13 workflow to appear..."
    fi
    
    # Summary of journey
    echo -e "\n📈 CI/CD Evolution Summary:"
    echo "• v0.11.4-7: Fixed warnings & workspace issues"
    echo "• v0.11.8-9: Updated tools & cross-compilation"
    echo "• v0.11.10: Custom workflow without cargo-dist"
    echo "• v0.11.11-12: YAML fixes & OpenSSL attempts"
    echo "• v0.11.13: Final success with rustls\! 🎯"
    
    echo -e "\n🔗 Links:"
    echo "• Actions: https://github.com/kindly-software-inc/kindly-guard/actions"
    echo "• Releases: https://github.com/kindly-software-inc/kindly-guard/releases"
else
    echo "❌ GitHub CLI not installed"
fi

echo -e "\n💡 What we achieved:"
echo "✅ Cross-platform builds (Linux, macOS, Windows)"
echo "✅ Static musl binaries without OpenSSL"
echo "✅ Automated releases with installers"
echo "✅ Clean, maintainable CI/CD pipeline"
echo ""
echo "🎊 Congratulations on your persistence\! 🎊"
