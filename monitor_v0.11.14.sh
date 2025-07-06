#!/bin/bash
# Monitor v0.11.14 - The One That Should Finally Work™

echo "🎯 Monitoring KindlyGuard v0.11.14 Release"
echo "========================================="
echo ""
echo "After fixing:"
echo "  ❌ v0.11.3 - Workspace issues"
echo "  ❌ v0.11.4 - More workspace issues"
echo "  ❌ v0.11.5 - Even more workspace issues"
echo "  ❌ v0.11.6 - Compilation warnings"
echo "  ❌ v0.11.7 - More warnings"
echo "  ❌ v0.11.8 - Cross-compilation"
echo "  ❌ v0.11.9 - Cross-compilation again"
echo "  ❌ v0.11.10 - Cross-compilation yet again"
echo "  ❌ v0.11.11 - OpenSSL issues"
echo "  ❌ v0.11.12 - Rustls migration"
echo "  ❌ v0.11.13 - Final rustls fixes"
echo ""
echo "We finally found the real issue:"
echo "  🎯 v0.11.14 - Deprecated GitHub Action!"
echo ""
echo "The fix: Replace actions/create-release@v1 with gh CLI"
echo ""

# Check GitHub Actions
echo "📊 Checking CI status..."
echo "View at: https://github.com/kindly-software-inc/kindly-guard/actions"
echo ""

# Function to check workflow status with color
check_status() {
    echo -n "Checking build status... "
    
    # Get latest workflow run
    run_status=$(gh run list --repo kindly-software-inc/kindly-guard --limit 1 --json status,conclusion,name | jq -r '.[0] | "\(.name): \(.status) (\(.conclusion))"')
    
    if [[ $run_status == *"completed"* ]] && [[ $run_status == *"success"* ]]; then
        echo "✅ BUILD SUCCESSFUL!"
        return 0
    elif [[ $run_status == *"in_progress"* ]] || [[ $run_status == *"queued"* ]]; then
        echo "⏳ Build in progress..."
        return 1
    else
        echo "❌ Build status: $run_status"
        return 2
    fi
}

# Main monitoring loop
echo "Starting monitoring (press Ctrl+C to stop)..."
echo ""

attempt=0
while true; do
    attempt=$((attempt + 1))
    echo -n "[Attempt $attempt] "
    
    if check_status; then
        echo ""
        echo "🎉 SUCCESS! The CI is finally working!"
        echo ""
        echo "📦 Check the release at:"
        echo "https://github.com/kindly-software-inc/kindly-guard/releases/tag/v0.11.14"
        echo ""
        echo "🍾 After 11 versions and countless hours, we found that one deprecated action."
        echo "Sometimes the bug is not where you think it is!"
        break
    fi
    
    # Show recent error if any
    if [[ $? -eq 2 ]]; then
        echo "Checking for errors..."
        gh run view --repo kindly-software-inc/kindly-guard --log-failed 2>/dev/null | tail -20
    fi
    
    echo "Waiting 30 seconds before next check..."
    sleep 30
done

echo ""
echo "📝 The Journey's End"
echo "==================="
echo "What we learned:"
echo "1. Always check for deprecated actions"
echo "2. Error messages can be misleading"
echo "3. Sometimes you fix 10 things before finding the 1 real issue"
echo "4. Persistence pays off!"
echo ""
echo "Total versions to fix one deprecated action: 11"
echo "Was it worth it? The builds work now! 🎯"