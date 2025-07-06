#!/bin/bash
# Monitor v0.11.14 CI/CD status

echo "Monitoring v0.11.14 CI/CD runs..."
echo "=================================="

while true; do
    clear
    echo "KindlyGuard v0.11.14 CI/CD Status"
    echo "=================================="
    echo "Time: $(date)"
    echo ""
    
    # Get CI run status
    echo "CI Runs:"
    gh run list --limit 10 | grep -E "(v0.11.14|160ab5c)" | head -10
    
    echo ""
    echo "Detailed Status:"
    # Get the latest CI run ID
    CI_RUN=$(gh run list --workflow=CI --limit 10 | grep v0.11.14 | head -1 | awk '{print $(NF-2)}')
    if [ ! -z "$CI_RUN" ]; then
        echo "CI Run ID: $CI_RUN"
        gh run view $CI_RUN 2>&1 | grep -E "(^✓|^X|Test|Build|Check)" | head -20
    fi
    
    echo ""
    echo "Press Ctrl+C to exit"
    echo "Refreshing in 30 seconds..."
    sleep 30
done