#!/bin/bash

echo "Testing Advanced Mode with Purple Theme..."
echo "========================================"

# Enable advanced mode first
echo -e "\n1. Enabling advanced mode:"
/home/samuel/kindly-guard/kindlyguard advancedsecurity enable

echo -e "\n2. Status with advanced mode (should show purple):"
/home/samuel/kindly-guard/kindlyguard status

echo -e "\n3. Minimal format with advanced mode:"
/home/samuel/kindly-guard/kindlyguard status --format minimal

echo -e "\n4. Advanced security status:"
/home/samuel/kindly-guard/kindlyguard advancedsecurity status

echo -e "\n5. Info about advanced features:"
/home/samuel/kindly-guard/kindlyguard info advanced

echo -e "\n6. Scan with threat (unicode bidirectional override):"
echo -e "Testing text with hidden threat: Hello\u202eWorld" > /tmp/test_threat.txt
/home/samuel/kindly-guard/kindlyguard scan /tmp/test_threat.txt

echo -e "\n7. Dashboard format:"
/home/samuel/kindly-guard/kindlyguard status --format dashboard

echo -e "\n8. Check status file:"
if [ -f /tmp/kindlyguard-status.json ]; then
    echo "Status file exists. Contents:"
    cat /tmp/kindlyguard-status.json | jq '.' 2>/dev/null || cat /tmp/kindlyguard-status.json
else
    echo "Status file not found at /tmp/kindlyguard-status.json"
fi

echo -e "\nAll tests completed!"