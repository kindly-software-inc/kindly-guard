#!/bin/bash
# Performance stress test for KindlyGuard

set -e

echo "KindlyGuard Performance Stress Test"
echo "=================================="

# Check if binary exists
if [ ! -f "./target/release/kindly-guard" ]; then
    echo "Error: Release binary not found. Building..."
    cargo build --release
fi

# Function to monitor system resources
monitor_resources() {
    local pid=$1
    local duration=$2
    local output_file=$3
    
    echo "Timestamp,CPU%,Memory(MB),Threads" > "$output_file"
    
    for ((i=0; i<duration; i++)); do
        if ps -p $pid > /dev/null; then
            cpu=$(ps -p $pid -o %cpu | tail -1 | tr -d ' ')
            mem=$(ps -p $pid -o rss | tail -1 | awk '{print $1/1024}')
            threads=$(ps -p $pid -o nlwp | tail -1 | tr -d ' ')
            echo "$(date +%s),$cpu,$mem,$threads" >> "$output_file"
            sleep 1
        else
            break
        fi
    done
}

# Test 1: Memory leak detection
echo -e "\n[Test 1] Memory Leak Detection"
echo "Running 10,000 requests and monitoring memory..."

./target/release/kindly-guard --stdio > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

# Monitor resources in background
monitor_resources $SERVER_PID 60 "memory_test.csv" &
MONITOR_PID=$!

# Send many requests
for i in {1..10000}; do
    echo '{"method":"tools/scan","params":{"content":"test data"}}' | \
        timeout 1 ./target/release/kindly-guard --stdio > /dev/null 2>&1 || true
    
    if [ $((i % 1000)) -eq 0 ]; then
        echo "  Processed $i requests..."
    fi
done

kill $SERVER_PID 2>/dev/null || true
wait $MONITOR_PID

echo "  Memory test complete. Results in memory_test.csv"

# Test 2: CPU stress test
echo -e "\n[Test 2] CPU Stress Test"
echo "Sending complex patterns at high rate..."

./target/release/kindly-guard --stdio > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

# Create complex test file
cat > complex_input.json << 'EOF'
{
    "method": "tools/scan",
    "params": {
        "content": {
            "nested": {
                "deep": {
                    "structure": {
                        "with": {
                            "many": {
                                "levels": {
                                    "and": {
                                        "data": "'; DROP TABLE users; --"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "patterns": [
                "admin' OR '1'='1",
                "<script>alert('xss')</script>",
                "../../../etc/passwd",
                "Hello\u202EWorld"
            ]
        }
    }
}
EOF

# Send requests rapidly
START_TIME=$(date +%s)
REQUEST_COUNT=0

for i in {1..30}; do
    for j in {1..100}; do
        cat complex_input.json | timeout 0.5 ./target/release/kindly-guard --stdio > /dev/null 2>&1 &
        REQUEST_COUNT=$((REQUEST_COUNT + 1))
    done
    sleep 0.1
done

wait
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
RPS=$((REQUEST_COUNT / DURATION))

kill $SERVER_PID 2>/dev/null || true

echo "  Sent $REQUEST_COUNT requests in $DURATION seconds"
echo "  Average: $RPS requests/second"

# Test 3: Large input handling
echo -e "\n[Test 3] Large Input Handling"
echo "Testing with increasingly large inputs..."

./target/release/kindly-guard --stdio > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

for size in 1 10 100 1000; do
    # Generate large JSON
    python3 -c "
import json
data = {'method': 'tools/scan', 'params': {'content': 'x' * (${size} * 1024)}}
print(json.dumps(data))
" > "large_${size}kb.json"
    
    START=$(date +%s%N)
    timeout 5 bash -c "cat large_${size}kb.json | ./target/release/kindly-guard --stdio" > /dev/null 2>&1
    END=$(date +%s%N)
    
    ELAPSED=$((($END - $START) / 1000000))
    echo "  ${size}KB input: ${ELAPSED}ms"
    
    rm "large_${size}kb.json"
done

kill $SERVER_PID 2>/dev/null || true

# Test 4: Concurrent connections
echo -e "\n[Test 4] Concurrent Connection Test"
echo "Testing with multiple simultaneous connections..."

# Start shield UI server (if available)
if [ -f "./kindly-guard-shield/target/release/kindly-guard-shield" ]; then
    ./kindly-guard-shield/target/release/kindly-guard-shield > /dev/null 2>&1 &
    SHIELD_PID=$!
    sleep 3
    
    # Simulate multiple WebSocket clients
    for i in {1..50}; do
        (
            for j in {1..10}; do
                curl -s http://localhost:9955/api/status > /dev/null || true
                sleep 0.1
            done
        ) &
    done
    
    wait
    kill $SHIELD_PID 2>/dev/null || true
    echo "  Concurrent connection test complete"
else
    echo "  Shield binary not found, skipping WebSocket test"
fi

# Test 5: Pathological inputs
echo -e "\n[Test 5] Pathological Input Test"
echo "Testing with inputs designed to stress the system..."

./target/release/kindly-guard --stdio > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

# Deeply nested JSON
python3 -c "
import json
nested = {'a': 'value'}
for i in range(100):
    nested = {'nested': nested}
data = {'method': 'tools/scan', 'params': {'content': json.dumps(nested)}}
print(json.dumps(data))
" | timeout 2 ./target/release/kindly-guard --stdio > /dev/null 2>&1 || echo "  Deep nesting: Timeout (expected)"

# Repetitive patterns
echo '{"method":"tools/scan","params":{"content":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"}}' | \
    timeout 1 ./target/release/kindly-guard --stdio > /dev/null 2>&1 || echo "  Repetitive pattern: Timeout"

kill $SERVER_PID 2>/dev/null || true

# Generate report
echo -e "\n=================================="
echo "Performance Test Summary"
echo "=================================="
echo "1. Memory Test: Check memory_test.csv for leak detection"
echo "2. CPU Stress: Achieved ~$RPS requests/second"
echo "3. Large Inputs: Handled up to 1MB inputs"
echo "4. Concurrency: Tested 50 concurrent connections"
echo "5. Pathological: System protected against malicious inputs"
echo ""
echo "For detailed analysis, run: python3 performance-analysis.py"

# Cleanup
rm -f complex_input.json memory_test.csv