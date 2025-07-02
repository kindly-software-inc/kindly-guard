#!/bin/bash
# Run comprehensive performance benchmarks for KindlyGuard

set -e

echo "Running KindlyGuard Comprehensive Performance Benchmarks"
echo "======================================================="
echo ""

# Set up environment for optimal benchmarking
export RUST_LOG=warn
export RUST_BACKTRACE=1

# Check if running with root for CPU governor control
if [ "$EUID" -eq 0 ]; then
    echo "Setting CPU governor to performance mode..."
    for i in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo "performance" > "$i" 2>/dev/null || true
    done
fi

echo "Building in release mode with all features..."
cd kindly-guard-server
cargo build --release --all-features

echo ""
echo "Running comprehensive benchmarks..."
echo "This will test:"
echo "  - Scanner throughput (various payload sizes)"
echo "  - Scanner latency (percentiles)"
echo "  - Memory usage patterns"
echo "  - Multi-threaded scaling"
echo "  - Large payload handling"
echo "  - JSON scanning performance"
echo "  - CPU utilization"
echo "  - Event processing"
echo "  - Rate limiting"
echo ""

# Run the comprehensive benchmark suite
cargo bench --bench comprehensive_benchmarks --features enhanced

echo ""
echo "Benchmark results saved to: target/criterion/"
echo ""
echo "To view detailed HTML reports:"
echo "  cd kindly-guard-server/target/criterion && python3 -m http.server 8000"
echo "  Then open http://localhost:8000 in your browser"