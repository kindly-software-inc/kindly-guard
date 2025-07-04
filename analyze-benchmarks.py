#!/usr/bin/env python3
"""
Analyze and visualize KindlyGuard benchmark results.

This script parses Criterion benchmark output and generates:
- Performance comparison charts
- Memory usage analysis
- Scaling efficiency metrics
- Enhanced vs Standard mode comparisons
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
import argparse

try:
    import matplotlib.pyplot as plt
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available. Install with: pip install matplotlib numpy")

def find_criterion_dir() -> Path:
    """Find the criterion output directory."""
    search_paths = [
        Path("kindly-guard-server/target/criterion"),
        Path("target/criterion"),
        Path(".")
    ]
    
    for path in search_paths:
        if path.exists() and path.is_dir():
            return path
    
    raise FileNotFoundError("Could not find criterion output directory")

def load_benchmark_data(criterion_dir: Path) -> Dict[str, Any]:
    """Load all benchmark data from criterion directory."""
    results = {}
    
    for bench_dir in criterion_dir.iterdir():
        if bench_dir.is_dir() and not bench_dir.name.startswith('.'):
            estimates_file = bench_dir / "base" / "estimates.json"
            if estimates_file.exists():
                with open(estimates_file) as f:
                    data = json.load(f)
                    results[bench_dir.name] = data
    
    return results

def analyze_throughput(results: Dict[str, Any]) -> Dict[str, float]:
    """Analyze scanner throughput benchmarks."""
    throughput_results = {}
    
    for bench_name, data in results.items():
        if "scanner_throughput" in bench_name:
            # Extract throughput in MB/s
            mean_time = data.get("mean", {}).get("point_estimate", 0)
            if mean_time > 0:
                # Parse size from benchmark name
                if "1KB" in bench_name:
                    size_bytes = 1024
                elif "10KB" in bench_name:
                    size_bytes = 10 * 1024
                elif "100KB" in bench_name:
                    size_bytes = 100 * 1024
                elif "1MB" in bench_name:
                    size_bytes = 1024 * 1024
                elif "10MB" in bench_name:
                    size_bytes = 10 * 1024 * 1024
                else:
                    continue
                
                # Calculate throughput in MB/s
                throughput_mbps = (size_bytes / (1024 * 1024)) / (mean_time / 1e9)
                throughput_results[bench_name] = throughput_mbps
    
    return throughput_results

def analyze_latency(results: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    """Analyze scanner latency benchmarks."""
    latency_results = {}
    
    for bench_name, data in results.items():
        if "scanner_latency" in bench_name:
            mean_time = data.get("mean", {}).get("point_estimate", 0)
            std_dev = data.get("std_dev", {}).get("point_estimate", 0)
            
            latency_results[bench_name] = {
                "mean_us": mean_time / 1000,  # Convert to microseconds
                "std_dev_us": std_dev / 1000,
                "p99_us": (mean_time + 2.33 * std_dev) / 1000,  # Approximate p99
            }
    
    return latency_results

def analyze_scaling(results: Dict[str, Any]) -> Dict[str, List[float]]:
    """Analyze multi-threaded scaling efficiency."""
    scaling_results = {"standard": [], "enhanced": []}
    thread_counts = [1, 2, 4, 8, 16]
    
    for mode in ["standard", "enhanced"]:
        baseline = None
        
        for threads in thread_counts:
            bench_name = f"multi_threaded_scaling/{mode}/{threads}"
            if bench_name in results:
                throughput = results[bench_name].get("mean", {}).get("point_estimate", 0)
                
                if threads == 1:
                    baseline = throughput
                
                if baseline and baseline > 0:
                    efficiency = (throughput / baseline) / threads * 100
                    scaling_results[mode].append(efficiency)
    
    return scaling_results

def generate_report(results: Dict[str, Any]) -> str:
    """Generate a text report of benchmark results."""
    report = []
    report.append("KindlyGuard Performance Benchmark Report")
    report.append("=" * 50)
    report.append("")
    
    # Throughput analysis
    throughput = analyze_throughput(results)
    if throughput:
        report.append("Scanner Throughput (MB/s):")
        report.append("-" * 30)
        for bench, mbps in sorted(throughput.items()):
            mode = "Enhanced" if "enhanced" in bench else "Standard"
            threat_type = "Threats" if "threats" in bench else "Benign"
            report.append(f"  {mode} {threat_type}: {mbps:.2f} MB/s")
        report.append("")
    
    # Latency analysis
    latency = analyze_latency(results)
    if latency:
        report.append("Scanner Latency (microseconds):")
        report.append("-" * 30)
        for bench, stats in sorted(latency.items()):
            mode = "Enhanced" if "enhanced" in bench else "Standard"
            report.append(f"  {mode}:")
            report.append(f"    Mean: {stats['mean_us']:.2f} μs")
            report.append(f"    Std Dev: {stats['std_dev_us']:.2f} μs")
            report.append(f"    P99 (est): {stats['p99_us']:.2f} μs")
        report.append("")
    
    # Enhanced vs Standard comparison
    report.append("Enhanced vs Standard Mode Comparison:")
    report.append("-" * 30)
    
    enhanced_times = []
    standard_times = []
    
    for bench_name, data in results.items():
        mean_time = data.get("mean", {}).get("point_estimate", 0)
        if "enhanced" in bench_name:
            enhanced_times.append(mean_time)
        elif "standard" in bench_name:
            standard_times.append(mean_time)
    
    if enhanced_times and standard_times:
        avg_enhanced = np.mean(enhanced_times)
        avg_standard = np.mean(standard_times)
        overhead = ((avg_enhanced - avg_standard) / avg_standard) * 100
        report.append(f"  Average Enhanced Mode Overhead: {overhead:.1f}%")
    
    report.append("")
    
    return "\n".join(report)

def plot_results(results: Dict[str, Any], output_dir: Path):
    """Generate visualization plots if matplotlib is available."""
    if not MATPLOTLIB_AVAILABLE:
        return
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    # Plot throughput comparison
    throughput = analyze_throughput(results)
    if throughput:
        fig, ax = plt.subplots(figsize=(10, 6))
        
        standard_throughput = [v for k, v in throughput.items() if "standard" in k]
        enhanced_throughput = [v for k, v in throughput.items() if "enhanced" in k]
        
        x = np.arange(len(standard_throughput))
        width = 0.35
        
        ax.bar(x - width/2, standard_throughput, width, label='Standard')
        ax.bar(x + width/2, enhanced_throughput, width, label='Enhanced')
        
        ax.set_ylabel('Throughput (MB/s)')
        ax.set_title('Scanner Throughput Comparison')
        ax.set_xticks(x)
        ax.set_xticklabels(['1KB', '10KB', '100KB', '1MB', '10MB'])
        ax.legend()
        
        plt.savefig(output_dir / 'throughput_comparison.png')
        plt.close()
    
    # Plot scaling efficiency
    scaling = analyze_scaling(results)
    if scaling["standard"] and scaling["enhanced"]:
        fig, ax = plt.subplots(figsize=(10, 6))
        
        thread_counts = [1, 2, 4, 8, 16][:len(scaling["standard"])]
        
        ax.plot(thread_counts, scaling["standard"], 'o-', label='Standard')
        ax.plot(thread_counts, scaling["enhanced"], 's-', label='Enhanced')
        ax.plot(thread_counts, [100]*len(thread_counts), '--', color='gray', label='Perfect Scaling')
        
        ax.set_xlabel('Thread Count')
        ax.set_ylabel('Scaling Efficiency (%)')
        ax.set_title('Multi-threaded Scaling Efficiency')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.savefig(output_dir / 'scaling_efficiency.png')
        plt.close()

def main():
    parser = argparse.ArgumentParser(description='Analyze KindlyGuard benchmark results')
    parser.add_argument('--output-dir', type=Path, default=Path('benchmark_analysis'),
                       help='Output directory for reports and plots')
    parser.add_argument('--criterion-dir', type=Path, default=None,
                       help='Path to criterion output directory')
    args = parser.parse_args()
    
    # Find criterion directory
    if args.criterion_dir:
        criterion_dir = args.criterion_dir
    else:
        criterion_dir = find_criterion_dir()
    
    print(f"Loading benchmark data from: {criterion_dir}")
    
    # Load benchmark results
    results = load_benchmark_data(criterion_dir)
    
    if not results:
        print("No benchmark results found. Run benchmarks first with:")
        print("  ./run-comprehensive-benchmarks.sh")
        sys.exit(1)
    
    print(f"Found {len(results)} benchmark results")
    
    # Generate report
    report = generate_report(results)
    print("\n" + report)
    
    # Save report
    args.output_dir.mkdir(exist_ok=True)
    with open(args.output_dir / 'benchmark_report.txt', 'w') as f:
        f.write(report)
    
    # Generate plots
    if MATPLOTLIB_AVAILABLE:
        print(f"\nGenerating visualization plots in {args.output_dir}...")
        plot_results(results, args.output_dir)
        print("Plots generated successfully!")
    
    print(f"\nAnalysis complete. Results saved to: {args.output_dir}")

if __name__ == "__main__":
    main()