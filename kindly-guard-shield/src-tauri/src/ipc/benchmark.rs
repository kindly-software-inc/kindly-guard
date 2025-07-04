// Copyright 2025 Kindly-Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use tracing::info;

use crate::{
    core::{Severity, Threat, ThreatType},
    errors::ShieldError,
    ipc::{
        factory::IpcFactory,
        shm::{IpcTransport, SharedMemoryIpc, ShmConfig},
    },
};

/// Benchmark results for IPC performance
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    /// Method being benchmarked
    pub method: String,
    /// Number of iterations
    pub iterations: usize,
    /// Average latency in microseconds
    pub avg_latency_us: f64,
    /// Minimum latency in microseconds
    pub min_latency_us: f64,
    /// Maximum latency in microseconds
    pub max_latency_us: f64,
    /// 99th percentile latency
    pub p99_latency_us: f64,
    /// Throughput in events per second
    pub throughput: f64,
}

/// IPC benchmark runner
pub struct IpcBenchmark;

impl IpcBenchmark {
    /// Run a latency benchmark on the given transport
    pub fn benchmark_latency(
        transport: Arc<Mutex<dyn IpcTransport>>,
        iterations: usize,
    ) -> Result<BenchmarkResults, ShieldError> {
        let mut latencies = Vec::with_capacity(iterations);
        
        // Create a test threat
        let threat = Threat {
            id: "bench-1".to_string(),
            threat_type: ThreatType::UnicodeInvisible,
            severity: Severity::Medium,
            source: "benchmark".to_string(),
            details: "Benchmark threat for latency testing".to_string(),
            blocked: true,
            timestamp: chrono::Utc::now(),
            context: None,
        };
        
        // Warm up
        for _ in 0..100 {
            transport.lock().write_threat(&threat)?;
        }
        
        // Benchmark writes
        let start_time = Instant::now();
        
        for _ in 0..iterations {
            let iter_start = Instant::now();
            transport.lock().write_threat(&threat)?;
            let latency = iter_start.elapsed();
            latencies.push(latency.as_micros() as f64);
        }
        
        let total_duration = start_time.elapsed();
        
        // Calculate statistics
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let min = latencies[0];
        let max = latencies[iterations - 1];
        let avg = latencies.iter().sum::<f64>() / iterations as f64;
        let p99_index = (iterations as f64 * 0.99) as usize;
        let p99 = latencies[p99_index.min(iterations - 1)];
        
        let throughput = iterations as f64 / total_duration.as_secs_f64();
        
        Ok(BenchmarkResults {
            method: "write_threat".to_string(),
            iterations,
            avg_latency_us: avg,
            min_latency_us: min,
            max_latency_us: max,
            p99_latency_us: p99,
            throughput,
        })
    }
    
    /// Compare shared memory vs WebSocket performance
    pub fn compare_transports(iterations: usize) -> Result<(), ShieldError> {
        info!("Starting IPC transport comparison benchmark");
        
        // Benchmark shared memory
        if SharedMemoryIpc::is_available() {
            let shm = SharedMemoryIpc::new(ShmConfig::default())?;
            let shm_transport = Arc::new(Mutex::new(shm));
            
            let shm_results = Self::benchmark_latency(shm_transport, iterations)?;
            Self::print_results("Shared Memory", &shm_results);
        } else {
            info!("Shared memory not available on this platform");
        }
        
        // Benchmark WebSocket (mock for now)
        // In a real implementation, this would benchmark actual WebSocket
        info!("\nWebSocket benchmark would be performed here");
        info!("Expected latency: 1000-5000μs (network overhead)");
        
        Ok(())
    }
    
    /// Benchmark throughput for batch operations
    pub fn benchmark_throughput(
        transport: Arc<Mutex<dyn IpcTransport>>,
        duration_secs: u64,
    ) -> Result<usize, ShieldError> {
        let threat = Threat {
            id: "throughput-1".to_string(),
            threat_type: ThreatType::SuspiciousPattern,
            severity: Severity::Low,
            source: "throughput-test".to_string(),
            details: "Testing maximum throughput".to_string(),
            blocked: false,
            timestamp: chrono::Utc::now(),
            context: None,
        };
        
        let start = Instant::now();
        let duration = Duration::from_secs(duration_secs);
        let mut count = 0;
        
        while start.elapsed() < duration {
            transport.lock().write_threat(&threat)?;
            count += 1;
        }
        
        let elapsed = start.elapsed().as_secs_f64();
        let throughput = count as f64 / elapsed;
        
        info!(
            "Throughput test: {} events in {:.2}s = {:.0} events/sec",
            count, elapsed, throughput
        );
        
        Ok(count)
    }
    
    fn print_results(name: &str, results: &BenchmarkResults) {
        println!("\n{} Benchmark Results:", name);
        println!("  Iterations: {}", results.iterations);
        println!("  Average latency: {:.2}μs", results.avg_latency_us);
        println!("  Min latency: {:.2}μs", results.min_latency_us);
        println!("  Max latency: {:.2}μs", results.max_latency_us);
        println!("  P99 latency: {:.2}μs", results.p99_latency_us);
        println!("  Throughput: {:.0} events/sec", results.throughput);
        
        // Check if we met the <100μs target
        if results.avg_latency_us < 100.0 {
            println!("  ✓ Achieved sub-100μs average latency!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ShieldCore;
    
    #[test]
    fn test_benchmark_shared_memory() {
        if !SharedMemoryIpc::is_available() {
            println!("Shared memory not available, skipping test");
            return;
        }
        
        let shm = SharedMemoryIpc::new(ShmConfig::default()).unwrap();
        let transport = Arc::new(Mutex::new(shm));
        
        let results = IpcBenchmark::benchmark_latency(transport, 1000).unwrap();
        
        // Shared memory should achieve very low latency
        assert!(results.avg_latency_us < 1000.0); // Should be well under 1ms
        assert!(results.min_latency_us < 500.0);  // Best case should be very fast
    }
    
    #[test]
    fn test_throughput_benchmark() {
        if !SharedMemoryIpc::is_available() {
            println!("Shared memory not available, skipping test");
            return;
        }
        
        let shm = SharedMemoryIpc::new(ShmConfig::default()).unwrap();
        let transport = Arc::new(Mutex::new(shm));
        
        let count = IpcBenchmark::benchmark_throughput(transport, 1).unwrap();
        
        // Should handle at least 10k events per second
        assert!(count > 10_000);
    }
}