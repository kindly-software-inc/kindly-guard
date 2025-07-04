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
    time::Duration,
};

use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::{
    errors::ShieldError,
    ipc::{
        factory::IpcFactory,
        shm::{SharedMemoryIpc, ShmConfig},
    },
    core::Threat,
};

/// Client for reading threats from shared memory
pub struct ShmClient {
    shm: SharedMemoryIpc,
}

impl ShmClient {
    /// Create a new shared memory client (read-only)
    pub fn new() -> Result<Self, ShieldError> {
        let config = ShmConfig::default();
        let shm = SharedMemoryIpc::new(config)?;
        Ok(Self { shm })
    }
    
    /// Poll for new threats
    pub async fn poll_threats<F>(&self, mut callback: F) -> Result<(), ShieldError>
    where
        F: FnMut(Threat) -> bool + Send,
    {
        let mut ticker = interval(Duration::from_micros(100)); // 100μs polling interval
        
        loop {
            ticker.tick().await;
            
            // Check if shared memory is still healthy
            if !self.shm.is_healthy() {
                warn!("Shared memory unhealthy, stopping poll");
                return Err(ShieldError::Platform("Shared memory unhealthy".into()));
            }
            
            // Read all available threats
            while let Some(threat) = self.shm.read_threat()? {
                debug!("Read threat from shared memory: {:?}", threat.id);
                
                // Call the callback, stop if it returns false
                if !callback(threat) {
                    info!("Client requested stop");
                    return Ok(());
                }
            }
        }
    }
    
    /// Get current statistics
    pub fn get_stats(&self) -> crate::ipc::shm::ShmStats {
        self.shm.get_stats()
    }
}

/// Example usage for Claude Code extension
pub struct ClaudeCodeIntegration;

impl ClaudeCodeIntegration {
    /// Initialize shared memory client for Claude Code
    pub async fn init() -> Result<(), ShieldError> {
        // Check if shared memory is available
        if !SharedMemoryIpc::is_available() {
            warn!("Shared memory not available, falling back to WebSocket");
            return Self::init_websocket().await;
        }
        
        info!("Initializing shared memory client for Claude Code");
        
        let client = ShmClient::new()?;
        let stats = client.get_stats();
        info!("Connected to shared memory: {:?}", stats);
        
        // Start polling for threats
        tokio::spawn(async move {
            if let Err(e) = client.poll_threats(|threat| {
                // Process threat in Claude Code
                info!("Claude Code received threat: {:?}", threat);
                
                // Return true to continue polling
                true
            }).await {
                error!("Polling error: {}", e);
            }
        });
        
        Ok(())
    }
    
    /// Fall back to WebSocket if shared memory not available
    async fn init_websocket() -> Result<(), ShieldError> {
        info!("Initializing WebSocket client for Claude Code");
        // WebSocket implementation would go here
        Ok(())
    }
}

/// Benchmark client for testing latency
pub struct BenchmarkClient;

impl BenchmarkClient {
    /// Measure end-to-end latency
    pub async fn measure_latency() -> Result<(), ShieldError> {
        use std::time::Instant;
        
        let client = ShmClient::new()?;
        let mut latencies = Vec::new();
        
        // Measure read latency
        for _ in 0..1000 {
            let start = Instant::now();
            let _ = client.shm.read_threat()?;
            let latency = start.elapsed();
            latencies.push(latency.as_micros());
        }
        
        // Calculate statistics
        latencies.sort();
        let avg = latencies.iter().sum::<u128>() / latencies.len() as u128;
        let min = latencies[0];
        let max = latencies[latencies.len() - 1];
        let p99 = latencies[(latencies.len() as f64 * 0.99) as usize];
        
        info!("Shared Memory Read Latency:");
        info!("  Average: {}μs", avg);
        info!("  Min: {}μs", min);
        info!("  Max: {}μs", max);
        info!("  P99: {}μs", p99);
        
        if avg < 100 {
            info!("✓ Achieved sub-100μs average latency!");
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_shm_client() {
        if !SharedMemoryIpc::is_available() {
            println!("Shared memory not available, skipping test");
            return;
        }
        
        let client = ShmClient::new().unwrap();
        let stats = client.get_stats();
        
        assert_eq!(stats.events_read, 0);
    }
}