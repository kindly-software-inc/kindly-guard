// Copyright 2025 Kindly Software Inc.
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
//! Bulkhead isolation pattern for resource protection
//!
//! This module implements the bulkhead pattern to isolate resources and prevent
//! cascading failures. It ensures that failure in one component doesn't affect others.

use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::config::Config;

/// Bulkhead error types
#[derive(Debug, thiserror::Error)]
pub enum BulkheadError {
    #[error("Bulkhead full: {name}")]
    BulkheadFull { name: String },
    
    #[error("Execution failed: {0}")]
    ExecutionFailed(#[from] anyhow::Error),
    
    #[error("Timeout: {name}")]
    Timeout { name: String },
}

/// Bulkhead statistics
#[derive(Debug, Clone)]
pub struct BulkheadStats {
    pub name: String,
    pub max_concurrent: u32,
    pub active_calls: u32,
    pub total_calls: u64,
    pub rejected_calls: u64,
    pub failed_calls: u64,
}

/// Bulkhead trait for resource isolation
#[async_trait]
pub trait BulkheadTrait: Send + Sync {
    /// Execute a function with bulkhead protection
    async fn execute<F, T, Fut>(&self, name: &str, f: F) -> Result<T, BulkheadError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send;
    
    /// Get bulkhead statistics
    fn stats(&self, name: &str) -> BulkheadStats;
    
    /// Check if bulkhead has capacity
    fn has_capacity(&self, name: &str) -> bool;
}

/// Standard bulkhead implementation
pub struct StandardBulkhead {
    semaphores: dashmap::DashMap<String, Arc<BulkheadState>>,
    max_concurrent: u32,
    timeout: std::time::Duration,
}

struct BulkheadState {
    semaphore: Semaphore,
    active_calls: AtomicU32,
    total_calls: std::sync::atomic::AtomicU64,
    rejected_calls: std::sync::atomic::AtomicU64,
    failed_calls: std::sync::atomic::AtomicU64,
}

impl StandardBulkhead {
    /// Create from configuration
    pub fn from_config(config: &Config) -> Self {
        let max_concurrent = config.resilience.bulkhead.max_concurrent.unwrap_or(10);
        let timeout_ms = config.resilience.bulkhead.timeout_ms.unwrap_or(5000);
        
        Self {
            semaphores: dashmap::DashMap::new(),
            max_concurrent,
            timeout: std::time::Duration::from_millis(timeout_ms),
        }
    }
    
    /// Get or create bulkhead state
    fn get_or_create_state(&self, name: &str) -> Arc<BulkheadState> {
        self.semaphores
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(BulkheadState {
                    semaphore: Semaphore::new(self.max_concurrent as usize),
                    active_calls: AtomicU32::new(0),
                    total_calls: std::sync::atomic::AtomicU64::new(0),
                    rejected_calls: std::sync::atomic::AtomicU64::new(0),
                    failed_calls: std::sync::atomic::AtomicU64::new(0),
                })
            })
            .clone()
    }
}

#[async_trait]
impl BulkheadTrait for StandardBulkhead {
    async fn execute<F, T, Fut>(&self, name: &str, f: F) -> Result<T, BulkheadError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        let state = self.get_or_create_state(name);
        
        // Try to acquire permit
        let permit = match state.semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                state.rejected_calls.fetch_add(1, Ordering::Relaxed);
                warn!("Bulkhead full for {}", name);
                return Err(BulkheadError::BulkheadFull {
                    name: name.to_string(),
                });
            }
        };
        
        state.total_calls.fetch_add(1, Ordering::Relaxed);
        state.active_calls.fetch_add(1, Ordering::Relaxed);
        
        debug!("Bulkhead {} acquired, active: {}", name, state.active_calls.load(Ordering::Relaxed));
        
        // Execute with timeout
        let result = match tokio::time::timeout(self.timeout, f()).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => {
                state.failed_calls.fetch_add(1, Ordering::Relaxed);
                Err(BulkheadError::ExecutionFailed(e))
            }
            Err(_) => {
                state.failed_calls.fetch_add(1, Ordering::Relaxed);
                warn!("Bulkhead timeout for {}", name);
                Err(BulkheadError::Timeout {
                    name: name.to_string(),
                })
            }
        };
        
        state.active_calls.fetch_sub(1, Ordering::Relaxed);
        drop(permit);
        
        debug!("Bulkhead {} released, active: {}", name, state.active_calls.load(Ordering::Relaxed));
        
        result
    }
    
    fn stats(&self, name: &str) -> BulkheadStats {
        let state = self.get_or_create_state(name);
        
        BulkheadStats {
            name: name.to_string(),
            max_concurrent: self.max_concurrent,
            active_calls: state.active_calls.load(Ordering::Relaxed),
            total_calls: state.total_calls.load(Ordering::Relaxed),
            rejected_calls: state.rejected_calls.load(Ordering::Relaxed),
            failed_calls: state.failed_calls.load(Ordering::Relaxed),
        }
    }
    
    fn has_capacity(&self, name: &str) -> bool {
        let state = self.get_or_create_state(name);
        state.semaphore.available_permits() > 0
    }
}

/// Enhanced bulkhead with adaptive limits
#[cfg(feature = "enhanced")]
pub struct EnhancedBulkhead {
    base: StandardBulkhead,
    adaptive_limits: dashmap::DashMap<String, AdaptiveLimits>,
}

#[cfg(feature = "enhanced")]
struct AdaptiveLimits {
    current_limit: AtomicU32,
    success_rate: std::sync::Mutex<f64>,
    last_adjustment: std::sync::Mutex<std::time::Instant>,
}

#[cfg(feature = "enhanced")]
impl EnhancedBulkhead {
    /// Create from configuration
    pub fn from_config(config: &Config) -> Self {
        Self {
            base: StandardBulkhead::from_config(config),
            adaptive_limits: dashmap::DashMap::new(),
        }
    }
    
    /// Adjust limits based on performance
    fn adjust_limits(&self, name: &str, success: bool) {
        let limits = self.adaptive_limits
            .entry(name.to_string())
            .or_insert_with(|| AdaptiveLimits {
                current_limit: AtomicU32::new(self.base.max_concurrent),
                success_rate: std::sync::Mutex::new(1.0),
                last_adjustment: std::sync::Mutex::new(std::time::Instant::now()),
            });
        
        // Update success rate
        let mut success_rate = limits.success_rate.lock().unwrap();
        *success_rate = (*success_rate * 0.95) + (if success { 0.05 } else { 0.0 });
        
        // Check if we should adjust
        let mut last_adjustment = limits.last_adjustment.lock().unwrap();
        if last_adjustment.elapsed() > std::time::Duration::from_secs(60) {
            let current = limits.current_limit.load(Ordering::Relaxed);
            
            if *success_rate > 0.98 && current < self.base.max_concurrent * 2 {
                // Increase limit
                limits.current_limit.store(current + 1, Ordering::Relaxed);
                debug!("Increased bulkhead limit for {} to {}", name, current + 1);
            } else if *success_rate < 0.90 && current > 2 {
                // Decrease limit
                limits.current_limit.store(current - 1, Ordering::Relaxed);
                debug!("Decreased bulkhead limit for {} to {}", name, current - 1);
            }
            
            *last_adjustment = std::time::Instant::now();
        }
    }
}

#[cfg(feature = "enhanced")]
#[async_trait]
impl BulkheadTrait for EnhancedBulkhead {
    async fn execute<F, T, Fut>(&self, name: &str, f: F) -> Result<T, BulkheadError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        let result = self.base.execute(name, f).await;
        
        // Adjust limits based on result
        self.adjust_limits(name, result.is_ok());
        
        result
    }
    
    fn stats(&self, name: &str) -> BulkheadStats {
        let mut stats = self.base.stats(name);
        
        // Add adaptive limit if available
        if let Some(limits) = self.adaptive_limits.get(name) {
            stats.max_concurrent = limits.current_limit.load(Ordering::Relaxed);
        }
        
        stats
    }
    
    fn has_capacity(&self, name: &str) -> bool {
        self.base.has_capacity(name)
    }
}

/// Type-erased bulkhead for dyn compatibility
#[async_trait]
pub trait DynBulkhead: Send + Sync {
    /// Execute a JSON-RPC operation with bulkhead protection
    async fn execute_json(
        &self,
        name: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, BulkheadError>;
    
    /// Get bulkhead statistics
    fn stats(&self, name: &str) -> BulkheadStats;
    
    /// Check if bulkhead has capacity
    fn has_capacity(&self, name: &str) -> bool;
}

/// Wrapper to adapt BulkheadTrait to DynBulkhead
pub struct BulkheadWrapper<T: BulkheadTrait> {
    inner: T,
}

impl<T: BulkheadTrait> BulkheadWrapper<T> {
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<T: BulkheadTrait> DynBulkhead for BulkheadWrapper<T> {
    async fn execute_json(
        &self,
        name: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, BulkheadError> {
        self.inner
            .execute(name, || async {
                // Simulate JSON-RPC processing
                Ok(serde_json::json!({
                    "result": "processed",
                    "request": request
                }))
            })
            .await
    }
    
    fn stats(&self, name: &str) -> BulkheadStats {
        self.inner.stats(name)
    }
    
    fn has_capacity(&self, name: &str) -> bool {
        self.inner.has_capacity(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_bulkhead_limits() {
        let config = Config::default();
        let bulkhead = StandardBulkhead::from_config(&config);
        
        // Test capacity enforcement
        let results = futures::future::join_all((0..15).map(|i| {
            let bulkhead = &bulkhead;
            async move {
                bulkhead.execute("test", || async {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    Ok::<_, anyhow::Error>(i)
                }).await
            }
        })).await;
        
        // Some should fail due to capacity
        let rejected = results.iter().filter(|r| {
            matches!(r, Err(BulkheadError::BulkheadFull { .. }))
        }).count();
        
        assert!(rejected > 0, "Some requests should be rejected");
    }
    
    #[tokio::test]
    async fn test_bulkhead_stats() {
        let config = Config::default();
        let bulkhead = StandardBulkhead::from_config(&config);
        
        // Execute some operations
        for _ in 0..5 {
            let _ = bulkhead.execute("test", || async {
                Ok::<_, anyhow::Error>(())
            }).await;
        }
        
        let stats = bulkhead.stats("test");
        assert_eq!(stats.total_calls, 5);
    }
}