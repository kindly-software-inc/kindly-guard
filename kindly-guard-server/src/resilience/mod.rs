//! Resilience patterns for production reliability
//!
//! This module provides circuit breakers, retry logic, and other patterns
//! to ensure the system can handle failures gracefully.
//!
//! The architecture uses trait-based abstractions to allow both standard
//! and enhanced implementations, with runtime selection based on configuration.

pub mod circuit_breaker;
pub mod config;
#[cfg(feature = "enhanced")]
pub mod enhanced;
pub mod retry;
pub mod standard;
pub mod stubs;

use crate::config::Config;
use crate::traits::{
    DynCircuitBreaker, DynRetryStrategy, HealthCheckTrait, RecoveryStrategyTrait, ResilienceFactory,
};
use anyhow::Result;
use std::sync::Arc;

// Re-export core types
pub use standard::StandardResilienceFactory;

/// Create a circuit breaker based on configuration
pub fn create_circuit_breaker(config: &Config) -> Result<Arc<dyn DynCircuitBreaker>> {
    let factory = create_resilience_factory(config);
    factory.create_circuit_breaker(config)
}

/// Create a retry strategy based on configuration
pub fn create_retry_strategy(config: &Config) -> Result<Arc<dyn DynRetryStrategy>> {
    let factory = create_resilience_factory(config);
    factory.create_retry_strategy(config)
}

/// Create a health checker based on configuration
pub fn create_health_checker(config: &Config) -> Result<Arc<dyn HealthCheckTrait>> {
    let factory = create_resilience_factory(config);
    factory.create_health_checker(config)
}

/// Create a recovery strategy based on configuration
pub fn create_recovery_strategy(config: &Config) -> Result<Arc<dyn RecoveryStrategyTrait>> {
    let factory = create_resilience_factory(config);
    factory.create_recovery_strategy(config)
}

/// Create the appropriate resilience factory based on configuration
fn create_resilience_factory(config: &Config) -> Box<dyn ResilienceFactory> {
    if config.resilience.enhanced_mode {
        tracing::info!("Resilience mode: enhanced");

        #[cfg(feature = "enhanced")]
        {
            Box::new(enhanced::EnhancedResilienceFactory)
        }
        #[cfg(not(feature = "enhanced"))]
        {
            tracing::warn!("Enhanced mode requested but feature not enabled, using standard");
            Box::new(StandardResilienceFactory)
        }
    } else {
        tracing::info!("Resilience mode: standard");
        Box::new(StandardResilienceFactory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
