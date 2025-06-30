//! KindlyGuard Server Library
//! 
//! Exposes the scanner functionality for use by the CLI and other tools

pub mod auth;
pub mod config;
pub mod error;
pub mod event_processor;
pub mod protocol;
pub mod rate_limit;
pub mod scanner;
pub mod server;
pub mod shield;
pub mod signing;
pub mod traits;
pub mod standard_impl;
#[cfg(feature = "enhanced")]
pub(crate) mod enhanced_impl;
pub mod component_selector;
pub mod logging;
pub mod permissions;
pub mod versioning;
pub mod telemetry;
pub mod storage;
pub mod plugins;
pub mod audit;
pub mod transport;
pub mod web;
pub mod cli;
pub mod security;
pub mod daemon;
pub mod metrics;
pub(crate) mod resilience;

pub use config::{Config, ScannerConfig};
pub use error::{KindlyError, KindlyResult, ResultExt};
pub use scanner::{SecurityScanner, Threat, ThreatType, Severity};
pub use server::McpServer;
pub use shield::Shield;
pub use traits::{SecurityEventProcessor, EnhancedScanner, CorrelationEngine, RateLimiter};
pub use component_selector::{ComponentSelector, ComponentManager};
pub use metrics::MetricsRegistry;

use anyhow::Result;

/// Create an event buffer based on configuration
pub fn create_event_buffer(config: &event_processor::EventProcessorConfig) -> Result<Option<Box<dyn traits::EventBufferTrait>>> {
    // For now, return a simple stub implementation
    // Enhanced implementations can be added behind feature flags
    if config.enabled {
        Ok(Some(Box::new(event_processor::SimpleEventBuffer::new())))
    } else {
        Ok(None)
    }
}

/// Mock types for testing
#[cfg(any(test, feature = "test-utils"))]
pub mod mocks {
    // NOTE: Trait mocks disabled due to mockall compatibility issues with async_trait
    // Manual test doubles should be created when needed
    pub use crate::permissions::MockToolPermissionManager;
    pub use crate::traits::{MockEnhancedScanner}; // This one doesn't use async_trait
}