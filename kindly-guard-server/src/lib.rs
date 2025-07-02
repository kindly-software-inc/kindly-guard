//! `KindlyGuard` Server Library
//!
//! Exposes the scanner functionality for use by the CLI and other tools

pub mod audit;
pub mod auth;
pub mod cli;
pub mod component_selector;
pub mod config;
pub mod daemon;
#[cfg(feature = "enhanced")]
pub(crate) mod enhanced_impl;
pub mod error;
pub mod event_processor;
pub mod logging;
pub mod metrics;
pub mod neutralizer;
pub mod permissions;
pub mod plugins;
pub mod protocol;
pub mod rate_limit;
pub mod resilience;
pub mod scanner;
pub mod security;
pub mod server;
pub mod shield;
pub mod signing;
pub mod standard_impl;
pub mod storage;
pub mod telemetry;
pub mod traits;
pub mod transport;
pub mod versioning;
pub mod web;

pub use component_selector::{ComponentManager, ComponentSelector};
pub use config::{Config, ScannerConfig};
pub use error::{KindlyError, KindlyResult, ResultExt};
pub use metrics::MetricsRegistry;
pub use neutralizer::{
    create_neutralizer, create_neutralizer_with_telemetry, NeutralizationConfig,
    NeutralizationMode, NeutralizeResult, ThreatNeutralizer,
};
pub use scanner::{Location, SecurityScanner, Severity, Threat, ThreatType};
pub use server::McpServer;
pub use shield::Shield;
pub use traits::{CorrelationEngine, EnhancedScanner, RateLimiter, SecurityEventProcessor};

use anyhow::Result;

/// Create an event buffer based on configuration
pub fn create_event_buffer(
    config: &event_processor::EventProcessorConfig,
) -> Result<Option<Box<dyn traits::EventBufferTrait>>> {
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
    pub use crate::traits::MockEnhancedScanner; // This one doesn't use async_trait
}
