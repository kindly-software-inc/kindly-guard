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
#[cfg(feature = "enhanced")]
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

pub use auth::{AuthContext, AuthManager};
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
#[cfg(feature = "enhanced")]
pub fn create_event_buffer(
    config: &event_processor::EventProcessorConfig,
) -> Result<Option<Box<dyn traits::EventBufferTrait>>> {
    if !config.enabled {
        return Ok(None);
    }

    #[cfg(feature = "enhanced")]
    {
        // Check if enhanced mode is requested
        if config.enhanced_mode.unwrap_or(false) {
            tracing::info!(
                target: "security.config",
                buffer_size_mb = config.buffer_size_mb,
                max_endpoints = config.max_endpoints,
                "Initializing enhanced atomic bit-packed event buffer"
            );
            // Use the factory function from kindly-guard-core
            let buffer_config = kindly_guard_core::EventBufferConfig {
                buffer_size_mb: config.buffer_size_mb,
                max_endpoints: config.max_endpoints,
            };
            return Ok(Some(
                kindly_guard_core::create_atomic_event_buffer(buffer_config)
                    .context("Failed to create enhanced event buffer")?,
            ));
        }
    }

    // Default to simple implementation
    tracing::info!(
        target: "security.config",
        "Using standard event buffer implementation"
    );
    Ok(Some(Box::new(event_processor::SimpleEventBuffer::new())))
}

/// Mock types for testing
#[cfg(any(test, feature = "test-utils"))]
pub mod mocks {
    // NOTE: Trait mocks disabled due to mockall compatibility issues with async_trait
    // Manual test doubles should be created when needed
    pub use crate::permissions::MockToolPermissionManager;
    pub use crate::traits::MockEnhancedScanner; // This one doesn't use async_trait
}
