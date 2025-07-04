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
//! KindlyGuard Core - Enhanced security primitives
//!
//! This crate provides the patented lock-free data structures and
//! advanced algorithms used by KindlyGuard's enhanced mode.
//!
//! NOTE: This is a stub implementation for development purposes.
//! The actual proprietary implementation would include the patented
//! AtomicEventBuffer and other advanced features.

#![warn(missing_docs)]

use anyhow::Result;

pub mod atomic_event_buffer;
pub mod binary_protocol;
pub mod pattern_matcher;
#[cfg(feature = "premium")]
pub mod premium;

pub use atomic_event_buffer::{
    create_atomic_event_buffer, CircuitState, EndpointStats, EventBufferConfig, EventBufferTrait,
    Priority,
};
pub use binary_protocol::{BinaryProtocol, MessageCompressor, CompressionLevel};
pub use pattern_matcher::{PatternMatcher, ThreatClassifier, UnicodeNormalizer, ThreatType};

// Re-export premium features when available
#[cfg(feature = "premium")]
pub use premium::{
    ClaudeCodeIntegration,
    ClaudeIntegrationConfig,
    SecurityStats,
};

/// Module version for compatibility checking
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Verify core library compatibility
pub fn verify_compatibility(required_version: &str) -> Result<()> {
    if VERSION != required_version {
        anyhow::bail!(
            "KindlyGuard core version mismatch: expected {}, got {}",
            required_version,
            VERSION
        );
    }
    Ok(())
}