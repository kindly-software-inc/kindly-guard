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

pub use atomic_event_buffer::{AtomicEventBuffer, Priority};
pub use binary_protocol::{BinaryProtocol, MessageCompressor, CompressionLevel};
pub use pattern_matcher::{PatternMatcher, ThreatClassifier, UnicodeNormalizer, ThreatType};

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