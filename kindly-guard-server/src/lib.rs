//! KindlyGuard Server Library
//! 
//! Exposes the scanner functionality for use by the CLI and other tools

pub mod auth;
pub mod config;
pub mod error;
#[cfg(feature = "enhanced")]
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
pub mod enhanced_impl;
pub mod component_selector;
pub mod logging;
pub mod permissions;
pub mod versioning;
pub mod telemetry;

pub use config::{Config, ScannerConfig};
pub use error::{KindlyError, KindlyResult, ResultExt};
pub use scanner::{SecurityScanner, Threat, ThreatType, Severity};
pub use server::McpServer;
pub use shield::Shield;
pub use traits::{SecurityEventProcessor, EnhancedScanner, CorrelationEngine, RateLimiter};
pub use component_selector::{ComponentSelector, ComponentManager};