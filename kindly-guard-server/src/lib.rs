//! KindlyGuard Server Library
//! 
//! Exposes the scanner functionality for use by the CLI and other tools

pub mod config;
pub mod scanner;
pub mod server;
pub mod shield;

pub use config::Config;
pub use scanner::{SecurityScanner, Threat, ThreatType, Severity};
pub use server::McpServer;
pub use shield::Shield;