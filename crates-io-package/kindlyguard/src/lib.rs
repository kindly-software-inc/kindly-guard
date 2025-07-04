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
//! # KindlyGuard
//!
//! Security-focused MCP (Model Context Protocol) server for AI protection.
//!
//! This crate provides a unified interface to the KindlyGuard server functionality.
//! The CLI tools are available as a separate binary crate that should be installed
//! with `cargo install kindly-guard-cli`.
//!
//! ## Features
//!
//! - **Unicode Security**: Advanced detection and prevention of Unicode-based attacks
//! - **Injection Protection**: Guards against various injection attempts (SQL, command, etc.)
//! - **Real-time Monitoring**: Continuous threat detection and alerting
//! - **MCP Protocol Integration**: Seamless integration with the Model Context Protocol
//! - **CLI Tools**: Command-line utilities for scanning and monitoring
//!
//! ## Usage
//!
//! ### As a Library
//!
//! ```rust,no_run
//! use kindlyguard::server::{SecurityScanner, Threat};
//! use kindlyguard::server::config::ScannerConfig;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a scanner with default configuration
//! let config = ScannerConfig::default();
//! let scanner = SecurityScanner::new(config)?;
//!
//! // Scan some text for threats
//! let threats = scanner.scan_text("Hello, world!")?;
//! println!("Found {} threats", threats.len());
//! # Ok(())
//! # }
//! ```
//!
//! ### Running the MCP Server
//!
//! The server can be run using the `kindly-guard` binary:
//!
//! ```bash
//! kindly-guard --config /path/to/config.toml
//! ```
//!
//! ### Using the CLI
//!
//! The CLI tools can be accessed through the `kindly-guard-cli` binary:
//!
//! ```bash
//! kindly-guard-cli scan --path /path/to/scan
//! kindly-guard-cli monitor --config /path/to/config.toml
//! ```
//!
//! ## Modules
//!
//! - `server`: Core server functionality including scanners, detectors, and MCP protocol
//!
//! ## Re-exports
//!
//! This crate re-exports the main functionality from:
//! - [`kindly-guard-server`](https://docs.rs/kindly-guard-server) - Core server implementation
//!
//! For CLI tools, install the [`kindly-guard-cli`](https://docs.rs/kindly-guard-cli) crate:
//! ```bash
//! cargo install kindly-guard-cli
//! ```
//!
//! For more detailed documentation, please visit:
//! <https://github.com/samduchaine/kindly-guard>

#![doc(html_root_url = "https://docs.rs/kindlyguard/0.9.1")]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(rust_2018_idioms)]

/// Re-export of the server module from kindly-guard-server
///
/// This module provides the core server functionality including:
/// - Scanner for threat detection
/// - MCP protocol implementation
/// - Security detectors and analyzers
/// - Configuration management
pub use kindly_guard_server as server;


// Re-export commonly used types at the crate root for convenience
pub use server::{SecurityScanner, Threat, ThreatType, Severity};
pub use server::security::SecurityContext;
pub use server::config::{Config, ScannerConfig};
pub use server::error::{KindlyError, KindlyResult};

/// Prelude module for convenient imports
///
/// This module re-exports the most commonly used types and traits
/// for easy importing with a single use statement:
///
/// ```rust
/// use kindlyguard::prelude::*;
/// ```
pub mod prelude {
    pub use crate::server::{SecurityScanner, Threat, ThreatType, Severity};
    pub use crate::server::security::SecurityContext;
    pub use crate::server::config::{Config, ScannerConfig};
    pub use crate::server::error::{KindlyError, KindlyResult};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reexports() {
        // Verify that the re-exports are accessible
        let _ = std::any::type_name::<server::SecurityScanner>();
        let _ = std::any::type_name::<server::Threat>();
        let _ = std::any::type_name::<server::config::Config>();
        let _ = std::any::type_name::<server::security::SecurityContext>();
    }
}
