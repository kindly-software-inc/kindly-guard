//! Setup utilities for KindlyGuard MCP server
//!
//! This module provides utilities for detecting IDE environments and generating
//! appropriate MCP configuration files. It supports multiple IDEs including
//! Claude Desktop, Claude Code, VS Code, Cursor, and Neovim.
//!
//! # Example
//!
//! ```no_run
//! use kindly_guard_server::setup::{McpDetector, IdeType};
//!
//! // Create detector
//! let detector = McpDetector::new();
//!
//! // Detect active IDE
//! match detector.detect_active_ide() {
//!     Ok(ide) => println!("Active IDE: {}", ide.as_str()),
//!     Err(e) => eprintln!("Error detecting IDE: {}", e),
//! }
//!
//! // Find all MCP configurations
//! if let Ok(configs) = detector.detect_all() {
//!     for config in configs.iter().filter(|c| c.exists) {
//!         println!("Found config: {} at {}",
//!                  config.ide.as_str(),
//!                  config.path.display());
//!     }
//! }
//! ```

mod config_writer;
mod interactive;
mod mcp_detector;

// Re-export public types and traits
pub use config_writer::{
    create_config_writer, ConfigWriter, JsonConfigWriter, JsonLocalConfigWriter, TomlConfigWriter,
    YamlConfigWriter,
};
pub use mcp_detector::{ConfigFormat, ConfigLocation, IdeType, McpDetector};

// Re-export interactive utilities
pub use interactive::{
    complete_progress, confirm_action, format_config_preview, print_section_header,
    print_welcome_banner, prompt_ide_selection, run_setup_wizard, show_progress, show_setup_result,
};
