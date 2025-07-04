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

mod mcp_detector;
mod config_writer;
mod interactive;

// Re-export public types and traits
pub use mcp_detector::{McpDetector, IdeType, ConfigFormat, ConfigLocation};
pub use config_writer::{ConfigWriter, JsonConfigWriter, JsonLocalConfigWriter, 
                       TomlConfigWriter, YamlConfigWriter, create_config_writer};

// Re-export interactive utilities
pub use interactive::{
    prompt_ide_selection,
    confirm_action,
    show_setup_result,
    format_config_preview,
    show_progress,
    complete_progress,
    print_welcome_banner,
    print_section_header,
    run_setup_wizard,
};