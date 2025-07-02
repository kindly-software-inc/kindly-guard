//! MCP Protocol implementation with Claude Code extensions
//!
//! This module provides the core MCP protocol types and the Claude Code
//! specific extensions for shield status monitoring.

// Core protocol types
pub mod types;
pub use types::*;

// Claude Code extensions
pub mod claude_code;

pub use claude_code::{
    create_status_notification, threat_to_severity, ClaudeCodeError, ClaudeCodeErrorCode,
    LastThreatInfo, PerformanceMetrics, ShieldConfig, ShieldControlAction, ShieldControlRequest,
    ShieldControlResponse, ShieldInfoParams, ShieldInfoResponse, ShieldState, ShieldStatistics,
    ShieldStatusNotification, ShieldStatusParams, ThreatPattern, ThreatSeverity,
};

#[cfg(feature = "enhanced")]
pub use claude_code::{BinaryMessageHeader, BinaryShieldStatus};