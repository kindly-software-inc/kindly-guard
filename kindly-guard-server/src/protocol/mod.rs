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
pub use claude_code::BinaryMessageHeader;
