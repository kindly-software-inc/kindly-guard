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
//! Claude Code specific MCP protocol extensions
//!
//! This module defines the MCP protocol extensions for Claude Code integration,
//! providing real-time shield status notifications and control methods.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Shield status notification for Claude Code
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldStatusNotification {
    /// Always "2.0" for JSON-RPC
    pub jsonrpc: String,
    /// Method name: "shield/status"
    pub method: String,
    /// Shield status parameters
    pub params: ShieldStatusParams,
}

/// Shield status parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldStatusParams {
    /// Is the shield currently active
    pub active: bool,
    /// Is enhanced mode enabled
    pub enhanced: bool,
    /// Total number of threats blocked
    pub threats: u64,
    /// Threat detection rate per minute
    pub threat_rate: f64,
    /// Last detected threat information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_threat: Option<LastThreatInfo>,
    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// Information about the last detected threat
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastThreatInfo {
    /// Type of threat detected
    #[serde(rename = "type")]
    pub threat_type: String,
    /// Severity level
    pub severity: ThreatSeverity,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Human-readable description
    pub description: String,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Performance metrics for Claude Code monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PerformanceMetrics {
    /// Last scan time in microseconds
    pub scan_time_us: u64,
    /// Current queue depth
    pub queue_depth: usize,
    /// Memory usage in MB
    pub memory_mb: f64,
}

/// Shield control request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldControlRequest {
    /// Control action to perform
    pub action: ShieldControlAction,
    /// Optional duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
}

/// Shield control actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShieldControlAction {
    /// Temporarily pause shield
    Pause,
    /// Resume shield operation
    Resume,
    /// Reset statistics
    Reset,
    /// Enable enhanced mode
    Enhance,
}

/// Shield control response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldControlResponse {
    /// Whether the action was successful
    pub success: bool,
    /// New shield state after action
    pub state: ShieldState,
    /// Optional message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Current shield state
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldState {
    /// Is shield active
    pub active: bool,
    /// Is paused
    pub paused: bool,
    /// Enhanced mode enabled
    pub enhanced: bool,
    /// Pause end time (if paused)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_until: Option<u64>,
}

/// Shield info request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldInfoParams {
    /// Request detailed information
    #[serde(default)]
    pub detailed: bool,
}

/// Shield info response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldInfoResponse {
    /// Shield version
    pub version: String,
    /// Current state
    pub state: ShieldState,
    /// Statistics
    pub stats: ShieldStatistics,
    /// Configuration (if detailed requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ShieldConfig>,
    /// Threat patterns (if detailed requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<ThreatPattern>>,
}

/// Shield statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldStatistics {
    /// Total threats blocked
    pub threats_blocked: u64,
    /// Threats by type
    pub threats_by_type: std::collections::HashMap<String, u64>,
    /// Total scans performed
    pub total_scans: u64,
    /// Average scan time in microseconds
    pub avg_scan_time_us: u64,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Memory usage in MB
    pub memory_usage_mb: f64,
}

/// Shield configuration info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShieldConfig {
    /// Scanner sensitivity level
    pub sensitivity: String,
    /// Enabled threat detectors
    pub enabled_detectors: Vec<String>,
    /// Rate limiting enabled
    pub rate_limiting: bool,
    /// Max threats per minute before blocking
    pub max_threat_rate: u64,
}

/// Threat pattern information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatPattern {
    /// Pattern name
    pub name: String,
    /// Pattern type
    #[serde(rename = "type")]
    pub pattern_type: String,
    /// Is enabled
    pub enabled: bool,
    /// Detection count
    pub detections: u64,
}

/// Claude Code specific errors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeCodeError {
    /// Error code
    pub code: ClaudeCodeErrorCode,
    /// Error message
    pub message: String,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Claude Code error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaudeCodeErrorCode {
    /// Shield is not available
    ShieldUnavailable = -40001,
    /// Invalid control action
    InvalidAction = -40002,
    /// Operation timeout
    OperationTimeout = -40003,
    /// Enhanced mode not available
    EnhancedModeUnavailable = -40004,
    /// Rate limit exceeded
    RateLimitExceeded = -40005,
}

/// Binary protocol message header (enhanced mode)
#[cfg(feature = "enhanced")]
#[repr(C, packed)]
pub struct BinaryMessageHeader {
    /// Magic number: 0x4B475344 ('KGSD')
    pub magic: u32,
    /// Protocol version
    pub version: u16,
    /// Message type
    pub msg_type: u16,
    /// Payload length
    pub payload_len: u32,
    /// Timestamp (nanoseconds since epoch)
    pub timestamp: u64,
    /// Sequence number
    pub sequence: u32,
    /// Checksum
    pub checksum: u32,
}

#[cfg(feature = "enhanced")]
impl BinaryMessageHeader {
    pub const MAGIC: u32 = 0x4B475344; // 'KGSD'
    pub const VERSION: u16 = 1;

    pub const MSG_TYPE_STATUS: u16 = 1;
    pub const MSG_TYPE_THREAT: u16 = 2;
    pub const MSG_TYPE_CONTROL: u16 = 3;
    pub const MSG_TYPE_PERF: u16 = 4;
}

/// Helper to create shield status notification
pub fn create_status_notification(params: ShieldStatusParams) -> ShieldStatusNotification {
    ShieldStatusNotification {
        jsonrpc: "2.0".to_string(),
        method: "shield/status".to_string(),
        params,
    }
}

/// Helper to convert threat to severity
pub fn threat_to_severity(threat: &crate::scanner::Threat) -> ThreatSeverity {
    match &threat.threat_type {
        crate::scanner::ThreatType::UnicodeInvisible => ThreatSeverity::Medium,
        crate::scanner::ThreatType::UnicodeBiDi => ThreatSeverity::High,
        crate::scanner::ThreatType::UnicodeHomograph => ThreatSeverity::Medium,
        crate::scanner::ThreatType::UnicodeControl => ThreatSeverity::Medium,
        crate::scanner::ThreatType::PromptInjection => ThreatSeverity::High,
        crate::scanner::ThreatType::CommandInjection => ThreatSeverity::Critical,
        crate::scanner::ThreatType::PathTraversal => ThreatSeverity::High,
        crate::scanner::ThreatType::SqlInjection => ThreatSeverity::Critical,
        crate::scanner::ThreatType::CrossSiteScripting => ThreatSeverity::High,
        crate::scanner::ThreatType::LdapInjection => ThreatSeverity::High,
        crate::scanner::ThreatType::XmlInjection => ThreatSeverity::High,
        crate::scanner::ThreatType::NoSqlInjection => ThreatSeverity::High,
        crate::scanner::ThreatType::SessionIdExposure => ThreatSeverity::Critical,
        crate::scanner::ThreatType::ToolPoisoning => ThreatSeverity::Critical,
        crate::scanner::ThreatType::TokenTheft => ThreatSeverity::Critical,
        crate::scanner::ThreatType::DosPotential => ThreatSeverity::High,
        crate::scanner::ThreatType::Custom(_) => ThreatSeverity::Medium,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_notification_serialization() {
        let notification = create_status_notification(ShieldStatusParams {
            active: true,
            enhanced: false,
            threats: 42,
            threat_rate: 2.5,
            last_threat: Some(LastThreatInfo {
                threat_type: "unicode_bidi".to_string(),
                severity: ThreatSeverity::High,
                timestamp: 1234567890,
                description: "Right-to-left override detected".to_string(),
            }),
            performance: PerformanceMetrics {
                scan_time_us: 123,
                queue_depth: 5,
                memory_mb: 45.6,
            },
        });

        let json = serde_json::to_string_pretty(&notification).unwrap();
        assert!(json.contains("\"method\": \"shield/status\""));
        assert!(json.contains("\"threats\": 42"));
        assert!(json.contains("\"severity\": \"high\""));
    }

    #[test]
    fn test_control_request_deserialization() {
        let json = r#"{
            "action": "pause",
            "duration": 5000
        }"#;

        let request: ShieldControlRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.action, ShieldControlAction::Pause);
        assert_eq!(request.duration, Some(5000));
    }

    #[cfg(feature = "enhanced")]
    #[test]
    fn test_binary_header() {
        use std::mem;

        assert_eq!(mem::size_of::<BinaryMessageHeader>(), 28);
        assert_eq!(BinaryMessageHeader::MAGIC, 0x4B475344);
    }
}
