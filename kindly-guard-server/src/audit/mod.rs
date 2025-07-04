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
//! Audit logging system for compliance and security monitoring
//!
//! This module provides a trait-based audit architecture that allows
//! different audit backends while maintaining compliance requirements.
//!
//! # Compliance Standards Support
//!
//! The audit system is designed to meet requirements for:
//! - **GDPR** (General Data Protection Regulation) - EU privacy regulation
//! - **SOC2** (Service Organization Control 2) - Security and availability standards
//! - **HIPAA** (Health Insurance Portability and Accountability Act) - Healthcare data protection
//! - **PCI DSS** (Payment Card Industry Data Security Standard) - Payment processing security
//! - **ISO 27001** - Information security management standards
//!
//! # Key Features
//!
//! - Immutable audit trail with cryptographic integrity verification
//! - Configurable retention policies for compliance
//! - Export capabilities for regulatory reporting
//! - Real-time security event monitoring
//! - Tamper-evident logging with integrity checks
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use kindly_guard_server::audit::{
//!     AuditEventBuilder, AuditEventType, AuditSeverity, AuditLogger
//! };
//!
//! # async fn example(logger: &dyn AuditLogger) -> anyhow::Result<()> {
//! // Log a security event
//! let event = AuditEventBuilder::new(
//!     AuditEventType::ThreatDetected {
//!         client_id: "client-123".to_string(),
//!         threat_count: 5,
//!     },
//!     AuditSeverity::Warning,
//! )
//! .ip_address("192.168.1.100".to_string())
//! .tag("security".to_string())
//! .tag("automated-detection".to_string())
//! .build();
//!
//! logger.log(event).await?;
//! # Ok(())
//! # }
//! ```

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "enhanced")]
pub mod enhanced;
pub mod file;
pub mod memory;
pub mod neutralization;

// Re-exports
pub use file::FileAuditLogger;
pub use memory::InMemoryAuditLogger;

/// Audit event identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEventId(pub String);

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditEventId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

/// Audit event severity levels
///
/// Severity levels determine the importance and urgency of audit events.
/// They are used for filtering, alerting, and compliance reporting.
///
/// # Compliance Mapping
///
/// Different compliance standards require logging at different severity levels:
/// - **SOC2**: All levels required, with Critical events requiring immediate notification
/// - **PCI DSS**: Error and Critical events must trigger security alerts
/// - **HIPAA**: All access events (regardless of severity) must be logged
/// - **ISO 27001**: Critical events require incident response procedures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Informational events for routine operations
    ///
    /// **When to use:**
    /// - Successful authentication/authorization
    /// - Configuration changes (non-security)
    /// - Normal system lifecycle events
    /// - Successful API calls
    ///
    /// **Compliance notes:**
    /// - GDPR: Required for data access logs
    /// - SOC2: Required for access tracking
    /// - Retention: Typically 30-90 days
    Info,

    /// Warning events that may indicate potential issues
    ///
    /// **When to use:**
    /// - Failed authentication attempts (below threshold)
    /// - Rate limiting triggered
    /// - Deprecated API usage
    /// - Performance degradation
    ///
    /// **Compliance notes:**
    /// - PCI DSS: Must be reviewed daily
    /// - SOC2: Requires monitoring and trend analysis
    /// - Retention: Minimum 90 days
    Warning,

    /// Error events indicating operational problems
    ///
    /// **When to use:**
    /// - System errors that don't compromise security
    /// - Service unavailability
    /// - Integration failures
    /// - Data validation errors
    ///
    /// **Compliance notes:**
    /// - SOC2: Must be included in incident reports
    /// - ISO 27001: Requires root cause analysis
    /// - Retention: Minimum 1 year
    Error,

    /// Critical security events requiring immediate attention
    ///
    /// **When to use:**
    /// - Security threats detected and blocked
    /// - Multiple authentication failures (brute force)
    /// - Data breach attempts
    /// - System compromise indicators
    /// - Unauthorized access attempts
    ///
    /// **Compliance notes:**
    /// - ALL standards: Immediate notification required
    /// - PCI DSS: Must trigger security incident response
    /// - HIPAA: Must be reported within 24-72 hours
    /// - SOC2: Requires executive notification
    /// - Retention: Minimum 3-7 years
    Critical,
}

/// Audit event types
///
/// Each event type captures specific security-relevant activities with fields
/// required for compliance reporting and forensic analysis.
///
/// # Compliance Requirements Matrix
///
/// | Event Category | GDPR | SOC2 | HIPAA | PCI DSS | ISO 27001 |
/// |----------------|------|------|-------|---------|-----------|
/// | Authentication | ✓    | ✓    | ✓     | ✓       | ✓         |
/// | Authorization  | ✓    | ✓    | ✓     | ✓       | ✓         |
/// | Security       | ○    | ✓    | ✓     | ✓       | ✓         |
/// | Configuration  | ○    | ✓    | ○     | ✓       | ✓         |
/// | System         | ○    | ✓    | ○     | ○       | ✓         |
///
/// Legend: ✓ = Required, ○ = Recommended
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // ==================== Authentication Events ====================
    /// Successful authentication event
    ///
    /// **Triggered when:** User successfully authenticates to the system
    ///
    /// **Required fields:**
    /// - `user_id`: Unique identifier of the authenticated user (required)
    ///
    /// **Additional context to capture:**
    /// - `authentication_method`: (e.g., "password", "mfa", "sso")
    /// - `session_id`: New session identifier
    /// - `ip_address`: Source IP (auto-captured)
    /// - `user_agent`: Client information (auto-captured)
    ///
    /// **Compliance requirements:**
    /// - GDPR: Required for access logs and user activity tracking
    /// - SOC2: Required for access control monitoring (AC-2)
    /// - HIPAA: Required for user activity tracking (§164.312(b))
    /// - PCI DSS: Required for individual user access (8.1.1)
    /// - ISO 27001: Required for access control (A.9.2.1)
    ///
    /// **Typical severity:** Info
    AuthSuccess { user_id: String },

    /// Failed authentication attempt
    ///
    /// **Triggered when:** Authentication attempt fails for any reason
    ///
    /// **Required fields:**
    /// - `user_id`: Attempted username (optional - may be None for invalid users)
    /// - `reason`: Specific failure reason (required)
    ///
    /// **Additional context to capture:**
    /// - `attempt_count`: Number of consecutive failures
    /// - `authentication_method`: Method attempted
    /// - `ip_address`: Source IP (auto-captured)
    /// - `lockout_triggered`: Whether account was locked
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for security monitoring (CA-7)
    /// - HIPAA: Required for login monitoring (§164.308(a)(5)(ii)(C))
    /// - PCI DSS: Required after 6 attempts (8.1.6)
    /// - ISO 27001: Required for security incident detection
    ///
    /// **Typical severity:** Warning (Error if repeated, Critical if threshold exceeded)
    AuthFailure {
        user_id: Option<String>,
        reason: String,
    },

    // ==================== Authorization Events ====================
    /// Successful resource access
    ///
    /// **Triggered when:** User successfully accesses a protected resource
    ///
    /// **Required fields:**
    /// - `user_id`: User performing the access (required)
    /// - `resource`: Resource identifier/path (required)
    ///
    /// **Additional context to capture:**
    /// - `action`: Specific action performed (read/write/delete)
    /// - `resource_type`: Type of resource accessed
    /// - `data_classification`: Sensitivity level of data
    ///
    /// **Compliance requirements:**
    /// - GDPR: Required for personal data access (Article 30)
    /// - SOC2: Required for logical access monitoring
    /// - HIPAA: Required for PHI access logs (§164.312(a)(1))
    /// - PCI DSS: Required for cardholder data access (10.2.1)
    ///
    /// **Typical severity:** Info
    AccessGranted { user_id: String, resource: String },

    /// Denied resource access attempt
    ///
    /// **Triggered when:** User is denied access to a protected resource
    ///
    /// **Required fields:**
    /// - `user_id`: User attempting access (required)
    /// - `resource`: Resource identifier/path (required)
    /// - `reason`: Denial reason (required)
    ///
    /// **Additional context to capture:**
    /// - `required_permission`: Permission that was missing
    /// - `user_permissions`: Current user permissions
    /// - `escalation_attempted`: If privilege escalation was detected
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for unauthorized access attempts
    /// - HIPAA: Required for access violation tracking
    /// - PCI DSS: Required for all access denials (10.2.4)
    /// - ISO 27001: Required for security monitoring
    ///
    /// **Typical severity:** Warning (Critical if privilege escalation detected)
    AccessDenied {
        user_id: String,
        resource: String,
        reason: String,
    },

    // ==================== Security Events ====================
    /// Security threat detected
    ///
    /// **Triggered when:** System detects potential security threats
    ///
    /// **Required fields:**
    /// - `client_id`: Client/session where threat originated (required)
    /// - `threat_count`: Number of threats detected (required)
    ///
    /// **Additional context to capture:**
    /// - `threat_types`: Array of specific threat types detected
    /// - `threat_details`: Detailed threat information
    /// - `risk_score`: Calculated risk level (0-100)
    /// - `automated_response`: Actions taken automatically
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for security monitoring (SI-4)
    /// - HIPAA: Required for malicious software detection
    /// - PCI DSS: Required for intrusion detection (11.5)
    /// - ISO 27001: Required for security event logging
    ///
    /// **Typical severity:** Warning to Critical (based on threat severity)
    ThreatDetected {
        client_id: String,
        threat_count: u32,
    },

    /// Security threat blocked
    ///
    /// **Triggered when:** System successfully blocks a security threat
    ///
    /// **Required fields:**
    /// - `client_id`: Client/session where threat originated (required)
    /// - `threat_type`: Type of threat blocked (required)
    ///
    /// **Additional context to capture:**
    /// - `block_method`: How the threat was blocked
    /// - `threat_signature`: Pattern/signature that matched
    /// - `confidence_score`: Detection confidence (0-100)
    /// - `false_positive_probability`: Likelihood of false positive
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for incident response (IR-4)
    /// - PCI DSS: Required for security controls (6.6)
    /// - ISO 27001: Required for security control effectiveness
    ///
    /// **Typical severity:** Critical
    ThreatBlocked {
        client_id: String,
        threat_type: String,
    },

    // ==================== Neutralization Events ====================
    /// Threat neutralization initiated
    ///
    /// **Triggered when:** System begins automated threat neutralization
    ///
    /// **Required fields:**
    /// - `client_id`: Client being protected (required)
    /// - `threat_id`: Unique threat identifier (required)
    /// - `threat_type`: Type of threat being neutralized (required)
    ///
    /// **Additional context to capture:**
    /// - `neutralization_strategy`: Method being used
    /// - `estimated_duration`: Expected completion time
    /// - `impact_assessment`: Potential user impact
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for automated response tracking
    /// - ISO 27001: Required for incident handling (A.16.1)
    ///
    /// **Typical severity:** Warning
    NeutralizationStarted {
        client_id: String,
        threat_id: String,
        threat_type: String,
    },

    /// Threat neutralization completed successfully
    ///
    /// **Triggered when:** Threat neutralization completes successfully
    ///
    /// **Required fields:**
    /// - `client_id`: Client that was protected (required)
    /// - `threat_id`: Unique threat identifier (required)
    /// - `action`: Specific action taken (required)
    /// - `duration_ms`: Time taken in milliseconds (required)
    ///
    /// **Additional context to capture:**
    /// - `effectiveness_score`: How well the threat was neutralized
    /// - `side_effects`: Any unintended consequences
    /// - `rollback_available`: Whether action can be reversed
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for incident resolution tracking
    /// - ISO 27001: Required for corrective action records
    ///
    /// **Typical severity:** Info
    NeutralizationCompleted {
        client_id: String,
        threat_id: String,
        action: String,
        duration_ms: u64,
    },

    /// Threat neutralization failed
    ///
    /// **Triggered when:** Neutralization attempt fails
    ///
    /// **Required fields:**
    /// - `client_id`: Client affected (required)
    /// - `threat_id`: Unique threat identifier (required)
    /// - `error`: Error description (required)
    ///
    /// **Additional context to capture:**
    /// - `fallback_action`: Alternative action taken
    /// - `manual_intervention_required`: Whether human action needed
    /// - `threat_persists`: Whether threat is still active
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for incident escalation
    /// - ISO 27001: Required for control failure documentation
    ///
    /// **Typical severity:** Error to Critical
    NeutralizationFailed {
        client_id: String,
        threat_id: String,
        error: String,
    },

    /// Neutralization skipped by policy
    ///
    /// **Triggered when:** Neutralization skipped due to policy/configuration
    ///
    /// **Required fields:**
    /// - `client_id`: Client affected (required)
    /// - `threat_id`: Unique threat identifier (required)
    /// - `reason`: Why neutralization was skipped (required)
    ///
    /// **Additional context to capture:**
    /// - `policy_name`: Specific policy that prevented action
    /// - `override_available`: Whether manual override possible
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for policy compliance tracking
    ///
    /// **Typical severity:** Warning
    NeutralizationSkipped {
        client_id: String,
        threat_id: String,
        reason: String,
    },

    /// Neutralization action rolled back
    ///
    /// **Triggered when:** Previous neutralization is reversed
    ///
    /// **Required fields:**
    /// - `client_id`: Client affected (required)
    /// - `threat_id`: Unique threat identifier (required)
    /// - `reason`: Rollback reason (required)
    ///
    /// **Additional context to capture:**
    /// - `original_action`: What was rolled back
    /// - `rollback_complete`: Whether fully reversed
    /// - `initiated_by`: Automatic or manual rollback
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for change management
    /// - ISO 27001: Required for corrective action tracking
    ///
    /// **Typical severity:** Warning
    NeutralizationRolledBack {
        client_id: String,
        threat_id: String,
        reason: String,
    },

    // ==================== Rate Limiting Events ====================
    /// Rate limit exceeded
    ///
    /// **Triggered when:** Client exceeds configured rate limits
    ///
    /// **Required fields:**
    /// - `client_id`: Client that triggered limit (required)
    /// - `limit_type`: Type of limit exceeded (required)
    ///
    /// **Additional context to capture:**
    /// - `limit_value`: The limit that was exceeded
    /// - `current_value`: Current usage value
    /// - `reset_time`: When limit will reset
    /// - `blocked_requests`: Number of requests blocked
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for availability monitoring
    /// - PCI DSS: Required for DoS protection (6.6)
    ///
    /// **Typical severity:** Warning
    RateLimitTriggered {
        client_id: String,
        limit_type: String,
    },

    // ==================== Configuration Events ====================
    /// Configuration modified
    ///
    /// **Triggered when:** System configuration is changed
    ///
    /// **Required fields:**
    /// - `changed_by`: User/system that made change (required)
    /// - `changes`: Map of changed settings (required)
    ///
    /// **Additional context to capture:**
    /// - `change_reason`: Business justification
    /// - `approval_ticket`: Change management reference
    /// - `rollback_plan`: How to reverse if needed
    /// - `security_impact`: Security implications
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for change management (CC6.1)
    /// - PCI DSS: Required for configuration tracking (2.2)
    /// - ISO 27001: Required for change control (A.12.1.2)
    ///
    /// **Typical severity:** Info (Warning for security settings)
    ConfigChanged {
        changed_by: String,
        changes: HashMap<String, String>,
    },

    /// Configuration reloaded
    ///
    /// **Triggered when:** Configuration is reloaded from source
    ///
    /// **Required fields:**
    /// - `success`: Whether reload succeeded (required)
    /// - `error`: Error message if failed (optional)
    ///
    /// **Additional context to capture:**
    /// - `trigger`: What initiated the reload
    /// - `config_version`: New configuration version
    /// - `validation_results`: Configuration validation outcome
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for operational monitoring
    ///
    /// **Typical severity:** Info (Error if failed)
    ConfigReloaded {
        success: bool,
        error: Option<String>,
    },

    // ==================== Plugin Events ====================
    /// Plugin loaded
    ///
    /// **Triggered when:** Security plugin is loaded
    ///
    /// **Required fields:**
    /// - `plugin_id`: Unique plugin identifier (required)
    /// - `plugin_name`: Human-readable name (required)
    ///
    /// **Additional context to capture:**
    /// - `plugin_version`: Version information
    /// - `plugin_vendor`: Plugin creator/vendor
    /// - `plugin_signature`: Digital signature status
    /// - `capabilities`: What the plugin can access
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for third-party management
    /// - ISO 27001: Required for supplier relationships
    ///
    /// **Typical severity:** Info
    PluginLoaded {
        plugin_id: String,
        plugin_name: String,
    },

    /// Plugin unloaded
    ///
    /// **Triggered when:** Security plugin is unloaded
    ///
    /// **Required fields:**
    /// - `plugin_id`: Unique plugin identifier (required)
    /// - `reason`: Why plugin was unloaded (required)
    ///
    /// **Additional context to capture:**
    /// - `initiated_by`: Manual or automatic unload
    /// - `cleanup_status`: Whether resources were freed
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for component lifecycle tracking
    ///
    /// **Typical severity:** Info (Warning if error-triggered)
    PluginUnloaded { plugin_id: String, reason: String },

    /// Plugin error
    ///
    /// **Triggered when:** Plugin encounters an error
    ///
    /// **Required fields:**
    /// - `plugin_id`: Plugin that errored (required)
    /// - `error`: Error description (required)
    ///
    /// **Additional context to capture:**
    /// - `error_code`: Specific error code
    /// - `stack_trace`: Technical details (sanitized)
    /// - `recovery_action`: Automatic recovery attempted
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for third-party monitoring
    ///
    /// **Typical severity:** Error
    PluginError { plugin_id: String, error: String },

    // ==================== System Events ====================
    /// Server started
    ///
    /// **Triggered when:** Security server starts up
    ///
    /// **Required fields:**
    /// - `version`: Server version (required)
    ///
    /// **Additional context to capture:**
    /// - `startup_time_ms`: Time to become operational
    /// - `config_source`: Where configuration was loaded from
    /// - `features_enabled`: Active feature flags
    /// - `security_mode`: Current security posture
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for availability tracking
    /// - ISO 27001: Required for operational procedures
    ///
    /// **Typical severity:** Info
    ServerStarted { version: String },

    /// Server stopped
    ///
    /// **Triggered when:** Security server shuts down
    ///
    /// **Required fields:**
    /// - `reason`: Shutdown reason (required)
    ///
    /// **Additional context to capture:**
    /// - `shutdown_type`: Graceful or forced
    /// - `active_connections`: Connections at shutdown
    /// - `cleanup_complete`: Whether cleanup finished
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for availability tracking
    /// - ISO 27001: Required for operational procedures
    ///
    /// **Typical severity:** Info (Error if unexpected)
    ServerStopped { reason: String },

    /// System error
    ///
    /// **Triggered when:** System-level error occurs
    ///
    /// **Required fields:**
    /// - `component`: System component affected (required)
    /// - `error`: Error description (required)
    ///
    /// **Additional context to capture:**
    /// - `error_type`: Category of error
    /// - `impact`: User/system impact assessment
    /// - `auto_recovery`: Whether self-healing attempted
    ///
    /// **Compliance requirements:**
    /// - SOC2: Required for system monitoring
    /// - ISO 27001: Required for incident management
    ///
    /// **Typical severity:** Error to Critical
    SystemError { component: String, error: String },

    // ==================== Custom Events ====================
    /// Custom audit event
    ///
    /// **Triggered when:** Application needs to log custom security events
    ///
    /// **Required fields:**
    /// - `event_type`: Custom event type name (required)
    /// - `data`: Event-specific data (required)
    ///
    /// **Additional context to capture:**
    /// - Should follow same context patterns as standard events
    /// - Must include compliance-relevant fields
    ///
    /// **Compliance requirements:**
    /// - Must map to appropriate compliance categories
    /// - Must include required fields for relevant standards
    ///
    /// **Typical severity:** Varies by event type
    Custom {
        event_type: String,
        data: serde_json::Value,
    },
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: AuditEventId,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Event severity
    pub severity: AuditSeverity,
    /// Client/session ID if applicable
    pub client_id: Option<String>,
    /// IP address if applicable
    pub ip_address: Option<String>,
    /// User agent if applicable
    pub user_agent: Option<String>,
    /// Additional context
    pub context: HashMap<String, serde_json::Value>,
    /// Event tags for filtering
    pub tags: Vec<String>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(event_type: AuditEventType, severity: AuditSeverity) -> Self {
        Self {
            id: AuditEventId::new(),
            timestamp: Utc::now(),
            event_type,
            severity,
            client_id: None,
            ip_address: None,
            user_agent: None,
            context: HashMap::new(),
            tags: Vec::new(),
        }
    }

    /// Set client ID
    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    /// Set IP address
    pub fn with_ip_address(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Add context data
    pub fn with_context(mut self, key: String, value: serde_json::Value) -> Self {
        self.context.insert(key, value);
        self
    }

    /// Add tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Audit query filter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by severity (minimum level)
    pub min_severity: Option<AuditSeverity>,
    /// Filter by event type pattern
    pub event_type_pattern: Option<String>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by IP address
    pub ip_address: Option<String>,
    /// Filter by time range (start)
    pub start_time: Option<DateTime<Utc>>,
    /// Filter by time range (end)
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by tags (any match)
    pub tags: Vec<String>,
    /// Maximum results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Audit statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total events logged
    pub total_events: u64,
    /// Events by severity
    pub events_by_severity: HashMap<String, u64>,
    /// Events by type
    pub events_by_type: HashMap<String, u64>,
    /// Storage size in bytes
    pub storage_size_bytes: u64,
    /// Oldest event timestamp
    pub oldest_event: Option<DateTime<Utc>>,
    /// Newest event timestamp
    pub newest_event: Option<DateTime<Utc>>,
}

/// Audit logger trait
///
/// The core trait that all audit logger implementations must satisfy.
/// Implementations must ensure compliance with security and regulatory requirements.
///
/// # Security Requirements
///
/// All implementations MUST:
/// 1. **Immutability**: Events once written cannot be modified or deleted (except by retention policy)
/// 2. **Integrity**: Provide mechanisms to detect tampering (e.g., checksums, digital signatures)
/// 3. **Availability**: Ensure audit logs remain accessible even during system failures
/// 4. **Confidentiality**: Protect sensitive data in logs (encryption at rest/in transit)
/// 5. **Non-repudiation**: Ensure actions cannot be denied (timestamps, user identification)
///
/// # Compliance Implementation Notes
///
/// - **GDPR**: Implement data minimization - only log necessary data
/// - **HIPAA**: Ensure encryption for any PHI in audit logs
/// - **PCI DSS**: Implement secure log storage with access controls
/// - **SOC2**: Provide continuous monitoring and alerting capabilities
/// - **ISO 27001**: Implement log integrity checking and secure timestamps
///
/// # Performance Considerations
///
/// - Logging must not significantly impact system performance
/// - Batch operations should be preferred for high-volume scenarios
/// - Consider using write-ahead logging for critical events
/// - Implement appropriate buffering and async I/O
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Log a single audit event
    ///
    /// # Requirements
    /// - MUST be atomic - either fully logged or not at all
    /// - MUST return unique event ID for tracking
    /// - MUST capture timestamp at log time if not provided
    /// - SHOULD complete within 100ms for critical events
    ///
    /// # Compliance Notes
    /// - Critical events may require synchronous logging
    /// - Some regulations require immediate persistence
    async fn log(&self, event: AuditEvent) -> Result<AuditEventId>;

    /// Log multiple events in an atomic batch
    ///
    /// # Requirements
    /// - All events succeed or all fail (transactional)
    /// - Order must be preserved
    /// - More efficient than multiple log() calls
    ///
    /// # Compliance Notes
    /// - Useful for correlated events that must be logged together
    /// - May improve performance for high-volume logging
    async fn log_batch(&self, events: Vec<AuditEvent>) -> Result<Vec<AuditEventId>>;

    /// Query audit events with filtering
    ///
    /// # Requirements
    /// - MUST NOT allow modification of returned events
    /// - MUST respect access controls (who can see what)
    /// - SHOULD support efficient pagination
    /// - SHOULD optimize common query patterns
    ///
    /// # Compliance Notes
    /// - GDPR: May need to filter out personal data based on consent
    /// - HIPAA: Must enforce minimum necessary standard
    /// - Results must be immutable copies
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>>;

    /// Retrieve a specific event by ID
    ///
    /// # Requirements
    /// - MUST return exact event as originally logged
    /// - MUST verify integrity if available
    ///
    /// # Compliance Notes
    /// - Used for forensic investigation
    /// - May be required for legal proceedings
    async fn get_event(&self, id: &AuditEventId) -> Result<Option<AuditEvent>>;

    /// Delete events older than specified timestamp
    ///
    /// # Requirements
    /// - MUST only delete based on retention policy
    /// - MUST log the deletion action itself
    /// - SHOULD archive before deletion if required
    /// - MUST be irreversible
    ///
    /// # Compliance Notes
    /// - GDPR: Right to erasure may require selective deletion
    /// - Most standards require specific retention periods
    /// - Some events may have legal hold requirements
    /// - Deletion must be audited as a critical event
    async fn delete_before(&self, timestamp: DateTime<Utc>) -> Result<u64>;

    /// Get audit log statistics
    ///
    /// # Requirements
    /// - MUST NOT impact ongoing logging
    /// - SHOULD cache results appropriately
    ///
    /// # Compliance Notes
    /// - Used for compliance reporting
    /// - Helps identify unusual patterns
    async fn get_stats(&self) -> Result<AuditStats>;

    /// Export events in specified format
    ///
    /// # Requirements
    /// - MUST preserve all event data
    /// - MUST include integrity information
    /// - SHOULD support standard formats (CEF, SYSLOG)
    ///
    /// # Compliance Notes
    /// - Required for regulatory reporting
    /// - May need to redact sensitive data
    /// - Format must be suitable for long-term archival
    async fn export(&self, filter: AuditFilter, format: ExportFormat) -> Result<Vec<u8>>;

    /// Verify integrity of audit logs
    ///
    /// # Requirements
    /// - MUST detect any tampering or corruption
    /// - MUST NOT modify logs during verification
    /// - SHOULD be efficient for large log volumes
    ///
    /// # Compliance Notes
    /// - PCI DSS: Required for log integrity monitoring (10.5.5)
    /// - SOC2: Part of security monitoring controls
    /// - Should be run periodically and after incidents
    /// - Results must be logged as audit events
    async fn verify_integrity(&self) -> Result<IntegrityReport>;
}

/// Export formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
    Syslog,
    Cef, // Common Event Format
}

/// Integrity verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Is integrity intact
    pub intact: bool,
    /// Total events checked
    pub events_checked: u64,
    /// Any issues found
    pub issues: Vec<String>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
}

/// Audit logger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Audit backend type
    pub backend: AuditBackend,
    /// Retention period in days
    pub retention_days: u32,
    /// Maximum events to keep
    pub max_events: Option<u64>,
    /// Buffer size for batch operations
    pub buffer_size: usize,
    /// File path (for file backend)
    pub file_path: Option<String>,
    /// Rotation settings (for file backend)
    pub rotation: Option<RotationConfig>,
    /// Enable compression
    pub compress: bool,
    /// Enable encryption
    pub encrypt: bool,
    /// Custom backend configuration
    pub custom_config: HashMap<String, serde_json::Value>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: AuditBackend::Memory,
            retention_days: 90,
            max_events: Some(1_000_000),
            buffer_size: 1000,
            file_path: Some("./audit.log".to_string()),
            rotation: Some(RotationConfig::default()),
            compress: false,
            encrypt: false,
            custom_config: HashMap::new(),
        }
    }
}

/// Audit backend types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditBackend {
    Memory,
    File,
    #[cfg(feature = "enhanced")]
    Enhanced,
    Custom(String),
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Rotation strategy
    pub strategy: RotationStrategy,
    /// Maximum file size (for size-based rotation)
    pub max_size_mb: u64,
    /// Maximum file age (for time-based rotation)
    pub max_age_hours: u64,
    /// Maximum number of backups to keep
    pub max_backups: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            strategy: RotationStrategy::Size,
            max_size_mb: 100,
            max_age_hours: 24,
            max_backups: 10,
        }
    }
}

/// Rotation strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationStrategy {
    Size,
    Time,
    Both,
}

/// Factory for creating audit loggers
pub trait AuditLoggerFactory: Send + Sync {
    /// Create an audit logger
    fn create(&self, config: &AuditConfig) -> Result<Arc<dyn AuditLogger>>;
}

/// Default audit logger factory
pub struct DefaultAuditLoggerFactory;

impl AuditLoggerFactory for DefaultAuditLoggerFactory {
    fn create(&self, config: &AuditConfig) -> Result<Arc<dyn AuditLogger>> {
        if !config.enabled {
            // Return a no-op logger when disabled
            return Ok(Arc::new(NoOpAuditLogger));
        }

        match &config.backend {
            AuditBackend::Memory => Ok(Arc::new(InMemoryAuditLogger::new(config.clone())?)),
            AuditBackend::File => Ok(Arc::new(FileAuditLogger::new(config.clone())?)),
            #[cfg(feature = "enhanced")]
            AuditBackend::Enhanced => Ok(Arc::new(enhanced::EnhancedAuditLogger::new(
                config.clone(),
            )?)),
            AuditBackend::Custom(name) => Err(anyhow::anyhow!(
                "Custom audit backend '{}' not implemented",
                name
            )),
        }
    }
}

/// No-op audit logger for when auditing is disabled
struct NoOpAuditLogger;

#[async_trait]
impl AuditLogger for NoOpAuditLogger {
    async fn log(&self, _event: AuditEvent) -> Result<AuditEventId> {
        Ok(AuditEventId::new())
    }

    async fn log_batch(&self, events: Vec<AuditEvent>) -> Result<Vec<AuditEventId>> {
        Ok(events.into_iter().map(|_| AuditEventId::new()).collect())
    }

    async fn query(&self, _filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        Ok(Vec::new())
    }

    async fn get_event(&self, _id: &AuditEventId) -> Result<Option<AuditEvent>> {
        Ok(None)
    }

    async fn delete_before(&self, _timestamp: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }

    async fn get_stats(&self) -> Result<AuditStats> {
        Ok(AuditStats::default())
    }

    async fn export(&self, _filter: AuditFilter, _format: ExportFormat) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    async fn verify_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            intact: true,
            events_checked: 0,
            issues: Vec::new(),
            verified_at: Utc::now(),
        })
    }
}

/// Helper for creating audit events
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    pub fn new(event_type: AuditEventType, severity: AuditSeverity) -> Self {
        Self {
            event: AuditEvent::new(event_type, severity),
        }
    }

    pub fn client_id(mut self, id: String) -> Self {
        self.event.client_id = Some(id);
        self
    }

    pub fn ip_address(mut self, ip: String) -> Self {
        self.event.ip_address = Some(ip);
        self
    }

    pub fn user_agent(mut self, ua: String) -> Self {
        self.event.user_agent = Some(ua);
        self
    }

    pub fn context(mut self, key: String, value: serde_json::Value) -> Self {
        self.event.context.insert(key, value);
        self
    }

    pub fn tag(mut self, tag: String) -> Self {
        self.event.tags.push(tag);
        self
    }

    pub fn build(self) -> AuditEvent {
        self.event
    }
}

// ==================== COMPLIANCE REFERENCE GUIDE ====================

/// Compliance reference guide for audit requirements
///
/// This module provides detailed mapping between compliance standards and audit requirements.
/// Use this guide to ensure your audit configuration meets regulatory requirements.
pub mod compliance {
    /// GDPR (General Data Protection Regulation) Requirements
    ///
    /// # Required Events
    /// - AuthSuccess/AuthFailure - Track who accesses personal data
    /// - AccessGranted/AccessDenied - Monitor data access attempts
    /// - ConfigChanged - Track consent and privacy settings changes
    ///
    /// # Key Requirements
    /// - Data minimization: Only log necessary information
    /// - Right to erasure: Must support selective deletion
    /// - Data portability: Export functionality required
    /// - Breach notification: Critical events within 72 hours
    ///
    /// # Retention
    /// - Access logs: 6 months typical
    /// - Security events: 1 year
    /// - Consent records: Duration of processing + 3 years
    pub struct GDPR;

    /// SOC2 (Service Organization Control 2) Requirements
    ///
    /// # Required Events
    /// - ALL authentication and authorization events
    /// - ALL security events (threat detection/blocking)
    /// - Configuration changes
    /// - System lifecycle events
    /// - Rate limiting (availability)
    ///
    /// # Key Requirements
    /// - Continuous monitoring and alerting
    /// - Change management tracking
    /// - Incident response documentation
    /// - Access control monitoring
    ///
    /// # Retention
    /// - Minimum 1 year for all events
    /// - 3 years for security incidents
    /// - 7 years for critical events
    pub struct SOC2;

    /// HIPAA (Health Insurance Portability and Accountability Act) Requirements
    ///
    /// # Required Events
    /// - ALL authentication events (successful and failed)
    /// - ALL authorization events (PHI access)
    /// - System errors that could affect PHI
    /// - Configuration changes affecting security
    ///
    /// # Key Requirements
    /// - Encryption required for PHI in logs
    /// - Minimum necessary standard for access
    /// - User activity tracking mandatory
    /// - Regular log reviews required
    ///
    /// # Retention
    /// - 6 years minimum for all PHI-related events
    /// - Immediate notification for breaches
    pub struct HIPAA;

    /// PCI DSS (Payment Card Industry Data Security Standard) Requirements
    ///
    /// # Required Events
    /// - User access to cardholder data (10.2.1)
    /// - All administrator actions (10.2.2)
    /// - Access to audit trails (10.2.3)
    /// - Invalid access attempts (10.2.4)
    /// - Authentication/authorization changes (10.2.5)
    /// - System/log initialization (10.2.6)
    /// - System-level object changes (10.2.7)
    ///
    /// # Key Requirements
    /// - Daily log review required
    /// - Secure centralized logging
    /// - Log integrity monitoring
    /// - Time synchronization critical
    ///
    /// # Retention
    /// - 1 year online, readily available
    /// - 3 months immediately accessible
    /// - Secure archival after 1 year
    pub struct PciDss;

    /// ISO 27001 Information Security Management Requirements
    ///
    /// # Required Events
    /// - ALL security events
    /// - Access control events
    /// - System changes and errors
    /// - Security control effectiveness
    ///
    /// # Key Requirements
    /// - Risk-based approach to logging
    /// - Regular log analysis and review
    /// - Incident management integration
    /// - Corrective action tracking
    ///
    /// # Retention
    /// - Based on risk assessment
    /// - Typically 1-3 years minimum
    /// - 7 years for major incidents
    pub struct ISO27001;

    /// Quick reference: Event types by compliance standard
    ///
    /// ```text
    /// | Event Type                | GDPR | SOC2 | HIPAA | PCI DSS | ISO 27001 |
    /// |---------------------------|------|------|-------|---------|-----------|
    /// | AuthSuccess              | ✓    | ✓    | ✓     | ✓       | ✓         |
    /// | AuthFailure              | ✓    | ✓    | ✓     | ✓       | ✓         |
    /// | AccessGranted            | ✓    | ✓    | ✓     | ✓       | ✓         |
    /// | AccessDenied             | ✓    | ✓    | ✓     | ✓       | ✓         |
    /// | ThreatDetected           | ○    | ✓    | ✓     | ✓       | ✓         |
    /// | ThreatBlocked            | ○    | ✓    | ✓     | ✓       | ✓         |
    /// | NeutralizationStarted    |      | ✓    |       |         | ✓         |
    /// | NeutralizationCompleted  |      | ✓    |       |         | ✓         |
    /// | NeutralizationFailed     |      | ✓    |       |         | ✓         |
    /// | RateLimitTriggered       |      | ✓    |       | ✓       |           |
    /// | ConfigChanged            | ○    | ✓    | ○     | ✓       | ✓         |
    /// | ServerStarted            |      | ✓    |       | ✓       | ✓         |
    /// | ServerStopped            |      | ✓    |       | ✓       | ✓         |
    /// | SystemError              |      | ✓    | ○     |         | ✓         |
    ///
    /// Legend: ✓ = Required, ○ = Recommended
    /// ```
    pub struct ComplianceMatrix;

    /// Recommended audit configuration for multi-compliance
    ///
    /// ```toml
    /// [audit]
    /// enabled = true
    /// backend = "file"  # or "enhanced" for high-security environments
    /// retention_days = 2555  # 7 years for maximum compliance
    /// encrypt = true  # Required for HIPAA
    /// compress = true  # For efficient storage
    ///
    /// [audit.alerts]
    /// critical_events = ["email", "siem"]  # Immediate notification
    /// threshold_events = ["email"]  # Repeated failures, rate limits
    ///
    /// [audit.integrity]
    /// checksum = "sha256"  # For tamper detection
    /// verify_interval = "daily"  # PCI DSS requirement
    /// ```
    pub struct RecommendedConfig;
}
