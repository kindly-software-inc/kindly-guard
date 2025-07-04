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
//! Error handling and recovery mechanisms for production resilience
//!
//! This module provides comprehensive error handling with security-aware design.
//! All error types are designed to fail securely and prevent information leakage.
//!
//! # Security Principles
//!
//! 1. **Fail Closed**: Security errors always fail closed (deny by default)
//! 2. **Information Hiding**: Never expose internal details in external errors
//! 3. **Audit Trail**: All security errors generate audit events
//! 4. **Recovery Strategies**: Each error type has defined recovery behavior
//! 5. **Rate Limiting**: Authentication errors trigger progressive penalties

use anyhow::Result;
use std::io;
use thiserror::Error;

/// Type alias for Result with `KindlyError`
pub type KindlyResult<T> = Result<T, KindlyError>;

/// Extension trait for Result types
pub trait ResultExt<T> {
    /// Convert to `KindlyResult`
    fn kindly(self) -> KindlyResult<T>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: Into<anyhow::Error>,
{
    fn kindly(self) -> KindlyResult<T> {
        self.map_err(|e| KindlyError::ConfigError(e.into().to_string()))
    }
}

/// `KindlyGuard` error types with actionable recovery strategies
#[derive(Error, Debug)]
pub enum KindlyError {
    // Display and UI errors
    #[error("Display rendering failed: {0}")]
    DisplayError(String),

    #[error("Terminal not available")]
    TerminalError,

    // Validation errors
    /// Command validation failed. This occurs when user input doesn't meet
    /// expected format or contains forbidden patterns.
    ///
    /// **Security Impact**: Medium - Could indicate probing for vulnerabilities
    /// **Recovery**: Fail fast, log attempt, increment failure counter
    /// **Safe Handling**: Never echo back the invalid input verbatim
    #[error("Command validation failed: {0}")]
    ValidationError(String),

    /// Invalid input detected during parameter validation.
    ///
    /// **Security Impact**: High - Often precedes injection attacks
    /// **Recovery**: Reject immediately, audit log with sanitized details
    /// **Safe Handling**: Return generic "Invalid input" without specifics
    /// **Example**: SQL injection attempts, path traversal patterns
    #[error("Invalid input: {reason}")]
    InvalidInput { reason: String },

    #[error("Invalid configuration: {field}: {reason}")]
    InvalidConfig { field: String, reason: String },

    // IO errors
    #[error("File operation failed: {0}")]
    FileError(#[from] io::Error),

    #[error("Path not found: {path}")]
    PathNotFound { path: String },

    // Serialization errors
    #[error("JSON serialization failed: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Format error: expected {expected}, got {actual}")]
    FormatError { expected: String, actual: String },

    // Scanner errors
    #[error("Scanner initialization failed: {0}")]
    ScannerError(String),

    /// **CRITICAL SECURITY ERROR**: Active threat detected in input/output.
    ///
    /// **When It Occurs**:
    /// - Unicode attacks (invisible characters, RTL override)
    /// - Injection attempts (SQL, command, path traversal)
    /// - Known malicious patterns
    ///
    /// **Security Impact**: CRITICAL - Active attack in progress
    /// **Recovery**: ALWAYS FAIL CLOSED
    /// - Block the request immediately
    /// - Generate high-priority audit event
    /// - Increment threat counter for client
    /// - Consider temporary IP ban after repeated attempts
    ///
    /// **Safe Handling**:
    /// - NEVER include threat details in user-facing messages
    /// - Log full details to secure audit log only
    /// - Return generic "Security policy violation" to client
    /// - Preserve evidence for forensic analysis
    ///
    /// **Example Response**:
    /// ```json
    /// {
    ///   "error": {
    ///     "code": -32004,
    ///     "message": "Request blocked by security policy"
    ///   }
    /// }
    /// ```
    #[error("Threat detected: {threat_type} at {location}")]
    ThreatDetected {
        threat_type: String,
        location: String,
    },

    // Resource errors
    /// Resource exhaustion detected - possible DoS attempt.
    ///
    /// **Security Impact**: High - Resource exhaustion attacks
    /// **Recovery**: Rate limit, circuit break, graceful degradation
    /// **Safe Handling**: Generic message, preserve service availability
    ///
    /// **Common Scenarios**:
    /// - Memory limit exceeded (large file uploads)
    /// - Connection pool exhausted (connection flood)
    /// - CPU quota exceeded (computational DoS)
    ///
    /// **Response Strategy**:
    /// - Apply exponential backoff to client
    /// - Shed load if necessary
    /// - Return 503 Service Unavailable with Retry-After header
    #[error("Resource limit exceeded: {resource}: {limit}")]
    ResourceError { resource: String, limit: String },

    /// Operation timeout - prevents indefinite resource holding.
    ///
    /// **Security Impact**: Medium - Possible slowloris attack
    /// **Recovery**: Clean up resources, fail fast
    /// **Safe Handling**: No internal timing information in response
    #[error("Operation timed out after {0} seconds")]
    TimeoutError(u64),

    // Network errors
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Connection failed to {endpoint}: {reason}")]
    ConnectionError { endpoint: String, reason: String },

    // Auth errors
    /// **CRITICAL**: Authentication failure - possible credential attack.
    ///
    /// **Security Impact**: CRITICAL - Unauthorized access attempt
    /// **Recovery**: ALWAYS FAIL CLOSED
    ///
    /// **Required Actions**:
    /// 1. Log to security audit with timestamp, IP, attempt details
    /// 2. Increment auth failure counter for IP/client
    /// 3. Apply progressive delay (2^n seconds after n failures)
    /// 4. Trigger account lockout after threshold (e.g., 5 attempts)
    /// 5. Alert on patterns (distributed attempts, timing attacks)
    ///
    /// **Safe Handling**:
    /// - NEVER reveal why authentication failed
    /// - Use constant-time comparison for credentials
    /// - Return identical error for "user not found" vs "wrong password"
    /// - Generic message: "Authentication failed"
    ///
    /// **Logging Requirements**:
    /// ```rust
    /// audit_log.critical(AuditEvent::AuthFailure {
    ///     client_ip: ip,
    ///     user_id: sanitize(user_id), // Hash if sensitive
    ///     timestamp: SystemTime::now(),
    ///     failure_count: count,
    /// });
    /// ```
    #[error("Authentication failed: {reason}")]
    AuthError { reason: String },

    /// **CRITICAL**: Authorization failure - privilege escalation attempt.
    ///
    /// **Security Impact**: CRITICAL - Possible privilege escalation
    /// **Recovery**: DENY and audit
    ///
    /// **Required Actions**:
    /// 1. Deny the action immediately
    /// 2. Log full context to security audit
    /// 3. Check for authorization probe patterns
    /// 4. Consider session termination for repeated attempts
    ///
    /// **Safe Handling**:
    /// - Return minimal information: "Unauthorized"
    /// - Don't reveal what permissions are needed
    /// - Don't indicate if resource exists
    #[error("Unauthorized: {action}")]
    Unauthorized { action: String },

    // MCP Protocol errors
    #[error("Protocol error: {code}: {message}")]
    ProtocolError { code: i32, message: String },

    #[error("Method not found: {method}")]
    MethodNotFound { method: String },

    // Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),

    // Internal errors
    #[error("Internal error: {0}")]
    Internal(String),
}

impl KindlyError {
    /// Get the severity level of the error
    pub const fn severity(&self) -> ErrorSeverity {
        match self {
            // Critical errors that require immediate attention
            Self::ThreatDetected { .. } => ErrorSeverity::Critical,
            Self::AuthError { .. } => ErrorSeverity::Critical,
            Self::Unauthorized { .. } => ErrorSeverity::Critical,

            // High severity errors that impact functionality
            Self::ScannerError(_) => ErrorSeverity::High,
            Self::ResourceError { .. } => ErrorSeverity::High,
            Self::TimeoutError(_) => ErrorSeverity::High,
            Self::Internal(_) => ErrorSeverity::High,

            // Medium severity errors
            Self::NetworkError(_) => ErrorSeverity::Medium,
            Self::ConnectionError { .. } => ErrorSeverity::Medium,
            Self::ProtocolError { .. } => ErrorSeverity::Medium,
            Self::ConfigError(_) => ErrorSeverity::Medium,

            // Low severity errors
            Self::DisplayError(_) => ErrorSeverity::Low,
            Self::TerminalError => ErrorSeverity::Low,
            Self::ValidationError(_) => ErrorSeverity::Low,
            Self::InvalidInput { .. } => ErrorSeverity::Low,
            Self::InvalidConfig { .. } => ErrorSeverity::Low,
            Self::FileError(_) => ErrorSeverity::Low,
            Self::PathNotFound { .. } => ErrorSeverity::Low,
            Self::SerializationError(_) => ErrorSeverity::Low,
            Self::FormatError { .. } => ErrorSeverity::Low,
            Self::MethodNotFound { .. } => ErrorSeverity::Low,
        }
    }

    /// Check if the error is retryable
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::NetworkError(_)
                | Self::ConnectionError { .. }
                | Self::TimeoutError(_)
                | Self::ResourceError { .. }
        )
    }

    /// Get a user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            Self::ThreatDetected { .. } => {
                // NEVER expose threat details to avoid information leakage
                "Security threat detected: policy violation".to_string()
            }
            Self::AuthError { .. } => {
                // Generic message - don't reveal why auth failed
                "Authentication failed. Please check your credentials.".to_string()
            }
            Self::Unauthorized { .. } => {
                // Don't reveal what action was attempted
                "Unauthorized access".to_string()
            }
            Self::TimeoutError(_) => {
                // Don't reveal exact timeout to prevent timing attacks
                "Operation timed out".to_string()
            }
            Self::ResourceError { .. } => {
                // Don't reveal specific resource or limits
                "Resource limit exceeded".to_string()
            }
            _ => self.to_string(),
        }
    }

    /// Convert to MCP protocol error code
    pub const fn to_protocol_code(&self) -> i32 {
        match self {
            Self::ProtocolError { code, .. } => *code,
            Self::MethodNotFound { .. } => -32601,
            Self::InvalidInput { .. } => -32602,
            Self::AuthError { .. } | Self::Unauthorized { .. } => -32001,
            Self::TimeoutError(_) => -32002,
            Self::ResourceError { .. } => -32003,
            Self::ThreatDetected { .. } => -32004,
            _ => -32603, // Internal error
        }
    }
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Error recovery strategies
#[derive(Debug, Clone)]
pub enum RecoveryStrategy {
    /// Retry the operation with exponential backoff
    RetryWithBackoff {
        max_attempts: u32,
        base_delay_ms: u64,
    },

    /// Fall back to a simpler operation
    Fallback,

    /// Log and continue
    LogAndContinue,

    /// Fail fast with user-friendly message
    FailFast,
}

/// Error context with recovery hints
pub struct ErrorContext {
    pub error: KindlyError,
    pub strategy: RecoveryStrategy,
    pub user_hint: String,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new(error: KindlyError, strategy: RecoveryStrategy, hint: &str) -> Self {
        Self {
            error,
            strategy,
            user_hint: hint.to_string(),
        }
    }

    /// Convert to user-friendly message
    pub fn user_message(&self) -> String {
        format!("{}\n\nHint: {}", self.error, self.user_hint)
    }
}

/// Recovery helper functions
pub mod recovery {
    use super::{KindlyError, Result};
    use std::time::Duration;
    use tokio::time::sleep;

    /// Retry an operation with exponential backoff
    pub async fn retry_with_backoff<F, T, E>(
        mut operation: F,
        max_attempts: u32,
        base_delay_ms: u64,
    ) -> Result<T>
    where
        F: FnMut() -> Result<T, E>,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut attempt = 0;
        let mut delay = base_delay_ms;

        loop {
            attempt += 1;

            match operation() {
                Ok(result) => return Ok(result),
                Err(e) if attempt >= max_attempts => {
                    return Err(anyhow::anyhow!(
                        "Operation failed after {} attempts: {}",
                        max_attempts,
                        e
                    ));
                }
                Err(_) => {
                    sleep(Duration::from_millis(delay)).await;
                    delay = (delay * 2).min(30_000); // Cap at 30 seconds
                }
            }
        }
    }

    /// Execute with timeout
    pub async fn with_timeout<F, T>(operation: F, timeout_secs: u64) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = anyhow::Result<T>>,
    {
        match tokio::time::timeout(Duration::from_secs(timeout_secs), operation).await {
            Ok(result) => result,
            Err(_) => Err(KindlyError::TimeoutError(timeout_secs).into()),
        }
    }
}

/// Error handlers for specific components
pub mod handlers {
    use super::{io, ErrorContext, KindlyError, RecoveryStrategy};

    /// Handle display rendering errors with fallback
    pub fn handle_display_error(error: anyhow::Error) -> String {
        eprintln!("Display error: {error}");

        // Fallback to minimal text output
        format!(
            "KindlyGuard | Status: Error | Message: Display unavailable\n\
             Error: {error}\n\
             Try running with --format minimal or --no-color"
        )
    }

    /// Handle file operation errors
    pub fn handle_file_error(path: &str, error: io::Error) -> ErrorContext {
        let hint = match error.kind() {
            io::ErrorKind::NotFound => {
                format!("File '{path}' not found. Check the path and try again.")
            }
            io::ErrorKind::PermissionDenied => {
                format!("Permission denied for '{path}'. Check file permissions.")
            }
            io::ErrorKind::InvalidData => {
                "File contains invalid data. It may be corrupted.".to_string()
            }
            _ => {
                format!("Failed to access '{path}': {error}")
            }
        };

        ErrorContext::new(
            KindlyError::FileError(error),
            RecoveryStrategy::FailFast,
            &hint,
        )
    }

    /// Handle validation errors with helpful messages
    pub fn handle_validation_error(field: &str, value: &str, reason: &str) -> ErrorContext {
        let hint = match field {
            "path" => "Use absolute paths without '..' and ensure the file exists.".to_string(),
            "port" => "Use a port number between 1024 and 65535.".to_string(),
            "feature" => "Valid features: unicode, injection, path, advanced.".to_string(),
            _ => {
                format!("Check the {field} value and try again.")
            }
        };

        ErrorContext::new(
            KindlyError::ValidationError(format!("Invalid {field}: '{value}' - {reason}")),
            RecoveryStrategy::FailFast,
            &hint,
        )
    }
}

/// Graceful degradation for display operations
pub mod degradation {

    use crate::shield::Shield;
    use std::sync::Arc;

    /// Try multiple display formats until one works
    pub fn degrade_display_format(
        shield: Arc<Shield>,
        mut formats: Vec<crate::shield::universal_display::DisplayFormat>,
    ) -> String {
        use crate::shield::{UniversalDisplay, UniversalDisplayConfig};

        // Try each format in order
        while let Some(format) = formats.pop() {
            let config = UniversalDisplayConfig {
                color: false, // Disable color for safety
                detailed: false,
                format,
                status_file: None, // Skip file writing
            };

            let display = UniversalDisplay::new(shield.clone(), config);

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| display.render())) {
                Ok(output) if !output.is_empty() => return output,
                _ => continue,
            }
        }

        // Ultimate fallback
        "KindlyGuard | Status: Unknown | Error: Display system failure".to_string()
    }
}

/// Security-aware error handling patterns
pub mod security_patterns {
    use super::*;
    use tracing::{error, warn};

    /// Example: Handle authentication errors securely
    ///
    /// ```rust
    /// use kindly_guard_server::error::{KindlyError, security_patterns::handle_auth_error};
    ///
    /// async fn authenticate(credentials: &Credentials) -> Result<User> {
    ///     match verify_credentials(credentials).await {
    ///         Ok(user) => Ok(user),
    ///         Err(e) => handle_auth_error(e, credentials.username())
    ///     }
    /// }
    /// ```
    pub fn handle_auth_error(error: anyhow::Error, username: &str) -> Result<(), KindlyError> {
        // Log detailed error internally (never expose to client)
        error!(
            target: "security",
            username = %username,
            error = %error,
            "Authentication failed"
        );

        // Audit event
        // audit_log.record(AuditEvent::AuthFailure { ... });

        // Return generic error to client
        Err(KindlyError::AuthError {
            reason: "Authentication failed".to_string(), // Generic message
        })
    }

    /// Example: Handle threat detection without information leakage
    ///
    /// ```rust
    /// use kindly_guard_server::error::{KindlyError, security_patterns::handle_threat};
    ///
    /// fn scan_input(input: &str) -> Result<()> {
    ///     let threats = scanner.scan_text(input)?;
    ///     if !threats.is_empty() {
    ///         return handle_threat(&threats[0], input);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn handle_threat(threat: &crate::scanner::Threat, input: &str) -> Result<(), KindlyError> {
        // Log full details for security team
        error!(
            target: "security.threats",
            threat_type = ?threat.threat_type,
            severity = ?threat.severity,
            input_hash = %sha256_hash(input), // Hash sensitive data
            "Threat detected"
        );

        // Generic error for client
        Err(KindlyError::ThreatDetected {
            threat_type: "policy violation".to_string(), // Don't reveal attack type
            location: "request".to_string(),             // Don't reveal specific location
        })
    }

    /// Example: Handle resource exhaustion with rate limiting
    ///
    /// ```rust
    /// use kindly_guard_server::error::{KindlyError, security_patterns::handle_resource_limit};
    ///
    /// async fn process_request(req: Request) -> Result<Response> {
    ///     if !rate_limiter.check_limit(&req.client_id).await? {
    ///         return handle_resource_limit("rate_limit", &req.client_id);
    ///     }
    ///     // Process request...
    /// }
    /// ```
    pub fn handle_resource_limit(resource: &str, client_id: &str) -> Result<(), KindlyError> {
        warn!(
            target: "security.resources",
            resource = %resource,
            client_id = %client_id,
            "Resource limit exceeded"
        );

        // Apply progressive penalties
        // rate_limiter.apply_penalty(client_id);

        Err(KindlyError::ResourceError {
            resource: "request".to_string(),     // Generic resource name
            limit: "quota exceeded".to_string(), // Don't reveal specific limits
        })
    }

    /// Example: Timeout handling that prevents timing attacks
    ///
    /// ```rust
    /// use kindly_guard_server::error::{KindlyError, security_patterns::handle_timeout};
    /// use std::time::Duration;
    ///
    /// async fn timed_operation() -> Result<String> {
    ///     match timeout(Duration::from_secs(30), operation()).await {
    ///         Ok(result) => result,
    ///         Err(_) => handle_timeout(30)
    ///     }
    /// }
    /// ```
    pub fn handle_timeout(timeout_secs: u64) -> Result<(), KindlyError> {
        warn!(
            target: "security.timeout",
            timeout_secs = timeout_secs,
            "Operation timed out"
        );

        // Add random jitter to prevent timing analysis
        use rand::Rng;
        let jitter = rand::thread_rng().gen_range(0..5);

        Err(KindlyError::TimeoutError(timeout_secs + jitter))
    }

    /// Hash sensitive data for logging
    fn sha256_hash(data: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Example: Constant-time string comparison for security
    ///
    /// ```rust
    /// use kindly_guard_server::error::security_patterns::constant_time_compare;
    ///
    /// fn verify_token(provided: &str, expected: &str) -> bool {
    ///     constant_time_compare(provided.as_bytes(), expected.as_bytes())
    /// }
    /// ```
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }

        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_context_formatting() {
        let error = KindlyError::ValidationError("Invalid path".to_string());
        let context =
            ErrorContext::new(error, RecoveryStrategy::FailFast, "Use absolute paths only");

        let msg = context.user_message();
        assert!(msg.contains("Invalid path"));
        assert!(msg.contains("Use absolute paths only"));
    }

    #[tokio::test]
    async fn test_retry_with_backoff() {
        let mut attempts = 0;
        let result = recovery::retry_with_backoff(
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(io::Error::other("temp error"))
                } else {
                    Ok("success")
                }
            },
            5,
            10,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn test_timeout() {
        use std::time::Duration;

        let result = recovery::with_timeout(
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok("should timeout")
            },
            1,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().downcast::<KindlyError>().unwrap(),
            KindlyError::TimeoutError(_) // Don't check exact value due to jitter
        ));
    }

    #[test]
    fn test_security_error_severity() {
        // Critical errors
        assert_eq!(
            KindlyError::ThreatDetected {
                threat_type: "sql_injection".to_string(),
                location: "input".to_string()
            }
            .severity(),
            ErrorSeverity::Critical
        );

        assert_eq!(
            KindlyError::AuthError {
                reason: "invalid_token".to_string()
            }
            .severity(),
            ErrorSeverity::Critical
        );

        assert_eq!(
            KindlyError::Unauthorized {
                action: "read_secrets".to_string()
            }
            .severity(),
            ErrorSeverity::Critical
        );

        // High severity
        assert_eq!(
            KindlyError::ResourceError {
                resource: "memory".to_string(),
                limit: "1GB".to_string()
            }
            .severity(),
            ErrorSeverity::High
        );

        assert_eq!(
            KindlyError::TimeoutError(30).severity(),
            ErrorSeverity::High
        );
    }

    #[test]
    fn test_constant_time_compare() {
        use security_patterns::constant_time_compare;

        // Equal strings
        assert!(constant_time_compare(b"secret123", b"secret123"));

        // Different strings (same length)
        assert!(!constant_time_compare(b"secret123", b"secret124"));

        // Different lengths
        assert!(!constant_time_compare(b"short", b"longer_string"));

        // Empty strings
        assert!(constant_time_compare(b"", b""));
    }

    #[test]
    fn test_error_to_protocol_code() {
        // Security-specific codes
        assert_eq!(
            KindlyError::AuthError {
                reason: "test".to_string()
            }
            .to_protocol_code(),
            -32001
        );

        assert_eq!(
            KindlyError::Unauthorized {
                action: "test".to_string()
            }
            .to_protocol_code(),
            -32001
        );

        assert_eq!(
            KindlyError::ThreatDetected {
                threat_type: "test".to_string(),
                location: "test".to_string()
            }
            .to_protocol_code(),
            -32004
        );

        assert_eq!(KindlyError::TimeoutError(30).to_protocol_code(), -32002);

        assert_eq!(
            KindlyError::ResourceError {
                resource: "test".to_string(),
                limit: "test".to_string()
            }
            .to_protocol_code(),
            -32003
        );
    }

    #[test]
    fn test_security_error_messages() {
        // Auth errors should not reveal details
        let auth_err = KindlyError::AuthError {
            reason: "user_not_found_in_database".to_string(),
        };
        let user_msg = auth_err.user_message();
        assert!(!user_msg.contains("database"));
        assert!(!user_msg.contains("not_found"));
        assert_eq!(
            user_msg,
            "Authentication failed. Please check your credentials."
        );

        // Threat errors should be generic
        let threat_err = KindlyError::ThreatDetected {
            threat_type: "sql_injection_union_select".to_string(),
            location: "parameter_user_id".to_string(),
        };
        let user_msg = threat_err.user_message();
        assert!(!user_msg.contains("sql"));
        assert!(!user_msg.contains("injection"));
        assert!(!user_msg.contains("parameter"));
        assert!(!user_msg.contains("union"));
        assert!(!user_msg.contains("user_id"));
        assert_eq!(user_msg, "Security threat detected: policy violation");

        // Unauthorized errors should hide the action
        let unauth_err = KindlyError::Unauthorized {
            action: "delete_all_users".to_string(),
        };
        let user_msg = unauth_err.user_message();
        assert!(!user_msg.contains("delete"));
        assert!(!user_msg.contains("users"));
        assert_eq!(user_msg, "Unauthorized access");

        // Resource errors should hide limits
        let resource_err = KindlyError::ResourceError {
            resource: "memory_heap".to_string(),
            limit: "2GB".to_string(),
        };
        let user_msg = resource_err.user_message();
        assert!(!user_msg.contains("memory"));
        assert!(!user_msg.contains("heap"));
        assert!(!user_msg.contains("2GB"));
        assert_eq!(user_msg, "Resource limit exceeded");

        // Timeout errors should hide duration
        let timeout_err = KindlyError::TimeoutError(30);
        let user_msg = timeout_err.user_message();
        assert!(!user_msg.contains("30"));
        assert_eq!(user_msg, "Operation timed out");
    }
}
