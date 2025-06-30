//! Error handling and recovery mechanisms for production resilience

use std::io;
use thiserror::Error;
use anyhow::Result;

/// Type alias for Result with KindlyError
pub type KindlyResult<T> = Result<T, KindlyError>;

/// Extension trait for Result types
pub trait ResultExt<T> {
    /// Convert to KindlyResult
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

/// KindlyGuard error types with actionable recovery strategies
#[derive(Error, Debug)]
pub enum KindlyError {
    // Display and UI errors
    #[error("Display rendering failed: {0}")]
    DisplayError(String),
    
    #[error("Terminal not available")]
    TerminalError,
    
    // Validation errors
    #[error("Command validation failed: {0}")]
    ValidationError(String),
    
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
    
    #[error("Threat detected: {threat_type} at {location}")]
    ThreatDetected { threat_type: String, location: String },
    
    // Resource errors
    #[error("Resource limit exceeded: {resource}: {limit}")]
    ResourceError { resource: String, limit: String },
    
    #[error("Operation timed out after {0} seconds")]
    TimeoutError(u64),
    
    // Network errors
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Connection failed to {endpoint}: {reason}")]
    ConnectionError { endpoint: String, reason: String },
    
    // Auth errors
    #[error("Authentication failed: {reason}")]
    AuthError { reason: String },
    
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
    pub fn severity(&self) -> ErrorSeverity {
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
    pub fn is_retryable(&self) -> bool {
        matches!(self,
            Self::NetworkError(_) |
            Self::ConnectionError { .. } |
            Self::TimeoutError(_) |
            Self::ResourceError { .. }
        )
    }
    
    /// Get a user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            Self::ThreatDetected { threat_type, .. } => {
                format!("Security threat detected: {}", threat_type)
            }
            Self::AuthError { .. } => "Authentication failed. Please check your credentials.".to_string(),
            Self::Unauthorized { action } => format!("You are not authorized to {}", action),
            Self::TimeoutError(seconds) => format!("Operation timed out after {} seconds", seconds),
            Self::ResourceError { resource, limit } => {
                format!("Resource limit exceeded for {}: {}", resource, limit)
            }
            _ => self.to_string(),
        }
    }
    
    /// Convert to MCP protocol error code
    pub fn to_protocol_code(&self) -> i32 {
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
    RetryWithBackoff { max_attempts: u32, base_delay_ms: u64 },
    
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
    use super::*;
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
    pub async fn with_timeout<F, T>(
        operation: F,
        timeout_secs: u64,
    ) -> anyhow::Result<T>
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
    use super::*;
    use crate::shield::universal_display::DisplayFormat;
    
    /// Handle display rendering errors with fallback
    pub fn handle_display_error(error: anyhow::Error) -> String {
        eprintln!("Display error: {}", error);
        
        // Fallback to minimal text output
        format!(
            "KindlyGuard | Status: Error | Message: Display unavailable\n\
             Error: {}\n\
             Try running with --format minimal or --no-color",
            error
        )
    }
    
    /// Handle file operation errors
    pub fn handle_file_error(path: &str, error: io::Error) -> ErrorContext {
        let hint = match error.kind() {
            io::ErrorKind::NotFound => {
                format!("File '{}' not found. Check the path and try again.", path)
            }
            io::ErrorKind::PermissionDenied => {
                format!("Permission denied for '{}'. Check file permissions.", path)
            }
            io::ErrorKind::InvalidData => {
                "File contains invalid data. It may be corrupted.".to_string()
            }
            _ => {
                format!("Failed to access '{}': {}", path, error)
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
            "path" => {
                "Use absolute paths without '..' and ensure the file exists.".to_string()
            }
            "port" => {
                "Use a port number between 1024 and 65535.".to_string()
            }
            "feature" => {
                "Valid features: unicode, injection, path, advanced.".to_string()
            }
            _ => {
                format!("Check the {} value and try again.", field)
            }
        };
        
        ErrorContext::new(
            KindlyError::ValidationError(format!(
                "Invalid {}: '{}' - {}",
                field, value, reason
            )),
            RecoveryStrategy::FailFast,
            &hint,
        )
    }
}

/// Graceful degradation for display operations
pub mod degradation {
    use super::*;
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_context_formatting() {
        let error = KindlyError::ValidationError("Invalid path".to_string());
        let context = ErrorContext::new(
            error,
            RecoveryStrategy::FailFast,
            "Use absolute paths only",
        );
        
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
                    Err(io::Error::new(io::ErrorKind::Other, "temp error"))
                } else {
                    Ok("success")
                }
            },
            5,
            10,
        ).await;
        
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
        ).await;
        
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().downcast::<KindlyError>().unwrap(),
            KindlyError::TimeoutError(1)
        ));
    }
}