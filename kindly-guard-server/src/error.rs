//! Centralized error handling for KindlyGuard
//! 
//! Provides a unified error type and consistent error handling patterns
//! across the entire codebase.

use thiserror::Error;
use crate::protocol::JsonRpcError;
use crate::scanner::Threat;

/// Central error type for KindlyGuard
#[derive(Error, Debug)]
pub enum KindlyError {
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Authentication errors
    #[error("Authentication failed: {0}")]
    Auth(String),
    
    /// Authorization errors
    #[error("Authorization failed: {0}")]
    Authorization(String),
    
    /// Rate limiting errors
    #[error("Rate limit exceeded")]
    RateLimited {
        retry_after: Option<u64>,
    },
    
    /// Security threat detected
    #[error("Security threat detected")]
    ThreatDetected {
        threats: Vec<Threat>,
    },
    
    /// Scanner errors
    #[error("Scanner error: {0}")]
    Scanner(String),
    
    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// Method not found
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    
    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    
    /// Internal server error
    #[error("Internal server error: {0}")]
    Internal(String),
    
    /// IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// JSON errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    /// UTF-8 errors
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    
    /// Generic errors from anyhow
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl KindlyError {
    /// Convert to JSON-RPC error
    pub fn to_json_rpc_error(&self) -> JsonRpcError {
        match self {
            KindlyError::MethodNotFound(method) => JsonRpcError {
                code: crate::protocol::error_codes::METHOD_NOT_FOUND,
                message: format!("Method not found: {}", method),
                data: None,
            },
            
            KindlyError::InvalidRequest(msg) => JsonRpcError {
                code: crate::protocol::error_codes::INVALID_REQUEST,
                message: format!("Invalid request: {}", msg),
                data: None,
            },
            
            KindlyError::InvalidParams(msg) => JsonRpcError {
                code: crate::protocol::error_codes::INVALID_PARAMS,
                message: format!("Invalid parameters: {}", msg),
                data: None,
            },
            
            KindlyError::Auth(msg) => JsonRpcError {
                code: -32000, // Custom error code for auth
                message: format!("Authentication failed: {}", msg),
                data: None,
            },
            
            KindlyError::Authorization(msg) => JsonRpcError {
                code: -32001, // Custom error code for authorization
                message: format!("Authorization failed: {}", msg),
                data: None,
            },
            
            KindlyError::RateLimited { retry_after } => JsonRpcError {
                code: -32002, // Custom error code for rate limiting
                message: "Rate limit exceeded".to_string(),
                data: retry_after.map(|seconds| {
                    serde_json::json!({
                        "retry_after": seconds,
                    })
                }),
            },
            
            KindlyError::ThreatDetected { threats } => JsonRpcError {
                code: -32003, // Custom error code for threats
                message: "Security threat detected".to_string(),
                data: Some(serde_json::json!({
                    "threats": threats,
                })),
            },
            
            _ => JsonRpcError {
                code: crate::protocol::error_codes::INTERNAL_ERROR,
                message: self.to_string(),
                data: None,
            },
        }
    }
    
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            KindlyError::RateLimited { .. } |
            KindlyError::Internal(_) |
            KindlyError::Io(_)
        )
    }
    
    /// Get suggested retry delay in seconds
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            KindlyError::RateLimited { retry_after } => *retry_after,
            KindlyError::Internal(_) | KindlyError::Io(_) => Some(5), // Default 5 second retry
            _ => None,
        }
    }
    
    /// Create a sanitized error message suitable for external clients
    pub fn client_message(&self) -> String {
        match self {
            KindlyError::Config(_) => "Configuration error".to_string(),
            KindlyError::Auth(_) => "Authentication failed".to_string(),
            KindlyError::Authorization(_) => "Authorization failed".to_string(),
            KindlyError::RateLimited { .. } => "Rate limit exceeded".to_string(),
            KindlyError::ThreatDetected { .. } => "Security threat detected".to_string(),
            KindlyError::Scanner(_) => "Scanner error".to_string(),
            KindlyError::Protocol(_) => "Protocol error".to_string(),
            KindlyError::MethodNotFound(method) => format!("Method not found: {}", method),
            KindlyError::InvalidRequest(_) => "Invalid request".to_string(),
            KindlyError::InvalidParams(_) => "Invalid parameters".to_string(),
            KindlyError::Internal(_) => "Internal server error".to_string(),
            KindlyError::Io(_) => "IO error".to_string(),
            KindlyError::Json(_) => "JSON parsing error".to_string(),
            KindlyError::Utf8(_) => "Invalid UTF-8".to_string(),
            KindlyError::Other(_) => "An error occurred".to_string(),
        }
    }
}

/// Result type alias using KindlyError
pub type KindlyResult<T> = Result<T, KindlyError>;

/// Extension trait for Result to add context
pub trait ResultExt<T> {
    /// Add context to an error
    fn context(self, msg: &str) -> KindlyResult<T>;
    
    /// Convert to internal error with context
    fn internal_error(self, msg: &str) -> KindlyResult<T>;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context(self, msg: &str) -> KindlyResult<T> {
        self.map_err(|e| KindlyError::Other(anyhow::Error::new(e).context(msg.to_string())))
    }
    
    fn internal_error(self, msg: &str) -> KindlyResult<T> {
        self.map_err(|_| KindlyError::Internal(msg.to_string()))
    }
}

/// Macro for creating config errors
#[macro_export]
macro_rules! config_error {
    ($msg:expr) => {
        $crate::error::KindlyError::Config($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KindlyError::Config(format!($fmt, $($arg)*))
    };
}

/// Macro for creating auth errors
#[macro_export]
macro_rules! auth_error {
    ($msg:expr) => {
        $crate::error::KindlyError::Auth($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KindlyError::Auth(format!($fmt, $($arg)*))
    };
}

/// Macro for creating scanner errors
#[macro_export]
macro_rules! scanner_error {
    ($msg:expr) => {
        $crate::error::KindlyError::Scanner($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::KindlyError::Scanner(format!($fmt, $($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_conversions() {
        let err = KindlyError::Auth("Invalid token".to_string());
        let json_err = err.to_json_rpc_error();
        assert_eq!(json_err.code, -32000);
        assert!(json_err.message.contains("Invalid token"));
    }
    
    #[test]
    fn test_retryable_errors() {
        assert!(KindlyError::RateLimited { retry_after: Some(60) }.is_retryable());
        assert!(KindlyError::Internal("test".to_string()).is_retryable());
        assert!(!KindlyError::Auth("test".to_string()).is_retryable());
    }
    
    #[test]
    fn test_client_messages() {
        let err = KindlyError::Internal("Sensitive internal details".to_string());
        assert_eq!(err.client_message(), "Internal server error");
        
        let err = KindlyError::ThreatDetected { threats: vec![] };
        assert_eq!(err.client_message(), "Security threat detected");
    }
    
    #[test]
    fn test_error_macros() {
        let err = config_error!("Invalid setting");
        assert!(matches!(err, KindlyError::Config(_)));
        
        let err = auth_error!("Token expired for user {}", "alice");
        assert!(matches!(err, KindlyError::Auth(_)));
    }
}