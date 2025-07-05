//! Custom error types for xtask

use std::fmt;
use std::path::PathBuf;

/// Result type alias for xtask operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for xtask operations
#[derive(Debug)]
pub enum Error {
    /// Command execution failed
    CommandFailed {
        command: String,
        exit_code: Option<i32>,
        stderr: Option<String>,
    },

    /// File or directory not found
    NotFound {
        path: PathBuf,
        context: String,
    },

    /// Version-related errors
    Version {
        message: String,
    },

    /// Build-related errors
    Build {
        message: String,
        profile: String,
    },

    /// Test-related errors
    Test {
        message: String,
        package: Option<String>,
    },

    /// Release-related errors
    Release {
        message: String,
        version: String,
    },

    /// Security check failed
    Security {
        check: String,
        details: String,
    },

    /// Configuration error
    Config {
        message: String,
    },

    /// IO error wrapper
    Io {
        context: String,
        source: std::io::Error,
    },

    /// Serialization/deserialization error
    Serde {
        context: String,
        source: serde_json::Error,
    },

    /// Git operation failed
    Git {
        operation: String,
        details: String,
    },

    /// Network-related error
    Network {
        operation: String,
        details: String,
    },

    /// User cancelled operation
    Cancelled,

    /// Generic error with context
    Other {
        context: String,
        source: anyhow::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CommandFailed {
                command,
                exit_code,
                stderr,
            } => {
                write!(f, "Command failed: {}", command)?;
                if let Some(code) = exit_code {
                    write!(f, " (exit code: {})", code)?;
                }
                if let Some(err) = stderr {
                    write!(f, "\nError output: {}", err)?;
                }
                Ok(())
            }
            Error::NotFound { path, context } => {
                write!(f, "{}: {} not found", context, path.display())
            }
            Error::Version { message } => write!(f, "Version error: {}", message),
            Error::Build { message, profile } => {
                write!(f, "Build error (profile: {}): {}", profile, message)
            }
            Error::Test { message, package } => {
                write!(f, "Test error")?;
                if let Some(pkg) = package {
                    write!(f, " in package {}", pkg)?;
                }
                write!(f, ": {}", message)
            }
            Error::Release { message, version } => {
                write!(f, "Release error for version {}: {}", version, message)
            }
            Error::Security { check, details } => {
                write!(f, "Security check '{}' failed: {}", check, details)
            }
            Error::Config { message } => write!(f, "Configuration error: {}", message),
            Error::Io { context, source } => {
                write!(f, "IO error in {}: {}", context, source)
            }
            Error::Serde { context, source } => {
                write!(f, "Serialization error in {}: {}", context, source)
            }
            Error::Git { operation, details } => {
                write!(f, "Git operation '{}' failed: {}", operation, details)
            }
            Error::Network { operation, details } => {
                write!(f, "Network error during {}: {}", operation, details)
            }
            Error::Cancelled => write!(f, "Operation cancelled by user"),
            Error::Other { context, source } => {
                write!(f, "{}: {}", context, source)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Serde { source, .. } => Some(source),
            Error::Other { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

// Convenience conversions
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io {
            context: "IO operation".to_string(),
            source: err,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serde {
            context: "JSON operation".to_string(),
            source: err,
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Other {
            context: "Operation failed".to_string(),
            source: err,
        }
    }
}

// Helper functions for creating common errors
impl Error {
    /// Create a command failed error
    pub fn command_failed(command: impl Into<String>) -> Self {
        Error::CommandFailed {
            command: command.into(),
            exit_code: None,
            stderr: None,
        }
    }

    /// Create a not found error
    pub fn not_found(path: impl Into<PathBuf>, context: impl Into<String>) -> Self {
        Error::NotFound {
            path: path.into(),
            context: context.into(),
        }
    }

    /// Create a version error
    pub fn version(message: impl Into<String>) -> Self {
        Error::Version {
            message: message.into(),
        }
    }

    /// Create a build error
    pub fn build(message: impl Into<String>, profile: impl Into<String>) -> Self {
        Error::Build {
            message: message.into(),
            profile: profile.into(),
        }
    }

    /// Create a test error
    pub fn test(message: impl Into<String>, package: Option<String>) -> Self {
        Error::Test {
            message: message.into(),
            package,
        }
    }

    /// Create a release error
    pub fn release(message: impl Into<String>, version: impl Into<String>) -> Self {
        Error::Release {
            message: message.into(),
            version: version.into(),
        }
    }

    /// Create a security error
    pub fn security(check: impl Into<String>, details: impl Into<String>) -> Self {
        Error::Security {
            check: check.into(),
            details: details.into(),
        }
    }

    /// Create a config error
    pub fn config(message: impl Into<String>) -> Self {
        Error::Config {
            message: message.into(),
        }
    }

    /// Create a git error
    pub fn git(operation: impl Into<String>, details: impl Into<String>) -> Self {
        Error::Git {
            operation: operation.into(),
            details: details.into(),
        }
    }
}