//! Input validation and sanitization for CLI commands

use anyhow::{anyhow, bail, Result};
use regex::Regex;
use std::path::PathBuf;

/// Maximum input size for text scanning (10MB)
const MAX_SCAN_INPUT_SIZE: usize = 10 * 1024 * 1024;

/// Valid port range for dashboard
const MIN_USER_PORT: u16 = 1024;
const MAX_PORT: u16 = 65535;

/// Maximum path length
const MAX_PATH_LENGTH: usize = 4096;

/// Valid feature names for info command
const VALID_FEATURES: &[&str] = &[
    "unicode",
    "injection",
    "path",
    "advanced",
    "enhanced",
    "all",
];

/// Valid output formats
const VALID_FORMATS: &[&str] = &["json", "text", "minimal", "compact", "dashboard"];

/// Pattern for safe feature names (alphanumeric + dash/underscore)
static SAFE_NAME_PATTERN: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap());

/// Validate and sanitize file path
pub fn validate_file_path(path: &str) -> Result<PathBuf> {
    // Check length
    if path.len() > MAX_PATH_LENGTH {
        bail!("Path too long: maximum {} characters", MAX_PATH_LENGTH);
    }

    // Check for null bytes
    if path.contains('\0') {
        bail!("Invalid path: contains null bytes");
    }

    let path_buf = PathBuf::from(path);

    // Prevent directory traversal
    if path.contains("..") {
        bail!("Invalid path: directory traversal detected");
    }

    // Normalize path
    let canonical = if path_buf.exists() {
        path_buf
            .canonicalize()
            .map_err(|e| anyhow!("Failed to resolve path: {}", e))?
    } else {
        // For non-existent files, just check parent directory
        if let Some(parent) = path_buf.parent() {
            if parent.exists() && !parent.is_dir() {
                bail!("Parent path is not a directory");
            }
        }
        path_buf
    };

    Ok(canonical)
}

/// Validate text input for scanning
pub fn validate_scan_input(input: &str) -> Result<String> {
    // Check size
    if input.len() > MAX_SCAN_INPUT_SIZE {
        bail!(
            "Input too large: maximum {} MB",
            MAX_SCAN_INPUT_SIZE / 1024 / 1024
        );
    }

    // Validate UTF-8 (already guaranteed by Rust strings, but be explicit)
    if let Err(e) = std::str::from_utf8(input.as_bytes()) {
        bail!("Invalid UTF-8 input: {}", e);
    }

    Ok(input.to_string())
}

/// Validate port number
pub fn validate_port(port: u16) -> Result<u16> {
    if port < MIN_USER_PORT {
        bail!(
            "Port {} is reserved. Use ports {} and above",
            port,
            MIN_USER_PORT
        );
    }

    if port > MAX_PORT {
        bail!("Invalid port: {} exceeds maximum", port);
    }

    Ok(port)
}

/// Validate feature name
pub fn validate_feature_name(feature: &str) -> Result<String> {
    // Check if it's a known feature
    let feature_lower = feature.to_lowercase();
    if VALID_FEATURES.contains(&feature_lower.as_str()) {
        return Ok(feature_lower);
    }

    // For unknown features, ensure they're safe
    if !SAFE_NAME_PATTERN.is_match(feature) {
        bail!("Invalid feature name: must be alphanumeric with dashes/underscores");
    }

    if feature.len() > 50 {
        bail!("Feature name too long: maximum 50 characters");
    }

    Ok(feature.to_string())
}

/// Validate output format
pub fn validate_format(format: &str) -> Result<String> {
    let format_lower = format.to_lowercase();

    if VALID_FORMATS.contains(&format_lower.as_str()) {
        Ok(format_lower)
    } else {
        // Don't fail, just use default
        Ok("text".to_string())
    }
}

/// Sanitize output for display
pub fn sanitize_output(text: &str) -> String {
    // Remove control characters except newline, tab, and ANSI escape sequences
    let mut result = String::with_capacity(text.len());

    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\n' | '\t' => result.push(ch),
            '\x1b' => {
                // Preserve ANSI escape sequences
                result.push(ch);
                // Simple ANSI sequence handling
                if chars.next() == Some('[') {
                    result.push('[');
                    // Read until 'm' or invalid
                    for ch in chars.by_ref() {
                        result.push(ch);
                        if ch == 'm' || !ch.is_ascii() {
                            break;
                        }
                    }
                }
            }
            _ if ch.is_control() => {
                // Skip other control characters
            }
            _ => result.push(ch),
        }
    }

    result
}

/// Validate command-line arguments before execution
pub struct CommandValidator;

impl CommandValidator {
    /// Validate scan command inputs
    pub fn validate_scan(input: &str, is_text: bool) -> Result<String> {
        if is_text {
            validate_scan_input(input)
        } else {
            validate_file_path(input).map(|p| p.to_string_lossy().to_string())
        }
    }

    /// Validate info command feature
    pub fn validate_info_feature(feature: Option<&str>) -> Result<Option<String>> {
        match feature {
            Some(f) => validate_feature_name(f).map(Some),
            None => Ok(None),
        }
    }

    /// Validate dashboard port
    pub fn validate_dashboard_port(port: u16) -> Result<u16> {
        validate_port(port)
    }

    /// Validate format option
    pub fn validate_format(format: &str) -> Result<String> {
        validate_format(format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_path_validation() {
        // Valid paths
        assert!(validate_file_path("/tmp/test.txt").is_ok());
        assert!(validate_file_path("./local.file").is_ok());

        // Directory traversal
        assert!(validate_file_path("../../../etc/passwd").is_err());
        assert!(validate_file_path("/tmp/../etc/passwd").is_err());

        // Null bytes
        assert!(validate_file_path("/tmp/test\0.txt").is_err());

        // Too long
        let long_path = "a".repeat(5000);
        assert!(validate_file_path(&long_path).is_err());
    }

    #[test]
    fn test_scan_input_validation() {
        // Valid input
        assert!(validate_scan_input("Hello, world!").is_ok());
        assert!(validate_scan_input("Unicode: 你好").is_ok());

        // Too large
        let large_input = "x".repeat(MAX_SCAN_INPUT_SIZE + 1);
        assert!(validate_scan_input(&large_input).is_err());
    }

    #[test]
    fn test_port_validation() {
        // Valid ports
        assert_eq!(validate_port(3000).unwrap(), 3000);
        assert_eq!(validate_port(8080).unwrap(), 8080);
        assert_eq!(validate_port(65535).unwrap(), 65535);

        // Reserved ports
        assert!(validate_port(80).is_err());
        assert!(validate_port(443).is_err());
        assert!(validate_port(22).is_err());
    }

    #[test]
    fn test_feature_name_validation() {
        // Known features
        assert_eq!(validate_feature_name("unicode").unwrap(), "unicode");
        assert_eq!(validate_feature_name("INJECTION").unwrap(), "injection");

        // Safe unknown features
        assert_eq!(
            validate_feature_name("custom-feature").unwrap(),
            "custom-feature"
        );
        assert_eq!(validate_feature_name("test_123").unwrap(), "test_123");

        // Invalid features
        assert!(validate_feature_name("../../etc").is_err());
        assert!(validate_feature_name("feature with spaces").is_err());
        assert!(validate_feature_name("feature!@#").is_err());
    }

    #[test]
    fn test_format_validation() {
        // Valid formats
        assert_eq!(validate_format("json").unwrap(), "json");
        assert_eq!(validate_format("JSON").unwrap(), "json");
        assert_eq!(validate_format("minimal").unwrap(), "minimal");

        // Invalid formats default to text
        assert_eq!(validate_format("invalid").unwrap(), "text");
        assert_eq!(validate_format("").unwrap(), "text");
    }

    #[test]
    fn test_output_sanitization() {
        // Preserve normal text
        assert_eq!(sanitize_output("Hello, world!"), "Hello, world!");

        // Preserve newlines and tabs
        assert_eq!(
            sanitize_output("Line 1\nLine 2\tTabbed"),
            "Line 1\nLine 2\tTabbed"
        );

        // Preserve ANSI colors
        assert_eq!(
            sanitize_output("\x1b[31mRed text\x1b[0m"),
            "\x1b[31mRed text\x1b[0m"
        );

        // Remove other control characters
        assert_eq!(sanitize_output("Bad\x00\x01\x02chars"), "Badchars");
        assert_eq!(sanitize_output("Bell\x07Alert"), "BellAlert");
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fuzz_path_validation(path in "\\PC*") {
            // Should not panic on any input
            let _ = validate_file_path(&path);
        }

        #[test]
        fn fuzz_input_validation(input in "\\PC*") {
            // Should not panic on any input
            let _ = validate_scan_input(&input);
        }

        #[test]
        fn fuzz_feature_validation(feature in "\\PC*") {
            // Should not panic on any input
            let _ = validate_feature_name(&feature);
        }

        #[test]
        fn fuzz_output_sanitization(output in "\\PC*") {
            // Should not panic and produce valid output
            let sanitized = sanitize_output(&output);
            // Result should not contain control chars except allowed ones
            for ch in sanitized.chars() {
                assert!(
                    !ch.is_control() ||
                    ch == '\n' ||
                    ch == '\t' ||
                    ch == '\x1b'
                );
            }
        }
    }
}
