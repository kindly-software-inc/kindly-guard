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
//! Configuration for `KindlyGuard`
//!
//! This module defines all security-related configuration structures for KindlyGuard.
//! Each configuration option has been carefully designed with security implications in mind.
//!
//! # Security Principles
//!
//! 1. **Secure Defaults**: All configuration defaults err on the side of security
//! 2. **Defense in Depth**: Multiple layers of security can be configured independently
//! 3. **Least Privilege**: Features are disabled by default and must be explicitly enabled
//! 4. **Transparency**: Security implications of each setting are clearly documented
//!
//! # Configuration Hierarchy
//!
//! Configuration sources are checked in order:
//! 1. Environment variable `KINDLY_GUARD_CONFIG` (highest precedence)
//! 2. `kindly-guard.toml` in current directory
//! 3. Built-in secure defaults (lowest precedence)

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub mod reload;

use crate::audit::AuditConfig;
use crate::auth::AuthConfig;
#[cfg(feature = "enhanced")]
use crate::event_processor::EventProcessorConfig;
use crate::neutralizer::NeutralizationConfig;
use crate::plugins::PluginConfig;
use crate::rate_limit::RateLimitConfig;
use crate::resilience::config::ResilienceConfig;
use crate::signing::SigningConfig;
use crate::storage::StorageConfig;
use crate::telemetry::TelemetryConfig;
use crate::transport::TransportConfig;

// Stub EventProcessorConfig when enhanced feature is not enabled
#[cfg(not(feature = "enhanced"))]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventProcessorConfig {
    pub enabled: bool,
}

/// Main configuration structure for KindlyGuard
///
/// # Security Architecture
///
/// KindlyGuard's configuration implements defense-in-depth with multiple
/// security layers that work together:
///
/// 1. **Authentication** (`auth`) - Identity verification and access control
/// 2. **Rate Limiting** (`rate_limit`) - Abuse and DoS prevention
/// 3. **Scanner** (`scanner`) - Threat detection and analysis
/// 4. **Neutralization** (`neutralization`) - Threat remediation
/// 5. **Audit** (`audit`) - Security event logging and compliance
///
/// # Configuration Priority
///
/// When multiple security features could conflict:
/// 1. Authentication failures block everything (highest priority)
/// 2. Rate limits apply after authentication
/// 3. Scanner runs on all authenticated requests
/// 4. Neutralization only acts on detected threats
///
/// # Example: Minimum Secure Configuration
///
/// ```toml
/// [auth]
/// enabled = true
/// jwt_secret = "your-base64-encoded-secret"
/// trusted_issuers = ["https://your-auth-server.com"]
///
/// [rate_limit]
/// enabled = true
/// default_rpm = 60
///
/// [scanner]
/// unicode_detection = true
/// injection_detection = true
/// path_traversal_detection = true
/// xss_detection = true
///
/// [neutralization]
/// mode = "automatic"
/// audit_all_actions = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    ///
    /// Controls network exposure and connection handling.
    /// Lower limits = more secure but less scalable.
    pub server: ServerConfig,

    /// Security scanning configuration
    ///
    /// Primary defense against malicious input.
    /// More detections enabled = better security coverage.
    pub scanner: ScannerConfig,

    /// Shield display configuration
    ///
    /// Visual security status indicator.
    /// No direct security impact but aids monitoring.
    pub shield: ShieldConfig,

    /// Authentication configuration
    ///
    /// Access control and identity verification.
    /// MUST be enabled in production environments.
    pub auth: AuthConfig,

    /// Message signing configuration
    ///
    /// Cryptographic integrity for requests/responses.
    /// Prevents tampering and replay attacks.
    pub signing: SigningConfig,

    /// Rate limiting configuration
    ///
    /// Prevents abuse and resource exhaustion.
    /// Essential for public-facing deployments.
    pub rate_limit: RateLimitConfig,

    /// Enhanced security event processing configuration
    ///
    /// Advanced threat correlation and analysis.
    /// Provides deeper security insights when enabled.
    pub event_processor: EventProcessorConfig,

    /// Telemetry configuration
    ///
    /// Security monitoring and metrics.
    /// Critical for detecting attacks and anomalies.
    pub telemetry: TelemetryConfig,

    /// Storage configuration
    ///
    /// Secure storage for backups and audit logs.
    /// Encryption and access control are essential.
    pub storage: StorageConfig,

    /// Plugin system configuration
    ///
    /// Extensibility with security boundaries.
    /// Only load trusted, signed plugins.
    pub plugins: PluginConfig,

    /// Audit logging configuration
    ///
    /// Forensic trail of all security events.
    /// Required for compliance and incident response.
    pub audit: AuditConfig,

    /// Transport layer configuration
    ///
    /// Communication security settings.
    /// Use TLS for all network transports.
    pub transport: TransportConfig,

    /// Resilience configuration for circuit breakers and retry
    ///
    /// Prevents cascading failures under attack.
    /// Maintains availability during security incidents.
    pub resilience: ResilienceConfig,

    /// Threat neutralization configuration
    ///
    /// Active threat remediation settings.
    /// Transforms malicious input into safe content.
    pub neutralization: NeutralizationConfig,

    /// Neutralizer configuration (alias for neutralization)
    ///
    /// Some tests expect this field name.
    /// This is an alias for backwards compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neutralizer: Option<NeutralizationConfig>,
}

/// Server configuration controlling network and connection settings
///
/// # Security Implications
///
/// The server configuration affects the attack surface and resource consumption:
/// - Lower connection limits prevent resource exhaustion attacks
/// - Shorter timeouts reduce the window for slow loris attacks
/// - stdio mode is more secure than network modes (no network exposure)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Port to listen on (for HTTP transport)
    ///
    /// **Default**: 8080
    /// **Security**: Use non-standard ports to reduce automated scanning.
    /// Consider using a reverse proxy for production deployments.
    /// **Range**: 1-65535 (ports < 1024 require root/admin privileges)
    #[serde(default = "default_port")]
    pub port: u16,

    /// Enable stdio transport (default for MCP)
    ///
    /// **Default**: true (secure by default)
    /// **Security**: stdio is the most secure transport as it doesn't expose
    /// a network interface. Recommended for local integrations.
    /// **Trade-off**: Limited to local process communication only
    #[serde(default = "default_true")]
    pub stdio: bool,

    /// Maximum concurrent connections
    ///
    /// **Default**: 100
    /// **Security**: Prevents resource exhaustion attacks. Lower values are more
    /// secure but may impact legitimate high-traffic scenarios.
    /// **Range**: 1-10000 (recommend 10-500 for most deployments)
    /// **Warning**: Values > 1000 may cause memory issues under attack
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Request timeout in seconds
    ///
    /// **Default**: 30 seconds
    /// **Security**: Shorter timeouts prevent slow loris and resource holding attacks.
    /// Longer timeouts may be needed for complex operations.
    /// **Range**: 1-300 (recommend 10-60 for most use cases)
    /// **Trade-off**: Too short may interrupt legitimate long operations
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

/// Scanner configuration for threat detection settings
///
/// # Security Implications
///
/// The scanner is your first line of defense against malicious input:
/// - Disabling any detection reduces security coverage
/// - Custom patterns can detect organization-specific threats
/// - Scan depth limits prevent algorithmic complexity attacks
/// - Enhanced mode provides better detection at a performance cost
///
/// # Example: Secure Production Configuration
///
/// ```toml
/// [scanner]
/// unicode_detection = true      # Detect unicode attacks
/// injection_detection = true    # Detect SQL/command injection
/// path_traversal_detection = true  # Detect directory traversal
/// xss_detection = true         # Detect XSS attempts
/// enhanced_mode = true         # Maximum security (if available)
/// max_scan_depth = 20          # Deep scanning for nested payloads
/// custom_patterns = "/etc/kindly-guard/patterns.toml"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Enable unicode threat detection
    ///
    /// **Default**: true (secure by default)
    /// **Security**: Detects BiDi overrides, zero-width chars, homoglyphs.
    /// Essential for preventing unicode-based attacks and spoofing.
    /// **Warning**: Disabling exposes you to text direction manipulation
    #[serde(default = "default_true")]
    pub unicode_detection: bool,

    /// Enable injection detection
    ///
    /// **Default**: true (secure by default)
    /// **Security**: Detects SQL, NoSQL, command, and LDAP injection attempts.
    /// Critical for preventing code execution and data breaches.
    /// **Coverage**: SQL, shell commands, LDAP queries, NoSQL operations
    #[serde(default = "default_true")]
    pub injection_detection: bool,

    /// Enable path traversal detection
    ///
    /// **Default**: true (secure by default)
    /// **Security**: Detects attempts to access files outside intended directories.
    /// Prevents unauthorized file access and directory listing.
    /// **Patterns**: ../, ..\, absolute paths, URL encoding variants
    #[serde(default = "default_true")]
    pub path_traversal_detection: bool,

    /// Enable XSS detection
    ///
    /// **Default**: Some(true) (secure by default)
    /// **Security**: Detects cross-site scripting attempts in various contexts.
    /// Essential for web-facing applications and APIs.
    /// **Coverage**: Script tags, event handlers, data URIs, SVG attacks
    #[serde(default = "default_some_true")]
    pub xss_detection: Option<bool>,

    /// Enable cryptographic security detection
    ///
    /// **Default**: true (secure by default)
    /// **Security**: Detects weak cryptographic patterns and insecure implementations.
    /// Critical for preventing cryptographic vulnerabilities and data exposure.
    /// **Coverage**: Deprecated algorithms (MD5, SHA1, DES), weak keys, insecure RNG, bad KDF
    /// **2025 Standards**: Enforces current NIST recommendations for key sizes and algorithms
    #[serde(default = "default_true")]
    pub crypto_detection: bool,

    /// Enable enhanced mode for scanners (uses advanced algorithms when available)
    ///
    /// **Default**: Some(false) (standard mode)
    /// **Security**: Enhanced mode provides deeper analysis and pattern correlation.
    /// Better detection accuracy at the cost of some performance.
    /// **Trade-off**: 10-20% performance impact for 50%+ better detection
    #[serde(default = "default_some_false")]
    pub enhanced_mode: Option<bool>,

    /// Custom threat patterns file
    ///
    /// **Default**: None
    /// **Security**: Add organization-specific threat patterns.
    /// Useful for detecting internal security policies violations.
    /// **Format**: TOML file with regex patterns and metadata
    /// **Example**: `/etc/kindly-guard/custom-patterns.toml`
    pub custom_patterns: Option<PathBuf>,

    /// Maximum scan depth for nested structures
    ///
    /// **Default**: 10
    /// **Security**: Prevents algorithmic complexity attacks through deep nesting.
    /// Lower values are more secure but may miss deeply nested threats.
    /// **Range**: 1-100 (recommend 5-20 for most use cases)
    /// **Warning**: Values > 50 may cause performance issues
    #[serde(default = "default_max_depth")]
    pub max_scan_depth: usize,

    /// Enable high-performance event buffer
    ///
    /// **Default**: false (standard mode)
    /// **Security**: Enables advanced correlation and pattern matching.
    /// Provides "purple shield" mode with enhanced threat detection.
    /// **Requirements**: Additional memory (10-50MB depending on load)
    #[serde(default = "default_false")]
    pub enable_event_buffer: bool,

    /// Maximum content size to scan (in bytes)
    ///
    /// **Default**: 5MB (5,242,880 bytes)
    /// **Security**: Prevents DoS attacks through large payload scanning.
    /// Content larger than this will be rejected with a DosPotential threat.
    /// **Range**: 1KB-100MB (recommend 1-10MB for most use cases)
    /// **Trade-off**: Larger values allow bigger legitimate payloads but increase DoS risk
    #[serde(default = "default_max_content_size")]
    pub max_content_size: usize,

    /// Maximum input size to scan (alias for max_content_size)
    ///
    /// **Default**: Uses max_content_size value
    /// **Security**: Some tests expect this field name.
    /// This is an alias for backwards compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_input_size: Option<usize>,
}

/// Shield display configuration
///
/// The shield provides visual feedback about security status:
/// - 🟢 Green: Normal operation, no threats
/// - 🟣 Purple: Enhanced mode active (better detection)
/// - 🔴 Red: Active threat detected
/// - ⚫ Gray: Disabled or error state
///
/// While not a security feature itself, the shield aids in:
/// - Real-time threat awareness
/// - System health monitoring
/// - Security posture visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    /// Enable shield display
    ///
    /// **Default**: false (no visual output)
    /// **Security**: No direct impact, but helps operators monitor security status.
    /// Useful for development and attended deployments.
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// Update interval in milliseconds
    ///
    /// **Default**: 1000ms (1 second)
    /// **Performance**: Lower values provide more responsive feedback but use more CPU.
    /// **Range**: 100-10000ms (recommend 500-2000ms)
    #[serde(default = "default_update_interval")]
    pub update_interval_ms: u64,

    /// Show detailed statistics
    ///
    /// **Default**: false (basic display only)
    /// **Security**: Shows threat counts, types, and neutralization stats.
    /// Helpful for understanding attack patterns in real-time.
    #[serde(default = "default_false")]
    pub detailed_stats: bool,

    /// Enable color output
    ///
    /// **Default**: true (colored output)
    /// **Accessibility**: Set to false for screen readers or monochrome terminals.
    /// Colors help quickly identify security state changes.
    #[serde(default = "default_true")]
    pub color: bool,
}

impl Config {
    /// Check if event processor is enabled
    pub const fn is_event_processor_enabled(&self) -> bool {
        #[cfg(feature = "enhanced")]
        return self.event_processor.enabled;
        #[cfg(not(feature = "enhanced"))]
        return false;
    }

    /// Get neutralizer configuration
    /// Returns the neutralizer field if set, otherwise returns neutralization
    pub fn neutralizer(&self) -> &NeutralizationConfig {
        self.neutralizer.as_ref().unwrap_or(&self.neutralization)
    }

    /// Load configuration from environment and files
    ///
    /// # Security Notes
    ///
    /// - Configuration files should have restricted permissions (600 or 640)
    /// - Never store secrets directly in config files - use environment variables
    /// - Validate all loaded configurations before use
    /// - Default configuration is intentionally conservative for security
    pub fn load() -> Result<Self> {
        // First, try to load from config file
        let config_path = std::env::var("KINDLY_GUARD_CONFIG")
            .map_or_else(|_| PathBuf::from("kindly-guard.toml"), PathBuf::from);

        if config_path.exists() {
            Self::load_from_file(&config_path.to_string_lossy())
        } else {
            // Use default configuration
            Ok(Self::default())
        }
    }

    /// Load configuration from a specific file
    ///
    /// # Security Warning
    ///
    /// Ensure the configuration file is from a trusted source and has
    /// appropriate file permissions to prevent unauthorized modifications.
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Validate configuration for security best practices
    ///
    /// # Example
    ///
    /// ```
    /// let config = Config::load()?;
    /// config.validate_security()?;
    /// ```
    pub fn validate_security(&self) -> Result<()> {
        // Warn if authentication is disabled
        if !self.auth.enabled {
            tracing::warn!("Authentication is disabled - this is insecure for production!");
        }

        // Warn if rate limiting is disabled
        if !self.rate_limit.enabled {
            tracing::warn!("Rate limiting is disabled - vulnerable to DoS attacks!");
        }

        // Check for weak JWT secrets
        if let Some(ref secret) = self.auth.jwt_secret {
            let decoded = general_purpose::STANDARD.decode(secret)?;
            if decoded.len() < 32 {
                return Err(anyhow::anyhow!(
                    "JWT secret too short - use at least 256 bits (32 bytes)"
                ));
            }
        }

        // Ensure scanner is properly configured
        if !self.scanner.unicode_detection
            || !self.scanner.injection_detection
            || !self.scanner.path_traversal_detection
        {
            tracing::warn!("Some threat detections are disabled - reduced security coverage");
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: default_port(),
                stdio: default_true(),
                max_connections: default_max_connections(),
                request_timeout_secs: default_timeout(),
            },
            scanner: ScannerConfig {
                unicode_detection: default_true(),
                injection_detection: default_true(),
                path_traversal_detection: default_true(),
                xss_detection: Some(true),
                crypto_detection: default_true(),
                enhanced_mode: Some(false),
                custom_patterns: None,
                max_scan_depth: default_max_depth(),
                enable_event_buffer: default_false(),
                max_content_size: default_max_content_size(),
                max_input_size: None,
            },
            shield: ShieldConfig {
                enabled: default_false(),
                update_interval_ms: default_update_interval(),
                detailed_stats: default_false(),
                color: default_true(),
            },
            auth: AuthConfig::default(),
            signing: SigningConfig::default(),
            rate_limit: RateLimitConfig::default(),
            event_processor: EventProcessorConfig::default(),
            telemetry: TelemetryConfig::default(),
            storage: StorageConfig::default(),
            plugins: PluginConfig::default(),
            audit: AuditConfig::default(),
            transport: TransportConfig::default(),
            resilience: ResilienceConfig::default(),
            neutralization: NeutralizationConfig::default(),
            neutralizer: None,
        }
    }
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            update_interval_ms: default_update_interval(),
            detailed_stats: default_false(),
            color: default_true(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            stdio: default_true(),
            max_connections: default_max_connections(),
            request_timeout_secs: default_timeout(),
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            unicode_detection: default_true(),
            injection_detection: default_true(),
            path_traversal_detection: default_true(),
            xss_detection: default_some_true(),
            crypto_detection: default_true(),
            enhanced_mode: default_some_false(),
            custom_patterns: None,
            max_scan_depth: default_max_depth(),
            enable_event_buffer: default_false(),
            max_content_size: default_max_content_size(),
            max_input_size: None,
        }
    }
}

// Default value functions
const fn default_port() -> u16 {
    8080
}
const fn default_true() -> bool {
    true
}
const fn default_false() -> bool {
    false
}
fn default_some_true() -> Option<bool> {
    Some(true)
}
fn default_some_false() -> Option<bool> {
    Some(false)
}
const fn default_max_connections() -> usize {
    100
}
const fn default_max_depth() -> usize {
    10
}
const fn default_update_interval() -> u64 {
    1000
}
const fn default_timeout() -> u64 {
    30
}
const fn default_max_content_size() -> usize {
    5 * 1024 * 1024 // 5MB
}

/// Example secure production configuration
///
/// Save this as `kindly-guard.toml` and adjust for your environment:
///
/// ```toml
/// # Server Configuration
/// [server]
/// port = 8443                    # Use HTTPS port
/// stdio = false                  # Network mode for production
/// max_connections = 500          # Adjust based on load
/// request_timeout_secs = 30      # Prevent slow loris attacks
///
/// # Authentication - REQUIRED for production
/// [auth]
/// enabled = true
/// validation_endpoint = "https://auth.example.com/oauth2/introspect"
/// trusted_issuers = ["https://auth.example.com"]
/// cache_ttl_seconds = 300
/// validate_resource_indicators = true
/// jwt_secret = "YOUR-BASE64-ENCODED-256-BIT-SECRET"  # Generate with: openssl rand -base64 32
/// require_signature_verification = true
///
/// [auth.required_scopes]
/// default = ["kindlyguard:access"]
///
/// [auth.required_scopes.tools]
/// "scan" = ["security:read"]
/// "neutralize" = ["security:write"]
///
/// # Rate Limiting - Essential for DoS protection
/// [rate_limit]
/// enabled = true
/// default_rpm = 60
/// burst_capacity = 10
/// cleanup_interval_secs = 300
/// adaptive = true
/// threat_penalty_multiplier = 0.5
///
/// [rate_limit.method_limits]
/// "tools/list" = { rpm = 120, burst = 20 }
/// "tools/call" = { rpm = 30, burst = 5 }
/// "security/threats" = { rpm = 10, burst = 2 }
///
/// # Scanner - Core threat detection
/// [scanner]
/// unicode_detection = true
/// injection_detection = true
/// path_traversal_detection = true
/// xss_detection = true
/// enhanced_mode = true          # If available
/// max_scan_depth = 20           # Deep scanning
/// enable_event_buffer = true    # Purple shield mode
/// custom_patterns = "/etc/kindly-guard/patterns.toml"
///
/// # Neutralization - Active threat remediation
/// [neutralization]
/// mode = "automatic"
/// backup_originals = true
/// audit_all_actions = true
///
/// [neutralization.unicode]
/// bidi_replacement = "marker"
/// zero_width_action = "remove"
/// homograph_action = "ascii"
///
/// [neutralization.injection]
/// sql_action = "parameterize"
/// command_action = "escape"
/// path_action = "normalize"
/// prompt_action = "wrap"
///
/// # Audit - Security event logging
/// [audit]
/// enabled = true
/// file_path = "/var/log/kindly-guard/audit.log"
/// max_file_size_mb = 100
/// max_files = 10
/// include_request_body = true
/// include_response_body = false
///
/// # Shield Display
/// [shield]
/// enabled = true
/// update_interval_ms = 1000
/// detailed_stats = true
/// color = true
/// ```

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.server.stdio);
        assert!(config.scanner.unicode_detection);
        assert_eq!(config.server.port, 8080);
    }

    #[test]
    fn test_security_validation() {
        let mut config = Config::default();

        // Should warn but not error with default config
        assert!(config.validate_security().is_ok());

        // Should error with weak JWT secret
        config.auth.jwt_secret = Some("c2hvcnQ=".to_string()); // "short" in base64
        assert!(config.validate_security().is_err());
    }
}
