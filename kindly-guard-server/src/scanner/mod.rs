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
//! Security scanner module for threat detection
//!
//! This module provides comprehensive security scanning capabilities for detecting
//! various types of threats in text and JSON inputs. It combines multiple specialized
//! scanners to provide defense-in-depth protection.
//!
//! # Architecture
//!
//! The scanner module follows a modular architecture with specialized sub-scanners:
//!
//! - **Unicode Scanner** (`unicode`): Detects Unicode-based attacks including:
//!   - Invisible characters (zero-width spaces, joiners)
//!   - BiDi override attacks for text spoofing
//!   - Homograph attacks using similar-looking characters
//!   - Dangerous control characters
//!
//! - **Injection Scanner** (`injection`): Detects various injection attacks:
//!   - SQL injection patterns
//!   - Command injection attempts
//!   - Prompt injection for LLMs
//!   - Path traversal attempts
//!   - LDAP, XML, and NoSQL injections
//!
//! - **XSS Scanner** (`xss_scanner`): Detects cross-site scripting:
//!   - Script tags and event handlers
//!   - JavaScript URLs and data URIs
//!   - HTML entity encoding bypasses
//!
//! - **Pattern Scanner** (`patterns`): Customizable threat patterns:
//!   - MCP-specific threats (session IDs, tokens)
//!   - Tool poisoning attempts
//!   - Custom patterns from configuration
//!
//! - **Crypto Scanner** (`crypto`): Detects cryptographic security issues:
//!   - Deprecated algorithms (MD5, SHA1, DES)
//!   - Insecure random number generation
//!   - Weak key sizes for 2025 standards
//!   - Insecure encryption modes (ECB)
//!   - Bad key derivation practices
//!
//! # Configuration
//!
//! The scanner behavior is controlled through `ScannerConfig`:
//!
//! ```toml
//! [scanner]
//! # Enable/disable specific threat detection types
//! unicode_detection = true          # Detect Unicode-based attacks
//! injection_detection = true        # Detect injection attempts
//! path_traversal_detection = true   # Detect directory traversal
//! xss_detection = true             # Detect XSS patterns
//! crypto_detection = true          # Detect weak crypto patterns
//!
//! # Performance and limits
//! max_scan_depth = 20              # Max recursion for JSON scanning
//! enhanced_mode = false            # Enable advanced detection algorithms
//! enable_event_buffer = false      # Enable event correlation (requires enhanced feature)
//!
//! # Custom patterns
//! custom_patterns = "/etc/kindly-guard/patterns.toml"  # Optional custom patterns file
//! ```
//!
//! # Security Principles
//!
//! 1. **Defense in Depth**: Multiple scanners provide overlapping protection
//! 2. **Type Safety**: All threats are represented as typed enums, not strings
//! 3. **Fail Safe**: Errors in one scanner don't affect others
//! 4. **Performance**: Zero-copy scanning where possible, SIMD optimizations available
//! 5. **Extensibility**: Plugin system allows custom threat detection
//!
//! # Usage Example
//!
//! ```no_run
//! use kindly_guard_server::config::ScannerConfig;
//! use kindly_guard_server::scanner::{SecurityScanner, Severity};
//!
//! // Configure scanner
//! let config = ScannerConfig {
//!     unicode_detection: true,
//!     injection_detection: true,
//!     xss_detection: Some(true),
//!     max_scan_depth: 20,
//!     ..Default::default()
//! };
//!
//! // Create scanner instance
//! let scanner = SecurityScanner::new(config)?;
//!
//! // Scan text input
//! let threats = scanner.scan_text("SELECT * FROM users WHERE id = '1' OR '1'='1'")?;
//!
//! // Handle detected threats
//! for threat in threats {
//!     if threat.severity >= Severity::High {
//!         // Block the request
//!         return Err("Security threat detected");
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

pub mod crypto;
pub mod injection;
pub mod patterns;
pub mod sync_wrapper;
pub mod unicode;
pub mod xss_scanner;

pub use crypto::CryptoScanner;
pub use injection::InjectionScanner;
pub use patterns::ThreatPatterns;
pub use unicode::UnicodeScanner;
pub use xss_scanner::{create_xss_scanner, XssScanner};

/// Main security scanner combining all threat detection
///
/// The `SecurityScanner` is the central component for detecting security threats in text and JSON inputs.
/// It combines multiple specialized scanners (Unicode, Injection, XSS, Crypto) and supports plugin-based extensions.
///
/// # Architecture
/// - **Unicode Scanner**: Detects invisible characters, BiDi spoofing, homograph attacks
/// - **Injection Scanner**: Detects SQL, command, prompt, and other injection attempts
/// - **XSS Scanner**: Detects cross-site scripting patterns
/// - **Crypto Scanner**: Detects weak cryptographic patterns and insecure implementations
/// - **Plugin System**: Allows custom threat detection via external plugins
///
/// # Security Considerations
/// - All scanners run with configurable depth limits to prevent DoS attacks
/// - Pattern matching uses size-limited regex to prevent ReDoS attacks
/// - Results are type-safe using enums, never raw strings for security decisions
/// - Enhanced mode provides additional correlation and pattern analysis
///
/// # Performance
/// - Scanners use zero-copy operations where possible
/// - Text is scanned in a single pass per scanner
/// - JSON scanning uses recursive descent with depth limiting
/// - Enhanced mode may use SIMD optimizations when available
pub struct SecurityScanner {
    unicode_scanner: UnicodeScanner,
    injection_scanner: InjectionScanner,
    xss_scanner: Arc<dyn XssScanner>,
    crypto_scanner: CryptoScanner,
    pub patterns: ThreatPatterns,
    config: crate::config::ScannerConfig,
    plugin_manager: Option<Arc<dyn crate::plugins::PluginManagerTrait>>,
    #[allow(dead_code)]
    #[cfg(feature = "enhanced")]
    event_processor: Option<Arc<dyn crate::traits::SecurityEventProcessor>>,
}

/// Represents a detected security threat
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Threat {
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub location: Location,
    pub description: String,
    pub remediation: Option<String>,
}

/// Types of security threats that can be detected
///
/// This enum categorizes different attack vectors and malicious patterns
/// that the security scanner can identify. Each variant represents a specific
/// threat type with unique characteristics and security implications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    // Unicode threats
    /// Invisible Unicode characters used to hide malicious content
    ///
    /// **Detection**: Zero-width spaces, joiners, and other invisible characters
    /// **Security Impact**: Can hide malicious code or bypass filters
    /// **Common Vectors**: Comments, usernames, file names
    /// **Recommended Response**: Remove or escape invisible characters
    UnicodeInvisible,

    /// Bidirectional (BiDi) text spoofing attacks
    ///
    /// **Detection**: Right-to-left override (U+202E) and related BiDi control characters
    /// **Security Impact**: Can reverse text display to mislead users (e.g., "txt.exe" appears as "exe.txt")
    /// **Common Vectors**: File names, URLs, email addresses
    /// **Recommended Response**: Block or escape BiDi control characters
    UnicodeBiDi,

    /// Homograph attacks using similar-looking Unicode characters
    ///
    /// **Detection**: Characters that visually resemble ASCII but have different code points
    /// **Security Impact**: Phishing attacks, domain spoofing (e.g., "аpple.com" with Cyrillic 'а')
    /// **Common Vectors**: URLs, domain names, usernames
    /// **Recommended Response**: Convert to ASCII or warn users about mixed scripts
    UnicodeHomograph,

    /// Dangerous Unicode control characters
    ///
    /// **Detection**: Format control, line/paragraph separators, other control characters
    /// **Security Impact**: Can break parsing, cause unexpected behavior, or bypass validation
    /// **Common Vectors**: Any text input, configuration files
    /// **Recommended Response**: Strip or escape control characters
    UnicodeControl,

    // Injection threats
    /// Prompt injection attacks against LLMs and AI systems
    ///
    /// **Detection**: Instructions attempting to override system prompts or context
    /// **Security Impact**: Can manipulate AI behavior, extract training data, or bypass restrictions
    /// **Common Vectors**: Chat interfaces, AI-powered features, automated responses
    /// **Recommended Response**: Wrap user input in safety context, escape control sequences
    PromptInjection,

    /// Command injection attacks targeting system shells
    ///
    /// **Detection**: Shell metacharacters, command separators, backticks
    /// **Security Impact**: Remote code execution, system compromise
    /// **Common Vectors**: System calls, file operations, process spawning
    /// **Recommended Response**: Use parameterized commands, escape shell metacharacters
    CommandInjection,

    /// Path traversal attacks attempting directory traversal
    ///
    /// **Detection**: "../", "..\\", absolute paths, null bytes in paths
    /// **Security Impact**: Unauthorized file access, information disclosure
    /// **Common Vectors**: File uploads, include statements, template paths
    /// **Recommended Response**: Normalize paths, validate against whitelist
    PathTraversal,

    /// SQL injection attacks against databases
    ///
    /// **Detection**: SQL keywords with quotes, UNION statements, comment sequences
    /// **Security Impact**: Data breach, data manipulation, authentication bypass
    /// **Common Vectors**: Search fields, login forms, URL parameters
    /// **Recommended Response**: Use parameterized queries, escape special characters
    SqlInjection,

    /// Cross-site scripting (XSS) attacks
    ///
    /// **Detection**: JavaScript code, event handlers, script tags
    /// **Security Impact**: Session hijacking, defacement, malware distribution
    /// **Common Vectors**: User comments, profile fields, search results
    /// **Recommended Response**: HTML encode output, use Content Security Policy
    CrossSiteScripting,

    /// LDAP injection attacks against directory services
    ///
    /// **Detection**: LDAP filter metacharacters, DN manipulation attempts
    /// **Security Impact**: Authentication bypass, information disclosure
    /// **Common Vectors**: Login systems, user lookups, group membership checks
    /// **Recommended Response**: Escape LDAP metacharacters, use parameterized filters
    LdapInjection,

    /// XML injection and XXE (XML External Entity) attacks
    ///
    /// **Detection**: DTD declarations, ENTITY definitions, SYSTEM keywords
    /// **Security Impact**: File disclosure, SSRF, denial of service
    /// **Common Vectors**: XML APIs, SOAP services, configuration files
    /// **Recommended Response**: Disable external entities, use safe XML parsers
    XmlInjection,

    /// NoSQL injection attacks against document databases
    ///
    /// **Detection**: MongoDB operators ($where, $ne), JavaScript in queries
    /// **Security Impact**: Data breach, authentication bypass, denial of service
    /// **Common Vectors**: REST APIs, search interfaces, user profiles
    /// **Recommended Response**: Validate input types, avoid string concatenation in queries
    NoSqlInjection,

    // MCP-specific threats
    /// Exposure of MCP session identifiers
    ///
    /// **Detection**: Session IDs in logs, URLs, or error messages
    /// **Security Impact**: Session hijacking, unauthorized access to MCP resources
    /// **Common Vectors**: Debug output, error messages, URLs
    /// **Recommended Response**: Redact session IDs, use secure session management
    SessionIdExposure,

    /// Tool poisoning attacks against MCP tools
    ///
    /// **Detection**: Malicious tool definitions, backdoored implementations
    /// **Security Impact**: Compromised tool execution, data exfiltration
    /// **Common Vectors**: Tool repositories, dynamic tool loading
    /// **Recommended Response**: Verify tool signatures, use tool allowlists
    ToolPoisoning,

    /// Token theft attempts targeting authentication tokens
    ///
    /// **Detection**: Token patterns in unexpected locations, extraction attempts
    /// **Security Impact**: Account takeover, unauthorized API access
    /// **Common Vectors**: Log files, error messages, client-side storage
    /// **Recommended Response**: Implement token rotation, use secure storage
    TokenTheft,

    /// Denial of Service attempt through oversized content
    ///
    /// **Detection**: Content exceeding configured size limits
    /// **Security Impact**: Resource exhaustion, service unavailability
    /// **Common Vectors**: Large file uploads, oversized API payloads
    /// **Recommended Response**: Reject oversized content, implement rate limiting
    DosPotential,

    // Plugin-detected threats
    /// Custom threat detected by a security plugin
    ///
    /// **Detection**: Varies by plugin implementation
    /// **Security Impact**: Depends on the specific threat
    /// **Common Vectors**: Plugin-specific
    /// **Recommended Response**: Consult plugin documentation for remediation
    Custom(String),
}

/// Threat severity levels
///
/// Indicates the potential impact and urgency of a detected threat.
/// The ordering is important: Low < Medium < High < Critical.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low severity threats
    ///
    /// **Characteristics**: Minimal immediate risk, informational findings
    /// **Examples**: Suspicious but likely benign patterns, deprecated practices
    /// **Response Time**: Can be addressed during regular maintenance
    /// **Action**: Log and monitor, fix in next update cycle
    Low,

    /// Medium severity threats
    ///
    /// **Characteristics**: Moderate risk, potential for escalation
    /// **Examples**: Weak encoding, information leakage, misconfiguration
    /// **Response Time**: Should be addressed within days
    /// **Action**: Prioritize for next release, implement compensating controls
    Medium,

    /// High severity threats
    ///
    /// **Characteristics**: Significant risk, likely exploitable
    /// **Examples**: SQL injection, XSS, authentication bypass attempts
    /// **Response Time**: Address within hours to days
    /// **Action**: Immediate remediation, notify security team
    High,

    /// Critical severity threats
    ///
    /// **Characteristics**: Severe risk, actively exploitable, system compromise
    /// **Examples**: Remote code execution, complete authentication bypass, data breach
    /// **Response Time**: Immediate response required
    /// **Action**: Emergency patching, incident response activation
    Critical,
}

/// Location of a threat in the input
///
/// Provides precise information about where a threat was detected,
/// enabling accurate reporting and targeted remediation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Location {
    /// Threat found in plain text content
    ///
    /// **Fields**:
    /// - `offset`: Byte offset from start of text
    /// - `length`: Length of the threat in bytes
    ///
    /// **Usage**: For threats in plain text, source code, or string literals
    /// **Example**: SQL injection at offset 142, length 25
    Text { offset: usize, length: usize },

    /// Threat found in JSON structure
    ///
    /// **Fields**:
    /// - `path`: JSONPath-style location (e.g., "$.user.name", "$.items[2].value")
    ///
    /// **Usage**: For threats in JSON documents, API payloads, configuration files
    /// **Example**: XSS attempt at path "$.comments[0].text"
    Json { path: String },

    /// Threat found in binary data
    ///
    /// **Fields**:
    /// - `offset`: Byte offset in binary stream
    ///
    /// **Usage**: For threats in binary protocols, encoded data, file uploads
    /// **Example**: Malicious pattern at byte offset 0x1A4F
    Binary { offset: usize },
}

/// Scanner errors
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Maximum scan depth exceeded")]
    MaxDepthExceeded,

    #[error("Invalid input format: {0}")]
    InvalidInput(String),

    #[error("Pattern compilation failed: {0}")]
    PatternError(String),

    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

/// Result type for scanner operations
pub type ScanResult = Result<Vec<Threat>, ScanError>;

impl SecurityScanner {
    /// Set the plugin manager for this scanner
    ///
    /// Enables plugin-based threat detection by attaching a plugin manager to the scanner.
    /// Plugins can detect custom threats specific to your application or domain.
    ///
    /// # Arguments
    /// * `plugin_manager` - The plugin manager that will coordinate plugin scanning
    ///
    /// # Plugin Security
    /// - Plugins run in isolated contexts with limited permissions
    /// - Plugin errors are logged but don't fail the main scan
    /// - Each plugin has configurable timeouts to prevent DoS
    ///
    /// # Example
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use kindly_guard_server::scanner::SecurityScanner;
    /// # use kindly_guard_server::plugins::PluginManagerTrait;
    /// # let plugin_manager: Arc<dyn PluginManagerTrait> = todo!();
    /// let mut scanner = SecurityScanner::new(Default::default())?;
    /// scanner.set_plugin_manager(plugin_manager);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn set_plugin_manager(
        &mut self,
        plugin_manager: Arc<dyn crate::plugins::PluginManagerTrait>,
    ) {
        self.plugin_manager = Some(plugin_manager);
    }

    /// Create a new security scanner with the given configuration
    ///
    /// Initializes all sub-scanners and loads threat patterns based on the provided configuration.
    ///
    /// # Arguments
    /// * `config` - Scanner configuration controlling detection features and limits
    ///
    /// # Configuration Options
    /// - `unicode_detection`: Enable/disable Unicode threat detection
    /// - `injection_detection`: Enable/disable injection attack detection
    /// - `xss_detection`: Enable/disable XSS detection
    /// - `max_scan_depth`: Maximum recursion depth for JSON scanning (default: 20)
    /// - `custom_patterns`: Optional path to custom threat pattern file
    /// - `enhanced_mode`: Enable enhanced detection with advanced correlation
    ///
    /// # Returns
    /// - `Ok(SecurityScanner)` - Configured scanner ready for threat detection
    /// - `Err(ScanError)` - If pattern loading or scanner initialization fails
    ///
    /// # Errors
    /// - `ScanError::PatternError` - If custom patterns file is invalid
    /// - `ScanError::InvalidInput` - If scanner initialization fails
    ///
    /// # Security Best Practices
    /// - Always validate the custom patterns file path if provided
    /// - Set appropriate `max_scan_depth` to prevent stack exhaustion
    /// - Enable all detection types unless you have specific requirements
    ///
    /// # Example
    /// ```no_run
    /// use kindly_guard_server::config::ScannerConfig;
    /// use kindly_guard_server::scanner::SecurityScanner;
    ///
    /// // Basic configuration with all protections enabled
    /// let config = ScannerConfig {
    ///     unicode_detection: true,
    ///     injection_detection: true,
    ///     xss_detection: Some(true),
    ///     max_scan_depth: 20,
    ///     custom_patterns: None,
    ///     enhanced_mode: Some(false),
    ///     enable_event_buffer: false,
    /// };
    ///
    /// let scanner = SecurityScanner::new(config)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Performance Notes
    /// - Scanner initialization is relatively expensive due to pattern compilation
    /// - Reuse scanner instances across multiple scans for better performance
    /// - Enhanced mode may increase memory usage but improves detection accuracy
    pub fn new(config: crate::config::ScannerConfig) -> Result<Self, ScanError> {
        Self::with_processor(config, None)
    }

    /// Create a new security scanner with an optional event processor
    ///
    /// This method allows creation of a scanner with enhanced capabilities through
    /// an event processor for advanced threat correlation and pattern analysis.
    ///
    /// # Arguments
    /// * `config` - Scanner configuration
    /// * `event_processor` - Optional processor for enhanced threat analysis
    ///
    /// # Enhanced Mode Features
    /// When an event processor is provided and `enable_event_buffer` is true:
    /// - Real-time threat correlation across multiple scans
    /// - Pattern analysis for identifying attack campaigns
    /// - Performance optimizations through event batching
    /// - Advanced metrics and analytics
    ///
    /// # Implementation Note
    /// This follows the trait-based architecture pattern where enhanced implementations
    /// are hidden behind trait abstractions, allowing for both standard and optimized
    /// scanning modes without exposing implementation details.
    pub fn with_processor(
        config: crate::config::ScannerConfig,
        #[allow(unused_variables)]
        event_processor: Option<Arc<dyn crate::traits::SecurityEventProcessor>>,
    ) -> Result<Self, ScanError> {
        let patterns = if let Some(path) = &config.custom_patterns {
            ThreatPatterns::load_from_file(path)?
        } else {
            ThreatPatterns::default()
        };

        // Use provided event processor if available and enabled
        #[cfg(feature = "enhanced")]
        let event_processor = if config.enable_event_buffer {
            event_processor
        } else {
            None
        };

        #[cfg(not(feature = "enhanced"))]
        let _event_processor: Option<Arc<dyn crate::traits::SecurityEventProcessor>> = None;

        // Create scanners with optional enhancement
        #[cfg(feature = "enhanced")]
        let mut unicode_scanner = UnicodeScanner::new();
        #[cfg(not(feature = "enhanced"))]
        let unicode_scanner = UnicodeScanner::new();
        
        #[cfg(feature = "enhanced")]
        let mut injection_scanner = InjectionScanner::new(&patterns)?;
        #[cfg(not(feature = "enhanced"))]
        let injection_scanner = InjectionScanner::new(&patterns)?;
        let crypto_scanner = CryptoScanner::new();

        // Create XSS scanner with trait-based architecture
        let xss_scanner = create_xss_scanner(
            patterns.xss_patterns().to_vec(),
            config.enhanced_mode.unwrap_or(false),
        )?;

        // Enhance scanners when processor is available
        #[cfg(feature = "enhanced")]
        if event_processor.is_some() {
            unicode_scanner.enable_enhancement();
            injection_scanner.enable_enhancement();
            tracing::debug!("Scanner optimization enabled");
        }

        Ok(Self {
            unicode_scanner,
            injection_scanner,
            xss_scanner,
            crypto_scanner,
            patterns,
            config,
            plugin_manager: None, // Will be set later
            #[cfg(feature = "enhanced")]
            event_processor,
        })
    }

    /// Scan text for threats
    pub fn scan_text(&self, text: &str) -> ScanResult {
        let mut threats = Vec::new();

        // Check for oversized content to prevent DoS
        if text.len() > self.config.max_content_size {
            threats.push(Threat {
                threat_type: ThreatType::DosPotential,
                severity: Severity::High,
                location: Location::Text {
                    offset: 0,
                    length: text.len(),
                },
                description: format!(
                    "Content size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    text.len(),
                    self.config.max_content_size
                ),
                remediation: Some(
                    "Reduce content size or increase max_content_size configuration".to_string(),
                ),
            });
            return Ok(threats);
        }

        // For large content, use chunk-based scanning with timeout
        const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
        const MAX_SCAN_TIME: std::time::Duration = std::time::Duration::from_secs(5);

        // If content is large, scan in chunks with early termination
        if text.len() > CHUNK_SIZE {
            return self.scan_text_chunked(text, CHUNK_SIZE, MAX_SCAN_TIME);
        }

        // For smaller content, use regular scanning
        self.scan_text_regular(text)
    }

    /// Scan large text in chunks with timeout protection
    fn scan_text_chunked(
        &self,
        text: &str,
        chunk_size: usize,
        max_scan_time: std::time::Duration,
    ) -> ScanResult {
        let mut all_threats = Vec::new();
        let scan_start = std::time::Instant::now();

        // Process text in chunks
        for (chunk_offset, chunk) in text.as_bytes().chunks(chunk_size).enumerate() {
            // Check timeout
            if scan_start.elapsed() > max_scan_time {
                tracing::warn!(
                    "Scan timeout reached after {} seconds, processed {} bytes of {}",
                    max_scan_time.as_secs(),
                    chunk_offset * chunk_size,
                    text.len()
                );
                all_threats.push(Threat {
                    threat_type: ThreatType::DosPotential,
                    severity: Severity::Medium,
                    location: Location::Text {
                        offset: chunk_offset * chunk_size,
                        length: text.len() - (chunk_offset * chunk_size),
                    },
                    description: "Scan timeout - content too large to scan completely".to_string(),
                    remediation: Some(
                        "Consider reducing content size or increasing scan timeout".to_string(),
                    ),
                });
                break;
            }

            // Convert chunk back to str safely
            let chunk_str = match std::str::from_utf8(chunk) {
                Ok(s) => s,
                Err(e) => {
                    // If chunk boundary splits a UTF-8 sequence, try to find a valid boundary
                    let valid_up_to = e.valid_up_to();
                    if valid_up_to == 0 {
                        continue; // Skip this chunk if we can't find any valid UTF-8
                    }
                    match std::str::from_utf8(&chunk[..valid_up_to]) {
                        Ok(s) => s,
                        Err(_) => continue, // Skip invalid chunk
                    }
                }
            };

            // Scan this chunk
            let chunk_threats = self.scan_text_regular(chunk_str)?;

            // Adjust threat locations to account for chunk offset
            let byte_offset = chunk_offset * chunk_size;
            for mut threat in chunk_threats {
                if let Location::Text { ref mut offset, .. } = threat.location {
                    *offset += byte_offset;
                }
                all_threats.push(threat);
            }
        }

        Ok(all_threats)
    }

    /// Regular scan implementation (extracted from original scan_text)
    fn scan_text_regular(&self, text: &str) -> ScanResult {
        let mut threats = Vec::new();

        // Use enhanced scanning when available
        #[cfg(feature = "enhanced")]
        if let Some(processor) = &self.event_processor {
            // Process scan event for correlation
            let event = crate::traits::SecurityEvent {
                event_type: "scan".to_string(),
                client_id: "scanner".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                metadata: serde_json::json!({
                    "preview": &text[..text.len().min(100)]
                }),
            };
            // Check if we're already in a runtime context
            if let Ok(_handle) = tokio::runtime::Handle::try_current() {
                // We're in a runtime, use std::thread::spawn to avoid blocking
                let processor_clone = processor.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    if let Ok(rt) = rt {
                        let _ = rt.block_on(processor_clone.process_event(event));
                    }
                })
                .join()
                .ok();
            } else {
                // Not in a runtime, create a new one
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(rt) = rt {
                    let _ = rt.block_on(processor.process_event(event));
                }
            }

            tracing::trace!("Optimized scanning active");
        }

        if self.config.unicode_detection {
            threats.extend(self.unicode_scanner.scan_text(text)?);
        }

        if self.config.injection_detection || self.config.path_traversal_detection {
            // Get all threats from injection scanner
            let injection_threats = self.injection_scanner.scan_text(text)?;

            // Filter based on configuration
            for threat in injection_threats {
                match threat.threat_type {
                    ThreatType::PathTraversal => {
                        if self.config.path_traversal_detection {
                            threats.push(threat);
                        }
                    }
                    _ => {
                        if self.config.injection_detection {
                            threats.push(threat);
                        }
                    }
                }
            }
        }

        // Run crypto scanner
        if self.config.crypto_detection {
            threats.extend(self.crypto_scanner.scan_text(text)?);
        }

        // Run XSS scanner (async scanner in sync context)
        if self.config.xss_detection.unwrap_or(true) {
            // Check if we're already in a runtime context
            let xss_threats = if let Ok(_handle) = tokio::runtime::Handle::try_current() {
                // We're in a runtime, use std::thread::spawn to run in a separate thread
                let text_clone = text.to_string();
                let xss_scanner = self.xss_scanner.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            ScanError::RuntimeError(format!("Failed to create runtime: {}", e))
                        })?;

                    rt.block_on(xss_scanner.scan_xss(&text_clone))
                })
                .join()
                .map_err(|_| ScanError::RuntimeError("Thread panic".to_string()))??
            } else {
                // Not in a runtime, create a new one
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        ScanError::RuntimeError(format!("Failed to create runtime: {}", e))
                    })?;

                rt.block_on(self.xss_scanner.scan_xss(text))?
            };
            threats.extend(xss_threats);
        }

        // Run plugin scanners if available
        if let Some(plugin_manager) = &self.plugin_manager {
            // Note: Plugin scanning is currently only supported when called from
            // non-async contexts (e.g., from the MCP server). The CLI uses async
            // and cannot call plugins from within its runtime.
            if tokio::runtime::Handle::try_current().is_err() {
                use crate::plugins::{ScanContext, ScanOptions};
                use tokio::runtime::Runtime;

                let context = ScanContext {
                    data: text.as_bytes(),
                    content_type: Some("text/plain"),
                    client_id: "scanner",
                    metadata: &std::collections::HashMap::new(),
                    options: ScanOptions::default(),
                };

                // Create runtime for async plugin calls
                let rt = Runtime::new().map_err(|e| ScanError::InvalidInput(e.to_string()))?;

                match rt.block_on(plugin_manager.scan_all(context)) {
                    Ok(plugin_results) => {
                        for (_plugin_id, plugin_threats) in plugin_results {
                            threats.extend(plugin_threats);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Plugin scan error: {}", e);
                    }
                }
            } else {
                tracing::debug!("Plugin scanning skipped in async context");
            }
        }

        // Track threats through processor for pattern analysis
        #[cfg(feature = "enhanced")]
        if !threats.is_empty() {
            if let Some(processor) = &self.event_processor {
                for threat in &threats {
                    let event = crate::traits::SecurityEvent {
                        event_type: "threat_detected".to_string(),
                        client_id: "scanner".to_string(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        metadata: serde_json::json!({
                            "threat_type": match &threat.threat_type {
                                ThreatType::Custom(name) => name.clone(),
                                _ => format!("{:?}", threat.threat_type),
                            },
                            "severity": format!("{:?}", threat.severity)
                        }),
                    };
                    // Check if we're already in a runtime context
                    if let Ok(_handle) = tokio::runtime::Handle::try_current() {
                        // We're in a runtime, use std::thread::spawn to avoid blocking
                        let processor_clone = processor.clone();
                        std::thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build();
                            if let Ok(rt) = rt {
                                let _ = rt.block_on(processor_clone.process_event(event));
                            }
                        })
                        .join()
                        .ok();
                    } else {
                        // Not in a runtime, create a new one
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build();
                        if let Ok(rt) = rt {
                            let _ = rt.block_on(processor.process_event(event));
                        }
                    }
                }
            }
        }

        Ok(threats)
    }

    /// Scan JSON value for security threats
    ///
    /// Recursively scans a JSON structure for threats in all string values and object keys.
    /// This method is essential for securing API endpoints that accept JSON payloads.
    ///
    /// # Arguments
    /// * `value` - The JSON value to scan (can be any valid JSON type)
    ///
    /// # Returns
    /// - `Ok(Vec<Threat>)` - List of detected threats with JSON path locations
    /// - `Err(ScanError)` - If scanning fails or depth limit is exceeded
    ///
    /// # Security Considerations
    /// - **Depth Limiting**: Prevents stack exhaustion from deeply nested JSON
    /// - **Key Scanning**: Object keys are scanned as they can contain payloads
    /// - **Path Tracking**: Each threat includes the JSON path for precise location
    /// - **Type Safety**: Only string values are scanned (numbers/bools are safe)
    ///
    /// # JSON Path Format
    /// Threats are reported with JSON paths for easy identification:
    /// - Root: `$`
    /// - Object field: `$.field` or `$.parent.child`
    /// - Array element: `$[0]` or `$.array[2]`
    /// - Nested: `$.users[0].name`
    ///
    /// # Error Handling
    /// - `ScanError::MaxDepthExceeded` - If nesting exceeds `max_scan_depth`
    /// - `ScanError::InvalidInput` - If JSON serialization fails
    /// - Plugin errors are logged but don't fail the scan
    ///
    /// # Example
    /// ```no_run
    /// use kindly_guard_server::scanner::{SecurityScanner, Location};
    /// use serde_json::json;
    ///
    /// # let scanner = SecurityScanner::new(Default::default())?;
    /// // Scan a JSON API request
    /// let request = json!({
    ///     "user": {
    ///         "name": "admin' OR '1'='1",
    ///         "bio": "Hello\u{202E}World",  // BiDi override
    ///         "tags": ["safe", "<script>alert(1)</script>"]
    ///     }
    /// });
    ///
    /// let threats = scanner.scan_json(&request)?;
    ///
    /// for threat in threats {
    ///     if let Location::Json { path } = &threat.location {
    ///         eprintln!("Threat at {}: {}", path, threat.description);
    ///         // Outputs:
    ///         // Threat at $.user.name: SQL Injection
    ///         // Threat at $.user.bio: BiDi Text Spoofing
    ///         // Threat at $.user.tags[1]: Cross-Site Scripting
    ///     }
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Performance and Security Trade-offs
    /// - **Depth vs Security**: Lower `max_scan_depth` prevents DoS but may miss threats
    /// - **Memory Usage**: Large JSON structures consume memory proportional to depth
    /// - **Scan Time**: O(n) where n is total number of string values in JSON
    /// - **Recommendation**: Set depth limit based on expected legitimate nesting
    ///
    /// # Best Practices
    /// - Validate JSON schema before scanning for structural attacks
    /// - Consider rate limiting based on JSON size/complexity
    /// - Log scan results for security monitoring and pattern analysis
    /// - Implement allowlists for known-safe patterns to reduce false positives
    pub fn scan_json(&self, value: &serde_json::Value) -> ScanResult {
        let mut threats = self.scan_json_recursive(value, "$", 0)?;

        // Run plugin scanners if available
        if let Some(plugin_manager) = &self.plugin_manager {
            // Note: Plugin scanning is currently only supported when called from
            // non-async contexts (e.g., from the MCP server). The CLI uses async
            // and cannot call plugins from within its runtime.
            if tokio::runtime::Handle::try_current().is_err() {
                use crate::plugins::{ScanContext, ScanOptions};
                use tokio::runtime::Runtime;

                // Convert JSON to bytes for plugin scanning
                let json_bytes = serde_json::to_vec(value)
                    .map_err(|e| ScanError::InvalidInput(e.to_string()))?;

                let context = ScanContext {
                    data: &json_bytes,
                    content_type: Some("application/json"),
                    client_id: "scanner",
                    metadata: &std::collections::HashMap::new(),
                    options: ScanOptions::default(),
                };

                // Create runtime for async plugin calls
                let rt = Runtime::new().map_err(|e| ScanError::InvalidInput(e.to_string()))?;

                match rt.block_on(plugin_manager.scan_all(context)) {
                    Ok(plugin_results) => {
                        for (_plugin_id, plugin_threats) in plugin_results {
                            // Convert plugin threats to have JSON location
                            for mut threat in plugin_threats {
                                if matches!(threat.location, Location::Text { .. }) {
                                    threat.location = Location::Json {
                                        path: "$".to_string(),
                                    };
                                }
                                threats.push(threat);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Plugin scan error: {}", e);
                    }
                }
            } else {
                tracing::debug!("Plugin scanning skipped in async context");
            }
        }

        Ok(threats)
    }

    /// Recursively scan JSON values with depth tracking
    ///
    /// # Implementation Details
    /// - Depth is tracked to prevent stack exhaustion from malicious deeply nested JSON
    /// - Object keys are scanned as they can contain injection payloads
    /// - Arrays are indexed numerically in the path (e.g., `$[0]`, `$[1]`)
    /// - Only string values are scanned; numbers, booleans, and null are inherently safe
    ///
    /// # Security Note
    /// This method is private to ensure depth tracking is always enforced. Public API
    /// must use `scan_json()` which initializes depth tracking correctly.
    fn scan_json_recursive(
        &self,
        value: &serde_json::Value,
        path: &str,
        depth: usize,
    ) -> ScanResult {
        if depth > self.config.max_scan_depth {
            return Err(ScanError::MaxDepthExceeded);
        }

        let mut threats = Vec::new();

        match value {
            serde_json::Value::String(s) => {
                let text_threats = self.scan_text(s)?;
                for mut threat in text_threats {
                    threat.location = Location::Json {
                        path: path.to_string(),
                    };
                    threats.push(threat);
                }
            }
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    // Check the key itself
                    if let Ok(key_threats) = self.scan_text(key) {
                        for mut threat in key_threats {
                            threat.location = Location::Json {
                                path: format!("{path}.{key}"),
                            };
                            threats.push(threat);
                        }
                    }

                    // Recursively check the value
                    let sub_path = format!("{path}.{key}");
                    threats.extend(self.scan_json_recursive(val, &sub_path, depth + 1)?);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let sub_path = format!("{path}[{i}]");
                    threats.extend(self.scan_json_recursive(val, &sub_path, depth + 1)?);
                }
            }
            _ => {} // Numbers, booleans, null are safe
        }

        Ok(threats)
    }

    /// Get scanner statistics for monitoring and analysis
    ///
    /// Returns current statistics from all enabled scanners including:
    /// - Total number of scans performed
    /// - Number of threats detected by type
    /// - Performance metrics when enhanced mode is enabled
    ///
    /// # Thread Safety
    /// Statistics are collected using atomic operations and are safe to read
    /// while scanning is in progress on other threads.
    ///
    /// # Example
    /// ```no_run
    /// # use kindly_guard_server::scanner::SecurityScanner;
    /// # let scanner = SecurityScanner::new(Default::default())?;
    /// let stats = scanner.stats();
    /// println!("Total scans: {}", stats.total_scans);
    /// println!("Unicode threats: {}", stats.unicode_threats_detected);
    /// println!("Injection threats: {}", stats.injection_threats_detected);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn stats(&self) -> ScannerStats {
        let stats = ScannerStats {
            unicode_threats_detected: self.unicode_scanner.threats_detected(),
            injection_threats_detected: self.injection_scanner.threats_detected(),
            total_scans: self.unicode_scanner.total_scans() + self.injection_scanner.total_scans(),
        };

        // Enhance stats with processor metrics
        #[cfg(feature = "enhanced")]
        if let Some(processor) = &self.event_processor {
            let processor_stats = processor.get_stats();
            // Add processed events to total scans for more accurate metrics
            stats.total_scans += processor_stats.events_processed / 10; // Approximate scan count
            tracing::trace!("Analytics enhanced");
        }

        stats
    }
}

/// Scanner statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerStats {
    pub unicode_threats_detected: u64,
    pub injection_threats_detected: u64,
    pub total_scans: u64,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnicodeInvisible => write!(f, "Invisible Unicode Character"),
            Self::UnicodeBiDi => write!(f, "BiDi Text Spoofing"),
            Self::UnicodeHomograph => write!(f, "Homograph Attack"),
            Self::UnicodeControl => write!(f, "Dangerous Control Character"),
            Self::PromptInjection => write!(f, "Prompt Injection"),
            Self::CommandInjection => write!(f, "Command Injection"),
            Self::PathTraversal => write!(f, "Path Traversal"),
            Self::SqlInjection => write!(f, "SQL Injection"),
            Self::CrossSiteScripting => write!(f, "Cross-Site Scripting"),
            Self::LdapInjection => write!(f, "LDAP Injection"),
            Self::XmlInjection => write!(f, "XML Injection/XXE"),
            Self::NoSqlInjection => write!(f, "NoSQL Injection"),
            Self::SessionIdExposure => write!(f, "Session ID Exposure"),
            Self::ToolPoisoning => write!(f, "Tool Poisoning"),
            Self::TokenTheft => write!(f, "Token Theft Risk"),
            Self::DosPotential => write!(f, "Denial of Service Potential"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

impl fmt::Display for Threat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] at {}: {}",
            self.threat_type, self.severity, self.location, self.description
        )
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text { offset, length } => write!(f, "offset {}, length {}", offset, length),
            Self::Json { path } => write!(f, "JSON path '{}'", path),
            Self::Binary { offset } => write!(f, "binary offset {}", offset),
        }
    }
}

// Implement the trait for compatibility with the trait-based architecture
/// Create a security scanner wrapped in Arc for thread-safe usage
pub fn create_security_scanner(
    config: &crate::config::ScannerConfig,
) -> Arc<dyn crate::traits::SecurityScannerTrait> {
    let scanner = SecurityScanner::new(config.clone()).unwrap_or_else(|e| {
        tracing::error!("Failed to create security scanner: {}", e);
        // Return a basic scanner with default config on error
        SecurityScanner::new(Default::default()).expect("Default scanner creation should not fail")
    });
    Arc::new(scanner)
}

impl crate::traits::SecurityScannerTrait for SecurityScanner {
    fn scan_text(&self, text: &str) -> Vec<Threat> {
        self.scan_text(text).unwrap_or_default()
    }

    fn scan_json(&self, value: &serde_json::Value) -> Vec<Threat> {
        self.scan_json(value).unwrap_or_default()
    }

    fn scan_with_depth(&self, text: &str, _max_depth: usize) -> Vec<Threat> {
        // TODO: Implement depth-limited scanning
        self.scan_text(text).unwrap_or_default()
    }

    fn get_stats(&self) -> crate::traits::ScannerStats {
        crate::traits::ScannerStats {
            texts_scanned: 0,     // TODO: Track this
            threats_found: 0,     // TODO: Track this
            unicode_threats: 0,   // TODO: Track this
            injection_threats: 0, // TODO: Track this
            pattern_threats: 0,   // TODO: Track this
            avg_scan_time_us: 0,  // TODO: Track this
        }
    }

    fn reset_stats(&self) {
        // TODO: Implement stats reset when tracking is added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_type_display() {
        assert_eq!(
            ThreatType::UnicodeInvisible.to_string(),
            "Invisible Unicode Character"
        );
        assert_eq!(ThreatType::PromptInjection.to_string(), "Prompt Injection");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
