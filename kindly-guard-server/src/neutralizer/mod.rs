//! Threat neutralization system
//!
//! Provides actual threat remediation capabilities beyond just detection.
//! Both standard and enhanced implementations provide full protection,
//! with optimized implementations offering superior performance.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use crate::scanner::{Threat, ThreatType};

pub mod api;
#[cfg(feature = "enhanced")]
pub mod enhanced;
pub mod health;
pub mod metrics;
pub mod rate_limited;
pub mod recovery;
pub mod rollback;
pub mod security_aware;
pub mod standard;
pub mod traced;
pub mod validation;

#[cfg(test)]
mod security_tests;

/// Trait for threat neutralization
#[async_trait]
pub trait ThreatNeutralizer: Send + Sync {
    /// Neutralize a specific threat in content
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult>;

    /// Check if this neutralizer can handle a threat type
    fn can_neutralize(&self, threat_type: &ThreatType) -> bool;

    /// Get neutralizer capabilities
    fn get_capabilities(&self) -> NeutralizerCapabilities;

    /// Batch neutralize multiple threats
    async fn batch_neutralize(
        &self,
        threats: &[Threat],
        content: &str,
    ) -> Result<BatchNeutralizeResult> {
        let mut results = Vec::new();
        let mut current_content = content.to_string();

        for threat in threats {
            let result = self.neutralize(threat, &current_content).await?;
            if let Some(ref sanitized) = result.sanitized_content {
                current_content = sanitized.clone();
            }
            results.push(result);
        }

        Ok(BatchNeutralizeResult {
            final_content: current_content,
            individual_results: results,
        })
    }
}

/// Result of neutralization operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizeResult {
    /// Action taken to neutralize threat
    pub action_taken: NeutralizeAction,

    /// Sanitized content (if modified)
    pub sanitized_content: Option<String>,

    /// Confidence in neutralization (0.0 - 1.0)
    pub confidence_score: f64,

    /// Processing time in microseconds
    pub processing_time_us: u64,

    /// Correlation data (enhanced mode only)
    pub correlation_data: Option<CorrelationData>,

    /// Any parameters extracted (e.g., SQL params)
    pub extracted_params: Option<Vec<String>>,
}

/// Batch neutralization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchNeutralizeResult {
    /// Final sanitized content after all neutralizations
    pub final_content: String,

    /// Individual results for each threat
    pub individual_results: Vec<NeutralizeResult>,
}

/// Actions that can be taken to neutralize threats
///
/// Each action represents a specific remediation technique applied
/// to neutralize a detected security threat. The choice of action
/// depends on the threat type and configured neutralization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeutralizeAction {
    /// Content was sanitized by removing or modifying dangerous elements
    ///
    /// **When Used**: HTML/script content, user input with mixed safe/unsafe content
    /// **Technique**: Removes dangerous tags/attributes while preserving safe content
    /// **Example**: `<script>alert('XSS')</script>Hello` → `Hello`
    /// **Preserves**: Safe text and allowed HTML tags
    Sanitized,

    /// Query was converted to use parameterized/prepared statements
    ///
    /// **When Used**: SQL, LDAP, or other injection attempts in queries
    /// **Technique**: Separates query structure from user data
    /// **Example**: `SELECT * FROM users WHERE id = '1' OR '1'='1'` → `SELECT * FROM users WHERE id = ?` with param `[1' OR '1'='1]`
    /// **Preserves**: Query intent while preventing injection
    Parameterized,

    /// Path was normalized to prevent directory traversal
    ///
    /// **When Used**: File paths containing `../`, absolute paths, or other traversal attempts
    /// **Technique**: Resolves to canonical path within allowed directory
    /// **Example**: `/var/www/../../../etc/passwd` → `/etc/passwd` (blocked) or `/var/www/passwd` (allowed)
    /// **Preserves**: Valid file references within boundaries
    Normalized,

    /// Content was escaped to prevent interpretation as code
    ///
    /// **When Used**: When content must be preserved but made safe for output context
    /// **Technique**: Context-specific escaping (HTML, SQL, Shell, etc.)
    /// **Example**: `<script>` → `&lt;script&gt;` (HTML context)
    /// **Preserves**: Original content in escaped form
    Escaped,

    /// Threat was completely removed from content
    ///
    /// **When Used**: Malicious content with no legitimate use case
    /// **Technique**: Strips out entire threat leaving remaining content
    /// **Example**: `Hello[INVISIBLE_CHAR]World` → `HelloWorld`
    /// **Preserves**: Only safe surrounding content
    Removed,

    /// Content was quarantined for manual review
    ///
    /// **When Used**: High-risk content requiring human judgment
    /// **Technique**: Isolates content and blocks processing
    /// **Example**: Suspected malware upload → moved to quarantine directory
    /// **Preserves**: Original content in isolated storage
    Quarantined,

    /// No action was needed for this threat
    ///
    /// **When Used**: False positives, acceptable risks, or report-only mode
    /// **Technique**: Threat logged but content unchanged
    /// **Example**: Legitimate use of SQL keywords in documentation
    /// **Preserves**: Everything unchanged
    NoAction,
}

impl fmt::Display for NeutralizeAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sanitized => write!(f, "Sanitized"),
            Self::Parameterized => write!(f, "Parameterized"),
            Self::Normalized => write!(f, "Normalized"),
            Self::Escaped => write!(f, "Escaped"),
            Self::Removed => write!(f, "Removed"),
            Self::Quarantined => write!(f, "Quarantined"),
            Self::NoAction => write!(f, "No Action"),
        }
    }
}

/// Correlation data from enhanced analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationData {
    /// Related threat IDs
    pub related_threats: Vec<String>,

    /// Detected attack pattern
    pub attack_pattern: Option<AttackPattern>,

    /// Prediction confidence (0.0 - 1.0)
    pub prediction_score: f64,
}

/// Attack patterns detected through correlation
///
/// These patterns represent coordinated or sophisticated attack behaviors
/// identified by analyzing multiple threats in context. Detection of these
/// patterns indicates a more serious security event requiring escalated response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackPattern {
    /// Multiple unicode attacks in sequence indicating targeted deception
    ///
    /// **Detection**: Series of unicode-based attacks (homograph, BiDi, invisible chars)
    /// **Implication**: Sophisticated attacker attempting various unicode bypasses
    /// **Common Scenario**: Phishing campaigns, social engineering attempts
    /// **Recommended Response**: Block source, enhanced monitoring, alert security team
    CoordinatedUnicode,

    /// SQL injection attempts across multiple inputs indicating database compromise attempt
    ///
    /// **Detection**: Multiple SQL injection variants targeting different parameters
    /// **Implication**: Automated tool usage or skilled manual testing
    /// **Common Scenario**: Database enumeration, data exfiltration attempts
    /// **Recommended Response**: Enable WAF rules, review database access logs, consider IP blocking
    SqlInjectionCampaign,

    /// Command injection with privilege escalation attempts
    ///
    /// **Detection**: Command injections followed by privilege escalation patterns
    /// **Implication**: Attacker seeking system-level access
    /// **Common Scenario**: Webshell installation, backdoor creation
    /// **Recommended Response**: Immediate incident response, system isolation, forensic analysis
    CommandEscalation,

    /// Mixed attack types indicating advanced persistent threat
    ///
    /// **Detection**: Combination of different attack vectors (XSS + SQLi + Path Traversal)
    /// **Implication**: Sophisticated attacker using multiple techniques
    /// **Common Scenario**: APT groups, professional penetration testing
    /// **Recommended Response**: Full security audit, enhanced monitoring across all systems
    MultiVector,

    /// Reconnaissance pattern indicating pre-attack information gathering
    ///
    /// **Detection**: Low-severity probes, error triggering, boundary testing
    /// **Implication**: Attack preparation phase, vulnerability scanning
    /// **Common Scenario**: Automated scanning tools, manual reconnaissance
    /// **Recommended Response**: Increase monitoring sensitivity, prepare incident response
    Probing,
}

/// Neutralizer capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizerCapabilities {
    /// Can neutralize in real-time
    pub real_time: bool,

    /// Supports batch operations
    pub batch_mode: bool,

    /// Can predict future threats
    pub predictive: bool,

    /// Supports cross-threat correlation
    pub correlation: bool,

    /// Maximum rollback depth
    pub rollback_depth: usize,

    /// Supported threat types
    pub supported_threats: Vec<ThreatType>,
}

/// Neutralization mode configuration
///
/// Determines how the neutralizer responds to detected threats.
/// This allows flexible deployment from monitoring to active protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeutralizationMode {
    /// Only report threats without modifying content
    ///
    /// **Use Case**: Initial deployment, testing, compliance monitoring
    /// **Behavior**: Logs all threats but returns original content unchanged
    /// **Security Impact**: No protection, only visibility
    /// **Recommended For**: Pre-production testing, false positive analysis
    ReportOnly,

    /// Ask user for confirmation before neutralizing each threat
    ///
    /// **Use Case**: Semi-automated workflows, high-value content
    /// **Behavior**: Prompts for user decision on each threat
    /// **Security Impact**: Delayed protection, requires human availability
    /// **Recommended For**: Content management systems, editorial workflows
    Interactive,

    /// Automatically neutralize all detected threats
    ///
    /// **Use Case**: Production systems, real-time protection
    /// **Behavior**: Immediately applies configured neutralization actions
    /// **Security Impact**: Maximum protection, potential for false positives
    /// **Recommended For**: API gateways, web applications, automated systems
    Automatic,
}

impl Default for NeutralizationMode {
    fn default() -> Self {
        Self::ReportOnly
    }
}

/// Configuration for neutralization
///
/// # Security Implications
///
/// Neutralization transforms detected threats into safe content:
/// - **Mode selection** - Balance between security and data integrity
/// - **Backup strategy** - Enables recovery but requires secure storage
/// - **Audit requirements** - Essential for compliance and forensics
/// - **Recovery handling** - Prevents neutralization failures from causing outages
///
/// # Example: Secure Production Configuration
///
/// ```toml
/// [neutralization]
/// mode = "automatic"           # Auto-neutralize threats
/// backup_originals = true      # Keep originals for recovery
/// audit_all_actions = true     # Full audit trail
///
/// [neutralization.unicode]
/// bidi_replacement = "marker"  # Visible markers for BiDi
/// zero_width_action = "remove" # Remove invisible chars
/// homograph_action = "ascii"   # Convert to ASCII
///
/// [neutralization.injection]
/// sql_action = "parameterize"  # Convert to safe queries
/// command_action = "escape"    # Escape shell metacharacters
/// path_action = "normalize"    # Resolve to safe paths
/// prompt_action = "wrap"       # Add safety boundaries
///
/// [neutralization.recovery]
/// enabled = true
/// max_retries = 3
/// backoff_ms = 100
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizationConfig {
    /// Neutralization mode
    ///
    /// **Default**: ReportOnly (safe default)
    /// **Security Trade-offs**:
    /// - `ReportOnly`: Detects but doesn't modify (safe for testing)
    /// - `Interactive`: Requires user confirmation (good for sensitive data)
    /// - `Automatic`: Immediate protection (recommended for production)
    pub mode: NeutralizationMode,

    /// Backup original content
    ///
    /// **Default**: true (secure by default)
    /// **Security**: Enables recovery from false positives but requires
    /// secure storage. Backups should be encrypted and access-controlled.
    /// **Warning**: Disabling prevents recovery from mistakes
    pub backup_originals: bool,

    /// Audit all actions
    ///
    /// **Default**: true (secure by default)
    /// **Security**: Creates forensic trail for all neutralization actions.
    /// Essential for compliance, debugging, and incident response.
    /// **Storage**: Ensure audit logs are tamper-proof and retained properly
    pub audit_all_actions: bool,

    /// Unicode-specific settings
    ///
    /// **Security**: Controls how unicode-based threats are neutralized.
    /// Different strategies balance security vs. internationalization needs.
    pub unicode: UnicodeNeutralizationConfig,

    /// Injection-specific settings
    ///
    /// **Security**: Defines how various injection attacks are neutralized.
    /// Each injection type requires specific handling to maintain functionality.
    pub injection: InjectionNeutralizationConfig,

    /// Recovery configuration for handling failures
    ///
    /// **Default**: Enabled with sensible retry settings
    /// **Security**: Prevents neutralization failures from causing service outages.
    /// Implements circuit breakers and exponential backoff.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<recovery::RecoveryConfig>,
}

/// Unicode neutralization configuration
///
/// Controls how unicode-based security threats are handled.
/// These attacks exploit unicode features to deceive users or systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicodeNeutralizationConfig {
    /// How to handle `BiDi` characters
    ///
    /// **Default**: Marker (visible indication)
    /// **Security**: BiDi characters can reverse text direction to deceive users.
    /// - `Remove`: Most secure, may break legitimate RTL text
    /// - `Marker`: Balance of security and usability (recommended)
    /// - `Escape`: Preserves data but may confuse users
    pub bidi_replacement: BiDiReplacement,

    /// Action for zero-width characters
    ///
    /// **Default**: Remove (most secure)
    /// **Security**: Zero-width characters are invisible and used for:
    /// - Hidden tracking codes
    /// - Bypassing filters
    /// - Creating invisible URLs
    /// **Warning**: Some languages legitimately use zero-width joiners
    pub zero_width_action: ZeroWidthAction,

    /// Action for homographs
    ///
    /// **Default**: Ascii (convert lookalikes)
    /// **Security**: Homographs look like ASCII but aren't (е vs e).
    /// - `Ascii`: Converts to ASCII equivalent (most secure)
    /// - `Warn`: Alerts but preserves (for international apps)
    /// - `Block`: Rejects content entirely (strictest)
    pub homograph_action: HomographAction,
}

/// `BiDi` character replacement strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiDiReplacement {
    /// Remove completely
    Remove,

    /// Replace with visible marker
    Marker,

    /// Escape as unicode sequence
    Escape,
}

/// Zero-width character action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZeroWidthAction {
    /// Remove completely
    Remove,

    /// Escape as unicode sequence
    Escape,
}

/// Homograph character action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HomographAction {
    /// Convert to ASCII equivalent
    Ascii,

    /// Warn but keep
    Warn,

    /// Block completely
    Block,
}

/// Injection neutralization configuration
///
/// Controls how various injection attacks are neutralized.
/// Each injection type requires specific handling to maintain functionality
/// while ensuring security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionNeutralizationConfig {
    /// SQL injection action
    ///
    /// **Default**: Parameterize (most secure)
    /// **Security**: SQL injection can lead to data breaches and corruption.
    /// - `Block`: Rejects query entirely (safest but may break functionality)
    /// - `Escape`: Escapes dangerous characters (good but not foolproof)
    /// - `Parameterize`: Converts to prepared statements (recommended)
    pub sql_action: SqlAction,

    /// Command injection action
    ///
    /// **Default**: Escape (balanced approach)
    /// **Security**: Command injection enables arbitrary code execution.
    /// - `Block`: Rejects command entirely (safest)
    /// - `Escape`: Escapes shell metacharacters (recommended)
    /// - `Sandbox`: Runs in restricted environment (complex but safe)
    pub command_action: CommandAction,

    /// Path traversal action
    ///
    /// **Default**: Normalize (maintains functionality)
    /// **Security**: Path traversal accesses unauthorized files.
    /// - `Block`: Rejects paths with traversal patterns
    /// - `Normalize`: Resolves to canonical safe path (recommended)
    pub path_action: PathAction,

    /// Prompt injection action
    ///
    /// **Default**: Wrap (adds safety context)
    /// **Security**: Prompt injection manipulates AI behavior.
    /// - `Block`: Rejects suspicious prompts
    /// - `Escape`: Escapes control sequences
    /// - `Wrap`: Adds safety boundaries (recommended for LLMs)
    pub prompt_action: PromptAction,
}

/// SQL injection neutralization action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SqlAction {
    /// Block the query
    Block,

    /// Escape dangerous characters
    Escape,

    /// Convert to parameterized query
    Parameterize,
}

/// Command injection neutralization action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandAction {
    /// Block the command
    Block,

    /// Escape shell metacharacters
    Escape,

    /// Sandbox the command
    Sandbox,
}

/// Path traversal neutralization action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathAction {
    /// Block the path
    Block,

    /// Normalize to safe path
    Normalize,
}

/// Prompt injection neutralization action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromptAction {
    /// Block the prompt
    Block,

    /// Escape control sequences
    Escape,

    /// Wrap in safety context
    Wrap,
}

impl Default for NeutralizationConfig {
    fn default() -> Self {
        Self {
            mode: NeutralizationMode::default(),
            backup_originals: true,
            audit_all_actions: true,
            unicode: UnicodeNeutralizationConfig {
                bidi_replacement: BiDiReplacement::Marker,
                zero_width_action: ZeroWidthAction::Remove,
                homograph_action: HomographAction::Ascii,
            },
            injection: InjectionNeutralizationConfig {
                sql_action: SqlAction::Parameterize,
                command_action: CommandAction::Escape,
                path_action: PathAction::Normalize,
                prompt_action: PromptAction::Wrap,
            },
            recovery: Some(recovery::RecoveryConfig::default()),
        }
    }
}

/// Factory for creating neutralizers
pub fn create_neutralizer(
    config: &NeutralizationConfig,
    rate_limiter: Option<Arc<dyn crate::traits::RateLimiter>>,
) -> Arc<dyn ThreatNeutralizer> {
    create_neutralizer_with_telemetry(config, rate_limiter, None)
}

/// Factory for creating neutralizers with optional telemetry
pub fn create_neutralizer_with_telemetry(
    config: &NeutralizationConfig,
    rate_limiter: Option<Arc<dyn crate::traits::RateLimiter>>,
    tracing_provider: Option<Arc<crate::telemetry::DistributedTracingProvider>>,
) -> Arc<dyn ThreatNeutralizer> {
    // Create base neutralizer
    let mut neutralizer: Arc<dyn ThreatNeutralizer> = {
        #[cfg(feature = "enhanced")]
        {
            Arc::new(enhanced::EnhancedNeutralizer::new(config.clone()))
        }

        #[cfg(not(feature = "enhanced"))]
        {
            Arc::new(standard::StandardNeutralizer::new(config.clone()))
        }
    };

    // Optionally wrap with recovery
    if let Some(ref recovery_config) = config.recovery {
        if recovery_config.enabled {
            neutralizer = Arc::new(recovery::ResilientNeutralizer::new(
                neutralizer,
                recovery_config.clone(),
            ));
        }
    }

    // Optionally wrap with rollback support
    if config.backup_originals {
        neutralizer =
            rollback::RollbackNeutralizer::new(neutralizer, rollback::RollbackConfig::default());
    }

    // Optionally wrap with rate limiting
    if let Some(limiter) = rate_limiter {
        neutralizer = Arc::new(rate_limited::RateLimitedNeutralizer::new(
            neutralizer,
            limiter,
            rate_limited::NeutralizationRateLimitConfig::default(),
        ));
    }

    // Always wrap with health monitoring
    neutralizer = health::HealthMonitoredNeutralizer::new(
        neutralizer,
        health::NeutralizationHealthConfig::default(),
    );

    // Optionally wrap with distributed tracing
    if let Some(provider) = tracing_provider {
        use crate::neutralizer::traced::NeutralizerTracingExt;
        neutralizer = neutralizer.with_tracing(provider);
    }

    neutralizer
}

/// Neutralization error types
#[derive(Debug, thiserror::Error)]
pub enum NeutralizeError {
    #[error("Threat type not supported: {0:?}")]
    UnsupportedThreatType(ThreatType),

    #[error("Neutralization failed: {0}")]
    NeutralizationFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}
