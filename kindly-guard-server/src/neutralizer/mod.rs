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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeutralizeAction {
    /// Content was sanitized
    Sanitized,

    /// Query was parameterized
    Parameterized,

    /// Path was normalized
    Normalized,

    /// Content was escaped
    Escaped,

    /// Threat was removed
    Removed,

    /// Content was quarantined
    Quarantined,

    /// No action needed
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackPattern {
    /// Multiple unicode attacks in sequence
    CoordinatedUnicode,

    /// SQL injection attempts across multiple inputs
    SqlInjectionCampaign,

    /// Command injection with escalation
    CommandEscalation,

    /// Mixed attack types
    MultiVector,

    /// Reconnaissance pattern
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NeutralizationMode {
    /// Only report threats, don't modify
    ReportOnly,

    /// Ask user for each threat
    Interactive,

    /// Automatically neutralize
    Automatic,
}

impl Default for NeutralizationMode {
    fn default() -> Self {
        Self::ReportOnly
    }
}

/// Configuration for neutralization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizationConfig {
    /// Neutralization mode
    pub mode: NeutralizationMode,

    /// Backup original content
    pub backup_originals: bool,

    /// Audit all actions
    pub audit_all_actions: bool,

    /// Unicode-specific settings
    pub unicode: UnicodeNeutralizationConfig,

    /// Injection-specific settings
    pub injection: InjectionNeutralizationConfig,

    /// Recovery configuration for handling failures
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<recovery::RecoveryConfig>,
}

/// Unicode neutralization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicodeNeutralizationConfig {
    /// How to handle `BiDi` characters
    pub bidi_replacement: BiDiReplacement,

    /// Action for zero-width characters
    pub zero_width_action: ZeroWidthAction,

    /// Action for homographs
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionNeutralizationConfig {
    /// SQL injection action
    pub sql_action: SqlAction,

    /// Command injection action
    pub command_action: CommandAction,

    /// Path traversal action
    pub path_action: PathAction,

    /// Prompt injection action
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
