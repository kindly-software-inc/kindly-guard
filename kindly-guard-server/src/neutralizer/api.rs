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
//! Public API documentation for the neutralization system
//!
//! This module provides comprehensive documentation for all public APIs
//! in the threat neutralization system.
//!
//! # Overview
//!
//! The neutralization system is designed to remediate security threats detected
//! by the scanner. It provides a layered architecture with optional features
//! like rate limiting, health monitoring, and distributed tracing.
//!
//! # Core Concepts
//!
//! - **Threat**: A security issue detected by the scanner
//! - **Neutralization**: The process of remediating a threat
//! - **Action**: The specific remediation applied (sanitize, parameterize, etc.)
//! - **Confidence**: How certain the system is about the neutralization
//!
//! # Basic Usage
//!
//! ```no_run
//! use kindly_guard_server::neutralizer::{
//!     create_neutralizer, NeutralizationConfig, ThreatNeutralizer,
//! };
//! use kindly_guard_server::scanner::{Threat, ThreatType, Severity, Location};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create with default config
//!     let config = NeutralizationConfig::default();
//!     let neutralizer = create_neutralizer(&config, None);
//!     
//!     // Define a threat
//!     let threat = Threat {
//!         threat_type: ThreatType::SqlInjection,
//!         severity: Severity::High,
//!         location: Location::Text { offset: 0, length: 10 },
//!         description: "SQL injection detected".to_string(),
//!         remediation: None,
//!     };
//!     
//!     // Neutralize the threat
//!     let result = neutralizer.neutralize(&threat, "SELECT * FROM users").await?;
//!     
//!     // Check the result
//!     if let Some(safe_content) = result.sanitized_content {
//!         println!("Safe content: {}", safe_content);
//!     }
//!     
//!     Ok(())
//! }
//! ```

use crate::scanner::{Threat, ThreatType};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// The main trait for threat neutralization.
///
/// This trait defines the interface that all neutralizers must implement.
/// It provides methods for neutralizing individual threats and batches of threats.
///
/// # Implementation Notes
///
/// - Implementations must be thread-safe (`Send + Sync`)
/// - Neutralization should be idempotent when possible
/// - Errors should be returned rather than panicking
///
/// # Example Implementation
///
/// ```ignore
/// struct MyNeutralizer {
///     config: NeutralizationConfig,
/// }
///
/// #[async_trait]
/// impl ThreatNeutralizer for MyNeutralizer {
///     async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
///         // Implementation here
///     }
///     
///     fn can_neutralize(&self, threat_type: &ThreatType) -> bool {
///         // Check if this neutralizer handles the threat type
///     }
///     
///     fn get_capabilities(&self) -> NeutralizerCapabilities {
///         // Return capabilities
///     }
/// }
/// ```
#[async_trait]
pub trait ThreatNeutralizerApi: Send + Sync {
    /// Neutralize a specific threat in content.
    ///
    /// This is the primary method for threat neutralization. It takes a threat
    /// detected by the scanner and the content containing the threat, then
    /// returns a result indicating what action was taken.
    ///
    /// # Arguments
    ///
    /// * `threat` - The threat to neutralize, as detected by the scanner
    /// * `content` - The original content containing the threat
    ///
    /// # Returns
    ///
    /// Returns a `NeutralizeResult` containing:
    /// - The action taken
    /// - Optionally, the sanitized content
    /// - Confidence score
    /// - Processing time
    /// - Optional correlation data
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The threat type is not supported
    /// - Neutralization fails due to invalid input
    /// - System resources are exhausted
    ///
    /// # Example
    ///
    /// ```ignore
    /// let threat = Threat {
    ///     threat_type: ThreatType::SqlInjection,
    ///     severity: Severity::High,
    ///     location: Location::Text { offset: 28, length: 15 },
    ///     description: "SQL injection in WHERE clause".to_string(),
    ///     remediation: Some("Use parameterized queries".to_string()),
    /// };
    ///
    /// let result = neutralizer.neutralize(
    ///     &threat,
    ///     "SELECT * FROM users WHERE id='1' OR '1'='1'"
    /// ).await?;
    ///
    /// assert_eq!(result.action_taken, NeutralizeAction::Parameterized);
    /// assert_eq!(
    ///     result.sanitized_content,
    ///     Some("SELECT * FROM users WHERE id=$1 OR $2=$3".to_string())
    /// );
    /// ```
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<super::NeutralizeResult>;

    /// Check if this neutralizer can handle a specific threat type.
    ///
    /// This method allows callers to determine whether a neutralizer supports
    /// a particular threat type before attempting neutralization.
    ///
    /// # Arguments
    ///
    /// * `threat_type` - The type of threat to check
    ///
    /// # Returns
    ///
    /// Returns `true` if this neutralizer can handle the threat type,
    /// `false` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if neutralizer.can_neutralize(&ThreatType::SqlInjection) {
    ///     // Proceed with neutralization
    /// } else {
    ///     // Use a different neutralizer or skip
    /// }
    /// ```
    fn can_neutralize(&self, threat_type: &ThreatType) -> bool;

    /// Get the capabilities of this neutralizer.
    ///
    /// Returns detailed information about what this neutralizer can do,
    /// including supported threat types, performance characteristics,
    /// and optional features.
    ///
    /// # Returns
    ///
    /// A `NeutralizerCapabilities` struct containing:
    /// - Whether real-time neutralization is supported
    /// - Batch mode support
    /// - Predictive capabilities
    /// - Correlation support
    /// - Rollback depth
    /// - List of supported threat types
    ///
    /// # Example
    ///
    /// ```ignore
    /// let caps = neutralizer.get_capabilities();
    ///
    /// if caps.batch_mode {
    ///     // Use batch neutralization for better performance
    /// }
    ///
    /// println!("Supported threats: {:?}", caps.supported_threats);
    /// ```
    fn get_capabilities(&self) -> super::NeutralizerCapabilities;

    /// Neutralize multiple threats in a single operation.
    ///
    /// This method provides efficient batch processing of multiple threats.
    /// Threats are processed in order, with each neutralization applied to
    /// the result of the previous one.
    ///
    /// # Arguments
    ///
    /// * `threats` - Slice of threats to neutralize, in order
    /// * `content` - The original content containing the threats
    ///
    /// # Returns
    ///
    /// Returns a `BatchNeutralizeResult` containing:
    /// - The final sanitized content after all neutralizations
    /// - Individual results for each threat
    ///
    /// # Default Implementation
    ///
    /// The default implementation processes threats sequentially.
    /// Implementations may override this for better performance.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let threats = vec![
    ///     sql_injection_threat,
    ///     unicode_threat,
    ///     path_traversal_threat,
    /// ];
    ///
    /// let result = neutralizer.batch_neutralize(&threats, original_content).await?;
    ///
    /// println!("Final safe content: {}", result.final_content);
    /// println!("Processed {} threats", result.individual_results.len());
    /// ```
    async fn batch_neutralize(
        &self,
        threats: &[Threat],
        content: &str,
    ) -> Result<super::BatchNeutralizeResult> {
        // Default implementation - can be overridden
        let mut results = Vec::new();
        let mut current_content = content.to_string();

        for threat in threats {
            let result = self.neutralize(threat, &current_content).await?;
            if let Some(ref sanitized) = result.sanitized_content {
                current_content = sanitized.clone();
            }
            results.push(result);
        }

        Ok(super::BatchNeutralizeResult {
            final_content: current_content,
            individual_results: results,
        })
    }
}

/// Factory function to create a neutralizer with default settings.
///
/// This is the primary way to create a neutralizer instance. It automatically
/// selects the appropriate implementation based on feature flags,
/// and wraps the neutralizer with production-ready features.
///
/// # Arguments
///
/// * `config` - Neutralization configuration
/// * `rate_limiter` - Optional rate limiter for throttling
///
/// # Returns
///
/// Returns an `Arc<dyn ThreatNeutralizer>` ready for use.
///
/// # Features Added
///
/// The returned neutralizer includes:
/// - Recovery and resilience (if configured)
/// - Rollback support (if `backup_originals` is true)
/// - Rate limiting (if provided)
/// - Health monitoring (always enabled)
///
/// # Example
///
/// ```ignore
/// use kindly_guard_server::neutralizer::{
///     create_neutralizer, NeutralizationConfig, NeutralizationMode,
/// };
///
/// let config = NeutralizationConfig {
///     mode: NeutralizationMode::Automatic,
///     backup_originals: true,
///     audit_all_actions: true,
///     ..Default::default()
/// };
///
/// let neutralizer = create_neutralizer(&config, None);
/// ```
pub fn create_neutralizer_api(
    config: &super::NeutralizationConfig,
    rate_limiter: Option<Arc<dyn crate::traits::RateLimiter>>,
) -> Arc<dyn super::ThreatNeutralizer> {
    super::create_neutralizer(config, rate_limiter)
}

/// Factory function to create a neutralizer with distributed tracing.
///
/// This extends `create_neutralizer` by adding distributed tracing capabilities
/// for observability in production environments.
///
/// # Arguments
///
/// * `config` - Neutralization configuration
/// * `rate_limiter` - Optional rate limiter for throttling
/// * `tracing_provider` - Optional distributed tracing provider
///
/// # Returns
///
/// Returns an `Arc<dyn ThreatNeutralizer>` with all features including tracing.
///
/// # Example
///
/// ```ignore
/// use kindly_guard_server::neutralizer::create_neutralizer_with_telemetry;
/// use kindly_guard_server::telemetry::{
///     DistributedTracingProvider, ProbabilitySampler, W3CTraceContextPropagator,
/// };
///
/// // Set up tracing
/// let tracing_provider = Arc::new(DistributedTracingProvider::new(
///     base_provider,
///     Arc::new(ProbabilitySampler::new(0.1)),
///     Arc::new(W3CTraceContextPropagator),
/// ));
///
/// // Create neutralizer with tracing
/// let neutralizer = create_neutralizer_with_telemetry(
///     &config,
///     rate_limiter,
///     Some(tracing_provider),
/// );
/// ```
pub fn create_neutralizer_with_telemetry_api(
    config: &super::NeutralizationConfig,
    rate_limiter: Option<Arc<dyn crate::traits::RateLimiter>>,
    tracing_provider: Option<Arc<crate::telemetry::DistributedTracingProvider>>,
) -> Arc<dyn super::ThreatNeutralizer> {
    super::create_neutralizer_with_telemetry(config, rate_limiter, tracing_provider)
}

// Re-export commonly used types for convenience
pub use super::{
    AttackPattern,
    BatchNeutralizeResult,
    BiDiReplacement,
    CommandAction,
    // Correlation types
    CorrelationData,
    HomographAction,
    // Injection configuration
    InjectionNeutralizationConfig,
    NeutralizationConfig,
    NeutralizationMode,
    NeutralizeAction,
    NeutralizeResult,
    NeutralizerCapabilities,
    PathAction,
    PromptAction,
    SqlAction,
    // Unicode configuration
    UnicodeNeutralizationConfig,
    ZeroWidthAction,
};

/// Module containing detailed examples of neutralizer usage.
pub mod examples {
    /// Basic neutralization example.
    ///
    /// ```ignore
    /// # use kindly_guard_server::neutralizer::*;
    /// # use kindly_guard_server::scanner::*;
    /// # async fn example() -> anyhow::Result<()> {
    /// // Create neutralizer
    /// let config = NeutralizationConfig::default();
    /// let neutralizer = create_neutralizer(&config, None);
    ///
    /// // Create a threat
    /// let threat = Threat {
    ///     threat_type: ThreatType::SqlInjection,
    ///     severity: Severity::High,
    ///     location: Location::Text { offset: 0, length: 20 },
    ///     description: "SQL injection".to_string(),
    ///     remediation: None,
    /// };
    ///
    /// // Neutralize
    /// let result = neutralizer.neutralize(&threat, "'; DROP TABLE users;").await?;
    /// assert_eq!(result.action_taken, NeutralizeAction::Parameterized);
    /// # Ok(())
    /// # }
    /// ```
    pub const fn basic_example() {}

    /// Batch neutralization example.
    ///
    /// ```ignore
    /// # use kindly_guard_server::neutralizer::*;
    /// # use kindly_guard_server::scanner::*;
    /// # async fn example() -> anyhow::Result<()> {
    /// let neutralizer = create_neutralizer(&Default::default(), None);
    ///
    /// let threats = vec![
    ///     // SQL injection
    ///     Threat {
    ///         threat_type: ThreatType::SqlInjection,
    ///         severity: Severity::High,
    ///         location: Location::Text { offset: 0, length: 10 },
    ///         description: "SQL injection".to_string(),
    ///         remediation: None,
    ///     },
    ///     // Unicode attack
    ///     Threat {
    ///         threat_type: ThreatType::UnicodeBiDi,
    ///         severity: Severity::Medium,
    ///         location: Location::Text { offset: 20, length: 5 },
    ///         description: "BiDi override".to_string(),
    ///         remediation: None,
    ///     },
    /// ];
    ///
    /// let content = "SELECT * FROM users; Hello\u{202E}World";
    /// let result = neutralizer.batch_neutralize(&threats, content).await?;
    ///
    /// println!("Safe content: {}", result.final_content);
    /// # Ok(())
    /// # }
    /// ```
    pub const fn batch_example() {}

    /// Custom configuration example.
    ///
    /// ```ignore
    /// # use kindly_guard_server::neutralizer::*;
    /// let config = NeutralizationConfig {
    ///     mode: NeutralizationMode::Automatic,
    ///     backup_originals: true,
    ///     audit_all_actions: true,
    ///     unicode: UnicodeNeutralizationConfig {
    ///         bidi_replacement: BiDiReplacement::Marker,
    ///         zero_width_action: ZeroWidthAction::Remove,
    ///         homograph_action: HomographAction::Ascii,
    ///     },
    ///     injection: InjectionNeutralizationConfig {
    ///         sql_action: SqlAction::Parameterize,
    ///         command_action: CommandAction::Escape,
    ///         path_action: PathAction::Normalize,
    ///         prompt_action: PromptAction::Wrap,
    ///     },
    ///     recovery: None,
    /// };
    ///
    /// let neutralizer = create_neutralizer(&config, None);
    /// ```
    pub const fn configuration_example() {}
}
