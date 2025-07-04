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
//! Security context-aware neutralization
//!
//! Integrates neutralization with the security context to provide
//! comprehensive threat tracking and security decisions.

use crate::{
    neutralizer::{NeutralizeResult, ThreatNeutralizer},
    scanner::Threat,
    security::{CommandSource, SecurityContext},
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// Security-aware neutralizer that tracks operations in security context
pub struct SecurityAwareNeutralizer {
    inner: Arc<dyn ThreatNeutralizer>,
    security_context: Arc<tokio::sync::RwLock<SecurityContext>>,
}

impl SecurityAwareNeutralizer {
    pub fn new(
        neutralizer: Arc<dyn ThreatNeutralizer>,
        security_context: Arc<tokio::sync::RwLock<SecurityContext>>,
    ) -> Self {
        Self {
            inner: neutralizer,
            security_context,
        }
    }

    /// Create with a new security context
    pub fn with_new_context(
        neutralizer: Arc<dyn ThreatNeutralizer>,
        source: CommandSource,
        enhanced_mode: bool,
        neutralization_mode: crate::security::NeutralizationMode,
    ) -> Self {
        let context = SecurityContext::new(source)
            .with_enhanced_mode(enhanced_mode)
            .with_neutralization_mode(neutralization_mode);

        Self {
            inner: neutralizer,
            security_context: Arc::new(tokio::sync::RwLock::new(context)),
        }
    }

    /// Get the security context
    pub async fn get_context(&self) -> SecurityContext {
        (*self.security_context.read().await).clone()
    }

    /// Update security context user
    pub async fn set_user(&self, user_id: String) {
        let mut context = self.security_context.write().await;
        context.user_id = Some(user_id);
    }
}

#[async_trait]
impl ThreatNeutralizer for SecurityAwareNeutralizer {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        // Check if neutralization should be attempted
        let should_neutralize = {
            let context = self.security_context.read().await;
            context.should_neutralize()
        };

        if !should_neutralize {
            // Return no-action result if neutralization is disabled
            return Ok(NeutralizeResult {
                action_taken: crate::neutralizer::NeutralizeAction::NoAction,
                sanitized_content: None,
                confidence_score: 1.0,
                processing_time_us: 0,
                correlation_data: None,
                extracted_params: None,
            });
        }

        // Log the neutralization attempt
        tracing::info!(
            "Attempting neutralization for threat {:?} in security context {}",
            threat.threat_type,
            self.security_context.read().await.request_id
        );

        // Perform neutralization
        let result = self.inner.neutralize(threat, content).await;

        // Update security context based on result
        let mut context = self.security_context.write().await;
        match &result {
            Ok(_) => {
                context.record_neutralization(true);
                tracing::info!(
                    "Neutralization successful for request {}. Total neutralized: {}",
                    context.request_id,
                    context.neutralization.threats_neutralized
                );
            }
            Err(e) => {
                context.record_neutralization(false);
                tracing::error!(
                    "Neutralization failed for request {}: {}. Total failures: {}",
                    context.request_id,
                    e,
                    context.neutralization.neutralization_failures
                );
            }
        }

        result
    }

    fn can_neutralize(&self, threat_type: &crate::scanner::ThreatType) -> bool {
        self.inner.can_neutralize(threat_type)
    }

    fn get_capabilities(&self) -> crate::neutralizer::NeutralizerCapabilities {
        self.inner.get_capabilities()
    }
}

/// Security context manager for neutralization operations
pub struct NeutralizationSecurityManager {
    contexts: Arc<
        tokio::sync::RwLock<
            std::collections::HashMap<String, Arc<tokio::sync::RwLock<SecurityContext>>>,
        >,
    >,
}

impl Default for NeutralizationSecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NeutralizationSecurityManager {
    pub fn new() -> Self {
        Self {
            contexts: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Create a new security context for a session
    pub async fn create_context(
        &self,
        session_id: &str,
        source: CommandSource,
    ) -> Arc<tokio::sync::RwLock<SecurityContext>> {
        let context = Arc::new(tokio::sync::RwLock::new(SecurityContext::new(source)));

        let mut contexts = self.contexts.write().await;
        contexts.insert(session_id.to_string(), context.clone());

        context
    }

    /// Get context for a session
    pub async fn get_context(
        &self,
        session_id: &str,
    ) -> Option<Arc<tokio::sync::RwLock<SecurityContext>>> {
        let contexts = self.contexts.read().await;
        contexts.get(session_id).cloned()
    }

    /// Remove context when session ends
    pub async fn remove_context(&self, session_id: &str) {
        let mut contexts = self.contexts.write().await;
        contexts.remove(session_id);
    }

    /// Get summary of all active contexts
    pub async fn get_summary(&self) -> NeutralizationSecuritySummary {
        let contexts = self.contexts.read().await;

        let mut total_neutralized = 0u32;
        let mut total_failures = 0u32;
        let mut active_sessions = 0usize;

        for (_, context) in contexts.iter() {
            let ctx = context.read().await;
            total_neutralized += ctx.neutralization.threats_neutralized;
            total_failures += ctx.neutralization.neutralization_failures;
            active_sessions += 1;
        }

        NeutralizationSecuritySummary {
            active_sessions,
            total_neutralized,
            total_failures,
            overall_success_rate: if total_neutralized + total_failures > 0 {
                f64::from(total_neutralized) / f64::from(total_neutralized + total_failures)
            } else {
                1.0
            },
        }
    }
}

/// Summary of neutralization security status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NeutralizationSecuritySummary {
    pub active_sessions: usize,
    pub total_neutralized: u32,
    pub total_failures: u32,
    pub overall_success_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neutralizer::standard::StandardNeutralizer;
    use crate::neutralizer::NeutralizationConfig;

    #[tokio::test]
    async fn test_security_aware_neutralizer() {
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));

        let security_neutralizer = SecurityAwareNeutralizer::with_new_context(
            neutralizer,
            CommandSource::Api,
            false,
            crate::security::NeutralizationMode::Automatic,
        );

        // Should allow neutralization in automatic mode
        let threat = crate::scanner::Threat {
            threat_type: crate::scanner::ThreatType::SqlInjection,
            severity: crate::scanner::Severity::High,
            location: crate::scanner::Location::Text {
                offset: 0,
                length: 10,
            },
            description: "SQL injection detected".to_string(),
            remediation: None,
        };

        let result = security_neutralizer
            .neutralize(&threat, "test content")
            .await;
        assert!(result.is_ok());

        // Check context was updated
        let context = security_neutralizer.get_context().await;
        assert_eq!(context.neutralization.threats_neutralized, 1);
    }
}
