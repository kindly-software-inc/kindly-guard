//! Neutralization audit integration
//!
//! This module provides helpers for logging neutralization events
//! to the audit system for compliance and security monitoring.

use crate::{
    audit::{AuditEvent, AuditEventType, AuditLogger, AuditSeverity},
    neutralizer::{NeutralizeAction, NeutralizeResult},
    scanner::Threat,
};
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

/// Audit context for neutralization operations
pub struct NeutralizationAuditContext {
    client_id: String,
    audit_logger: Option<Arc<dyn AuditLogger>>,
}

impl NeutralizationAuditContext {
    /// Create a new neutralization audit context
    pub fn new(client_id: String, audit_logger: Option<Arc<dyn AuditLogger>>) -> Self {
        Self {
            client_id,
            audit_logger,
        }
    }

    /// Log neutralization start
    pub async fn log_start(&self, threat: &Threat) -> Result<()> {
        if let Some(logger) = &self.audit_logger {
            let event = AuditEvent::new(
                AuditEventType::NeutralizationStarted {
                    client_id: self.client_id.clone(),
                    threat_id: format!(
                        "threat-{:?}-{}",
                        threat.threat_type,
                        match &threat.location {
                            crate::scanner::Location::Text { offset, .. } => *offset,
                            crate::scanner::Location::Json { path } => path.len(),
                            crate::scanner::Location::Binary { offset } => *offset,
                        }
                    ),
                    threat_type: format!("{:?}", threat.threat_type),
                },
                AuditSeverity::Info,
            )
            .with_client_id(self.client_id.clone())
            .with_tags(vec!["neutralization".to_string(), "security".to_string()]);

            logger.log(event).await?;
        }
        Ok(())
    }

    /// Log neutralization completion
    pub async fn log_completion(
        &self,
        threat: &Threat,
        result: &NeutralizeResult,
        duration: std::time::Duration,
    ) -> Result<()> {
        if let Some(logger) = &self.audit_logger {
            let action_str = match result.action_taken {
                NeutralizeAction::Sanitized => "sanitized",
                NeutralizeAction::Parameterized => "parameterized",
                NeutralizeAction::Normalized => "normalized",
                NeutralizeAction::Escaped => "escaped",
                NeutralizeAction::Removed => "removed",
                NeutralizeAction::Quarantined => "quarantined",
                NeutralizeAction::NoAction => "no_action",
            };

            let event = AuditEvent::new(
                AuditEventType::NeutralizationCompleted {
                    client_id: self.client_id.clone(),
                    threat_id: format!(
                        "threat-{:?}-{}",
                        threat.threat_type,
                        match &threat.location {
                            crate::scanner::Location::Text { offset, .. } => *offset,
                            crate::scanner::Location::Json { path } => path.len(),
                            crate::scanner::Location::Binary { offset } => *offset,
                        }
                    ),
                    action: action_str.to_string(),
                    duration_ms: duration.as_millis() as u64,
                },
                AuditSeverity::Info,
            )
            .with_client_id(self.client_id.clone())
            .with_context(
                "sanitized_content".to_string(),
                serde_json::to_value(&result.sanitized_content)?,
            )
            .with_context(
                "confidence".to_string(),
                serde_json::to_value(result.confidence_score)?,
            )
            .with_tags(vec![
                "neutralization".to_string(),
                "security".to_string(),
                "success".to_string(),
            ]);

            logger.log(event).await?;
        }
        Ok(())
    }

    /// Log neutralization failure
    pub async fn log_failure(&self, threat: &Threat, error: &str) -> Result<()> {
        if let Some(logger) = &self.audit_logger {
            let event = AuditEvent::new(
                AuditEventType::NeutralizationFailed {
                    client_id: self.client_id.clone(),
                    threat_id: format!(
                        "threat-{:?}-{}",
                        threat.threat_type,
                        match &threat.location {
                            crate::scanner::Location::Text { offset, .. } => *offset,
                            crate::scanner::Location::Json { path } => path.len(),
                            crate::scanner::Location::Binary { offset } => *offset,
                        }
                    ),
                    error: error.to_string(),
                },
                AuditSeverity::Error,
            )
            .with_client_id(self.client_id.clone())
            .with_tags(vec![
                "neutralization".to_string(),
                "security".to_string(),
                "failure".to_string(),
            ]);

            logger.log(event).await?;
        }
        Ok(())
    }

    /// Log neutralization skip
    pub async fn log_skip(&self, threat: &Threat, reason: &str) -> Result<()> {
        if let Some(logger) = &self.audit_logger {
            let event = AuditEvent::new(
                AuditEventType::NeutralizationSkipped {
                    client_id: self.client_id.clone(),
                    threat_id: format!(
                        "threat-{:?}-{}",
                        threat.threat_type,
                        match &threat.location {
                            crate::scanner::Location::Text { offset, .. } => *offset,
                            crate::scanner::Location::Json { path } => path.len(),
                            crate::scanner::Location::Binary { offset } => *offset,
                        }
                    ),
                    reason: reason.to_string(),
                },
                AuditSeverity::Warning,
            )
            .with_client_id(self.client_id.clone())
            .with_tags(vec![
                "neutralization".to_string(),
                "security".to_string(),
                "skipped".to_string(),
            ]);

            logger.log(event).await?;
        }
        Ok(())
    }

    /// Log neutralization rollback
    pub async fn log_rollback(&self, threat: &Threat, reason: &str) -> Result<()> {
        if let Some(logger) = &self.audit_logger {
            let event = AuditEvent::new(
                AuditEventType::NeutralizationRolledBack {
                    client_id: self.client_id.clone(),
                    threat_id: format!(
                        "threat-{:?}-{}",
                        threat.threat_type,
                        match &threat.location {
                            crate::scanner::Location::Text { offset, .. } => *offset,
                            crate::scanner::Location::Json { path } => path.len(),
                            crate::scanner::Location::Binary { offset } => *offset,
                        }
                    ),
                    reason: reason.to_string(),
                },
                AuditSeverity::Critical,
            )
            .with_client_id(self.client_id.clone())
            .with_tags(vec![
                "neutralization".to_string(),
                "security".to_string(),
                "rollback".to_string(),
            ]);

            logger.log(event).await?;
        }
        Ok(())
    }
}

/// Audit-aware neutralization wrapper
pub struct AuditedNeutralizer<N> {
    neutralizer: N,
    audit_logger: Option<Arc<dyn AuditLogger>>,
}

impl<N> AuditedNeutralizer<N> {
    pub fn new(neutralizer: N, audit_logger: Option<Arc<dyn AuditLogger>>) -> Self {
        Self {
            neutralizer,
            audit_logger,
        }
    }

    /// Neutralize with audit logging
    pub async fn neutralize_with_audit(
        &self,
        threat: &Threat,
        content: &str,
        client_id: &str,
    ) -> Result<NeutralizeResult>
    where
        N: crate::neutralizer::ThreatNeutralizer,
    {
        let context =
            NeutralizationAuditContext::new(client_id.to_string(), self.audit_logger.clone());

        // Log start
        context.log_start(threat).await?;

        let start = Instant::now();

        // Perform neutralization
        match self.neutralizer.neutralize(threat, content).await {
            Ok(result) => {
                // Log completion
                context
                    .log_completion(threat, &result, start.elapsed())
                    .await?;
                Ok(result)
            }
            Err(e) => {
                // Log failure
                context.log_failure(threat, &e.to_string()).await?;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        audit::memory::InMemoryAuditLogger,
        audit::AuditConfig,
        scanner::{Severity as ThreatSeverity, ThreatType},
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_neutralization_audit_logging() {
        // Create in-memory audit logger
        let audit_config = AuditConfig::default();
        let audit_logger = Arc::new(InMemoryAuditLogger::new(audit_config).unwrap());

        // Create context
        let context =
            NeutralizationAuditContext::new("test-client".to_string(), Some(audit_logger.clone()));

        // Create test threat
        let threat = Threat {
            threat_type: ThreatType::SqlInjection,
            severity: ThreatSeverity::High,
            location: crate::scanner::Location::Text {
                offset: 0,
                length: 10,
            },
            description: "SQL injection detected".to_string(),
            remediation: Some("Use parameterized queries".to_string()),
        };

        // Test logging start
        context.log_start(&threat).await.unwrap();

        // Test logging completion
        let result = NeutralizeResult {
            sanitized_content: Some("safe content".to_string()),
            action_taken: NeutralizeAction::Parameterized,
            confidence_score: 0.99,
            processing_time_us: 50000,
            correlation_data: None,
            extracted_params: None,
        };

        context
            .log_completion(&threat, &result, std::time::Duration::from_millis(50))
            .await
            .unwrap();

        // Verify events were logged
        let stats = audit_logger.get_stats().await.unwrap();
        assert_eq!(stats.total_events, 2);
    }
}
