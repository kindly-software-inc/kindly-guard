//! Quarantine-aware neutralizer that automatically backs up threats

use std::sync::Arc;
use async_trait::async_trait;
use anyhow::Result;

use crate::quarantine::{Quarantine, ThreatInfo};
use crate::scanner::Threat;
use super::{BatchNeutralizeResult, NeutralizeAction, NeutralizeResult, ThreatNeutralizer};

/// A neutralizer that automatically quarantines content before neutralization
pub struct QuarantineAwareNeutralizer<N: ThreatNeutralizer> {
    inner: Arc<N>,
    quarantine: Arc<dyn Quarantine>,
    auto_quarantine: bool,
}

impl<N: ThreatNeutralizer> QuarantineAwareNeutralizer<N> {
    /// Create a new quarantine-aware neutralizer
    pub fn new(inner: Arc<N>, quarantine: Arc<dyn Quarantine>) -> Self {
        Self {
            inner,
            quarantine,
            auto_quarantine: true,
        }
    }
    
    /// Set whether to automatically quarantine threats
    pub fn set_auto_quarantine(&mut self, enabled: bool) {
        self.auto_quarantine = enabled;
    }
    
    /// Quarantine content associated with a threat
    async fn quarantine_threat(&self, threat: &Threat, content: &str) -> Result<String> {
        let threat_info = ThreatInfo {
            threat_type: threat.threat_type.to_string(),
            severity: threat.severity.to_string(),
            description: threat.description.clone(),
            location: Some(format!("{:?}", threat.location)),
            timestamp: std::time::SystemTime::now(),
        };
        
        self.quarantine.quarantine(
            content,
            threat_info,
            Some("auto-neutralization".to_string()),
        ).await
    }
}

#[async_trait]
impl<N: ThreatNeutralizer> ThreatNeutralizer for QuarantineAwareNeutralizer<N> {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        // First, quarantine the original content if enabled
        let quarantine_id = if self.auto_quarantine {
            match self.quarantine_threat(threat, content).await {
                Ok(id) => Some(id),
                Err(e) => {
                    tracing::warn!("Failed to quarantine threat: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        // Then neutralize using the inner neutralizer
        let mut result = self.inner.neutralize(threat, content).await?;
        
        // Add quarantine information to the result
        if let Some(id) = quarantine_id {
            // Store quarantine ID in extracted params
            let mut params = result.extracted_params.unwrap_or_default();
            params.push(format!("quarantine_id:{}", id));
            
            // If the action was to quarantine, mark it as auto-quarantined
            if result.action_taken == NeutralizeAction::Quarantined {
                params.push("auto_quarantined:true".to_string());
            }
            
            result.extracted_params = Some(params);
        }
        
        Ok(result)
    }
    
    async fn batch_neutralize(&self, threats: &[Threat], content: &str) -> Result<BatchNeutralizeResult> {
        // Quarantine the original content once for all threats
        let quarantine_id = if self.auto_quarantine && !threats.is_empty() {
            let combined_info = ThreatInfo {
                threat_type: "multiple".to_string(),
                severity: threats.iter()
                    .map(|t| &t.severity)
                    .max()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                description: format!("{} threats detected", threats.len()),
                location: None,
                timestamp: std::time::SystemTime::now(),
            };
            
            match self.quarantine.quarantine(
                content,
                combined_info,
                Some("batch-neutralization".to_string()),
            ).await {
                Ok(id) => Some(id),
                Err(e) => {
                    tracing::warn!("Failed to quarantine batch threats: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        // Neutralize all threats
        let mut batch_result = self.inner.batch_neutralize(threats, content).await?;
        
        // Add quarantine information to all results
        if let Some(id) = quarantine_id {
            for result in &mut batch_result.individual_results {
                // Add to extracted params
                let mut params = result.extracted_params.clone().unwrap_or_default();
                params.push(format!("batch_quarantine_id:{}", id));
                result.extracted_params = Some(params);
            }
        }
        
        Ok(batch_result)
    }
    
    fn can_neutralize(&self, threat_type: &crate::scanner::ThreatType) -> bool {
        self.inner.can_neutralize(threat_type)
    }
    
    fn get_capabilities(&self) -> super::NeutralizerCapabilities {
        self.inner.get_capabilities()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neutralizer::standard::StandardNeutralizer;
    use crate::quarantine::{QuarantineConfig, create_quarantine};
    use crate::scanner::{ThreatType, Severity, Location};
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_quarantine_aware_neutralizer() {
        let temp_dir = TempDir::new().unwrap();
        let quarantine_config = QuarantineConfig {
            base_path: temp_dir.path().to_path_buf(),
            encrypt: false,
            ..Default::default()
        };
        
        let quarantine = create_quarantine(&quarantine_config);
        let inner = Arc::new(StandardNeutralizer::new(Default::default()));
        let neutralizer = QuarantineAwareNeutralizer::new(inner, quarantine.clone());
        
        let threat = Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text { offset: 0, length: 10 },
            description: "SQL injection detected".to_string(),
            remediation: Some("Use parameterized queries".to_string()),
        };
        
        let content = "SELECT * FROM users WHERE id='1' OR '1'='1'";
        let result = neutralizer.neutralize(&threat, content).await.unwrap();
        
        // Verify neutralization happened
        assert!(result.sanitized_content.is_some());
        
        // Verify quarantine happened via extracted_params
        let params = result.extracted_params.as_ref().unwrap();
        let quarantine_param = params.iter()
            .find(|p| p.starts_with("quarantine_id:"))
            .expect("Should have quarantine_id in extracted params");
        let quarantine_id = quarantine_param.strip_prefix("quarantine_id:").unwrap();
        
        // Verify we can retrieve the quarantined content
        let entry = quarantine.retrieve(quarantine_id).await.unwrap().unwrap();
        assert_eq!(entry.original_content, content);
        assert_eq!(entry.threat_info.threat_type, "SQL Injection");
    }
    
    #[tokio::test]
    async fn test_batch_quarantine() {
        let temp_dir = TempDir::new().unwrap();
        let quarantine_config = QuarantineConfig {
            base_path: temp_dir.path().to_path_buf(),
            encrypt: false,
            ..Default::default()
        };
        
        let quarantine = create_quarantine(&quarantine_config);
        let inner = Arc::new(StandardNeutralizer::new(Default::default()));
        let neutralizer = QuarantineAwareNeutralizer::new(inner, quarantine.clone());
        
        let threats = vec![
            Threat {
                threat_type: ThreatType::SqlInjection,
                severity: Severity::High,
                location: Location::Text { offset: 0, length: 20 },
                description: "SQL injection".to_string(),
                remediation: Some("Use parameterized queries".to_string()),
            },
            Threat {
                threat_type: ThreatType::CrossSiteScripting,
                severity: Severity::Medium,
                location: Location::Text { offset: 30, length: 15 },
                description: "XSS attack".to_string(),
                remediation: Some("Escape HTML entities".to_string()),
            },
        ];
        
        let content = "SELECT * FROM users; <script>alert('XSS')</script>";
        let batch_result = neutralizer.batch_neutralize(&threats, content).await.unwrap();
        
        assert_eq!(batch_result.individual_results.len(), 2);
        
        // All results should have the same batch quarantine ID via extracted_params
        let params0 = batch_result.individual_results[0].extracted_params.as_ref().unwrap();
        let quarantine_param0 = params0.iter()
            .find(|p| p.starts_with("batch_quarantine_id:"))
            .expect("Should have batch_quarantine_id in extracted params");
        let quarantine_id = quarantine_param0.strip_prefix("batch_quarantine_id:").unwrap();
        
        let params1 = batch_result.individual_results[1].extracted_params.as_ref().unwrap();
        let quarantine_param1 = params1.iter()
            .find(|p| p.starts_with("batch_quarantine_id:"))
            .expect("Should have batch_quarantine_id in extracted params");
        assert_eq!(
            quarantine_param0.strip_prefix("batch_quarantine_id:").unwrap(),
            quarantine_param1.strip_prefix("batch_quarantine_id:").unwrap()
        );
        
        // Verify the quarantined content
        let entry = quarantine.retrieve(quarantine_id).await.unwrap().unwrap();
        assert_eq!(entry.original_content, content);
        assert_eq!(entry.threat_info.threat_type, "multiple");
        assert_eq!(entry.threat_info.description, "2 threats detected");
    }
}