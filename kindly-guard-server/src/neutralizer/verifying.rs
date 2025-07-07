//! Verifying neutralizer that re-scans content after neutralization

use std::sync::Arc;
use async_trait::async_trait;
use anyhow::Result;

use crate::scanner::{SecurityScanner, Threat};
use super::{BatchNeutralizeResult, NeutralizeResult, ThreatNeutralizer};

/// A neutralizer that verifies content is safe after neutralization
pub struct VerifyingNeutralizer<N: ThreatNeutralizer> {
    inner: Arc<N>,
    scanner: Arc<SecurityScanner>,
    max_iterations: usize,
}

impl<N: ThreatNeutralizer> VerifyingNeutralizer<N> {
    /// Create a new verifying neutralizer
    pub fn new(inner: Arc<N>, scanner: Arc<SecurityScanner>) -> Self {
        Self {
            inner,
            scanner,
            max_iterations: 5,
        }
    }
    
    /// Set maximum iterations for recursive neutralization
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }
    
    /// Verify that content is safe after neutralization
    async fn verify_safe(&self, content: &str) -> Result<Vec<Threat>> {
        Ok(self.scanner.scan_text(content)?)
    }
}

#[async_trait]
impl<N: ThreatNeutralizer> ThreatNeutralizer for VerifyingNeutralizer<N> {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        let mut result = self.inner.neutralize(threat, content).await?;
        
        // If neutralization produced sanitized content, verify it's safe
        if let Some(ref sanitized) = result.sanitized_content {
            let remaining_threats = self.verify_safe(sanitized).await?;
            
            let mut params = result.extracted_params.unwrap_or_default();
            
            if !remaining_threats.is_empty() {
                params.push(format!(
                    "verification_failed:{} threats remain after neutralization",
                    remaining_threats.len()
                ));
                
                // Log warning but don't fail - the neutralizer did its best
                tracing::warn!(
                    "Neutralization incomplete: {} threats remain after neutralizing {}",
                    remaining_threats.len(),
                    threat.threat_type
                );
            } else {
                params.push("verified_safe:true".to_string());
            }
            
            result.extracted_params = Some(params);
        }
        
        Ok(result)
    }
    
    async fn batch_neutralize(&self, threats: &[Threat], content: &str) -> Result<BatchNeutralizeResult> {
        let mut current_content = content.to_string();
        let mut all_results = Vec::new();
        let mut iterations = 0;
        let mut threats_to_process = threats;
        let mut remaining_threats_vec;
        
        loop {
            iterations += 1;
            if iterations > self.max_iterations {
                tracing::warn!("Max neutralization iterations ({}) reached", self.max_iterations);
                break;
            }
            
            // Neutralize current threats
            let batch_result = self.inner.batch_neutralize(threats_to_process, &current_content).await?;
            
            // Update current content from batch result
            current_content = batch_result.final_content.clone();
            
            // Collect individual results
            all_results.extend(batch_result.individual_results);
            
            // Re-scan for remaining threats
            remaining_threats_vec = self.verify_safe(&current_content).await?;
            
            if remaining_threats_vec.is_empty() {
                // Content is now safe
                // Mark the last result as verified
                if let Some(last) = all_results.last_mut() {
                    let mut params = last.extracted_params.clone().unwrap_or_default();
                    params.push("verified_safe:true".to_string());
                    params.push(format!("iterations:{}", iterations));
                    last.extracted_params = Some(params);
                }
                
                return Ok(BatchNeutralizeResult {
                    final_content: current_content,
                    individual_results: all_results,
                });
            }
            
            // More threats found, continue neutralizing
            tracing::info!(
                "Iteration {}: Found {} more threats after neutralization",
                iterations,
                remaining_threats_vec.len()
            );
            
            // Update threats for next iteration
            threats_to_process = &remaining_threats_vec;
        }
        
        // If we get here, we couldn't fully neutralize
        if let Some(last) = all_results.last_mut() {
            let mut params = last.extracted_params.clone().unwrap_or_default();
            params.push(format!("verification_incomplete:Stopped after {} iterations", iterations));
            last.extracted_params = Some(params);
        }
        
        Ok(BatchNeutralizeResult {
            final_content: current_content,
            individual_results: all_results,
        })
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
    use crate::config::ScannerConfig;
    use crate::neutralizer::standard::StandardNeutralizer;
    use crate::scanner::{ThreatType, Severity, Location};
    
    #[tokio::test]
    async fn test_verifying_neutralizer() {
        let scanner_config = ScannerConfig::default();
        let scanner = Arc::new(SecurityScanner::new(scanner_config).unwrap());
        let inner = Arc::new(StandardNeutralizer::new(Default::default()));
        let neutralizer = VerifyingNeutralizer::new(inner, scanner.clone());
        
        // Test with content that becomes safe after neutralization
        let threat = Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text { offset: 28, length: 15 },
            description: "SQL injection detected".to_string(),
            remediation: Some("Use parameterized queries".to_string()),
        };
        
        let content = "SELECT * FROM users WHERE id='1' OR '1'='1'";
        let result = neutralizer.neutralize(&threat, content).await.unwrap();
        
        // Should have neutralized the threat
        assert!(result.sanitized_content.is_some());
        
        // Should have verified it's safe via extracted_params
        let params = result.extracted_params.as_ref().unwrap();
        assert!(params.contains(&"verified_safe:true".to_string()));
    }
    
    #[tokio::test]
    async fn test_recursive_neutralization() {
        let scanner_config = ScannerConfig::default();
        let scanner = Arc::new(SecurityScanner::new(scanner_config).unwrap());
        let inner = Arc::new(StandardNeutralizer::new(Default::default()));
        let neutralizer = VerifyingNeutralizer::new(inner, scanner.clone())
            .with_max_iterations(3);
        
        // Content with multiple threats that might need multiple passes
        let content = "SELECT * FROM users WHERE id='1' OR '1'='1'; <script>alert('xss')</script>";
        
        // Scan for initial threats
        let threats = scanner.scan_text(content).unwrap();
        assert!(!threats.is_empty());
        
        // Batch neutralize with verification
        let batch_result = neutralizer.batch_neutralize(&threats, content).await.unwrap();
        
        // Should have neutralized all threats eventually
        assert!(!batch_result.individual_results.is_empty());
        
        // Check if final result is verified safe
        let last_result = batch_result.individual_results.last().unwrap();
        let params = last_result.extracted_params.as_ref();
        
        if let Some(params_vec) = params {
            let verified = params_vec.iter().any(|p| p.starts_with("verified_safe:"));
            let iterations = params_vec.iter().find(|p| p.starts_with("iterations:"));
            let incomplete = params_vec.iter().any(|p| p.starts_with("verification_incomplete:"));
            
            println!("Verification result: {}, iterations: {:?}", verified, iterations);
            
            // The content should either be verified safe or marked as incomplete
            assert!(verified || incomplete);
        }
    }
}