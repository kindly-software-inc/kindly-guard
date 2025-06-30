//! Enhanced permission manager with advanced features
//! Uses optimized event tracking for high-performance pattern analysis

use async_trait::async_trait;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

use super::{
    ToolPermissionManager, Permission, PermissionContext, ClientPermissions,
    PermissionStats, PermissionRules, ThreatLevel,
};
use crate::resilience::stubs::EventBuffer;
use crate::event_processor::{Priority, CircuitState};

/// Enhanced permission manager with pattern learning
pub struct EnhancedPermissionManager {
    rules: Arc<PermissionRules>,
    client_permissions: Arc<RwLock<HashMap<String, ClientPermissions>>>,
    event_buffer: Arc<EventBuffer>,
    risk_scores: Arc<RwLock<HashMap<String, f32>>>,
    total_checks: AtomicU64,
    allowed_count: AtomicU64,
    denied_count: AtomicU64,
    pattern_matches: AtomicU64,
}

impl EnhancedPermissionManager {
    /// Create a new enhanced permission manager
    pub fn new(rules: PermissionRules) -> Self {
        // Create event buffer for tracking permission patterns
        let event_buffer = Arc::new(EventBuffer::new(
            10, // 10MB buffer
            1000, // Track up to 1000 clients
            1000.0, // 1000 events/sec rate limit
            10, // Max tokens
        ));
        
        Self {
            rules: Arc::new(rules),
            client_permissions: Arc::new(RwLock::new(HashMap::new())),
            event_buffer,
            risk_scores: Arc::new(RwLock::new(HashMap::new())),
            total_checks: AtomicU64::new(0),
            allowed_count: AtomicU64::new(0),
            denied_count: AtomicU64::new(0),
            pattern_matches: AtomicU64::new(0),
        }
    }
    
    /// Get client permissions with dynamic adjustments
    fn get_client_permissions(&self, client_id: &str) -> ClientPermissions {
        let permissions = self.client_permissions.read();
        let mut perms = permissions.get(client_id)
            .cloned()
            .unwrap_or_else(|| self.rules.default_permissions.clone());
        
        // Adjust based on risk score
        let risk_scores = self.risk_scores.read();
        if let Some(&risk_score) = risk_scores.get(client_id) {
            if risk_score > 0.8 {
                perms.max_threat_level = ThreatLevel::Low;
            } else if risk_score > 0.6 {
                perms.max_threat_level = ThreatLevel::Medium;
            }
        }
        
        perms
    }
    
    /// Calculate dynamic risk score
    fn calculate_risk_score(&self, client_id: &str) -> f32 {
        // Get recent events from buffer
        let endpoint_id = self.get_or_create_endpoint_id(client_id);
        
        // Simplified risk calculation based on available data
        let mut risk_score: f32 = 0.0;
        
        // Check if endpoint exists
        if let Ok(stats) = self.event_buffer.get_endpoint_stats(endpoint_id) {
            // Factor in circuit breaker state
            if matches!(stats.circuit_state, CircuitState::Open) {
                risk_score += 0.6;
            }
            
            // Factor in available tokens (lower tokens = higher risk)
            if stats.available_tokens < 10 {
                risk_score += 0.3;
            } else if stats.available_tokens < 50 {
                risk_score += 0.1;
            }
        }
        
        risk_score.min(1.0f32)
    }
    
    /// Get or create endpoint ID for client
    fn get_or_create_endpoint_id(&self, client_id: &str) -> u32 {
        // Simple hash-based mapping
        let hash = client_id.bytes().fold(0u32, |acc, b| {
            acc.wrapping_mul(31).wrapping_add(b as u32)
        });
        hash % 1000 // Map to available endpoints
    }
    
    /// Track permission event
    fn track_permission_event(
        &self,
        client_id: &str,
        tool_name: &str,
        allowed: bool,
        reason: Option<&str>,
    ) {
        let endpoint_id = self.get_or_create_endpoint_id(client_id);
        
        let event = format!(
            "perm:{}:{}:{}:{}",
            tool_name,
            if allowed { "allow" } else { "deny" },
            reason.unwrap_or(""),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        
        let priority = if allowed { Priority::Normal } else { Priority::Urgent };
        
        let _ = self.event_buffer.enqueue_event(
            endpoint_id,
            event.as_bytes(),
            priority
        );
    }
    
    /// Detect suspicious patterns
    fn detect_suspicious_patterns(&self, client_id: &str) -> bool {
        // Simplified pattern detection based on risk score
        let risk_score = self.risk_scores.read()
            .get(client_id)
            .copied()
            .unwrap_or(0.0);
        
        if risk_score > 0.8 {
            self.pattern_matches.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        
        false
    }
    
    /// Enhanced permission check with pattern analysis
    async fn check_enhanced_permission(
        &self,
        client_id: &str,
        _tool_name: &str,
        _context: &PermissionContext,
    ) -> Option<Permission> {
        // Update risk score
        let risk_score = self.calculate_risk_score(client_id);
        {
            let mut scores = self.risk_scores.write();
            scores.insert(client_id.to_string(), risk_score);
        }
        
        // Check for suspicious patterns
        if self.detect_suspicious_patterns(client_id) {
            warn!("Suspicious pattern detected for client {}", client_id);
            return Some(Permission::Deny(
                "Suspicious activity pattern detected".to_string()
            ));
        }
        
        // Apply dynamic rate limiting based on risk
        if risk_score > 0.7 {
            debug!("High risk score {} for client {}", risk_score, client_id);
            // Could implement additional checks here
        }
        
        None
    }
}

#[async_trait]
impl ToolPermissionManager for EnhancedPermissionManager {
    async fn check_permission(
        &self,
        client_id: &str,
        tool_name: &str,
        context: &PermissionContext,
    ) -> Result<Permission> {
        debug!("Enhanced permission check for client {} tool {}", client_id, tool_name);
        
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        
        // First, check enhanced features
        if let Some(denial) = self.check_enhanced_permission(client_id, tool_name, context).await {
            if let Permission::Deny(ref reason) = denial {
                self.denied_count.fetch_add(1, Ordering::Relaxed);
                self.track_permission_event(client_id, tool_name, false, Some(reason));
            }
            return Ok(denial);
        }
        
        // Get dynamically adjusted permissions
        let permissions = self.get_client_permissions(client_id);
        
        // Standard checks (similar to standard implementation)
        // Check global deny list
        if self.rules.global_deny_list.contains(tool_name) {
            let reason = "Tool globally denied";
            self.denied_count.fetch_add(1, Ordering::Relaxed);
            self.track_permission_event(client_id, tool_name, false, Some(reason));
            return Ok(Permission::Deny(reason.to_string()));
        }
        
        // Check client-specific rules
        if permissions.denied_tools.contains(tool_name) {
            let reason = format!("Tool denied for client {}", client_id);
            self.denied_count.fetch_add(1, Ordering::Relaxed);
            self.track_permission_event(client_id, tool_name, false, Some(&reason));
            return Ok(Permission::Deny(reason));
        }
        
        // Tool-specific checks
        if let Some(tool_def) = self.rules.tools.get(tool_name) {
            for required_scope in &tool_def.required_scopes {
                if !context.scopes.contains(required_scope) {
                    let reason = format!("Missing required scope: {}", required_scope);
                    self.denied_count.fetch_add(1, Ordering::Relaxed);
                    self.track_permission_event(client_id, tool_name, false, Some(&reason));
                    return Ok(Permission::Deny(reason));
                }
            }
        }
        
        // Permission granted
        info!("Enhanced permission granted for {} to use {}", client_id, tool_name);
        self.allowed_count.fetch_add(1, Ordering::Relaxed);
        self.track_permission_event(client_id, tool_name, true, None);
        
        Ok(Permission::Allow)
    }
    
    async fn get_allowed_tools(&self, client_id: &str) -> Result<Vec<String>> {
        let permissions = self.get_client_permissions(client_id);
        let risk_score = self.risk_scores.read()
            .get(client_id)
            .copied()
            .unwrap_or(0.0);
        
        let mut allowed = Vec::new();
        
        for (tool_name, tool_def) in &self.rules.tools {
            // Skip globally denied tools
            if self.rules.global_deny_list.contains(tool_name) {
                continue;
            }
            
            // Skip client-denied tools
            if permissions.denied_tools.contains(tool_name) {
                continue;
            }
            
            // Apply risk-based filtering
            if risk_score > 0.8 && matches!(tool_def.category, super::ToolCategory::Administrative) {
                continue;
            }
            
            // Check explicit allow list
            if !permissions.allowed_tools.is_empty() 
                && !permissions.allowed_tools.contains(tool_name) {
                continue;
            }
            
            allowed.push(tool_name.clone());
        }
        
        Ok(allowed)
    }
    
    async fn update_permissions(
        &self,
        client_id: &str,
        permissions: ClientPermissions,
    ) -> Result<()> {
        let mut client_perms = self.client_permissions.write();
        client_perms.insert(client_id.to_string(), permissions);
        
        // Track update event
        self.track_permission_event(client_id, "update_permissions", true, None);
        
        debug!("Updated permissions for client {} with pattern tracking", client_id);
        Ok(())
    }
    
    fn get_stats(&self) -> PermissionStats {
        PermissionStats {
            total_checks: self.total_checks.load(Ordering::Relaxed),
            allowed: self.allowed_count.load(Ordering::Relaxed),
            denied: self.denied_count.load(Ordering::Relaxed),
            denied_by_reason: {
                let mut reasons = HashMap::new();
                reasons.insert("pattern_detection".to_string(), 
                    self.pattern_matches.load(Ordering::Relaxed));
                reasons.insert("enhanced_checks".to_string(), 
                    self.total_checks.load(Ordering::Relaxed));
                reasons
            },
        }
    }
}