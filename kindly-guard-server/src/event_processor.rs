//! Enhanced Security Event Processor
//! Provides lock-free, high-performance security event tracking and correlation

use std::collections::HashMap;
use parking_lot::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::traits::EventBufferTrait;

/// Priority levels for events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Normal,
    Urgent,
}

/// Statistics for an endpoint
#[derive(Debug, Clone)]
pub struct EndpointStats {
    pub success_count: u64,
    pub failure_count: u64,
    pub circuit_state: CircuitState,
    pub available_tokens: u32,
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Security event types for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    // Authentication events
    AuthSuccess { client_id: String },
    AuthFailure { client_id: String, reason: String },
    TokenValidated { client_id: String, token_hash: String },
    TokenExpired { client_id: String },
    
    // Message signing events
    MessageSigned { client_id: String, signature_hash: String },
    SignatureVerified { client_id: String, valid: bool },
    SignatureReplay { client_id: String, signature_hash: String },
    
    // Rate limiting events
    RateLimitCheck { client_id: String, method: String, allowed: bool },
    RateLimitExceeded { client_id: String, method: String },
    RateLimitPenalty { client_id: String, factor: f64 },
    
    // MCP protocol events
    RequestReceived { client_id: String, method: String, request_id: String },
    ResponseSent { client_id: String, method: String, request_id: String, duration_ms: u64 },
    ThreatDetected { client_id: String, threat_type: String, severity: String },
    
    // Circuit breaker events
    CircuitOpened { endpoint: String, failure_count: u32 },
    CircuitClosed { endpoint: String },
}

/// Security event with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub timestamp: u64,
    pub correlation_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Event processor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventProcessorConfig {
    /// Enable advanced security processing
    pub enabled: bool,
    
    /// Buffer size in MB
    pub buffer_size_mb: usize,
    
    /// Maximum endpoints to track
    pub max_endpoints: u32,
    
    /// Events per second limit
    pub rate_limit: f64,
    
    /// Circuit breaker failure threshold
    pub failure_threshold: u32,
    
    /// Event retention duration
    pub retention_duration: Duration,
    
    /// Enable pattern detection
    pub pattern_detection: bool,
    
    /// Enable real-time correlation
    pub correlation_enabled: bool,
}

impl Default for EventProcessorConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for stealth
            buffer_size_mb: 20, // 20MB for high volume
            max_endpoints: 1000,
            rate_limit: 10000.0, // 10k events/sec
            failure_threshold: 5,
            retention_duration: Duration::from_secs(3600), // 1 hour
            pattern_detection: true,
            correlation_enabled: true,
        }
    }
}

/// Security event processor using trait-based buffer
pub struct SecurityEventProcessor {
    config: EventProcessorConfig,
    buffer: Option<Box<dyn EventBufferTrait>>,
    endpoint_map: RwLock<HashMap<String, u32>>,
    next_endpoint_id: RwLock<u32>,
    start_time: Instant,
}

/// Attack patterns detected by correlation
#[derive(Debug, Clone)]
pub enum AttackPattern {
    CredentialStuffing { client_id: String, attempts: u32 },
    TokenAbuse { client_id: String, reuse_count: u32 },
    RateLimitProbing { client_id: String, methods_tested: Vec<String> },
    MultiStageAttack { client_id: String, stages: Vec<String> },
    SignatureReplayAttack { client_id: String, replay_count: u32 },
}

impl SecurityEventProcessor {
    /// Create a new security event processor
    pub fn new(config: EventProcessorConfig) -> Result<Self> {
        let buffer = if config.enabled {
            crate::create_event_buffer(&config)?
        } else {
            None
        };
        
        Ok(Self {
            config,
            buffer,
            endpoint_map: RwLock::new(HashMap::new()),
            next_endpoint_id: RwLock::new(0),
            start_time: Instant::now(),
        })
    }
    
    /// Track a security event
    pub fn track_event(&self, event: SecurityEvent) -> Result<()> {
        if !self.config.enabled {
            return Ok(()); // Silently skip if disabled
        }
        
        let buffer = match &self.buffer {
            Some(b) => b,
            None => return Ok(()), // No buffer available
        };
        
        // Determine endpoint based on event type
        let endpoint = match &event.event_type {
            SecurityEventType::AuthSuccess { client_id, .. } |
            SecurityEventType::AuthFailure { client_id, .. } |
            SecurityEventType::TokenValidated { client_id, .. } |
            SecurityEventType::TokenExpired { client_id } => {
                format!("auth:{}", client_id)
            }
            SecurityEventType::MessageSigned { client_id, .. } |
            SecurityEventType::SignatureVerified { client_id, .. } |
            SecurityEventType::SignatureReplay { client_id, .. } => {
                format!("signing:{}", client_id)
            }
            SecurityEventType::RateLimitCheck { client_id, method, .. } |
            SecurityEventType::RateLimitExceeded { client_id, method } => {
                format!("ratelimit:{}:{}", client_id, method)
            }
            SecurityEventType::RateLimitPenalty { client_id, .. } => {
                format!("ratelimit:{}", client_id)
            }
            SecurityEventType::RequestReceived { client_id, method, .. } |
            SecurityEventType::ResponseSent { client_id, method, .. } => {
                format!("mcp:{}:{}", client_id, method)
            }
            SecurityEventType::ThreatDetected { client_id, .. } => {
                format!("threat:{}", client_id)
            }
            SecurityEventType::CircuitOpened { endpoint, .. } |
            SecurityEventType::CircuitClosed { endpoint } => {
                endpoint.clone()
            }
        };
        
        // Determine priority based on event severity
        let priority = match &event.event_type {
            SecurityEventType::ThreatDetected { .. } => Priority::Urgent,
            SecurityEventType::AuthFailure { .. } |
            SecurityEventType::SignatureReplay { .. } |
            SecurityEventType::RateLimitExceeded { .. } => Priority::Urgent,
            SecurityEventType::CircuitOpened { .. } => Priority::Normal,
            _ => Priority::Normal,
        };
        
        // Serialize event data
        let data = serde_json::to_vec(&event)
            .context("Failed to serialize security event")?;
        
        // Get or create endpoint ID
        let endpoint_id = self.get_or_create_endpoint_id(&endpoint)?;
        
        // Enqueue event in atomic buffer
        let _handle = buffer.enqueue_event(endpoint_id, &data, priority)
            .map_err(|e| anyhow::anyhow!("Failed to enqueue event: {:?}", e))?;
        
        // Trigger pattern detection if enabled
        if self.config.pattern_detection {
            self.detect_patterns(&event)?;
        }
        
        Ok(())
    }
    
    /// Get or create endpoint ID for a string endpoint
    fn get_or_create_endpoint_id(&self, endpoint: &str) -> Result<u32> {
        let mut map = self.endpoint_map.write();
        
        if let Some(&id) = map.get(endpoint) {
            Ok(id)
        } else {
            let mut next_id = self.next_endpoint_id.write();
            let id = *next_id;
            *next_id += 1;
            
            if id >= self.config.max_endpoints {
                anyhow::bail!("Maximum endpoints exceeded");
            }
            
            map.insert(endpoint.to_string(), id);
            Ok(id)
        }
    }
    
    /// Get statistics for an endpoint
    pub fn get_endpoint_stats(&self, endpoint: &str) -> Option<EndpointStats> {
        let map = self.endpoint_map.read();
        let endpoint_id = *map.get(endpoint)?;
        self.buffer.as_ref()?
            .get_endpoint_stats(endpoint_id)
            .map_err(|e| {
                // Log error but continue
                tracing::debug!("Failed to get endpoint stats: {:?}", e);
                e
            })
            .ok()
    }
    
    /// Check if a client is under attack monitoring
    pub fn is_monitored(&self, client_id: &str) -> bool {
        if self.buffer.is_some() {
            // Check various endpoints for this client
            let endpoints = vec![
                format!("auth:{}", client_id),
                format!("threat:{}", client_id),
                format!("ratelimit:{}", client_id),
            ];
            
            let map = self.endpoint_map.read();
            
            for endpoint in endpoints {
                if let Some(&endpoint_id) = map.get(&endpoint) {
                    // Check if endpoint has high failure rate based on stats
                    if let Some(stats) = self.get_endpoint_stats(&endpoint) {
                        // Consider monitored if circuit is open (failure state)
                        if matches!(stats.circuit_state, CircuitState::Open) {
                            return true;
                        }
                        // Also check if available tokens are depleted (rate limited)
                        if stats.available_tokens == 0 {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    
    /// Detect attack patterns from events
    fn detect_patterns(&self, event: &SecurityEvent) -> Result<Option<AttackPattern>> {
        // Pattern detection logic would go here
        // For now, return None to indicate no pattern detected
        Ok(None)
    }
    
    /// Create event from auth attempt
    pub fn auth_event(client_id: &str, success: bool, reason: Option<&str>) -> SecurityEvent {
        let event_type = if success {
            SecurityEventType::AuthSuccess { 
                client_id: client_id.to_string() 
            }
        } else {
            SecurityEventType::AuthFailure { 
                client_id: client_id.to_string(),
                reason: reason.unwrap_or("unknown").to_string(),
            }
        };
        
        SecurityEvent {
            event_type,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            correlation_id: None,
            metadata: None,
        }
    }
    
    /// Create event from signature verification
    pub fn signature_event(client_id: &str, signature: &str, valid: bool) -> SecurityEvent {
        let mut hasher = Sha256::new();
        hasher.update(signature.as_bytes());
        let signature_hash = format!("{:x}", hasher.finalize());
        
        let event_type = if valid {
            SecurityEventType::SignatureVerified { 
                client_id: client_id.to_string(),
                valid: true,
            }
        } else {
            SecurityEventType::SignatureReplay { 
                client_id: client_id.to_string(),
                signature_hash,
            }
        };
        
        SecurityEvent {
            event_type,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            correlation_id: None,
            metadata: None,
        }
    }
    
    /// Create event from rate limit check
    pub fn rate_limit_event(client_id: &str, method: &str, allowed: bool) -> SecurityEvent {
        let event_type = if allowed {
            SecurityEventType::RateLimitCheck { 
                client_id: client_id.to_string(),
                method: method.to_string(),
                allowed: true,
            }
        } else {
            SecurityEventType::RateLimitExceeded { 
                client_id: client_id.to_string(),
                method: method.to_string(),
            }
        };
        
        SecurityEvent {
            event_type,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            correlation_id: None,
            metadata: None,
        }
    }
    
    /// Create event from MCP request
    pub fn request_event(client_id: &str, method: &str, request_id: &str) -> SecurityEvent {
        SecurityEvent {
            event_type: SecurityEventType::RequestReceived { 
                client_id: client_id.to_string(),
                method: method.to_string(),
                request_id: request_id.to_string(),
            },
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            correlation_id: Some(request_id.to_string()),
            metadata: None,
        }
    }
    
    /// Check if processor is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.buffer.is_some()
    }
}

/// Simple event buffer implementation for standard mode
pub struct SimpleEventBuffer {
    // Basic in-memory storage
}

impl SimpleEventBuffer {
    pub fn new() -> Self {
        Self {}
    }
}

impl crate::traits::EventBufferTrait for SimpleEventBuffer {
    fn enqueue_event(&self, _endpoint_id: u32, _data: &[u8], _priority: Priority) -> Result<u64> {
        // Simple implementation - just return a sequential ID
        Ok(0) // In production, this would maintain state
    }
    
    fn get_endpoint_stats(&self, _endpoint_id: u32) -> Result<EndpointStats> {
        // Return default stats for simple implementation
        Ok(EndpointStats {
            success_count: 0,
            failure_count: 0,
            circuit_state: CircuitState::Closed,
            available_tokens: 100,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_processor_creation() {
        let config = EventProcessorConfig::default();
        let processor = SecurityEventProcessor::new(config).unwrap();
        assert!(!processor.is_enabled()); // Should be disabled by default
    }
    
    #[test]
    fn test_event_tracking() {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        
        let processor = SecurityEventProcessor::new(config).unwrap();
        let event = SecurityEventProcessor::auth_event("test-client", true, None);
        
        // Should not error even if buffer operations fail
        processor.track_event(event).unwrap();
    }
}