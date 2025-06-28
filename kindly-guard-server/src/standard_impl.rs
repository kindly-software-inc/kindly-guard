//! Standard implementations of security component traits
//! These work without any enhanced/patented technology

use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use anyhow::Result;
use parking_lot::RwLock;
use crate::traits::*;
use crate::scanner::Threat;

/// Standard event processor implementation
pub struct StandardEventProcessor {
    events_processed: AtomicU64,
    start_time: Instant,
    recent_events: RwLock<Vec<SecurityEvent>>,
    monitored_endpoints: RwLock<HashMap<String, Instant>>,
}

impl StandardEventProcessor {
    pub fn new() -> Self {
        Self {
            events_processed: AtomicU64::new(0),
            start_time: Instant::now(),
            recent_events: RwLock::new(Vec::with_capacity(1000)),
            monitored_endpoints: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SecurityEventProcessor for StandardEventProcessor {
    async fn process_event(&self, event: SecurityEvent) -> Result<EventHandle> {
        let event_id = self.events_processed.fetch_add(1, Ordering::SeqCst);
        
        // Store event in memory (limited buffer)
        {
            let mut events = self.recent_events.write();
            events.push(event.clone());
            if events.len() > 1000 {
                events.remove(0);
            }
        }
        
        // Simple monitoring based on event type
        if event.event_type.contains("failure") || event.event_type.contains("threat") {
            let mut monitored = self.monitored_endpoints.write();
            monitored.insert(event.client_id, Instant::now());
        }
        
        Ok(EventHandle {
            event_id,
            processed: true,
        })
    }
    
    fn get_stats(&self) -> ProcessorStats {
        let events_processed = self.events_processed.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        
        ProcessorStats {
            events_processed,
            events_per_second: events_processed as f64 / elapsed.max(1.0),
            buffer_utilization: self.recent_events.read().len() as f64 / 1000.0,
            correlation_hits: 0,
        }
    }
    
    fn is_monitored(&self, endpoint: &str) -> bool {
        let monitored = self.monitored_endpoints.read();
        monitored.get(endpoint)
            .map(|&time| time.elapsed() < Duration::from_secs(300))
            .unwrap_or(false)
    }
    
    async fn get_insights(&self, client_id: &str) -> Result<SecurityInsights> {
        let events = self.recent_events.read();
        let client_events: Vec<_> = events.iter()
            .filter(|e| e.client_id == client_id)
            .collect();
        
        let threat_count = client_events.iter()
            .filter(|e| e.event_type.contains("threat"))
            .count();
        
        let risk_score = (threat_count as f32 / 10.0).min(1.0);
        
        Ok(SecurityInsights {
            risk_score,
            detected_patterns: vec![],
            recommendations: if risk_score > 0.5 {
                vec!["Consider additional authentication".to_string()]
            } else {
                vec![]
            },
        })
    }
    
    async fn cleanup(&self) -> Result<()> {
        // Clean up old monitored endpoints
        let mut monitored = self.monitored_endpoints.write();
        monitored.retain(|_, &mut time| time.elapsed() < Duration::from_secs(3600));
        Ok(())
    }
}

/// Standard scanner implementation
pub struct StandardScanner {
    scans_performed: AtomicU64,
    threats_detected: AtomicU64,
}

impl StandardScanner {
    pub fn new() -> Self {
        Self {
            scans_performed: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
        }
    }
}

impl EnhancedScanner for StandardScanner {
    fn enhanced_scan(&self, data: &[u8]) -> Result<Vec<Threat>> {
        self.scans_performed.fetch_add(1, Ordering::Relaxed);
        
        // Basic pattern matching
        let data_str = String::from_utf8_lossy(data);
        let mut threats = Vec::new();
        
        // Check for obvious injection patterns
        if data_str.contains("'; DROP TABLE") || data_str.contains("1=1") {
            threats.push(Threat {
                threat_type: crate::scanner::ThreatType::SqlInjection,
                severity: crate::scanner::Severity::High,
                location: crate::scanner::Location::Text { offset: 0, length: data.len() },
                description: "SQL injection pattern detected".to_string(),
                remediation: Some("Sanitize input".to_string()),
            });
        }
        
        if !threats.is_empty() {
            self.threats_detected.fetch_add(threats.len() as u64, Ordering::Relaxed);
        }
        
        Ok(threats)
    }
    
    fn get_metrics(&self) -> ScannerMetrics {
        ScannerMetrics {
            scans_performed: self.scans_performed.load(Ordering::Relaxed),
            threats_detected: self.threats_detected.load(Ordering::Relaxed),
            avg_scan_time_us: 100, // Placeholder
            pattern_cache_hits: 0,
        }
    }
    
    fn preload_patterns(&self, _patterns: &[String]) -> Result<()> {
        // No-op for standard implementation
        Ok(())
    }
}

/// Standard correlation engine
pub struct StandardCorrelationEngine {
    patterns_detected: AtomicU64,
    rules: RwLock<CorrelationRules>,
}

impl StandardCorrelationEngine {
    pub fn new() -> Self {
        Self {
            patterns_detected: AtomicU64::new(0),
            rules: RwLock::new(CorrelationRules {
                time_window: Duration::from_secs(300),
                min_events: 5,
                patterns: vec![],
            }),
        }
    }
}

#[async_trait]
impl CorrelationEngine for StandardCorrelationEngine {
    async fn correlate(&self, events: &[SecurityEvent]) -> Result<Vec<ThreatPattern>> {
        let rules = self.rules.read();
        let mut patterns = Vec::new();
        
        // Simple correlation: look for repeated failures
        let mut failure_counts: HashMap<String, usize> = HashMap::new();
        
        for event in events {
            if event.event_type.contains("failure") {
                *failure_counts.entry(event.client_id.clone()).or_insert(0) += 1;
            }
        }
        
        for (client_id, count) in failure_counts {
            if count >= rules.min_events {
                self.patterns_detected.fetch_add(1, Ordering::Relaxed);
                patterns.push(ThreatPattern {
                    pattern_type: "repeated_failures".to_string(),
                    confidence: 0.8,
                    events: vec![],
                    description: format!("{} failures from {}", count, client_id),
                });
            }
        }
        
        Ok(patterns)
    }
    
    async fn update_rules(&self, rules: CorrelationRules) -> Result<()> {
        *self.rules.write() = rules;
        Ok(())
    }
    
    fn get_correlation_stats(&self) -> CorrelationStats {
        CorrelationStats {
            patterns_detected: self.patterns_detected.load(Ordering::Relaxed),
            false_positives: 0,
            avg_correlation_time_ms: 10,
        }
    }
}

/// Standard rate limiter using token bucket
pub struct StandardRateLimiter {
    buckets: RwLock<HashMap<RateLimitKey, TokenBucket>>,
    requests_allowed: AtomicU64,
    requests_denied: AtomicU64,
    default_rpm: u32,
    burst_capacity: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rpm: u32,
}

impl StandardRateLimiter {
    pub fn new(default_rpm: u32, burst_capacity: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            requests_allowed: AtomicU64::new(0),
            requests_denied: AtomicU64::new(0),
            default_rpm,
            burst_capacity,
        }
    }
}

#[async_trait]
impl RateLimiter for StandardRateLimiter {
    async fn check_rate_limit(&self, key: &RateLimitKey) -> Result<RateLimitDecision> {
        let mut buckets = self.buckets.write();
        let bucket = buckets.entry(key.clone()).or_insert_with(|| TokenBucket {
            tokens: self.burst_capacity as f64,
            last_refill: Instant::now(),
            rpm: self.default_rpm,
        });
        
        // Refill tokens
        let elapsed = bucket.last_refill.elapsed();
        let tokens_to_add = elapsed.as_secs_f64() * (bucket.rpm as f64 / 60.0);
        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.burst_capacity as f64);
        bucket.last_refill = Instant::now();
        
        // Check if request allowed
        let allowed = bucket.tokens >= 1.0;
        if allowed {
            bucket.tokens -= 1.0;
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_denied.fetch_add(1, Ordering::Relaxed);
        }
        
        Ok(RateLimitDecision {
            allowed,
            tokens_remaining: bucket.tokens,
            reset_after: Duration::from_secs(60),
        })
    }
    
    async fn record_request(&self, _key: &RateLimitKey) -> Result<()> {
        // Already recorded in check_rate_limit
        Ok(())
    }
    
    async fn apply_penalty(&self, client_id: &str, factor: f32) -> Result<()> {
        let mut buckets = self.buckets.write();
        for (key, bucket) in buckets.iter_mut() {
            if key.client_id == client_id {
                bucket.tokens = (bucket.tokens / factor as f64).max(0.0);
            }
        }
        Ok(())
    }
    
    fn get_stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            requests_allowed: self.requests_allowed.load(Ordering::Relaxed),
            requests_denied: self.requests_denied.load(Ordering::Relaxed),
            active_buckets: self.buckets.read().len(),
        }
    }
}

/// Standard component factory
pub struct StandardComponentFactory;

impl SecurityComponentFactory for StandardComponentFactory {
    fn create_event_processor(&self, _config: &crate::config::Config) -> Result<Arc<dyn SecurityEventProcessor>> {
        Ok(Arc::new(StandardEventProcessor::new()))
    }
    
    fn create_scanner(&self, _config: &crate::config::Config) -> Result<Arc<dyn EnhancedScanner>> {
        Ok(Arc::new(StandardScanner::new()))
    }
    
    fn create_correlation_engine(&self, _config: &crate::config::Config) -> Result<Arc<dyn CorrelationEngine>> {
        Ok(Arc::new(StandardCorrelationEngine::new()))
    }
    
    fn create_rate_limiter(&self, config: &crate::config::Config) -> Result<Arc<dyn RateLimiter>> {
        Ok(Arc::new(StandardRateLimiter::new(
            config.rate_limit.default_rpm,
            config.rate_limit.burst_capacity,
        )))
    }
}