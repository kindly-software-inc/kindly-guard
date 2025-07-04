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
//! Standard implementations of security component traits
//! These provide baseline functionality without enhanced optimizations

use crate::scanner::Threat;
use crate::storage::StorageProvider;
use crate::traits::{
    CorrelationEngine, CorrelationRules, CorrelationStats, EnhancedScanner, EventHandle,
    ProcessorStats, RateLimitDecision, RateLimitKey, RateLimiter, RateLimiterStats, ScannerMetrics,
    SecurityComponentFactory, SecurityEvent, SecurityEventProcessor, SecurityInsights,
    SecurityScannerTrait, ThreatPattern,
};
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Standard event processor implementation
pub struct StandardEventProcessor {
    events_processed: AtomicU64,
    start_time: Instant,
    storage: Arc<dyn StorageProvider>,
    monitored_endpoints: RwLock<HashMap<String, Instant>>,
}

impl StandardEventProcessor {
    pub fn new(storage: Arc<dyn StorageProvider>) -> Self {
        Self {
            events_processed: AtomicU64::new(0),
            start_time: Instant::now(),
            storage,
            monitored_endpoints: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SecurityEventProcessor for StandardEventProcessor {
    async fn process_event(&self, event: SecurityEvent) -> Result<EventHandle> {
        let event_id = self.events_processed.fetch_add(1, Ordering::SeqCst);

        // Store event persistently
        self.storage.store_event(&event).await?;

        // Simple monitoring based on event type
        if event.event_type.contains("failure") || event.event_type.contains("threat") {
            let mut monitored = self.monitored_endpoints.write();
            monitored.insert(event.client_id.clone(), Instant::now());
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
            buffer_utilization: 0.0, // Storage doesn't expose buffer utilization yet
            correlation_hits: 0,
        }
    }

    fn is_monitored(&self, endpoint: &str) -> bool {
        let monitored = self.monitored_endpoints.read();
        monitored
            .get(endpoint)
            .is_some_and(|&time| time.elapsed() < Duration::from_secs(300))
    }

    async fn get_insights(&self, client_id: &str) -> Result<SecurityInsights> {
        use crate::storage::EventFilter;
        use chrono::{Duration, Utc};

        // Query recent events for this client
        let filter = EventFilter {
            client_id: Some(client_id.to_string()),
            from_time: Some(Utc::now() - Duration::hours(1)),
            limit: Some(100),
            ..Default::default()
        };

        let events = self.storage.query_events(filter).await?;

        let threat_count = events
            .iter()
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

impl Default for StandardScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardScanner {
    pub const fn new() -> Self {
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
        if data_str.contains("'; DROP TABLE")
            || data_str.contains("1=1")
            || data_str.contains("'1'='1'")
            || data_str.contains("' OR '")
        {
            threats.push(Threat {
                threat_type: crate::scanner::ThreatType::SqlInjection,
                severity: crate::scanner::Severity::High,
                location: crate::scanner::Location::Text {
                    offset: 0,
                    length: data.len(),
                },
                description: "SQL injection pattern detected".to_string(),
                remediation: Some("Sanitize input".to_string()),
            });
        }

        if !threats.is_empty() {
            self.threats_detected
                .fetch_add(threats.len() as u64, Ordering::Relaxed);
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

impl Default for StandardCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardCorrelationEngine {
    pub const fn new() -> Self {
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
                    description: format!("{count} failures from {client_id}"),
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
    storage: Arc<dyn StorageProvider>,
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
    pub fn new(storage: Arc<dyn StorageProvider>, default_rpm: u32, burst_capacity: u32) -> Self {
        Self {
            storage,
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
            tokens: f64::from(self.burst_capacity),
            last_refill: Instant::now(),
            rpm: self.default_rpm,
        });

        // Refill tokens
        let elapsed = bucket.last_refill.elapsed();
        let tokens_to_add = elapsed.as_secs_f64() * (f64::from(bucket.rpm) / 60.0);
        bucket.tokens = (bucket.tokens + tokens_to_add).min(f64::from(self.burst_capacity));
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
                bucket.tokens = (bucket.tokens / f64::from(factor)).max(0.0);
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
    fn create_event_processor(
        &self,
        _config: &crate::config::Config,
        storage: Arc<dyn crate::storage::StorageProvider>,
    ) -> Result<Arc<dyn SecurityEventProcessor>> {
        Ok(Arc::new(StandardEventProcessor::new(storage)))
    }

    fn create_scanner(&self, _config: &crate::config::Config) -> Result<Arc<dyn EnhancedScanner>> {
        Ok(Arc::new(StandardScanner::new()))
    }

    fn create_correlation_engine(
        &self,
        _config: &crate::config::Config,
        _storage: Arc<dyn crate::storage::StorageProvider>,
    ) -> Result<Arc<dyn CorrelationEngine>> {
        Ok(Arc::new(StandardCorrelationEngine::new()))
    }

    fn create_rate_limiter(
        &self,
        config: &crate::config::Config,
        storage: Arc<dyn crate::storage::StorageProvider>,
    ) -> Result<Arc<dyn RateLimiter>> {
        Ok(Arc::new(StandardRateLimiter::new(
            storage,
            config.rate_limit.default_rpm,
            config.rate_limit.burst_capacity,
        )))
    }

    fn create_security_scanner(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn SecurityScannerTrait>> {
        // For now, return a simple wrapper around the existing scanner
        // TODO: Properly refactor SecurityScanner to implement trait
        Err(anyhow::anyhow!(
            "SecurityScanner trait implementation pending"
        ))
    }
}
