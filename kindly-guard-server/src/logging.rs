//! Enhanced logging with semantic fields for stealth operation
//! This module provides structured logging that hides implementation details

use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    Layer,
};
use std::io;

/// Initialize the logging system with stealth configuration
pub fn init_logging(detailed: bool) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            if detailed {
                EnvFilter::new("kindly_guard=debug,info")
            } else {
                EnvFilter::new("kindly_guard=info,warn")
            }
        });
    
    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_span_events(if detailed { FmtSpan::FULL } else { FmtSpan::NONE })
        .with_filter(StealthFilter);
    
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();
    
    Ok(())
}

/// Custom filter that sanitizes log messages
struct StealthFilter;

impl<S> Layer<S> for StealthFilter 
where 
    S: Subscriber,
{
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) -> bool {
        // Filter out any logs that might reveal implementation details
        let target = metadata.target();
        
        // Block logs from internal implementation
        if target.contains("atomic_event_buffer") || 
           target.contains("kindly_guard_core") ||
           target.contains("enhanced_impl") {
            return false;
        }
        
        true
    }
}

/// Log security events with semantic fields
#[macro_export]
macro_rules! log_security_event {
    ($level:expr, event_type:$event_type:expr, client:$client:expr, $($field:tt)*) => {
        match $level {
            Level::ERROR => tracing::error!(
                event_type = $event_type,
                client = $client,
                category = "security",
                $($field)*
            ),
            Level::WARN => tracing::warn!(
                event_type = $event_type,
                client = $client,
                category = "security",
                $($field)*
            ),
            Level::INFO => tracing::info!(
                event_type = $event_type,
                client = $client,
                category = "security",
                $($field)*
            ),
            Level::DEBUG => tracing::debug!(
                event_type = $event_type,
                client = $client,
                category = "security",
                $($field)*
            ),
            _ => tracing::trace!(
                event_type = $event_type,
                client = $client,
                category = "security",
                $($field)*
            ),
        }
    };
}

/// Log performance metrics without revealing internals
#[macro_export]
macro_rules! log_performance {
    ($operation:expr, $duration_ms:expr, $($field:tt)*) => {
        tracing::debug!(
            operation = $operation,
            duration_ms = $duration_ms,
            category = "performance",
            $($field)*
        );
    };
}

/// Semantic event types for consistent logging
pub mod event_types {
    pub const AUTH_SUCCESS: &str = "authentication.success";
    pub const AUTH_FAILURE: &str = "authentication.failure";
    pub const RATE_LIMIT_EXCEEDED: &str = "rate_limit.exceeded";
    pub const THREAT_DETECTED: &str = "threat.detected";
    pub const THREAT_BLOCKED: &str = "threat.blocked";
    pub const REQUEST_PROCESSED: &str = "request.processed";
    pub const CIRCUIT_BREAKER_OPEN: &str = "protection.activated";
    pub const CIRCUIT_BREAKER_CLOSE: &str = "protection.restored";
    pub const PATTERN_DETECTED: &str = "pattern.detected";
    pub const PERFORMANCE_OPTIMIZED: &str = "performance.optimized";
}

/// Semantic field names for structured logging
pub mod field_names {
    pub const CLIENT_ID: &str = "client.id";
    pub const METHOD: &str = "request.method";
    pub const THREAT_TYPE: &str = "threat.type";
    pub const THREAT_SEVERITY: &str = "threat.severity";
    pub const RESPONSE_TIME_MS: &str = "response.time_ms";
    pub const TOKENS_REMAINING: &str = "rate_limit.tokens_remaining";
    pub const PATTERN_CONFIDENCE: &str = "pattern.confidence";
    pub const OPTIMIZATION_LEVEL: &str = "performance.level";
}

/// Helper to log with semantic fields
pub struct SemanticLogger;

impl SemanticLogger {
    /// Log an authentication event
    pub fn auth_event(success: bool, client_id: &str, method: Option<&str>) {
        let event_type = if success { 
            event_types::AUTH_SUCCESS 
        } else { 
            event_types::AUTH_FAILURE 
        };
        
        if let Some(method) = method {
            tracing::info!(
                event_type = event_type,
                client.id = client_id,
                auth.method = method,
                category = "security"
            );
        } else {
            tracing::info!(
                event_type = event_type,
                client.id = client_id,
                category = "security"
            );
        }
    }
    
    /// Log a threat detection
    pub fn threat_detected(client_id: &str, threat_type: &str, severity: &str) {
        tracing::warn!(
            event_type = event_types::THREAT_DETECTED,
            client.id = client_id,
            threat.type = threat_type,
            threat.severity = severity,
            category = "security"
        );
    }
    
    /// Log rate limiting
    pub fn rate_limit_event(client_id: &str, allowed: bool, tokens: f64) {
        if allowed {
            tracing::debug!(
                event_type = "rate_limit.check",
                client.id = client_id,
                rate_limit.allowed = allowed,
                rate_limit.tokens_remaining = tokens,
                category = "security"
            );
        } else {
            tracing::warn!(
                event_type = event_types::RATE_LIMIT_EXCEEDED,
                client.id = client_id,
                rate_limit.allowed = allowed,
                rate_limit.tokens_remaining = tokens,
                category = "security"
            );
        }
    }
    
    /// Log performance metrics
    pub fn performance_metric(operation: &str, duration_ms: u64, enhanced: bool) {
        let level = if enhanced { "optimized" } else { "standard" };
        tracing::debug!(
            event_type = "performance.metric",
            operation = operation,
            duration_ms = duration_ms,
            performance.mode = level,
            category = "performance"
        );
    }
    
    /// Log circuit breaker events
    pub fn circuit_breaker_event(endpoint: &str, open: bool) {
        let event_type = if open {
            event_types::CIRCUIT_BREAKER_OPEN
        } else {
            event_types::CIRCUIT_BREAKER_CLOSE
        };
        
        tracing::info!(
            event_type = event_type,
            endpoint = endpoint,
            protection.active = open,
            category = "security"
        );
    }
}

/// Sanitize sensitive data from logs
pub fn sanitize_for_log(input: &str) -> String {
    // Remove any references to internal components
    let sanitized = input
        .replace("AtomicEventBuffer", "event processor")
        .replace("enhanced", "optimized")
        .replace("standard", "normal")
        .replace("kindly_guard_core", "core")
        .replace("breaker", "protection");
    
    // Truncate if too long
    if sanitized.len() > 200 {
        format!("{}...", &sanitized[..200])
    } else {
        sanitized
    }
}