//! Distributed tracing support for `KindlyGuard`
//!
//! Provides context propagation, span relationships, and distributed tracing
//! capabilities for tracking operations across system boundaries.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use super::{MetricValue, TelemetryContext, TelemetryMetric, TelemetryProvider};

/// Distributed tracing span with full context
#[derive(Debug, Clone)]
pub struct DistributedSpan {
    /// Unique span ID
    pub span_id: String,

    /// Trace ID for correlation
    pub trace_id: String,

    /// Parent span ID (if any)
    pub parent_span_id: Option<String>,

    /// Operation name
    pub operation_name: String,

    /// Start time
    pub start_time: Instant,

    /// End time (when completed)
    pub end_time: Option<Instant>,

    /// Span kind
    pub kind: SpanKind,

    /// Status
    pub status: SpanStatus,

    /// Attributes
    pub attributes: HashMap<String, String>,

    /// Events within the span
    pub events: Vec<SpanEvent>,

    /// Links to other spans
    pub links: Vec<SpanLink>,
}

/// Span kinds following OpenTelemetry spec
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanKind {
    /// Default span kind
    Internal,

    /// Span represents handling of a request
    Server,

    /// Span represents making a request
    Client,

    /// Span represents a producer of messages
    Producer,

    /// Span represents a consumer of messages
    Consumer,
}

/// Span status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanStatus {
    pub code: StatusCode,
    pub description: Option<String>,
}

/// Status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatusCode {
    /// Operation completed successfully
    Ok,

    /// Operation encountered an error
    Error,

    /// Status not set
    Unset,
}

/// Event within a span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    pub name: String,
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    pub timestamp_utc: chrono::DateTime<chrono::Utc>,
    pub attributes: HashMap<String, String>,
}

/// Link to another span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLink {
    pub trace_id: String,
    pub span_id: String,
    pub attributes: HashMap<String, String>,
}

/// Distributed tracing provider
pub struct DistributedTracingProvider {
    /// Base telemetry provider
    base_provider: Arc<dyn TelemetryProvider>,

    /// Active spans
    active_spans: Arc<RwLock<HashMap<String, DistributedSpan>>>,

    /// Completed spans buffer
    completed_spans: Arc<RwLock<Vec<DistributedSpan>>>,

    /// Sampling strategy
    sampler: Arc<dyn TracingSampler>,

    /// Context propagator
    propagator: Arc<dyn ContextPropagator>,
}

/// Sampling decision
#[derive(Debug, Clone)]
pub struct SamplingDecision {
    pub sampled: bool,
    pub attributes: Option<SamplingAttributes>,
}

/// Sampling attributes to add to span
#[derive(Debug, Clone)]
pub struct SamplingAttributes {
    pub sampling_priority: f64,
    pub sampling_rate: f64,
}

/// Trait for sampling strategies
pub trait TracingSampler: Send + Sync {
    /// Decide whether to sample a span
    fn should_sample(
        &self,
        trace_id: &str,
        parent_context: Option<&TelemetryContext>,
        span_name: &str,
        span_kind: SpanKind,
        attributes: &[(String, String)],
    ) -> SamplingDecision;
}

/// Trait for context propagation
#[async_trait]
pub trait ContextPropagator: Send + Sync {
    /// Extract context from carrier (e.g., HTTP headers)
    async fn extract(&self, carrier: &dyn ContextCarrier) -> Result<Option<TelemetryContext>>;

    /// Inject context into carrier
    async fn inject(
        &self,
        context: &TelemetryContext,
        carrier: &mut dyn ContextCarrier,
    ) -> Result<()>;
}

/// Carrier for context propagation
pub trait ContextCarrier: Send + Sync {
    /// Get value by key
    fn get(&self, key: &str) -> Option<&str>;

    /// Set value by key
    fn set(&mut self, key: &str, value: String);

    /// Get all keys
    fn keys(&self) -> Vec<&str>;
}

impl DistributedTracingProvider {
    /// Create a new distributed tracing provider
    pub fn new(
        base_provider: Arc<dyn TelemetryProvider>,
        sampler: Arc<dyn TracingSampler>,
        propagator: Arc<dyn ContextPropagator>,
    ) -> Self {
        Self {
            base_provider,
            active_spans: Arc::new(RwLock::new(HashMap::new())),
            completed_spans: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            sampler,
            propagator,
        }
    }

    /// Start a new distributed span
    pub async fn start_distributed_span(
        &self,
        operation_name: &str,
        kind: SpanKind,
        parent_context: Option<&TelemetryContext>,
    ) -> DistributedSpan {
        let (trace_id, parent_span_id) = if let Some(parent) = parent_context {
            (parent.trace_id.clone(), Some(parent.span_id.clone()))
        } else {
            (uuid::Uuid::new_v4().to_string(), None)
        };

        let span_id = uuid::Uuid::new_v4().to_string();

        // Check sampling decision
        let sampling_decision =
            self.sampler
                .should_sample(&trace_id, parent_context, operation_name, kind, &[]);

        let mut attributes = HashMap::new();

        // Add sampling attributes if provided
        if let Some(sampling_attrs) = sampling_decision.attributes {
            attributes.insert(
                "sampling.priority".to_string(),
                sampling_attrs.sampling_priority.to_string(),
            );
            attributes.insert(
                "sampling.rate".to_string(),
                sampling_attrs.sampling_rate.to_string(),
            );
        }

        // Add standard attributes
        attributes.insert("span.kind".to_string(), format!("{kind:?}"));
        attributes.insert("service.name".to_string(), "kindly-guard".to_string());

        let span = DistributedSpan {
            span_id: span_id.clone(),
            trace_id: trace_id.clone(),
            parent_span_id,
            operation_name: operation_name.to_string(),
            start_time: Instant::now(),
            end_time: None,
            kind,
            status: SpanStatus {
                code: StatusCode::Unset,
                description: None,
            },
            attributes,
            events: Vec::new(),
            links: Vec::new(),
        };

        // Store active span if sampled
        if sampling_decision.sampled {
            self.active_spans
                .write()
                .await
                .insert(span_id.clone(), span.clone());

            // Also notify base provider
            self.base_provider.start_span(operation_name);
        }

        span
    }

    /// Add event to span
    pub async fn add_span_event(
        &self,
        span_id: &str,
        event_name: &str,
        attributes: Vec<(&str, &str)>,
    ) {
        if let Some(span) = self.active_spans.write().await.get_mut(span_id) {
            let event = SpanEvent {
                name: event_name.to_string(),
                timestamp: Instant::now(),
                timestamp_utc: chrono::Utc::now(),
                attributes: attributes
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            };
            span.events.push(event);
        }
    }

    /// Add link to span
    pub async fn add_span_link(
        &self,
        span_id: &str,
        link_trace_id: &str,
        link_span_id: &str,
        attributes: Vec<(&str, &str)>,
    ) {
        if let Some(span) = self.active_spans.write().await.get_mut(span_id) {
            let link = SpanLink {
                trace_id: link_trace_id.to_string(),
                span_id: link_span_id.to_string(),
                attributes: attributes
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            };
            span.links.push(link);
        }
    }

    /// End a distributed span
    pub async fn end_distributed_span(&self, span_id: &str, status: SpanStatus) {
        if let Some(mut span) = self.active_spans.write().await.remove(span_id) {
            span.end_time = Some(Instant::now());
            span.status = status;

            // Calculate duration
            if let Some(end_time) = span.end_time {
                let duration = end_time.duration_since(span.start_time);

                // Record span duration metric
                self.base_provider.record_metric(TelemetryMetric {
                    name: format!("trace.span.duration.{}", span.operation_name),
                    value: MetricValue::Histogram(duration.as_secs_f64() * 1000.0),
                    labels: vec![
                        ("span.kind".to_string(), format!("{:?}", span.kind)),
                        ("status.code".to_string(), format!("{:?}", span.status.code)),
                    ],
                });
            }

            // Store completed span
            let mut completed = self.completed_spans.write().await;
            completed.push(span.clone());

            // Limit buffer size
            if completed.len() > 10000 {
                completed.drain(0..1000);
            }
        }
    }

    /// Get trace context for a span
    pub async fn get_span_context(&self, span_id: &str) -> Option<TelemetryContext> {
        self.active_spans
            .read()
            .await
            .get(span_id)
            .map(|span| TelemetryContext {
                trace_id: span.trace_id.clone(),
                span_id: span.span_id.clone(),
                parent_span_id: span.parent_span_id.clone(),
                baggage: vec![],
            })
    }

    /// Export completed spans (for background processing)
    pub async fn export_spans(&self) -> Vec<DistributedSpan> {
        let mut completed = self.completed_spans.write().await;
        let spans: Vec<_> = completed.drain(..).collect();
        spans
    }
}

/// Probability sampler implementation
pub struct ProbabilitySampler {
    sampling_rate: f64,
}

impl ProbabilitySampler {
    pub const fn new(sampling_rate: f64) -> Self {
        Self {
            sampling_rate: sampling_rate.clamp(0.0, 1.0),
        }
    }
}

impl TracingSampler for ProbabilitySampler {
    fn should_sample(
        &self,
        trace_id: &str,
        parent_context: Option<&TelemetryContext>,
        _span_name: &str,
        _span_kind: SpanKind,
        _attributes: &[(String, String)],
    ) -> SamplingDecision {
        // If parent is sampled, always sample
        if parent_context.is_some() {
            return SamplingDecision {
                sampled: true,
                attributes: Some(SamplingAttributes {
                    sampling_priority: 1.0,
                    sampling_rate: self.sampling_rate,
                }),
            };
        }

        // Use trace ID for deterministic sampling
        // Use a better hash distribution for sequential IDs
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        trace_id.hash(&mut hasher);
        let hash = hasher.finish();

        let probability = (hash as f64) / (u64::MAX as f64);
        let sampled = probability < self.sampling_rate;

        SamplingDecision {
            sampled,
            attributes: if sampled {
                Some(SamplingAttributes {
                    sampling_priority: if sampled { 1.0 } else { 0.0 },
                    sampling_rate: self.sampling_rate,
                })
            } else {
                None
            },
        }
    }
}

/// W3C `TraceContext` propagator
pub struct W3CTraceContextPropagator;

#[async_trait]
impl ContextPropagator for W3CTraceContextPropagator {
    async fn extract(&self, carrier: &dyn ContextCarrier) -> Result<Option<TelemetryContext>> {
        // Extract traceparent header
        if let Some(traceparent) = carrier.get("traceparent") {
            // Parse W3C trace context format: version-trace_id-parent_id-trace_flags
            let parts: Vec<&str> = traceparent.split('-').collect();
            if parts.len() >= 4 {
                let trace_id = parts[1].to_string();
                let span_id = parts[2].to_string();

                // Extract tracestate if present
                let baggage = if let Some(tracestate) = carrier.get("tracestate") {
                    tracestate
                        .split(',')
                        .filter_map(|kv| {
                            let parts: Vec<&str> = kv.split('=').collect();
                            if parts.len() == 2 {
                                Some((parts[0].to_string(), parts[1].to_string()))
                            } else {
                                None
                            }
                        })
                        .collect()
                } else {
                    vec![]
                };

                return Ok(Some(TelemetryContext {
                    trace_id,
                    span_id: uuid::Uuid::new_v4().to_string(), // Generate new span ID
                    parent_span_id: Some(span_id),
                    baggage,
                }));
            }
        }

        Ok(None)
    }

    async fn inject(
        &self,
        context: &TelemetryContext,
        carrier: &mut dyn ContextCarrier,
    ) -> Result<()> {
        // Create traceparent header
        let parent_id = context.parent_span_id.as_ref().unwrap_or(&context.span_id);
        let traceparent = format!("00-{}-{}-01", context.trace_id, parent_id);
        carrier.set("traceparent", traceparent);

        // Create tracestate header if baggage exists
        if !context.baggage.is_empty() {
            let tracestate = context
                .baggage
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",");
            carrier.set("tracestate", tracestate);
        }

        Ok(())
    }
}

/// HTTP headers carrier implementation
pub struct HttpHeadersCarrier {
    headers: HashMap<String, String>,
}

impl Default for HttpHeadersCarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpHeadersCarrier {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub const fn from_headers(headers: HashMap<String, String>) -> Self {
        Self { headers }
    }
}

impl ContextCarrier for HttpHeadersCarrier {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).map(std::string::String::as_str)
    }

    fn set(&mut self, key: &str, value: String) {
        self.headers.insert(key.to_string(), value);
    }

    fn keys(&self) -> Vec<&str> {
        self.headers
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }
}

/// Span builder for convenience
pub struct SpanBuilder<'a> {
    provider: &'a DistributedTracingProvider,
    operation_name: String,
    kind: SpanKind,
    parent_context: Option<TelemetryContext>,
    attributes: Vec<(String, String)>,
    links: Vec<SpanLink>,
}

impl<'a> SpanBuilder<'a> {
    pub fn new(provider: &'a DistributedTracingProvider, operation_name: &str) -> Self {
        Self {
            provider,
            operation_name: operation_name.to_string(),
            kind: SpanKind::Internal,
            parent_context: None,
            attributes: Vec::new(),
            links: Vec::new(),
        }
    }

    pub const fn with_kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_parent(mut self, parent: TelemetryContext) -> Self {
        self.parent_context = Some(parent);
        self
    }

    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.push((key.to_string(), value.to_string()));
        self
    }

    pub fn with_link(mut self, trace_id: &str, span_id: &str) -> Self {
        self.links.push(SpanLink {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            attributes: HashMap::new(),
        });
        self
    }

    pub async fn start(self) -> DistributedSpan {
        let mut span = self
            .provider
            .start_distributed_span(
                &self.operation_name,
                self.kind,
                self.parent_context.as_ref(),
            )
            .await;

        // Add attributes
        for (key, value) in self.attributes {
            span.attributes.insert(key, value);
        }

        // Add links
        span.links = self.links;

        span
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::standard::StandardTelemetryProvider;
    use crate::telemetry::TelemetryConfig;

    #[tokio::test]
    async fn test_distributed_span_lifecycle() {
        let config = TelemetryConfig::default();
        let base_provider = Arc::new(StandardTelemetryProvider::new(config));
        let sampler = Arc::new(ProbabilitySampler::new(1.0)); // Always sample
        let propagator = Arc::new(W3CTraceContextPropagator);

        let provider = DistributedTracingProvider::new(base_provider, sampler, propagator);

        // Start a span
        let span = provider
            .start_distributed_span("test_operation", SpanKind::Internal, None)
            .await;

        assert!(!span.trace_id.is_empty());
        assert!(!span.span_id.is_empty());
        assert_eq!(span.operation_name, "test_operation");

        // Add event
        provider
            .add_span_event(&span.span_id, "test_event", vec![("key", "value")])
            .await;

        // End span
        provider
            .end_distributed_span(
                &span.span_id,
                SpanStatus {
                    code: StatusCode::Ok,
                    description: None,
                },
            )
            .await;

        // Check completed spans
        let exported = provider.export_spans().await;
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].span_id, span.span_id);
    }

    #[tokio::test]
    async fn test_context_propagation() {
        let propagator = W3CTraceContextPropagator;
        let mut carrier = HttpHeadersCarrier::new();

        let context = TelemetryContext {
            trace_id: "00112233445566778899aabbccddeeff".to_string(),
            span_id: "0123456789abcdef".to_string(),
            parent_span_id: Some("fedcba9876543210".to_string()),
            baggage: vec![("user".to_string(), "test".to_string())],
        };

        // Inject context
        propagator.inject(&context, &mut carrier).await.unwrap();
        assert!(carrier.get("traceparent").is_some());

        // Extract context
        let extracted = propagator.extract(&carrier).await.unwrap().unwrap();
        assert_eq!(extracted.trace_id, context.trace_id);
        assert_eq!(
            extracted.parent_span_id,
            Some("fedcba9876543210".to_string())
        );
    }

    #[test]
    fn test_probability_sampler() {
        let sampler = ProbabilitySampler::new(0.5);

        // Test multiple trace IDs to verify sampling behavior
        let sampled_count = (0..1000)
            .filter(|i| {
                let trace_id = format!("trace-{}", i);
                let decision =
                    sampler.should_sample(&trace_id, None, "test", SpanKind::Internal, &[]);
                decision.sampled
            })
            .count();

        // Should be roughly 50% sampled (with some variance)
        // Allow for wider variance due to hash distribution
        assert!(
            sampled_count > 350 && sampled_count < 650,
            "Sampled count {} is outside expected range [350, 650]",
            sampled_count
        );
    }
}
