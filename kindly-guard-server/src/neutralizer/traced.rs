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
//! Distributed tracing integration for neutralization
//!
//! Provides distributed tracing capabilities for tracking neutralization
//! operations across system boundaries with detailed span information.

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Instant;

use crate::{
    neutralizer::{
        BatchNeutralizeResult, NeutralizeResult, NeutralizerCapabilities, ThreatNeutralizer,
    },
    scanner::{Threat, ThreatType},
    telemetry::{
        DistributedTracingProvider, SpanBuilder, SpanKind, SpanStatus, StatusCode, TelemetryContext,
    },
};

/// Neutralizer wrapper that adds distributed tracing
pub struct TracedNeutralizer {
    inner: Arc<dyn ThreatNeutralizer>,
    tracing_provider: Arc<DistributedTracingProvider>,
    service_name: String,
}

impl TracedNeutralizer {
    /// Create a new traced neutralizer
    pub fn new(
        neutralizer: Arc<dyn ThreatNeutralizer>,
        tracing_provider: Arc<DistributedTracingProvider>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: neutralizer,
            tracing_provider,
            service_name: "kindly-guard.neutralizer".to_string(),
        })
    }

    /// Extract parent context from current async context (if available)
    async fn get_parent_context(&self) -> Option<TelemetryContext> {
        // In a real implementation, this would extract from async-local context
        // For now, we'll return None and spans will be root spans
        None
    }
}

#[async_trait]
impl ThreatNeutralizer for TracedNeutralizer {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        let parent_context = self.get_parent_context().await;

        // Start neutralization span
        let span = SpanBuilder::new(&self.tracing_provider, "neutralize")
            .with_kind(SpanKind::Internal)
            .with_attribute("service.name", &self.service_name)
            .with_attribute("threat.type", &format!("{:?}", threat.threat_type))
            .with_attribute("threat.severity", &format!("{:?}", threat.severity))
            .with_attribute("content.length", &content.len().to_string())
            .with_attribute(
                "threat.location.offset",
                &match &threat.location {
                    crate::scanner::Location::Text { offset, .. } => offset.to_string(),
                    crate::scanner::Location::Json { path, .. } => format!("json:{path}"),
                    crate::scanner::Location::Binary { offset } => format!("binary:{offset}"),
                },
            )
            .start()
            .await;

        let span_id = span.span_id.clone();
        let start_time = Instant::now();

        // Add start event
        self.tracing_provider
            .add_span_event(
                &span_id,
                "neutralization.start",
                vec![("threat.description", &threat.description)],
            )
            .await;

        // Perform neutralization
        let result = self.inner.neutralize(threat, content).await;
        let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;

        // Determine status based on result
        let (status_code, status_description) = match &result {
            Ok(neutralize_result) => {
                // Add success event with details
                self.tracing_provider
                    .add_span_event(
                        &span_id,
                        "neutralization.complete",
                        vec![
                            ("action", &format!("{}", neutralize_result.action_taken)),
                            (
                                "confidence",
                                &neutralize_result.confidence_score.to_string(),
                            ),
                            (
                                "processing_time_us",
                                &neutralize_result.processing_time_us.to_string(),
                            ),
                            (
                                "modified",
                                if neutralize_result.sanitized_content.is_some() {
                                    "true"
                                } else {
                                    "false"
                                },
                            ),
                        ],
                    )
                    .await;

                // Add correlation data if present
                if let Some(ref correlation) = neutralize_result.correlation_data {
                    self.tracing_provider
                        .add_span_event(
                            &span_id,
                            "neutralization.correlation",
                            vec![
                                (
                                    "related_threats",
                                    &correlation.related_threats.len().to_string(),
                                ),
                                (
                                    "attack_pattern",
                                    &format!("{:?}", correlation.attack_pattern),
                                ),
                                (
                                    "prediction_score",
                                    &correlation.prediction_score.to_string(),
                                ),
                            ],
                        )
                        .await;

                    // Link to related threat spans if they exist
                    for related_id in &correlation.related_threats {
                        // In a real system, we'd look up the trace/span IDs for related threats
                        self.tracing_provider
                            .add_span_link(
                                &span_id,
                                &span.trace_id, // Same trace for now
                                related_id,
                                vec![("link.type", "related_threat")],
                            )
                            .await;
                    }
                }

                (StatusCode::Ok, None)
            }
            Err(e) => {
                // Add error event
                self.tracing_provider
                    .add_span_event(
                        &span_id,
                        "neutralization.error",
                        vec![
                            ("error.type", &format!("{e:?}")),
                            ("error.message", &e.to_string()),
                        ],
                    )
                    .await;

                (StatusCode::Error, Some(e.to_string()))
            }
        };

        // Record metrics via span attributes (before ending span)
        if let Ok(ref neutralize_result) = result {
            self.tracing_provider
                .add_span_event(
                    &span_id,
                    "metrics.recorded",
                    vec![
                        ("duration_ms", &duration_ms.to_string()),
                        ("threat_type", &format!("{:?}", threat.threat_type)),
                        (
                            "action_taken",
                            &format!("{}", neutralize_result.action_taken),
                        ),
                    ],
                )
                .await;
        }

        // End span with status
        self.tracing_provider
            .end_distributed_span(
                &span_id,
                SpanStatus {
                    code: status_code,
                    description: status_description,
                },
            )
            .await;

        result
    }

    async fn batch_neutralize(
        &self,
        threats: &[Threat],
        content: &str,
    ) -> Result<BatchNeutralizeResult> {
        let parent_context = self.get_parent_context().await;

        // Start batch span
        let batch_span = SpanBuilder::new(&self.tracing_provider, "batch_neutralize")
            .with_kind(SpanKind::Internal)
            .with_attribute("service.name", &self.service_name)
            .with_attribute("batch.size", &threats.len().to_string())
            .with_attribute("content.length", &content.len().to_string())
            .start()
            .await;

        let batch_span_id = batch_span.span_id.clone();
        let batch_context = TelemetryContext {
            trace_id: batch_span.trace_id.clone(),
            span_id: batch_span.span_id.clone(),
            parent_span_id: parent_context.as_ref().map(|p| p.span_id.clone()),
            baggage: vec![],
        };

        // Create child spans for each threat
        let mut individual_results = Vec::new();
        let mut current_content = content.to_string();
        let start_time = Instant::now();

        for (i, threat) in threats.iter().enumerate() {
            // Create child span for this threat
            let child_span = SpanBuilder::new(&self.tracing_provider, "batch_neutralize.item")
                .with_kind(SpanKind::Internal)
                .with_parent(batch_context.child())
                .with_attribute("batch.index", &i.to_string())
                .with_attribute("threat.type", &format!("{:?}", threat.threat_type))
                .start()
                .await;

            let child_span_id = child_span.span_id.clone();

            // Neutralize with the inner implementation
            let result = self.inner.neutralize(threat, &current_content).await;

            // Update content if modified
            if let Ok(ref neutralize_result) = result {
                if let Some(ref sanitized) = neutralize_result.sanitized_content {
                    current_content = sanitized.clone();
                }
                individual_results.push(neutralize_result.clone());
            }

            // End child span
            let status = if result.is_ok() {
                SpanStatus {
                    code: StatusCode::Ok,
                    description: None,
                }
            } else {
                SpanStatus {
                    code: StatusCode::Error,
                    description: result.as_ref().err().map(std::string::ToString::to_string),
                }
            };

            self.tracing_provider
                .end_distributed_span(&child_span_id, status)
                .await;

            // Link child span to batch span
            self.tracing_provider
                .add_span_link(
                    &batch_span_id,
                    &child_span.trace_id,
                    &child_span_id,
                    vec![("link.type", "batch_item")],
                )
                .await;
        }

        let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;

        // Add batch summary event
        let successful_count = individual_results.len();
        self.tracing_provider
            .add_span_event(
                &batch_span_id,
                "batch.summary",
                vec![
                    ("total_threats", &threats.len().to_string()),
                    ("successful", &successful_count.to_string()),
                    ("failed", &(threats.len() - successful_count).to_string()),
                    ("duration_ms", &duration_ms.to_string()),
                ],
            )
            .await;

        // End batch span
        self.tracing_provider
            .end_distributed_span(
                &batch_span_id,
                SpanStatus {
                    code: if successful_count == threats.len() {
                        StatusCode::Ok
                    } else {
                        StatusCode::Error
                    },
                    description: if successful_count < threats.len() {
                        Some(format!(
                            "{} of {} threats failed",
                            threats.len() - successful_count,
                            threats.len()
                        ))
                    } else {
                        None
                    },
                },
            )
            .await;

        Ok(BatchNeutralizeResult {
            final_content: current_content,
            individual_results,
        })
    }

    fn can_neutralize(&self, threat_type: &ThreatType) -> bool {
        self.inner.can_neutralize(threat_type)
    }

    fn get_capabilities(&self) -> NeutralizerCapabilities {
        self.inner.get_capabilities()
    }
}

/// Extension trait for adding tracing to neutralizers
pub trait NeutralizerTracingExt {
    /// Wrap this neutralizer with distributed tracing
    fn with_tracing(
        self: Arc<Self>,
        tracing_provider: Arc<DistributedTracingProvider>,
    ) -> Arc<TracedNeutralizer>;
}

impl NeutralizerTracingExt for dyn ThreatNeutralizer {
    fn with_tracing(
        self: Arc<Self>,
        tracing_provider: Arc<DistributedTracingProvider>,
    ) -> Arc<TracedNeutralizer> {
        TracedNeutralizer::new(self, tracing_provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        neutralizer::{standard::StandardNeutralizer, NeutralizationConfig},
        scanner::{Location, Severity},
        telemetry::{
            ProbabilitySampler, StandardTelemetryProvider, TelemetryConfig,
            W3CTraceContextPropagator,
        },
    };

    #[tokio::test]
    async fn test_traced_neutralization() {
        // Setup
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));

        let telemetry_config = TelemetryConfig::default();
        let base_provider = Arc::new(StandardTelemetryProvider::new(telemetry_config));
        let sampler = Arc::new(ProbabilitySampler::new(1.0));
        let propagator = Arc::new(W3CTraceContextPropagator);

        let tracing_provider = Arc::new(DistributedTracingProvider::new(
            base_provider,
            sampler,
            propagator,
        ));

        // Create traced neutralizer
        let traced =
            (neutralizer as Arc<dyn ThreatNeutralizer>).with_tracing(tracing_provider.clone());

        // Test threat
        let threat = Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text {
                offset: 0,
                length: 10,
            },
            description: "SQL injection test".to_string(),
            remediation: None,
        };

        // Perform neutralization
        let result = traced.neutralize(&threat, "SELECT * FROM users").await;
        assert!(result.is_ok());

        // Export spans to verify tracing
        let spans = tracing_provider.export_spans().await;
        assert!(!spans.is_empty());

        let span = &spans[0];
        assert_eq!(span.operation_name, "neutralize");
        // Debug: print attributes to see what's there
        eprintln!("Span attributes: {:?}", span.attributes);
        assert!(span.attributes.contains_key("threat.type"));
        assert!(span.events.iter().any(|e| e.name == "neutralization.start"));
    }

    #[tokio::test]
    async fn test_batch_traced_neutralization() {
        // Setup
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));

        let telemetry_config = TelemetryConfig::default();
        let base_provider = Arc::new(StandardTelemetryProvider::new(telemetry_config));
        let sampler = Arc::new(ProbabilitySampler::new(1.0));
        let propagator = Arc::new(W3CTraceContextPropagator);

        let tracing_provider = Arc::new(DistributedTracingProvider::new(
            base_provider,
            sampler,
            propagator,
        ));

        // Create traced neutralizer
        let traced =
            (neutralizer as Arc<dyn ThreatNeutralizer>).with_tracing(tracing_provider.clone());

        // Test threats
        let threats = vec![
            Threat {
                threat_type: ThreatType::SqlInjection,
                severity: Severity::High,
                location: Location::Text {
                    offset: 0,
                    length: 10,
                },
                description: "SQL injection".to_string(),
                remediation: None,
            },
            Threat {
                threat_type: ThreatType::CommandInjection,
                severity: Severity::High,
                location: Location::Text {
                    offset: 20,
                    length: 10,
                },
                description: "Command injection".to_string(),
                remediation: None,
            },
        ];

        // Perform batch neutralization
        let result = traced
            .batch_neutralize(&threats, "SELECT * FROM users; echo test")
            .await;
        assert!(result.is_ok());

        // Export spans
        let spans = tracing_provider.export_spans().await;

        // Should have batch span plus child spans
        assert!(spans.len() >= 3); // 1 batch + 2 items

        // Find batch span
        let batch_span = spans
            .iter()
            .find(|s| s.operation_name == "batch_neutralize")
            .unwrap();
        eprintln!("Batch span attributes: {:?}", batch_span.attributes);
        assert!(batch_span.attributes.contains_key("batch.size"));
        assert!(batch_span.events.iter().any(|e| e.name == "batch.summary"));
    }
}
