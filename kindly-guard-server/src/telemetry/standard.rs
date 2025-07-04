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
//! Standard telemetry implementation using OpenTelemetry

use super::{
    async_trait, Result, TelemetryConfig, TelemetryMetric, TelemetryProvider,
    TelemetryProviderFactory, TelemetrySpan,
};
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

/// Standard telemetry provider using in-memory storage
pub struct StandardTelemetryProvider {
    config: TelemetryConfig,
    spans: Arc<Mutex<Vec<TelemetrySpan>>>,
    metrics: Arc<Mutex<Vec<TelemetryMetric>>>,
    events: Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>,
}

impl StandardTelemetryProvider {
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config,
            spans: Arc::new(Mutex::new(Vec::new())),
            metrics: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get collected metrics (for testing/debugging)
    pub fn get_metrics(&self) -> Vec<TelemetryMetric> {
        self.metrics.lock().unwrap().clone()
    }
}

#[async_trait]
impl TelemetryProvider for StandardTelemetryProvider {
    fn start_span(&self, name: &str) -> TelemetrySpan {
        let span = TelemetrySpan {
            name: name.to_string(),
            start_time: std::time::Instant::now(),
            attributes: vec![
                ("service.name".to_string(), self.config.service_name.clone()),
                (
                    "service.version".to_string(),
                    self.config.service_version.clone(),
                ),
            ],
        };

        if self.config.tracing_enabled {
            debug!("Starting span: {}", name);
        }

        span
    }

    fn end_span(&self, span: TelemetrySpan) {
        if !self.config.tracing_enabled {
            return;
        }

        let duration = span.start_time.elapsed();
        debug!("Ending span: {} (duration: {:?})", span.name, duration);

        if let Ok(mut spans) = self.spans.lock() {
            spans.push(span);

            // Keep only last 1000 spans to prevent memory growth
            if spans.len() > 1000 {
                spans.drain(0..100);
            }
        }
    }

    fn record_metric(&self, metric: TelemetryMetric) {
        if !self.config.metrics_enabled {
            return;
        }

        debug!("Recording metric: {} = {:?}", metric.name, metric.value);

        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.push(metric);

            // Keep only last 10000 metrics
            if metrics.len() > 10000 {
                metrics.drain(0..1000);
            }
        }
    }

    fn add_event(&self, name: &str, attributes: Vec<(&str, &str)>) {
        if !self.config.tracing_enabled {
            return;
        }

        debug!("Adding event: {}", name);

        let attrs: Vec<(String, String)> = attributes
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if let Ok(mut events) = self.events.lock() {
            events.push((name.to_string(), attrs));

            // Keep only last 5000 events
            if events.len() > 5000 {
                events.drain(0..500);
            }
        }
    }

    fn set_status(&self, span: &TelemetrySpan, is_error: bool, message: Option<&str>) {
        if !self.config.tracing_enabled {
            return;
        }

        debug!(
            "Setting span status for {}: error={}, message={:?}",
            span.name, is_error, message
        );
    }

    async fn flush(&self) -> Result<()> {
        info!("Flushing telemetry data");

        // In a real implementation, this would export to OTLP endpoint
        if let Some(endpoint) = &self.config.export_endpoint {
            debug!("Would export to: {}", endpoint);
        }

        // Log summary
        let spans_count = self.spans.lock().map(|s| s.len()).unwrap_or(0);
        let metrics_count = self.metrics.lock().map(|m| m.len()).unwrap_or(0);
        let events_count = self.events.lock().map(|e| e.len()).unwrap_or(0);

        info!(
            "Telemetry summary: {} spans, {} metrics, {} events",
            spans_count, metrics_count, events_count
        );

        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down telemetry provider");
        self.flush().await?;

        // Clear all data
        if let Ok(mut spans) = self.spans.lock() {
            spans.clear();
        }
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.clear();
        }
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }

        Ok(())
    }
}

/// Factory for standard telemetry
pub struct StandardTelemetryFactory;

impl TelemetryProviderFactory for StandardTelemetryFactory {
    fn create(&self, config: &TelemetryConfig) -> Result<Arc<dyn TelemetryProvider>> {
        Ok(Arc::new(StandardTelemetryProvider::new(config.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_standard_telemetry() {
        let config = TelemetryConfig::default();
        let provider = StandardTelemetryProvider::new(config);

        // Test span
        let span = provider.start_span("test.operation");
        std::thread::sleep(std::time::Duration::from_millis(10));
        provider.end_span(span);

        // Test metric
        provider.record_metric(TelemetryMetric {
            name: "test.counter".to_string(),
            value: crate::telemetry::MetricValue::Counter(42),
            labels: vec![],
        });

        // Test event
        provider.add_event("test.event", vec![("key", "value")]);

        // Verify data was collected
        let metrics = provider.get_metrics();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, "test.counter");

        // Test flush
        provider.flush().await.unwrap();
    }
}
