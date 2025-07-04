// Copyright 2025 Kindly Software Inc.
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
//! Metrics collection and export for monitoring
//! Provides trait-based abstraction for different implementations

pub mod enhanced_interface;
pub mod standard;

use self::standard::StandardMetricsProvider;
use crate::config::Config;
use crate::traits::MetricsProvider;
use std::sync::Arc;

// Re-export the standard implementation for compatibility
pub use standard::StandardMetricsProvider as MetricsRegistry;

// Re-export traits for convenience
pub use crate::traits::{CounterTrait, GaugeTrait, HistogramStats, HistogramTrait};

/// Create a metrics provider based on configuration
#[allow(unused_variables)]
pub fn create_metrics_provider(config: &Config) -> Arc<dyn MetricsProvider> {
    #[cfg(feature = "enhanced")]
    {
        if config.is_event_processor_enabled() {
            // Try to use enhanced implementation
            if let Some(provider) = try_create_enhanced_provider() {
                tracing::info!(
                    target: "metrics.init",
                    mode = "enhanced",
                    "Initializing enhanced metrics provider"
                );
                return provider;
            }
        }
    }

    tracing::info!(
        target: "metrics.init",
        mode = "standard",
        "Initializing standard metrics provider"
    );

    Arc::new(StandardMetricsProvider::new())
}

#[cfg(feature = "enhanced")]
fn try_create_enhanced_provider() -> Option<Arc<dyn MetricsProvider>> {
    // This would load enhanced implementation if available
    // For now, return None to use standard implementation
    None
}

/// Timer for measuring durations
pub struct Timer {
    histogram: Arc<dyn HistogramTrait>,
    start: std::time::Instant,
}

impl Timer {
    /// Create a new timer
    pub fn new(histogram: Arc<dyn HistogramTrait>) -> Self {
        Self {
            histogram,
            start: std::time::Instant::now(),
        }
    }

    /// Stop the timer and record the duration
    pub fn stop(self) {
        let duration = self.start.elapsed();
        self.histogram.observe(duration.as_secs_f64());
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        self.histogram.observe(duration.as_secs_f64());
    }
}
