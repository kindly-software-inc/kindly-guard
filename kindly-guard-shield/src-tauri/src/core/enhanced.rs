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
//! Enhanced event processor implementation
//! 
//! This module is only available when the "enhanced" feature is enabled
//! and provides optimized event processing.

#![cfg(feature = "enhanced")]

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

// Enhanced implementation types would be imported here
use crate::core::{EventMetrics, EventProcessorTrait, SecurityEvent};

/// Priority levels for event processing
#[derive(Debug, Clone, Copy)]
enum Priority {
    Urgent,
    High,
    Normal,
    Low,
}

/// Event buffer trait for abstraction
trait EventBuffer: Send + Sync {
    fn enqueue_event(&self, client_id: &[u8], data: &[u8], priority: Priority) -> Result<u64>;
    fn get_utilization(&self) -> f64;
    fn get_avg_latency_ms(&self) -> f64;
    fn is_responsive(&self) -> bool;
    fn flush(&self) -> Result<()>;
}

/// Enhanced event processor with optimized buffer
pub struct EnhancedEventProcessor {
    /// Core event buffer implementation
    buffer: Arc<dyn EventBuffer>,
    
    /// Performance metrics
    events_processed: AtomicU64,
    events_dropped: AtomicU64,
    
    /// Runtime tracking
    start_time: Instant,
}

impl EnhancedEventProcessor {
    /// Create new enhanced processor with specified buffer size
    pub fn new(buffer_size_mb: usize) -> Result<Self> {
        // Create enhanced buffer implementation
        let buffer: Arc<dyn EventBuffer> = create_enhanced_buffer(buffer_size_mb * 1024 * 1024)?;
        
        Ok(Self {
            buffer,
            events_processed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            start_time: Instant::now(),
        })
    }
    
    /// Map threat level to priority for event buffer
    fn map_priority(threat_level: f32) -> Priority {
        if threat_level >= 0.8 {
            Priority::Urgent
        } else if threat_level >= 0.5 {
            Priority::High
        } else if threat_level >= 0.3 {
            Priority::Normal
        } else {
            Priority::Low
        }
    }
}

impl EventProcessorTrait for EnhancedEventProcessor {
    fn process_event(&self, event: SecurityEvent) -> Result<()> {
        let priority = Self::map_priority(event.threat_level);
        
        // Serialize event for buffer storage
        let event_data = serde_json::to_vec(&event)?;
        
        // Use enhanced buffer for optimized enqueue
        match self.buffer.enqueue_event(
            event.client_id.as_bytes(),
            &event_data,
            priority
        ) {
            Ok(_event_id) => {
                self.events_processed.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    event_type = %event.event_type,
                    threat_level = event.threat_level,
                    "Event processed using enhanced buffer"
                );
                Ok(())
            }
            Err(e) => {
                self.events_dropped.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    error = %e,
                    event_type = %event.event_type,
                    "Failed to enqueue event in enhanced buffer"
                );
                Err(e.into())
            }
        }
    }
    
    fn get_metrics(&self) -> EventMetrics {
        let elapsed = self.start_time.elapsed();
        let events_processed = self.events_processed.load(Ordering::Relaxed);
        let events_dropped = self.events_dropped.load(Ordering::Relaxed);
        
        let events_per_second = if elapsed.as_secs() > 0 {
            events_processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        
        EventMetrics {
            events_processed,
            events_dropped,
            events_per_second,
            buffer_utilization: self.buffer.get_utilization(),
            avg_latency_ms: self.buffer.get_avg_latency_ms(),
        }
    }
    
    fn is_healthy(&self) -> bool {
        // Check buffer health and utilization
        let utilization = self.buffer.get_utilization();
        let is_responsive = self.buffer.is_responsive();
        
        utilization < 0.9 && is_responsive
    }
    
    fn flush(&self) -> Result<()> {
        // Enhanced buffer handles its own persistence
        self.buffer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enhanced_processor_creation() {
        let processor = EnhancedEventProcessor::new(16).unwrap();
        assert!(processor.is_healthy());
    }
    
    #[test]
    fn test_priority_mapping() {
        assert!(matches!(EnhancedEventProcessor::map_priority(0.9), Priority::Urgent));
        assert!(matches!(EnhancedEventProcessor::map_priority(0.6), Priority::High));
        assert!(matches!(EnhancedEventProcessor::map_priority(0.4), Priority::Normal));
        assert!(matches!(EnhancedEventProcessor::map_priority(0.1), Priority::Low));
    }
}

/// Create an enhanced buffer implementation
/// This would create the actual enhanced buffer based on available implementations
fn create_enhanced_buffer(_size: usize) -> Result<Arc<dyn EventBuffer>> {
    // Placeholder - actual implementation would be provided by the enhanced feature
    unimplemented!("Enhanced buffer implementation not available")
}