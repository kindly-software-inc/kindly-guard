//! Enhanced event processor implementation using kindly-guard-core
//! 
//! This module is only available when the "enhanced" feature is enabled
//! and provides optimized event processing using patented AtomicEventBuffer technology.

#![cfg(feature = "enhanced")]

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use kindly_guard_core::{AtomicEventBuffer, Priority};

use crate::core::{EventMetrics, EventProcessorTrait, SecurityEvent};

/// Enhanced event processor with lock-free AtomicEventBuffer
pub struct EnhancedEventProcessor {
    /// Core event buffer using patented atomic technology
    buffer: Arc<AtomicEventBuffer>,
    
    /// Performance metrics
    events_processed: AtomicU64,
    events_dropped: AtomicU64,
    
    /// Runtime tracking
    start_time: Instant,
}

impl EnhancedEventProcessor {
    /// Create new enhanced processor with specified buffer size
    pub fn new(buffer_size_mb: usize) -> Result<Self> {
        let buffer = Arc::new(AtomicEventBuffer::new(buffer_size_mb * 1024 * 1024));
        
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
        
        // Use AtomicEventBuffer for lock-free enqueue
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
        // AtomicEventBuffer handles its own persistence
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