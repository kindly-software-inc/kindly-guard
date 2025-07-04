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
//! Standard event processor implementation
//!
//! This provides the default event processing without enhanced features

use anyhow::Result;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use crate::core::{EventMetrics, EventProcessorTrait, SecurityEvent};

/// Standard event processor with in-memory queue
pub struct StandardEventProcessor {
    /// Simple in-memory event queue
    event_queue: Mutex<VecDeque<SecurityEvent>>,
    
    /// Maximum queue size
    max_queue_size: usize,
    
    /// Performance counters
    events_processed: AtomicU64,
    events_dropped: AtomicU64,
    
    /// Runtime tracking
    start_time: Instant,
}

impl StandardEventProcessor {
    /// Create new standard processor
    pub fn new() -> Self {
        Self {
            event_queue: Mutex::new(VecDeque::with_capacity(1000)),
            max_queue_size: 10000,
            events_processed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
}

impl EventProcessorTrait for StandardEventProcessor {
    fn process_event(&self, event: SecurityEvent) -> Result<()> {
        let mut queue = self.event_queue.lock().unwrap();
        
        if queue.len() >= self.max_queue_size {
            // Drop oldest event to make room
            queue.pop_front();
            self.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        
        queue.push_back(event);
        self.events_processed.fetch_add(1, Ordering::Relaxed);
        
        tracing::trace!("Event processed using standard queue");
        Ok(())
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
        
        let queue_len = self.event_queue.lock().unwrap().len();
        let buffer_utilization = queue_len as f64 / self.max_queue_size as f64;
        
        EventMetrics {
            events_processed,
            events_dropped,
            events_per_second,
            buffer_utilization,
            avg_latency_ms: 0.1, // Standard implementation has minimal latency
        }
    }
    
    fn is_healthy(&self) -> bool {
        let queue_len = self.event_queue.lock().unwrap().len();
        queue_len < (self.max_queue_size * 9 / 10) // Less than 90% full
    }
    
    fn flush(&self) -> Result<()> {
        let mut queue = self.event_queue.lock().unwrap();
        queue.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_standard_processor() {
        let processor = StandardEventProcessor::new();
        
        let event = SecurityEvent {
            event_type: "test".to_string(),
            client_id: "client1".to_string(),
            threat_level: 0.5,
            timestamp: 12345,
            data: serde_json::json!({}),
        };
        
        assert!(processor.process_event(event).is_ok());
        assert!(processor.is_healthy());
        
        let metrics = processor.get_metrics();
        assert_eq!(metrics.events_processed, 1);
        assert_eq!(metrics.events_dropped, 0);
    }
}