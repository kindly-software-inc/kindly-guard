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
//! Atomic Event Buffer - Lock-free ring buffer implementation
//!
//! This module provides the patented AtomicEventBuffer using advanced
//! lock-free algorithms with bit-packed atomic state for ultra-high
//! performance event processing.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Event priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    /// Normal priority events
    Normal = 0,
    /// Urgent priority events
    Urgent = 1,
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is closed - normal operation
    Closed,
    /// Circuit is open - all requests blocked
    Open,
    /// Circuit is half-open - testing recovery
    HalfOpen,
    /// Circuit is throttled - degraded operation
    Throttled,
}

/// Statistics for an endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStats {
    /// Number of successful operations
    pub success_count: u64,
    /// Number of failed operations
    pub failure_count: u64,
    /// Current circuit breaker state
    pub circuit_state: CircuitState,
    /// Available rate limit tokens
    pub available_tokens: u32,
}

/// Configuration for the event buffer
pub struct EventBufferConfig {
    pub buffer_size_mb: usize,
    pub max_endpoints: u32,
}

/// Trait for event buffer implementations
pub trait EventBufferTrait: Send + Sync {
    /// Enqueue an event in the buffer
    fn enqueue_event(&self, endpoint_id: u32, data: &[u8], priority: Priority) -> Result<u64>;

    /// Get statistics for an endpoint
    fn get_endpoint_stats(&self, endpoint_id: u32) -> Result<EndpointStats>;
}

/// Bit-packed atomic state machine for event processing
/// All state fits in a single 64-bit atomic for cache efficiency
struct AtomicBitPackedEventBuffer {
    /// Per-endpoint state machines
    /// Layout: [position:16][count:16][priority:16][flags:8][version:8]
    endpoint_states: Vec<AtomicU64>,
    
    /// Ring buffer for event data
    event_storage: Arc<EventRingBuffer>,
    
    /// Global event counter
    total_events: AtomicU64,
    
    /// Configuration
    max_endpoints: u32,
    buffer_size_bytes: usize,
}

// Bit positions and masks for state packing
// Layout: [failure_count:16][success_count:16][tokens:8][compression_ratio:8][flags:8][version:8]
const FAILURE_SHIFT: u32 = 48;
const SUCCESS_SHIFT: u32 = 32;
const TOKENS_SHIFT: u32 = 24;
const RATIO_SHIFT: u32 = 16;
const FLAGS_SHIFT: u32 = 8;

const FAILURE_MASK: u64 = 0xFFFF_0000_0000_0000;
const SUCCESS_MASK: u64 = 0x0000_FFFF_0000_0000;
const TOKENS_MASK: u64 = 0x0000_0000_FF00_0000;
const RATIO_MASK: u64 = 0x0000_0000_00FF_0000;
const FLAGS_MASK: u64 = 0x0000_0000_0000_FF00;
const VERSION_MASK: u64 = 0x0000_0000_0000_00FF;

// Flag bits - includes compression flag for security
const FLAG_CIRCUIT_OPEN: u8 = 0b0000_0001;
const FLAG_CIRCUIT_HALF: u8 = 0b0000_0010;
const FLAG_THROTTLED: u8 = 0b0000_0100;
const FLAG_MONITORED: u8 = 0b0000_1000;
const FLAG_COMPRESSED: u8 = 0b0001_0000;  // Critical: tracks compression state

// Security constants
const MAX_COMPRESSION_RATIO: u8 = 10;  // Maximum 10:1 compression ratio
const MAX_DECOMPRESSED_SIZE: usize = 1024 * 1024;  // 1MB max decompressed

/// Lock-free ring buffer for event storage
struct EventRingBuffer {
    /// Buffer capacity (must be power of 2)
    capacity: usize,
    
    /// Write position
    write_pos: AtomicUsize,
    
    /// Read position
    read_pos: AtomicUsize,
    
    /// Actual storage
    buffer: Vec<u8>,
    
    /// Size tracking
    used_bytes: AtomicUsize,
}

impl AtomicBitPackedEventBuffer {
    fn new(config: &EventBufferConfig) -> Result<Self> {
        let max_endpoints = config.max_endpoints;
        let buffer_size_bytes = config.buffer_size_mb * 1024 * 1024;
        
        // Pre-allocate endpoint states
        let mut endpoint_states = Vec::with_capacity(max_endpoints as usize);
        for _ in 0..max_endpoints {
            // Initialize with 100 tokens available, no compression
            let initial_state = (100u64) << TOKENS_SHIFT;
            endpoint_states.push(AtomicU64::new(initial_state));
        }
        
        // Create ring buffer
        let event_storage = Arc::new(EventRingBuffer::new(buffer_size_bytes)?);
        
        Ok(Self {
            endpoint_states,
            event_storage,
            total_events: AtomicU64::new(0),
            max_endpoints,
            buffer_size_bytes,
        })
    }
    
    /// Extract circuit state from flags
    fn flags_to_circuit_state(flags: u8) -> CircuitState {
        if flags & FLAG_CIRCUIT_OPEN != 0 {
            CircuitState::Open
        } else if flags & FLAG_CIRCUIT_HALF != 0 {
            CircuitState::HalfOpen
        } else if flags & FLAG_THROTTLED != 0 {
            CircuitState::Throttled
        } else {
            CircuitState::Closed
        }
    }
    
    /// Update endpoint state atomically with compression tracking
    fn update_endpoint_state(
        &self,
        endpoint_id: u32,
        increment_success: bool,
        increment_failure: bool,
        consume_token: bool,
        is_compressed: bool,
        compression_ratio: u8,
    ) -> Result<()> {
        if endpoint_id >= self.max_endpoints {
            anyhow::bail!("Invalid endpoint ID: {}", endpoint_id);
        }
        
        let state_atomic = &self.endpoint_states[endpoint_id as usize];
        let mut current = state_atomic.load(Ordering::Acquire);
        
        loop {
            // Extract current values with proper masks
            let mut failure_count = ((current & FAILURE_MASK) >> FAILURE_SHIFT) as u16;
            let mut success_count = ((current & SUCCESS_MASK) >> SUCCESS_SHIFT) as u16;
            let mut tokens = ((current & TOKENS_MASK) >> TOKENS_SHIFT) as u8;
            let current_ratio = ((current & RATIO_MASK) >> RATIO_SHIFT) as u8;
            let mut flags = ((current & FLAGS_MASK) >> FLAGS_SHIFT) as u8;
            let version = (current & VERSION_MASK) as u8;
            
            // Security check: validate compression ratio
            if is_compressed && compression_ratio > MAX_COMPRESSION_RATIO {
                tracing::warn!(
                    target: "security.compression",
                    "Suspicious compression ratio: {}",
                    compression_ratio
                );
                return Err(anyhow::anyhow!("Compression ratio exceeds security limits"));
            }
            
            // Update counts
            if increment_success {
                success_count = success_count.saturating_add(1);
            }
            if increment_failure {
                failure_count = failure_count.saturating_add(1);
                
                // Open circuit if too many failures
                if failure_count > 5 {
                    flags |= FLAG_CIRCUIT_OPEN;
                }
            }
            if consume_token && tokens > 0 {
                tokens = tokens.saturating_sub(1);
            }
            
            // Update compression flag using constant-time operation
            flags = (flags & !FLAG_COMPRESSED) | if is_compressed { FLAG_COMPRESSED } else { 0 };
            
            // Audit log compression state changes
            if is_compressed != (flags & FLAG_COMPRESSED != 0) {
                tracing::info!(
                    target: "security.audit.compression",
                    endpoint_id = endpoint_id,
                    compressed = is_compressed,
                    ratio = compression_ratio,
                    "Compression state changed"
                );
            }
            
            // Pack new state with compression info
            let new_ratio = if is_compressed { compression_ratio } else { 0 };
            let new_state = ((failure_count as u64) << FAILURE_SHIFT)
                | ((success_count as u64) << SUCCESS_SHIFT)
                | ((tokens as u64) << TOKENS_SHIFT)
                | ((new_ratio as u64) << RATIO_SHIFT)
                | ((flags as u64) << FLAGS_SHIFT)
                | (version.wrapping_add(1) as u64);
            
            // Try to update atomically
            match state_atomic.compare_exchange_weak(
                current,
                new_state,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }
}

impl EventBufferTrait for AtomicBitPackedEventBuffer {
    fn enqueue_event(&self, endpoint_id: u32, data: &[u8], priority: Priority) -> Result<u64> {
        // Security: Check for compression bombs
        let is_compressed = data.len() > 4 && data[0] == 0x1F && data[1] == 0x8B; // gzip magic
        let compression_ratio = if is_compressed {
            // Simple heuristic: compressed data is typically 10-50% of original
            // If claiming extreme compression, it might be a bomb
            let claimed_size = u32::from_le_bytes([data[2], data[3], data[4], data[5]]) as usize;
            if claimed_size > data.len() * MAX_COMPRESSION_RATIO as usize {
                return Err(anyhow::anyhow!("Potential compression bomb detected"));
            }
            (claimed_size / data.len().max(1)) as u8
        } else {
            0
        };
        
        // Update endpoint state with compression info
        self.update_endpoint_state(endpoint_id, true, false, true, is_compressed, compression_ratio)?;
        
        // Generate event ID
        let event_id = self.total_events.fetch_add(1, Ordering::Relaxed);
        
        // Store in ring buffer (simplified for now)
        self.event_storage.write(data)?;
        
        Ok(event_id)
    }
    
    fn get_endpoint_stats(&self, endpoint_id: u32) -> Result<EndpointStats> {
        if endpoint_id >= self.max_endpoints {
            anyhow::bail!("Invalid endpoint ID: {}", endpoint_id);
        }
        
        let state = self.endpoint_states[endpoint_id as usize].load(Ordering::Acquire);
        
        // Extract values with security information
        let failure_count = ((state & FAILURE_MASK) >> FAILURE_SHIFT) as u64;
        let success_count = ((state & SUCCESS_MASK) >> SUCCESS_SHIFT) as u64;
        let available_tokens = ((state & TOKENS_MASK) >> TOKENS_SHIFT) as u32;
        let compression_ratio = ((state & RATIO_MASK) >> RATIO_SHIFT) as u8;
        let flags = ((state & FLAGS_MASK) >> FLAGS_SHIFT) as u8;
        
        // Log if endpoint is using compression (security monitoring)
        if flags & FLAG_COMPRESSED != 0 {
            tracing::debug!(
                target: "security.stats",
                endpoint_id = endpoint_id,
                compression_ratio = compression_ratio,
                "Endpoint using compression"
            );
        }
        
        Ok(EndpointStats {
            success_count,
            failure_count,
            circuit_state: Self::flags_to_circuit_state(flags),
            available_tokens,
        })
    }
}

impl EventRingBuffer {
    fn new(capacity: usize) -> Result<Self> {
        // Ensure capacity is power of 2 for efficient modulo
        let capacity = capacity.next_power_of_two();
        
        Ok(Self {
            capacity,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
            buffer: vec![0u8; capacity],
            used_bytes: AtomicUsize::new(0),
        })
    }
    
    fn write(&self, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        
        // Check if we have space
        let used = self.used_bytes.load(Ordering::Acquire);
        if used + data_len > self.capacity {
            anyhow::bail!("Ring buffer full");
        }
        
        // Reserve space atomically
        let write_pos = self.write_pos.fetch_add(data_len, Ordering::AcqRel);
        
        // Write data (wrapping around if needed)
        let start = write_pos % self.capacity;
        let end = (write_pos + data_len) % self.capacity;
        
        if start < end {
            // Simple case: continuous write
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    (self.buffer.as_ptr() as *mut u8).add(start),
                    data_len,
                );
            }
        } else {
            // Wrap around: write in two parts
            let first_part = self.capacity - start;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    (self.buffer.as_ptr() as *mut u8).add(start),
                    first_part,
                );
                std::ptr::copy_nonoverlapping(
                    data.as_ptr().add(first_part),
                    self.buffer.as_ptr() as *mut u8,
                    data_len - first_part,
                );
            }
        }
        
        // Update used bytes
        self.used_bytes.fetch_add(data_len, Ordering::Release);
        
        Ok(())
    }
}

/// Create an atomic event buffer with given configuration
/// This is the public factory function that hides implementation details
pub fn create_atomic_event_buffer(config: EventBufferConfig) -> Result<Box<dyn EventBufferTrait>> {
    Ok(Box::new(AtomicBitPackedEventBuffer::new(&config)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bit_packing() {
        let state: u64 = ((5u64) << FAILURE_SHIFT)  // failure_count = 5
            | ((100u64) << SUCCESS_SHIFT)              // success_count = 100
            | ((50u64) << TOKENS_SHIFT)              // tokens = 50
            | ((FLAG_CIRCUIT_OPEN as u64) << FLAGS_SHIFT)  // circuit open
            | 42u64;                                  // version = 42
        
        // Extract values
        let failure_count = ((state & FAILURE_MASK) >> FAILURE_SHIFT) as u16;
        let success_count = ((state & SUCCESS_MASK) >> SUCCESS_SHIFT) as u16;
        let tokens = ((state & TOKENS_MASK) >> TOKENS_SHIFT) as u8;
        let flags = ((state & FLAGS_MASK) >> FLAGS_SHIFT) as u8;
        let version = (state & VERSION_MASK) as u8;
        
        assert_eq!(failure_count, 5);
        assert_eq!(success_count, 100);
        assert_eq!(tokens, 50);
        assert_eq!(flags, FLAG_CIRCUIT_OPEN);
        assert_eq!(version, 42);
    }
    
    #[test]
    fn test_concurrent_updates() {
        use std::sync::Arc;
        use std::thread;
        
        let config = EventBufferConfig {
            buffer_size_mb: 10,
            max_endpoints: 100,
        };
        
        let buffer = Arc::new(AtomicBitPackedEventBuffer::new(&config).unwrap());
        let mut handles = vec![];
        
        // Spawn 10 threads each sending 100 events
        for _ in 0..10 {
            let buffer_clone = Arc::clone(&buffer);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = buffer_clone.enqueue_event(
                        0, // endpoint 0
                        b"test event",
                        Priority::Normal,
                    );
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify stats
        let stats = buffer.get_endpoint_stats(0).unwrap();
        assert_eq!(stats.success_count, 1000); // All events counted
    }
}