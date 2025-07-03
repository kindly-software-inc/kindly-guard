//! Enhanced Event Buffer Implementation
//! Uses bit-packed atomic state machine for maximum performance

use crate::event_processor::{EndpointStats, Priority};
use crate::traits::{CircuitState, EventBufferTrait};
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Bit-packed atomic state machine for event processing
/// All state fits in a single 64-bit atomic for cache efficiency
pub struct AtomicBitPackedEventBuffer {
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
const POSITION_SHIFT: u32 = 48;
const COUNT_SHIFT: u32 = 32;
const TOKENS_SHIFT: u32 = 16;
const FLAGS_SHIFT: u32 = 8;

const POSITION_MASK: u64 = 0xFFFF_0000_0000_0000;
const COUNT_MASK: u64 = 0x0000_FFFF_0000_0000;
const TOKENS_MASK: u64 = 0x0000_0000_FFFF_0000;
const FLAGS_MASK: u64 = 0x0000_0000_0000_FF00;
const VERSION_MASK: u64 = 0x0000_0000_0000_00FF;

// Flag bits
const FLAG_CIRCUIT_OPEN: u8 = 0b0000_0001;
const FLAG_CIRCUIT_HALF: u8 = 0b0000_0010;
const FLAG_THROTTLED: u8 = 0b0000_0100;
const FLAG_MONITORED: u8 = 0b0000_1000;

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
    pub fn new(config: &crate::event_processor::EventProcessorConfig) -> Result<Self> {
        let max_endpoints = config.max_endpoints;
        let buffer_size_bytes = config.buffer_size_mb * 1024 * 1024;
        
        // Pre-allocate endpoint states
        let mut endpoint_states = Vec::with_capacity(max_endpoints as usize);
        for _ in 0..max_endpoints {
            // Initialize with 100 tokens available
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
    
    /// Update endpoint state atomically
    fn update_endpoint_state(
        &self,
        endpoint_id: u32,
        increment_success: bool,
        increment_failure: bool,
        consume_token: bool,
    ) -> Result<()> {
        if endpoint_id >= self.max_endpoints {
            anyhow::bail!("Invalid endpoint ID: {}", endpoint_id);
        }
        
        let state_atomic = &self.endpoint_states[endpoint_id as usize];
        let mut current = state_atomic.load(Ordering::Acquire);
        
        loop {
            // Extract current values
            let mut success_count = ((current & COUNT_MASK) >> COUNT_SHIFT) as u16;
            let mut failure_count = ((current & POSITION_MASK) >> POSITION_SHIFT) as u16;
            let mut tokens = ((current & TOKENS_MASK) >> TOKENS_SHIFT) as u16;
            let flags = ((current & FLAGS_MASK) >> FLAGS_SHIFT) as u8;
            let version = (current & VERSION_MASK) as u8;
            
            // Update counts
            if increment_success {
                success_count = success_count.saturating_add(1);
            }
            if increment_failure {
                failure_count = failure_count.saturating_add(1);
                
                // Open circuit if too many failures
                if failure_count > 5 {
                    // Set circuit open flag
                    let new_flags = flags | FLAG_CIRCUIT_OPEN;
                    let new_state = ((failure_count as u64) << POSITION_SHIFT)
                        | ((success_count as u64) << COUNT_SHIFT)
                        | ((tokens as u64) << TOKENS_SHIFT)
                        | ((new_flags as u64) << FLAGS_SHIFT)
                        | (version.wrapping_add(1) as u64);
                    
                    state_atomic.store(new_state, Ordering::Release);
                    return Ok(());
                }
            }
            if consume_token && tokens > 0 {
                tokens -= 1;
            }
            
            // Pack new state
            let new_state = ((failure_count as u64) << POSITION_SHIFT)
                | ((success_count as u64) << COUNT_SHIFT)
                | ((tokens as u64) << TOKENS_SHIFT)
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
        // Update endpoint state
        self.update_endpoint_state(endpoint_id, true, false, true)?;
        
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
        
        // Extract values
        let failure_count = ((state & POSITION_MASK) >> POSITION_SHIFT) as u64;
        let success_count = ((state & COUNT_MASK) >> COUNT_SHIFT) as u64;
        let available_tokens = ((state & TOKENS_MASK) >> TOKENS_SHIFT) as u32;
        let flags = ((state & FLAGS_MASK) >> FLAGS_SHIFT) as u8;
        
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bit_packing() {
        let state: u64 = ((5u64) << POSITION_SHIFT)  // failure_count = 5
            | ((100u64) << COUNT_SHIFT)              // success_count = 100
            | ((50u64) << TOKENS_SHIFT)              // tokens = 50
            | ((FLAG_CIRCUIT_OPEN as u64) << FLAGS_SHIFT)  // circuit open
            | 42u64;                                  // version = 42
        
        // Extract values
        let failure_count = ((state & POSITION_MASK) >> POSITION_SHIFT) as u16;
        let success_count = ((state & COUNT_MASK) >> COUNT_SHIFT) as u16;
        let tokens = ((state & TOKENS_MASK) >> TOKENS_SHIFT) as u16;
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
        
        let config = crate::event_processor::EventProcessorConfig {
            enabled: true,
            buffer_size_mb: 10,
            max_endpoints: 100,
            ..Default::default()
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