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
use std::{
    fs::{self, OpenOptions},
    io::{self, Error, ErrorKind},
    mem::{self, size_of},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crossbeam::utils::CachePadded;
use memmap2::{MmapMut, MmapOptions};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::{
    core::{Severity, Threat, ThreatType},
    errors::ShieldError,
    ipc::platform::{PlatformShm, PlatformOptimizations},
};

/// Shared memory IPC implementation for ultra-low latency communication
/// Provides <100μs latency for local threat event notifications
pub struct SharedMemoryIpc {
    /// Memory-mapped file for the ring buffer
    mmap: MmapMut,
    /// Path to the shared memory file
    path: PathBuf,
    /// Configuration for the shared memory
    config: ShmConfig,
    /// Lock file path (for cleanup on drop)
    lock_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ShmConfig {
    /// Size of the ring buffer in bytes
    pub buffer_size: usize,
    /// Directory for shared memory files
    pub shm_dir: PathBuf,
    /// Maximum number of events in the ring buffer
    pub max_events: usize,
    /// Enable checksums for data integrity
    pub enable_checksums: bool,
}

impl Default for ShmConfig {
    fn default() -> Self {
        Self {
            buffer_size: PlatformShm::get_optimal_buffer_size(),
            shm_dir: PlatformShm::get_shm_dir(),
            max_events: 1000,
            enable_checksums: true,
        }
    }
}

/// Header structure for the shared memory region
#[repr(C)]
struct ShmHeader {
    /// Magic number for validation
    magic: u32,
    /// Version of the shared memory format
    version: u32,
    /// Total size of the shared memory region
    total_size: u64,
    /// Ring buffer write position
    write_pos: CachePadded<AtomicUsize>,
    /// Ring buffer read position
    read_pos: CachePadded<AtomicUsize>,
    /// Number of events written
    events_written: CachePadded<AtomicU64>,
    /// Number of events read
    events_read: CachePadded<AtomicU64>,
    /// Last heartbeat timestamp
    last_heartbeat: CachePadded<AtomicU64>,
    /// Process ID of the writer
    writer_pid: u32,
    /// Reserved for future use
    _reserved: [u8; 64],
}

const SHM_MAGIC: u32 = 0x4B474D53; // "KGMS" in hex
const SHM_VERSION: u32 = 1;
const HEADER_SIZE: usize = size_of::<ShmHeader>();

/// Fixed-size threat event for zero-copy transfer
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThreatEvent {
    /// Timestamp in microseconds since epoch
    pub timestamp_us: u64,
    /// Type of threat (mapped to u32)
    pub threat_type: u32,
    /// Severity level (mapped to u8)
    pub severity: u8,
    /// Whether the threat was blocked
    pub blocked: u8,
    /// Source identifier (fixed size)
    pub source: [u8; 64],
    /// Details (fixed size)
    pub details: [u8; 256],
    /// Checksum for data integrity
    pub checksum: u32,
    /// Reserved for alignment
    _reserved: [u8; 2],
}

impl ThreatEvent {
    pub fn from_threat(threat: &Threat) -> Self {
        let mut event = Self {
            timestamp_us: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
            threat_type: threat_type_to_u32(&threat.threat_type),
            severity: severity_to_u8(&threat.severity),
            blocked: if threat.blocked { 1 } else { 0 },
            source: [0; 64],
            details: [0; 256],
            checksum: 0,
            _reserved: [0; 2],
        };

        // Copy source and details (truncate if needed)
        let source_bytes = threat.source.as_bytes();
        let source_len = source_bytes.len().min(64);
        event.source[..source_len].copy_from_slice(&source_bytes[..source_len]);

        let details_bytes = threat.details.as_bytes();
        let details_len = details_bytes.len().min(256);
        event.details[..details_len].copy_from_slice(&details_bytes[..details_len]);

        // Calculate checksum
        event.checksum = event.calculate_checksum();
        event
    }

    fn calculate_checksum(&self) -> u32 {
        // Simple checksum for data integrity
        let mut sum = 0u32;
        sum = sum.wrapping_add(self.timestamp_us as u32);
        sum = sum.wrapping_add(self.threat_type);
        sum = sum.wrapping_add(self.severity as u32);
        sum = sum.wrapping_add(self.blocked as u32);
        
        for byte in &self.source {
            sum = sum.wrapping_add(*byte as u32);
        }
        for byte in &self.details {
            sum = sum.wrapping_add(*byte as u32);
        }
        
        sum
    }

    pub fn verify_checksum(&self) -> bool {
        self.checksum == self.calculate_checksum()
    }

    pub fn to_threat(&self) -> Result<Threat, ShieldError> {
        if !self.verify_checksum() {
            return Err(ShieldError::Validation("Invalid checksum".into()));
        }

        let source = String::from_utf8_lossy(&self.source)
            .trim_end_matches('\0')
            .to_string();
        let details = String::from_utf8_lossy(&self.details)
            .trim_end_matches('\0')
            .to_string();

        Ok(Threat {
            id: format!("{}", self.timestamp_us),
            threat_type: u32_to_threat_type(self.threat_type),
            severity: u8_to_severity(self.severity),
            source,
            details,
            blocked: self.blocked != 0,
            timestamp: chrono::Utc::now(),
            context: None,
        })
    }
}

fn threat_type_to_u32(threat_type: &ThreatType) -> u32 {
    match threat_type {
        ThreatType::UnicodeInvisible => 1,
        ThreatType::UnicodeBiDi => 2,
        ThreatType::UnicodeHomoglyph => 3,
        ThreatType::InjectionAttempt => 4,
        ThreatType::PathTraversal => 5,
        ThreatType::SuspiciousPattern => 6,
        ThreatType::RateLimitViolation => 7,
        ThreatType::Unknown => 0,
    }
}

fn u32_to_threat_type(value: u32) -> ThreatType {
    match value {
        1 => ThreatType::UnicodeInvisible,
        2 => ThreatType::UnicodeBiDi,
        3 => ThreatType::UnicodeHomoglyph,
        4 => ThreatType::InjectionAttempt,
        5 => ThreatType::PathTraversal,
        6 => ThreatType::SuspiciousPattern,
        7 => ThreatType::RateLimitViolation,
        _ => ThreatType::Unknown,
    }
}

fn severity_to_u8(severity: &Severity) -> u8 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn u8_to_severity(value: u8) -> Severity {
    match value {
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        4 => Severity::Critical,
        _ => Severity::Medium,
    }
}

impl SharedMemoryIpc {
    /// Create a new shared memory IPC instance
    pub fn new(config: ShmConfig) -> Result<Self, ShieldError> {
        // Ensure shared memory directory exists
        fs::create_dir_all(&config.shm_dir)
            .map_err(|e| ShieldError::Io(format!("Failed to create shm directory: {}", e)))?;

        // Try to create lock file (ensures single writer)
        let lock_path = PlatformShm::create_lock_file(&config.shm_dir).ok();

        let path = config.shm_dir.join("kindly-guard.shm");
        
        // Create or open the shared memory file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|e| ShieldError::Io(format!("Failed to open shm file: {}", e)))?;

        // Set file size
        file.set_len(config.buffer_size as u64)
            .map_err(|e| ShieldError::Io(format!("Failed to set file size: {}", e)))?;

        // Set platform-specific permissions
        PlatformShm::set_shm_permissions(&path)?;

        // Memory map the file
        let mut mmap = unsafe {
            MmapOptions::new()
                .map_mut(&file)
                .map_err(|e| ShieldError::Io(format!("Failed to mmap file: {}", e)))?
        };

        // Apply platform-specific optimizations
        PlatformOptimizations::optimize_memory_region(
            mmap.as_mut_ptr(),
            config.buffer_size,
        )?;

        let mut shm = Self { 
            mmap, 
            path, 
            config,
            lock_path,
        };

        // Initialize header if needed
        shm.init_header()?;

        Ok(shm)
    }

    /// Initialize the shared memory header
    fn init_header(&mut self) -> Result<(), ShieldError> {
        let header = self.get_header_mut();
        
        // Check if already initialized
        if header.magic == SHM_MAGIC && header.version == SHM_VERSION {
            debug!("Shared memory already initialized");
            return Ok(());
        }

        info!("Initializing shared memory header");
        
        header.magic = SHM_MAGIC;
        header.version = SHM_VERSION;
        header.total_size = self.config.buffer_size as u64;
        header.write_pos.store(0, Ordering::SeqCst);
        header.read_pos.store(0, Ordering::SeqCst);
        header.events_written.store(0, Ordering::Relaxed);
        header.events_read.store(0, Ordering::Relaxed);
        header.last_heartbeat.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        header.writer_pid = std::process::id();

        Ok(())
    }

    /// Get a reference to the header
    fn get_header(&self) -> &ShmHeader {
        unsafe { &*(self.mmap.as_ptr() as *const ShmHeader) }
    }

    /// Get a mutable reference to the header
    fn get_header_mut(&mut self) -> &mut ShmHeader {
        unsafe { &mut *(self.mmap.as_mut_ptr() as *mut ShmHeader) }
    }

    /// Write a threat event to the ring buffer
    pub fn write_threat(&mut self, threat: &Threat) -> Result<(), ShieldError> {
        let event = ThreatEvent::from_threat(threat);
        let event_size = size_of::<ThreatEvent>();
        
        let header = self.get_header();
        let buffer_start = HEADER_SIZE;
        let buffer_size = self.config.buffer_size - HEADER_SIZE;
        
        // Get current write position
        let write_pos = header.write_pos.load(Ordering::Acquire);
        let next_write_pos = (write_pos + event_size) % buffer_size;
        
        // Check if buffer is full (would overwrite unread data)
        let read_pos = header.read_pos.load(Ordering::Acquire);
        if next_write_pos > read_pos && write_pos < read_pos {
            warn!("Shared memory buffer full, dropping event");
            return Err(ShieldError::Capacity("Buffer full".into()));
        }
        
        // Write the event
        let event_ptr = unsafe {
            self.mmap.as_mut_ptr().add(buffer_start + write_pos)
        };
        
        unsafe {
            std::ptr::write(event_ptr as *mut ThreatEvent, event);
        }
        
        // Update write position
        header.write_pos.store(next_write_pos, Ordering::Release);
        header.events_written.fetch_add(1, Ordering::Relaxed);
        
        // Update heartbeat
        header.last_heartbeat.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Ordering::Relaxed,
        );
        
        debug!("Wrote threat event at position {}", write_pos);
        Ok(())
    }

    /// Read a threat event from the ring buffer
    pub fn read_threat(&self) -> Result<Option<Threat>, ShieldError> {
        let header = self.get_header();
        let buffer_start = HEADER_SIZE;
        let buffer_size = self.config.buffer_size - HEADER_SIZE;
        
        // Get current positions
        let read_pos = header.read_pos.load(Ordering::Acquire);
        let write_pos = header.write_pos.load(Ordering::Acquire);
        
        // Check if buffer is empty
        if read_pos == write_pos {
            return Ok(None);
        }
        
        // Read the event
        let event_size = size_of::<ThreatEvent>();
        let event_ptr = unsafe {
            self.mmap.as_ptr().add(buffer_start + read_pos)
        };
        
        let event = unsafe {
            std::ptr::read(event_ptr as *const ThreatEvent)
        };
        
        // Update read position
        let next_read_pos = (read_pos + event_size) % buffer_size;
        header.read_pos.store(next_read_pos, Ordering::Release);
        header.events_read.fetch_add(1, Ordering::Relaxed);
        
        debug!("Read threat event from position {}", read_pos);
        
        // Convert to Threat
        event.to_threat().map(Some)
    }

    /// Get statistics about the shared memory usage
    pub fn get_stats(&self) -> ShmStats {
        let header = self.get_header();
        
        ShmStats {
            events_written: header.events_written.load(Ordering::Relaxed),
            events_read: header.events_read.load(Ordering::Relaxed),
            buffer_usage: self.calculate_buffer_usage(),
            last_heartbeat: header.last_heartbeat.load(Ordering::Relaxed),
            writer_pid: header.writer_pid,
        }
    }

    fn calculate_buffer_usage(&self) -> f32 {
        let header = self.get_header();
        let buffer_size = self.config.buffer_size - HEADER_SIZE;
        
        let read_pos = header.read_pos.load(Ordering::Relaxed);
        let write_pos = header.write_pos.load(Ordering::Relaxed);
        
        let used = if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            buffer_size - read_pos + write_pos
        };
        
        (used as f32 / buffer_size as f32) * 100.0
    }

    /// Check if the shared memory is healthy (writer is alive)
    pub fn is_healthy(&self) -> bool {
        let header = self.get_header();
        let last_heartbeat = header.last_heartbeat.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Consider unhealthy if no heartbeat for 30 seconds
        now - last_heartbeat < 30
    }

    /// Platform-specific check for shared memory availability
    pub fn is_available() -> bool {
        // Check if we can create a test shared memory file
        let test_path = std::env::temp_dir().join(".kindly-guard-shm-test");
        
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&test_path)
        {
            Ok(file) => {
                // Try to memory map it
                let result = file.set_len(4096).is_ok() && unsafe {
                    MmapOptions::new().map_mut(&file).is_ok()
                };
                
                // Clean up
                let _ = fs::remove_file(test_path);
                result
            }
            Err(_) => false,
        }
    }
}

impl Drop for SharedMemoryIpc {
    fn drop(&mut self) {
        // Clean up lock file if we created one
        if let Some(ref lock_path) = self.lock_path {
            PlatformShm::cleanup_lock_file(lock_path);
        }
        
        // Sync memory map before dropping
        if let Err(e) = self.mmap.flush() {
            error!("Failed to flush memory map: {}", e);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmStats {
    pub events_written: u64,
    pub events_read: u64,
    pub buffer_usage: f32,
    pub last_heartbeat: u64,
    pub writer_pid: u32,
}

/// Fallback trait for when shared memory is not available
pub trait IpcTransport: Send + Sync {
    fn write_threat(&mut self, threat: &Threat) -> Result<(), ShieldError>;
    fn read_threat(&self) -> Result<Option<Threat>, ShieldError>;
    fn get_stats(&self) -> ShmStats;
    fn is_healthy(&self) -> bool;
}

impl IpcTransport for SharedMemoryIpc {
    fn write_threat(&mut self, threat: &Threat) -> Result<(), ShieldError> {
        self.write_threat(threat)
    }

    fn read_threat(&self) -> Result<Option<Threat>, ShieldError> {
        self.read_threat()
    }

    fn get_stats(&self) -> ShmStats {
        self.get_stats()
    }

    fn is_healthy(&self) -> bool {
        self.is_healthy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_event_conversion() {
        let threat = Threat {
            id: "test-1".to_string(),
            threat_type: ThreatType::UnicodeInvisible,
            severity: Severity::High,
            source: "test-source".to_string(),
            details: "Test threat details".to_string(),
            blocked: true,
            timestamp: chrono::Utc::now(),
            context: None,
        };

        let event = ThreatEvent::from_threat(&threat);
        assert_eq!(event.threat_type, 1);
        assert_eq!(event.severity, 3);
        assert_eq!(event.blocked, 1);
        assert!(event.verify_checksum());

        let converted = event.to_threat().unwrap();
        assert_eq!(converted.threat_type, threat.threat_type);
        assert_eq!(converted.severity, threat.severity);
        assert_eq!(converted.blocked, threat.blocked);
    }

    #[test]
    fn test_shm_availability() {
        // This test checks if shared memory is available on the current platform
        let available = SharedMemoryIpc::is_available();
        println!("Shared memory available: {}", available);
    }
}