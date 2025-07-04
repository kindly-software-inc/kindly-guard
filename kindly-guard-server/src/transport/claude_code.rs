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
//! Claude Code integration transport
//!
//! This module provides a specialized WebSocket transport for Claude Code integration,
//! featuring real-time shield status notifications with optional performance enhancements.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::protocol::claude_code::{
    create_status_notification, threat_to_severity, ClaudeCodeError, ClaudeCodeErrorCode,
    LastThreatInfo, PerformanceMetrics, ShieldControlAction, ShieldControlRequest,
    ShieldControlResponse, ShieldInfoParams, ShieldInfoResponse, ShieldState, ShieldStatistics,
    ShieldStatusNotification, ShieldStatusParams, ThreatPattern, ThreatSeverity,
};
use crate::scanner::{SecurityScanner, Threat};
use crate::shield::Shield;
use crate::traits::SecurityEvent;

use super::{
    ConnectionInfo, ConnectionStats, Transport, TransportConnection, TransportMessage,
    TransportStats, TransportType,
};

/// Claude Code transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeCodeConfig {
    /// Port to bind to (default: 9955)
    pub port: u16,
    /// Bind address (default: 127.0.0.1)
    pub bind_addr: String,
    /// Enable enhanced mode with binary protocol
    pub enhanced_mode: bool,
    /// Maximum batch delay in milliseconds (default: 50)
    pub batch_delay_ms: u64,
    /// Enable shared memory optimization
    pub shared_memory: bool,
    /// Maximum connections allowed
    pub max_connections: usize,
    /// Authentication token (from environment variable)
    pub auth_token_env: Option<String>,
    /// Notification settings
    pub notifications: NotificationConfig,
}

impl Default for ClaudeCodeConfig {
    fn default() -> Self {
        Self {
            port: 9955,
            bind_addr: "127.0.0.1".to_string(),
            enhanced_mode: false,
            batch_delay_ms: 50,
            shared_memory: false,
            max_connections: 10,
            auth_token_env: Some("CLAUDE_CODE_TOKEN".to_string()),
            notifications: NotificationConfig::default(),
        }
    }
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Send threat alerts
    pub threat_alerts: bool,
    /// Include performance metrics
    pub performance_metrics: bool,
    /// Send detailed threat information
    pub detailed_threats: bool,
    /// Minimum interval between status updates (ms)
    pub min_interval_ms: u64,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            threat_alerts: true,
            performance_metrics: true,
            detailed_threats: false,
            min_interval_ms: 100, // 10 updates per second max
        }
    }
}

/// Event processor trait for performance optimization
#[async_trait]
pub trait EventProcessor: Send + Sync {
    /// Process a batch of security events
    async fn process_batch(&self, events: &[SecurityEvent]) -> Result<ShieldStatusParams>;
    
    /// Check if binary protocol is supported
    fn supports_binary(&self) -> bool;
    
    /// Check if shared memory is supported
    fn supports_shared_memory(&self) -> bool;
    
    /// Get current statistics atomically
    fn get_stats(&self) -> ShieldStatistics;
}

/// Standard event processor implementation
pub struct StandardEventProcessor {
    shield: Arc<Shield>,
    scanner: Arc<SecurityScanner>,
    stats: Arc<RwLock<ProcessorStats>>,
}

#[derive(Default)]
struct ProcessorStats {
    threats_blocked: u64,
    total_scans: u64,
    total_scan_time_us: u64,
    threats_by_type: std::collections::HashMap<String, u64>,
}

impl StandardEventProcessor {
    pub fn new(shield: Arc<Shield>, scanner: Arc<SecurityScanner>) -> Self {
        Self {
            shield,
            scanner,
            stats: Arc::new(RwLock::new(ProcessorStats::default())),
        }
    }
}

#[async_trait]
impl EventProcessor for StandardEventProcessor {
    async fn process_batch(&self, events: &[SecurityEvent]) -> Result<ShieldStatusParams> {
        let start = std::time::Instant::now();
        let mut stats = self.stats.write().await;
        
        for event in events {
            match event {
                SecurityEvent::ThreatDetected { threat, .. } => {
                    stats.threats_blocked += 1;
                    let threat_type = format!("{:?}", threat.threat_type);
                    *stats.threats_by_type.entry(threat_type).or_insert(0) += 1;
                }
                SecurityEvent::ScanCompleted { duration_us, .. } => {
                    stats.total_scans += 1;
                    stats.total_scan_time_us += duration_us;
                }
                _ => {}
            }
        }
        
        let scan_time_us = start.elapsed().as_micros() as u64;
        
        // Calculate threat rate (per minute)
        let threat_rate = if stats.total_scans > 0 {
            (stats.threats_blocked as f64 / stats.total_scans as f64) * 600.0
        } else {
            0.0
        };
        
        // Get shield status
        let shield_stats = self.shield.get_stats();
        
        Ok(ShieldStatusParams {
            active: self.shield.is_active(),
            enhanced: false, // Standard mode
            threats: stats.threats_blocked,
            threat_rate,
            last_threat: None, // TODO: Track last threat
            performance: PerformanceMetrics {
                scan_time_us,
                queue_depth: 0, // TODO: Get from scanner
                memory_mb: 0.0, // TODO: Calculate memory usage
            },
        })
    }
    
    fn supports_binary(&self) -> bool {
        false
    }
    
    fn supports_shared_memory(&self) -> bool {
        false
    }
    
    fn get_stats(&self) -> ShieldStatistics {
        let stats = self.stats.blocking_read();
        let avg_scan_time = if stats.total_scans > 0 {
            stats.total_scan_time_us / stats.total_scans
        } else {
            0
        };
        
        ShieldStatistics {
            threats_blocked: stats.threats_blocked,
            threats_by_type: stats.threats_by_type.clone(),
            total_scans: stats.total_scans,
            avg_scan_time_us: avg_scan_time,
            uptime_seconds: 0, // TODO: Track uptime
            memory_usage_mb: 0.0, // TODO: Calculate
        }
    }
}

/// Enhanced event processor with lock-free operations
#[cfg(feature = "enhanced")]
pub struct AtomicEventProcessor {
    shield: Arc<Shield>,
    scanner: Arc<SecurityScanner>,
    // Atomic statistics for lock-free updates
    threats_blocked: AtomicU64,
    total_scans: AtomicU64,
    total_scan_time_us: AtomicU64,
    // Proprietary AtomicEventBuffer would be used here
    event_buffer: Arc<dyn crate::enhanced_impl::AtomicEventBuffer>,
}

/// Factory function for creating event processors
pub fn create_event_processor(
    config: &ClaudeCodeConfig,
    shield: Arc<Shield>,
    scanner: Arc<SecurityScanner>,
) -> Arc<dyn EventProcessor> {
    if config.enhanced_mode {
        #[cfg(feature = "enhanced")]
        {
            info!("Creating enhanced Claude Code event processor");
            return Arc::new(AtomicEventProcessor::new(shield, scanner));
        }
        
        warn!("Enhanced mode requested but not available, using standard processor");
    }
    
    Arc::new(StandardEventProcessor::new(shield, scanner))
}

/// Claude Code WebSocket transport
pub struct ClaudeCodeTransport {
    config: ClaudeCodeConfig,
    shield: Arc<Shield>,
    scanner: Arc<SecurityScanner>,
    event_processor: Arc<dyn EventProcessor>,
    running: AtomicBool,
    stats: Arc<Mutex<TransportStats>>,
    connections: Arc<RwLock<Vec<Arc<ClaudeCodeConnection>>>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ClaudeCodeTransport {
    /// Create new Claude Code transport
    pub fn new(
        config: ClaudeCodeConfig,
        shield: Arc<Shield>,
        scanner: Arc<SecurityScanner>,
    ) -> Result<Self> {
        let event_processor = create_event_processor(&config, shield.clone(), scanner.clone());
        
        Ok(Self {
            config,
            shield,
            scanner,
            event_processor,
            running: AtomicBool::new(false),
            stats: Arc::new(Mutex::new(TransportStats::default())),
            connections: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx: None,
        })
    }
    
    /// Start the notification loop
    async fn start_notification_loop(&self) -> Result<()> {
        let connections = self.connections.clone();
        let event_processor = self.event_processor.clone();
        let config = self.config.clone();
        let mut interval = interval(Duration::from_millis(config.batch_delay_ms));
        
        tokio::spawn(async move {
            let mut event_batch = Vec::new();
            
            loop {
                interval.tick().await;
                
                // Collect events (in real implementation, from a queue)
                // For now, generate status update
                
                if let Ok(status) = event_processor.process_batch(&event_batch).await {
                    let notification = create_status_notification(status);
                    
                    // Send to all connected clients
                    let conns = connections.read().await;
                    for conn in conns.iter() {
                        if conn.is_connected() {
                            let msg = TransportMessage {
                                id: uuid::Uuid::new_v4().to_string(),
                                payload: serde_json::to_value(&notification).unwrap(),
                                metadata: Default::default(),
                            };
                            
                            if let Err(e) = conn.send_notification(msg).await {
                                warn!("Failed to send notification: {}", e);
                            }
                        }
                    }
                }
                
                event_batch.clear();
            }
        });
        
        Ok(())
    }
}

#[async_trait]
impl Transport for ClaudeCodeTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Custom(9955) // Use port as custom identifier
    }
    
    async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Transport already running"));
        }
        
        // Start WebSocket server
        let addr = format!("{}:{}", self.config.bind_addr, self.config.port);
        info!("Starting Claude Code transport on {}", addr);
        
        // Start notification loop
        self.start_notification_loop().await?;
        
        self.running.store(true, Ordering::Relaxed);
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Relaxed);
        
        // Close all connections
        let mut connections = self.connections.write().await;
        for conn in connections.iter_mut() {
            let _ = conn.close().await;
        }
        connections.clear();
        
        info!("Stopped Claude Code transport");
        Ok(())
    }
    
    async fn accept(&mut self) -> Result<Box<dyn TransportConnection>> {
        // In real implementation, accept WebSocket connections
        Err(anyhow::anyhow!("Not implemented yet"))
    }
    
    async fn connect(&mut self, _address: &str) -> Result<Box<dyn TransportConnection>> {
        // Claude Code transport is server-only
        Err(anyhow::anyhow!("Claude Code transport is server-only"))
    }
    
    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    
    fn get_stats(&self) -> TransportStats {
        self.stats.blocking_lock().clone()
    }
    
    async fn set_option(&mut self, key: &str, value: serde_json::Value) -> Result<()> {
        match key {
            "enhanced_mode" => {
                if let Some(enabled) = value.as_bool() {
                    self.config.enhanced_mode = enabled;
                    // Recreate event processor if mode changed
                    self.event_processor = create_event_processor(
                        &self.config,
                        self.shield.clone(),
                        self.scanner.clone(),
                    );
                }
            }
            "batch_delay_ms" => {
                if let Some(delay) = value.as_u64() {
                    self.config.batch_delay_ms = delay.min(1000); // Max 1 second
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Claude Code connection implementation
struct ClaudeCodeConnection {
    info: ConnectionInfo,
    connected: AtomicBool,
    stats: Arc<Mutex<ConnectionStats>>,
    outgoing_tx: mpsc::UnboundedSender<TransportMessage>,
}

impl ClaudeCodeConnection {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    
    async fn send_notification(&self, message: TransportMessage) -> Result<()> {
        self.outgoing_tx.send(message)?;
        Ok(())
    }
    
    async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
}

#[async_trait]
impl TransportConnection for ClaudeCodeConnection {
    fn connection_info(&self) -> &ConnectionInfo {
        &self.info
    }
    
    async fn send(&mut self, message: TransportMessage) -> Result<()> {
        self.outgoing_tx.send(message)?;
        let mut stats = self.stats.lock().await;
        stats.messages_sent += 1;
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<TransportMessage>> {
        // Implement message receiving
        Ok(None)
    }
    
    async fn close(&mut self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    
    fn get_stats(&self) -> ConnectionStats {
        self.stats.blocking_lock().clone()
    }
    
    async fn set_option(&mut self, _key: &str, _value: serde_json::Value) -> Result<()> {
        Ok(())
    }
}