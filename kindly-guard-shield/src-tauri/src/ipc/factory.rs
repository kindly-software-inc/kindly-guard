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
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{info, warn};

use crate::{
    core::{ShieldCore, Threat},
    errors::ShieldError,
    ipc::shm::{IpcTransport, SharedMemoryIpc, ShmConfig, ShmStats},
    websocket::WebSocketServer,
};

/// Factory for creating the appropriate IPC transport
pub struct IpcFactory;

impl IpcFactory {
    /// Create an IPC transport, preferring shared memory if available
    pub fn create_transport(
        core: Arc<ShieldCore>,
        prefer_shm: bool,
    ) -> Result<Arc<dyn IpcTransport>, ShieldError> {
        if prefer_shm && SharedMemoryIpc::is_available() {
            info!("Using shared memory IPC for ultra-low latency");
            let config = ShmConfig::default();
            let shm = SharedMemoryIpc::new(config)?;
            Ok(Arc::new(shm))
        } else {
            if prefer_shm {
                warn!("Shared memory not available, falling back to WebSocket");
            } else {
                info!("Using WebSocket IPC as requested");
            }
            
            let ws_transport = WebSocketTransport::new(core);
            Ok(Arc::new(ws_transport))
        }
    }

    /// Create both transports for hybrid operation
    pub fn create_hybrid_transport(
        core: Arc<ShieldCore>,
    ) -> Result<HybridTransport, ShieldError> {
        let shm_transport = if SharedMemoryIpc::is_available() {
            info!("Shared memory available for local clients");
            Some(Arc::new(Mutex::new(SharedMemoryIpc::new(ShmConfig::default())?)))
        } else {
            warn!("Shared memory not available");
            None
        };

        let ws_transport = Arc::new(WebSocketTransport::new(core));

        Ok(HybridTransport {
            shm: shm_transport,
            websocket: ws_transport,
        })
    }
}

/// WebSocket-based IPC transport (fallback)
pub struct WebSocketTransport {
    core: Arc<ShieldCore>,
    stats: Mutex<WsStats>,
}

#[derive(Default)]
struct WsStats {
    events_written: u64,
    events_read: u64,
}

impl WebSocketTransport {
    pub fn new(core: Arc<ShieldCore>) -> Self {
        Self {
            core,
            stats: Mutex::new(WsStats::default()),
        }
    }
}

impl IpcTransport for WebSocketTransport {
    fn write_threat(&mut self, threat: &Threat) -> Result<(), ShieldError> {
        // In a real implementation, this would send via WebSocket
        // For now, just record to core
        self.core.record_threat(threat.clone())?;
        
        let mut stats = self.stats.lock();
        stats.events_written += 1;
        
        Ok(())
    }

    fn read_threat(&self) -> Result<Option<Threat>, ShieldError> {
        // WebSocket is push-based, so this would typically return None
        // unless we implement a queue
        Ok(None)
    }

    fn get_stats(&self) -> ShmStats {
        let stats = self.stats.lock();
        ShmStats {
            events_written: stats.events_written,
            events_read: stats.events_read,
            buffer_usage: 0.0,
            last_heartbeat: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            writer_pid: std::process::id(),
        }
    }

    fn is_healthy(&self) -> bool {
        true // WebSocket health would check connection status
    }
}

/// Hybrid transport that can use both shared memory and WebSocket
pub struct HybridTransport {
    shm: Option<Arc<Mutex<SharedMemoryIpc>>>,
    websocket: Arc<WebSocketTransport>,
}

impl HybridTransport {
    /// Write threat using the best available transport
    pub fn write_threat(&self, threat: &Threat) -> Result<(), ShieldError> {
        // Try shared memory first for local clients
        if let Some(shm) = &self.shm {
            match shm.lock().write_threat(threat) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!("Shared memory write failed: {}, falling back to WebSocket", e);
                }
            }
        }
        
        // Fall back to WebSocket
        // Note: WebSocketTransport doesn't need &mut self
        let mut ws = WebSocketTransport::new(self.websocket.core.clone());
        ws.write_threat(threat)
    }

    /// Get statistics from both transports
    pub fn get_combined_stats(&self) -> CombinedStats {
        let shm_stats = self.shm.as_ref().map(|shm| shm.lock().get_stats());
        let ws_stats = self.websocket.get_stats();
        
        CombinedStats {
            shm_stats,
            ws_stats,
        }
    }

    /// Check if shared memory is being used
    pub fn is_shm_active(&self) -> bool {
        self.shm.as_ref().map(|shm| shm.lock().is_healthy()).unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct CombinedStats {
    pub shm_stats: Option<ShmStats>,
    pub ws_stats: ShmStats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_factory() {
        let core = Arc::new(ShieldCore::new());
        
        // Test creating transport with SHM preference
        let transport = IpcFactory::create_transport(core.clone(), true);
        assert!(transport.is_ok());
        
        // Test creating transport without SHM preference
        let transport = IpcFactory::create_transport(core.clone(), false);
        assert!(transport.is_ok());
    }
}