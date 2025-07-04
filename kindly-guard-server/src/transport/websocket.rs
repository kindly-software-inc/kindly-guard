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
//! WebSocket transport implementation

use anyhow::Result;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info};

use super::{
    ConnectionInfo, ConnectionStats, Deserialize, Serialize, Transport, TransportConnection,
    TransportMessage, TransportStats, TransportType,
};

/// WebSocket transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Bind address for server mode
    pub bind_addr: Option<String>,
    /// Enable TLS (WSS)
    pub tls: bool,
    /// TLS certificate path
    pub cert_path: Option<String>,
    /// TLS key path
    pub key_path: Option<String>,
    /// Maximum frame size
    pub max_frame_size: usize,
    /// Ping interval (ms)
    pub ping_interval_ms: u64,
    /// Ping timeout (ms)
    pub ping_timeout_ms: u64,
    /// Enable compression
    pub compression: bool,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            bind_addr: Some("127.0.0.1:8081".to_string()),
            tls: false,
            cert_path: None,
            key_path: None,
            max_frame_size: 10 * 1024 * 1024, // 10MB
            ping_interval_ms: 30000,
            ping_timeout_ms: 10000,
            compression: true,
        }
    }
}

/// WebSocket transport for bidirectional streaming
pub struct WebSocketTransport {
    config: WebSocketConfig,
    running: AtomicBool,
    stats: Arc<Mutex<TransportStats>>,
    connection_queue: Arc<Mutex<mpsc::UnboundedReceiver<WebSocketConnection>>>,
    connection_tx: mpsc::UnboundedSender<WebSocketConnection>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl WebSocketTransport {
    /// Create new WebSocket transport
    pub fn new(config: serde_json::Value) -> Result<Self> {
        let config: WebSocketConfig = serde_json::from_value(config)?;
        let (connection_tx, connection_rx) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            running: AtomicBool::new(false),
            stats: Arc::new(Mutex::new(TransportStats::default())),
            connection_queue: Arc::new(Mutex::new(connection_rx)),
            connection_tx,
            shutdown_tx: None,
        })
    }

    /// Start WebSocket server (placeholder)
    async fn start_server(&mut self) -> Result<mpsc::Sender<()>> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

        if let Some(bind_addr) = &self.config.bind_addr {
            let addr = bind_addr.clone();
            let _stats = self.stats.clone();
            let _connection_tx = self.connection_tx.clone();

            tokio::spawn(async move {
                info!("WebSocket server listening on {}", addr);

                // In real implementation, this would:
                // 1. Create WebSocket server using tokio-tungstenite
                // 2. Accept connections and upgrade HTTP to WebSocket
                // 3. Send connections through the channel

                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("WebSocket server shutting down");
                    }
                }
            });
        }

        Ok(shutdown_tx)
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Transport already running"));
        }

        let shutdown_tx = self.start_server().await?;
        self.shutdown_tx = Some(shutdown_tx);
        self.running.store(true, Ordering::Relaxed);

        info!("Started WebSocket transport");
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        self.running.store(false, Ordering::Relaxed);
        info!("Stopped WebSocket transport");
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn TransportConnection>> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Transport not running"));
        }

        // Wait for incoming connection
        let mut queue = self.connection_queue.lock().await;
        match queue.recv().await {
            Some(conn) => {
                let mut stats = self.stats.lock().await;
                stats.connections_accepted += 1;
                stats.active_connections += 1;
                drop(stats);

                Ok(Box::new(conn))
            }
            None => Err(anyhow::anyhow!("Connection queue closed")),
        }
    }

    async fn connect(&mut self, address: &str) -> Result<Box<dyn TransportConnection>> {
        // Create WebSocket client connection
        let url = if self.config.tls {
            format!("wss://{address}")
        } else {
            format!("ws://{address}")
        };

        info!("Connecting to WebSocket server at {}", url);

        // In real implementation, this would use tokio-tungstenite to connect
        Ok(Box::new(WebSocketConnection::new(
            address.to_string(),
            self.stats.clone(),
        )))
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn get_stats(&self) -> TransportStats {
        if let Ok(stats) = self.stats.try_lock() {
            stats.clone()
        } else {
            TransportStats::default()
        }
    }

    async fn set_option(&mut self, key: &str, value: serde_json::Value) -> Result<()> {
        match key {
            "compression" => {
                if let Some(enabled) = value.as_bool() {
                    self.config.compression = enabled;
                }
            }
            "ping_interval_ms" => {
                if let Some(interval) = value.as_u64() {
                    self.config.ping_interval_ms = interval;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// WebSocket connection implementation
pub struct WebSocketConnection {
    info: ConnectionInfo,
    remote_addr: String,
    connected: AtomicBool,
    stats: Arc<Mutex<ConnectionStats>>,
    transport_stats: Arc<Mutex<TransportStats>>,
    incoming_messages: Arc<Mutex<mpsc::UnboundedReceiver<TransportMessage>>>,
    incoming_tx: mpsc::UnboundedSender<TransportMessage>,
    outgoing_messages: Arc<Mutex<mpsc::UnboundedSender<TransportMessage>>>,
}

impl WebSocketConnection {
    fn new(remote_addr: String, transport_stats: Arc<Mutex<TransportStats>>) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel::<TransportMessage>();

        let info = ConnectionInfo {
            id: uuid::Uuid::new_v4().to_string(),
            transport_type: TransportType::WebSocket,
            client_id: None,
            remote_addr: Some(remote_addr.clone()),
            connected_at: chrono::Utc::now(),
            security_info: None, // Would be populated based on TLS info
        };

        // Simulate WebSocket message handling
        let connected = Arc::new(AtomicBool::new(true));
        let connected_clone = connected;
        let addr = remote_addr.clone();

        tokio::spawn(async move {
            while connected_clone.load(Ordering::Relaxed) {
                tokio::select! {
                    Some(msg) = outgoing_rx.recv() => {
                        debug!("WebSocket {} sending: {}", addr, msg.id);
                        // In real implementation, send over WebSocket
                    }
                    () = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                        // Heartbeat or other periodic tasks
                    }
                }
            }
        });

        Self {
            info,
            remote_addr,
            connected: AtomicBool::new(true),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
            transport_stats,
            incoming_messages: Arc::new(Mutex::new(incoming_rx)),
            incoming_tx,
            outgoing_messages: Arc::new(Mutex::new(outgoing_tx)),
        }
    }

    /// Simulate receiving a message (for testing)
    #[allow(dead_code)]
    pub fn inject_message(&self, message: TransportMessage) {
        let _ = self.incoming_tx.send(message);
    }
}

#[async_trait]
impl TransportConnection for WebSocketConnection {
    fn connection_info(&self) -> &ConnectionInfo {
        &self.info
    }

    async fn send(&mut self, message: TransportMessage) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection closed"));
        }

        let outgoing = self.outgoing_messages.lock().await;
        outgoing.send(message.clone())?;
        drop(outgoing);

        let bytes_sent = serde_json::to_vec(&message.payload)?.len() as u64;

        let mut stats = self.stats.lock().await;
        stats.messages_sent += 1;
        stats.bytes_sent += bytes_sent;
        drop(stats);

        let mut transport_stats = self.transport_stats.lock().await;
        transport_stats.messages_sent += 1;
        transport_stats.bytes_sent += bytes_sent;
        drop(transport_stats);

        debug!("WebSocket sent message: {}", message.id);
        Ok(())
    }

    async fn receive(&mut self) -> Result<Option<TransportMessage>> {
        if !self.connected.load(Ordering::Relaxed) {
            return Ok(None);
        }

        let mut incoming = self.incoming_messages.lock().await;
        match incoming.recv().await {
            Some(message) => {
                let bytes_received = serde_json::to_vec(&message.payload)?.len() as u64;

                let mut stats = self.stats.lock().await;
                stats.messages_received += 1;
                stats.bytes_received += bytes_received;
                drop(stats);

                let mut transport_stats = self.transport_stats.lock().await;
                transport_stats.messages_received += 1;
                transport_stats.bytes_received += bytes_received;
                drop(transport_stats);

                debug!("WebSocket received message: {}", message.id);
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    async fn close(&mut self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);

        let mut transport_stats = self.transport_stats.lock().await;
        transport_stats.active_connections = transport_stats.active_connections.saturating_sub(1);
        drop(transport_stats);

        info!("Closed WebSocket connection to {}", self.remote_addr);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    fn get_stats(&self) -> ConnectionStats {
        if let Ok(stats) = self.stats.try_lock() {
            stats.clone()
        } else {
            ConnectionStats::default()
        }
    }

    async fn set_option(&mut self, key: &str, value: serde_json::Value) -> Result<()> {
        if key == "client_id" {
            if let Some(id) = value.as_str() {
                self.info.client_id = Some(id.to_string());
            }
        }
        Ok(())
    }
}

// Note: Full WebSocket implementation would require:
// 1. Integration with tokio-tungstenite
// 2. Proper frame handling and fragmentation
// 3. Ping/pong heartbeat mechanism
// 4. Compression support (permessage-deflate)
// 5. Proper close handshake
// 6. Automatic reconnection for client mode
// 7. Subprotocol negotiation
