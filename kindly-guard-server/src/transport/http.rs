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
//! HTTP transport implementation

use anyhow::Result;
use async_trait::async_trait;
use axum::{extract::State, routing::post, Json, Router};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info};

use super::{
    ConnectionInfo, ConnectionStats, Transport, TransportConnection, TransportMessage,
    TransportStats, TransportType,
};

use super::Deserialize;
/// HTTP transport configuration
use super::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Bind address
    pub bind_addr: String,
    /// Enable TLS
    pub tls: bool,
    /// TLS certificate path
    pub cert_path: Option<String>,
    /// TLS key path
    pub key_path: Option<String>,
    /// Maximum request body size
    pub max_body_size: usize,
    /// Request timeout (ms)
    pub request_timeout_ms: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".to_string(),
            tls: false,
            cert_path: None,
            key_path: None,
            max_body_size: 10 * 1024 * 1024, // 10MB
            request_timeout_ms: 30000,
        }
    }
}

/// HTTP transport for REST-style communication
pub struct HttpTransport {
    config: HttpConfig,
    running: AtomicBool,
    stats: Arc<Mutex<TransportStats>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl HttpTransport {
    /// Create new HTTP transport
    pub fn new(config: serde_json::Value) -> Result<Self> {
        let config: HttpConfig = serde_json::from_value(config)?;

        Ok(Self {
            config,
            running: AtomicBool::new(false),
            stats: Arc::new(Mutex::new(TransportStats::default())),
            shutdown_tx: None,
        })
    }

    /// Start HTTP server
    async fn start_server(&mut self) -> Result<mpsc::Sender<()>> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        let addr: SocketAddr = self.config.bind_addr.parse()?;
        let stats = self.stats.clone();

        // Create router with basic endpoint
        let app = Router::new()
            .route("/rpc", post(handle_rpc))
            .layer(
                ServiceBuilder::new()
                    .layer(CorsLayer::permissive())
                    .into_inner(),
            )
            .with_state(stats);

        // Start server
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        info!("HTTP server listening on {}", addr);

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.recv().await;
                    info!("HTTP server shutting down");
                })
                .await
                .map_err(|e| error!("Server error: {}", e))
                .ok();
        });

        Ok(shutdown_tx)
    }
}

#[async_trait]
impl Transport for HttpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Http
    }

    async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Transport already running"));
        }

        let shutdown_tx = self.start_server().await?;
        self.shutdown_tx = Some(shutdown_tx);
        self.running.store(true, Ordering::Relaxed);

        info!("Started HTTP transport on {}", self.config.bind_addr);
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }

        self.running.store(false, Ordering::Relaxed);
        info!("Stopped HTTP transport");
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn TransportConnection>> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Transport not running"));
        }

        // In real implementation, this would accept HTTP connections
        // For now, return a stub connection
        let mut stats = self.stats.lock().await;
        stats.connections_accepted += 1;
        stats.active_connections += 1;
        drop(stats);

        Ok(Box::new(HttpConnection::new(
            "127.0.0.1:12345".to_string(),
            self.stats.clone(),
        )))
    }

    async fn connect(&mut self, address: &str) -> Result<Box<dyn TransportConnection>> {
        // Create HTTP client connection
        Ok(Box::new(HttpConnection::new(
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
            "max_body_size" => {
                if let Some(size) = value.as_u64() {
                    self.config.max_body_size = size as usize;
                }
            }
            "request_timeout_ms" => {
                if let Some(timeout) = value.as_u64() {
                    self.config.request_timeout_ms = timeout;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// HTTP connection implementation
pub struct HttpConnection {
    info: ConnectionInfo,
    remote_addr: String,
    connected: AtomicBool,
    stats: Arc<Mutex<ConnectionStats>>,
    transport_stats: Arc<Mutex<TransportStats>>,
    message_queue: Arc<Mutex<mpsc::UnboundedReceiver<TransportMessage>>>,
    message_tx: mpsc::UnboundedSender<TransportMessage>,
}

impl HttpConnection {
    fn new(remote_addr: String, transport_stats: Arc<Mutex<TransportStats>>) -> Self {
        let (message_tx, message_rx) = mpsc::unbounded_channel();

        let info = ConnectionInfo {
            id: uuid::Uuid::new_v4().to_string(),
            transport_type: TransportType::Http,
            client_id: None,
            remote_addr: Some(remote_addr.clone()),
            connected_at: chrono::Utc::now(),
            security_info: None, // Would be populated based on TLS info
        };

        Self {
            info,
            remote_addr,
            connected: AtomicBool::new(true),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
            transport_stats,
            message_queue: Arc::new(Mutex::new(message_rx)),
            message_tx,
        }
    }
}

#[async_trait]
impl TransportConnection for HttpConnection {
    fn connection_info(&self) -> &ConnectionInfo {
        &self.info
    }

    async fn send(&mut self, message: TransportMessage) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection closed"));
        }

        // In real implementation, send HTTP request/response
        debug!("HTTP send to {}: {}", self.remote_addr, message.id);

        let mut stats = self.stats.lock().await;
        stats.messages_sent += 1;
        stats.bytes_sent += serde_json::to_vec(&message.payload)?.len() as u64;
        drop(stats);

        let mut transport_stats = self.transport_stats.lock().await;
        transport_stats.messages_sent += 1;
        drop(transport_stats);

        Ok(())
    }

    async fn receive(&mut self) -> Result<Option<TransportMessage>> {
        if !self.connected.load(Ordering::Relaxed) {
            return Ok(None);
        }

        // Check message queue
        let mut queue = self.message_queue.lock().await;
        match queue.recv().await {
            Some(message) => {
                let mut stats = self.stats.lock().await;
                stats.messages_received += 1;
                drop(stats);

                let mut transport_stats = self.transport_stats.lock().await;
                transport_stats.messages_received += 1;
                drop(transport_stats);

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

        info!("Closed HTTP connection to {}", self.remote_addr);
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

/// HTTP RPC handler
async fn handle_rpc(
    State(stats): State<Arc<Mutex<TransportStats>>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // Update stats
    let mut s = stats.lock().await;
    s.messages_received += 1;

    // Echo back for now (would process RPC in real impl)
    Ok(Json(serde_json::json!({
        "jsonrpc": "2.0",
        "result": payload,
        "id": payload.get("id").cloned().unwrap_or(serde_json::Value::Null)
    })))
}

// Note: Additional features to implement:
// 1. Proper request/response handling
// 2. TLS support with rustls or native-tls
// 3. Connection pooling for client mode
// 4. Proper error handling and retries
// 5. Request routing and middleware support
