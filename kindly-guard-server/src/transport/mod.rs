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
//! Transport layer abstraction for multiple communication protocols
//!
//! This module provides a trait-based architecture that allows `KindlyGuard`
//! to communicate over different transport mechanisms while maintaining
//! security and protocol compliance.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[cfg(feature = "enhanced")]
pub mod enhanced;
pub mod http;
pub mod proxy;
pub mod stdio;
pub mod websocket;

// Re-exports
pub use http::HttpTransport;
pub use proxy::ProxyTransport;
pub use stdio::StdioTransport;
pub use websocket::WebSocketTransport;

/// Transport message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportMessage {
    /// Message ID for correlation
    pub id: String,
    /// Message payload (typically JSON-RPC)
    pub payload: serde_json::Value,
    /// Optional metadata
    pub metadata: TransportMetadata,
}

/// Transport metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportMetadata {
    /// Client identifier
    pub client_id: Option<String>,
    /// Source address (for network transports)
    pub source_address: Option<String>,
    /// Transport-specific headers
    pub headers: std::collections::HashMap<String, String>,
    /// Timestamp
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,
}

/// Transport connection info
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Unique connection ID
    pub id: String,
    /// Transport type
    pub transport_type: TransportType,
    /// Client identifier
    pub client_id: Option<String>,
    /// Remote address (if applicable)
    pub remote_addr: Option<String>,
    /// Connection established time
    pub connected_at: chrono::DateTime<chrono::Utc>,
    /// TLS/encryption info
    pub security_info: Option<SecurityInfo>,
}

/// Security information for the connection
#[derive(Debug, Clone)]
pub struct SecurityInfo {
    /// Is connection encrypted
    pub encrypted: bool,
    /// TLS version (if applicable)
    pub tls_version: Option<String>,
    /// Cipher suite
    pub cipher_suite: Option<String>,
    /// Client certificate info
    pub client_cert: Option<CertificateInfo>,
}

/// Certificate information
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Subject DN
    pub subject: String,
    /// Issuer DN
    pub issuer: String,
    /// Serial number
    pub serial: String,
    /// Not valid after
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Transport types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Stdio,
    Http,
    WebSocket,
    Grpc,
    Custom(u32),
}

/// Transport trait for different communication mechanisms
#[async_trait]
pub trait Transport: Send + Sync {
    /// Get transport type
    fn transport_type(&self) -> TransportType;

    /// Start the transport
    async fn start(&mut self) -> Result<()>;

    /// Stop the transport
    async fn stop(&mut self) -> Result<()>;

    /// Accept new connections (for server transports)
    async fn accept(&mut self) -> Result<Box<dyn TransportConnection>>;

    /// Connect to a server (for client transports)
    async fn connect(&mut self, address: &str) -> Result<Box<dyn TransportConnection>>;

    /// Check if transport is running
    fn is_running(&self) -> bool;

    /// Get transport statistics
    fn get_stats(&self) -> TransportStats;

    /// Set transport options
    async fn set_option(&mut self, key: &str, value: serde_json::Value) -> Result<()>;
}

/// Individual transport connection
#[async_trait]
pub trait TransportConnection: Send + Sync {
    /// Get connection info
    fn connection_info(&self) -> &ConnectionInfo;

    /// Send a message
    async fn send(&mut self, message: TransportMessage) -> Result<()>;

    /// Receive a message
    async fn receive(&mut self) -> Result<Option<TransportMessage>>;

    /// Close the connection
    async fn close(&mut self) -> Result<()>;

    /// Check if connection is alive
    fn is_connected(&self) -> bool;

    /// Get connection statistics
    fn get_stats(&self) -> ConnectionStats;

    /// Set connection-specific options
    async fn set_option(&mut self, key: &str, value: serde_json::Value) -> Result<()>;
}

/// Transport statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    /// Total connections accepted
    pub connections_accepted: u64,
    /// Active connections
    pub active_connections: u64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Errors encountered
    pub errors: u64,
}

/// Connection statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Errors encountered
    pub errors: u64,
    /// Round-trip time (microseconds)
    pub rtt_us: Option<u64>,
}

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Enable transport multiplexing
    pub multiplexing: bool,
    /// Transport type preferences
    pub transports: Vec<TransportTypeConfig>,
    /// Global timeout settings
    pub timeouts: TimeoutConfig,
    /// Security settings
    pub security: SecurityConfig,
    /// Buffer sizes
    pub buffers: BufferConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            multiplexing: false,
            transports: vec![TransportTypeConfig {
                transport_type: TransportType::Stdio,
                enabled: true,
                config: serde_json::json!({}),
            }],
            timeouts: TimeoutConfig::default(),
            security: SecurityConfig::default(),
            buffers: BufferConfig::default(),
        }
    }
}

/// Transport type specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportTypeConfig {
    /// Transport type
    pub transport_type: TransportType,
    /// Is this transport enabled
    pub enabled: bool,
    /// Transport-specific configuration
    pub config: serde_json::Value,
}

/// Timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Connection timeout (ms)
    pub connect_ms: u64,
    /// Read timeout (ms)
    pub read_ms: u64,
    /// Write timeout (ms)
    pub write_ms: u64,
    /// Keep-alive interval (ms)
    pub keepalive_ms: Option<u64>,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_ms: 5000,
            read_ms: 30000,
            write_ms: 30000,
            keepalive_ms: Some(60000),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require TLS for network transports
    pub require_tls: bool,
    /// Minimum TLS version
    pub min_tls_version: Option<String>,
    /// Allowed cipher suites
    pub cipher_suites: Option<Vec<String>>,
    /// Client certificate requirements
    pub client_auth: ClientAuthConfig,
    /// Enable transport-level encryption
    pub encryption: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_tls: true,
            min_tls_version: Some("1.2".to_string()),
            cipher_suites: None,
            client_auth: ClientAuthConfig::default(),
            encryption: true,
        }
    }
}

/// Client authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    /// Require client certificates
    pub required: bool,
    /// Trusted CA certificates
    pub ca_certs: Vec<String>,
    /// Certificate verification depth
    pub verify_depth: u32,
}

impl Default for ClientAuthConfig {
    fn default() -> Self {
        Self {
            required: false,
            ca_certs: Vec::new(),
            verify_depth: 3,
        }
    }
}

/// Buffer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    /// Receive buffer size
    pub recv_buffer_size: usize,
    /// Send buffer size
    pub send_buffer_size: usize,
    /// Message queue size
    pub message_queue_size: usize,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            recv_buffer_size: 65536,
            send_buffer_size: 65536,
            message_queue_size: 1000,
        }
    }
}

/// Transport manager for handling multiple transports
pub struct TransportManager {
    #[allow(dead_code)]
    config: TransportConfig,
    transports: Vec<Box<dyn Transport>>,
    connections: Arc<tokio::sync::RwLock<Vec<Box<dyn TransportConnection>>>>,
    #[allow(dead_code)]
    message_handler: Arc<dyn MessageHandler>,
}

/// Message handler trait
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handle incoming message
    async fn handle_message(
        &self,
        message: TransportMessage,
        connection: &dyn TransportConnection,
    ) -> Result<Option<TransportMessage>>;

    /// Handle connection established
    async fn on_connect(&self, connection: &dyn TransportConnection) -> Result<()>;

    /// Handle connection closed
    async fn on_disconnect(&self, connection: &dyn TransportConnection) -> Result<()>;
}

impl TransportManager {
    /// Create new transport manager
    pub fn new(config: TransportConfig, handler: Arc<dyn MessageHandler>) -> Result<Self> {
        Ok(Self {
            config,
            transports: Vec::new(),
            connections: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            message_handler: handler,
        })
    }

    /// Add a transport
    pub fn add_transport(&mut self, transport: Box<dyn Transport>) -> Result<()> {
        self.transports.push(transport);
        Ok(())
    }

    /// Start all transports
    pub async fn start(&mut self) -> Result<()> {
        for transport in &mut self.transports {
            transport.start().await?;
        }
        Ok(())
    }

    /// Stop all transports
    pub async fn stop(&mut self) -> Result<()> {
        // Close all connections
        let mut connections = self.connections.write().await;
        for conn in connections.iter_mut() {
            let _ = conn.close().await;
        }
        connections.clear();

        // Stop all transports
        for transport in &mut self.transports {
            transport.stop().await?;
        }
        Ok(())
    }

    /// Get statistics for all transports
    pub fn get_stats(&self) -> Vec<(TransportType, TransportStats)> {
        self.transports
            .iter()
            .map(|t| (t.transport_type(), t.get_stats()))
            .collect()
    }
}

/// Factory for creating transports
pub trait TransportFactory: Send + Sync {
    /// Create a transport
    fn create(&self, config: &TransportTypeConfig) -> Result<Box<dyn Transport>>;
}

/// Default transport factory
pub struct DefaultTransportFactory;

impl TransportFactory for DefaultTransportFactory {
    fn create(&self, config: &TransportTypeConfig) -> Result<Box<dyn Transport>> {
        match config.transport_type {
            TransportType::Stdio => Ok(Box::new(StdioTransport::new(config.config.clone())?)),
            TransportType::Http => Ok(Box::new(HttpTransport::new(config.config.clone())?)),
            TransportType::WebSocket => {
                Ok(Box::new(WebSocketTransport::new(config.config.clone())?))
            }
            #[cfg(feature = "enhanced")]
            TransportType::Grpc => Ok(Box::new(enhanced::GrpcTransport::new(
                config.config.clone(),
            )?)),
            _ => Err(anyhow::anyhow!(
                "Unsupported transport type: {:?}",
                config.transport_type
            )),
        }
    }
}

/// Create a transport based on configuration
pub fn create_transport(config: &crate::config::Config) -> Arc<dyn Transport> {
    // For now, default to stdio transport
    // TODO: Read transport config from main Config struct
    let transport_config = TransportTypeConfig {
        transport_type: TransportType::Stdio,
        enabled: true,
        config: serde_json::json!({}),
    };
    
    let factory = DefaultTransportFactory;
    factory.create(&transport_config)
        .unwrap_or_else(|_| Box::new(StdioTransport::new(serde_json::json!({})).unwrap()))
        .into()
}

/// Helper for creating transport messages
pub struct TransportMessageBuilder {
    message: TransportMessage,
}

impl TransportMessageBuilder {
    pub fn new(payload: serde_json::Value) -> Self {
        Self {
            message: TransportMessage {
                id: uuid::Uuid::new_v4().to_string(),
                payload,
                metadata: TransportMetadata::default(),
            },
        }
    }

    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.message.metadata.client_id = Some(client_id);
        self
    }

    pub fn with_trace_id(mut self, trace_id: String) -> Self {
        self.message.metadata.trace_id = Some(trace_id);
        self
    }

    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.message.metadata.headers.insert(key, value);
        self
    }

    pub fn build(mut self) -> TransportMessage {
        self.message.metadata.timestamp = Some(chrono::Utc::now());
        self.message
    }
}
