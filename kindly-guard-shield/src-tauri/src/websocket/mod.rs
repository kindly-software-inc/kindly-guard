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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, tungstenite::Message, WebSocketStream};
use tracing::{debug, error, info, warn};

use crate::{
    core::{ShieldCore, Threat},
    security::{SecurityError, SecurityValidator},
};

// Enhanced implementation module
#[cfg(feature = "enhanced")]
pub mod enhanced;

// Standard implementation module
pub mod standard;

/// WebSocket message for internal processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessage {
    pub msg_type: String,
    pub data: serde_json::Value,
    pub timestamp: u64,
}

/// WebSocket metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMetrics {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_connections: usize,
    pub compression_ratio: f32,
}

/// WebSocket handler trait
#[async_trait::async_trait]
pub trait WebSocketHandlerTrait: Send + Sync {
    /// Handle a new WebSocket connection
    async fn handle_connection(&self, stream: WebSocketStream<TcpStream>) -> Result<()>;
    
    /// Broadcast a message to all connected clients
    async fn broadcast_message(&self, msg: WebSocketMessage) -> Result<()>;
    
    /// Get handler metrics
    fn get_metrics(&self) -> WebSocketMetrics;
    
    /// Check if binary protocol is supported
    fn supports_binary_protocol(&self) -> bool;
}

/// Factory for creating WebSocket handlers
pub struct WebSocketHandlerFactory;

impl WebSocketHandlerFactory {
    /// Create appropriate WebSocket handler based on configuration
    pub fn create(config: &crate::config::Config) -> Result<Arc<dyn WebSocketHandlerTrait>> {
        #[cfg(feature = "enhanced")]
        {
            if config.enhanced_mode {
                return Ok(Arc::new(enhanced::EnhancedWebSocketHandler::new(
                    config.enable_compression
                )?));
            }
        }
        
        // Default to standard implementation
        Ok(Arc::new(standard::StandardWebSocketHandler::new()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "threat")]
    Threat {
        threats: Vec<Threat>,
    },
    #[serde(rename = "status")]
    Status {
        protection_enabled: bool,
        threats_blocked: u64,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat,
    #[serde(rename = "error")]
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsCommand {
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "unsubscribe")]
    Unsubscribe,
    #[serde(rename = "get_status")]
    GetStatus,
    #[serde(rename = "toggle_protection")]
    ToggleProtection,
}

#[derive(Clone)]
pub struct WebSocketServer {
    core: Arc<ShieldCore>,
    validator: Arc<SecurityValidator>,
}

impl WebSocketServer {
    pub fn new(core: Arc<ShieldCore>, validator: Arc<SecurityValidator>) -> Self {
        Self { core, validator }
    }
    
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = "127.0.0.1:9955";
        let listener = TcpListener::bind(&addr).await?;
        info!("WebSocket server listening on ws://{}", addr);
        
        let server = self.clone();
        
        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.handle_connection(stream, addr).await {
                        error!("WebSocket connection error: {}", e);
                    }
                });
            }
        });
        
        Ok(())
    }
    
    async fn handle_connection(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("New WebSocket connection from: {}", addr);
        
        // Accept WebSocket connection with timeout
        let ws_stream = match timeout(Duration::from_secs(10), accept_async(stream)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                error!("WebSocket handshake failed: {}", e);
                return Err(Box::new(e));
            }
            Err(_) => {
                error!("WebSocket handshake timeout");
                return Err("Handshake timeout".into());
            }
        };
        
        let (tx, rx) = mpsc::channel(100);
        
        // Spawn message handler
        let handler = self.clone();
        tokio::spawn(async move {
            handler.handle_messages(ws_stream, rx, addr).await;
        });
        
        // Send initial status
        let status = WsMessage::Status {
            protection_enabled: self.core.is_protection_enabled(),
            threats_blocked: self.core.get_statistics().threats_blocked,
        };
        
        let _ = tx.send(status).await;
        
        Ok(())
    }
    
    async fn handle_messages(
        &self,
        ws_stream: WebSocketStream<TcpStream>,
        mut rx: mpsc::Receiver<WsMessage>,
        addr: SocketAddr,
    ) {
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        
        loop {
            tokio::select! {
                // Handle incoming WebSocket messages
                msg = ws_receiver.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            // Validate message
                            match self.validator.validate_message(text.as_bytes()) {
                                Ok(_) => {
                                    if let Err(e) = self.handle_command(&text).await {
                                        error!("Command handling error: {}", e);
                                        let error_msg = WsMessage::Error {
                                            message: format!("Command error: {}", e),
                                        };
                                        let _ = ws_sender.send(Message::Text(
                                            serde_json::to_string(&error_msg).unwrap()
                                        )).await;
                                    }
                                }
                                Err(SecurityError::RateLimitExceeded) => {
                                    warn!("Rate limit exceeded from {}", addr);
                                    let error_msg = WsMessage::Error {
                                        message: "Rate limit exceeded".to_string(),
                                    };
                                    let _ = ws_sender.send(Message::Text(
                                        serde_json::to_string(&error_msg).unwrap()
                                    )).await;
                                }
                                Err(e) => {
                                    error!("Security validation failed: {}", e);
                                    break;
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            info!("Client {} disconnected", addr);
                            break;
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let _ = ws_sender.send(Message::Pong(data)).await;
                        }
                        Some(Err(e)) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
                
                // Handle outgoing messages
                Some(msg) = rx.recv() => {
                    match serde_json::to_string(&msg) {
                        Ok(json) => {
                            if ws_sender.send(Message::Text(json)).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("JSON serialization error: {}", e);
                        }
                    }
                }
            }
        }
        
        info!("WebSocket connection closed for {}", addr);
    }
    
    async fn handle_command(&self, text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let command: WsCommand = serde_json::from_str(text)?;
        
        match command {
            WsCommand::Subscribe => {
                debug!("Client subscribed to updates");
                // In a real implementation, you'd add this client to a subscription list
            }
            WsCommand::Unsubscribe => {
                debug!("Client unsubscribed from updates");
                // Remove from subscription list
            }
            WsCommand::GetStatus => {
                debug!("Status requested");
                // Status is sent through the channel in handle_connection
            }
            WsCommand::ToggleProtection => {
                debug!("Protection toggle requested");
                self.core.toggle_protection();
            }
        }
        
        Ok(())
    }
    
    pub async fn broadcast_threat(&self, threat: Threat) {
        // In a real implementation, this would send to all connected clients
        debug!("Broadcasting threat: {:?}", threat);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_serialization() {
        let msg = WsMessage::Status {
            protection_enabled: true,
            threats_blocked: 42,
        };
        
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"status\""));
        assert!(json.contains("\"protection_enabled\":true"));
        assert!(json.contains("\"threats_blocked\":42"));
    }
    
    #[test]
    fn test_command_deserialization() {
        let json = r#"{"type":"subscribe"}"#;
        let cmd: WsCommand = serde_json::from_str(json).unwrap();
        
        match cmd {
            WsCommand::Subscribe => {}
            _ => panic!("Wrong command type"),
        }
    }
}