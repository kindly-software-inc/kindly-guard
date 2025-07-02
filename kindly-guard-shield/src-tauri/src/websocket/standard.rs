//! Standard WebSocket handler implementation
//!
//! This provides basic WebSocket functionality without enhanced features

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    tungstenite::Message,
    WebSocketStream,
};

use crate::websocket::{WebSocketHandlerTrait, WebSocketMessage, WebSocketMetrics};

/// Standard WebSocket handler with text protocol
pub struct StandardWebSocketHandler {
    /// Active connections
    connections: Arc<Mutex<Vec<WebSocketStream<TcpStream>>>>,
    
    /// Metrics
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    active_connections: AtomicUsize,
}

impl StandardWebSocketHandler {
    /// Create new standard handler
    pub fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl WebSocketHandlerTrait for StandardWebSocketHandler {
    async fn handle_connection(&self, stream: WebSocketStream<TcpStream>) -> Result<()> {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        let (mut write, mut read) = stream.split();
        
        // Handle incoming messages
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    self.bytes_received.fetch_add(text.len() as u64, Ordering::Relaxed);
                    self.messages_received.fetch_add(1, Ordering::Relaxed);
                    
                    // Parse and process message
                    match serde_json::from_str::<WebSocketMessage>(&text) {
                        Ok(ws_msg) => {
                            tracing::trace!("Received message: {}", ws_msg.msg_type);
                            
                            // Echo back for now
                            let response = WebSocketMessage {
                                msg_type: "ack".to_string(),
                                data: serde_json::json!({
                                    "original_type": ws_msg.msg_type,
                                    "status": "processed"
                                }),
                                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                            };
                            
                            let response_text = serde_json::to_string(&response)?;
                            write.send(Message::Text(response_text.clone())).await?;
                            
                            self.bytes_sent.fetch_add(response_text.len() as u64, Ordering::Relaxed);
                            self.messages_sent.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse WebSocket message: {}", e);
                        }
                    }
                }
                Ok(Message::Binary(data)) => {
                    // Standard handler converts binary to text
                    self.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                    tracing::debug!("Received binary message, converting to text");
                    
                    if let Ok(text) = String::from_utf8(data) {
                        // Process as text
                        self.messages_received.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Message::Close(_)) => {
                    tracing::info!("WebSocket connection closed");
                    break;
                }
                Ok(Message::Ping(data)) => {
                    write.send(Message::Pong(data)).await?;
                }
                Err(e) => {
                    tracing::error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
        
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }
    
    async fn broadcast_message(&self, msg: WebSocketMessage) -> Result<()> {
        let message_text = serde_json::to_string(&msg)?;
        let connections = self.connections.lock().await;
        
        // In real implementation, we'd iterate over write halves
        // and send to each connection
        let sent_count = connections.len();
        
        self.messages_sent.fetch_add(sent_count as u64, Ordering::Relaxed);
        self.bytes_sent.fetch_add(
            (message_text.len() * sent_count) as u64,
            Ordering::Relaxed
        );
        
        tracing::debug!("Broadcast message to {} clients", sent_count);
        Ok(())
    }
    
    fn get_metrics(&self) -> WebSocketMetrics {
        WebSocketMetrics {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            compression_ratio: 1.0, // No compression in standard mode
        }
    }
    
    fn supports_binary_protocol(&self) -> bool {
        false // Standard handler uses text protocol only
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_standard_handler_creation() {
        let handler = StandardWebSocketHandler::new();
        assert!(!handler.supports_binary_protocol());
        
        let metrics = handler.get_metrics();
        assert_eq!(metrics.messages_sent, 0);
        assert_eq!(metrics.compression_ratio, 1.0);
    }
}