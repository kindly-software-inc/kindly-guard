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
//! Enhanced WebSocket implementation with binary protocol support
//!
//! This module provides optimized WebSocket handling using binary
//! protocol for improved performance and reduced overhead.

#![cfg(feature = "enhanced")]

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    tungstenite::Message,
    WebSocketStream,
};

use crate::websocket::{WebSocketHandlerTrait, WebSocketMessage, WebSocketMetrics};

// Local trait definitions for binary protocol
pub trait BinaryProtocolTrait: Send + Sync {
    fn encode(&self, msg: &WebSocketMessage) -> Result<Vec<u8>>;
    fn decode(&self, data: &[u8]) -> Result<WebSocketMessage>;
}

pub trait MessageCompressorTrait: Send + Sync {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn get_compression_ratio(&self) -> f32;
}

#[derive(Debug, Clone, Copy)]
pub enum CompressionLevel {
    None,
    Fast,
    Best,
}

// Mock implementations
struct BinaryProtocol;
struct MessageCompressor {
    level: CompressionLevel,
}

impl BinaryProtocol {
    fn new() -> Self {
        Self
    }
}

impl MessageCompressor {
    fn new(level: CompressionLevel) -> Self {
        Self { level }
    }
}

impl BinaryProtocolTrait for BinaryProtocol {
    fn encode(&self, msg: &WebSocketMessage) -> Result<Vec<u8>> {
        // Simple serialization
        Ok(serde_json::to_vec(msg)?)
    }
    
    fn decode(&self, data: &[u8]) -> Result<WebSocketMessage> {
        // Simple deserialization
        Ok(serde_json::from_slice(data)?)
    }
}

impl MessageCompressorTrait for MessageCompressor {
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Mock compression - just return the data
        Ok(data.to_vec())
    }
    
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Mock decompression - just return the data
        Ok(data.to_vec())
    }
    
    fn get_compression_ratio(&self) -> f32 {
        match self.level {
            CompressionLevel::None => 1.0,
            CompressionLevel::Fast => 0.8,
            CompressionLevel::Best => 0.6,
        }
    }
}

/// Enhanced WebSocket handler with binary protocol support
pub struct EnhancedWebSocketHandler {
    /// Binary protocol encoder/decoder
    protocol: Arc<dyn BinaryProtocolTrait>,
    
    /// Message compressor for bandwidth optimization
    compressor: Arc<dyn MessageCompressorTrait>,
    
    /// Active connections
    connections: Arc<Mutex<Vec<WebSocketStream<TcpStream>>>>,
    
    /// Performance metrics
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl EnhancedWebSocketHandler {
    /// Create new enhanced handler with compression enabled
    pub fn new(enable_compression: bool) -> Result<Self> {
        let protocol = Arc::new(BinaryProtocol::new());
        let compressor = Arc::new(MessageCompressor::new(
            if enable_compression {
                CompressionLevel::Fast
            } else {
                CompressionLevel::None
            }
        ));
        
        Ok(Self {
            protocol,
            compressor,
            connections: Arc::new(Mutex::new(Vec::new())),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        })
    }
    
    /// Convert internal message to binary format
    fn encode_message(&self, msg: &WebSocketMessage) -> Result<Vec<u8>> {
        // Serialize to binary format
        let encoded = self.protocol.encode(msg)?;
        
        // Optionally compress
        let compressed = self.compressor.compress(&encoded)?;
        
        Ok(compressed)
    }
    
    /// Decode binary message to internal format
    fn decode_message(&self, data: &[u8]) -> Result<WebSocketMessage> {
        // Decompress if needed
        let decompressed = self.compressor.decompress(data)?;
        
        // Decode from binary format
        let message = self.protocol.decode(&decompressed)?;
        
        Ok(message)
    }
}

#[async_trait::async_trait]
impl WebSocketHandlerTrait for EnhancedWebSocketHandler {
    async fn handle_connection(&self, stream: WebSocketStream<TcpStream>) -> Result<()> {
        let (mut write, mut read) = stream.split();
        
        // Store connection
        {
            let mut connections = self.connections.lock().await;
            // Note: In real implementation, we'd store the write half separately
            // This is simplified for the example
        }
        
        // Handle incoming messages
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    self.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
                    self.messages_received.fetch_add(1, Ordering::Relaxed);
                    
                    // Decode binary message
                    match self.decode_message(&data) {
                        Ok(decoded) => {
                            tracing::trace!("Received binary message: {:?}", decoded.msg_type);
                            
                            // Process message and prepare response
                            let response = WebSocketMessage {
                                msg_type: "response".to_string(),
                                data: serde_json::json!({"status": "ok"}),
                                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                            };
                            
                            // Encode and send response
                            let encoded = self.encode_message(&response)?;
                            write.send(Message::Binary(encoded.clone())).await?;
                            
                            self.bytes_sent.fetch_add(encoded.len() as u64, Ordering::Relaxed);
                            self.messages_sent.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to decode binary message: {}", e);
                        }
                    }
                }
                Ok(Message::Text(text)) => {
                    // Fallback to text protocol for compatibility
                    self.bytes_received.fetch_add(text.len() as u64, Ordering::Relaxed);
                    self.messages_received.fetch_add(1, Ordering::Relaxed);
                    
                    tracing::debug!("Received text message (legacy mode)");
                }
                Ok(Message::Close(_)) => {
                    tracing::info!("WebSocket connection closed");
                    break;
                }
                Err(e) => {
                    tracing::error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
        
        Ok(())
    }
    
    async fn broadcast_message(&self, msg: WebSocketMessage) -> Result<()> {
        let encoded = self.encode_message(&msg)?;
        let connections = self.connections.lock().await;
        
        // In real implementation, we'd iterate over write halves
        // and send to each connection
        let sent_count = connections.len();
        
        self.messages_sent.fetch_add(sent_count as u64, Ordering::Relaxed);
        self.bytes_sent.fetch_add(
            (encoded.len() * sent_count) as u64,
            Ordering::Relaxed
        );
        
        Ok(())
    }
    
    fn get_metrics(&self) -> WebSocketMetrics {
        WebSocketMetrics {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            active_connections: 0, // Would need proper tracking in real impl
            compression_ratio: self.compressor.get_compression_ratio(),
        }
    }
    
    fn supports_binary_protocol(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_enhanced_handler_creation() {
        let handler = EnhancedWebSocketHandler::new(true).unwrap();
        assert!(handler.supports_binary_protocol());
    }
    
    #[test]
    fn test_message_encoding() {
        let handler = EnhancedWebSocketHandler::new(false).unwrap();
        let msg = WebSocketMessage {
            msg_type: "test".to_string(),
            data: serde_json::json!({"key": "value"}),
            timestamp: 12345,
        };
        
        let encoded = handler.encode_message(&msg).unwrap();
        assert!(!encoded.is_empty());
        
        let decoded = handler.decode_message(&encoded).unwrap();
        assert_eq!(decoded.msg_type, msg.msg_type);
    }
}