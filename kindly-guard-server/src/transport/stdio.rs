//! Standard I/O transport implementation (default for MCP)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tracing::{debug, info, error};

use super::*;

/// Standard I/O transport for MCP protocol
pub struct StdioTransport {
    config: serde_json::Value,
    running: AtomicBool,
    stats: Arc<Mutex<TransportStats>>,
}

impl StdioTransport {
    /// Create new stdio transport
    pub fn new(config: serde_json::Value) -> Result<Self> {
        Ok(Self {
            config,
            running: AtomicBool::new(false),
            stats: Arc::new(Mutex::new(TransportStats::default())),
        })
    }
}

#[async_trait]
impl Transport for StdioTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Stdio
    }
    
    async fn start(&mut self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Transport already running"));
        }
        
        self.running.store(true, Ordering::Relaxed);
        info!("Started stdio transport");
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::Relaxed);
        info!("Stopped stdio transport");
        Ok(())
    }
    
    async fn accept(&mut self) -> Result<Box<dyn TransportConnection>> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Transport not running"));
        }
        
        // For stdio, we only have one "connection"
        let mut stats = self.stats.lock().await;
        stats.connections_accepted += 1;
        stats.active_connections = 1;
        drop(stats);
        
        Ok(Box::new(StdioConnection::new()))
    }
    
    async fn connect(&mut self, _address: &str) -> Result<Box<dyn TransportConnection>> {
        // Stdio doesn't support outbound connections
        Err(anyhow::anyhow!("Stdio transport doesn't support outbound connections"))
    }
    
    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    
    fn get_stats(&self) -> TransportStats {
        // Try to get stats without blocking
        if let Ok(stats) = self.stats.try_lock() {
            stats.clone()
        } else {
            TransportStats::default()
        }
    }
    
    async fn set_option(&mut self, key: &str, value: serde_json::Value) -> Result<()> {
        self.config[key] = value;
        Ok(())
    }
}

/// Stdio connection implementation
pub struct StdioConnection {
    info: ConnectionInfo,
    stdin: Arc<Mutex<BufReader<tokio::io::Stdin>>>,
    stdout: Arc<Mutex<tokio::io::Stdout>>,
    connected: AtomicBool,
    stats: Arc<Mutex<ConnectionStats>>,
}

impl StdioConnection {
    fn new() -> Self {
        let info = ConnectionInfo {
            id: uuid::Uuid::new_v4().to_string(),
            transport_type: TransportType::Stdio,
            client_id: None,
            remote_addr: None,
            connected_at: chrono::Utc::now(),
            security_info: None, // Stdio inherits process security
        };
        
        Self {
            info,
            stdin: Arc::new(Mutex::new(BufReader::new(tokio::io::stdin()))),
            stdout: Arc::new(Mutex::new(tokio::io::stdout())),
            connected: AtomicBool::new(true),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
        }
    }
    
    async fn read_line(&self) -> Result<Option<String>> {
        let mut stdin = self.stdin.lock().await;
        let mut line = String::new();
        
        match stdin.read_line(&mut line).await {
            Ok(0) => Ok(None), // EOF
            Ok(n) => {
                let mut stats = self.stats.lock().await;
                stats.bytes_received += n as u64;
                drop(stats);
                
                Ok(Some(line.trim().to_string()))
            }
            Err(e) => {
                let mut stats = self.stats.lock().await;
                stats.errors += 1;
                drop(stats);
                
                Err(anyhow::anyhow!("Failed to read from stdin: {}", e))
            }
        }
    }
    
    async fn write_line(&self, data: &str) -> Result<()> {
        let mut stdout = self.stdout.lock().await;
        let bytes = format!("{}\n", data).into_bytes();
        
        match stdout.write_all(&bytes).await {
            Ok(_) => {
                stdout.flush().await?;
                
                let mut stats = self.stats.lock().await;
                stats.bytes_sent += bytes.len() as u64;
                drop(stats);
                
                Ok(())
            }
            Err(e) => {
                let mut stats = self.stats.lock().await;
                stats.errors += 1;
                drop(stats);
                
                Err(anyhow::anyhow!("Failed to write to stdout: {}", e))
            }
        }
    }
}

#[async_trait]
impl TransportConnection for StdioConnection {
    fn connection_info(&self) -> &ConnectionInfo {
        &self.info
    }
    
    async fn send(&mut self, message: TransportMessage) -> Result<()> {
        if !self.connected.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection closed"));
        }
        
        // Serialize message to JSON
        let json = serde_json::to_string(&message.payload)?;
        
        // Send over stdout
        self.write_line(&json).await?;
        
        let mut stats = self.stats.lock().await;
        stats.messages_sent += 1;
        drop(stats);
        
        debug!("Sent message: {}", message.id);
        Ok(())
    }
    
    async fn receive(&mut self) -> Result<Option<TransportMessage>> {
        if !self.connected.load(Ordering::Relaxed) {
            return Ok(None);
        }
        
        // Read from stdin
        match self.read_line().await? {
            Some(line) if !line.is_empty() => {
                // Parse JSON
                let payload: serde_json::Value = serde_json::from_str(&line)?;
                
                let message = TransportMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    payload,
                    metadata: TransportMetadata {
                        timestamp: Some(chrono::Utc::now()),
                        ..Default::default()
                    },
                };
                
                let mut stats = self.stats.lock().await;
                stats.messages_received += 1;
                drop(stats);
                
                debug!("Received message: {}", message.id);
                Ok(Some(message))
            }
            _ => Ok(None),
        }
    }
    
    async fn close(&mut self) -> Result<()> {
        self.connected.store(false, Ordering::Relaxed);
        info!("Closed stdio connection");
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
    
    async fn set_option(&mut self, _key: &str, _value: serde_json::Value) -> Result<()> {
        // No options for stdio connection
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_stdio_transport_lifecycle() {
        let mut transport = StdioTransport::new(serde_json::json!({})).unwrap();
        
        // Should not be running initially
        assert!(!transport.is_running());
        
        // Start transport
        transport.start().await.unwrap();
        assert!(transport.is_running());
        
        // Stop transport
        transport.stop().await.unwrap();
        assert!(!transport.is_running());
    }
    
    #[test]
    fn test_message_builder() {
        let message = TransportMessageBuilder::new(serde_json::json!({
            "method": "test",
            "params": {}
        }))
        .with_client_id("test-client".to_string())
        .with_trace_id("trace-123".to_string())
        .with_header("X-Custom".to_string(), "value".to_string())
        .build();
        
        assert_eq!(message.metadata.client_id, Some("test-client".to_string()));
        assert_eq!(message.metadata.trace_id, Some("trace-123".to_string()));
        assert_eq!(message.metadata.headers.get("X-Custom"), Some(&"value".to_string()));
        assert!(message.metadata.timestamp.is_some());
    }
}