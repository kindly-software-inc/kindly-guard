//! HTTPS proxy transport for intercepting AI API calls
//!
//! This transport acts as a transparent HTTPS proxy that intercepts
//! and scans requests/responses to AI services for security threats.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use super::{
    Transport, TransportConnection,
    TransportStats, TransportType,
};
use crate::server::McpServer;

/// Proxy transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Bind address
    pub bind_addr: String,
    /// Whether to intercept HTTPS traffic
    pub intercept_https: bool,
    /// List of AI service domains to intercept
    pub ai_services: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".to_string(),
            intercept_https: true,
            ai_services: vec![
                "api.anthropic.com".to_string(),
                "api.openai.com".to_string(),
                "generativelanguage.googleapis.com".to_string(),
                "api.cohere.ai".to_string(),
                "api.mistral.ai".to_string(),
                "api.together.xyz".to_string(),
                "api.replicate.com".to_string(),
            ],
        }
    }
}

/// HTTPS proxy transport
pub struct ProxyTransport {
    config: ProxyConfig,
    listener: Option<TcpListener>,
}

impl ProxyTransport {
    /// Create new proxy transport
    pub fn new(config: Value) -> Result<Self> {
        let config: ProxyConfig = serde_json::from_value(config)?;
        Ok(Self {
            config,
            listener: None,
        })
    }

    /// Parse HTTP CONNECT request
    fn parse_connect(&self, data: &[u8]) -> Result<(String, u16)> {
        let request = String::from_utf8_lossy(data);
        let lines: Vec<&str> = request.lines().collect();
        
        if lines.is_empty() {
            return Err(anyhow!("Empty CONNECT request"));
        }

        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "CONNECT" {
            return Err(anyhow!("Invalid CONNECT request"));
        }

        let host_port: Vec<&str> = parts[1].split(':').collect();
        if host_port.len() != 2 {
            return Err(anyhow!("Invalid host:port format"));
        }

        let host = host_port[0].to_string();
        let port = host_port[1].parse::<u16>()
            .map_err(|_| anyhow!("Invalid port number"))?;

        Ok((host, port))
    }

    /// Check if we should intercept this host
    fn should_intercept(&self, host: &str) -> bool {
        self.config.ai_services.iter().any(|service| {
            host == service || host.ends_with(&format!(".{}", service))
        })
    }

    /// Handle a proxy connection
    async fn handle_connection(
        self: Arc<Self>,
        mut client: TcpStream,
        server: Arc<McpServer>,
    ) -> Result<()> {
        let client_addr = client.peer_addr()?;
        debug!("New proxy connection from {}", client_addr);

        // Read CONNECT request
        let mut buffer = vec![0; 4096];
        let n = client.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }

        // Parse CONNECT request
        let (host, port) = self.parse_connect(&buffer[..n])?;
        info!("CONNECT request to {}:{}", host, port);

        // Check if we should intercept
        if !self.should_intercept(&host) {
            // Pass through without interception
            debug!("Passing through connection to {}:{}", host, port);
            
            // Connect to target
            let mut target = TcpStream::connect((host.as_str(), port)).await?;
            
            // Send 200 Connection Established
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            
            // Relay traffic
            let (mut client_read, mut client_write) = client.into_split();
            let (mut target_read, mut target_write) = target.into_split();
            
            tokio::select! {
                _ = tokio::io::copy(&mut client_read, &mut target_write) => {},
                _ = tokio::io::copy(&mut target_read, &mut client_write) => {},
            }
        } else {
            // Intercept and scan
            info!("Intercepting connection to {}:{}", host, port);
            
            // Send 200 Connection Established
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            
            // Create intercepting proxy connection
            let conn = ProxyConnection::new(client, host, port, server.clone());
            conn.handle().await?;
        }

        Ok(())
    }

    /// Serve proxy connections
    pub async fn serve(mut self, server: Arc<McpServer>) -> Result<()> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        info!("Proxy listening on {}", self.config.bind_addr);
        
        self.listener = Some(listener);
        let self_arc = Arc::new(self);

        // Accept connections
        while let Some(listener) = &self_arc.listener {
            match listener.accept().await {
                Ok((client, _)) => {
                    let self_clone = self_arc.clone();
                    let server_clone = server.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = self_clone.handle_connection(client, server_clone).await {
                            error!("Proxy connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }

        Ok(())
    }
}

/// Intercepting proxy connection
struct ProxyConnection {
    client: TcpStream,
    host: String,
    port: u16,
    server: Arc<McpServer>,
}

impl ProxyConnection {
    fn new(client: TcpStream, host: String, port: u16, server: Arc<McpServer>) -> Self {
        Self {
            client,
            host,
            port,
            server,
        }
    }

    async fn handle(self) -> Result<()> {
        // Connect to target
        let target = TcpStream::connect((self.host.as_str(), self.port)).await?;
        
        // TODO: Implement TLS interception for HTTPS
        // For now, we'll do TCP-level inspection
        
        let server = self.server.clone();
        let host = self.host.clone();
        let (client_read, client_write) = self.client.into_split();
        let (target_read, target_write) = target.into_split();
        
        // Intercept and scan traffic in both directions
        tokio::select! {
            _ = ProxyConnection::relay_traffic(client_read, target_write, true, server.clone(), host.clone()) => {},
            _ = ProxyConnection::relay_traffic(target_read, client_write, false, server, host) => {},
        }
        
        Ok(())
    }

    async fn relay_traffic(
        mut reader: tokio::net::tcp::OwnedReadHalf,
        mut writer: tokio::net::tcp::OwnedWriteHalf,
        is_request: bool,
        server: Arc<McpServer>,
        host: String,
    ) -> Result<()> {
        let mut buffer = vec![0; 8192];
        
        loop {
            let n = reader.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            
            // Try to parse as HTTP and scan
            if let Ok(data_str) = std::str::from_utf8(&buffer[..n]) {
                // Look for JSON content
                if let Some(json_start) = data_str.find('{') {
                    if let Ok(json_value) = serde_json::from_str::<Value>(&data_str[json_start..]) {
                        // Scan JSON content
                        let threats = server.scanner().scan_json(&json_value)?;
                        
                        if !threats.is_empty() {
                            warn!(
                                "Threats detected in {} to {}: {:?}",
                                if is_request { "request" } else { "response" },
                                host,
                                threats
                            );
                            
                            // Record threats
                            server.shield.record_threats(&threats);
                            
                            // TODO: Optionally block or modify content
                        }
                    }
                }
            }
            
            // Forward data
            writer.write_all(&buffer[..n]).await?;
        }
        
        Ok(())
    }
}

#[async_trait]
impl Transport for ProxyTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Http
    }

    async fn start(&mut self) -> Result<()> {
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn TransportConnection>> {
        Err(anyhow!("Proxy transport doesn't use accept pattern"))
    }

    async fn connect(&mut self, _address: &str) -> Result<Box<dyn TransportConnection>> {
        Err(anyhow!("Proxy transport doesn't use connect pattern"))
    }

    fn is_running(&self) -> bool {
        self.listener.is_some()
    }

    fn get_stats(&self) -> TransportStats {
        TransportStats {
            messages_received: 0,
            messages_sent: 0,
            bytes_received: 0,
            bytes_sent: 0,
            errors: 0,
            ..Default::default()
        }
    }

    async fn set_option(&mut self, _key: &str, _value: serde_json::Value) -> Result<()> {
        Ok(())
    }
}