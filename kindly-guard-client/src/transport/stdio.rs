//! Stdio transport for MCP communication

use async_trait::async_trait;
use anyhow::{Result, anyhow};
use tokio::process::{Command, Child};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error};

use crate::traits::McpTransport;

/// Stdio transport implementation
pub struct StdioTransport {
    process: Arc<Mutex<Option<Child>>>,
    reader: Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>,
    writer: Arc<Mutex<Option<tokio::process::ChildStdin>>>,
    server_path: String,
    server_args: Vec<String>,
}

impl StdioTransport {
    /// Create a new stdio transport
    pub fn new(server_path: String, server_args: Vec<String>) -> Self {
        Self {
            process: Arc::new(Mutex::new(None)),
            reader: Arc::new(Mutex::new(None)),
            writer: Arc::new(Mutex::new(None)),
            server_path,
            server_args,
        }
    }
    
    /// Start the server process
    pub async fn start(&self) -> Result<()> {
        let mut process = Command::new(&self.server_path)
            .args(&self.server_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        let stdin = process.stdin.take()
            .ok_or_else(|| anyhow!("Failed to get stdin"))?;
        let stdout = process.stdout.take()
            .ok_or_else(|| anyhow!("Failed to get stdout"))?;
        
        *self.writer.lock().await = Some(stdin);
        *self.reader.lock().await = Some(BufReader::new(stdout));
        *self.process.lock().await = Some(process);
        
        debug!("Started server process: {}", self.server_path);
        
        // Give the server time to initialize
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        Ok(())
    }
}

#[async_trait]
impl McpTransport for StdioTransport {
    async fn send_request(&self, request: &str) -> Result<String> {
        // Write request
        {
            let mut writer_guard = self.writer.lock().await;
            let writer = writer_guard.as_mut()
                .ok_or_else(|| anyhow!("Transport not connected"))?;
            
            writer.write_all(request.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
            
            debug!("Sent request: {}", request);
        }
        
        // Read response
        let response = {
            let mut reader_guard = self.reader.lock().await;
            let reader = reader_guard.as_mut()
                .ok_or_else(|| anyhow!("Transport not connected"))?;
            
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            
            debug!("Received response: {}", line.trim());
            
            line
        };
        
        Ok(response)
    }
    
    fn is_connected(&self) -> bool {
        // Check if we have a process handle
        let process = self.process.blocking_lock();
        process.is_some()
    }
    
    async fn close(&self) -> Result<()> {
        // Close writer first
        if let Some(mut writer) = self.writer.lock().await.take() {
            let _ = writer.shutdown().await;
        }
        
        // Kill the process
        if let Some(mut process) = self.process.lock().await.take() {
            match process.kill().await {
                Ok(_) => debug!("Server process terminated"),
                Err(e) => error!("Failed to kill server process: {}", e),
            }
        }
        
        Ok(())
    }
}

/// Builder for stdio transport
pub struct StdioTransportBuilder {
    server_path: String,
    server_args: Vec<String>,
}

impl StdioTransportBuilder {
    /// Create a new builder
    pub fn new(server_path: impl Into<String>) -> Self {
        Self {
            server_path: server_path.into(),
            server_args: vec!["--stdio".to_string()],
        }
    }
    
    /// Add a server argument
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.server_args.push(arg.into());
        self
    }
    
    /// Enable shield display
    pub fn with_shield(mut self) -> Self {
        self.server_args.push("--shield".to_string());
        self
    }
    
    /// Set config file
    pub fn with_config(mut self, config_path: impl Into<String>) -> Self {
        self.server_args.push("--config".to_string());
        self.server_args.push(config_path.into());
        self
    }
    
    /// Build the transport
    pub fn build(self) -> StdioTransport {
        StdioTransport::new(self.server_path, self.server_args)
    }
}