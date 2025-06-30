//! Daemon mode support with signal handling
//! Provides proper daemon functionality including signal handling,
//! PID file management, and graceful shutdown

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;
use anyhow::{Result, Context};
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{info, warn, error};

/// Daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Path to PID file
    pub pid_file: Option<String>,
    /// Working directory
    pub working_dir: Option<String>,
    /// User to run as (Unix only)
    pub user: Option<String>,
    /// Group to run as (Unix only)
    pub group: Option<String>,
    /// Enable graceful shutdown timeout (seconds)
    pub shutdown_timeout: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pid_file: Some("/var/run/kindly-guard.pid".to_string()),
            working_dir: None,
            user: None,
            group: None,
            shutdown_timeout: 30,
        }
    }
}

/// Daemon handle for managing the daemon lifecycle
pub struct DaemonHandle {
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Running state
    running: Arc<AtomicBool>,
    /// PID file path
    pid_file: Option<String>,
}

impl DaemonHandle {
    /// Create a new daemon handle
    pub fn new(config: DaemonConfig) -> Result<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let running = Arc::new(AtomicBool::new(true));
        
        // Write PID file if configured
        if let Some(ref pid_path) = config.pid_file {
            write_pid_file(pid_path)?;
        }
        
        // Change working directory if specified
        if let Some(ref dir) = config.working_dir {
            std::env::set_current_dir(dir)
                .context("Failed to change working directory")?;
        }
        
        // Drop privileges if configured (Unix only)
        #[cfg(unix)]
        if config.user.is_some() || config.group.is_some() {
            drop_privileges(config.user.as_deref(), config.group.as_deref())?;
        }
        
        Ok(Self {
            shutdown_tx,
            running,
            pid_file: config.pid_file,
        })
    }
    
    /// Get a shutdown receiver
    pub fn shutdown_receiver(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
    
    /// Check if daemon is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    
    /// Trigger shutdown
    pub fn shutdown(&self) {
        info!("Daemon shutdown requested");
        self.running.store(false, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(());
    }
    
    /// Setup signal handlers
    pub async fn setup_signal_handlers(self: Arc<Self>) {
        // Handle SIGTERM and SIGINT
        let handle1 = self.clone();
        tokio::spawn(async move {
            match signal::ctrl_c().await {
                Ok(()) => {
                    info!("Received SIGINT, shutting down gracefully");
                    handle1.shutdown();
                }
                Err(e) => {
                    error!("Failed to listen for SIGINT: {}", e);
                }
            }
        });
        
        // Handle SIGTERM on Unix
        #[cfg(unix)]
        {
            let handle2 = self.clone();
            tokio::spawn(async move {
                let mut stream = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to listen for SIGTERM: {}", e);
                        return;
                    }
                };
                
                loop {
                    stream.recv().await;
                    info!("Received SIGTERM, shutting down gracefully");
                    handle2.shutdown();
                    break;
                }
            });
            
            // Handle SIGHUP for reload (optional)
            let handle3 = self.clone();
            tokio::spawn(async move {
                let mut stream = match signal::unix::signal(signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to listen for SIGHUP: {}", e);
                        return;
                    }
                };
                
                loop {
                    stream.recv().await;
                    info!("Received SIGHUP, reloading configuration");
                    // In a real implementation, this would trigger config reload
                    // For now, just log it
                }
            });
        }
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        // Clean up PID file
        if let Some(ref pid_path) = self.pid_file {
            if let Err(e) = std::fs::remove_file(pid_path) {
                warn!("Failed to remove PID file: {}", e);
            }
        }
    }
}

/// Write PID file
fn write_pid_file(path: &str) -> Result<()> {
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("Failed to write PID file: {}", path))?;
    info!("Wrote PID {} to {}", pid, path);
    Ok(())
}

/// Drop privileges on Unix systems
#[cfg(unix)]
fn drop_privileges(user: Option<&str>, group: Option<&str>) -> Result<()> {
    // TODO: Implement privilege dropping when nix crate is added
    if user.is_some() || group.is_some() {
        warn!("Privilege dropping not yet implemented - would drop to user: {:?}, group: {:?}", user, group);
    }
    Ok(())
}

/// Run function with daemon support
pub async fn run_with_daemon<F, Fut>(
    config: DaemonConfig,
    run_fn: F,
) -> Result<()>
where
    F: FnOnce(broadcast::Receiver<()>) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    // Create daemon handle
    let daemon = Arc::new(DaemonHandle::new(config)?);
    
    // Setup signal handlers
    daemon.clone().setup_signal_handlers().await;
    
    // Get shutdown receiver
    let shutdown_rx = daemon.shutdown_receiver();
    
    // Run the main function
    info!("Daemon started successfully");
    
    // Run with shutdown signal
    tokio::select! {
        result = run_fn(shutdown_rx) => {
            match result {
                Ok(()) => info!("Daemon function completed successfully"),
                Err(e) => error!("Daemon function error: {}", e),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received interrupt signal");
        }
    }
    
    info!("Daemon shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_daemon_handle_creation() {
        let config = DaemonConfig {
            pid_file: None,
            ..Default::default()
        };
        
        let handle = DaemonHandle::new(config).unwrap();
        assert!(handle.is_running());
        
        handle.shutdown();
        assert!(!handle.is_running());
    }
    
    #[tokio::test]
    async fn test_pid_file_creation() {
        let dir = tempdir().unwrap();
        let pid_path = dir.path().join("test.pid");
        
        let config = DaemonConfig {
            pid_file: Some(pid_path.to_str().unwrap().to_string()),
            ..Default::default()
        };
        
        {
            let _handle = DaemonHandle::new(config).unwrap();
            assert!(pid_path.exists());
            
            let content = std::fs::read_to_string(&pid_path).unwrap();
            let pid: u32 = content.trim().parse().unwrap();
            assert_eq!(pid, std::process::id());
        }
        
        // PID file should be cleaned up after drop
        assert!(!pid_path.exists());
    }
    
    #[tokio::test]
    async fn test_shutdown_signal() {
        let config = DaemonConfig {
            pid_file: None,
            ..Default::default()
        };
        
        let handle = Arc::new(DaemonHandle::new(config).unwrap());
        let mut rx = handle.shutdown_receiver();
        
        // Send shutdown signal
        handle.shutdown();
        
        // Receiver should get the signal
        assert!(rx.recv().await.is_ok());
    }
}