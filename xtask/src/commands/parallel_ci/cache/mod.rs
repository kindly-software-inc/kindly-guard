//! Caching layer for parallel CI builds

use anyhow::Result;
use std::path::PathBuf;
use tokio::process::Command;

/// Cache manager for build artifacts
pub struct CacheManager {
    backend: CacheBackend,
    _cache_dir: PathBuf,
}

/// Supported cache backends
#[derive(Debug, Clone)]
pub enum CacheBackend {
    Local { path: PathBuf },
    Sccache { config: SccacheConfig },
    None,
}

/// Sccache configuration
#[derive(Debug, Clone)]
pub struct SccacheConfig {
    pub storage: SccacheStorage,
    pub max_size: String,
}

#[derive(Debug, Clone)]
pub enum SccacheStorage {
    Local { dir: PathBuf },
    Redis { url: String },
    S3 { bucket: String, region: String },
    GHA, // GitHub Actions cache
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new(backend: CacheBackend) -> Self {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("kindly-guard");

        Self { backend, _cache_dir: cache_dir }
    }

    /// Initialize the cache backend
    pub async fn init(&self) -> Result<()> {
        match &self.backend {
            CacheBackend::Sccache { config } => {
                self.setup_sccache(config).await?;
            },
            CacheBackend::Local { path } => {
                tokio::fs::create_dir_all(path).await?;
            },
            CacheBackend::None => {},
        }

        Ok(())
    }

    /// Setup sccache with configuration
    async fn setup_sccache(&self, config: &SccacheConfig) -> Result<()> {
        // Check if sccache is installed
        let sccache_available = Command::new("sccache")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !sccache_available {
            return Err(anyhow::anyhow!(
                "sccache not installed. Install with: cargo install sccache"
            ));
        }

        // Set environment variables based on storage backend
        match &config.storage {
            SccacheStorage::Local { dir } => {
                std::env::set_var("SCCACHE_DIR", dir);
            },
            SccacheStorage::Redis { url } => {
                std::env::set_var("SCCACHE_REDIS", url);
            },
            SccacheStorage::S3 { bucket, region } => {
                std::env::set_var("SCCACHE_BUCKET", bucket);
                std::env::set_var("SCCACHE_REGION", region);
            },
            SccacheStorage::GHA => {
                std::env::set_var("SCCACHE_GHA_ENABLED", "true");
            },
        }

        // Set cache size
        std::env::set_var("SCCACHE_CACHE_SIZE", &config.max_size);

        // Set Rust to use sccache
        std::env::set_var("RUSTC_WRAPPER", "sccache");

        // Start sccache server
        Command::new("sccache")
            .arg("--start-server")
            .output()
            .await?;

        Ok(())
    }

    /// Get cache statistics
    pub async fn stats(&self) -> Result<CacheStats> {
        match &self.backend {
            CacheBackend::Sccache { .. } => {
                let output = Command::new("sccache").arg("--show-stats").output().await?;

                if output.status.success() {
                    let stats_str = String::from_utf8_lossy(&output.stdout);
                    Ok(CacheStats::from_sccache_output(&stats_str))
                } else {
                    Ok(CacheStats::default())
                }
            },
            CacheBackend::Local { path } => {
                // Calculate local cache size
                let size = calculate_dir_size(path).await?;
                Ok(CacheStats {
                    hits: 0,
                    misses: 0,
                    cache_size: size,
                })
            },
            CacheBackend::None => Ok(CacheStats::default()),
        }
    }

    /// Clear the cache
    pub async fn clear(&self) -> Result<()> {
        match &self.backend {
            CacheBackend::Sccache { .. } => {
                Command::new("sccache").arg("--zero-stats").output().await?;
            },
            CacheBackend::Local { path } => {
                if path.exists() {
                    tokio::fs::remove_dir_all(path).await?;
                    tokio::fs::create_dir_all(path).await?;
                }
            },
            CacheBackend::None => {},
        }

        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub cache_size: u64,
}

impl CacheStats {
    /// Parse sccache output
    fn from_sccache_output(output: &str) -> Self {
        let mut stats = Self::default();

        // Simple parsing of sccache stats
        for line in output.lines() {
            if line.contains("Cache hits") {
                if let Some(num) = line.split_whitespace().last() {
                    stats.hits = num.parse().unwrap_or(0);
                }
            } else if line.contains("Cache misses") {
                if let Some(num) = line.split_whitespace().last() {
                    stats.misses = num.parse().unwrap_or(0);
                }
            } else if line.contains("Cache size") {
                // Parse size (handle units like MB, GB)
                if let Some(size_str) = line.split(':').nth(1) {
                    stats.cache_size = parse_size(size_str.trim()).unwrap_or(0);
                }
            }
        }

        stats
    }
}

/// Calculate directory size recursively
async fn calculate_dir_size(path: &PathBuf) -> Result<u64> {
    let mut size = 0u64;
    let mut entries = tokio::fs::read_dir(path).await?;

    while let Some(entry) = entries.next_entry().await? {
        let metadata = entry.metadata().await?;
        if metadata.is_file() {
            size += metadata.len();
        } else if metadata.is_dir() {
            size += Box::pin(calculate_dir_size(&entry.path())).await?;
        }
    }

    Ok(size)
}

/// Parse size string with units
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(num_str) = s.split_whitespace().next() {
        let num: f64 = num_str.parse().ok()?;

        if s.contains("GB") {
            Some((num * 1024.0 * 1024.0 * 1024.0) as u64)
        } else if s.contains("MB") {
            Some((num * 1024.0 * 1024.0) as u64)
        } else if s.contains("KB") {
            Some((num * 1024.0) as u64)
        } else {
            Some(num as u64)
        }
    } else {
        None
    }
}
