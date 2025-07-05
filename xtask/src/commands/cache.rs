//! Compilation cache management using sccache

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use std::env;
use std::process::Command;
use which::which;

use crate::utils::{self, Context};

#[derive(Parser)]
pub struct CacheCmd {
    #[command(subcommand)]
    command: CacheCommands,
}

#[derive(Subcommand)]
enum CacheCommands {
    /// Set up compilation caching
    Setup {
        /// Cache backend to use
        #[arg(long, value_enum, default_value = "local")]
        backend: CacheBackend,
        
        /// Maximum cache size
        #[arg(long, default_value = "10G")]
        max_size: String,
        
        /// S3 bucket for S3 backend
        #[arg(long, required_if_eq("backend", "s3"))]
        s3_bucket: Option<String>,
        
        /// Redis URL for Redis backend
        #[arg(long, required_if_eq("backend", "redis"))]
        redis_url: Option<String>,
    },
    
    /// Show cache statistics
    Stats,
    
    /// Clear the cache
    Clear {
        /// Force clear without confirmation
        #[arg(long)]
        force: bool,
    },
    
    /// Enable caching for current shell session
    Enable,
    
    /// Disable caching for current shell session
    Disable,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum CacheBackend {
    /// Local disk cache
    Local,
    /// AWS S3 cache
    S3,
    /// Redis cache
    Redis,
    /// GitHub Actions cache
    Gha,
}

pub async fn run(cmd: CacheCmd, ctx: Context) -> Result<()> {
    match cmd.command {
        CacheCommands::Setup { backend, max_size, s3_bucket, redis_url } => {
            setup_cache(ctx, backend, max_size, s3_bucket, redis_url).await
        }
        CacheCommands::Stats => show_stats(ctx).await,
        CacheCommands::Clear { force } => clear_cache(ctx, force).await,
        CacheCommands::Enable => enable_cache(ctx),
        CacheCommands::Disable => disable_cache(ctx),
    }
}

async fn setup_cache(
    ctx: Context,
    backend: CacheBackend,
    max_size: String,
    s3_bucket: Option<String>,
    redis_url: Option<String>,
) -> Result<()> {
    ctx.info("Setting up compilation cache with sccache");
    
    // Check if sccache is installed
    if which("sccache").is_err() {
        ctx.info("sccache not found, installing...");
        install_sccache(&ctx).await?;
    }
    
    // Configure sccache based on backend
    match backend {
        CacheBackend::Local => {
            setup_local_cache(&ctx, &max_size)?;
        }
        CacheBackend::S3 => {
            let bucket = s3_bucket.context("S3 bucket is required for S3 backend")?;
            setup_s3_cache(&ctx, &bucket, &max_size)?;
        }
        CacheBackend::Redis => {
            let url = redis_url.context("Redis URL is required for Redis backend")?;
            setup_redis_cache(&ctx, &url, &max_size)?;
        }
        CacheBackend::Gha => {
            setup_gha_cache(&ctx)?;
        }
    }
    
    // Test the configuration
    test_cache_config(&ctx)?;
    
    ctx.success("Compilation cache configured successfully!");
    ctx.info("To enable caching, run: cargo xtask cache enable");
    
    Ok(())
}

async fn install_sccache(ctx: &Context) -> Result<()> {
    let pb = utils::spinner("Installing sccache");
    
    // Try cargo-binstall first (faster)
    if which("cargo-binstall").is_ok() && !ctx.dry_run {
        let result = Command::new("cargo")
            .args(&["binstall", "--no-confirm", "sccache"])
            .output()
            .context("Failed to run cargo-binstall")?;
            
        if result.status.success() {
            pb.finish_with_message("✓ sccache installed via cargo-binstall");
            return Ok(());
        }
    }
    
    // Fall back to cargo install
    ctx.run_command("cargo", &["install", "sccache"])?;
    pb.finish_with_message("✓ sccache installed");
    
    Ok(())
}

fn setup_local_cache(ctx: &Context, max_size: &str) -> Result<()> {
    ctx.info(&format!("Configuring local cache with max size: {}", max_size));
    
    // Set environment variables
    env::set_var("SCCACHE_CACHE_SIZE", max_size);
    env::set_var("SCCACHE_DIR", dirs::cache_dir()
        .context("Failed to get cache directory")?
        .join("sccache"));
    
    // Write to config file for persistence
    write_cache_config("local", Some(("max_size", max_size)))?;
    
    Ok(())
}

fn setup_s3_cache(ctx: &Context, bucket: &str, max_size: &str) -> Result<()> {
    ctx.info(&format!("Configuring S3 cache with bucket: {}", bucket));
    
    // Check AWS credentials
    if env::var("AWS_ACCESS_KEY_ID").is_err() || env::var("AWS_SECRET_ACCESS_KEY").is_err() {
        ctx.warn("AWS credentials not found in environment");
        ctx.info("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
    }
    
    env::set_var("SCCACHE_BUCKET", bucket);
    env::set_var("SCCACHE_S3_KEY_PREFIX", "kindlyguard-cache");
    env::set_var("SCCACHE_CACHE_SIZE", max_size);
    
    write_cache_config("s3", Some(("bucket", bucket)))?;
    
    Ok(())
}

fn setup_redis_cache(ctx: &Context, url: &str, max_size: &str) -> Result<()> {
    ctx.info(&format!("Configuring Redis cache with URL: {}", url));
    
    env::set_var("SCCACHE_REDIS", url);
    env::set_var("SCCACHE_CACHE_SIZE", max_size);
    
    write_cache_config("redis", Some(("url", url)))?;
    
    Ok(())
}

fn setup_gha_cache(ctx: &Context) -> Result<()> {
    ctx.info("Configuring GitHub Actions cache");
    
    // Check if running in GitHub Actions
    if env::var("GITHUB_ACTIONS").is_err() {
        ctx.warn("Not running in GitHub Actions environment");
        ctx.info("GHA cache backend will only work in GitHub Actions");
    }
    
    env::set_var("SCCACHE_GHA_ENABLED", "true");
    env::set_var("ACTIONS_CACHE_URL", env::var("ACTIONS_CACHE_URL").unwrap_or_default());
    env::set_var("ACTIONS_RUNTIME_TOKEN", env::var("ACTIONS_RUNTIME_TOKEN").unwrap_or_default());
    
    write_cache_config("gha", None)?;
    
    Ok(())
}

fn write_cache_config(backend: &str, extra: Option<(&str, &str)>) -> Result<()> {
    use std::fs;
    use std::io::Write;
    
    let config_dir = dirs::config_dir()
        .context("Failed to get config directory")?
        .join("kindlyguard");
    
    fs::create_dir_all(&config_dir)?;
    
    let config_path = config_dir.join("cache.toml");
    let mut config = fs::File::create(&config_path)?;
    
    writeln!(config, "[cache]")?;
    writeln!(config, "backend = \"{}\"", backend)?;
    
    if let Some((key, value)) = extra {
        writeln!(config, "{} = \"{}\"", key, value)?;
    }
    
    Ok(())
}

fn test_cache_config(ctx: &Context) -> Result<()> {
    ctx.info("Testing cache configuration...");
    
    // Start sccache server
    Command::new("sccache")
        .arg("--start-server")
        .output()
        .context("Failed to start sccache server")?;
    
    // Show stats to verify it's working
    let output = Command::new("sccache")
        .arg("--show-stats")
        .output()
        .context("Failed to get sccache stats")?;
    
    if output.status.success() {
        ctx.success("Cache is working correctly!");
    } else {
        anyhow::bail!("Cache test failed");
    }
    
    Ok(())
}

async fn show_stats(ctx: Context) -> Result<()> {
    let output = Command::new("sccache")
        .arg("--show-stats")
        .output()
        .context("Failed to get sccache stats")?;
    
    if !output.status.success() {
        ctx.warn("sccache server not running, starting it...");
        Command::new("sccache")
            .arg("--start-server")
            .output()?;
        
        // Try again
        let output = Command::new("sccache")
            .arg("--show-stats")
            .output()?;
            
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
    
    // Also show cache location and size
    if let Ok(cache_dir) = env::var("SCCACHE_DIR") {
        ctx.info(&format!("Cache directory: {}", cache_dir));
        
        // Calculate cache size
        if let Ok(size) = calculate_dir_size(&cache_dir) {
            ctx.info(&format!("Cache size: {}", format_size(size)));
        }
    }
    
    Ok(())
}

async fn clear_cache(ctx: Context, force: bool) -> Result<()> {
    if !force {
        use dialoguer::Confirm;
        
        let confirm = Confirm::new()
            .with_prompt("Are you sure you want to clear the cache?")
            .default(false)
            .interact()?;
            
        if !confirm {
            ctx.info("Cache clear cancelled");
            return Ok(());
        }
    }
    
    ctx.info("Clearing compilation cache...");
    
    // Stop sccache server
    Command::new("sccache")
        .arg("--stop-server")
        .output()
        .ok();
    
    // Clear cache directory
    if let Ok(cache_dir) = env::var("SCCACHE_DIR") {
        if std::path::Path::new(&cache_dir).exists() {
            std::fs::remove_dir_all(&cache_dir)
                .context("Failed to remove cache directory")?;
        }
    }
    
    // For S3/Redis backends, we can't easily clear from here
    if env::var("SCCACHE_BUCKET").is_ok() {
        ctx.warn("S3 cache must be cleared manually via AWS console or CLI");
    }
    
    if env::var("SCCACHE_REDIS").is_ok() {
        ctx.warn("Redis cache must be cleared manually via Redis CLI");
    }
    
    ctx.success("Cache cleared successfully!");
    
    Ok(())
}

fn enable_cache(ctx: Context) -> Result<()> {
    ctx.info("Enabling compilation cache for current shell session");
    
    println!("# Add these to your shell environment:");
    println!("export RUSTC_WRAPPER=sccache");
    
    // Load config to get backend-specific vars
    if let Ok(config) = load_cache_config() {
        match config.backend.as_str() {
            "local" => {
                if let Some(dir) = config.cache_dir {
                    println!("export SCCACHE_DIR={}", dir);
                }
            }
            "s3" => {
                if let Some(bucket) = config.s3_bucket {
                    println!("export SCCACHE_BUCKET={}", bucket);
                }
            }
            "redis" => {
                if let Some(url) = config.redis_url {
                    println!("export SCCACHE_REDIS={}", url);
                }
            }
            "gha" => {
                println!("export SCCACHE_GHA_ENABLED=true");
            }
            _ => {}
        }
    }
    
    ctx.info("\nOr run: eval $(cargo xtask cache enable)");
    
    Ok(())
}

fn disable_cache(ctx: Context) -> Result<()> {
    ctx.info("Disabling compilation cache for current shell session");
    
    println!("# Add this to your shell environment:");
    println!("unset RUSTC_WRAPPER");
    
    ctx.info("\nOr run: eval $(cargo xtask cache disable)");
    
    Ok(())
}

#[derive(serde::Deserialize)]
struct CacheConfig {
    backend: String,
    #[serde(default)]
    cache_dir: Option<String>,
    #[serde(default)]
    s3_bucket: Option<String>,
    #[serde(default)]
    redis_url: Option<String>,
}

fn load_cache_config() -> Result<CacheConfig> {
    let config_path = dirs::config_dir()
        .context("Failed to get config directory")?
        .join("kindlyguard")
        .join("cache.toml");
    
    let contents = std::fs::read_to_string(&config_path)?;
    let config: toml::Value = toml::from_str(&contents)?;
    
    Ok(CacheConfig {
        backend: config["cache"]["backend"].as_str().unwrap_or("local").to_string(),
        cache_dir: config["cache"].get("cache_dir").and_then(|v| v.as_str()).map(String::from),
        s3_bucket: config["cache"].get("bucket").and_then(|v| v.as_str()).map(String::from),
        redis_url: config["cache"].get("url").and_then(|v| v.as_str()).map(String::from),
    })
}

fn calculate_dir_size(path: &str) -> Result<u64> {
    use walkdir::WalkDir;
    
    let mut size = 0;
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            size += entry.metadata()?.len();
        }
    }
    
    Ok(size)
}

fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit = 0;
    
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    
    format!("{:.2} {}", size, UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
        assert_eq!(format_size(1500 * 1024 * 1024), "1.46 GB");
    }
}