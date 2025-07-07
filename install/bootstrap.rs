#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! reqwest = { version = "0.12", features = ["blocking", "json"] }
//! indicatif = "0.17"
//! anyhow = "1.0"
//! colored = "2.1"
//! dirs = "5.0"
//! flate2 = "1.0"
//! tar = "0.4"
//! ```

use anyhow::{Context, Result};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

const GITHUB_REPO: &str = "kindly-software-inc/kindly-guard";
const BINARY_NAME: &str = "kindly-tools";

fn main() -> Result<()> {
    println!("{}", "🛡️  KindlyGuard Installer".bright_blue().bold());
    println!("{}", "No cloud. No proxy. Pure stealth.".bright_green());
    println!();

    // Detect platform
    let platform = detect_platform()?;
    println!("📍 Detected platform: {}", platform.bright_yellow());

    // Try to download and run kindly-tools
    match download_and_run_installer(&platform) {
        Ok(_) => {
            println!("{}", "✅ Installation completed successfully!".bright_green());
            Ok(())
        }
        Err(e) => {
            eprintln!("{}", format!("❌ Installation failed: {}", e).bright_red());
            eprintln!();
            eprintln!("{}", "🔄 Fallback Options:".bright_yellow());
            show_fallback_options(&platform);
            std::process::exit(1);
        }
    }
}

fn detect_platform() -> Result<String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    
    let platform = match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("linux", "arm") => "armv7-unknown-linux-gnueabihf",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => return Err(anyhow::anyhow!("Unsupported platform: {} {}", os, arch)),
    };
    
    Ok(platform.to_string())
}

fn download_and_run_installer(platform: &str) -> Result<()> {
    // Get latest release info
    let client = reqwest::blocking::Client::new();
    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    
    let response = client
        .get(&url)
        .header("User-Agent", "KindlyGuard-Installer")
        .send()
        .context("Failed to fetch release info")?;
    
    if !response.status().is_success() {
        return Err(anyhow::anyhow!("GitHub API request failed: {}", response.status()));
    }
    
    let release: serde_json::Value = response.json()
        .context("Failed to parse release info")?;
    
    let version = release["tag_name"].as_str()
        .ok_or_else(|| anyhow::anyhow!("No tag_name in release"))?;
    
    println!("📦 Latest version: {}", version.bright_cyan());
    
    // Find the asset for our platform
    let asset_name = format!("{}-{}.tar.gz", BINARY_NAME, platform);
    let assets = release["assets"].as_array()
        .ok_or_else(|| anyhow::anyhow!("No assets in release"))?;
    
    let asset = assets.iter()
        .find(|a| a["name"].as_str() == Some(&asset_name))
        .ok_or_else(|| anyhow::anyhow!("No asset found for platform {}", platform))?;
    
    let download_url = asset["browser_download_url"].as_str()
        .ok_or_else(|| anyhow::anyhow!("No download URL"))?;
    
    // Download the binary
    println!("⬇️  Downloading {} ...", asset_name);
    let response = client.get(download_url)
        .header("User-Agent", "KindlyGuard-Installer")
        .send()
        .context("Failed to download binary")?;
    
    let total_size = response.content_length().unwrap_or(0);
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("█▓░"));
    
    let content = response.bytes()
        .context("Failed to read download")?;
    pb.finish();
    
    // Extract and run
    let temp_dir = std::env::temp_dir().join("kindlyguard-install");
    fs::create_dir_all(&temp_dir)?;
    
    let archive_path = temp_dir.join(&asset_name);
    fs::write(&archive_path, content)?;
    
    println!("📂 Extracting...");
    extract_tar_gz(&archive_path, &temp_dir)?;
    
    let binary_path = temp_dir.join(BINARY_NAME);
    #[cfg(unix)]
    {
        fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755))?;
    }
    
    println!("🚀 Running installer with recovery support...");
    println!();
    
    // Run kindly-tools install with full recovery support
    let status = Command::new(&binary_path)
        .args(["install", "--interactive"])
        .status()
        .context("Failed to run installer")?;
    
    if !status.success() {
        return Err(anyhow::anyhow!("Installer exited with error"));
    }
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
    
    Ok(())
}

fn extract_tar_gz(archive_path: &PathBuf, dest_dir: &PathBuf) -> Result<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;
    
    let file = fs::File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.unpack(dest_dir)?;
    Ok(())
}

fn show_fallback_options(platform: &str) {
    println!("1. If you have Rust installed:");
    println!("   {}", format!("cargo install --git https://github.com/{} {}", GITHUB_REPO, BINARY_NAME).bright_white());
    println!();
    
    println!("2. Using NPM (if available):");
    println!("   {}", "npx @kindlyguard/cli install".bright_white());
    println!();
    
    println!("3. Direct download:");
    println!("   Visit: {}", format!("https://github.com/{}/releases", GITHUB_REPO).bright_white());
    println!("   Download: {}", format!("{}-{}.tar.gz", BINARY_NAME, platform).bright_white());
    println!();
    
    println!("4. Build from source:");
    println!("   {}", format!("git clone https://github.com/{}.git", GITHUB_REPO).bright_white());
    println!("   {}", "cd kindly-guard".bright_white());
    println!("   {}", "cargo xtask --interactive".bright_white());
}