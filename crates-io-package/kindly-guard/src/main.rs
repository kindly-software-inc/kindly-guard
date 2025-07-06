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

use anyhow::{Context, Result};
use clap::Parser;
use dirs::home_dir;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tar::Archive;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_REPO: &str = "samduchaine/kindly-guard";
const BINARY_NAME: &str = "kindly-guard";

#[derive(Parser)]
#[command(
    name = "kindlyguard",
    about = "Security-focused MCP server for AI protection",
    version = VERSION
)]
struct Cli {
    /// Force download even if binary exists
    #[arg(long)]
    force_download: bool,

    /// Show version information
    #[arg(long)]
    version: bool,

    /// All other arguments to pass to kindly-guard
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn get_binary_dir() -> Result<PathBuf> {
    let home = home_dir().context("Could not find home directory")?;
    let binary_dir = home.join(".kindlyguard").join("bin");
    fs::create_dir_all(&binary_dir)?;
    Ok(binary_dir)
}

fn get_binary_path() -> Result<PathBuf> {
    Ok(get_binary_dir()?.join(BINARY_NAME))
}

fn get_target_triple() -> &'static str {
    if cfg!(target_os = "linux") {
        if cfg!(target_arch = "x86_64") {
            "x86_64-unknown-linux-gnu"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-unknown-linux-gnu"
        } else {
            panic!("Unsupported Linux architecture")
        }
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "x86_64") {
            "x86_64-apple-darwin"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            panic!("Unsupported macOS architecture")
        }
    } else if cfg!(target_os = "windows") {
        if cfg!(target_arch = "x86_64") {
            "x86_64-pc-windows-msvc"
        } else {
            panic!("Unsupported Windows architecture")
        }
    } else {
        panic!("Unsupported operating system")
    }
}

fn download_binary() -> Result<()> {
    println!("Downloading KindlyGuard binary...");

    // Get the latest release
    let client = reqwest::blocking::Client::new();
    let releases_url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);
    
    let release: GithubRelease = client
        .get(&releases_url)
        .header("User-Agent", "kindlyguard-installer")
        .send()
        .context("Failed to fetch release information")?
        .json()
        .context("Failed to parse release information")?;

    // Find the appropriate asset
    let target = get_target_triple();
    let asset_name = format!("kindly-guard-{}-{}.tar.gz", release.tag_name.trim_start_matches('v'), target);
    
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .context(format!("Could not find binary for target: {}", target))?;

    // Download the asset
    print!("Downloading from {}... ", asset.browser_download_url);
    io::stdout().flush()?;
    
    let response = client
        .get(&asset.browser_download_url)
        .header("User-Agent", "kindlyguard-installer")
        .send()
        .context("Failed to download binary")?;

    let bytes = response.bytes().context("Failed to read response bytes")?;
    println!("done.");

    // Extract the tarball
    print!("Extracting binary... ");
    io::stdout().flush()?;
    
    let tar_gz = GzDecoder::new(&bytes[..]);
    let mut archive = Archive::new(tar_gz);
    
    let binary_dir = get_binary_dir()?;
    let temp_dir = binary_dir.join("temp");
    fs::create_dir_all(&temp_dir)?;
    
    archive.unpack(&temp_dir).context("Failed to extract archive")?;
    
    // Find and move the binary
    let extracted_binary = temp_dir.join(BINARY_NAME);
    if !extracted_binary.exists() {
        // Try with .exe extension on Windows
        let extracted_binary_exe = temp_dir.join(format!("{}.exe", BINARY_NAME));
        if extracted_binary_exe.exists() {
            fs::rename(&extracted_binary_exe, get_binary_path()?)?;
        } else {
            return Err(anyhow::anyhow!("Binary not found in archive"));
        }
    } else {
        fs::rename(&extracted_binary, get_binary_path()?)?;
    }
    
    // Clean up temp directory
    fs::remove_dir_all(&temp_dir)?;
    
    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let binary_path = get_binary_path()?;
        let mut perms = fs::metadata(&binary_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&binary_path, perms)?;
    }
    
    println!("done.");
    println!("KindlyGuard binary installed to: {}", get_binary_path()?.display());
    
    Ok(())
}

fn run_binary(args: Vec<String>) -> Result<()> {
    let binary_path = get_binary_path()?;
    
    let mut cmd = Command::new(&binary_path);
    cmd.args(&args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    
    let status = cmd.status().context("Failed to run kindly-guard")?;
    
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    if cli.version {
        println!("kindlyguard installer version: {}", VERSION);
        return Ok(());
    }
    
    let binary_path = get_binary_path()?;
    
    // Check if binary exists or if force download is requested
    if cli.force_download || !binary_path.exists() {
        download_binary()?;
    }
    
    // Run the binary with passed arguments
    run_binary(cli.args)?;
    
    Ok(())
}