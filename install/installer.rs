//! KindlyGuard Universal Installer
//! 
//! This installer provides multiple installation methods with automatic
//! fallback and recovery options. It leverages the existing kindly-tools
//! recovery menu system for handling installation failures.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const GITHUB_REPO: &str = "https://github.com/kindly-software-inc/kindly-guard";
const CRATE_NAME: &str = "kindly-tools";

fn main() {
    println!("🛡️  KindlyGuard Universal Installer");
    println!("No cloud. No proxy. Pure stealth.");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Detect environment
    let env_info = detect_environment();
    println!("📍 Environment: {}", env_info);
    println!();

    // Try primary installation method
    if let Err(e) = install_with_cargo() {
        eprintln!("⚠️  Cargo installation failed: {}", e);
        println!();
        
        // Try alternative methods
        if env::var("CI").is_ok() {
            // In CI, try direct download
            println!("🔄 CI environment detected. Trying direct download...");
            if let Err(e) = download_binary_direct() {
                eprintln!("❌ Direct download failed: {}", e);
                show_ci_alternatives();
                std::process::exit(1);
            }
        } else {
            // Interactive environment - show options
            show_interactive_alternatives();
        }
    }
}

fn detect_environment() -> String {
    let mut env_parts = vec![];
    
    // OS and architecture
    env_parts.push(format!("{}/{}", env::consts::OS, env::consts::ARCH));
    
    // Special environments
    if env::var("CI").is_ok() {
        env_parts.push("CI".to_string());
    }
    if env::var("DOCKER_CONTAINER").is_ok() || std::path::Path::new("/.dockerenv").exists() {
        env_parts.push("Docker".to_string());
    }
    if env::var("WSL_DISTRO_NAME").is_ok() {
        env_parts.push("WSL".to_string());
    }
    if env::var("SSH_CONNECTION").is_ok() {
        env_parts.push("SSH".to_string());
    }
    
    env_parts.join(", ")
}

fn install_with_cargo() -> Result<(), String> {
    println!("📦 Installing kindly-tools via cargo...");
    println!("   This may take a few minutes on first install.");
    println!();
    
    let output = Command::new("cargo")
        .args(&["install", "--git", GITHUB_REPO, CRATE_NAME])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("Failed to execute cargo: {}", e))?;
    
    if !output.status.success() {
        return Err("Cargo install failed".to_string());
    }
    
    println!();
    println!("✅ kindly-tools installed successfully!");
    println!();
    
    // Now run kindly-tools install with recovery support
    run_kindly_tools_install()
}

fn run_kindly_tools_install() -> Result<(), String> {
    println!("🚀 Running kindly-tools installer with recovery support...");
    println!();
    
    let status = Command::new(CRATE_NAME)
        .args(&["install", "--interactive"])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("Failed to run kindly-tools: {}", e))?;
    
    if !status.success() {
        return Err("kindly-tools install failed".to_string());
    }
    
    println!();
    println!("🎉 KindlyGuard installed successfully!");
    println!();
    println!("📚 Quick Start:");
    println!("   kindlyguard --help     Show all commands");
    println!("   kindlyguard scan FILE  Scan a file for threats");
    println!("   kindlyguard status     Check protection status");
    println!();
    println!("📖 Documentation: https://github.com/samuel-lucas6/kindly-guard/tree/main/docs");
    
    Ok(())
}

fn download_binary_direct() -> Result<(), String> {
    let platform = detect_platform()?;
    let binary_name = format!("kindly-tools-{}", platform);
    let url = format!(
        "{}/releases/latest/download/{}.tar.gz",
        GITHUB_REPO.replace("https://github.com", "https://github.com"),
        binary_name
    );
    
    println!("📥 Downloading {} ...", binary_name);
    
    // Use curl to download
    let temp_dir = env::temp_dir().join("kindlyguard-install");
    fs::create_dir_all(&temp_dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;
    
    let archive_path = temp_dir.join(format!("{}.tar.gz", binary_name));
    
    let status = Command::new("curl")
        .args(&["-L", "-o", archive_path.to_str().unwrap(), &url])
        .status()
        .map_err(|e| format!("Failed to download: {}", e))?;
    
    if !status.success() {
        return Err("Download failed".to_string());
    }
    
    // Extract
    println!("📂 Extracting...");
    let status = Command::new("tar")
        .args(&["xzf", archive_path.to_str().unwrap()])
        .current_dir(&temp_dir)
        .status()
        .map_err(|e| format!("Failed to extract: {}", e))?;
    
    if !status.success() {
        return Err("Extraction failed".to_string());
    }
    
    // Run the binary
    let binary_path = temp_dir.join(CRATE_NAME);
    let status = Command::new(&binary_path)
        .args(&["install", "--interactive"])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("Failed to run installer: {}", e))?;
    
    if !status.success() {
        return Err("Installation failed".to_string());
    }
    
    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
    
    Ok(())
}

fn detect_platform() -> Result<String, String> {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;
    
    let platform = match (os, arch) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("linux", "arm") => "armv7-unknown-linux-gnueabihf",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => return Err(format!("Unsupported platform: {} {}", os, arch)),
    };
    
    Ok(platform.to_string())
}

fn show_interactive_alternatives() {
    println!("🔄 Alternative Installation Methods:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    
    println!("1️⃣  Using NPM (if available):");
    println!("   npx @kindlyguard/cli install");
    println!();
    
    println!("2️⃣  Download Pre-built Binary:");
    println!("   Visit: {}/releases", GITHUB_REPO);
    println!("   Download the appropriate binary for your platform");
    println!();
    
    println!("3️⃣  Build from Source:");
    println!("   git clone {}.git", GITHUB_REPO);
    println!("   cd kindly-guard");
    println!("   cargo xtask --interactive");
    println!();
    
    println!("4️⃣  Platform Package Managers:");
    println!("   macOS:  brew install kindlyguard (coming soon)");
    println!("   Linux:  snap install kindlyguard (coming soon)");
    println!("   Arch:   yay -S kindlyguard (AUR)");
    println!();
    
    println!("💡 Tip: The NPM method works on all platforms and includes");
    println!("   the same recovery menu system.");
}

fn show_ci_alternatives() {
    println!();
    println!("🤖 CI/CD Installation Instructions:");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("For GitHub Actions:");
    println!("  - uses: kindly-software/setup-kindlyguard@v1");
    println!();
    println!("For other CI systems, set these environment variables:");
    println!("  KINDLYGUARD_INSTALL_DIR=/custom/path");
    println!("  KINDLYGUARD_NO_MODIFY_PATH=1");
    println!();
    println!("Then run:");
    println!("  curl -sSfL {} | bash -s -- --ci", 
        "https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh");
}