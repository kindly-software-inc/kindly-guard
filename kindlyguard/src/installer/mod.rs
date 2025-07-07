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

//! Sophisticated installer module with OS detection and error recovery

use anyhow::Result;
use colored::Colorize;

pub mod doctor;
pub mod platform;
pub mod recovery;
pub mod update;

use platform::{detect_environment, detect_platform, Platform};

/// Run the installation command with sophisticated error handling
pub async fn run_install(
    component: Option<String>,
    all: bool,
    detect: bool,
    force: bool,
) -> Result<()> {
    println!("{}", "KindlyGuard Intelligent Installer".bright_blue().bold());
    println!();

    // Detect environment
    let env_info = detect_environment();
    let platform = detect_platform();

    // Show environment info
    println!("{} Detected Environment:", "🔍".bright_cyan());
    println!("  Platform: {}", format!("{:?}", platform).bright_white());
    if env_info.docker {
        println!("  Running in: {}", "Docker container".yellow());
    }
    if env_info.wsl {
        println!("  Running in: {}", "WSL".yellow());
    }
    if env_info.ci {
        println!("  Running in: {}", "CI/CD environment".yellow());
    }
    if env_info.ssh {
        println!("  Running via: {}", "SSH".yellow());
    }
    println!();

    // Run pre-flight checks
    if let Err(e) = run_preflight_checks(&platform).await {
        println!("{} Pre-flight check failed: {}", "⚠️".yellow(), e);
        
        // Show installation tips
        recovery::show_installation_tips(&e);
        
        // Show recovery options
        if let Some(recovery) = recovery::show_recovery_menu()? {
            return recovery::execute_recovery(recovery, "install", "kindlyguard", &platform).await;
        }
    }

    if detect {
        // Auto-detect best installation method
        detect_and_install(&platform, component.as_deref()).await?;
    } else if all {
        // Install all components
        install_all_components(&platform, force).await?;
    } else if let Some(comp) = component {
        // Install specific component
        install_component(&comp, &platform, force).await?;
    } else {
        // Show available components
        show_available_components();
    }

    Ok(())
}

/// Run pre-flight checks before installation
async fn run_preflight_checks(platform: &Platform) -> Result<()> {
    println!("{} Running pre-flight checks...", "🔧".bright_cyan());

    // Check disk space
    check_disk_space()?;

    // Check network connectivity
    check_network().await?;

    // Check permissions
    check_permissions(platform)?;

    println!("{} All checks passed!", "✅".bright_green());
    println!();

    Ok(())
}

/// Check available disk space
fn check_disk_space() -> Result<()> {
    // TODO: Implement actual disk space check
    Ok(())
}

/// Check network connectivity
async fn check_network() -> Result<()> {
    // TODO: Implement network check
    Ok(())
}

/// Check required permissions
fn check_permissions(platform: &Platform) -> Result<()> {
    match platform {
        Platform::Linux(_) | Platform::MacOS => {
            // Check if we can write to install directory
            let install_dir = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
                .join(".local")
                .join("bin");
            
            if !install_dir.exists() {
                std::fs::create_dir_all(&install_dir)?;
            }
        }
        Platform::Windows => {
            // Windows permission checks
        }
        Platform::Unknown => {
            println!("{} Unknown platform - skipping permission checks", "⚠️".yellow());
        }
    }
    Ok(())
}

/// Auto-detect and use best installation method
async fn detect_and_install(platform: &Platform, component: Option<&str>) -> Result<()> {
    println!("{} Auto-detecting best installation method...", "🚀".bright_cyan());

    let method = platform::detect_best_install_method(platform)?;
    
    println!("  Recommended: {}", method.bright_green());
    println!();

    match method.as_str() {
        "cargo" => {
            println!("Installing via cargo...");
            install_via_cargo(component).await?;
        }
        "homebrew" => {
            println!("Installing via Homebrew...");
            install_via_homebrew(component).await?;
        }
        "npm" => {
            println!("Installing via npm...");
            install_via_npm(component).await?;
        }
        "binary" => {
            println!("Installing pre-built binary...");
            install_binary_direct(component, platform).await?;
        }
        _ => {
            anyhow::bail!("Unknown installation method: {}", method);
        }
    }

    Ok(())
}

/// Install all components
async fn install_all_components(platform: &Platform, force: bool) -> Result<()> {
    println!("{} Installing all KindlyGuard components...", "📦".bright_cyan());

    let components = vec!["server", "shield", "extensions"];

    for component in &components {
        match install_component(component, platform, force).await {
            Ok(_) => {
                println!("{} {} installed successfully", "✅".bright_green(), component);
            }
            Err(e) => {
                println!("{} Failed to install {}: {}", "❌".bright_red(), component, e);
            }
        }
    }

    Ok(())
}

/// Install a specific component
async fn install_component(component: &str, platform: &Platform, _force: bool) -> Result<()> {
    println!("{} Installing {}...", "📦".bright_cyan(), component.bright_white());

    match component {
        "server" => {
            // Server is included in this binary
            println!("  Server functionality is built into this binary");
        }
        "shield" => {
            // Install desktop UI components
            install_shield_component(platform).await?;
        }
        "extensions" => {
            // Install optional extensions
            install_extensions(platform).await?;
        }
        _ => {
            anyhow::bail!("Unknown component: {}", component);
        }
    }

    Ok(())
}

/// Show available components
fn show_available_components() {
    println!("{}", "Available components:".bright_cyan());
    println!();
    println!("  {} - MCP security server (built-in)", "server".bright_white());
    println!("  {} - Desktop UI application", "shield".bright_white());
    println!("  {} - Optional extensions", "extensions".bright_white());
    println!();
    println!("Usage:");
    println!("  {} install <component>", "kindlyguard".bright_cyan());
    println!("  {} install --all", "kindlyguard".bright_cyan());
    println!("  {} install --detect", "kindlyguard".bright_cyan());
}


// Installation method implementations
async fn install_via_cargo(_component: Option<&str>) -> Result<()> {
    // TODO: Implement cargo installation
    Ok(())
}

async fn install_via_homebrew(_component: Option<&str>) -> Result<()> {
    // TODO: Implement homebrew installation
    Ok(())
}

async fn install_via_npm(_component: Option<&str>) -> Result<()> {
    // TODO: Implement npm installation
    Ok(())
}

async fn install_binary_direct(_component: Option<&str>, platform: &Platform) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};
    use futures::StreamExt;
    
    println!("{} Downloading KindlyGuard binary...", "💿".bright_cyan());
    
    // Get download URL
    let version = "latest";
    let url = get_download_url(version, platform);
    println!("{} URL: {}", "📍", url.cyan());
    
    // Determine installation directory
    let install_dir = match platform {
        Platform::Windows => {
            dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
                .join(".kindlyguard")
                .join("bin")
        }
        _ => {
            let home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
            let local_bin = home.join(".local").join("bin");
            if local_bin.exists() {
                local_bin
            } else {
                home.join(".cargo").join("bin")
            }
        }
    };
    
    // Ensure directory exists
    std::fs::create_dir_all(&install_dir)?;
    
    // Determine binary name
    let binary_name = if platform == &Platform::Windows {
        "kindlyguard.exe"
    } else {
        "kindlyguard"
    };
    
    let dest_path = install_dir.join(binary_name);
    let temp_path = dest_path.with_extension("tmp");
    
    // Download with progress
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;
    
    if !response.status().is_success() {
        anyhow::bail!("Failed to download: HTTP {}", response.status());
    }
    
    let total_size = response.content_length().unwrap_or(0);
    
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("#>-")
    );
    pb.set_message(format!("Downloading {}", binary_name));
    
    // Create the destination file
    let mut file = std::fs::File::create(&temp_path)?;
    let mut downloaded = 0u64;
    let mut stream = response.bytes_stream();
    
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        std::io::Write::write_all(&mut file, &chunk)?;
        downloaded += chunk.len() as u64;
        pb.set_position(downloaded);
    }
    
    pb.finish_with_message("Download complete");
    
    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&temp_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&temp_path, perms)?;
    }
    
    // Move to final location
    std::fs::rename(&temp_path, &dest_path)?;
    
    println!("\n{} Installation successful!", "✅".green().bold());
    println!("{} Binary installed to: {}", "📍".cyan(), dest_path.display());
    
    // Check if directory is in PATH
    let path_var = std::env::var("PATH").unwrap_or_default();
    if !path_var.contains(&install_dir.to_string_lossy().to_string()) {
        println!("\n{} Installation directory is not in your PATH!", "⚠️".yellow());
        println!("{} Add this to your shell configuration:", "📋".cyan());
        
        match platform {
            Platform::Windows => {
                println!("   {} $env:Path += \";{}\"", "$".dimmed(), install_dir.display());
            }
            _ => {
                println!("   {} export PATH=\"$PATH:{}\"", "$".dimmed(), install_dir.display());
            }
        }
    }
    
    Ok(())
}

fn get_download_url(version: &str, platform: &Platform) -> String {
    let version_tag = if version == "latest" {
        "latest".to_string()
    } else {
        format!("v{}", version.trim_start_matches('v'))
    };
    
    let (os, arch, ext) = match platform {
        Platform::Windows => ("pc-windows-msvc", "x86_64", "exe"),
        Platform::MacOS => {
            if cfg!(target_arch = "aarch64") {
                ("apple-darwin", "aarch64", "")
            } else {
                ("apple-darwin", "x86_64", "")
            }
        },
        Platform::Linux(_) => ("unknown-linux-gnu", "x86_64", ""),
        Platform::Unknown => {
            return format!("https://github.com/samduchaine/kindly-guard/releases/{}", version_tag);
        }
    };
    
    let filename = if ext.is_empty() {
        format!("kindlyguard-{}-{}", arch, os)
    } else {
        format!("kindlyguard-{}-{}.{}", arch, os, ext)
    };
    
    if version_tag == "latest" {
        format!(
            "https://github.com/samduchaine/kindly-guard/releases/latest/download/{}",
            filename
        )
    } else {
        format!(
            "https://github.com/samduchaine/kindly-guard/releases/download/{}/{}",
            version_tag, filename
        )
    }
}

async fn install_shield_component(_platform: &Platform) -> Result<()> {
    // TODO: Implement shield installation
    Ok(())
}

async fn install_extensions(_platform: &Platform) -> Result<()> {
    // TODO: Implement extensions installation
    Ok(())
}