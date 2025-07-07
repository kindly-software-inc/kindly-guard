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

//! Recovery methods for installation failures

use anyhow::Result;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Select};
use crate::installer::platform::{Platform, LinuxDistro};

/// Recovery methods for installation failures
#[derive(Debug, Clone, Copy)]
pub enum RecoveryMethod {
    TryWithSudo,
    InstallToHome,
    UseDifferentPackageManager,
    DownloadBinaryDirectly,
    OfflineInstallation,
    ShowDiagnostics,
    Cancel,
}

impl RecoveryMethod {
    fn description(&self) -> &'static str {
        match self {
            Self::TryWithSudo => "Try again with sudo (requires password)",
            Self::InstallToHome => "Install to home directory (~/.local/bin)",
            Self::UseDifferentPackageManager => "Use a different package manager",
            Self::DownloadBinaryDirectly => "Download pre-built binary directly",
            Self::OfflineInstallation => "Offline installation from local file",
            Self::ShowDiagnostics => "Show detailed diagnostics",
            Self::Cancel => "Cancel installation",
        }
    }

    fn emoji(&self) -> &'static str {
        match self {
            Self::TryWithSudo => "🔐",
            Self::InstallToHome => "🏠",
            Self::UseDifferentPackageManager => "📦",
            Self::DownloadBinaryDirectly => "💿",
            Self::OfflineInstallation => "📴",
            Self::ShowDiagnostics => "🔍",
            Self::Cancel => "❌",
        }
    }
}

/// Show recovery menu to user
pub fn show_recovery_menu() -> Result<Option<RecoveryMethod>> {
    println!();
    println!("{}", "Installation failed. Let's try to fix this!".yellow().bold());
    println!();
    
    let methods = vec![
        RecoveryMethod::TryWithSudo,
        RecoveryMethod::InstallToHome,
        RecoveryMethod::UseDifferentPackageManager,
        RecoveryMethod::DownloadBinaryDirectly,
        RecoveryMethod::OfflineInstallation,
        RecoveryMethod::ShowDiagnostics,
        RecoveryMethod::Cancel,
    ];

    let items: Vec<String> = methods
        .iter()
        .map(|m| format!("{} {}", m.emoji(), m.description()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose a recovery option")
        .items(&items)
        .default(0)
        .interact_opt()?;

    Ok(selection.map(|i| methods[i]))
}

/// Execute recovery method based on user selection
pub async fn execute_recovery(
    method: RecoveryMethod,
    original_method: &str,
    package: &str,
    platform: &Platform,
) -> Result<()> {
    match method {
        RecoveryMethod::TryWithSudo => {
            println!("\n{} Retrying with sudo privileges...", "🔐".bright_cyan());
            match original_method {
                "cargo" => {
                    println!("{} Command:", "📋".cyan());
                    println!("   {} sudo cargo install {}", "$".dimmed(), package.bright_white());
                    println!("\n{} Note: Using sudo with cargo is not recommended", "⚠️".yellow());
                    println!("{} Consider using --root ~/.local/cargo instead", "💡".yellow());
                }
                "npm" => {
                    println!("{} Command:", "📋".cyan());
                    println!("   {} sudo npm install -g {}", "$".dimmed(), package.bright_white());
                    println!("\n{} This will install globally with root privileges", "⚠️".yellow());
                }
                _ => return Err(anyhow::anyhow!("Sudo not applicable for this method")),
            }
        }
        RecoveryMethod::InstallToHome => {
            println!("\n{} Installing to home directory...", "🏠".bright_cyan());
            match original_method {
                "cargo" => {
                    println!("{} Command:", "📋".cyan());
                    println!("   {} cargo install --root ~/.local/cargo {}", "$".dimmed(), package.bright_white());
                    println!("\n{} Add to PATH:", "💡".yellow());
                    println!("   {} export PATH=$HOME/.local/cargo/bin:$PATH", "$".dimmed());
                }
                "npm" => {
                    println!("{} Commands:", "📋".cyan());
                    println!("   {} mkdir -p ~/.local/npm", "$".dimmed());
                    println!("   {} npm config set prefix ~/.local/npm", "$".dimmed());
                    println!("   {} npm install -g {}", "$".dimmed(), package.bright_white());
                    println!("\n{} Add to PATH:", "💡".yellow());
                    println!("   {} export PATH=$HOME/.local/npm/bin:$PATH", "$".dimmed());
                }
                _ => {
                    println!("{} Manual installation to ~/.local/bin:", "📋".cyan());
                    println!("   1️⃣  Download the binary");
                    println!("   2️⃣  {} mkdir -p ~/.local/bin", "$".dimmed());
                    println!("   3️⃣  {} mv kindlyguard ~/.local/bin/", "$".dimmed());
                    println!("   4️⃣  {} chmod +x ~/.local/bin/kindlyguard", "$".dimmed());
                }
            }
        }
        RecoveryMethod::UseDifferentPackageManager => {
            show_alternative_package_managers(platform);
        }
        RecoveryMethod::DownloadBinaryDirectly => {
            show_direct_download_instructions(platform);
        }
        RecoveryMethod::OfflineInstallation => {
            show_offline_installation_guide();
        }
        RecoveryMethod::ShowDiagnostics => {
            run_diagnostics(original_method).await?;
        }
        RecoveryMethod::Cancel => {
            println!("\n{} Installation cancelled", "❌".red());
            return Ok(());
        }
    }
    
    Ok(())
}

fn show_alternative_package_managers(platform: &Platform) {
    println!("\n{} Alternative package managers:", "📦".cyan());
    match platform {
        Platform::MacOS => {
            println!("{} Homebrew:", "🍺".green());
            println!("   {} brew tap samduchaine/tap", "$".dimmed());
            println!("   {} brew install kindlyguard", "$".dimmed());
            println!("\n{} MacPorts:", "🌊".green());
            println!("   {} sudo port install kindlyguard", "$".dimmed());
        }
        Platform::Linux(_) => {
            println!("{} Snap:", "📦".green());
            println!("   {} sudo snap install kindlyguard", "$".dimmed());
            println!("\n{} Flatpak:", "📦".green());
            println!("   {} flatpak install flathub com.kindly.guard", "$".dimmed());
            println!("\n{} AppImage:", "📦".green());
            println!("   Download from releases page");
        }
        Platform::Windows => {
            println!("{} Chocolatey:", "🍫".green());
            println!("   {} choco install kindlyguard", "$".dimmed());
            println!("\n{} Scoop:", "🔷".green());
            println!("   {} scoop install kindlyguard", "$".dimmed());
            println!("\n{} WinGet:", "🔶".green());
            println!("   {} winget install Kindly.KindlyGuard", "$".dimmed());
        }
        Platform::Unknown => {
            println!("Platform-specific package managers not detected");
        }
    }
}

fn show_direct_download_instructions(platform: &Platform) {
    println!("\n{} Direct binary download:", "💿".cyan());
    println!("{} Visit:", "🌐".cyan());
    println!("   {}", "https://github.com/samduchaine/kindly-guard/releases".blue().underline());
    
    match platform {
        Platform::MacOS => {
            let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
            println!("\n{} Download: kindlyguard-{}-apple-darwin.tar.gz", "🍎", arch);
        }
        Platform::Linux(_) => {
            println!("\n{} Download: kindlyguard-x86_64-unknown-linux-gnu.tar.gz", "🐧");
        }
        Platform::Windows => {
            println!("\n{} Download: kindlyguard-x86_64-pc-windows-msvc.zip", "🪟");
        }
        _ => {}
    }
    
    println!("\n{} Manual installation steps:", "📋".cyan());
    println!("   1️⃣  Download the appropriate file");
    println!("   2️⃣  Extract the archive");
    println!("   3️⃣  Move binary to PATH location");
    println!("   4️⃣  Make it executable (Unix/Linux/macOS)");
}

fn show_offline_installation_guide() {
    println!("\n{} Offline installation:", "📴".cyan());
    println!("{} For offline environments:", "💡".yellow());
    println!("\n{} Steps:", "📋".cyan());
    println!("   1️⃣  Download on a connected machine:");
    println!("      - Binary from GitHub releases");
    println!("      - Or npm package: {} npm pack kindlyguard", "$".dimmed());
    println!("   2️⃣  Transfer to target machine via USB/network");
    println!("   3️⃣  Install locally:");
    println!("      - Binary: Copy to /usr/local/bin/");
    println!("      - npm: {} npm install -g kindlyguard-*.tgz", "$".dimmed());
}

async fn run_diagnostics(original_method: &str) -> Result<()> {
    println!("\n{} Running diagnostics...", "🔍".cyan());
    
    // Check disk space
    println!("\n{} Disk space:", "💾".yellow());
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("df").args(["-h", "."]).output() {
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
    }
    
    // Check permissions
    println!("\n{} Permissions:", "🔒".yellow());
    match original_method {
        "npm" => {
            if let Ok(output) = std::process::Command::new("npm")
                .args(["config", "get", "prefix"])
                .output()
            {
                let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                println!("   npm prefix: {}", prefix);
                
                #[cfg(unix)]
                {
                    if let Ok(output) = std::process::Command::new("ls")
                        .args(["-ld", &prefix])
                        .output()
                    {
                        println!("   {}", String::from_utf8_lossy(&output.stdout).trim());
                    }
                }
            }
        }
        "cargo" => {
            if let Some(home) = dirs::home_dir() {
                let cargo_home = home.join(".cargo");
                println!("   CARGO_HOME: {:?}", cargo_home);
                
                #[cfg(unix)]
                {
                    if let Ok(output) = std::process::Command::new("ls")
                        .args(["-ld", cargo_home.to_str().unwrap_or("")])
                        .output()
                    {
                        println!("   {}", String::from_utf8_lossy(&output.stdout).trim());
                    }
                }
            }
        }
        _ => {}
    }
    
    // Check network
    println!("\n{} Network connectivity:", "🌐".yellow());
    println!("   Testing connection to GitHub...");
    match reqwest::get("https://api.github.com").await {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("   {} GitHub API accessible", "✅".green());
            } else {
                println!("   {} GitHub API returned: {}", "❌".red(), resp.status());
            }
        }
        Err(e) => {
            println!("   {} Network error: {}", "❌".red(), e);
        }
    }
    
    // Platform-specific diagnostics
    show_platform_diagnostics().await?;
    
    Ok(())
}

async fn show_platform_diagnostics() -> Result<()> {
    println!("\n{} Platform information:", "🖥️".yellow());
    
    // OS info
    println!("   OS: {}", std::env::consts::OS);
    println!("   Architecture: {}", std::env::consts::ARCH);
    
    // Environment checks
    if std::env::var("DOCKER_CONTAINER").is_ok() || std::path::Path::new("/.dockerenv").exists() {
        println!("   {} Running in Docker container", "🐳".blue());
    }
    
    if std::env::var("WSL_DISTRO_NAME").is_ok() {
        println!("   {} Running in WSL", "🪟".blue());
    }
    
    if std::env::var("CI").is_ok() {
        println!("   {} Running in CI/CD environment", "🤖".blue());
    }
    
    Ok(())
}

/// Show installation tips based on the error
pub fn show_installation_tips(error: &anyhow::Error) {
    println!();
    println!("{} Installation Tips:", "💡".bright_cyan());
    
    let error_str = error.to_string().to_lowercase();
    
    if error_str.contains("permission") || error_str.contains("denied") {
        println!("  • Try running with sudo if installing system-wide");
        println!("  • Consider installing to your home directory instead");
        println!("  • Check if the installation directory is writable");
    }
    
    if error_str.contains("network") || error_str.contains("connection") {
        println!("  • Check your internet connection");
        println!("  • Try using a different DNS server (e.g., 8.8.8.8)");
        println!("  • Check if you're behind a proxy and set HTTP_PROXY");
        println!("  • Consider offline installation if network is restricted");
    }
    
    if error_str.contains("space") || error_str.contains("disk") {
        println!("  • Free up disk space (need at least 100MB)");
        println!("  • Try installing to a different location");
        println!("  • Clean up temporary files with 'rm -rf /tmp/*'");
    }
    
    if error_str.contains("not found") || error_str.contains("command") {
        println!("  • Make sure required tools are installed");
        println!("  • Update your PATH environment variable");
        println!("  • Try using a different installation method");
    }
    
    println!();
    println!("📚 For more help, visit: {}", 
        "https://github.com/samduchaine/kindly-guard/wiki/Installation".bright_blue());
}

/// Platform-specific recovery suggestions
pub fn get_platform_specific_recovery(platform: &Platform) -> Vec<String> {
    match platform {
        Platform::Linux(distro) => {
            match distro {
                LinuxDistro::Ubuntu | LinuxDistro::Debian => vec![
                    "Try: sudo apt update && sudo apt install -y build-essential".to_string(),
                    "Enable universe repository: sudo add-apt-repository universe".to_string(),
                    "Install via snap: sudo snap install kindlyguard".to_string(),
                ],
                LinuxDistro::Fedora | LinuxDistro::CentOS | LinuxDistro::RHEL => vec![
                    "Try: sudo dnf install -y gcc make".to_string(),
                    "Enable EPEL repository for more packages".to_string(),
                    "Use rpm directly: sudo rpm -i kindlyguard.rpm".to_string(),
                ],
                LinuxDistro::Arch => vec![
                    "Install from AUR: yay -S kindlyguard".to_string(),
                    "Build from source: makepkg -si".to_string(),
                    "Check Arch Wiki for troubleshooting".to_string(),
                ],
                LinuxDistro::Alpine => vec![
                    "Install dependencies: apk add --no-cache libc6-compat".to_string(),
                    "Use static binary for musl libc".to_string(),
                    "Consider using Docker instead".to_string(),
                ],
                _ => vec![
                    "Try downloading the binary directly".to_string(),
                    "Build from source: cargo install kindlyguard".to_string(),
                ],
            }
        }
        Platform::MacOS => vec![
            "Install Xcode Command Line Tools: xcode-select --install".to_string(),
            "Install Homebrew: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"".to_string(),
            "Try: brew install kindlyguard".to_string(),
            "Check Security & Privacy settings if blocked".to_string(),
        ],
        Platform::Windows => vec![
            "Run as Administrator".to_string(),
            "Disable Windows Defender temporarily".to_string(),
            "Install Visual C++ Redistributables".to_string(),
            "Try Windows Package Manager: winget install kindlyguard".to_string(),
        ],
        Platform::Unknown => vec![
            "Identify your platform: uname -a".to_string(),
            "Try generic Linux binary".to_string(),
            "Build from source if possible".to_string(),
        ],
    }
}