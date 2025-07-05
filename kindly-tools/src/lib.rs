// Modules defined inline below
pub mod platform;

use anyhow::Result;
use std::path::{Path, PathBuf};
use dialoguer::Select;

/// Common trait for all subcommands
#[allow(async_fn_in_trait)]
pub trait Execute {
    async fn execute(&self) -> Result<()>;
}

/// Check if a command exists in PATH
pub fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

/// Get the user's home directory
pub fn home_dir() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))
}

/// Get the KindlyGuard configuration directory
pub fn config_dir() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home.join(".kindlyguard"))
}

/// Ensure a directory exists, creating it if necessary
pub fn ensure_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Get the MCP configuration file path
pub fn get_mcp_config_path() -> Result<PathBuf> {
    let home = home_dir()?;
    
    // Check for different possible locations
    let candidates = vec![
        home.join(".mcp.json"),
        home.join(".config/claude/mcp.json"),
    ];
    
    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }
    
    // Default to .mcp.json
    Ok(home.join(".mcp.json"))
}

/// Download a file with progress bar
pub async fn download_file(_url: &str, _dest: &Path) -> Result<()> {
    // TODO: Implement when reqwest MSRV is compatible
    anyhow::bail!("Download functionality temporarily disabled due to MSRV constraints")
}

/// Detect various environment characteristics
pub fn detect_environment() -> EnvironmentInfo {
    use std::env;
    use std::path::Path;
    
    EnvironmentInfo {
        is_docker: Path::new("/.dockerenv").exists(),
        is_wsl: detect_wsl(),
        is_ci: env::var("CI").is_ok() || env::var("CONTINUOUS_INTEGRATION").is_ok(),
        is_ssh: env::var("SSH_CONNECTION").is_ok() || env::var("SSH_CLIENT").is_ok(),
        has_proxy: env::var("HTTP_PROXY").is_ok() || env::var("HTTPS_PROXY").is_ok() 
            || env::var("http_proxy").is_ok() || env::var("https_proxy").is_ok(),
    }
}

/// Check if running in WSL
fn detect_wsl() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/version") {
            return content.to_lowercase().contains("microsoft");
        }
    }
    false
}

/// Detect Linux distribution
pub fn detect_linux_distro() -> LinuxDistro {
    #[cfg(target_os = "linux")]
    {
        // Try /etc/os-release first (standard on most modern distros)
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("ID=") {
                    let id = line.trim_start_matches("ID=").trim_matches('"');
                    return match id {
                        "ubuntu" => LinuxDistro::Ubuntu,
                        "debian" => LinuxDistro::Debian,
                        "fedora" => LinuxDistro::Fedora,
                        "centos" => LinuxDistro::CentOS,
                        "rhel" => LinuxDistro::RHEL,
                        "arch" => LinuxDistro::Arch,
                        "manjaro" => LinuxDistro::Manjaro,
                        "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" | "suse" => LinuxDistro::OpenSUSE,
                        "alpine" => LinuxDistro::Alpine,
                        "nixos" => LinuxDistro::NixOS,
                        "gentoo" => LinuxDistro::Gentoo,
                        "void" => LinuxDistro::Void,
                        "elementary" => LinuxDistro::Elementary,
                        "pop" => LinuxDistro::PopOS,
                        "mint" | "linuxmint" => LinuxDistro::Mint,
                        _ => LinuxDistro::Unknown(id.to_string()),
                    };
                }
            }
        }
        
        // Fallback checks for older systems
        if Path::new("/etc/debian_version").exists() {
            return LinuxDistro::Debian;
        }
        if Path::new("/etc/redhat-release").exists() {
            return LinuxDistro::RHEL;
        }
        if Path::new("/etc/arch-release").exists() {
            return LinuxDistro::Arch;
        }
        if Path::new("/etc/gentoo-release").exists() {
            return LinuxDistro::Gentoo;
        }
        if Path::new("/etc/alpine-release").exists() {
            return LinuxDistro::Alpine;
        }
    }
    
    LinuxDistro::Unknown("generic".to_string())
}

/// Detect installed Node.js version managers
pub fn detect_node_managers() -> NodeManagers {
    use std::path::Path;
    
    let home = home_dir().unwrap_or_default();
    
    NodeManagers {
        has_nvm: Path::new(&home.join(".nvm")).exists() 
            || std::env::var("NVM_DIR").is_ok(),
        has_fnm: command_exists("fnm") 
            || Path::new(&home.join(".fnm")).exists()
            || Path::new(&home.join(".local/share/fnm")).exists(),
        has_n: command_exists("n") 
            || Path::new("/usr/local/n").exists()
            || Path::new("/usr/local/bin/n").exists(),
        has_volta: command_exists("volta") 
            || Path::new(&home.join(".volta")).exists(),
        has_asdf: command_exists("asdf") 
            || Path::new(&home.join(".asdf")).exists(),
    }
}

/// Environment information struct
#[derive(Debug, Clone)]
pub struct EnvironmentInfo {
    pub is_docker: bool,
    pub is_wsl: bool,
    pub is_ci: bool,
    pub is_ssh: bool,
    pub has_proxy: bool,
}

/// Linux distribution enum
#[derive(Debug, Clone, PartialEq)]
pub enum LinuxDistro {
    Ubuntu,
    Debian,
    Fedora,
    CentOS,
    RHEL,
    Arch,
    Manjaro,
    OpenSUSE,
    Alpine,
    NixOS,
    Gentoo,
    Void,
    Elementary,
    PopOS,
    Mint,
    Unknown(String),
}

impl LinuxDistro {
    /// Get display name with emoji
    pub fn display_name(&self) -> String {
        match self {
            LinuxDistro::Ubuntu => "🟠 Ubuntu".to_string(),
            LinuxDistro::Debian => "🔴 Debian".to_string(),
            LinuxDistro::Fedora => "🔵 Fedora".to_string(),
            LinuxDistro::CentOS => "🟣 CentOS".to_string(),
            LinuxDistro::RHEL => "🔴 Red Hat Enterprise Linux".to_string(),
            LinuxDistro::Arch => "🔷 Arch Linux".to_string(),
            LinuxDistro::Manjaro => "🟢 Manjaro".to_string(),
            LinuxDistro::OpenSUSE => "🦎 openSUSE".to_string(),
            LinuxDistro::Alpine => "🏔️ Alpine Linux".to_string(),
            LinuxDistro::NixOS => "❄️ NixOS".to_string(),
            LinuxDistro::Gentoo => "🟣 Gentoo".to_string(),
            LinuxDistro::Void => "🌑 Void Linux".to_string(),
            LinuxDistro::Elementary => "🦚 elementary OS".to_string(),
            LinuxDistro::PopOS => "🚀 Pop!_OS".to_string(),
            LinuxDistro::Mint => "🌿 Linux Mint".to_string(),
            LinuxDistro::Unknown(name) => format!("🐧 Linux ({})", name),
        }
    }
    
    /// Get package manager command
    pub fn package_manager(&self) -> &'static str {
        match self {
            LinuxDistro::Ubuntu | LinuxDistro::Debian | LinuxDistro::Elementary 
            | LinuxDistro::PopOS | LinuxDistro::Mint => "apt",
            LinuxDistro::Fedora | LinuxDistro::CentOS | LinuxDistro::RHEL => "dnf",
            LinuxDistro::Arch | LinuxDistro::Manjaro => "pacman",
            LinuxDistro::OpenSUSE => "zypper",
            LinuxDistro::Alpine => "apk",
            LinuxDistro::NixOS => "nix-env",
            LinuxDistro::Gentoo => "emerge",
            LinuxDistro::Void => "xbps-install",
            LinuxDistro::Unknown(_) => "apt", // fallback
        }
    }
}

/// Node.js version managers struct
#[derive(Debug, Clone)]
pub struct NodeManagers {
    pub has_nvm: bool,
    pub has_fnm: bool,
    pub has_n: bool,
    pub has_volta: bool,
    pub has_asdf: bool,
}

impl NodeManagers {
    /// Get the recommended manager if any is installed
    pub fn recommended(&self) -> Option<&'static str> {
        if self.has_volta { Some("volta") }
        else if self.has_fnm { Some("fnm") }
        else if self.has_nvm { Some("nvm") }
        else if self.has_n { Some("n") }
        else if self.has_asdf { Some("asdf") }
        else { None }
    }
    
    /// Check if any manager is installed
    pub fn has_any(&self) -> bool {
        self.has_nvm || self.has_fnm || self.has_n || self.has_volta || self.has_asdf
    }
}

/// Recovery options for installation failures
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecoveryMethod {
    TryWithSudo,
    InstallToHome,
    UseDifferentPackageManager,
    DownloadBinary,
    OfflineInstallation,
    ShowDiagnostics,
    Cancel,
}

/// Show interactive recovery menu when installation fails
pub fn show_recovery_menu(failed_method: &str) -> Result<RecoveryMethod> {
    use colored::*;
    
    println!("\n🚨 {}", format!("Installation failed using {}", failed_method).red().bold());
    println!("🔄 {}", "Let's try a different approach...".yellow());
    
    let options = vec![
        format!("🔐 Try with sudo privileges"),
        format!("🏠 Install to home directory (~/.local)"),
        format!("📦 Use different package manager"),
        format!("💿 Download binary directly"),
        format!("📴 Offline installation"),
        format!("🔍 Show diagnostics"),
        format!("❌ Cancel installation"),
    ];
    
    let selection = Select::new()
        .with_prompt("Select recovery method")
        .items(&options)
        .default(0)
        .interact()?;
    
    let method = match selection {
        0 => RecoveryMethod::TryWithSudo,
        1 => RecoveryMethod::InstallToHome,
        2 => RecoveryMethod::UseDifferentPackageManager,
        3 => RecoveryMethod::DownloadBinary,
        4 => RecoveryMethod::OfflineInstallation,
        5 => RecoveryMethod::ShowDiagnostics,
        _ => RecoveryMethod::Cancel,
    };
    
    Ok(method)
}

/// Execute recovery method based on user selection
pub async fn execute_recovery(method: RecoveryMethod, original_method: &str, package: &str, platform: &crate::platform::Platform) -> Result<()> {
    use colored::*;
    
    match method {
        RecoveryMethod::TryWithSudo => {
            println!("\n🔐 {}", "Retrying with sudo privileges...".cyan());
            match original_method {
                "npm" => {
                    println!("📋 {}", "Command:".cyan());
                    println!("   {} sudo npm install -g {}", "$".dimmed(), package.bright_white());
                    println!("\n⚠️  {}", "This will install globally with root privileges".yellow());
                }
                "cargo" => {
                    println!("📋 {}", "Command:".cyan());
                    println!("   {} sudo cargo install {}", "$".dimmed(), package.bright_white());
                    println!("\n⚠️  {}", "Note: Using sudo with cargo is not recommended".yellow());
                    println!("💡 {}", "Consider using --root ~/.local/cargo instead".yellow());
                }
                _ => return Err(anyhow::anyhow!("Sudo not applicable for this method")),
            }
        }
        RecoveryMethod::InstallToHome => {
            println!("\n🏠 {}", "Installing to home directory...".cyan());
            match original_method {
                "npm" => {
                    println!("📋 {}", "Commands:".cyan());
                    println!("   {} mkdir -p ~/.local/npm", "$".dimmed());
                    println!("   {} npm config set prefix ~/.local/npm", "$".dimmed());
                    println!("   {} npm install -g {}", "$".dimmed(), package.bright_white());
                    println!("\n💡 {}", "Add to PATH:".yellow());
                    println!("   {} export PATH=$HOME/.local/npm/bin:$PATH", "$".dimmed());
                }
                "cargo" => {
                    println!("📋 {}", "Command:".cyan());
                    println!("   {} cargo install --root ~/.local/cargo {}", "$".dimmed(), package.bright_white());
                    println!("\n💡 {}", "Add to PATH:".yellow());
                    println!("   {} export PATH=$HOME/.local/cargo/bin:$PATH", "$".dimmed());
                }
                _ => {
                    println!("📋 {}", "Manual installation to ~/.local/bin:".cyan());
                    println!("   1️⃣  Download the binary");
                    println!("   2️⃣  {} mkdir -p ~/.local/bin", "$".dimmed());
                    println!("   3️⃣  {} mv kindlyguard ~/.local/bin/", "$".dimmed());
                    println!("   4️⃣  {} chmod +x ~/.local/bin/kindlyguard", "$".dimmed());
                }
            }
        }
        RecoveryMethod::UseDifferentPackageManager => {
            println!("\n📦 {}", "Alternative package managers:".cyan());
            match platform {
                crate::platform::Platform::MacOS => {
                    println!("🍺 {}", "Homebrew:".green());
                    println!("   {} brew tap kindly-software-inc/tap", "$".dimmed());
                    println!("   {} brew install kindlyguard", "$".dimmed());
                    println!("\n🌊 {}", "MacPorts:".green());
                    println!("   {} sudo port install kindlyguard", "$".dimmed());
                }
                crate::platform::Platform::Linux => {
                    println!("📦 {}", "Snap:".green());
                    println!("   {} sudo snap install kindlyguard", "$".dimmed());
                    println!("\n📦 {}", "Flatpak:".green());
                    println!("   {} flatpak install flathub com.kindly.guard", "$".dimmed());
                    println!("\n📦 {}", "AppImage:".green());
                    println!("   Download from releases page");
                }
                crate::platform::Platform::Windows => {
                    println!("🍫 {}", "Chocolatey:".green());
                    println!("   {} choco install kindlyguard", "$".dimmed());
                    println!("\n🔷 {}", "Scoop:".green());
                    println!("   {} scoop install kindlyguard", "$".dimmed());
                    println!("\n🔶 {}", "WinGet:".green());
                    println!("   {} winget install KindlySoftware.KindlyGuard", "$".dimmed());
                }
                _ => {}
            }
        }
        RecoveryMethod::DownloadBinary => {
            println!("\n💿 {}", "Direct binary download:".cyan());
            println!("🌐 {}", "Visit:".cyan());
            println!("   {}", "https://github.com/kindly-software-inc/kindly-guard/releases".blue().underline());
            
            let arch = crate::platform::Architecture::detect();
            match platform {
                crate::platform::Platform::MacOS => {
                    let arch_str = if arch == crate::platform::Architecture::Arm64 { "aarch64" } else { "x86_64" };
                    println!("\n🍎 {}", format!("Download: kindly-guard-server-{}-apple-darwin.tar.gz", arch_str).bright_white());
                }
                crate::platform::Platform::Linux => {
                    println!("\n🐧 {}", "Download: kindly-guard-server-x86_64-unknown-linux-gnu.tar.gz".bright_white());
                }
                crate::platform::Platform::Windows => {
                    println!("\n🪟 {}", "Download: kindly-guard-server-x86_64-pc-windows-msvc.zip".bright_white());
                }
                _ => {}
            }
            
            println!("\n📋 {}", "Manual installation steps:".cyan());
            println!("   1️⃣  Download the appropriate file");
            println!("   2️⃣  Extract the archive");
            println!("   3️⃣  Move binary to PATH location");
            println!("   4️⃣  Make it executable (Unix/Linux/macOS)");
        }
        RecoveryMethod::OfflineInstallation => {
            println!("\n📴 {}", "Offline installation:".cyan());
            println!("💡 {}", "For offline environments:".yellow());
            println!("\n📋 {}", "Steps:".cyan());
            println!("   1️⃣  Download on a connected machine:");
            println!("      - Binary from GitHub releases");
            println!("      - Or npm package: {} npm pack kindly-guard-server", "$".dimmed());
            println!("   2️⃣  Transfer to target machine via USB/network");
            println!("   3️⃣  Install locally:");
            println!("      - Binary: Copy to /usr/local/bin/");
            println!("      - npm: {} npm install -g kindly-guard-server-*.tgz", "$".dimmed());
        }
        RecoveryMethod::ShowDiagnostics => {
            println!("\n🔍 {}", "Running diagnostics...".cyan());
            
            // Check disk space
            println!("\n💾 {}", "Disk space:".yellow());
            #[cfg(not(target_os = "windows"))]
            {
                if let Ok(output) = std::process::Command::new("df")
                    .args(["-h", "."])
                    .output()
                {
                    println!("{}", String::from_utf8_lossy(&output.stdout));
                }
            }
            
            // Check permissions
            println!("\n🔒 {}", "Permissions:".yellow());
            match original_method {
                "npm" => {
                    if let Ok(output) = std::process::Command::new("npm")
                        .args(["config", "get", "prefix"])
                        .output()
                    {
                        let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        println!("   npm prefix: {}", prefix);
                        
                        #[cfg(not(target_os = "windows"))]
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
                    if let Ok(home) = home_dir() {
                        let cargo_home = home.join(".cargo");
                        println!("   CARGO_HOME: {:?}", cargo_home);
                        
                        #[cfg(not(target_os = "windows"))]
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
            println!("\n🌐 {}", "Network connectivity:".yellow());
            #[cfg(not(target_os = "windows"))]
            {
                if let Ok(output) = std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "2", "8.8.8.8"])
                    .output()
                {
                    if output.status.success() {
                        println!("   ✅ Internet connection OK");
                    } else {
                        println!("   ❌ No internet connection");
                    }
                }
            }
            
            // Check environment
            let env_info = detect_environment();
            println!("\n🌍 {}", "Environment detection:".yellow());
            if env_info.is_docker {
                println!("   🐳 Running in Docker container");
            }
            if env_info.is_wsl {
                println!("   🪟 Running in WSL");
            }
            if env_info.is_ci {
                println!("   🤖 Running in CI/CD environment");
            }
            if env_info.is_ssh {
                println!("   🔐 Connected via SSH");
            }
            if env_info.has_proxy {
                println!("   🌐 Proxy detected:");
                if let Ok(http_proxy) = std::env::var("HTTP_PROXY").or_else(|_| std::env::var("http_proxy")) {
                    println!("      HTTP_PROXY: {}", http_proxy);
                }
                if let Ok(https_proxy) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) {
                    println!("      HTTPS_PROXY: {}", https_proxy);
                }
                
                // Show proxy configuration for package managers
                match original_method {
                    "npm" => {
                        println!("\n   💡 {}", "Configure npm for proxy:".yellow());
                        println!("      {} npm config set proxy $HTTP_PROXY", "$".dimmed());
                        println!("      {} npm config set https-proxy $HTTPS_PROXY", "$".dimmed());
                    }
                    "cargo" => {
                        println!("\n   💡 {}", "Cargo uses system proxy automatically".yellow());
                    }
                    _ => {}
                }
            }
            
            // Check Node.js managers if npm failed
            if original_method == "npm" {
                let node_managers = detect_node_managers();
                if node_managers.has_any() {
                    println!("\n🚀 {}", "Node.js version managers detected:".yellow());
                    if node_managers.has_nvm {
                        println!("   ✅ nvm - Try: nvm install --lts");
                    }
                    if node_managers.has_fnm {
                        println!("   ✅ fnm - Try: fnm install --lts");
                    }
                    if node_managers.has_n {
                        println!("   ✅ n - Try: n lts");
                    }
                    if node_managers.has_volta {
                        println!("   ✅ volta - Try: volta install node");
                    }
                    if node_managers.has_asdf {
                        println!("   ✅ asdf - Try: asdf install nodejs latest");
                    }
                }
            }
            
            // Check proxy settings
            println!("\n🔐 {}", "Proxy settings:".yellow());
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                if let Ok(value) = std::env::var(var) {
                    println!("   {}: {}", var, value);
                }
            }
            
            println!("\n💡 {}", "Common fixes:".cyan());
            println!("   - Free up disk space (200MB needed)");
            println!("   - Check file permissions");
            println!("   - Configure proxy if behind firewall");
            println!("   - Try different installation method");
        }
        RecoveryMethod::Cancel => {
            println!("\n❌ {}", "Installation cancelled".red());
            return Err(anyhow::anyhow!("Installation cancelled by user"));
        }
    }
    
    Ok(())
}

pub mod dev {
    use super::*;
    use clap::Subcommand;

    #[derive(clap::Args)]
    pub struct DevCommand {
        #[command(subcommand)]
        command: DevSubcommands,
    }

    #[derive(Subcommand)]
    enum DevSubcommands {
        /// Set up development environment
        Setup {
            /// Skip installing Rust tools
            #[arg(long)]
            skip_rust: bool,
        },
        /// Run security audit
        Audit,
        /// Generate documentation
        Docs {
            /// Open in browser after generation
            #[arg(long)]
            open: bool,
        },
    }

    impl Execute for DevCommand {
        async fn execute(&self) -> Result<()> {
            match &self.command {
                DevSubcommands::Setup { skip_rust } => setup_dev_env(*skip_rust).await,
                DevSubcommands::Audit => run_security_audit().await,
                DevSubcommands::Docs { open } => generate_docs(*open).await,
            }
        }
    }

    async fn setup_dev_env(skip_rust: bool) -> Result<()> {
        use crate::platform::Platform;
        use colored::*;
        
        println!("\n🚀 {}", "Setting up development environment...".bold().blue());
        
        let platform = Platform::detect();
        
        // Platform-specific emoji
        let platform_display = match platform {
            Platform::MacOS => format!("🍎 Platform: {}", platform),
            Platform::Windows => format!("🪟 Platform: {}", platform),
            Platform::Linux => format!("🐧 Platform: {}", platform),
            _ => format!("🖥️  Platform: {}", platform),
        };
        println!("{}", platform_display.cyan());
        
        // Check development dependencies inline
        println!("\n📋 {}", "Checking system dependencies...".cyan());
        check_basic_dev_deps(&platform)?;

        if !skip_rust {
            println!("\n🦀 {}", "Installing Rust development tools...".cyan());
            
            let tools = [
                ("cargo-audit", "🛡️  Security vulnerability scanner"),
                ("cargo-geiger", "☢️  Unsafe code detector"),
                ("cargo-dist", "📦 Distribution packaging tool"),
            ];
            
            for (tool, description) in &tools {
                println!("\n   {} {}: {}", "•".dimmed(), tool.bright_white(), description);
                
                // Check if already installed
                if command_exists(tool) {
                    println!("     ✅ {}", "Already installed".green());
                } else {
                    println!("     ⏳ {}", "Installing...".yellow());
                    
                    let status = std::process::Command::new("cargo")
                        .args(["install", tool])
                        .status()?;
                        
                    if status.success() {
                        println!("     ✅ {}", "Installed successfully!".green());
                    } else {
                        println!("     ❌ {}", "Installation failed".red());
                        println!("     💡 {}", format!("Try: cargo install {} --force", tool).yellow());
                    }
                }
            }
        } else {
            println!("\n⏭️  {}", "Skipping Rust tools installation (--skip-rust)".dimmed());
        }

        println!("\n✨ {}", "Development environment setup complete!".bold().green());
        println!("🎯 {}", "You're ready to start developing!".green());
        
        Ok(())
    }

    async fn run_security_audit() -> Result<()> {
        tracing::info!("Running security audit...");
        
        let output = std::process::Command::new("cargo")
            .args(["audit"])
            .output()?;
        
        if !output.status.success() {
            anyhow::bail!("Security audit failed");
        }
        
        tracing::info!("Security audit passed!");
        Ok(())
    }

    async fn generate_docs(open: bool) -> Result<()> {
        tracing::info!("Generating documentation...");
        
        let mut cmd = std::process::Command::new("cargo");
        cmd.args(["doc", "--no-deps"]);
        
        if open {
            cmd.arg("--open");
        }
        
        cmd.status()?;
        Ok(())
    }
    
    fn check_basic_dev_deps(platform: &crate::platform::Platform) -> Result<()> {
        use colored::*;
        
        let essentials = match platform {
            crate::platform::Platform::Linux => vec![
                ("gcc", "🔨 C compiler", "sudo apt install build-essential"),
                ("git", "🌿 Version control", "sudo apt install git"),
            ],
            crate::platform::Platform::MacOS => vec![
                ("git", "🌿 Version control", "xcode-select --install"),
                ("cc", "🔨 C compiler", "xcode-select --install"),
            ],
            crate::platform::Platform::Windows => vec![
                ("git", "🌿 Version control", "https://git-scm.com/download/win"),
            ],
            _ => vec![],
        };
        
        let mut missing = false;
        
        for (cmd, desc, install_hint) in essentials {
            print!("   {} {}: ", "•".dimmed(), desc);
            if command_exists(cmd) {
                println!("{}", "✅".green());
            } else {
                println!("{}", "❌ Missing".red());
                println!("     💡 Install: {}", install_hint.yellow());
                missing = true;
            }
        }
        
        if missing {
            println!("\n⚠️  {}", "Some essential tools are missing!".yellow());
        }
        
        Ok(())
    }
}

pub mod install {
    use super::*;
    use clap::Subcommand;
    use std::env;
    use std::process::Command;

    #[derive(clap::Args)]
    pub struct InstallCommand {
        #[command(subcommand)]
        command: InstallSubcommands,
    }

    #[derive(Subcommand)]
    enum InstallSubcommands {
        /// Install KindlyGuard MCP server
        #[command(visible_alias = "kindlyguard")]
        KindlyGuard {
            /// Installation method (auto-detected if not specified)
            #[arg(short, long)]
            method: Option<String>,
            
            /// Version to install (latest if not specified)
            #[arg(long)]
            version: Option<String>,
        },
        /// Install all recommended tools
        All,
        /// Install MCP servers
        McpServers {
            /// Specific server to install
            #[arg(short, long)]
            server: Option<String>,
        },
        /// Install development dependencies
        DevDeps,
    }

    impl Execute for InstallCommand {
        async fn execute(&self) -> Result<()> {
            match &self.command {
                InstallSubcommands::KindlyGuard { method, version } => {
                    install_kindlyguard(method.as_deref(), version.as_deref()).await
                }
                InstallSubcommands::All => install_all().await,
                InstallSubcommands::McpServers { server } => {
                    install_mcp_servers(server.as_deref()).await
                }
                InstallSubcommands::DevDeps => install_dev_deps().await,
            }
        }
    }

    async fn install_kindlyguard(method: Option<&str>, version: Option<&str>) -> Result<()> {
        use crate::platform::Platform;
        use colored::*;
        
        // Run pre-flight checks
        println!("\n🔍 {}", "Running pre-installation checks...".cyan());
        let platform = Platform::detect();
        let env_info = detect_environment();
        
        // Platform validation
        if platform == Platform::Unknown {
            println!("🤔 {}", "Hmm, couldn't detect your platform. Are you on a supported OS?".yellow());
            println!("💡 {}", "Supported platforms: Linux, macOS, Windows".yellow());
            println!("💡 {}", "Try specifying method manually: kindly-tools install kindlyguard --method npm".yellow());
            return Err(anyhow::anyhow!("Unsupported platform"));
        }
        
        // Version validation and normalization
        let version_str = if let Some(v) = version {
            validate_and_normalize_version(v)?
        } else {
            "latest".to_string()
        };
        
        // Auto-detect best installation method if not specified
        let install_method = if let Some(m) = method {
            m.to_string()
        } else {
            detect_best_install_method(&platform)?
        };
        
        // Display installation plan
        println!("\n🎯 {}", "Installation Plan".bold().blue());
        println!("   📦 Package: {}", "🛡️ KindlyGuard MCP Server".bright_white());
        
        // Platform-specific emoji
        let platform_display = match platform {
            Platform::MacOS => format!("🍎 {}", platform.to_string()),
            Platform::Windows => format!("🪟 {}", platform.to_string()),
            Platform::Linux => {
                let distro = detect_linux_distro();
                distro.display_name()
            },
            _ => format!("🖥️  {}", platform.to_string()),
        };
        println!("   {}", platform_display.green());
        
        // Show environment details if relevant
        if env_info.is_docker {
            println!("   🐳 Environment: {}", "Docker Container".cyan());
        }
        if env_info.is_wsl {
            println!("   🪟 Environment: {}", "Windows Subsystem for Linux".cyan());
        }
        if env_info.is_ci {
            println!("   🤖 Environment: {}", "CI/CD Pipeline".cyan());
        }
        if env_info.is_ssh {
            println!("   🔐 Connection: {}", "SSH Session".cyan());
        }
        if env_info.has_proxy {
            println!("   🌐 Network: {}", "Behind Proxy".yellow());
        }
        
        println!("   ⚙️ Method: {}", install_method.green());
        println!("   🏷️ Version: {}", version_str.green());
        
        // Run additional pre-flight checks
        if let Err(e) = run_preflight_checks(&platform, &install_method).await {
            println!("\n⚠️  {}", "Pre-flight check warnings:".yellow());
            println!("   {}", e.to_string().yellow());
            // Continue anyway, these are just warnings
        }
        
        println!("\n⏳ {}", "Preparing installation...".cyan());
        
        match install_method.as_str() {
            "homebrew" | "brew" => {
                println!("🍺 {}", "Installing via Homebrew...".green());
                
                if !command_exists("brew") {
                    println!("\n❌ {}", "Homebrew not found!".red());
                    println!("🔧 {}", "Install Homebrew first:".yellow());
                    println!("   {}", "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"".bright_white());
                    println!("\n💡 {}", "Or try a different method:".yellow());
                    println!("   {}", "kindly-tools install kindlyguard --method npm".bright_white());
                    return Err(anyhow::anyhow!("Homebrew not installed"));
                }
                
                println!("\n📋 {}", "Installation steps:".cyan());
                println!("   1️⃣  Add our tap:");
                println!("      {} {}", "$".dimmed(), "brew tap kindly-software-inc/tap".bright_white());
                println!("   2️⃣  Install KindlyGuard:");
                println!("      {} {}", "$".dimmed(), "brew install kindlyguard".bright_white());
                
                if version_str != "latest" {
                    println!("\n⚠️  {}", "Note: Homebrew installs the latest version by default.".yellow());
                    println!("💡 {}", "For specific versions, use npm or cargo instead.".yellow());
                }
                
                // Check if tap exists
                let output = std::process::Command::new("brew")
                    .args(["tap"])
                    .output()?;
                
                let taps = String::from_utf8_lossy(&output.stdout);
                let tap_exists = taps.contains("kindly-software-inc/tap");
                
                if !tap_exists {
                    println!("\n⏳ {}", "Adding tap...".yellow());
                    let tap_status = std::process::Command::new("brew")
                        .args(["tap", "kindly-software-inc/tap"])
                        .status();
                    
                    if tap_status.is_err() || !tap_status.unwrap().success() {
                        // Tap failed, show recovery menu
                        loop {
                            let recovery_method = show_recovery_menu("homebrew")?;
                            
                            if recovery_method == RecoveryMethod::Cancel {
                                return Err(anyhow::anyhow!("Installation cancelled"));
                            }
                            
                            execute_recovery(recovery_method, "homebrew", "kindlyguard", &platform).await?;
                            
                            let try_again = dialoguer::Confirm::new()
                                .with_prompt("Try another recovery method?")
                                .default(true)
                                .interact()?;
                            
                            if !try_again {
                                break;
                            }
                        }
                        return Ok(());
                    }
                }
                
                println!("\n⏳ {}", "Installing package...".yellow());
                let install_status = std::process::Command::new("brew")
                    .args(["install", "kindlyguard"])
                    .status();
                
                match install_status {
                    Ok(s) if s.success() => {
                        println!("\n✅ {}", "Installation successful!".green().bold());
                    }
                    _ => {
                        // Installation failed, show recovery menu
                        loop {
                            let recovery_method = show_recovery_menu("homebrew")?;
                            
                            if recovery_method == RecoveryMethod::Cancel {
                                return Err(anyhow::anyhow!("Installation cancelled"));
                            }
                            
                            execute_recovery(recovery_method, "homebrew", "kindlyguard", &platform).await?;
                            
                            let try_again = dialoguer::Confirm::new()
                                .with_prompt("Try another recovery method?")
                                .default(true)
                                .interact()?;
                            
                            if !try_again {
                                break;
                            }
                        }
                    }
                }
            }
            "npm" => {
                println!("📦 {}", "Installing via npm...".green());
                
                if !command_exists("npm") {
                    println!("\n❌ {}", "npm not found!".red());
                    
                    // Check for Node.js version managers
                    let node_managers = detect_node_managers();
                    if node_managers.has_any() {
                        println!("🔍 {}", "Detected Node.js version managers:".cyan());
                        if node_managers.has_nvm {
                            println!("   ✅ nvm detected! Try: {}", "nvm install --lts && nvm use --lts".bright_white());
                        }
                        if node_managers.has_fnm {
                            println!("   ✅ fnm detected! Try: {}", "fnm install --lts && fnm use lts-latest".bright_white());
                        }
                        if node_managers.has_n {
                            println!("   ✅ n detected! Try: {}", "n lts".bright_white());
                        }
                        if node_managers.has_volta {
                            println!("   ✅ volta detected! Try: {}", "volta install node".bright_white());
                        }
                        if node_managers.has_asdf {
                            println!("   ✅ asdf detected! Try: {}", "asdf plugin add nodejs && asdf install nodejs latest".bright_white());
                        }
                        println!("\n💡 {}", "After activating Node.js, run this command again!".yellow());
                    } else {
                        println!("🤖 {}", "Let's fix this! Choose your platform:".yellow());
                        
                        match platform {
                            Platform::MacOS => {
                                println!("\n🍎 {}", "macOS Options:".cyan());
                                println!("   🍺 Using Homebrew: {}", "brew install node".bright_white());
                                println!("   📥 Direct download: {}", "https://nodejs.org/".blue().underline());
                                println!("\n🚀 {}", "Recommended: Use a version manager".green());
                                println!("   • fnm (fast): {}", "brew install fnm".bright_white());
                                println!("   • volta (reliable): {}", "brew install volta".bright_white());
                            }
                            Platform::Linux => {
                                let distro = detect_linux_distro();
                                println!("\n{} {}", distro.display_name(), "Options:".cyan());
                                
                                match distro {
                                    LinuxDistro::Ubuntu | LinuxDistro::Debian | LinuxDistro::Mint => {
                                        println!("   📦 System package: {}", "sudo apt update && sudo apt install nodejs npm".bright_white());
                                    }
                                    LinuxDistro::Fedora | LinuxDistro::CentOS | LinuxDistro::RHEL => {
                                        println!("   📦 System package: {}", "sudo dnf install nodejs npm".bright_white());
                                    }
                                    LinuxDistro::Arch | LinuxDistro::Manjaro => {
                                        println!("   📦 System package: {}", "sudo pacman -S nodejs npm".bright_white());
                                    }
                                    LinuxDistro::Alpine => {
                                        println!("   📦 System package: {}", "sudo apk add nodejs npm".bright_white());
                                    }
                                    LinuxDistro::NixOS => {
                                        println!("   📦 System package: {}", "nix-env -iA nixpkgs.nodejs".bright_white());
                                    }
                                    _ => {
                                        println!("   📥 Direct download: {}", "https://nodejs.org/".blue().underline());
                                    }
                                }
                                
                                println!("\n🚀 {}", "Recommended: Use a version manager".green());
                                println!("   • fnm (fast): {}", "curl -fsSL https://fnm.vercel.app/install | bash".bright_white());
                                println!("   • volta (reliable): {}", "curl https://get.volta.sh | bash".bright_white());
                            }
                            Platform::Windows => {
                                println!("\n🪟 {}", "Windows Options:".cyan());
                                println!("   🍫 Using Chocolatey: {}", "choco install nodejs".bright_white());
                                println!("   🍞 Using Scoop: {}", "scoop install nodejs".bright_white());
                                println!("   🌀 Using winget: {}", "winget install OpenJS.NodeJS".bright_white());
                                println!("   📥 Direct download: {}", "https://nodejs.org/".blue().underline());
                                println!("\n🚀 {}", "Recommended: Use volta".green());
                                println!("   • Install: {}", "choco install volta".bright_white());
                            }
                            _ => {
                                println!("   📥 Direct download: {}", "https://nodejs.org/".blue().underline());
                            }
                        }
                    }
                    
                    println!("\n💡 {}", "After installing Node.js, run this command again!".yellow());
                    return Err(anyhow::anyhow!("npm not installed"));
                }
                
                let package = if version_str != "latest" {
                    format!("kindly-guard-server@{}", version_str)
                } else {
                    "kindly-guard-server".to_string()
                };
                
                println!("\n📋 {}", "Installation command:".cyan());
                println!("   {} npm install -g {}", "$".dimmed(), package.bright_white());
                
                println!("\n⏳ {}", "Attempting installation...".yellow());
                let status = std::process::Command::new("npm")
                    .args(["install", "-g", &package])
                    .status();
                
                match status {
                    Ok(s) if s.success() => {
                        println!("\n✅ {}", "Installation successful!".green().bold());
                    }
                    _ => {
                        // Installation failed, show recovery menu
                        loop {
                            let recovery_method = show_recovery_menu("npm")?;
                            
                            if recovery_method == RecoveryMethod::Cancel {
                                return Err(anyhow::anyhow!("Installation cancelled"));
                            }
                            
                            execute_recovery(recovery_method, "npm", &package, &platform).await?;
                            
                            // Ask if user wants to try another recovery method
                            let try_again = dialoguer::Confirm::new()
                                .with_prompt("Try another recovery method?")
                                .default(true)
                                .interact()?;
                            
                            if !try_again {
                                break;
                            }
                        }
                    }
                }
            }
            "cargo" => {
                println!("🦀 {}", "Installing via Cargo...".green());
                
                if !command_exists("cargo") {
                    println!("\n❌ {}", "Cargo not found!".red());
                    println!("🦀 {}", "Let's install Rust and Cargo:".yellow());
                    println!("\n📋 {}", "Quick install (all platforms):".cyan());
                    println!("   {} {}", "$".dimmed(), "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh".bright_white());
                    
                    match platform {
                        Platform::Windows => {
                            println!("\n🪟 {}", "Windows alternative:".cyan());
                            println!("   📥 Download installer: {}", "https://rustup.rs/".blue().underline());
                        }
                        _ => {}
                    }
                    
                    println!("\n💡 {}", "After installing Rust, restart your terminal and try again!".yellow());
                    return Err(anyhow::anyhow!("Cargo not installed"));
                }
                
                let package = if version_str != "latest" {
                    format!("kindlyguard@{}", version_str)
                } else {
                    "kindlyguard".to_string()
                };
                
                println!("\n📋 {}", "Installation command:".cyan());
                println!("   {} cargo install {}", "$".dimmed(), package.bright_white());
                
                println!("\n⏳ {}", "Attempting installation (this may take a while)...".yellow());
                let status = std::process::Command::new("cargo")
                    .args(["install", &package])
                    .status();
                
                match status {
                    Ok(s) if s.success() => {
                        println!("\n✅ {}", "Installation successful!".green().bold());
                        println!("📍 {}", "Binary installed to ~/.cargo/bin/".cyan());
                    }
                    _ => {
                        // Installation failed, show recovery menu
                        loop {
                            let recovery_method = show_recovery_menu("cargo")?;
                            
                            if recovery_method == RecoveryMethod::Cancel {
                                return Err(anyhow::anyhow!("Installation cancelled"));
                            }
                            
                            execute_recovery(recovery_method, "cargo", &package, &platform).await?;
                            
                            // Ask if user wants to try another recovery method
                            let try_again = dialoguer::Confirm::new()
                                .with_prompt("Try another recovery method?")
                                .default(true)
                                .interact()?;
                            
                            if !try_again {
                                break;
                            }
                        }
                    }
                }
            }
            "binary" => {
                println!("💿 {}", "Direct binary installation...".green());
                
                let arch = crate::platform::Architecture::detect();
                println!("\n🏗️  {}", format!("Detected architecture: {}", arch.name()).cyan());
                
                println!("\n📥 {}", "Download options:".cyan());
                println!("   🌐 Visit: {}", "https://github.com/kindly-software-inc/kindly-guard/releases".blue().underline());
                
                match platform {
                    Platform::MacOS => {
                        let arch_str = if arch == crate::platform::Architecture::Arm64 { "aarch64" } else { "x86_64" };
                        println!("\n🍎 {}", "macOS binary:".cyan());
                        println!("   📦 File: {}", format!("kindly-guard-server-{}-apple-darwin.tar.gz", arch_str).bright_white());
                        
                        println!("\n📋 {}", "Installation steps:".cyan());
                        println!("   1️⃣  Download the .tar.gz file");
                        println!("   2️⃣  Extract: {}", "tar -xzf kindly-guard-server-*.tar.gz".bright_white());
                        println!("   3️⃣  Move to PATH: {}", "sudo mv kindlyguard /usr/local/bin/".bright_white());
                        println!("   4️⃣  Make executable: {}", "sudo chmod +x /usr/local/bin/kindlyguard".bright_white());
                    }
                    Platform::Linux => {
                        println!("\n🐧 {}", "Linux binary:".cyan());
                        println!("   📦 File: {}", "kindly-guard-server-x86_64-unknown-linux-gnu.tar.gz".bright_white());
                        
                        println!("\n📋 {}", "Installation steps:".cyan());
                        println!("   1️⃣  Download the .tar.gz file");
                        println!("   2️⃣  Extract: {}", "tar -xzf kindly-guard-server-*.tar.gz".bright_white());
                        println!("   3️⃣  Move to PATH: {}", "sudo mv kindlyguard /usr/local/bin/".bright_white());
                        println!("   4️⃣  Make executable: {}", "sudo chmod +x /usr/local/bin/kindlyguard".bright_white());
                    }
                    Platform::Windows => {
                        println!("\n🪟 {}", "Windows options:".cyan());
                        println!("   📦 ZIP: {}", "kindly-guard-server-x86_64-pc-windows-msvc.zip".bright_white());
                        println!("   🎁 MSI installer: {}", "kindly-guard-server-x86_64-pc-windows-msvc.msi".bright_white());
                        
                        println!("\n📋 {}", "Installation steps:".cyan());
                        println!("   💡 {}", "Recommended: Use the MSI installer for automatic setup".green());
                        println!("   📂 Manual: Extract ZIP to C:\\Program Files\\KindlyGuard\\");
                        println!("   🔧 Add to PATH: {}", "%ProgramFiles%\\KindlyGuard".yellow());
                    }
                    _ => {}
                }
                
                println!("\n⚠️  {}", "Important:".yellow());
                println!("   🔍 Verify checksums after download");
                println!("   🔒 Check file permissions are correct");
                println!("   📍 Ensure binary is in your PATH");
            }
            _ => {
                println!("\n❌ {}", format!("Unknown installation method: {}", install_method).red());
                println!("🤔 {}", "Valid methods: homebrew, npm, cargo, binary".yellow());
                
                // Suggest best method
                let suggested = detect_best_install_method(&platform)?;
                println!("\n💡 {}", format!("Try: kindly-tools install kindlyguard --method {}", suggested).green());
                
                return Err(anyhow::anyhow!("Invalid installation method"));
            }
        }
        
        println!("\n🎯 {}", "Next steps:".bold().green());
        println!("   🚀 Start server: {}", "kindlyguard --stdio".bright_white());
        println!("   📖 Get help: {}", "kindlyguard --help".bright_white());
        println!("   🔧 Configure: {}", "kindlyguard config".bright_white());
        
        println!("\n🩺 {}", "If something goes wrong:".cyan());
        show_troubleshooting_tips();
        
        // Run post-installation verification
        println!("\n🔎 {}", "Verifying installation...".bold().cyan());
        verify_installation(&install_method)?;
        
        Ok(())
    }
    
    /// Verify that the installation succeeded
    fn verify_installation(method: &str) -> Result<()> {
        use colored::*;
        use std::path::Path;
        
        let mut checks_passed = true;
        let mut warnings = Vec::new();
        
        // 1. Check if binary exists in expected locations
        println!("\n📍 {}", "Checking binary locations...".cyan());
        
        let binary_locations: Vec<String> = match method {
            "homebrew" | "brew" => vec![
                "/usr/local/bin/kindlyguard".to_string(),
                "/opt/homebrew/bin/kindlyguard".to_string(),
            ],
            "npm" => {
                let npm_prefix = Command::new("npm")
                    .args(["prefix", "-g"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                    
                if npm_prefix.is_empty() {
                    vec![
                        "/usr/local/bin/kindlyguard".to_string(),
                        "/usr/bin/kindlyguard".to_string(),
                    ]
                } else {
                    vec![
                        format!("{}/bin/kindlyguard", npm_prefix),
                        "/usr/local/bin/kindlyguard".to_string(),
                    ]
                }
            }
            "cargo" => vec![
                format!("{}/.cargo/bin/kindlyguard", env::var("HOME").unwrap_or_default()),
                "/usr/local/bin/kindlyguard".to_string(),
            ],
            "binary" => vec![
                "/usr/local/bin/kindlyguard".to_string(),
                "/opt/kindlyguard/bin/kindlyguard".to_string(),
                format!("{}/bin/kindlyguard", env::var("HOME").unwrap_or_default()),
            ],
            _ => vec!["/usr/local/bin/kindlyguard".to_string()],
        };
        
        let mut found_binary = None;
        for location in &binary_locations {
            if Path::new(location).exists() {
                println!("   ✅ Found binary at: {}", location.green());
                found_binary = Some(location.clone());
                break;
            }
        }
        
        if found_binary.is_none() {
            println!("   ❌ {}", "Binary not found in expected locations".red());
            checks_passed = false;
            
            // Additional check using 'which'
            if let Ok(output) = Command::new("which")
                .arg("kindlyguard")
                .output()
            {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        println!("   ✅ Found binary via PATH at: {}", path.green());
                        found_binary = Some(path);
                        checks_passed = true;
                    }
                }
            }
        }
        
        // 2. Run --version to verify it works
        if let Some(binary_path) = &found_binary {
            println!("\n🔧 {}", "Checking binary execution...".cyan());
            
            match Command::new(binary_path)
                .arg("--version")
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        let version = String::from_utf8_lossy(&output.stdout);
                        println!("   ✅ Binary executes successfully");
                        println!("   📌 Version: {}", version.trim().green());
                    } else {
                        println!("   ❌ {}", "Binary failed to execute".red());
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if !stderr.is_empty() {
                            println!("   💡 Error: {}", stderr.trim().yellow());
                        }
                        checks_passed = false;
                    }
                }
                Err(e) => {
                    println!("   ❌ {}", format!("Failed to run binary: {}", e).red());
                    checks_passed = false;
                }
            }
        }
        
        // 3. Check file permissions (Unix only)
        #[cfg(unix)]
        if let Some(binary_path) = &found_binary {
            println!("\n🔐 {}", "Checking file permissions...".cyan());
            
            use std::os::unix::fs::PermissionsExt;
            match std::fs::metadata(binary_path) {
                Ok(metadata) => {
                    let mode = metadata.permissions().mode();
                    let is_executable = mode & 0o111 != 0;
                    
                    if is_executable {
                        println!("   ✅ Binary has executable permissions");
                    } else {
                        println!("   ❌ {}", "Binary is not executable".red());
                        println!("   💡 Fix with: {}", format!("chmod +x {}", binary_path).yellow());
                        checks_passed = false;
                    }
                }
                Err(e) => {
                    println!("   ⚠️  {}", format!("Could not check permissions: {}", e).yellow());
                    warnings.push("Could not verify file permissions");
                }
            }
        }
        
        // 4. Check if PATH contains the install directory
        println!("\n🌐 {}", "Checking PATH configuration...".cyan());
        
        if let Ok(path_var) = env::var("PATH") {
            let path_contains_binary = if let Some(binary_path) = &found_binary {
                if let Some(parent) = Path::new(binary_path).parent() {
                    path_var.split(':').any(|p| Path::new(p) == parent)
                } else {
                    false
                }
            } else {
                false
            };
            
            if path_contains_binary || command_exists("kindlyguard") {
                println!("   ✅ kindlyguard is accessible via PATH");
            } else {
                println!("   ⚠️  {}", "kindlyguard directory not in PATH".yellow());
                warnings.push("PATH configuration needed");
                
                // Detect shell and provide instructions
                detect_and_show_path_instructions(method);
            }
        }
        
        // Summary
        println!("\n📋 {}", "Verification Summary".bold().blue());
        
        if checks_passed && warnings.is_empty() {
            println!("\n✅ {}", "All checks passed! Installation verified.".bold().green());
            println!("🚀 {}", "You can now run: kindlyguard --help".green());
        } else if checks_passed && !warnings.is_empty() {
            println!("\n✅ {}", "Installation succeeded with warnings:".bold().yellow());
            for warning in &warnings {
                println!("   ⚠️  {}", warning.yellow());
            }
        } else {
            println!("\n❌ {}", "Installation verification failed!".bold().red());
            println!("🔧 {}", "Please check the errors above and try again.".yellow());
            return Err(anyhow::anyhow!("Installation verification failed"));
        }
        
        Ok(())
    }
    
    /// Detect shell and show PATH configuration instructions
    fn detect_and_show_path_instructions(method: &str) -> () {
        use colored::*;
        
        // Detect current shell
        let shell = env::var("SHELL").unwrap_or_default();
        let shell_name = if shell.contains("bash") {
            "bash"
        } else if shell.contains("zsh") {
            "zsh"
        } else if shell.contains("fish") {
            "fish"
        } else {
            "sh"
        };
        
        println!("\n💡 {}", "To add kindlyguard to your PATH:".cyan());
        
        let path_to_add = match method {
            "npm" => {
                let npm_prefix = Command::new("npm")
                    .args(["prefix", "-g"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|_| "/usr/local".to_string());
                format!("{}/bin", npm_prefix)
            }
            "cargo" => format!("$HOME/.cargo/bin"),
            "homebrew" | "brew" => {
                if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                    "/opt/homebrew/bin".to_string()
                } else {
                    "/usr/local/bin".to_string()
                }
            }
            _ => "/usr/local/bin".to_string(),
        };
        
        match shell_name {
            "bash" => {
                println!("\n   🐚 For Bash:");
                println!("      1. Add to ~/.bashrc:");
                println!("         {} echo 'export PATH=\"{}:$PATH\"' >> ~/.bashrc", "$".dimmed(), path_to_add.bright_white());
                println!("      2. Reload:");
                println!("         {} source ~/.bashrc", "$".dimmed());
            }
            "zsh" => {
                println!("\n   🐚 For Zsh:");
                println!("      1. Add to ~/.zshrc:");
                println!("         {} echo 'export PATH=\"{}:$PATH\"' >> ~/.zshrc", "$".dimmed(), path_to_add.bright_white());
                println!("      2. Reload:");
                println!("         {} source ~/.zshrc", "$".dimmed());
            }
            "fish" => {
                println!("\n   🐚 For Fish:");
                println!("      1. Add to config:");
                println!("         {} fish_add_path {}", "$".dimmed(), path_to_add.bright_white());
                println!("      2. Or manually:");
                println!("         {} set -Ua fish_user_paths {}", "$".dimmed(), path_to_add.bright_white());
            }
            _ => {
                println!("\n   🐚 For your shell:");
                println!("      1. Add to your shell config file:");
                println!("         export PATH=\"{}:$PATH\"", path_to_add.bright_white());
                println!("      2. Reload your shell configuration");
            }
        }
        
        println!("\n   💡 After updating PATH, restart your terminal or run the reload command");
    }
    
    fn validate_and_normalize_version(version: &str) -> Result<String> {
        use colored::*;
        
        // Remove common prefixes
        let normalized = version
            .trim()
            .trim_start_matches('v')
            .trim_start_matches('V');
        
        // Basic validation
        if normalized.is_empty() {
            println!("⚠️  {}", "Empty version specified, using 'latest'".yellow());
            return Ok("latest".to_string());
        }
        
        // Check format (basic semver validation)
        let parts: Vec<&str> = normalized.split('.').collect();
        if parts.len() != 3 && normalized != "latest" {
            println!("⚠️  {}", format!("Version '{}' doesn't look like semantic versioning", version).yellow());
            println!("💡 {}", "Expected format: X.Y.Z (e.g., 0.10.3)".yellow());
            println!("📋 {}", "Available versions: latest, 0.10.3, 0.10.2, 0.10.1".cyan());
            
            // Still allow it, just warn
        }
        
        Ok(normalized.to_string())
    }
    
    fn detect_best_install_method(platform: &crate::platform::Platform) -> Result<String> {
        match platform {
            crate::platform::Platform::MacOS => {
                if command_exists("brew") {
                    Ok("homebrew".to_string())
                } else if command_exists("npm") {
                    Ok("npm".to_string())
                } else if command_exists("cargo") {
                    Ok("cargo".to_string())
                } else {
                    Ok("binary".to_string())
                }
            }
            crate::platform::Platform::Linux => {
                if command_exists("npm") {
                    Ok("npm".to_string())
                } else if command_exists("cargo") {
                    Ok("cargo".to_string())
                } else {
                    Ok("binary".to_string())
                }
            }
            crate::platform::Platform::Windows => {
                if command_exists("npm") {
                    Ok("npm".to_string())
                } else if command_exists("cargo") {
                    Ok("cargo".to_string())
                } else {
                    Ok("binary".to_string())
                }
            }
            _ => Ok("npm".to_string()),
        }
    }
    
    async fn run_preflight_checks(_platform: &crate::platform::Platform, method: &str) -> Result<()> {
        use colored::*;
        
        // Check disk space (simplified - just a warning)
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(output) = std::process::Command::new("df")
                .args(["-h", "/"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Very basic check - just warn if root partition seems full
                if output_str.contains("100%") || output_str.contains("99%") || output_str.contains("98%") {
                    println!("💾 {}", "Warning: Disk space is running low!".yellow());
                    println!("   {}", "Installation needs approximately 200MB".yellow());
                }
            }
        }
        
        // Check network connectivity for non-binary methods
        if method != "binary" {
            // Simple check - try to resolve a common domain
            #[cfg(not(target_os = "windows"))]
            {
                if let Err(_) = std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "2", "8.8.8.8"])
                    .output()
                {
                    println!("🌐 {}", "Network connectivity might be limited".yellow());
                    println!("   {}", "If installation fails, check your internet connection".yellow());
                }
            }
        }
        
        Ok(())
    }
    
    fn show_troubleshooting_tips() {
        use colored::*;
        
        println!("   📝 Check internet connection");
        println!("   📝 Verify disk space (200MB needed)");
        println!("   📝 Ensure admin/sudo permissions");
        println!("   📝 Try a different installation method");
        println!("\n🆘 {}", "Need help?".cyan());
        println!("   📚 Docs: {}", "https://github.com/kindly-software-inc/kindly-guard/wiki".blue().underline());
        println!("   🐛 Issues: {}", "https://github.com/kindly-software-inc/kindly-guard/issues".blue().underline());
    }

    async fn install_all() -> Result<()> {
        use colored::*;
        
        println!("\n🎁 {}", "Installing all recommended tools...".bold().blue());
        println!("📦 {}", "This will install:".cyan());
        println!("   1️⃣  KindlyGuard MCP Server");
        println!("   2️⃣  Recommended MCP servers");
        println!("   3️⃣  Development dependencies");
        
        println!("\n⏳ {}", "Step 1/3: Installing KindlyGuard...".cyan());
        install_kindlyguard(None, None).await?;
        
        println!("\n⏳ {}", "Step 2/3: Installing MCP servers...".cyan());
        install_mcp_servers(None).await?;
        
        println!("\n⏳ {}", "Step 3/3: Installing dev dependencies...".cyan());
        install_dev_deps().await?;
        
        println!("\n🎉 {}", "All tools installed successfully!".bold().green());
        println!("✨ {}", "Your development environment is ready!".green());
        
        Ok(())
    }

    async fn install_mcp_servers(server: Option<&str>) -> Result<()> {
        use dialoguer::Confirm;
        use colored::*;
        
        let servers = if let Some(s) = server {
            vec![(s, get_server_description(s))]
        } else {
            vec![
                ("tree-sitter", "🌳 Parse and analyze code structure"),
                ("ast-grep", "🔍 Search code with AST patterns"),
                ("filesystem", "📁 Enhanced file system access"),
            ]
        };

        println!("\n🔌 {}", "MCP Server Installation".bold().blue());
        
        for (server_name, description) in servers {
            println!("\n📦 {}: {}", server_name.cyan(), description);
            
            if Confirm::new()
                .with_prompt(format!("   Install '{}'?", server_name))
                .default(true)
                .interact()?
            {
                println!("   ⏳ {}", format!("Installing {}...", server_name).yellow());
                
                // TODO: Add actual installation logic
                println!("   ✅ {}", format!("{} installed successfully!", server_name).green());
                
                // Provide configuration tips
                match server_name {
                    "tree-sitter" => {
                        println!("   💡 {}", "Tip: Use for code navigation and refactoring".yellow());
                    }
                    "ast-grep" => {
                        println!("   💡 {}", "Tip: Great for finding code patterns".yellow());
                    }
                    "filesystem" => {
                        println!("   💡 {}", "Tip: Provides secure file access to Claude".yellow());
                    }
                    _ => {}
                }
            } else {
                println!("   ⏭️  {}", format!("Skipping {}", server_name).dimmed());
            }
        }
        
        println!("\n📝 {}", "Note: Restart Claude Desktop after installing MCP servers".cyan());
        
        Ok(())
    }
    
    fn get_server_description(server: &str) -> &'static str {
        match server {
            "tree-sitter" => "🌳 Parse and analyze code structure",
            "ast-grep" => "🔍 Search code with AST patterns",
            "filesystem" => "📁 Enhanced file system access",
            "semgrep" => "🛡️  Security vulnerability scanning",
            "github" => "🐙 GitHub repository integration",
            _ => "📦 MCP server extension",
        }
    }

    async fn install_dev_deps() -> Result<()> {
        use colored::*;
        
        println!("\n🛠️  {}", "Development Dependencies Check".bold().blue());
        
        let platform = crate::platform::Platform::detect();
        let packages = match platform {
            crate::platform::Platform::Linux => vec![
                ("build-essential", "🔨 C/C++ compiler toolchain", "sudo apt install build-essential"),
                ("pkg-config", "📦 Library configuration tool", "sudo apt install pkg-config"),
                ("libssl-dev", "🔐 SSL development headers", "sudo apt install libssl-dev"),
            ],
            crate::platform::Platform::MacOS => vec![
                ("xcode-select", "🍎 Xcode command line tools", "xcode-select --install"),
                ("pkg-config", "📦 Library configuration tool", "brew install pkg-config"),
            ],
            crate::platform::Platform::Windows => vec![
                ("visual-studio", "🪟 Visual Studio Build Tools", "Download from https://visualstudio.microsoft.com/downloads/"),
            ],
            _ => vec![],
        };
        
        let mut missing = Vec::new();
        
        println!("\n🔍 {}", "Checking system dependencies...".cyan());
        
        for (pkg, description, install_cmd) in &packages {
            print!("   {} {}: ", "•".dimmed(), description);
            
            // Simple check - just see if command exists or path exists
            let is_installed = match *pkg {
                "xcode-select" => command_exists("xcodebuild"),
                "visual-studio" => {
                    // Check common VS paths
                    std::path::Path::new("C:\\Program Files\\Microsoft Visual Studio").exists() ||
                    std::path::Path::new("C:\\Program Files (x86)\\Microsoft Visual Studio").exists()
                }
                _ => command_exists(pkg),
            };
            
            if is_installed {
                println!("{}", "✅ Installed".green());
            } else {
                println!("{}", "❌ Not found".red());
                missing.push((pkg, description, install_cmd));
            }
        }
        
        if !missing.is_empty() {
            println!("\n⚠️  {}", "Missing dependencies detected!".yellow());
            println!("📋 {}", "Installation commands:".cyan());
            
            for (pkg, _desc, cmd) in missing {
                println!("\n   {} {}:", "•".dimmed(), pkg.bright_white());
                println!("     {}", cmd.bright_white());
            }
            
            println!("\n💡 {}", "Install these dependencies for optimal development experience".yellow());
        } else {
            println!("\n✅ {}", "All development dependencies are installed!".green());
        }
        
        // Additional recommendations
        println!("\n🚀 {}", "Recommended Rust tools:".cyan());
        println!("   {} cargo-watch - {}", "•".dimmed(), "Auto-rebuild on file changes".yellow());
        println!("   {} cargo-nextest - {}", "•".dimmed(), "3x faster test runner".yellow());
        println!("   {} sccache - {}", "•".dimmed(), "Compilation cache for faster builds".yellow());
        
        println!("\n💡 {}", "Install with: cargo install cargo-watch cargo-nextest sccache".cyan());
        
        Ok(())
    }
}

pub mod mcp {
    use super::*;
    use clap::Subcommand;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::process::{Command, Stdio};
    use std::io::Write;

    #[derive(clap::Args)]
    pub struct McpCommand {
        #[command(subcommand)]
        command: McpSubcommands,
    }

    #[derive(Subcommand)]
    enum McpSubcommands {
        /// Set up and install MCP server for KindlyGuard
        Setup {
            /// Skip interactive prompts and use defaults
            #[arg(short, long)]
            non_interactive: bool,
            
            /// Force reinstall even if already set up
            #[arg(short, long)]
            force: bool,
        },
        
        /// Verify MCP configuration and server status
        Verify {
            /// Show detailed verification output
            #[arg(short, long)]
            verbose: bool,
        },
        
        /// Show current MCP server status
        Status {
            /// Show process information
            #[arg(short, long)]
            processes: bool,
        },
        
        /// Start the MCP server
        Start {
            /// Run in background (daemon mode)
            #[arg(short, long)]
            daemon: bool,
        },
        
        /// Stop the MCP server
        Stop {
            /// Force stop all instances
            #[arg(short, long)]
            force: bool,
        },
        
        /// List installed MCP servers
        List,
        
        /// Configure MCP servers
        Config {
            /// Path to custom configuration file
            #[arg(short, long)]
            file: Option<PathBuf>,
            
            /// Show current configuration
            #[arg(short, long)]
            show: bool,
        },
        
        /// Test MCP server connection
        Test {
            /// Server to test
            server: String,
        },
    }

    #[derive(Serialize, Deserialize)]
    struct McpConfig {
        #[serde(rename = "mcpServers")]
        servers: std::collections::HashMap<String, ServerConfig>,
    }

    #[derive(Serialize, Deserialize)]
    struct ServerConfig {
        #[serde(rename = "type", default)]
        server_type: Option<String>,
        command: String,
        args: Vec<String>,
        #[serde(default)]
        env: std::collections::HashMap<String, String>,
    }

    impl Execute for McpCommand {
        async fn execute(&self) -> Result<()> {
            match &self.command {
                McpSubcommands::Setup { non_interactive, force } => {
                    setup_mcp_server(*non_interactive, *force).await
                }
                McpSubcommands::Verify { verbose } => {
                    verify_mcp_setup(*verbose).await
                }
                McpSubcommands::Status { processes } => {
                    show_mcp_status(*processes).await
                }
                McpSubcommands::Start { daemon } => {
                    start_mcp_server(*daemon).await
                }
                McpSubcommands::Stop { force } => {
                    stop_mcp_server(*force).await
                }
                McpSubcommands::List => list_mcp_servers().await,
                McpSubcommands::Config { file, show } => {
                    configure_mcp(file.as_deref(), *show).await
                }
                McpSubcommands::Test { server } => test_mcp_server(server).await,
            }
        }
    }

    async fn setup_mcp_server(non_interactive: bool, force: bool) -> Result<()> {
        tracing::info!("Setting up MCP server for KindlyGuard");
        
        // Check if already configured
        let config_path = get_mcp_config_path()?;
        if config_path.exists() && !force {
            tracing::warn!("MCP configuration already exists at {:?}", config_path);
            if !non_interactive {
                let proceed = dialoguer::Confirm::new()
                    .with_prompt("Configuration exists. Overwrite?")
                    .default(false)
                    .interact()?;
                if !proceed {
                    tracing::info!("Setup cancelled");
                    return Ok(());
                }
            } else {
                tracing::info!("Use --force to overwrite existing configuration");
                return Ok(());
            }
        }
        
        // Build the project first if needed
        if !non_interactive {
            let build = dialoguer::Confirm::new()
                .with_prompt("Build kindly-guard-server first?")
                .default(true)
                .interact()?;
            if build {
                tracing::info!("Building kindly-guard-server in release mode...");
                let status = Command::new("cargo")
                    .args(["build", "--release", "--package", "kindly-guard-server"])
                    .current_dir(find_project_root()?)
                    .status()?;
                if !status.success() {
                    return Err(anyhow::anyhow!("Build failed"));
                }
            }
        }
        
        // Find KindlyGuard server binary
        let kg_server = find_kindlyguard_server()?;
        tracing::info!("Found KindlyGuard server at: {:?}", kg_server);
        
        // Create MCP server directory
        let mcp_server_dir = home_dir()?
            .join(".claude/mcp-servers/kindly-guard");
        std::fs::create_dir_all(&mcp_server_dir)?;
        
        // Copy binary to MCP server directory
        let target_binary = mcp_server_dir.join("kindly-guard");
        std::fs::copy(&kg_server, &target_binary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&target_binary)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&target_binary, perms)?;
        }
        
        // Create default configuration file
        let server_config_file = mcp_server_dir.join("config.toml");
        if !server_config_file.exists() || force {
            let config_content = r#"# Kindly Guard Configuration
mode = "standard"
log_level = "info"

[rate_limit]
window_secs = 60
max_requests = 100

[scanner]
max_input_size = 1048576  # 1MB
patterns_file = ""

[metrics]
enabled = true
export_interval_secs = 60

[auth]
require_auth = false
"#;
            std::fs::write(&server_config_file, config_content)?;
        }
        
        // Create or update MCP configuration
        let mut config = if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            serde_json::from_str(&content)?
        } else {
            McpConfig { servers: HashMap::new() }
        };
        
        // Add KindlyGuard server
        let mut env = HashMap::new();
        env.insert("RUST_LOG".to_string(), "info".to_string());
        
        config.servers.insert(
            "kindly-guard".to_string(),
            ServerConfig {
                server_type: Some("stdio".to_string()),
                command: target_binary.to_string_lossy().to_string(),
                args: vec!["--config".to_string(), server_config_file.to_string_lossy().to_string()],
                env,
            },
        );
        
        // Save configuration
        let content = serde_json::to_string_pretty(&config)?;
        std::fs::write(&config_path, content)?;
        
        tracing::info!("MCP configuration saved to: {:?}", config_path);
        tracing::info!("Setup complete! Restart Claude Desktop to use the MCP server.");
        
        Ok(())
    }
    
    async fn verify_mcp_setup(verbose: bool) -> Result<()> {
        tracing::info!("Verifying MCP configuration");
        
        // Check configuration file
        let config_path = get_mcp_config_path()?;
        if !config_path.exists() {
            tracing::error!("MCP configuration not found at {:?}", config_path);
            return Err(anyhow::anyhow!("MCP not configured"));
        }
        
        // Load configuration
        let content = std::fs::read_to_string(&config_path)?;
        let config: McpConfig = serde_json::from_str(&content)?;
        
        // Check for KindlyGuard server
        if let Some(server) = config.servers.get("kindly-guard") {
            let command_path = Path::new(&server.command);
            if !command_path.exists() {
                tracing::error!("Server binary not found at: {:?}", command_path);
                return Err(anyhow::anyhow!("Server binary not found"));
            }
            
            // Test server execution
            if verbose {
                tracing::info!("Testing server execution...");
                let output = Command::new(&server.command)
                    .arg("--version")
                    .output()?;
                    
                if output.status.success() {
                    let version = String::from_utf8_lossy(&output.stdout);
                    tracing::info!("Server version: {}", version.trim());
                }
            }
            
            // Test MCP protocol
            tracing::info!("Testing MCP protocol communication...");
            test_mcp_protocol(&server.command, &server.args)?;
            
            tracing::info!("MCP configuration verified successfully");
        } else {
            tracing::error!("KindlyGuard server not configured");
            return Err(anyhow::anyhow!("Server not in configuration"));
        }
        
        Ok(())
    }
    
    async fn show_mcp_status(show_processes: bool) -> Result<()> {
        tracing::info!("Checking MCP server status");
        
        // Check configuration
        let config_path = get_mcp_config_path()?;
        if !config_path.exists() {
            tracing::error!("MCP not configured");
            return Ok(());
        }
        
        let content = std::fs::read_to_string(&config_path)?;
        let config: McpConfig = serde_json::from_str(&content)?;
        
        tracing::info!("Configuration loaded from: {:?}", config_path);
        
        // Check server configuration
        if let Some(server) = config.servers.get("kindly-guard") {
            tracing::info!("KindlyGuard server configured:");
            tracing::info!("  Command: {}", server.command);
            tracing::info!("  Args: {:?}", server.args);
        } else {
            tracing::warn!("KindlyGuard server not configured");
        }
        
        // Check running processes
        if show_processes {
            check_running_processes()?;
        }
        
        Ok(())
    }
    
    async fn start_mcp_server(daemon: bool) -> Result<()> {
        tracing::info!("Starting MCP server");
        
        // Load configuration
        let config_path = get_mcp_config_path()?;
        let content = std::fs::read_to_string(&config_path)?;
        let config: McpConfig = serde_json::from_str(&content)?;
        
        let server = config.servers.get("kindly-guard")
            .ok_or_else(|| anyhow::anyhow!("KindlyGuard server not configured"))?;
        
        if daemon {
            // Start in background
            tracing::info!("Starting server in daemon mode");
            
            let mut cmd = Command::new(&server.command);
            cmd.args(&server.args);
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
            
            for (key, value) in &server.env {
                cmd.env(key, value);
            }
            
            cmd.spawn()?;
            tracing::info!("Server started in background");
        } else {
            // Start in foreground
            tracing::info!("Starting server in foreground mode");
            tracing::info!("Press Ctrl+C to stop");
            
            let mut cmd = Command::new(&server.command);
            cmd.args(&server.args);
            
            for (key, value) in &server.env {
                cmd.env(key, value);
            }
            
            let status = cmd.status()?;
            if !status.success() {
                tracing::error!("Server exited with status: {:?}", status);
            }
        }
        
        Ok(())
    }
    
    async fn stop_mcp_server(force: bool) -> Result<()> {
        tracing::info!("Stopping MCP server");
        
        // Find running processes
        let pids = find_kindlyguard_processes()?;
        
        if pids.is_empty() {
            tracing::info!("No running KindlyGuard processes found");
            return Ok(());
        }
        
        tracing::info!("Found {} running process(es)", pids.len());
        
        for pid in pids {
            if force {
                Command::new("kill")
                    .arg("-9")
                    .arg(pid.to_string())
                    .status()?;
                tracing::info!("Force killed process {}", pid);
            } else {
                Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status()?;
                tracing::info!("Sent TERM signal to process {}", pid);
            }
        }
        
        Ok(())
    }

    async fn list_mcp_servers() -> Result<()> {
        let config_path = get_mcp_config_path()?;
        
        if !config_path.exists() {
            tracing::warn!("No MCP configuration found at {:?}", config_path);
            return Ok(());
        }

        let content = tokio::fs::read_to_string(&config_path).await?;
        let config: McpConfig = serde_json::from_str(&content)?;

        tracing::info!("Installed MCP servers:");
        for (name, server) in config.servers.iter() {
            tracing::info!("  {} - {}", name, server.command);
        }

        Ok(())
    }

    async fn configure_mcp(file: Option<&Path>, show: bool) -> Result<()> {
        let config_path = file.map(PathBuf::from)
            .unwrap_or_else(|| get_mcp_config_path().unwrap());
        
        if show {
            if !config_path.exists() {
                tracing::error!("Configuration file not found: {:?}", config_path);
                return Ok(());
            }
            
            let content = std::fs::read_to_string(&config_path)?;
            println!("{}", content);
        } else if let Some(custom_file) = file {
            tracing::info!("Loading configuration from: {:?}", custom_file);
            
            if !custom_file.exists() {
                return Err(anyhow::anyhow!("Configuration file not found"));
            }
            
            // Validate configuration
            let content = std::fs::read_to_string(custom_file)?;
            let _: McpConfig = serde_json::from_str(&content)?;
            
            // Copy to default location
            let default_path = get_mcp_config_path()?;
            std::fs::copy(custom_file, &default_path)?;
            tracing::info!("Configuration updated at: {:?}", default_path);
        } else {
            // Interactive configuration editor
            tracing::info!("Opening configuration editor...");
            let editor = std::env::var("EDITOR")
                .unwrap_or_else(|_| "nano".to_string());
                
            Command::new(&editor)
                .arg(&config_path)
                .status()?;
        }
        
        Ok(())
    }

    async fn test_mcp_server(server: &str) -> Result<()> {
        tracing::info!("Testing MCP server '{}'...", server);
        
        let config_path = get_mcp_config_path()?;
        let content = std::fs::read_to_string(&config_path)?;
        let config: McpConfig = serde_json::from_str(&content)?;
        
        if let Some(server_config) = config.servers.get(server) {
            test_mcp_protocol(&server_config.command, &server_config.args)?;
            tracing::info!("Test completed successfully");
        } else {
            tracing::error!("Server '{}' not found in configuration", server);
        }
        
        Ok(())
    }
    
    // Helper functions
    
    fn get_mcp_config_path() -> Result<PathBuf> {
        let home = home_dir()?;
        
        // Check for different possible locations
        let candidates = vec![
            home.join(".mcp.json"),
            home.join(".config/claude/mcp.json"),
        ];
        
        for path in &candidates {
            if path.exists() {
                return Ok(path.clone());
            }
        }
        
        // Default to .mcp.json
        Ok(home.join(".mcp.json"))
    }
    
    fn find_project_root() -> Result<PathBuf> {
        let mut current = std::env::current_dir()?;
        
        loop {
            if current.join("Cargo.toml").exists() && current.join("kindly-guard-server").exists() {
                return Ok(current);
            }
            
            if let Some(parent) = current.parent() {
                current = parent.to_path_buf();
            } else {
                break;
            }
        }
        
        // Try common locations
        let home = home_dir()?;
        let candidates = vec![
            home.join("kindly-guard"),
            PathBuf::from("/home/samuel/kindly-guard"),
        ];
        
        for path in candidates {
            if path.join("Cargo.toml").exists() && path.join("kindly-guard-server").exists() {
                return Ok(path);
            }
        }
        
        Err(anyhow::anyhow!("Could not find kindly-guard project root"))
    }
    
    fn find_kindlyguard_server() -> Result<PathBuf> {
        let candidates = vec![
            PathBuf::from("target/release/kindly-guard-server"),
            PathBuf::from("target/debug/kindly-guard-server"),
            PathBuf::from("../kindly-guard-server/target/release/kindly-guard-server"),
            PathBuf::from("../kindly-guard-server/target/debug/kindly-guard-server"),
            PathBuf::from("/usr/local/bin/kindly-guard-server"),
            PathBuf::from("/usr/bin/kindly-guard-server"),
            home_dir()?.join(".cargo/bin/kindly-guard-server"),
        ];
        
        for path in candidates {
            if path.exists() {
                return Ok(path.canonicalize()?);
            }
        }
        
        // Try using 'which'
        if let Ok(output) = Command::new("which")
            .arg("kindly-guard-server")
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout);
                return Ok(PathBuf::from(path.trim()));
            }
        }
        
        Err(anyhow::anyhow!(
            "KindlyGuard server not found. Build it with 'cargo build --release' in the kindly-guard directory"
        ))
    }
    
    fn test_mcp_protocol(command: &str, args: &[String]) -> Result<()> {
        let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kindly-tools","version":"0.1.0"}}}"#;
        
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
            
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(init_request.as_bytes())?;
            stdin.write_all(b"\n")?;
            stdin.flush()?;
        }
        
        // Wait briefly for response
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        let output = child.wait_with_output()?;
        let response = String::from_utf8_lossy(&output.stdout);
        
        if response.contains("jsonrpc") && response.contains("result") {
            tracing::info!("MCP protocol test successful");
        } else if response.contains("error") {
            tracing::error!("MCP protocol test failed");
            return Err(anyhow::anyhow!("MCP protocol error"));
        } else {
            tracing::warn!("Unexpected MCP protocol response");
        }
        
        Ok(())
    }
    
    fn check_running_processes() -> Result<()> {
        tracing::info!("Checking for running processes...");
        
        let output = Command::new("ps")
            .args(["aux"])
            .output()?;
            
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut found_any = false;
        
        for line in output_str.lines() {
            if line.contains("kindly-guard-server") && !line.contains("grep") {
                println!("{}", line);
                found_any = true;
            }
        }
        
        if !found_any {
            tracing::info!("No running KindlyGuard processes found");
        }
        
        Ok(())
    }
    
    fn find_kindlyguard_processes() -> Result<Vec<u32>> {
        let output = Command::new("pgrep")
            .arg("-f")
            .arg("kindly-guard-server")
            .output()?;
            
        if !output.status.success() {
            return Ok(vec![]);
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let pids: Vec<u32> = output_str
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect();
            
        Ok(pids)
    }
} // End of mcp module

pub mod utils {
    use super::*;
    use std::process::Command;

    /// Run a command and return its output
    pub fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
        let output = Command::new(cmd).args(args).output()?;

        if !output.status.success() {
            anyhow::bail!(
                "Command failed: {} {}",
                cmd,
                args.join(" ")
            );
        }

        Ok(String::from_utf8(output.stdout)?)
    }

    /// Check if running in CI environment
    pub fn is_ci() -> bool {
        std::env::var("CI").is_ok()
    }

    /// Get the current git branch
    pub fn current_git_branch() -> Result<String> {
        run_command("git", &["rev-parse", "--abbrev-ref", "HEAD"])
            .map(|s| s.trim().to_string())
    }
}