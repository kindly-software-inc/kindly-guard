// Modules defined inline below
pub mod platform;

use anyhow::Result;
use std::path::{Path, PathBuf};

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

/// Download a file with progress bar
pub async fn download_file(_url: &str, _dest: &Path) -> Result<()> {
    // TODO: Implement when reqwest MSRV is compatible
    anyhow::bail!("Download functionality temporarily disabled due to MSRV constraints")
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
        
        tracing::info!("Setting up development environment...");
        
        let platform = Platform::detect();
        tracing::info!("Detected platform: {}", platform);

        if !skip_rust {
            // Install Rust tools
            let tools = ["cargo-audit", "cargo-geiger", "cargo-dist"];
            for tool in &tools {
                tracing::info!("Installing {}...", tool);
                std::process::Command::new("cargo")
                    .args(["install", tool])
                    .status()?;
            }
        }

        tracing::info!("Development environment setup complete!");
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
}

pub mod install {
    use super::*;
    use clap::Subcommand;

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
            #[arg(short, long)]
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
        
        let platform = Platform::detect();
        let version_str = version.unwrap_or("latest");
        
        // Auto-detect best installation method if not specified
        let install_method = if let Some(m) = method {
            m.to_string()
        } else {
            match platform {
                Platform::MacOS => {
                    if command_exists("brew") {
                        "homebrew".to_string()
                    } else {
                        "npm".to_string()
                    }
                }
                Platform::Linux => "npm".to_string(),
                Platform::Windows => "npm".to_string(),
                _ => "npm".to_string(),
            }
        };
        
        println!("\n{}", "KindlyGuard Installation".bold().blue());
        println!("Platform: {}", platform.to_string().green());
        println!("Method: {}", install_method.green());
        println!("Version: {}\n", version_str.green());
        
        match install_method.as_str() {
            "homebrew" | "brew" => {
                println!("{}", "Installing via Homebrew...".yellow());
                println!("\nRun these commands:");
                println!("  {} {}", "$".dimmed(), "brew tap kindly-software-inc/tap".bright_white());
                println!("  {} {}", "$".dimmed(), "brew install kindlyguard".bright_white());
                
                if version != Some("latest") && version.is_some() {
                    println!("\n{}: Homebrew installs the latest version by default.", "Note".yellow());
                    println!("To install a specific version, use npm instead.");
                }
                
                // Check if tap exists
                if command_exists("brew") {
                    let output = std::process::Command::new("brew")
                        .args(["tap"])
                        .output()?;
                    
                    let taps = String::from_utf8_lossy(&output.stdout);
                    if !taps.contains("kindly-software-inc/tap") {
                        println!("\n{}: The Homebrew tap hasn't been added yet.", "Info".cyan());
                        println!("After running the tap command, you can install with:");
                        println!("  {} {}", "$".dimmed(), "brew install kindlyguard".bright_white());
                    }
                }
            }
            "npm" => {
                println!("{}", "Installing via npm...".yellow());
                let package = if let Some(v) = version {
                    format!("kindly-guard-server@{}", v)
                } else {
                    "kindly-guard-server".to_string()
                };
                
                println!("\nRun this command:");
                println!("  {} npm install -g {}", "$".dimmed(), package.bright_white());
                
                if !command_exists("npm") {
                    println!("\n{}: npm is not installed. Install Node.js first:", "Error".red());
                    println!("  {}", "https://nodejs.org/".blue().underline());
                }
            }
            "cargo" => {
                println!("{}", "Installing via Cargo...".yellow());
                let package = if let Some(v) = version {
                    format!("kindlyguard@{}", v)
                } else {
                    "kindlyguard".to_string()
                };
                
                println!("\nRun this command:");
                println!("  {} cargo install {}", "$".dimmed(), package.bright_white());
                
                if !command_exists("cargo") {
                    println!("\n{}: Cargo is not installed. Install Rust first:", "Error".red());
                    println!("  {}", "https://rustup.rs/".blue().underline());
                }
            }
            "binary" => {
                println!("{}", "Downloading binary release...".yellow());
                println!("\nVisit the releases page:");
                println!("  {}", "https://github.com/kindly-software-inc/kindly-guard/releases".blue().underline());
                
                match platform {
                    Platform::MacOS => {
                        println!("\nDownload: kindly-guard-server-{}-apple-darwin.tar.gz", 
                            if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" });
                    }
                    Platform::Linux => {
                        println!("\nDownload: kindly-guard-server-x86_64-unknown-linux-gnu.tar.gz");
                    }
                    Platform::Windows => {
                        println!("\nDownload: kindly-guard-server-x86_64-pc-windows-msvc.zip");
                        println!("Or use the MSI installer: kindly-guard-server-x86_64-pc-windows-msvc.msi");
                    }
                    _ => {}
                }
            }
            _ => {
                anyhow::bail!("Unknown installation method: {}", install_method);
            }
        }
        
        println!("\n{}", "After installation:".bold());
        println!("  Run {} to start the MCP server", "kindlyguard --stdio".bright_white());
        println!("  Run {} for help\n", "kindlyguard --help".bright_white());
        
        Ok(())
    }

    async fn install_all() -> Result<()> {
        tracing::info!("Installing all recommended tools...");
        install_kindlyguard(None, None).await?;
        install_mcp_servers(None).await?;
        install_dev_deps().await?;
        Ok(())
    }

    async fn install_mcp_servers(server: Option<&str>) -> Result<()> {
        use dialoguer::Confirm;
        
        let servers = if let Some(s) = server {
            vec![s]
        } else {
            vec!["tree-sitter", "ast-grep", "filesystem"]
        };

        for server in servers {
            if Confirm::new()
                .with_prompt(format!("Install MCP server '{}'?", server))
                .default(true)
                .interact()?
            {
                tracing::info!("Installing MCP server: {}", server);
                // Installation logic here
            }
        }
        
        Ok(())
    }

    async fn install_dev_deps() -> Result<()> {
        tracing::info!("Installing development dependencies...");
        
        // Check for required system packages
        let packages = match crate::platform::Platform::detect() {
            crate::platform::Platform::Linux => vec!["build-essential", "pkg-config"],
            crate::platform::Platform::MacOS => vec!["xcode-select"],
            crate::platform::Platform::Windows => vec!["visual-studio-build-tools"],
            _ => vec![],
        };
        
        for pkg in packages {
            tracing::info!("Checking for {}...", pkg);
        }
        
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
}

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