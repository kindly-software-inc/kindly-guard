use std::path::{Path, PathBuf};
use std::fs;
use std::env;
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdeType {
    ClaudeDesktop,
    ClaudeCode,
    VsCode,
    Cursor,
    Zed,
    Neovim,
    Unknown,
}

impl IdeType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ClaudeDesktop => "Claude Desktop",
            Self::ClaudeCode => "Claude Code",
            Self::VsCode => "VS Code",
            Self::Cursor => "Cursor",
            Self::Zed => "Zed",
            Self::Neovim => "Neovim",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigFormat {
    Json,
    JsonLocal,
    Toml,
    Yaml,
}

impl ConfigFormat {
    pub fn extension(&self) -> &str {
        match self {
            Self::Json => "json",
            Self::JsonLocal => "json.local",
            Self::Toml => "toml",
            Self::Yaml => "yaml",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigLocation {
    pub path: PathBuf,
    pub format: ConfigFormat,
    pub exists: bool,
    pub ide: IdeType,
}

impl ConfigLocation {
    fn new(path: PathBuf, format: ConfigFormat, ide: IdeType) -> Self {
        let exists = path.exists();
        Self { path, format, exists, ide }
    }
}

pub struct McpDetector {
    platform: Platform,
}

#[derive(Debug, Clone, Copy)]
enum Platform {
    Windows,
    MacOs,
    Linux,
}

impl McpDetector {
    pub fn new() -> Self {
        let platform = if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        };
        
        Self { platform }
    }

    /// Detect all possible MCP configuration locations
    pub fn detect_all(&self) -> Result<Vec<ConfigLocation>> {
        let mut locations = Vec::new();
        
        // Claude Desktop configs
        locations.extend(self.get_claude_desktop_configs()?);
        
        // Claude Code configs
        locations.extend(self.get_claude_code_configs()?);
        
        // VS Code configs
        locations.extend(self.get_vscode_configs()?);
        
        // Cursor configs
        locations.extend(self.get_cursor_configs()?);
        
        // Zed configs
        locations.extend(self.get_zed_configs()?);
        
        // Neovim configs
        locations.extend(self.get_neovim_configs()?);
        
        // Global MCP configs
        locations.extend(self.get_global_mcp_configs()?);
        
        Ok(locations)
    }

    /// Detect which IDE/terminal is currently running
    pub fn detect_active_ide(&self) -> Result<IdeType> {
        // Check environment variables first
        if env::var("CLAUDE_CODE").is_ok() {
            return Ok(IdeType::ClaudeCode);
        }
        
        if env::var("CLAUDE_DESKTOP").is_ok() {
            return Ok(IdeType::ClaudeDesktop);
        }
        
        if env::var("VSCODE_PID").is_ok() {
            return Ok(IdeType::VsCode);
        }
        
        if env::var("CURSOR_PID").is_ok() {
            return Ok(IdeType::Cursor);
        }
        
        if env::var("NVIM").is_ok() || env::var("NVIM_LISTEN_ADDRESS").is_ok() {
            return Ok(IdeType::Neovim);
        }
        
        // Check running processes
        match self.platform {
            Platform::Windows => self.detect_windows_processes(),
            Platform::MacOs => self.detect_macos_processes(),
            Platform::Linux => self.detect_linux_processes(),
        }
    }

    /// Get configuration location for a specific IDE
    pub fn get_config_location(&self, ide: IdeType) -> Result<ConfigLocation> {
        let path = self.get_config_path(ide)?;
        let format = ConfigFormat::Json; // Default to JSON for now
        Ok(ConfigLocation::new(path, format, ide))
    }

    /// Get configuration path for a specific IDE
    pub fn get_config_path(&self, ide: IdeType) -> Result<PathBuf> {
        match ide {
            IdeType::ClaudeDesktop => self.get_claude_desktop_config_path(),
            IdeType::ClaudeCode => self.get_claude_code_config_path(),
            IdeType::VsCode => self.get_vscode_config_path(),
            IdeType::Cursor => self.get_cursor_config_path(),
            IdeType::Zed => self.get_zed_config_path(),
            IdeType::Neovim => self.get_neovim_config_path(),
            IdeType::Unknown => Err(anyhow::anyhow!("Cannot get config path for unknown IDE")),
        }
    }

    /// Detect Claude-specific configurations
    pub fn detect_claude_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        configs.extend(self.get_claude_desktop_configs()?);
        configs.extend(self.get_claude_code_configs()?);
        Ok(configs)
    }

    // Platform-specific home directory helpers
    fn get_home_dir(&self) -> Result<PathBuf> {
        match self.platform {
            Platform::Windows => {
                env::var("USERPROFILE")
                    .or_else(|_| env::var("HOMEDRIVE").and_then(|drive| 
                        env::var("HOMEPATH").map(|path| format!("{}{}", drive, path))))
                    .map(PathBuf::from)
                    .context("Failed to get Windows home directory")
            }
            Platform::MacOs | Platform::Linux => {
                env::var("HOME")
                    .map(PathBuf::from)
                    .context("Failed to get Unix home directory")
            }
        }
    }

    fn get_config_dir(&self) -> Result<PathBuf> {
        match self.platform {
            Platform::Windows => {
                env::var("APPDATA")
                    .map(PathBuf::from)
                    .context("Failed to get Windows config directory")
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                Ok(home.join("Library").join("Application Support"))
            }
            Platform::Linux => {
                env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .or_else(|_| {
                        self.get_home_dir().map(|home| home.join(".config"))
                    })
                    .context("Failed to get Linux config directory")
            }
        }
    }

    // Claude Desktop configurations
    fn get_claude_desktop_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                configs.push(ConfigLocation::new(
                    appdata.join("Claude").join("claude_desktop_config.json"),
                    ConfigFormat::Json,
                    IdeType::ClaudeDesktop,
                ));
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                configs.push(ConfigLocation::new(
                    home.join("Library")
                        .join("Application Support")
                        .join("Claude")
                        .join("claude_desktop_config.json"),
                    ConfigFormat::Json,
                    IdeType::ClaudeDesktop,
                ));
            }
            Platform::Linux => {
                let config = self.get_config_dir()?;
                configs.push(ConfigLocation::new(
                    config.join("claude").join("claude_desktop_config.json"),
                    ConfigFormat::Json,
                    IdeType::ClaudeDesktop,
                ));
            }
        }
        
        Ok(configs)
    }

    // Claude Code configurations
    fn get_claude_code_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        let home = self.get_home_dir()?;
        
        // Primary config location
        configs.push(ConfigLocation::new(
            home.join(".mcp.json"),
            ConfigFormat::Json,
            IdeType::ClaudeCode,
        ));
        
        // Local override
        configs.push(ConfigLocation::new(
            home.join(".mcp.json.local"),
            ConfigFormat::JsonLocal,
            IdeType::ClaudeCode,
        ));
        
        // Alternative locations
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                configs.push(ConfigLocation::new(
                    appdata.join("claude-code").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::ClaudeCode,
                ));
            }
            Platform::MacOs => {
                configs.push(ConfigLocation::new(
                    home.join("Library")
                        .join("Application Support")
                        .join("claude-code")
                        .join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::ClaudeCode,
                ));
            }
            Platform::Linux => {
                let config = self.get_config_dir()?;
                configs.push(ConfigLocation::new(
                    config.join("claude-code").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::ClaudeCode,
                ));
            }
        }
        
        Ok(configs)
    }

    // VS Code configurations
    fn get_vscode_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                configs.push(ConfigLocation::new(
                    appdata.join("Code").join("User").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::VsCode,
                ));
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                configs.push(ConfigLocation::new(
                    home.join("Library")
                        .join("Application Support")
                        .join("Code")
                        .join("User")
                        .join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::VsCode,
                ));
            }
            Platform::Linux => {
                let config = self.get_config_dir()?;
                configs.push(ConfigLocation::new(
                    config.join("Code").join("User").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::VsCode,
                ));
            }
        }
        
        Ok(configs)
    }

    // Cursor configurations
    fn get_cursor_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                configs.push(ConfigLocation::new(
                    appdata.join("Cursor").join("User").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::Cursor,
                ));
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                configs.push(ConfigLocation::new(
                    home.join("Library")
                        .join("Application Support")
                        .join("Cursor")
                        .join("User")
                        .join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::Cursor,
                ));
            }
            Platform::Linux => {
                let config = self.get_config_dir()?;
                configs.push(ConfigLocation::new(
                    config.join("Cursor").join("User").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::Cursor,
                ));
            }
        }
        
        Ok(configs)
    }

    // Zed configurations
    fn get_zed_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                configs.push(ConfigLocation::new(
                    appdata.join("Zed").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::Zed,
                ));
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                configs.push(ConfigLocation::new(
                    home.join("Library").join("Application Support").join("Zed").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::Zed,
                ));
            }
            Platform::Linux => {
                let config_home = env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        let home = self.get_home_dir().unwrap_or_default();
                        home.join(".config")
                    });
                configs.push(ConfigLocation::new(
                    config_home.join("zed").join("mcp.json"),
                    ConfigFormat::Json,
                    IdeType::Zed,
                ));
            }
        }
        
        Ok(configs)
    }

    // Neovim configurations
    fn get_neovim_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        let home = self.get_home_dir()?;
        
        // Standard Neovim config locations
        configs.push(ConfigLocation::new(
            home.join(".config").join("nvim").join("mcp.json"),
            ConfigFormat::Json,
            IdeType::Neovim,
        ));
        
        configs.push(ConfigLocation::new(
            home.join(".config").join("nvim").join("mcp.toml"),
            ConfigFormat::Toml,
            IdeType::Neovim,
        ));
        
        // Legacy location
        configs.push(ConfigLocation::new(
            home.join(".nvim").join("mcp.json"),
            ConfigFormat::Json,
            IdeType::Neovim,
        ));
        
        Ok(configs)
    }

    // Global MCP configurations
    fn get_global_mcp_configs(&self) -> Result<Vec<ConfigLocation>> {
        let mut configs = Vec::new();
        let home = self.get_home_dir()?;
        
        // Global config in home directory
        configs.push(ConfigLocation::new(
            home.join(".mcp").join("config.json"),
            ConfigFormat::Json,
            IdeType::Unknown,
        ));
        
        configs.push(ConfigLocation::new(
            home.join(".mcp").join("config.toml"),
            ConfigFormat::Toml,
            IdeType::Unknown,
        ));
        
        configs.push(ConfigLocation::new(
            home.join(".mcp").join("config.yaml"),
            ConfigFormat::Yaml,
            IdeType::Unknown,
        ));
        
        // System-wide configs
        match self.platform {
            Platform::Windows => {
                let programdata = env::var("PROGRAMDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"));
                configs.push(ConfigLocation::new(
                    programdata.join("mcp").join("config.json"),
                    ConfigFormat::Json,
                    IdeType::Unknown,
                ));
            }
            Platform::MacOs | Platform::Linux => {
                configs.push(ConfigLocation::new(
                    PathBuf::from("/etc/mcp/config.json"),
                    ConfigFormat::Json,
                    IdeType::Unknown,
                ));
                configs.push(ConfigLocation::new(
                    PathBuf::from("/etc/mcp/config.toml"),
                    ConfigFormat::Toml,
                    IdeType::Unknown,
                ));
            }
        }
        
        Ok(configs)
    }

    // Process detection methods
    fn detect_windows_processes(&self) -> Result<IdeType> {
        use std::process::Command;
        
        let output = Command::new("tasklist")
            .output()
            .context("Failed to run tasklist")?;
        
        let processes = String::from_utf8_lossy(&output.stdout);
        
        if processes.contains("Claude.exe") || processes.contains("claude.exe") {
            return Ok(IdeType::ClaudeDesktop);
        }
        
        if processes.contains("ClaudeCode.exe") || processes.contains("claude-code.exe") {
            return Ok(IdeType::ClaudeCode);
        }
        
        if processes.contains("Code.exe") {
            return Ok(IdeType::VsCode);
        }
        
        if processes.contains("Cursor.exe") {
            return Ok(IdeType::Cursor);
        }
        
        if processes.contains("nvim.exe") || processes.contains("nvim-qt.exe") {
            return Ok(IdeType::Neovim);
        }
        
        Ok(IdeType::Unknown)
    }

    fn detect_macos_processes(&self) -> Result<IdeType> {
        use std::process::Command;
        
        let output = Command::new("ps")
            .args(&["-ax"])
            .output()
            .context("Failed to run ps")?;
        
        let processes = String::from_utf8_lossy(&output.stdout);
        
        if processes.contains("Claude.app") || processes.contains("Claude Desktop") {
            return Ok(IdeType::ClaudeDesktop);
        }
        
        if processes.contains("Claude Code") || processes.contains("claude-code") {
            return Ok(IdeType::ClaudeCode);
        }
        
        if processes.contains("Visual Studio Code.app") || processes.contains("Code Helper") {
            return Ok(IdeType::VsCode);
        }
        
        if processes.contains("Cursor.app") || processes.contains("Cursor Helper") {
            return Ok(IdeType::Cursor);
        }
        
        if processes.contains("nvim") {
            return Ok(IdeType::Neovim);
        }
        
        Ok(IdeType::Unknown)
    }

    fn detect_linux_processes(&self) -> Result<IdeType> {
        use std::process::Command;
        
        let output = Command::new("ps")
            .args(&["aux"])
            .output()
            .context("Failed to run ps")?;
        
        let processes = String::from_utf8_lossy(&output.stdout);
        
        if processes.contains("claude-desktop") || processes.contains("Claude") {
            return Ok(IdeType::ClaudeDesktop);
        }
        
        if processes.contains("claude-code") {
            return Ok(IdeType::ClaudeCode);
        }
        
        if processes.contains("code") && !processes.contains("claude-code") {
            return Ok(IdeType::VsCode);
        }
        
        if processes.contains("cursor") {
            return Ok(IdeType::Cursor);
        }
        
        if processes.contains("nvim") {
            return Ok(IdeType::Neovim);
        }
        
        Ok(IdeType::Unknown)
    }

    // Helper methods to get primary config paths
    fn get_claude_desktop_config_path(&self) -> Result<PathBuf> {
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                Ok(appdata.join("Claude").join("claude_desktop_config.json"))
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                Ok(home.join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude_desktop_config.json"))
            }
            Platform::Linux => {
                let config = self.get_config_dir()?;
                Ok(config.join("claude").join("claude_desktop_config.json"))
            }
        }
    }

    fn get_claude_code_config_path(&self) -> Result<PathBuf> {
        let home = self.get_home_dir()?;
        Ok(home.join(".mcp.json"))
    }

    fn get_vscode_config_path(&self) -> Result<PathBuf> {
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                Ok(appdata.join("Code").join("User").join("mcp.json"))
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                Ok(home.join("Library")
                    .join("Application Support")
                    .join("Code")
                    .join("User")
                    .join("mcp.json"))
            }
            Platform::Linux => {
                let config = self.get_config_dir()?;
                Ok(config.join("Code").join("User").join("mcp.json"))
            }
        }
    }

    fn get_cursor_config_path(&self) -> Result<PathBuf> {
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                Ok(appdata.join("Cursor").join("User").join("mcp.json"))
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                Ok(home.join("Library")
                    .join("Application Support")
                    .join("Cursor")
                    .join("User")
                    .join("mcp.json"))
            }
            Platform::Linux => {
                let config = self.get_config_dir()?;
                Ok(config.join("Cursor").join("User").join("mcp.json"))
            }
        }
    }

    fn get_zed_config_path(&self) -> Result<PathBuf> {
        match self.platform {
            Platform::Windows => {
                let appdata = env::var("APPDATA").map(PathBuf::from)?;
                Ok(appdata.join("Zed").join("mcp.json"))
            }
            Platform::MacOs => {
                let home = self.get_home_dir()?;
                Ok(home.join("Library").join("Application Support").join("Zed").join("mcp.json"))
            }
            Platform::Linux => {
                let config_home = env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        let home = self.get_home_dir().unwrap_or_default();
                        home.join(".config")
                    });
                Ok(config_home.join("zed").join("mcp.json"))
            }
        }
    }

    fn get_neovim_config_path(&self) -> Result<PathBuf> {
        let home = self.get_home_dir()?;
        Ok(home.join(".config").join("nvim").join("mcp.json"))
    }

    /// Check if a specific MCP server is configured
    pub fn is_server_configured(&self, server_name: &str) -> Result<bool> {
        let configs = self.detect_claude_configs()?;
        
        for config in configs.iter().filter(|c| c.exists) {
            if self.check_server_in_config(&config.path, server_name)? {
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    fn check_server_in_config(&self, path: &Path, server_name: &str) -> Result<bool> {
        let content = fs::read_to_string(path)?;
        
        // Basic check - could be enhanced with proper JSON/TOML parsing
        Ok(content.contains(server_name))
    }

    /// Get a summary of MCP configuration status
    pub fn get_status_summary(&self) -> Result<String> {
        let active_ide = self.detect_active_ide()?;
        let all_configs = self.detect_all()?;
        let existing_configs: Vec<_> = all_configs.iter()
            .filter(|c| c.exists)
            .collect();
        
        let mut summary = format!("MCP Configuration Status\n");
        summary.push_str(&format!("========================\n"));
        summary.push_str(&format!("Active IDE: {}\n", active_ide.as_str()));
        summary.push_str(&format!("Platform: {:?}\n", self.platform));
        summary.push_str(&format!("Total config locations checked: {}\n", all_configs.len()));
        summary.push_str(&format!("Existing configurations: {}\n\n", existing_configs.len()));
        
        if !existing_configs.is_empty() {
            summary.push_str("Found configurations:\n");
            for config in existing_configs {
                summary.push_str(&format!("  - {} ({:?}): {}\n", 
                    config.ide.as_str(),
                    config.format,
                    config.path.display()
                ));
            }
        }
        
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_creation() {
        let detector = McpDetector::new();
        assert!(matches!(detector.platform, Platform::Windows | Platform::MacOs | Platform::Linux));
    }

    #[test]
    fn test_config_format_extensions() {
        assert_eq!(ConfigFormat::Json.extension(), "json");
        assert_eq!(ConfigFormat::JsonLocal.extension(), "json.local");
        assert_eq!(ConfigFormat::Toml.extension(), "toml");
        assert_eq!(ConfigFormat::Yaml.extension(), "yaml");
    }

    #[test]
    fn test_ide_type_strings() {
        assert_eq!(IdeType::ClaudeDesktop.as_str(), "Claude Desktop");
        assert_eq!(IdeType::ClaudeCode.as_str(), "Claude Code");
        assert_eq!(IdeType::VsCode.as_str(), "VS Code");
        assert_eq!(IdeType::Cursor.as_str(), "Cursor");
        assert_eq!(IdeType::Neovim.as_str(), "Neovim");
        assert_eq!(IdeType::Unknown.as_str(), "Unknown");
    }
}