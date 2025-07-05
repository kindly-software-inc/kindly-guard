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

//! Configuration support for the wrap command

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Default configuration file name
const CONFIG_FILE_NAME: &str = "wrap.toml";

/// Default commands to auto-wrap
const DEFAULT_AUTO_WRAP_COMMANDS: &[&str] = &[
    "claude",
    "openai",
    "gemini",
    "anthropic",
    "gpt",
    "ai",
    "llm",
    "copilot",
    "codewhisperer",
    "tabnine",
    "codium",
    "bard",
    "perplexity",
];

/// Wrap command configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapConfig {
    /// Whether auto-wrapping is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Protection mode: "warning" or "blocking"
    #[serde(default = "default_mode")]
    pub mode: WrapMode,

    /// List of commands to auto-wrap
    #[serde(default = "default_commands")]
    pub commands: HashSet<String>,

    /// Additional user-defined commands to wrap
    #[serde(default)]
    pub custom_commands: HashSet<String>,

    /// Server URL for threat detection
    #[serde(default = "default_server")]
    pub server: String,

    /// Whether to show detailed threat information
    #[serde(default = "default_verbose")]
    pub verbose: bool,

    /// Whether to log wrapped sessions
    #[serde(default)]
    pub log_sessions: bool,

    /// Path to session log directory
    #[serde(default)]
    pub log_directory: Option<PathBuf>,
}

/// Protection mode for wrapped commands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WrapMode {
    /// Show warnings but allow threats through
    Warning,
    /// Block detected threats
    Blocking,
}

impl Default for WrapConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            mode: default_mode(),
            commands: default_commands(),
            custom_commands: HashSet::new(),
            server: default_server(),
            verbose: default_verbose(),
            log_sessions: false,
            log_directory: None,
        }
    }
}

impl WrapConfig {
    /// Load configuration from the default location
    pub fn load() -> Result<Self> {
        let config_path = Self::default_config_path()?;
        
        if config_path.exists() {
            Self::load_from_path(&config_path)
        } else {
            // Return default config if file doesn't exist
            Ok(Self::default())
        }
    }

    /// Load configuration from a specific path
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read configuration from {}", path.display()))?;
        
        let mut config: Self = toml::from_str(&content)
            .with_context(|| format!("Failed to parse configuration from {}", path.display()))?;
        
        // Merge custom commands into the main commands set
        config.merge_custom_commands();
        
        Ok(config)
    }

    /// Save configuration to the default location
    pub fn save(&self) -> Result<()> {
        let config_path = Self::default_config_path()?;
        self.save_to_path(&config_path)
    }

    /// Save configuration to a specific path
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
        }

        let content = toml::to_string_pretty(self)
            .context("Failed to serialize configuration")?;
        
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write configuration to {}", path.display()))?;
        
        Ok(())
    }

    /// Get the default configuration file path
    pub fn default_config_path() -> Result<PathBuf> {
        let config_dir = crate::config_dir()?;
        Ok(config_dir.join(CONFIG_FILE_NAME))
    }

    /// Check if a command should be wrapped
    pub fn should_wrap(&self, command: &str) -> bool {
        if !self.enabled {
            return false;
        }
        
        // Check if the command or its basename is in our wrap list
        let basename = Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);
        
        self.commands.contains(basename) || self.commands.contains(command)
    }

    /// Add a custom command to wrap
    pub fn add_command(&mut self, command: String) {
        self.custom_commands.insert(command.clone());
        self.commands.insert(command);
    }

    /// Remove a command from the wrap list
    pub fn remove_command(&mut self, command: &str) -> bool {
        self.custom_commands.remove(command);
        self.commands.remove(command)
    }

    /// Merge custom commands into the main commands set
    fn merge_custom_commands(&mut self) {
        for cmd in &self.custom_commands {
            self.commands.insert(cmd.clone());
        }
    }

    /// Create a default configuration file with example settings
    pub fn create_default_config() -> Result<()> {
        let config_path = Self::default_config_path()?;
        
        if config_path.exists() {
            anyhow::bail!("Configuration file already exists at {}", config_path.display());
        }

        let default_config = Self::default();
        default_config.save_to_path(&config_path)?;
        
        println!("Created default configuration at: {}", config_path.display());
        Ok(())
    }

    /// Get effective mode as a string
    pub fn mode_string(&self) -> &'static str {
        match self.mode {
            WrapMode::Warning => "warning",
            WrapMode::Blocking => "blocking",
        }
    }
}

// Default value functions for serde
fn default_enabled() -> bool {
    true
}

fn default_mode() -> WrapMode {
    WrapMode::Warning
}

fn default_commands() -> HashSet<String> {
    DEFAULT_AUTO_WRAP_COMMANDS
        .iter()
        .map(|&s| s.to_string())
        .collect()
}

fn default_server() -> String {
    "http://localhost:8080".to_string()
}

fn default_verbose() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = WrapConfig::default();
        assert!(config.enabled);
        assert_eq!(config.mode, WrapMode::Warning);
        assert!(config.commands.contains("claude"));
        assert!(config.commands.contains("openai"));
    }

    #[test]
    fn test_should_wrap() {
        let mut config = WrapConfig::default();
        
        // Should wrap known commands
        assert!(config.should_wrap("claude"));
        assert!(config.should_wrap("openai"));
        
        // Should handle full paths
        assert!(config.should_wrap("/usr/bin/claude"));
        assert!(config.should_wrap("./openai"));
        
        // Should not wrap unknown commands
        assert!(!config.should_wrap("ls"));
        assert!(!config.should_wrap("cat"));
        
        // Should respect enabled flag
        config.enabled = false;
        assert!(!config.should_wrap("claude"));
    }

    #[test]
    fn test_add_remove_commands() {
        let mut config = WrapConfig::default();
        
        // Add custom command
        config.add_command("mycli".to_string());
        assert!(config.should_wrap("mycli"));
        assert!(config.custom_commands.contains("mycli"));
        
        // Remove command
        assert!(config.remove_command("mycli"));
        assert!(!config.should_wrap("mycli"));
        assert!(!config.custom_commands.contains("mycli"));
    }

    #[test]
    fn test_save_load_config() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("wrap.toml");
        
        // Create and save config
        let mut config = WrapConfig::default();
        config.mode = WrapMode::Blocking;
        config.add_command("custom-ai".to_string());
        config.verbose = true;
        config.save_to_path(&config_path)?;
        
        // Load and verify
        let loaded = WrapConfig::load_from_path(&config_path)?;
        assert_eq!(loaded.mode, WrapMode::Blocking);
        assert!(loaded.should_wrap("custom-ai"));
        assert!(loaded.verbose);
        
        Ok(())
    }

    #[test]
    fn test_mode_serialization() -> Result<()> {
        let warning_toml = r#"mode = "warning""#;
        let config: WrapConfig = toml::from_str(warning_toml)?;
        assert_eq!(config.mode, WrapMode::Warning);
        
        let blocking_toml = r#"mode = "blocking""#;
        let config: WrapConfig = toml::from_str(blocking_toml)?;
        assert_eq!(config.mode, WrapMode::Blocking);
        
        Ok(())
    }
}