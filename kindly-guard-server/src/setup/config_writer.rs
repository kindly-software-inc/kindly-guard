use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Trait for writing MCP configurations to different file formats
pub trait ConfigWriter: Send + Sync {
    /// Write or update the configuration for kindly-guard
    fn write_config(&self, path: &Path, server_path: &str) -> Result<()>;
    
    /// Check if the configuration already exists
    fn config_exists(&self, path: &Path) -> Result<bool>;
    
    /// Create a backup of the existing configuration
    fn backup_config(&self, path: &Path) -> Result<Option<PathBuf>>;
}

/// JSON configuration writer for .mcp.json and claude_desktop_config.json
pub struct JsonConfigWriter {
    /// The server name to use in the configuration
    server_name: String,
}

impl JsonConfigWriter {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
        }
    }
    
    /// Create the kindly-guard server configuration
    fn create_server_config(&self, server_path: &str) -> Value {
        json!({
            "command": server_path,
            "args": ["--stdio"],
            "env": {}
        })
    }
}

impl ConfigWriter for JsonConfigWriter {
    fn write_config(&self, path: &Path, server_path: &str) -> Result<()> {
        info!("Writing JSON configuration to: {}", path.display());
        
        // Create backup if file exists
        if path.exists() {
            self.backup_config(path)?;
        }
        
        // Load existing config or create new
        let mut config = if path.exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            
            if content.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse JSON in {}", path.display()))?
            }
        } else {
            // Create parent directory if needed
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory {}", parent.display()))?;
            }
            json!({})
        };
        
        // Ensure mcpServers exists
        if !config.is_object() {
            config = json!({});
        }
        
        let obj = config.as_object_mut().unwrap();
        if !obj.contains_key("mcpServers") {
            obj.insert("mcpServers".to_string(), json!({}));
        }
        
        // Add kindly-guard configuration
        let servers = obj.get_mut("mcpServers").unwrap();
        if let Some(servers_obj) = servers.as_object_mut() {
            servers_obj.insert(
                self.server_name.clone(),
                self.create_server_config(server_path),
            );
        }
        
        // Write formatted JSON
        let formatted = serde_json::to_string_pretty(&config)?;
        fs::write(path, formatted)
            .with_context(|| format!("Failed to write configuration to {}", path.display()))?;
        
        info!("Successfully wrote configuration to {}", path.display());
        Ok(())
    }
    
    fn config_exists(&self, path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        
        let content = fs::read_to_string(path)?;
        if content.trim().is_empty() {
            return Ok(false);
        }
        
        let config: Value = serde_json::from_str(&content)?;
        
        // Check if kindly-guard is already configured
        if let Some(servers) = config.get("mcpServers").and_then(|s| s.as_object()) {
            Ok(servers.contains_key(&self.server_name))
        } else {
            Ok(false)
        }
    }
    
    fn backup_config(&self, path: &Path) -> Result<Option<PathBuf>> {
        let backup_path = path.with_extension("json.backup");
        
        debug!("Creating backup at: {}", backup_path.display());
        fs::copy(path, &backup_path)
            .with_context(|| format!("Failed to create backup of {}", path.display()))?;
        
        Ok(Some(backup_path))
    }
}

/// JSON configuration writer for settings.local.json (Windsurf variant)
pub struct JsonLocalConfigWriter {
    server_name: String,
}

impl JsonLocalConfigWriter {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
        }
    }
    
    fn create_server_config(&self, server_path: &str) -> Value {
        json!({
            "provider": "stdio",
            "command": server_path,
            "args": ["--stdio"],
            "env": {}
        })
    }
}

impl ConfigWriter for JsonLocalConfigWriter {
    fn write_config(&self, path: &Path, server_path: &str) -> Result<()> {
        info!("Writing JSON local configuration to: {}", path.display());
        
        // Create backup if file exists
        if path.exists() {
            self.backup_config(path)?;
        }
        
        // Load existing config or create new
        let mut config = if path.exists() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            
            if content.trim().is_empty() {
                json!({})
            } else {
                serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse JSON in {}", path.display()))?
            }
        } else {
            // Create parent directory if needed
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory {}", parent.display()))?;
            }
            json!({})
        };
        
        // Ensure correct structure
        if !config.is_object() {
            config = json!({});
        }
        
        let obj = config.as_object_mut().unwrap();
        
        // Initialize mcpServers if not present
        if !obj.contains_key("mcpServers") {
            obj.insert("mcpServers".to_string(), json!({}));
        }
        
        // Add kindly-guard configuration
        let servers = obj.get_mut("mcpServers").unwrap();
        if let Some(servers_obj) = servers.as_object_mut() {
            servers_obj.insert(
                self.server_name.clone(),
                self.create_server_config(server_path),
            );
        }
        
        // Write formatted JSON
        let formatted = serde_json::to_string_pretty(&config)?;
        fs::write(path, formatted)
            .with_context(|| format!("Failed to write configuration to {}", path.display()))?;
        
        info!("Successfully wrote configuration to {}", path.display());
        Ok(())
    }
    
    fn config_exists(&self, path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        
        let content = fs::read_to_string(path)?;
        if content.trim().is_empty() {
            return Ok(false);
        }
        
        let config: Value = serde_json::from_str(&content)?;
        
        // Check if kindly-guard is already configured
        if let Some(servers) = config.get("mcpServers").and_then(|s| s.as_object()) {
            Ok(servers.contains_key(&self.server_name))
        } else {
            Ok(false)
        }
    }
    
    fn backup_config(&self, path: &Path) -> Result<Option<PathBuf>> {
        let backup_path = path.with_extension("json.backup");
        
        debug!("Creating backup at: {}", backup_path.display());
        fs::copy(path, &backup_path)
            .with_context(|| format!("Failed to create backup of {}", path.display()))?;
        
        Ok(Some(backup_path))
    }
}

/// TOML configuration writer (future support)
pub struct TomlConfigWriter {
    server_name: String,
}

impl TomlConfigWriter {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
        }
    }
}

impl ConfigWriter for TomlConfigWriter {
    fn write_config(&self, _path: &Path, _server_path: &str) -> Result<()> {
        warn!("TOML configuration format not yet implemented");
        Ok(())
    }
    
    fn config_exists(&self, _path: &Path) -> Result<bool> {
        Ok(false)
    }
    
    fn backup_config(&self, _path: &Path) -> Result<Option<PathBuf>> {
        Ok(None)
    }
}

/// YAML configuration writer for VS Code variants
pub struct YamlConfigWriter {
    server_name: String,
}

impl YamlConfigWriter {
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
        }
    }
}

impl ConfigWriter for YamlConfigWriter {
    fn write_config(&self, _path: &Path, _server_path: &str) -> Result<()> {
        warn!("YAML configuration format not yet implemented");
        Ok(())
    }
    
    fn config_exists(&self, _path: &Path) -> Result<bool> {
        Ok(false)
    }
    
    fn backup_config(&self, _path: &Path) -> Result<Option<PathBuf>> {
        Ok(None)
    }
}

/// Factory function to create appropriate config writer based on file extension
pub fn create_config_writer(path: &Path, server_name: &str) -> Box<dyn ConfigWriter> {
    let extension = path.extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    
    match extension {
        "json" => {
            // Check if it's a local settings file
            if path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.contains("local"))
                .unwrap_or(false)
            {
                Box::new(JsonLocalConfigWriter::new(server_name))
            } else {
                Box::new(JsonConfigWriter::new(server_name))
            }
        }
        "toml" => Box::new(TomlConfigWriter::new(server_name)),
        "yaml" | "yml" => Box::new(YamlConfigWriter::new(server_name)),
        _ => Box::new(JsonConfigWriter::new(server_name)), // Default to JSON
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_json_writer_new_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.json");
        
        let writer = JsonConfigWriter::new("kindly-guard");
        writer.write_config(&config_path, "/usr/local/bin/kindly-guard").unwrap();
        
        let content = fs::read_to_string(&config_path).unwrap();
        let config: Value = serde_json::from_str(&content).unwrap();
        
        assert!(config.get("mcpServers").is_some());
        let servers = config.get("mcpServers").unwrap();
        assert!(servers.get("kindly-guard").is_some());
        
        let kg_config = servers.get("kindly-guard").unwrap();
        assert_eq!(kg_config.get("command").unwrap(), "/usr/local/bin/kindly-guard");
        assert_eq!(kg_config.get("args").unwrap(), &json!(["--stdio"]));
    }

    #[test]
    fn test_json_writer_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.json");
        
        // Create existing config
        let existing = json!({
            "mcpServers": {
                "other-server": {
                    "command": "/path/to/other",
                    "args": []
                }
            }
        });
        fs::write(&config_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();
        
        let writer = JsonConfigWriter::new("kindly-guard");
        writer.write_config(&config_path, "/usr/local/bin/kindly-guard").unwrap();
        
        let content = fs::read_to_string(&config_path).unwrap();
        let config: Value = serde_json::from_str(&content).unwrap();
        
        let servers = config.get("mcpServers").unwrap().as_object().unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers.contains_key("other-server"));
        assert!(servers.contains_key("kindly-guard"));
    }

    #[test]
    fn test_config_exists() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.json");
        
        let writer = JsonConfigWriter::new("kindly-guard");
        
        // Should not exist initially
        assert!(!writer.config_exists(&config_path).unwrap());
        
        // Write config
        writer.write_config(&config_path, "/usr/local/bin/kindly-guard").unwrap();
        
        // Should exist now
        assert!(writer.config_exists(&config_path).unwrap());
    }

    #[test]
    fn test_backup_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.json");
        
        // Create initial file
        fs::write(&config_path, "{}").unwrap();
        
        let writer = JsonConfigWriter::new("kindly-guard");
        let backup_path = writer.backup_config(&config_path).unwrap().unwrap();
        
        assert!(backup_path.exists());
        assert_eq!(backup_path.extension().unwrap(), "backup");
    }

    #[test]
    fn test_local_settings_format() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("settings.local.json");
        
        let writer = JsonLocalConfigWriter::new("kindly-guard");
        writer.write_config(&config_path, "/usr/local/bin/kindly-guard").unwrap();
        
        let content = fs::read_to_string(&config_path).unwrap();
        let config: Value = serde_json::from_str(&content).unwrap();
        
        let kg_config = config.get("mcpServers").unwrap().get("kindly-guard").unwrap();
        assert_eq!(kg_config.get("provider").unwrap(), "stdio");
        assert_eq!(kg_config.get("command").unwrap(), "/usr/local/bin/kindly-guard");
    }
}